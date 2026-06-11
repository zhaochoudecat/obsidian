---
name: ctf-challenge
description: CTF 协同解题：分析目标、寻找漏洞、利用攻击、获取 flag，最终输出中文 Writeup。适用于 web/crypto/pwn/misc 等各方向的 CTF 挑战。
---

# CTF 协同解题

作为 CTF 专家，按专业渗透测试流程完成 CTF 挑战，并将完整过程记录为中文 Writeup。

## 输入

用户提供以下信息（通过对话或 `$ARGUMENTS`）：
- **目标地址**：CTF 题目的 URL 或 ncat 地址（如 `http://xxx.node.buuoj.cn:81` 或 `ncat --ssl host port`）
- **WP 文件名**：保存 Writeup 的文件名（如 `web1.md`、`crypto1.md`、`pwn1.md`）
- **题目类型**（可选）：web / crypto / pwn / misc 等
- **附件路径**（可选）：本地已下载的题目附件目录
- **辅助信息**（可选）：Kali SSH 凭据、已知用户名密码、靶机已知信息等

## 工作流程

### 1. 信息收集

**Web 方向**：
- CTF 题目 URL 不要用 WebFetch（网络策略限制），一律使用 `curl -s -i <URL>` 获取页面信息和 HTTP 响应头
- 识别页面功能点（表单、参数、上传点）
- 技术栈识别（框架、后端语言、数据库类型）
- 目录扫描：`gobuster dir -u <URL> -w /usr/share/wordlists/dirb/common.txt`
- 端口扫描：`nmap -sV -sC <host>`

**Crypto 方向**：
- 分析题目附件中的加密脚本/密文
- 识别加密算法和参数
- 寻找算法弱点（短密钥、已知明文、 ECB 模式、 padding oracle 等）

**PWN 方向**：
- `file` 识别二进制类型和保护机制
- `checksec --file=<binary>` 查看保护
- `objdump -d` 或 `ghidra` 反汇编分析
- 本地调试：`gdb` + `pwndbg`

### 2. 漏洞探测

根据收集的信息，逐一测试可能的漏洞类型：

**Web**：SQL 注入、命令注入、SSTI、文件上传、LFI/RFI、XSS、CSRF、SSRF、反序列化、XXE、弱口令、源码泄露、逻辑漏洞
**Crypto**：密钥复用、ECB 模式、已知明文攻击、Padding Oracle、RSA 小指数/共模、格攻击
**PWN**：栈溢出、格式化字符串、堆漏洞、ROP、ret2libc、ret2syscall

### 3. 漏洞利用

- 确认漏洞后，构造 Payload 进行利用
- 逐步深入，获取更多权限或信息
- 如需远程工具，优先使用已有的 Kali（SSH `sshpass -p 'kali' ssh root@192.168.3.72`）
- Python exploit 使用 `pwntools`（`from pwn import *`）
- Java 反序列化可用 `ysoserial-all.jar`
- 如需安装工具，先问用户确认

### 4. 获取 Flag

- 搜索以 `flag{` 开头的字符串
- 常见 flag 位置：环境变量、配置文件、数据库、网页源码、/flag 文件、/root/、/tmp/
- 获取 flag 后记录获取方式

### 5. 保存 Writeup

将完整解题过程写入当前目录下的指定文件（中文）。

## Writeup 格式要求

文件保存在当前工作目录，使用以下结构：

```markdown
---
title: "[题目名称]"
date: <当前日期 YYYY-MM-DD>
categories:
  - CTF
  - <WEB/MISC/CRYPTO/PWN 等>
tags:
  - CTF
---

# [题目名称]

## 题目信息

- **URL**: <网址或 ncat 地址>
- **类型**: <WEB/CRYPTO/PWN/MISC 等>

## 信息收集

[描述访问页面看到的内容、源码关键部分、HTTP 头等]

## 漏洞分析

[详细的漏洞分析思路，为什么判断这里存在漏洞，使用了什么技术原理]

## 漏洞利用

[关键操作步骤，包括所有使用的 shell 命令及执行结果]

## 获取 Flag

```
flag{xxxxxxxx}
```

## 知识点总结

- 本题涉及的技术点
- 用到的工具及作用说明
- 防御建议
```

## 执行要点

- 每个解题步骤都要记录使用的命令和输出
- Writeup 中给出的每条线索/发现，必须附上获取该信息的命令或语句，不能只写结论
- 分析要详实，不仅说"做了什么"还要说"为什么这么做"
- 涉及的技术原理要解释清楚
- 如果遇到困难或尝试失败也要记录，展示完整的思考过程
- 使用 `curl`、`python3`、`sqlmap`、`gobuster`、`nmap`、`pwntools` 等工具
- 优先使用已有的 Kali 或 macOS 本地工具
- Writeup 中的 `curl` 命令示例使用未编码的原始 payload，保证可读性（实际执行时才用 URL 编码）

## 用户交互

- 攻击过程中遇到需要用户配合的步骤（注册账号、启动服务、提供信息），及时与用户沟通
- 如果工具缺失，先检查 Kali 是否已有，没有再请用户确认是否安装
- 多次尝试失败时，记录失败原因并调整思路，不要重复相同方法
