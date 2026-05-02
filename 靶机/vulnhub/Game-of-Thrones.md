---
title: Game-of-Thrones
date: 2026-05-03
categories:
  - 靶机
  - vulnhub
---

 https://www.vulnhub.com/entry/game-of-thrones-ctf-1,201/
![](assets/Pasted%20image%2020251223194902.png)
>[!tip]- tips
>Get the 7 kingdom flags and the 4 extra content flags (3 secret flags + final battle flag). There are 11 in total. 

权力的游戏

## 1.arp

![](assets/Pasted%20image%2020251223205139.png)
## 2.namp

推荐用这种方式, 可以扫描到1337端口，下面的命令扫描不到

```bash
nmap -A -T4 -p- 192.168.43.13 # 全开扫描+版本+系统+脚本探测
```
![](assets/Pasted%20image%2020251224104738.png)



```bash
nmap -T4 -sS -sV -sC -O 192.168.3.17
```

![](assets/Pasted%20image%2020251223205223.png)
>[!summary]- 端口号
>port doamin
>21 ftp
>22 ssh
>53 domain
>80 Apach httpd
>143 imap
>3306 mysql
>5432 postgresql
>10000 MiniServ


-sV 服务程序以及版本信息
-A  综合扫描
-oG 分类保存
-T4 快速扫描

[[扫描结果]]

![](assets/Pasted%20image%2020260102212517.png)
