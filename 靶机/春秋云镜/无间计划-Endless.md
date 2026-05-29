
![](assets/file-20260529150909917.png)
# flag01
## 登录 39.101.140.137
可能是SQL注入
![697](assets/file-20260529151640215.png)

## 登录39.101.138.52
有PbootCMS，PbootCMS 是一款**永久开源免费、可商用**的轻量级 PHP 企业建站系统，由于是PHP搭建的，尝试寻找漏洞
![](assets/file-20260529151439311.png)

## nmap扫描
对两个IP地址进行nmap扫描 ，第二个有PbootCMS
```
☁  endless  nmap -p- 39.101.140.137
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 15:06 CST
Nmap scan report for 39.101.140.137
Host is up (0.070s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
445/tcp  filtered microsoft-ds
5800/tcp filtered vnc-http
5900/tcp filtered vnc

☁  endless  nmap -sVC -p- 39.101.138.52             
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 15:09 CST
Nmap scan report for 39.101.138.52
Host is up (0.062s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:d3:14:1e:f4:c0:95:80:c6:be:63:45:3a:ce:52:18 (RSA)
|   256 0d:6a:13:05:42:49:24:bf:0b:d1:a3:a3:80:12:89:41 (ECDSA)
|_  256 90:ee:16:a1:00:12:1a:e3:be:76:5c:d1:4d:e0:bc:56 (ED25519)
80/tcp   open     http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/ad*
|_http-title: PbootCMS-\xE6\xB0\xB8\xE4\xB9\x85\xE5\xBC\x80\xE6\xBA\x90\xE5\x85\x8D\xE8\xB4\xB9\xE7\x9A\x84PHP\xE4\xBC\x81\xE4\xB8\x9A\xE7\xBD\x91\xE7\xAB\x99\xE5\xBC\x80\xE5\x8F\x91\xE5\xBB\xBA\xE8\xAE\xBE\xE7\xAE\xA1\xE7\x90...
445/tcp  filtered microsoft-ds
5800/tcp filtered vnc-http
5900/tcp filtered vnc
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

101.132.149.233
