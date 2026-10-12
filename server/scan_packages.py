#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yypm 附属模块清单扫描器
=========================================================
扫描 package/ 目录下所有 .zip，读出每个包里的 module.prop，
生成（或就地更新）package.json 清单，供 KernelSU 模块的 WebUI 检查更新使用。

相比只输出 sha256/size/url 的旧版清单，这里额外带上从包内 module.prop 解析出的
元信息（真实模块 id / 名称 / 版本 / versionCode）。这样客户端可以只比版本号就知道
有没有更新，不必为了看一眼版本就把几 MB 的包下载下来。

用法:
    python3 scan_packages.py                     # 扫描 ./package 并写回 package.json
    python3 scan_packages.py --dir /path/to/pkg  # 指定目录
    python3 scan_packages.py --print             # 只打印，不写文件
    python3 scan_packages.py --strict            # 任何 zip 缺 module.prop 即失败退出

默认行为对现有客户端完全向后兼容：modules 里每个条目的 sha256 / size / url 三个字段
含义与位置不变，只是多了几个新字段。
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timezone, timedelta

# 模块 id 的合理形态（KernelSU/Magisk 惯例），不满足则认为是坏包/异常内容
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# 版本串里常见的末尾版本号，例如 "v2.2.0 (7854)" -> 7854
TRAILING_NUM_RE = re.compile(r"\((\d+)\)\s*$")

DEFAULT_BASE_URL = "https://your-server.example.com/api/kernelsu/module/package/"


def log(msg):
    sys.stderr.write(msg + "\n")


def read_module_prop(zip_path):
    """从 zip 里读出 module.prop 文本；找不到或读不出返回 (None, 原因)。"""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            # 优先根目录；有些包会包一层目录，则退而求其次找最短路径的那个
            names = [n for n in zf.namelist() if n.endswith("module.prop")]
            if not names:
                return None, "包内没有 module.prop"
            names.sort(key=lambda n: (n.count("/"), len(n)))
            with zf.open(names[0]) as fh:
                raw = fh.read()
    except zipfile.BadZipFile:
        return None, "不是有效的 zip（文件可能损坏或下载不完整）"
    except OSError as exc:
        return None, "读取失败: %s" % exc

    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(enc), None
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), None


def parse_prop(text):
    """把 module.prop 的 key=value 解析成 dict（忽略注释与空行）。"""
    props = {}
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in props:          # 同名键以第一个为准
            props[key] = value.strip()
    return props


def to_int(value):
    """尽量转成整数，失败返回 None。"""
    if value is None:
        return None
    value = str(value).strip()
    return int(value) if re.fullmatch(r"\d+", value) else None


def describe(zip_path, name, base_url, old_entry):
    """算出一个 zip 的清单条目；返回 (entry, 警告列表)。"""
    warnings = []
    size = os.path.getsize(zip_path)

    sha256 = hashlib.sha256()
    with open(zip_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)

    # url 沿用旧清单里的值，避免域名/路径变更时被脚本改掉；没有才按 base_url 生成
    url = (old_entry or {}).get("url") or (base_url.rstrip("/") + "/" + name)

    entry = {
        "sha256": sha256.hexdigest(),
        "size": size,
        "url": url,
    }

    text, err = read_module_prop(zip_path)
    if err:
        warnings.append("%s: %s" % (name, err))
        return entry, warnings

    props = parse_prop(text)

    mod_id = props.get("id", "")
    if mod_id and not ID_RE.match(mod_id):
        warnings.append("%s: 包内 id 形态异常 [%s]，已忽略" % (name, mod_id))
        mod_id = ""

    version = props.get("version", "")
    version_code = to_int(props.get("versionCode"))
    if version_code is None and version:
        # 有些包不写 versionCode，版本号藏在 version 末尾的括号里
        m = TRAILING_NUM_RE.search(version)
        if m:
            version_code = int(m.group(1))

    # 新增字段，全部加 x- 前缀便于和旧字段区分，同时客户端可无痛忽略
    entry["x-id"] = mod_id
    entry["x-name"] = props.get("name", "") or name
    if version:
        entry["x-version"] = version
    if version_code is not None:
        entry["x-versionCode"] = version_code

    # 兼容：早先约定的精简字段名（有则一并给出，方便客户端取值）
    entry["module_id"] = mod_id
    entry["version"] = version
    entry["versionCode"] = version_code

    if not mod_id:
        warnings.append("%s: 包内没有可用的 id" % name)

    return entry, warnings


def load_old(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (ValueError, OSError) as exc:
        log("[!] 旧清单无法解析（将忽略）: %s" % exc)
        return {}
    modules = data.get("modules")
    return modules if isinstance(modules, dict) else {}


def main():
    ap = argparse.ArgumentParser(description="扫描附属模块包并生成 package.json 清单")
    ap.add_argument("--dir", default=None,
                    help="存放 zip 的目录（默认：脚本同级 package/）")
    ap.add_argument("--out", default=None,
                    help="清单输出路径（默认：<目录>/package.json）")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL,
                    help="生成下载地址用的前缀（仅在旧清单里没有 url 时使用）")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="只输出到 stdout，不写文件")
    ap.add_argument("--strict", action="store_true",
                    help="有任何警告就以非 0 退出（适合放进校验流程）")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    pkg_dir = os.path.abspath(args.dir or os.path.join(here, "package"))
    out_path = os.path.abspath(args.out or os.path.join(pkg_dir, "package.json"))

    if not os.path.isdir(pkg_dir):
        log("[x] 目录不存在: %s" % pkg_dir)
        return 2

    old_modules = load_old(out_path)

    names = sorted(n for n in os.listdir(pkg_dir) if n.lower().endswith(".zip"))
    if not names:
        log("[!] %s 里没有找到任何 .zip —— 不会覆盖原有清单" % pkg_dir)
        if old_modules:
            log("    旧清单里有 %d 个模块，保留不动" % len(old_modules))
        return 0 if not args.strict else 3

    modules = {}
    warnings = []
    for name in names:
        path = os.path.join(pkg_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            entry, warns = describe(path, name, args.base_url, old_modules.get(name))
        except OSError as exc:
            warnings.append("%s: 读取失败 %s" % (name, exc))
            continue
        modules[name] = entry
        warnings.extend(warns)

    for w in warnings:
        log("[!] " + w)

    tz = timezone(timedelta(hours=8))
    manifest = {
        "updated_at": datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(modules),
        "modules": modules,
    }
    text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n"

    if args.print_only:
        sys.stdout.write(text)
    else:
        # 先写临时文件再原子替换，避免客户端读到写一半的清单
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(out_path) or ".", prefix=".pkgjson.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(tmp, 0o644)
            os.replace(tmp, out_path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        log("[+] 已更新 %s（%d 个模块，%d 条警告）" % (out_path, len(modules), len(warnings)))

    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
