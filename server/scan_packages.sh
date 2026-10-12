#!/bin/bash
# =========================================================
# yypm 附属模块清单扫描 —— 供宝塔计划任务 / update.sh 调用
# 扫描 package/ 目录，读出每个 zip 内的 module.prop，
# 生成带版本信息的 package.json（对旧客户端向后兼容）
# =========================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$DIR/package"
PY=python3
[ -x /usr/bin/python3 ] && PY=/usr/bin/python3

"$PY" "$DIR/scan_packages.py" --dir "$PKG_DIR" "$@"
rc=$?

# 保证 Web 进程（www）能读、能覆盖写
if [ -f "$PKG_DIR/package.json" ]; then
    chown www:www "$PKG_DIR/package.json" 2>/dev/null
    chmod 644 "$PKG_DIR/package.json" 2>/dev/null
fi

exit $rc
