#!/bin/bash
# =========================================================
# OhMyKeymint 管理后台启动脚本 —— 本机调试快捷方式。
# 公网生产应由宝塔 nginx+php-fpm 承载（见 README 宝塔部署指南），本脚本仅用于开发/临时预览。
# 变量集中在此，风格照 update.sh。默认 127.0.0.1:8787，可用环境变量覆盖：
#   PHP=/path/to/php QX_HOST=127.0.0.1 QX_PORT=8787 ./qianxiao-start.sh
# =========================================================
PHP=${PHP:-/www/server/php/84/bin/php}
QX_HOST=${QX_HOST:-127.0.0.1}
QX_PORT=${QX_PORT:-8787}
DIR="$(cd "$(dirname "$0")" && pwd)"
QX_DIR="$DIR/qianxiao"

# 本机调试建议绑 127.0.0.1；若确实要绑其他地址，后台应用层仍按 config.php 三级策略控制访问。
if [ "$QX_HOST" != "127.0.0.1" ] && [ "$QX_HOST" != "localhost" ] && [ "$QX_HOST" != "::1" ]; then
    echo "注意: QX_HOST=$QX_HOST 非本机地址，公网生产请用宝塔 nginx+php-fpm，本脚本仅供调试。"
fi

if [ ! -d "$QX_DIR" ]; then
    echo "找不到后台目录: $QX_DIR"
    exit 1
fi
if [ ! -x "$PHP" ] && ! command -v "$PHP" >/dev/null 2>&1; then
    echo "找不到可执行的 PHP: $PHP（用 PHP=/path/to/php 覆盖）"
    exit 1
fi

# 数据/台账目录：确保运行用户可写（SQLite 与 JSON 双写都依赖它）
mkdir -p "$DIR/data" "$DIR/data/devices" 2>/dev/null
chmod 750 "$DIR/data" 2>/dev/null

echo "OMK 管理后台（本机调试模式）"
echo "  首次使用请先建管理员: $PHP $QX_DIR/cli.php init-admin <user> '<pass>'"
echo "  访问地址: http://$QX_HOST:$QX_PORT/   (Ctrl+C 停止)"

# 用 index.php 作路由：任何 URI 都经它的访问守卫，避免直接命中 pages/ 等内部文件。
exec "$PHP" -S "$QX_HOST:$QX_PORT" -t "$QX_DIR" "$QX_DIR/index.php"
