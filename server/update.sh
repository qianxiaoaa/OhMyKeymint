#!/bin/bash
# =========================================================
# yypm keybox 更新脚本 —— 宝塔计划任务执行此脚本
# 以 www 用户运行 PHP（与网站 PHP 进程同用户）
# =========================================================
PHP=/www/server/php/84/bin/php
DIR=/www/wwwroot/your-server.example.com/api/kernelsu/module

# 确保 www 用户对数据/密钥/模块目录有读写权限
chown -R www:www "$DIR/data" "$DIR/keys" "$DIR/package" 2>/dev/null
chmod -R 755 "$DIR/data" "$DIR/keys" "$DIR/package" 2>/dev/null

cd "$DIR" || exit 1

if [ "$(id -u)" = "0" ]; then
    # 以 root 运行时降级到 www
    sudo -u www "$PHP" "$DIR/fetch_packages.php" >> "$DIR/data/update.log" 2>&1
    sudo -u www "$PHP" "$DIR/update.php" >> "$DIR/data/update.log" 2>&1
else
    "$PHP" "$DIR/fetch_packages.php" >> "$DIR/data/update.log" 2>&1
    "$PHP" "$DIR/update.php" >> "$DIR/data/update.log" 2>&1
fi
