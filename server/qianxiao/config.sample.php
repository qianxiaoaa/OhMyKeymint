<?php
/**
 * 后台访问控制配置 —— 复制本文件为 config.php 后生效（config.php 已 .gitignore 不入库）。
 *
 * 三级策略：
 *   - allow_loopback_only = true  → 仅 127.0.0.1/::1 可达（紧急收紧或本机调试用）。
 *   - allow_ips 非空             → 仅白名单内 IP + 回环可达，其余 403。
 *   - 两者都为默认值（本文件不存在时） → 任意 IP 可达（公网模式）。
 *
 * Cookie Secure 说明：宝塔 https 站点经 php-fpm 会透传 HTTPS 变量，
 * auth.php 里的 secure cookie 判定（!empty($_SERVER['HTTPS'])）自动生效。
 * 若前置 CDN 终结 TLS 而未回传 HTTPS 头给 php-fpm，则 Secure 标志不会设置，
 * 此时建议在 nginx/CDN 层配置 X-Forwarded-Proto 并让 php-fpm 读取它，或考虑
 * 在 index.php 顶部手动设 $_SERVER['HTTPS']='on'（注意安全评估）。
 */
return [
    // 允许访问后台的 IP 列表（精确匹配 REMOTE_ADDR，不含 CIDR）。
    // 空数组 = 不启用白名单（公网模式，任何 IP 均可到达登录页）。
    'allow_ips' => [
        // '1.2.3.4',
        // '10.0.0.50',
    ],

    // 设为 true 可一键收紧为仅本机可达（等同旧版回环守卫）。
    // 适用场景：临时通过 SSH 隧道访问、本机 php -S 调试。
    'allow_loopback_only' => false,
];
