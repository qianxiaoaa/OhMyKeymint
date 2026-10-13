<?php
/**
 * OMK 服务端管理后台 —— 单入口路由：?page=login|overview|usage|logs|devices|users。
 *
 * 安全取舍与 dashboard/index.php 同源（会话/Cookie/bcrypt/CSRF/限流/预处理），
 * 数据落在与领取日志同库的 SQLite（见 lib/db.php）。写操作一律 POST + CSRF。
 *
 * 公网部署下的防线：bcrypt 口令 + 登录限流 + CSRF + 操作审计 + HTTPS（宝塔站点层）+
 * 强口令策略（CLI 建号强制 ≥10 位） + 可选 IP 白名单（qianxiao/config.php）。
 * 安全建议：站点 nginx 配置 deny data/ keys/ 目录；开启强制 HTTPS；考虑 fail2ban。
 *
 * 访问控制三级策略（配置见 qianxiao/config.sample.php）：
 *   1. allow_loopback_only=true  → 仅回环（紧急收紧/本机调试）
 *   2. allow_ips 非空           → 白名单 + 回环
 *   3. 默认（无 config.php） → 任意 IP（公网模式）
 *
 * 版本：见页脚注释「OMK qianxiao 1.0」。
 */
declare(strict_types=1);

// ---- 访问守卫：必须是本文件最先执行的逻辑，先于会话、先于任何输出 ----
// 只信 REMOTE_ADDR，故意不信 X-Forwarded-For：XFF 是客户端可伪造的请求头，
// 一旦信任它，任意公网请求都能伪造成白名单 IP 绕过这道守卫。真正限制来源
// 应由 nginx 层做，应用层这里宁可误拒本机 IPv6 也不放行任何可伪造头。
$remoteAddr = (string)($_SERVER['REMOTE_ADDR'] ?? '');

// 读取后台本地配置（不存在则用默认值，不报错）。
$qxCfg = ['allow_ips' => [], 'allow_loopback_only' => false];
$qxCfgFile = __DIR__ . '/config.php';
if (is_file($qxCfgFile)) {
    $loaded = require $qxCfgFile;
    if (is_array($loaded)) {
        $qxCfg['allow_ips']           = isset($loaded['allow_ips']) && is_array($loaded['allow_ips']) ? $loaded['allow_ips'] : [];
        $qxCfg['allow_loopback_only'] = !empty($loaded['allow_loopback_only']);
    }
}

$isLoopback = ($remoteAddr === '::1' || strncmp($remoteAddr, '127.', 4) === 0);

if ($qxCfg['allow_loopback_only']) {
    // 模式 1：仅回环可达（紧急收紧/本机调试，等同旧版行为）。
    if (!$isLoopback) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'forbidden';
        exit;
    }
} elseif ($qxCfg['allow_ips'] !== []) {
    // 模式 2：白名单 + 回环可达，其余 403。
    if (!$isLoopback && !in_array($remoteAddr, $qxCfg['allow_ips'], true)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'forbidden';
        exit;
    }
}
// 模式 3（默认）：allow_loopback_only=false 且 allow_ips 为空，任意 IP 可达（公网模式）。

// 入口标记：qianxiao/lib/*.php 与 qianxiao/pages/*.php 都靠它判断自己是「被本文件纳入」
// 而不是被 Web 直连执行，必须在 require 它们之前定义。
define('ADMIN_BOOT', 1);

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/page.php';

auth_session_start();

// 白名单路由：$page 只会取下列值，非法值一律回落 overview，杜绝文件包含注入。
$PAGES = ['login', 'overview', 'usage', 'logs', 'devices', 'users'];
$page  = (string)($_GET['page'] ?? 'overview');
if (!in_array($page, $PAGES, true)) $page = 'overview';

$ip = $remoteAddr;

// 退出登录：公网模式下必须 POST + CSRF，防 CSRF 强制登出攻击。
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['logout'])) {
    if (!empty($_SESSION['csrf']) && hash_equals((string)$_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
    }
    header('Location: ?page=login');
    exit;
}

// 数据库不可用（目录不可写等）：登录也依赖库，直接以纯文本友好报错并停住。
$pdo = admin_db();
if ($pdo === null) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo '后台暂不可用：' . admin_db_init_error() . "\n";
    exit;
}

// 当前用户（每请求回库确认仍 enabled）
$currentUser = auth_current_user($pdo);
$authed = $currentUser !== null;

// 已登录访问登录页 -> 直接进概览
if ($authed && $page === 'login') {
    header('Location: ?page=overview');
    exit;
}
// 未登录访问非登录页 -> 跳登录
if (!$authed && $page !== 'login') {
    header('Location: ?page=login');
    exit;
}

$loginErr = '';
// 登录页 POST（未鉴权，无 CSRF 概念；口令校验 + 限流在 auth_login 内）
if ($page === 'login' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['pass'])) {
    $res = auth_login($pdo, trim((string)($_POST['user'] ?? '')), (string)$_POST['pass'], $ip);
    if ($res['ok']) {
        header('Location: ?page=overview');
        exit;
    }
    $loginErr = $res['err'];
}

// 已登录写操作：进入页面前统一校验 CSRF（登录页除外）。不匹配直接 400。
if ($authed && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && $page !== 'login') {
    if (!auth_csrf_check()) {
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        exit('CSRF token 不匹配');
    }
}

// 路由到具体页面。$page 已白名单化，包含安全；页面文件内自行 render_header/footer，
// 需要 CSV 导出的页面在读到任何 HTML 前就发头并 exit（见对应 pages/*.php 顶部）。
require __DIR__ . '/pages/' . $page . '.php';
