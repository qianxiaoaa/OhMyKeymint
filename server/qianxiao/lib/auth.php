<?php
/**
 * 后台鉴权与会话 —— 安全范式照抄 dashboard/index.php（上一版踩过的坑都在这）。
 *
 *  1. 口令用 bcrypt（password_hash）存在 SQLite 里，磁盘/命令行都不留明文；
 *  2. 登录失败按 IP 限流（login_fail 小表，等价 dashboard 的 ac_login_fail）；
 *  3. 写操作带 CSRF token，校验用 hash_equals（定时比较，防时序侧信道）；
 *  4. 登录成功 session_regenerate_id(true) 防会话固定；Cookie HttpOnly/Secure/SameSite=Strict；
 *  5. 每个请求都回库确认账号仍 enabled=1，被禁用/删除的会话立刻失效；
 *  6. 全部 PDO 预处理，不拼 SQL。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

const MAX_FAIL = 5;      // 限流窗口内最多失败几次
const FAIL_WIN = 900;    // 窗口（秒）= 15 分钟
const SESSION_IDLE_TIMEOUT = 14400; // 会话空闲超时（秒）= 4 小时，防公用电脑/长期挂着

/**
 * 会话引导：cookie 参数照抄 dashboard，只是 path 设为 '/'（本后台可挂在 /qianxiao/ 下，
 * 但会话应覆盖整个后台路径；写操作另有 CSRF，SameSite=Strict 已挡跨站）。
 * 幂等：已在会话中就不重复设置。
 */
function auth_session_start(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    session_set_cookie_params([
        'httponly' => true,
        // 已知局限：nginx 做 TLS 终结却没把 HTTPS 变量透传给后端时，这里取到空值 -> cookie 不带 Secure。
        // 宝塔 php-fpm 站点正常会透传；若前置 CDN 终结 TLS，需确保配置了 X-Forwarded-Proto 或站点层设 HTTPS。
        'secure'   => !empty($_SERVER['HTTPS']),
        'samesite' => 'Strict',
        'path'     => '/',
    ]);
    session_start();
}

/** 签发（或复用）CSRF token。 */
function auth_csrf_issue(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return (string)$_SESSION['csrf'];
}

/** 校验 POST 携带的 CSRF token；用 hash_equals 定时比较。 */
function auth_csrf_check(): bool {
    $sess = (string)($_SESSION['csrf'] ?? '');
    $post = (string)($_POST['csrf'] ?? '');
    return $sess !== '' && $post !== '' && hash_equals($sess, $post);
}

/** 窗口内该 IP 的失败次数。 */
function auth_fails_recent(PDO $pdo, string $ip): int {
    $cutoff = gmdate('Y-m-d H:i:s', time() - FAIL_WIN);
    $st = $pdo->prepare('SELECT COUNT(*) c FROM login_fail WHERE ip = ? AND at > ?');
    $st->execute([$ip, $cutoff]);
    return (int)($st->fetch()['c'] ?? 0);
}

/** 记一次失败（一行一次，和 dashboard 同款；顺手清理过期行）。 */
function auth_fail_note(PDO $pdo, string $ip): void {
    $pdo->prepare('INSERT INTO login_fail (ip, at, cnt) VALUES (?, ?, 1)')->execute([$ip, admin_now()]);
    $cutoff = gmdate('Y-m-d H:i:s', time() - FAIL_WIN * 4);
    $pdo->prepare('DELETE FROM login_fail WHERE at < ?')->execute([$cutoff]);
}

/** 某 IP 成功后清空其失败计数（避免刚登录就被之前的失败拖进限流）。 */
function auth_fail_clear(PDO $pdo, string $ip): void {
    $pdo->prepare('DELETE FROM login_fail WHERE ip = ?')->execute([$ip]);
}

/**
 * 尝试登录。返回 ['ok' => bool, 'err' => string]。
 * err 一律用通用文案，不区分「用户不存在」与「口令错」，避免账号枚举。
 */
function auth_login(PDO $pdo, string $user, string $pass, string $ip): array {
    if (auth_fails_recent($pdo, $ip) >= MAX_FAIL) {
        return ['ok' => false, 'err' => '失败次数过多，请 15 分钟后再试'];
    }
    $st = $pdo->prepare('SELECT pass_hash, enabled FROM admin_user WHERE user = ? LIMIT 1');
    $st->execute([$user]);
    $row = $st->fetch();
    // 即使用户不存在也跑一次 password_verify，拉平耗时、避免计时探测。
    $hash = (string)($row['pass_hash'] ?? '$2y$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv');
    $okPw = password_verify($pass, $hash);
    if (!$row || !$okPw || (int)$row['enabled'] !== 1) {
        auth_fail_note($pdo, $ip);
        auth_audit($pdo, $user === '' ? '-' : $user, 'login_fail', null);
        return ['ok' => false, 'err' => '用户名或口令不对'];
    }
    session_regenerate_id(true);
    $_SESSION['admin'] = $user;
    $_SESSION['csrf']  = bin2hex(random_bytes(16));
    $_SESSION['last_seen'] = time(); // 会话空闲超时基准，纯 session 侧实现，不动 DB schema
    auth_fail_clear($pdo, $ip);
    $pdo->prepare('UPDATE admin_user SET last_login_at = ? WHERE user = ?')->execute([admin_now(), $user]);
    auth_audit($pdo, $user, 'login', null);
    return ['ok' => true, 'err' => ''];
}

/**
 * 当前登录用户：会话里有名字，还要每请求回库确认账号仍 enabled=1。
 * 被禁用/删除 -> 清会话返回 null（下个动作就会被踢回登录页）。
 */
function auth_current_user(PDO $pdo): ?string {
    $u = $_SESSION['admin'] ?? null;
    if (!is_string($u) || $u === '') return null;
    // 会话空闲超时：超过 SESSION_IDLE_TIMEOUT 秒无操作则自动失效。
    $lastSeen = (int)($_SESSION['last_seen'] ?? 0);
    if ($lastSeen > 0 && (time() - $lastSeen) > SESSION_IDLE_TIMEOUT) {
        $_SESSION = [];
        return null;
    }
    try {
        $st = $pdo->prepare('SELECT enabled FROM admin_user WHERE user = ? LIMIT 1');
        $st->execute([$u]);
        $row = $st->fetch();
    } catch (Throwable $e) {
        return null;   // 库临时不可用：保守当作未登录
    }
    if (!$row || (int)$row['enabled'] !== 1) {
        $_SESSION = [];
        return null;
    }
    $_SESSION['last_seen'] = time(); // 活性骨探：本次确认仍有效，刷新空闲计时器
    return $u;
}

/**
 * 操作审计（谁、什么时候、对哪个对象、从哪个 IP）。审计失败绝不打断正在进行的操作，
 * 只静默吞掉（表由 admin_db() 首跑建好，正常不会走到 catch）。
 */
function auth_audit(PDO $pdo, string $admin, string $act, ?string $target): void {
    try {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        $pdo->prepare('INSERT INTO audit (admin, act, target, ip, at) VALUES (?,?,?,?,?)')
            ->execute([$admin, $act, $target, $ip, admin_now()]);
    } catch (Throwable $e) {
        // 静默：审计写不进不能影响主操作
    }
}
