<?php
/**
 * API 入口 —— 部署到 /api/kernelsu/module/index.php。
 * 自包含：只读同目录 data/ 下的 keybox.xml / manifest.json / module.zip，
 * 不依赖 web 根之外的任何文件（兼容 open_basedir）。
 *
 * 路由（query 参数 action）：
 *   (无) / manifest -> data/manifest.json
 *   keybox           -> keybox.xml（响应头 X-Signature / X-SHA256）
 *   module           -> 模块包 module.zip（自更新）
 *   pubkey           -> Ed25519 公钥（来自 manifest）
 *   revocation       -> Google 吊销名单缓存（多源镜像拉取的结果）
 *   keyboxreport     -> 当前 keybox 的完整自检报告（证书链/有效期/吊销）
 *   acreport         -> 反挂上报 / 封禁查询（v2.7.0 起：设备令牌 + 限流，见分支注释）
 */

$dataDir      = __DIR__ . '/data';
$packageDir   = __DIR__ . '/package';
$keyboxFile   = $dataDir . '/keybox.xml';
$manifestFile = $dataDir . '/manifest.json';
$modulePkg    = $dataDir . '/module.zip';
$packageJson  = $packageDir . '/package.json';
$action       = $_GET['action'] ?? 'manifest';

header('Cache-Control: no-store, must-revalidate');
header('X-Robots-Tag: noindex');

function fail(int $code, string $msg) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

/**
 * v2.7.0 新表自愈：迁移 SQL 在 php-server/migrations/。没跑过迁移就在这里就地建 ——
 * 宝塔/搬迁环境下「表不存在」不该把整个接口打死。建不了（没权限）由调用方 try/catch 兜底。
 */
function acEnsureV2(PDO $pdo): void {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        $pdo->query('SELECT 1 FROM ac_token LIMIT 0');
        $pdo->query('SELECT 1 FROM ac_ratelimit LIMIT 0');
    } catch (Throwable $e) {
        $pdo->exec('CREATE TABLE IF NOT EXISTS ac_token (
            code CHAR(16) PRIMARY KEY,
            tok_hash CHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            last_seen DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
        $pdo->exec('CREATE TABLE IF NOT EXISTS ac_ratelimit (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            k VARCHAR(64) NOT NULL,
            at DATETIME NOT NULL,
            INDEX idx_k (k), INDEX idx_at (at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }
}

/** 窗口内计数达到上限返回 true（达到即拒） */
function acRateLimited(PDO $pdo, string $k, int $max, int $winSec): bool {
    $st = $pdo->prepare('SELECT COUNT(*) c FROM ac_ratelimit WHERE k = ? AND at > (NOW() - INTERVAL ? SECOND)');
    $st->execute([$k, $winSec]);
    return (int)($st->fetch(PDO::FETCH_ASSOC)['c'] ?? 0) >= $max;
}

function acRateNote(PDO $pdo, string $k): void {
    $pdo->prepare('INSERT INTO ac_ratelimit (k, at) VALUES (?, NOW())')->execute([$k]);
}

/**
 * 真实客户端 IP（限流用）。
 * 前面套了同机反代/WAF 时 REMOTE_ADDR 会是 127.0.0.1 或内网地址，全站共享一个
 * 限流桶 = 连坐。此时信任 X-Forwarded-For 的第一个地址；$cfg['trusted_proxies']
 * （yypm-private/db.php 里可选配置）里显式列出的回源 IP（如 CDN 节点段的具体地址）
 * 也信任。直连公网地址绝不看 XFF —— 否则谁都能伪造限流桶。
 */
function acClientIp(array $cfg = []): string {
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $trust = in_array($ip, (array)($cfg['trusted_proxies'] ?? []), true)
        || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    if ($trust) {
        $xff = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        $first = trim((string)(explode(',', $xff)[0] ?? ''));
        if ($first !== '' && filter_var($first, FILTER_VALIDATE_IP)) return $first;
    }
    return $ip;
}

/** 读取 manifest 并返回 keybox 相关字段 */
function manifestKeybox() {
    global $manifestFile;
    if (!is_file($manifestFile)) return null;
    $m = json_decode(@file_get_contents($manifestFile), true);
    return isset($m['keybox']) ? $m['keybox'] : null;
}

switch ($action) {
    case 'keybox': {
        if (!is_file($keyboxFile)) fail(404, 'no keybox');
        $data = file_get_contents($keyboxFile);
        header('Content-Type: application/xml');
        header('X-SHA256: ' . hash('sha256', $data));
        $kb = manifestKeybox();
        if ($kb && !empty($kb['signature'])) {
            header('X-Signature: ' . $kb['signature']);
        }
        echo $data;
        break;
    }

    case 'module': {
        if (!is_file($modulePkg)) fail(404, 'no module package');
        $data = file_get_contents($modulePkg);
        header('Content-Type: application/zip');
        header('Content-Length: ' . strlen($data));
        header('X-SHA256: ' . hash('sha256', $data));
        echo $data;
        break;
    }

    case 'pubkey': {
        $kb = manifestKeybox();
        if (!$kb || empty($kb['sign_public'])) fail(404, 'no pubkey');
        header('Content-Type: text/plain');
        echo $kb['sign_public'];
        break;
    }

    /**
     * 吊销名单（Google attestation/status）。
     *
     * 设备端拿这份数据自己比对本地 keybox 的证书序列号 —— 关键点是设备
     * 不需要能访问 Google：名单由服务器从 GitHub 镜像拉取后缓存在这里。
     *
     * entries 的键是【十六进制】序列号（去前导零、小写），与证书里的写法一致，
     * 设备端拿到十六进制序列号后直接查表即可。
     */
    case 'revocation': {
        $revFile = $dataDir . '/revocation.json';
        if (!is_file($revFile)) fail(404, 'no revocation list yet (run update.php first)');
        header('Content-Type: application/json');
        echo file_get_contents($revFile);
        break;
    }

    /**
     * 设备端「密钥自检」用：单独返回 manifest 里的 keybox 子对象。
     *
     * 为什么不直接让设备拉整个 manifest：设备端的 shell 里没有 JSON 解析器，
     * 让它去抠嵌套字段既脆弱又容易出错。这里把要展示的部分单独吐出来，
     * 设备端只负责原样搬运，由 WebUI 的 JS 做 JSON.parse。
     */
    case 'keyboxreport': {
        $kb = manifestKeybox();
        if (!$kb) fail(404, 'no keybox report yet (run update.php first)');
        header('Content-Type: application/json');
        echo json_encode($kb, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        break;
    }

    case 'packages': {
        if (!is_file($packageJson)) fail(404, 'no package manifest');
        header('Content-Type: application/json');
        echo file_get_contents($packageJson);
        break;
    }

    /**
     * 反挂上报 / 设备码封禁。
     *
     * 设备端开机扫描后调这里：ping 探活、scan 记录实锤、expire 表示宽限期已过。
     * 这个接口【只记录，不下发任何命令】—— 面板只做封禁，不干涉模块其它行为。
     *
     * 顺带兼任设备端的联网探针：能拿到 200 就说明在线，模块才肯工作。
     *
     * v2.7.0 起加【设备令牌】：首次联系下发 tok（只下发一次，库里只存哈希），
     * 之后 expire 必须带牌 —— 否则知道别人设备码就能伪造封禁。
     * 旧版模块（不带 tok）兼容：ping/scan 照常，expire 拒绝并记 expire_rej 取证。
     * 另有三级限流：IP 60 次/10 分钟、设备码 30 次/10 分钟、expire 3 次/天。
     */
    case 'acreport': {
        // v2.8.0 起客户端用 POST（tok 走 body，不进 nginx 访问日志）；旧版 GET 兼容保留。
        $src  = !empty($_POST) ? $_POST : $_GET;
        $code = preg_replace('/[^a-f0-9]/', '', strtolower((string)($src['code'] ?? '')));
        $ev   = preg_replace('/[^a-z]/', '', strtolower((string)($src['ev'] ?? 'ping')));
        $hits = substr(preg_replace('/[^A-Za-z0-9_,.-]/', '', (string)($src['hits'] ?? '')), 0, 240);
        $tok  = preg_replace('/[^a-f0-9]/', '', strtolower((string)($src['tok'] ?? '')));
        header('Content-Type: application/json');
        if (!is_string($code) || strlen($code) !== 16) { echo '{"ok":0,"err":"bad code"}'; break; }
        // 凭据在网站根目录之外，不进仓库。
        $cfgFile = '/path/to/yypm-private/db.php';
        if (!is_file($cfgFile)) { echo '{"ok":0,"err":"no cfg"}'; break; }
        $cfg = require $cfgFile;
        try {
            $pdo = new PDO($cfg['dsn'], $cfg['user'], $cfg['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (Throwable $e) { echo '{"ok":0,"err":"db"}'; break; }
        $ip = acClientIp(is_array($cfg) ? $cfg : []);

        try {
            acEnsureV2($pdo);

            // ---- 限流（超限直接拒，不写库）----
            if (acRateLimited($pdo, 'ip:' . $ip, 60, 600)) { echo '{"ok":0,"err":"rate"}'; break; }
            if ($ev !== 'ping' && acRateLimited($pdo, 'code:' . $code, 30, 600)) { echo '{"ok":0,"err":"rate"}'; break; }
            if ($ev === 'expire' && acRateLimited($pdo, 'exp:' . $code, 3, 86400)) { echo '{"ok":0,"err":"rate"}'; break; }
            acRateNote($pdo, 'ip:' . $ip);
            if ($ev !== 'ping') acRateNote($pdo, 'code:' . $code);
            if ($ev === 'expire') acRateNote($pdo, 'exp:' . $code);
            // 概率性清理（1/20）：限流表只留最近一天的行
            if (random_int(1, 20) === 1) {
                $pdo->exec('DELETE FROM ac_ratelimit WHERE at < (NOW() - INTERVAL 1 DAY)');
            }

            // ---- 设备令牌 ----
            $issuedTok = null;
            $st = $pdo->prepare('SELECT tok_hash FROM ac_token WHERE code = ? LIMIT 1');
            $st->execute([$code]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                // 首次联系：发牌。令牌原文只在这一刻下发一次，库里只存 sha256。
                $issuedTok = bin2hex(random_bytes(32));
                $pdo->prepare('INSERT INTO ac_token (code,tok_hash,created_at,last_seen) VALUES (?,?,NOW(),NOW())')
                    ->execute([$code, hash('sha256', $issuedTok)]);
            } elseif ($tok !== '') {
                if (!hash_equals((string)$row['tok_hash'], hash('sha256', $tok))) {
                    echo '{"ok":0,"err":"bad tok"}';
                    break;
                }
                $pdo->prepare('UPDATE ac_token SET last_seen = NOW() WHERE code = ?')->execute([$code]);
            } elseif ($ev === 'expire') {
                // 有牌设备却不带牌：要么是旧版模块，要么是伪造者 —— 都不受理封禁
                $pdo->prepare('INSERT INTO ac_report (code,ev,hits,ip,at) VALUES (?,?,?,?,NOW())')
                    ->execute([$code, 'expire_rej', $hits, $ip]);
                echo '{"ok":0,"err":"need tok"}';
                break;
            }
            // 无牌 + ping/scan：旧版模块兼容放行（不发新牌 —— 有牌设备的牌不可重领）

            if ($ev === 'expire') {
                $pdo->prepare('INSERT INTO ac_ban (code,reason,hits,ip,banned_at,banned_by) VALUES (?,?,?,?,NOW(),?)
                               ON DUPLICATE KEY UPDATE hits=VALUES(hits), banned_at=NOW()')
                    ->execute([$code, '实锤逾期未处理', $hits, $ip, 'auto']);
            }
            if ($ev !== 'ping') {
                $pdo->prepare('INSERT INTO ac_report (code,ev,hits,ip,at) VALUES (?,?,?,?,NOW())')
                    ->execute([$code, $ev, $hits, $ip]);
                // 只留最近 5000 条，别让表无限长
                $pdo->exec('DELETE FROM ac_report WHERE id < (SELECT MAX(id) - 5000 FROM (SELECT MAX(id) id FROM ac_report) t)');
            }
            $st = $pdo->prepare('SELECT 1 FROM ac_ban WHERE code = ? LIMIT 1');
            $st->execute([$code]);
            $resp = ['ok' => 1, 'banned' => $st->fetch() ? 1 : 0];
            if ($issuedTok !== null) $resp['tok'] = $issuedTok;
            echo json_encode($resp);
        } catch (Throwable $e) {
            // 新表不可用（迁移/权限问题）时降级成【只读查封禁】：
            // 上报与封禁全部停 —— 宁可封不上，也不能让防护失效期间被伪造封禁。
            try {
                $st = $pdo->prepare('SELECT 1 FROM ac_ban WHERE code = ? LIMIT 1');
                $st->execute([$code]);
                echo json_encode(['ok' => 1, 'banned' => $st->fetch() ? 1 : 0, 'degraded' => 1]);
            } catch (Throwable $e2) { echo '{"ok":0,"err":"db"}'; }
        }
        break;
    }

    case 'manifest':
    default: {
        if (!is_file($manifestFile)) fail(404, 'no manifest (run update_keybox.php first)');
        header('Content-Type: application/json');
        echo file_get_contents($manifestFile);
        break;
    }
}
