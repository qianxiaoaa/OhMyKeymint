<?php
/**
 * 领取埋点共享库 —— public/index.php 每下发一次 keybox/manifest 就记一行。
 *
 * 契约（和分发接口的关系决定了它必须极度"安静"）：
 *   - 所有函数全程 try/catch 吞掉一切异常，失败静默 return，绝不 echo、绝不 throw；
 *     日志层出任何问题都不能连累分发响应（这是"追加式埋点"能安全上线的前提）。
 *   - 库文件与后台同库：server/data/admin.sqlite。后台还没建表也没关系，
 *     入口检测 usage_log 表不存在时自愈建表（schema 与 admin/lib/db.php 完全一致）。
 *
 * 时间基准：UTC 文本，格式沿用仓库既有的 Y-m-d H:i:s（update.php 的 updated_at、
 * dashboard 的 at 列都是这个写法），不额外加 ISO8601 的 T 分隔符 —— 与后台展示、
 * CSV 导出保持同一可读格式；UTC 是为了消除多机/时区歧义。
 */

/** 与 admin/lib/db.php 保持一致的表结构，单独列出便于分发侧自愈建表 */
const USAGE_LOG_DDL = [
    'CREATE TABLE IF NOT EXISTS usage_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        ip TEXT NOT NULL,
        ua TEXT,
        action TEXT NOT NULL,
        keybox_sha256 TEXT,
        keybox_serials TEXT,
        note TEXT
    )',
    'CREATE INDEX IF NOT EXISTS idx_usage_at     ON usage_log(at)',
    'CREATE INDEX IF NOT EXISTS idx_usage_ip     ON usage_log(ip)',
    'CREATE INDEX IF NOT EXISTS idx_usage_action ON usage_log(action)',
];

/**
 * 懒连 SQLite，返回 PDO；任何原因失败都返回 null（调用方据此静默跳过）。
 * 静态只缓存【成功】的连接，避免每个请求重复打开文件。
 */
function usage_log_open(): ?PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;
    // 不做失败负缓存：php -S / PHP-FPM 是常驻进程，若首连失败就永久不再重试，
    // 一个瞬时的目录/权限抖动会把埋点静默到进程重启为止（后台再也看不到新行）。
    // 本函数全程 fail-safe，重试代价只有一次打开尝试，因此每次调用都试。
    try {
        // 本文件在 lib/，server 根 = dirname(__DIR__)；部署后与 data/ 同级，路径自洽。
        $dbFile = dirname(__DIR__) . '/data/admin.sqlite';
        $dir = dirname($dbFile);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        // 目录不可写就放弃 —— 埋点绝不能反过来影响分发。
        if (!is_dir($dir) || !is_writable($dir)) return null;
        $pdo = new PDO('sqlite:' . $dbFile, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        // 同机并发写：等锁只给 150ms。本函数处在 keybox/manifest 的分发热路径上，
        // 埋点是 best-effort —— 抢不到写锁就该在 150ms 内快速失败，交给下面的
        // fail-safe 直接丢这一行记录，绝不把锁等待（原为 2000ms）传导给分发响应。
        $pdo->exec('PRAGMA busy_timeout = 150');
        // WAL 提升并发，但要求同目录可写（-wal/-shm）；失败就算了，不阻断。
        try { $pdo->exec('PRAGMA journal_mode = WAL'); } catch (Throwable $e) {}
        // WAL 下 synchronous=NORMAL 即可（提交不等 fsync，只压提交时延；崩溃也不损坏库）。
        // 同样是 best-effort：不支持就静默忽略，维持 FULL 也不影响分发。
        try { $pdo->exec('PRAGMA synchronous = NORMAL'); } catch (Throwable $e) {}
        // 入口自愈：表不存在就建（后台可能还没首次访问过）。
        $has = false;
        try {
            $st = $pdo->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='usage_log' LIMIT 1");
            $has = (bool)$st->fetch();
        } catch (Throwable $e) { $has = false; }
        if (!$has) {
            foreach (USAGE_LOG_DDL as $ddl) { $pdo->exec($ddl); }
        }
    } catch (Throwable $e) {
        // 建表/连接失败：丢弃连接，下次调用仍会重试（分发响应优先，这里只静默）。
        $pdo = null;
    }
    return $pdo;
}

/**
 * 记一条领取/分发事件。全程静默，签名与后台写入侧一致。
 *
 * @param string      $action     事件类型（keybox / manifest）
 * @param string      $ip         REMOTE_ADDR 原值
 * @param string      $ua         HTTP_USER_AGENT（截断 200 字节）
 * @param string|null $sha256     本次下发的 keybox sha256（无则 null）
 * @param string      $serialsCsv 证书序列号逗号串（取不到传空串）
 */
function usage_log_event(string $action, string $ip, string $ua, ?string $sha256, string $serialsCsv): void {
    try {
        $pdo = usage_log_open();
        if ($pdo === null) return;
        // UA 可能很长且含控制字符，截断即可；这里用字节截断（不追求多字节安全，日志可读性优先）。
        $ua = substr($ua, 0, 200);
        $st = $pdo->prepare(
            'INSERT INTO usage_log (at, ip, ua, action, keybox_sha256, keybox_serials, note)
             VALUES (?, ?, ?, ?, ?, ?, NULL)'
        );
        $st->execute([gmdate('Y-m-d H:i:s'), $ip, $ua, $action, $sha256, $serialsCsv]);
    } catch (Throwable $e) {
        // 静默吞掉：埋点失败不影响本次 keybox/manifest 下发。
    }
}
