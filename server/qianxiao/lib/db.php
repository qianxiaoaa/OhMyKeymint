<?php
/**
 * 后台数据库层 —— SQLite，单文件库 server/data/admin.sqlite。
 *
 * 为什么用 SQLite 而不是复用 dashboard 的 MySQL：本后台是轻量运维台，
 * 不该假设这台分发主机装了 MySQL、也不该把凭据塞进 web 可达目录。SQLite 零配置、
 * 单文件、和领取日志同库，权限靠目录（data/ 已在 .gitignore）兜住。
 *
 * 自愈建表：首跑（或表被误删）时就地 CREATE TABLE IF NOT EXISTS，schema 与
 * lib/usage_log.php 的 usage_log 表、migrations/2026-10-14-admin-schema.sql 完全一致。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）或 qianxiao/cli.php 纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

// 库文件绝对路径：本文件在 server/qianxiao/lib/，server 根 = dirname(__DIR__, 2)；
// 部署后与 data/ 同级。用 define 而非 const —— const 表达式里不能调 dirname()。
define('DB_PATH', dirname(__DIR__, 2) . '/data/admin.sqlite');

/** 库文件绝对路径（等价于 DB_PATH，函数形式便于别处引用）。 */
function admin_db_file(): string {
    return DB_PATH;
}

/** 设备台账 JSON 目录（与库同侧，data/ 已被 git 忽略）。 */
function admin_devices_dir(): string {
    return dirname(__DIR__, 2) . '/data/devices';
}

/**
 * 全部建表 DDL。领取日志表 usage_log 与 lib/usage_log.php 严格一致，
 * 谁先访问谁建表，另一方用 IF NOT EXISTS 幂等跳过。
 */
function admin_schema(): array {
    return [
        'CREATE TABLE IF NOT EXISTS admin_user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_login_at TEXT,
            created_at TEXT NOT NULL
        )',
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
        // 设备台账：file_path 只存【相对文件名】（<hash>.json，不含目录），运行时由
        // admin_devices_dir() 拼接。存绝对路径会在换目录部署后当场失效而库里记录还在。
        'CREATE TABLE IF NOT EXISTS device (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            imei TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            note TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            file_path TEXT NOT NULL
        )',
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_device_imei ON device(imei)',
        'CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin TEXT NOT NULL,
            act TEXT NOT NULL,
            target TEXT,
            ip TEXT,
            at TEXT NOT NULL
        )',
        'CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at)',
        // 登录失败限流小表（与 dashboard 的 ac_login_fail 等价逻辑，见 auth.php）
        'CREATE TABLE IF NOT EXISTS login_fail (
            ip TEXT NOT NULL,
            at TEXT NOT NULL,
            cnt INTEGER NOT NULL DEFAULT 1
        )',
        'CREATE INDEX IF NOT EXISTS idx_login_fail_ip ON login_fail(ip)',
    ];
}

/** UTC 时间文本，格式沿用仓库既有 Y-m-d H:i:s（见 usage_log.php 说明）。 */
function admin_now(): string {
    return gmdate('Y-m-d H:i:s');
}

/**
 * LIKE 绑定值转义：% 与 _ 是 SQLite LIKE 的元字符，反斜杠是 ESCAPE 符自身。
 * 不转义的话用户搜“%”就能整表扇出（搜索变成越权扫库），输入反斜杠则语义错位。
 * 顺序必须是先转义反斜杠，否则会把随后为 %/_ 新加的反斜杠再转义一遍。调用侧
 * 需在返回值两侧自行补 %，并在 SQL 里给每个 LIKE 紧跟 ESCAPE '\'（ESCAPE 属于
 * LIKE 子句，必须写在 LIKE 之后、AND/OR 之前）。
 */
function admin_like(string $s): string {
    return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $s);
}

/**
 * CSV 单元格防公式注入：Excel / WPS / Google Sheets 会把以 = + - @ 制表符 或
 * 回车开头的单元格当公式执行（可走 DDE 拉起外部程序），而后台导出的 IP / UA /
 * 序列号 / 审计 target 全部源自匿名客户端的 HTTP 头，不信任。非空且首字符命中
 * 者前置单引号，使其退化成文本；仅导出侧中和，库里存的原文不动。
 */
function admin_csv_cell(string $v): string {
    if ($v === '') return $v;
    if (in_array($v[0], ['=', '+', '-', '@', "\t", "\r"], true)) return "'" . $v;
    return $v;
}

/**
 * 懒连 + 首跑建表，返回 PDO；失败返回 null，用 admin_db_init_error() 取友好原因。
 * 最近一次失败原因写进 $GLOBALS['ADMIN_DB_ERR']（静态变量不便跨函数读取）。
 */
function admin_db(): ?PDO {
    static $pdo = null;
    static $ready = false;
    if ($ready) return $pdo;
    $ready = true;
    try {
        $dbFile = admin_db_file();
        $dir = dirname($dbFile);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        if (!is_dir($dir)) {
            $GLOBALS['ADMIN_DB_ERR'] = '数据目录不存在且无法创建：' . $dir;
            return null;
        }
        if (!is_writable($dir)) {
            $GLOBALS['ADMIN_DB_ERR'] = '数据目录不可写（后台需要写 SQLite 与设备台账）：' . $dir . '，请 chown 给运行 PHP 的用户并给 0750';
            return null;
        }
        $pdo = new PDO('sqlite:' . $dbFile, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('PRAGMA busy_timeout = 2000');
        try { $pdo->exec('PRAGMA journal_mode = WAL'); } catch (Throwable $e) {}
        foreach (admin_schema() as $ddl) { $pdo->exec($ddl); }
    } catch (Throwable $e) {
        $pdo = null;
        $GLOBALS['ADMIN_DB_ERR'] = '数据库初始化失败：' . $e->getMessage();
    }
    return $pdo;
}

/** 上一次 admin_db() 失败的友好原因（无错误返回空串）。 */
function admin_db_init_error(): string {
    return (string)($GLOBALS['ADMIN_DB_ERR'] ?? '');
}
