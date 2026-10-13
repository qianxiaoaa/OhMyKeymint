<?php
/**
 * 后台命令行助手 —— 只允许 php-cli 运行（Web 环境拿不到 $argv，也绝不该被 web 访问）。
 *
 * 子命令：
 *   init-admin <user> <pass> [--force]   仅当 admin_user 为空时建首个管理员；--force 覆盖同名
 *   passwd     <user> <newpass>          改指定账号口令
 *   prune-logs <days>                    删除早于 N 天的 usage_log，打印删除行数
 *
 * 红线：口令只经 password_hash 落库，脚本不回显、不写任何明文口令文件；不碰私钥。
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

// cli.php 自己靠上面的 PHP_SAPI 守卫（Web 环境进不来），不必再查 ADMIN_BOOT；
// 但它 require 的 lib/db.php 有入口守卫，所以这里先补上入口标记。
define('ADMIN_BOOT', 1);

require_once __DIR__ . '/lib/db.php';

$args = $argv;
array_shift($args); // 去掉脚本名
$cmd = array_shift($args) ?? '';

/** 抽掉 --force 之类的选项，返回 [位置参数, 选项集合]。 */
function cli_split(array $args): array {
    $pos = [];
    $opts = [];
    foreach ($args as $a) {
        if (strncmp((string)$a, '--', 2) === 0) $opts[substr((string)$a, 2)] = true;
        else $pos[] = (string)$a;
    }
    return [$pos, $opts];
}

$pdo = admin_db();
if ($pdo === null) {
    fwrite(STDERR, '数据库不可用：' . admin_db_init_error() . "\n");
    exit(1);
}

switch ($cmd) {
    case 'init-admin': {
        list($pos, $opts) = cli_split($args);
        $user = trim((string)($pos[0] ?? ''));
        $pass = (string)($pos[1] ?? '');
        if ($user === '' || $pass === '') {
            fwrite(STDERR, "用法: php cli.php init-admin <user> <pass> [--force]\n");
            exit(2);
        }
        if (!preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $user)) {
            fwrite(STDERR, "用户名需 3-32 位，仅限字母/数字/._-\n");
            exit(2);
        }
        if (strlen($pass) < 10) {
            fwrite(STDERR, "口令至少 10 位\n");
            exit(2);
        }
        $count = (int)($pdo->query('SELECT COUNT(*) c FROM admin_user')->fetch()['c'] ?? 0);
        $hash = password_hash($pass, PASSWORD_BCRYPT);
        if ($count === 0) {
            $pdo->prepare('INSERT INTO admin_user (user, pass_hash, enabled, created_at) VALUES (?,?,1,?)')
                ->execute([$user, $hash, admin_now()]);
            echo "已创建管理员 {$user}\n";
        } elseif (!empty($opts['force'])) {
            // --force：表非空也允许。同名则改密，否则新增。
            $st = $pdo->prepare('SELECT 1 FROM admin_user WHERE user = ? LIMIT 1');
            $st->execute([$user]);
            if ($st->fetch()) {
                $pdo->prepare('UPDATE admin_user SET pass_hash = ?, enabled = 1 WHERE user = ?')->execute([$hash, $user]);
                echo "已存在同名账号，--force 覆盖口令并置为启用：{$user}\n";
            } else {
                $pdo->prepare('INSERT INTO admin_user (user, pass_hash, enabled, created_at) VALUES (?,?,1,?)')
                    ->execute([$user, $hash, admin_now()]);
                echo "--force 新增管理员：{$user}\n";
            }
        } else {
            fwrite(STDERR, "admin_user 已有 {$count} 个账号；如确需再建请加 --force\n");
            exit(3);
        }
        exit(0);
    }

    case 'passwd': {
        list($pos) = cli_split($args);
        $user = trim((string)($pos[0] ?? ''));
        $pass = (string)($pos[1] ?? '');
        if ($user === '' || strlen($pass) < 10) {
            fwrite(STDERR, "用法: php cli.php passwd <user> <newpass>（口令≥10 位）\n");
            exit(2);
        }
        $st = $pdo->prepare('SELECT 1 FROM admin_user WHERE user = ? LIMIT 1');
        $st->execute([$user]);
        if (!$st->fetch()) {
            fwrite(STDERR, "账号不存在：{$user}\n");
            exit(3);
        }
        $pdo->prepare('UPDATE admin_user SET pass_hash = ? WHERE user = ?')
            ->execute([password_hash($pass, PASSWORD_BCRYPT), $user]);
        echo "已更新口令：{$user}\n";
        exit(0);
    }

    case 'prune-logs': {
        list($pos) = cli_split($args);
        $days = (int)($pos[0] ?? 0);
        if ($days <= 0) {
            fwrite(STDERR, "用法: php cli.php prune-logs <days>\n");
            exit(2);
        }
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days * 86400);
        $st = $pdo->prepare('DELETE FROM usage_log WHERE at < ?');
        $st->execute([$cutoff]);
        echo "已删除 usage_log 早于 {$cutoff}(UTC) 的 " . $st->rowCount() . " 行\n";
        exit(0);
    }

    default:
        fwrite(STDERR, "未知命令。可用：init-admin / passwd / prune-logs\n");
        exit(2);
}
