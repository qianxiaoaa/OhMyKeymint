<?php
/**
 * 账号页 —— admin_user 的增删改（bcrypt 口令、启禁、重置口令）。
 * 可用变量：$pdo、$currentUser。写操作 POST + CSRF（index.php 已校验）。
 *
 * 约束（防自我锁死）：不能禁用/删除当前登录账号；系统必须始终保留至少 1 个
 * enabled 账号——执行会减少启用数的操作前先 COUNT 校验，且 COUNT 与写操作关在同一
 * 事务里用 BEGIN IMMEDIATE 先占写锁（见下方 toggle/del）。全部写审计。
 * 口令只在 POST body 里短暂存在，落库即 password_hash，绝不写文件/回显。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

function users_enabled_count(PDO $pdo): int {
    $st = $pdo->query('SELECT COUNT(*) c FROM admin_user WHERE enabled = 1');
    return (int)($st->fetch()['c'] ?? 0);
}

$flash = '';
$flashType = 'ok';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $act = (string)($_POST['act'] ?? '');

    if ($act === 'add') {
        $u = trim((string)($_POST['user'] ?? ''));
        $p = (string)($_POST['pass'] ?? '');
        if (!preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $u)) {
            $flash = '用户名需为 3-32 位，仅限字母/数字/._-'; $flashType = 'bad';
        } elseif (strlen($p) < 10) {
            $flash = '口令至少 10 位'; $flashType = 'bad';
        } else {
            try {
                $st = $pdo->prepare('INSERT INTO admin_user (user, pass_hash, enabled, created_at) VALUES (?,?,1,?)');
                $st->execute([$u, password_hash($p, PASSWORD_BCRYPT), admin_now()]);
                auth_audit($pdo, (string)$currentUser, 'user_add', 'user=' . $u);
                $flash = '已添加账号 ' . $u;
            } catch (Throwable $e) {
                $flash = '添加失败（用户名可能已存在）'; $flashType = 'bad';
            }
        }
    }

    if ($act === 'toggle') {
        $u = (string)($_POST['user'] ?? '');
        $st = $pdo->prepare('SELECT enabled FROM admin_user WHERE user = ? LIMIT 1');
        $st->execute([$u]);
        $row = $st->fetch();
        if (!$row) {
            $flash = '账号不存在'; $flashType = 'bad';
        } elseif ($u === $currentUser) {
            $flash = '不能禁用当前登录账号'; $flashType = 'bad';
        } else {
            // 原子防锁死：BEGIN IMMEDIATE 先拿写锁，把「重读当前状态 → COUNT → 写 → COMMIT」
            // 关进同一事务。少了这道锁，两个并发请求能各自数到「还剩 1 个启用账号」
            // 再互相禁用，把系统锁成 0 个可用账号；事务内重读 enabled 也顺带消掉
            // 加锁前预读的过期值。抢不到写锁会按 busy_timeout 等待后抛错，整事务回滚。
            $done = false; $blocked = false; $gone = false;
            try {
                $pdo->exec('BEGIN IMMEDIATE');
                $st2 = $pdo->prepare('SELECT enabled FROM admin_user WHERE user = ? LIMIT 1');
                $st2->execute([$u]);
                $cur2 = $st2->fetch();
                if (!$cur2) {
                    $gone = true;                       // 事务外被并发删了
                } else {
                    $cur = (int)$cur2['enabled'];
                    $new = $cur === 1 ? 0 : 1;
                    if ($cur === 1 && users_enabled_count($pdo) <= 1) {
                        $blocked = true;                 // 要禁用的是最后一个启用账号
                    } else {
                        $pdo->prepare('UPDATE admin_user SET enabled = ? WHERE user = ?')->execute([$new, $u]);
                        $done = true;
                    }
                }
                $pdo->exec('COMMIT');
            } catch (Throwable $e) {
                try { $pdo->exec('ROLLBACK'); } catch (Throwable $e2) {}
                $flash = '数据库正忙（有其他写入持锁），请片刻后重试'; $flashType = 'bad';
            }
            if ($gone) {
                $flash = '账号不存在'; $flashType = 'bad';
            } elseif ($blocked) {
                $flash = '系统必须保留至少 1 个启用账号，无法禁用最后一个'; $flashType = 'bad';
            } elseif ($done) {
                auth_audit($pdo, (string)$currentUser, $new ? 'user_enable' : 'user_disable', 'user=' . $u);
                $flash = $new ? '已启用 ' . $u : '已禁用 ' . $u;
            }
        }
    }

    if ($act === 'reset') {
        $u = (string)($_POST['user'] ?? '');
        $p = (string)($_POST['pass'] ?? '');
        if (strlen($p) < 10) {
            $flash = '新口令至少 10 位'; $flashType = 'bad';
        } else {
            $st = $pdo->prepare('SELECT 1 FROM admin_user WHERE user = ? LIMIT 1');
            $st->execute([$u]);
            if (!$st->fetch()) {
                $flash = '账号不存在'; $flashType = 'bad';
            } else {
                $pdo->prepare('UPDATE admin_user SET pass_hash = ? WHERE user = ?')
                    ->execute([password_hash($p, PASSWORD_BCRYPT), $u]);
                auth_audit($pdo, (string)$currentUser, 'user_reset', 'user=' . $u);
                $flash = '已重置 ' . $u . ' 的口令';
            }
        }
    }

    if ($act === 'del') {
        $u = (string)($_POST['user'] ?? '');
        $confirmed = (string)($_POST['confirm'] ?? '') === 'yes';
        if (!$confirmed) {
            $flash = '删除需勾选确认'; $flashType = 'bad';
        } elseif ($u === $currentUser) {
            $flash = '不能删除当前登录账号'; $flashType = 'bad';
        } else {
            $st = $pdo->prepare('SELECT enabled FROM admin_user WHERE user = ? LIMIT 1');
            $st->execute([$u]);
            $row = $st->fetch();
            if (!$row) {
                $flash = '账号不存在'; $flashType = 'bad';
            } else {
                // 「是否最后一个启用账号」不在这里判（加锁前的 COUNT 会过期），
                // 统一交给下面事务内的重读 + COUNT 决定，提示文案不变。
                // 同 toggle：COUNT 校验与 DELETE 关进同一个 BEGIN IMMEDIATE 事务。
                // 两个并发删各自过“仅剩 1 个启用账号”校验时会把最后的可用账号删完；
                // 事务内重读 enabled，避开加锁前预读的过期值。
                $done = false; $blocked = false; $gone = false;
                try {
                    $pdo->exec('BEGIN IMMEDIATE');
                    $st2 = $pdo->prepare('SELECT enabled FROM admin_user WHERE user = ? LIMIT 1');
                    $st2->execute([$u]);
                    $cur2 = $st2->fetch();
                    if (!$cur2) {
                        $gone = true;                       // 事务外被并发删了
                    } elseif ((int)$cur2['enabled'] === 1 && users_enabled_count($pdo) <= 1) {
                        $blocked = true;
                    } else {
                        $pdo->prepare('DELETE FROM admin_user WHERE user = ?')->execute([$u]);
                        $done = true;
                    }
                    $pdo->exec('COMMIT');
                } catch (Throwable $e) {
                    try { $pdo->exec('ROLLBACK'); } catch (Throwable $e2) {}
                    $flash = '数据库正忙（有其他写入持锁），请片刻后重试'; $flashType = 'bad';
                }
                if ($gone) {
                    $flash = '账号不存在'; $flashType = 'bad';
                } elseif ($blocked) {
                    $flash = '系统必须保留至少 1 个启用账号，无法删除最后一个启用账号'; $flashType = 'bad';
                } elseif ($done) {
                    auth_audit($pdo, (string)$currentUser, 'user_del', 'user=' . $u);
                    $flash = '已删除账号 ' . $u;
                }
            }
        }
    }

    if ($flash !== '') {
        $_SESSION['flash'] = ['m' => $flash, 't' => $flashType];
    }
    header('Location: ?page=users');
    exit;
}

$users = [];
try {
    $users = $pdo->query('SELECT user, enabled, last_login_at, created_at FROM admin_user ORDER BY id ASC')->fetchAll();
} catch (Throwable $e) { $users = []; }

render_header('账号', 'users');
$fl = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
if ($fl) echo flash((string)$fl['m'], (string)($fl['t'] ?? 'ok'));
?>
<div class="card"><h2>添加账号</h2>
  <form method="post" action="?page=users">
    <?=csrf_field()?>
    <input type="hidden" name="act" value="add">
    <div class="grid" style="margin-bottom:10px">
      <label class="muted">用户名<input name="user" required autocomplete="username"></label>
      <label class="muted">口令（≥10 位）<input type="password" name="pass" required autocomplete="new-password"></label>
    </div>
    <button type="submit" class="pri">添加</button>
  </form>
</div>

<div class="card"><h2>账号列表</h2>
  <?php
  $tableRows = array_map(function ($r) use ($currentUser) {
      $u = (string)$r['user'];
      $enabled = (int)$r['enabled'] === 1;
      $isSelf = ($u === $currentUser);
      $actions = '';
      if (!$isSelf) {
          $actions .= '<form method="post" action="?page=users" style="display:inline">'
              . csrf_field() . '<input type="hidden" name="act" value="toggle">'
              . '<input type="hidden" name="user" value="' . e($u) . '">'
              . '<button type="submit">' . ($enabled ? '禁用' : '启用') . '</button></form> ';
          $actions .= '<form method="post" action="?page=users" style="display:inline"'
              . ' onsubmit="return confirm(\'确认删除该账号？\')">'
              . csrf_field() . '<input type="hidden" name="act" value="del">'
              . '<input type="hidden" name="user" value="' . e($u) . '">'
              . '<label style="font-size:11px;color:var(--dim)"><input type="checkbox" name="confirm" value="yes" style="width:auto">确认</label> '
              . '<button type="submit" class="danger">删除</button></form>';
      } else {
          $actions = '<span class="muted">（当前登录）</span>';
      }
      // 重置口令：允许对任意账号（含自己）设置新口令
      $reset = '<form method="post" action="?page=users" style="display:flex;gap:6px;align-items:center">'
          . csrf_field() . '<input type="hidden" name="act" value="reset">'
          . '<input type="hidden" name="user" value="' . e($u) . '">'
          . '<input type="password" name="pass" placeholder="新口令 ≥10 位" style="width:180px" autocomplete="new-password">'
          . '<button type="submit">重置</button></form>';
      return [
          ['html' => '<code>' . e($u) . '</code>'],
          ['html' => $enabled ? '<span class="tag grn">启用</span>' : '<span class="tag red">禁用</span>'],
          (string)($r['last_login_at'] ?? ''),
          (string)($r['created_at'] ?? ''),
          ['html' => $actions],
          ['html' => $reset],
      ];
  }, $users);
  echo table(['用户名', '状态', '最后登录(UTC)', '创建(UTC)', '启禁/删除', '重置口令'], $tableRows);
  ?>
  <div class="note">口令以 bcrypt 存库，磁盘无明文；重置需直接设定新口令（后台不可查看原口令）。</div>
</div>
<?php
render_footer();
