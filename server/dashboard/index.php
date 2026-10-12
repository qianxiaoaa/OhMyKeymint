<?php
/**
 * yypm 反挂管理面板。
 *
 * 只做一件事：看被封的设备码、解封。刻意【不下发任何命令】——
 * 设备端的行为完全由设备自己决定，面板只影响「这台设备是否被记录为封禁」。
 *
 * 安全要点（上一版踩过的坑都在这）：
 *  1. 数据库凭据放在网站根目录【之外】，不在 web 可达范围
 *  2. 口令用 bcrypt 存在 MySQL 里，磁盘上没有任何明文口令文件
 *     —— 上一版把 pass.txt 放在 /dashboard/ 下，nginx 会直接当静态文件发出去
 *  3. 登录失败按 IP 限流，防爆破
 *  4. 写操作带 CSRF token
 *  5. 登录后 session_regenerate_id，Cookie 带 HttpOnly/Secure/SameSite
 *  6. 全部 PDO 预处理，不拼 SQL
 */
declare(strict_types=1);

const MAX_FAIL = 5;          // 15 分钟内最多失败几次
const FAIL_WIN = 900;        // 限流窗口（秒）

$cfgFile = '/path/to/yypm-private/db.php';
if (!is_file($cfgFile)) {
    http_response_code(500);
    exit('缺少私有配置 ' . htmlspecialchars($cfgFile, ENT_QUOTES, 'UTF-8'));
}
$cfg = require $cfgFile;

try {
    $pdo = new PDO($cfg['dsn'], $cfg['user'], $cfg['pass'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    exit('数据库连接失败');
}

// ---- 会话 ----
session_set_cookie_params([
    'httponly' => true,
    'secure'   => !empty($_SERVER['HTTPS']),
    'samesite' => 'Strict',
    'path'     => '/dashboard/',
]);
session_start();

$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function failsRecent(PDO $pdo, string $ip): int {
    $st = $pdo->prepare('SELECT COUNT(*) c FROM ac_login_fail WHERE ip = ? AND at > (NOW() - INTERVAL ? SECOND)');
    $st->execute([$ip, FAIL_WIN]);
    return (int)($st->fetch()['c'] ?? 0);
}
function failNote(PDO $pdo, string $ip): void {
    $pdo->prepare('INSERT INTO ac_login_fail (ip, at) VALUES (?, NOW())')->execute([$ip]);
    // 顺手清掉过期的
    $pdo->prepare('DELETE FROM ac_login_fail WHERE at < (NOW() - INTERVAL ? SECOND)')->execute([FAIL_WIN * 4]);
}

/**
 * 操作审计：登录成败、封禁、解封都留痕（谁、什么时候、对哪个设备码、从哪个 IP）。
 * 审计失败（比如迁移没跑）只自愈一次，绝不打断正在进行的操作。
 */
function audit(PDO $pdo, string $admin, string $act, ?string $code, string $ip): void {
    try {
        $pdo->prepare('INSERT INTO ac_audit (admin, act, code, ip, at) VALUES (?,?,?,?,NOW())')
            ->execute([$admin, $act, $code, $ip]);
    } catch (Throwable $e) {
        try {
            $pdo->exec('CREATE TABLE IF NOT EXISTS ac_audit (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                admin VARCHAR(32) NOT NULL,
                act VARCHAR(16) NOT NULL,
                code CHAR(16) DEFAULT NULL,
                ip VARCHAR(45) DEFAULT NULL,
                at DATETIME NOT NULL,
                INDEX idx_at (at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
            $pdo->prepare('INSERT INTO ac_audit (admin, act, code, ip, at) VALUES (?,?,?,?,NOW())')
                ->execute([$admin, $act, $code, $ip]);
        } catch (Throwable $e2) { }
    }
}

$err = '';
$authed = !empty($_SESSION['admin']);

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ./');
    exit;
}

if (!$authed && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['pass'])) {
    if (failsRecent($pdo, $ip) >= MAX_FAIL) {
        $err = '失败次数过多，请 15 分钟后再试';
    } else {
        $u = trim((string)($_POST['user'] ?? ''));
        $st = $pdo->prepare('SELECT pass_hash FROM ac_admin WHERE user = ? LIMIT 1');
        $st->execute([$u]);
        $row = $st->fetch();
        if ($row && password_verify((string)$_POST['pass'], (string)$row['pass_hash'])) {
            session_regenerate_id(true);
            $_SESSION['admin'] = $u;
            $_SESSION['csrf']  = bin2hex(random_bytes(16));
            audit($pdo, $u, 'login', null, $ip);
            header('Location: ./');
            exit;
        }
        failNote($pdo, $ip);
        audit($pdo, $u === '' ? '-' : $u, 'login_fail', null, $ip);
        $err = '用户名或口令不对';
    }
}

$authed = !empty($_SESSION['admin']);

// ---- 写操作 ----
if ($authed && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['act'])) {
    if (!hash_equals((string)$_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('CSRF token 不匹配');
    }
    $code = preg_replace('/[^a-f0-9]/', '', strtolower((string)($_POST['code'] ?? '')));
    if (is_string($code) && strlen($code) === 16) {
        if ($_POST['act'] === 'unban') {
            $pdo->prepare('DELETE FROM ac_ban WHERE code = ?')->execute([$code]);
            audit($pdo, (string)$_SESSION['admin'], 'unban', $code, $ip);
        } elseif ($_POST['act'] === 'ban') {
            $pdo->prepare('INSERT INTO ac_ban (code,reason,hits,ip,banned_at,banned_by) VALUES (?,?,?,?,NOW(),?)
                           ON DUPLICATE KEY UPDATE reason=VALUES(reason), banned_at=NOW(), banned_by=VALUES(banned_by)')
                ->execute([$code, '手动封禁', '(手动)', $ip, 'manual']);
            audit($pdo, (string)$_SESSION['admin'], 'ban', $code, $ip);
        }
    }
    header('Location: ./');
    exit;
}

$ban    = $authed ? $pdo->query('SELECT * FROM ac_ban ORDER BY banned_at DESC LIMIT 500')->fetchAll() : [];
$recent = $authed ? $pdo->query('SELECT * FROM ac_report ORDER BY id DESC LIMIT 60')->fetchAll() : [];
$total  = $authed ? (int)($pdo->query('SELECT COUNT(*) c FROM ac_ban')->fetch()['c'] ?? 0) : 0;
// 审计表可能还没建（迁移未跑）：读不到就显示空，绝不拖垮面板
$audit  = [];
if ($authed) {
    try { $audit = $pdo->query('SELECT * FROM ac_audit ORDER BY id DESC LIMIT 50')->fetchAll(); }
    catch (Throwable $e) { $audit = []; }
}
?><!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>yypm 反挂面板</title>
<style>
:root{--bg:#111318;--card:#1b1e24;--fg:#e6e1e5;--dim:#a8a2a8;--line:#33363d;--red:#f2b8b5;--redbg:#8c1d18;--grn:#b7f0c0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:12px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.tag.red{background:var(--redbg);color:var(--red)}
.tag.grn{background:#1e3a24;color:var(--grn)}
button{background:#2a2e36;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:6px 14px;font-size:13px;cursor:pointer}
button:hover{background:#343943}
button.pri{background:#4a4458;border-color:#5c5470}
input{background:#0e1015;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:8px 12px;font-size:14px;width:100%}
.muted{color:var(--dim);font-size:12.5px}
.note{color:var(--dim);font-size:12.5px;border-left:2px solid var(--line);padding-left:10px;margin:10px 0}
.empty{color:var(--dim);padding:18px 0;text-align:center}
.err{color:var(--red);margin-top:8px}
</style></head><body><div class="wrap">
<h1>yypm 反挂面板</h1>
<div class="sub">只做封禁记录，不下发任何命令，不干涉模块其它行为</div>
<?php if (!$authed): ?>
  <div class="card" style="max-width:380px">
    <form method="post" autocomplete="off">
      <input name="user" placeholder="用户名" autofocus style="margin-bottom:8px">
      <input type="password" name="pass" placeholder="口令">
      <div style="margin-top:12px"><button class="pri" type="submit">进入</button></div>
    </form>
    <?php if ($err): ?><div class="err"><?=h($err)?></div><?php endif; ?>
    <div class="note">口令以 bcrypt 存在 MySQL 里，服务器磁盘上没有明文口令文件。</div>
  </div>
<?php else: ?>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <b>已封禁设备 <span class="muted">（<?=$total?> 台）</span></b>
      <span><span class="muted" style="margin-right:10px"><?=h((string)$_SESSION['admin'])?></span><a href="?logout=1"><button>退出</button></a></span>
    </div>
    <?php if (!$ban): ?>
      <div class="empty">还没有设备被封禁</div>
    <?php else: ?>
      <table><thead><tr><th>设备码</th><th>封禁时间</th><th>来源</th><th>命中</th><th>IP</th><th></th></tr></thead><tbody>
      <?php foreach ($ban as $r): ?>
        <tr>
          <td><code><?=h($r['code'])?></code></td>
          <td class="muted"><?=h($r['banned_at'])?></td>
          <td><span class="tag <?=$r['banned_by']==='auto'?'red':'grn'?>"><?=h($r['banned_by'])?></span></td>
          <td class="muted"><?=h($r['hits'])?></td>
          <td class="muted"><?=h($r['ip'])?></td>
          <td style="text-align:right">
            <form method="post" onsubmit="return confirm('解除这台设备的封禁？')">
              <input type="hidden" name="act" value="unban">
              <input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>">
              <input type="hidden" name="code" value="<?=h($r['code'])?>">
              <button type="submit">解封</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody></table>
    <?php endif; ?>
  </div>

  <div class="card">
    <b>手动封禁</b>
    <form method="post" style="display:flex;gap:10px;margin-top:10px">
      <input type="hidden" name="act" value="ban">
      <input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>">
      <input name="code" placeholder="16 位设备码（十六进制）" style="flex:1" pattern="[0-9a-fA-F]{16}">
      <button class="pri" type="submit">封禁</button>
    </form>
    <div class="note">设备码是 <code>sha256(序列号+机型+指纹)</code> 的前 16 位，不落原始隐私信息。</div>
  </div>

  <div class="card">
    <b>最近上报</b>
    <div class="muted" style="margin-bottom:8px">时间 / 设备码 / 事件 / 命中 / IP</div>
    <?php if (!$recent): ?>
      <div class="empty">还没有上报记录</div>
    <?php else: ?>
      <table><tbody>
      <?php foreach ($recent as $r): ?>
        <tr>
          <td class="muted" style="white-space:nowrap"><?=h($r['at'])?></td>
          <td><code><?=h($r['code'])?></code></td>
          <td><span class="tag <?=$r['ev']==='expire'?'red':'grn'?>"><?=h($r['ev'])?></span></td>
          <td class="muted"><?=h($r['hits'])?></td>
          <td class="muted"><?=h($r['ip'])?></td>
        </tr>
      <?php endforeach; ?>
      </tbody></table>
    <?php endif; ?>
  </div>

  <div class="card">
    <b>操作审计</b>
    <div class="muted" style="margin-bottom:8px">时间 / 管理员 / 动作 / 设备码 / IP（最近 50 条）</div>
    <?php if (!$audit): ?>
      <div class="empty">还没有审计记录</div>
    <?php else: ?>
      <table><tbody>
      <?php foreach ($audit as $r): ?>
        <tr>
          <td class="muted" style="white-space:nowrap"><?=h($r['at'])?></td>
          <td><?=h($r['admin'])?></td>
          <td><span class="tag <?=in_array($r['act'], ['unban','login'], true)?'grn':'red'?>"><?=h($r['act'])?></span></td>
          <td><code><?=h((string)$r['code'])?></code></td>
          <td class="muted"><?=h((string)$r['ip'])?></td>
        </tr>
      <?php endforeach; ?>
      </tbody></table>
    <?php endif; ?>
  </div>
<?php endif; ?>
</div></body></html>
