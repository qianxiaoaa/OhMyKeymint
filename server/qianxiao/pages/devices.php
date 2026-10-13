<?php
/**
 * 设备台账页 —— 增删改查 device 表，且每次写「双写」到 data/devices/<hash>.json。
 * 可用变量：$pdo、$currentUser、$ip。写操作 POST，CSRF 已在 index.php 统一校验。
 *
 * file_path 一律服务端生成（sha256(imei) 前 16 位 + .json），用户输入绝对不进路径；库里只存
 * 【相对文件名】，运行时用 admin_devices_dir() 拼接 —— 绝对路径在换目录部署后会当场失效。
 * 双写顺序（并发窗口收口）：先 INSERT 抢 UNIQUE，撞唯一索引即中止（此时磁盘还未写），
 * 提交成功后再写档案；写文件失败则删掉本行，不留孤儿记录。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

$devDir = admin_devices_dir();
if (!is_dir($devDir)) @mkdir($devDir, 0755, true);

/** 服务端生成台账档案的【相对文件名】（sha256(imei) 前 16 位），入库只存这个。 */
function dev_file_name(string $imei): string {
    return substr(hash('sha256', $imei), 0, 16) . '.json';
}

/**
 * 相对文件名 -> 绝对路径。目录名每次现算（admin_devices_dir()），后台整体搬迁部署
 * 目录后依旧能命中档案；basename() 兜一层，防库里的值被人为写坏后跳出目录。
 */
function dev_file_path(string $name): string {
    return admin_devices_dir() . '/' . basename($name);
}

/** 台账记录 -> JSON 文本（固定 flags，便于人工 diff / 二次消费）。 */
function dev_json(array $rec): string {
    return (string)json_encode($rec, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

/** 字符长度/截断：优先 mbstring，缺失时退回按字节（不引入已废弃的 utf8_decode）。 */
function dev_len(string $s): int {
    return function_exists('mb_strlen') ? (int)mb_strlen($s) : (int)strlen($s);
}
function dev_clamp(string $s, int $n): string {
    return function_exists('mb_substr') ? (string)mb_substr($s, 0, $n) : (string)substr($s, 0, $n);
}

$flash = '';
$flashType = 'ok';

// ================= 写操作 =================
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $act = (string)($_POST['act'] ?? '');

    if ($act === 'add') {
        $imei = trim((string)($_POST['imei'] ?? ''));
        $fp   = trim((string)($_POST['fingerprint'] ?? ''));
        $note = dev_clamp(trim((string)($_POST['note'] ?? '')), 200);
        if (!preg_match('/^(?:[0-9]{14,16}|[0-9A-Fa-f]{8})$/', $imei)) {
            $flash = 'IMEI 需为 14-16 位数字，或 8 位十六进制 MEID'; $flashType = 'bad';
        } elseif ($fp === '' || dev_len($fp) > 300) {
            $flash = '指纹不能为空且不超过 300 字符'; $flashType = 'bad';
        } elseif (!is_dir($devDir) || !is_writable($devDir)) {
            $flash = '台账目录不可写：' . $devDir; $flashType = 'bad';
        } else {
            $exists = $pdo->prepare('SELECT 1 FROM device WHERE imei = ? LIMIT 1');
            $exists->execute([$imei]);
            if ($exists->fetch()) {
                $flash = '该 IMEI 已存在于台账'; $flashType = 'bad';
            } else {
                $now  = admin_now();
                $name = dev_file_name($imei);
                // 顺序调整（消除 TOCTOU 误删窗口）：同名并发 add 时，两个请求都能过
                // 上面的存在性预检查；原先「先写文件、再提交 DB」会让撞 UNIQUE 的后行者
                // 回滚时 unlink 掉同名路径 —— 那正是先行者刚写好的档案。改成先 INSERT：
                // 唯一索引冲突在 execute 就抛出中止，此刻磁盘上还没有任何写入，谁也不会删。
                $inserted = false;
                try {
                    $pdo->beginTransaction();
                    $st = $pdo->prepare('INSERT INTO device (imei, fingerprint, note, enabled, created_at, file_path)'
                        . ' VALUES (?,?,?,1,?,?)');
                    $st->execute([$imei, $fp, $note, $now, $name]);
                    $pdo->commit();
                    $inserted = true;   // 事务已落盘，接下来才写档案文件
                } catch (Throwable $e) {
                    if ($pdo->inTransaction()) $pdo->rollBack();
                    $flash = '入库失败（IMEI 可能已被并发提交占用）：' . $e->getMessage(); $flashType = 'bad';
                }
                if ($inserted) {
                    // DB 提交成功后再写档案；写失败就删掉本行（imei 唯一索引保证只命中自己的行），
                    // 宁可少一个台账，也不留一条指向空文件的记录。
                    $rec = ['imei' => $imei, 'fingerprint' => $fp, 'note' => $note, 'enabled' => 1, 'created_at' => $now];
                    if (@file_put_contents(dev_file_path($name), dev_json($rec)) === false) {
                        try {
                            $pdo->prepare('DELETE FROM device WHERE imei = ?')->execute([$imei]);
                        } catch (Throwable $e) {
                            // 行没删掉也只是多一条待人工清理的记录（档案可重建），不阻断响应
                        }
                        $flash = '台账文件写入失败，已回滚入库'; $flashType = 'bad';
                    } else {
                        auth_audit($pdo, (string)$currentUser, 'device_add', 'imei=' . $imei);
                        $flash = '已添加设备 ' . $imei;
                    }
                }
            }
        }
    }

    if ($act === 'toggle') {
        $id = (int)($_POST['id'] ?? 0);
        $st = $pdo->prepare('SELECT * FROM device WHERE id = ? LIMIT 1');
        $st->execute([$id]);
        $d = $st->fetch();
        if (!$d) {
            $flash = '设备不存在'; $flashType = 'bad';
        } else {
            $newEnabled = ((int)$d['enabled'] === 1) ? 0 : 1;
            try {
                $pdo->prepare('UPDATE device SET enabled = ? WHERE id = ?')->execute([$newEnabled, $id]);
                // 同步重写 JSON 的 enabled 字段（文件不存在则按当前 DB 值重建）
                // 库里 file_path 是相对文件名，目录由 admin_devices_dir() 现算拼接
                $path = dev_file_path((string)$d['file_path']);
                $rec = ['imei' => (string)$d['imei'], 'fingerprint' => (string)$d['fingerprint'],
                    'note' => (string)($d['note'] ?? ''), 'enabled' => $newEnabled, 'created_at' => (string)$d['created_at']];
                if (is_dir($devDir) && @file_put_contents($path, dev_json($rec)) === false) {
                    $flash = 'DB 已更新，但台账文件写入失败：' . $path; $flashType = 'bad';
                } else {
                    auth_audit($pdo, (string)$currentUser, $newEnabled ? 'device_enable' : 'device_disable', 'imei=' . (string)$d['imei']);
                    $flash = $newEnabled ? '已启用' : '已禁用';
                }
            } catch (Throwable $e) {
                $flash = '更新失败：' . $e->getMessage(); $flashType = 'bad';
            }
        }
    }

    if ($act === 'del') {
        $id = (int)($_POST['id'] ?? 0);
        $confirmed = (string)($_POST['confirm'] ?? '') === 'yes';
        if (!$confirmed) {
            $flash = '删除需勾选确认'; $flashType = 'bad';
        } else {
            $st = $pdo->prepare('SELECT * FROM device WHERE id = ? LIMIT 1');
            $st->execute([$id]);
            $d = $st->fetch();
            if (!$d) {
                $flash = '设备不存在'; $flashType = 'bad';
            } else {
                try {
                    $pdo->beginTransaction();
                    $pdo->prepare('DELETE FROM device WHERE id = ?')->execute([$id]);
                    $pdo->commit();
                    @unlink(dev_file_path((string)$d['file_path']));   // DB 成功后删文件（目录现算）；删不掉不影响台账一致性
                    auth_audit($pdo, (string)$currentUser, 'device_del', 'imei=' . (string)$d['imei']);
                    $flash = '已删除设备 ' . (string)$d['imei'];
                } catch (Throwable $e) {
                    if ($pdo->inTransaction()) $pdo->rollBack();
                    $flash = '删除失败：' . $e->getMessage(); $flashType = 'bad';
                }
            }
        }
    }

    if ($flash !== '') {
        $_SESSION['flash'] = ['m' => $flash, 't' => $flashType];   // PRG：跨跳转用会话带一次提示
    }
    header('Location: ?page=devices' . (isset($_POST['dq']) && trim((string)$_POST['dq']) !== '' ? '&dq=' . urlencode(trim((string)$_POST['dq'])) : ''));
    exit;
}

// ================= 列表 + 搜索 =================
$dq = trim((string)($_GET['dq'] ?? ''));
$rows = [];
$bind = [];
$where = '';
if ($dq !== '') {
    // 搜索词先过 admin_like() 转义 LIKE 元字符（% _ 反斜杠）；ESCAPE '\' 紧跟每个 LIKE
    // 之后、OR 之前（它属 LIKE 子句，不能放到 WHERE 末尾）。
    $l = '%' . admin_like($dq) . '%';
    $where = " WHERE imei LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\'";
    $bind = [$l, $l, $l];
}
try {
    $st = $pdo->prepare('SELECT * FROM device' . $where . ' ORDER BY id DESC LIMIT 500');
    $st->execute($bind);
    $rows = $st->fetchAll();
} catch (Throwable $e) { $rows = []; }

render_header('设备台账', 'devices');
$fl = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
if ($fl) echo flash((string)$fl['m'], (string)($fl['t'] ?? 'ok'));
?>
<div class="card"><h2>添加设备</h2>
  <form method="post" action="?page=devices">
    <?=csrf_field()?>
    <input type="hidden" name="act" value="add">
    <div class="grid" style="margin-bottom:10px">
      <label class="muted">IMEI（14-16 位数字 / 8 位十六进制 MEID）<input name="imei" required style="width:100%"></label>
      <label class="muted">指纹（≤300 字符）<input name="fingerprint" required style="width:100%"></label>
      <label class="muted">备注<input name="note" style="width:100%"></label>
    </div>
    <button type="submit" class="pri">添加</button>
  </form>
  <div class="note">台账文件名由服务端按 sha256(imei) 生成（库里只存相对文件名，目录由 admin_devices_dir() 现算），输入不进路径。</div>
</div>

<div class="card"><h2>台账列表</h2>
  <form class="inline" method="get" action="?page=devices">
    <input type="hidden" name="page" value="devices">
    <label>搜索（IMEI 尾号 / 指纹 / 备注）<input name="dq" value="<?=e($dq)?>"></label>
    <button type="submit">查询</button>
  </form>
  <?php
    $tableRows = array_map(function ($d) {
        $enabled = (int)$d['enabled'] === 1;
        $toggle = '<form method="post" action="?page=devices" style="display:inline">'
            . csrf_field() . '<input type="hidden" name="act" value="toggle">'
            . '<input type="hidden" name="id" value="' . (int)$d['id'] . '">'
            . '<button type="submit">' . ($enabled ? '禁用' : '启用') . '</button></form>';
        $del = '<form method="post" action="?page=devices" style="display:inline"'
            . ' onsubmit="return confirm(\'确认删除该设备台账？此操作不可撤销\')">'
            . csrf_field() . '<input type="hidden" name="act" value="del">'
            . '<input type="hidden" name="id" value="' . (int)$d['id'] . '">'
            . '<label style="font-size:11px;color:var(--dim)"><input type="checkbox" name="confirm" value="yes" style="width:auto">确认</label> '
            . '<button type="submit" class="danger">删除</button></form>';
        return [
            ['html' => '<code>' . e((string)$d['imei']) . '</code>'],
            (string)$d['fingerprint'],
            (string)($d['note'] ?? ''),
            ['html' => $enabled ? '<span class="tag grn">启用</span>' : '<span class="tag red">禁用</span>'],
            (string)$d['created_at'],
            ['html' => $toggle . ' ' . $del],
        ];
    }, $rows);
    echo table(['IMEI', '指纹', '备注', '状态', '创建时间(UTC)', '操作'], $tableRows);
  ?>
</div>
<?php
render_footer();
