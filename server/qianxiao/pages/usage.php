<?php
/**
 * 领取日志页 —— usage_log 分页 + 搜索 + CSV 导出。
 * 可用变量：$pdo、$currentUser。只读。
 *
 * 分发匿名，这里没有设备标识，只有 IP/UA/keybox sha/序列号串。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

/** 依据 GET 过滤条件拼 WHERE（全部预处理绑定，绝不拼值进 SQL）。 */
function usage_filters(array $g): array {
    $w = [];
    $bind = [];
    // 搜索词先过 admin_like() 转义 LIKE 元字符（% _ 反斜杠）再补通配符，并在 SQL 里
    // 给每个 LIKE 紧跟 ESCAPE '\'（ESCAPE 隶属 LIKE 子句，必须写在 LIKE 之后、AND 之前），
    // 否则搜一个 % 就能整表扇出；搜索框回填仍用原值，不受转义影响。
    $ip = trim((string)($g['q_ip'] ?? ''));
    if ($ip !== '') { $w[] = "ip LIKE ? ESCAPE '\\'"; $bind[] = '%' . admin_like($ip) . '%'; }
    $sha = trim((string)($g['q_sha'] ?? ''));
    if ($sha !== '') { $w[] = "keybox_sha256 LIKE ? ESCAPE '\\'"; $bind[] = admin_like($sha) . '%'; }
    $sn = trim((string)($g['q_serial'] ?? ''));
    if ($sn !== '') { $w[] = "keybox_serials LIKE ? ESCAPE '\\'"; $bind[] = '%' . admin_like($sn) . '%'; }
    $act = (string)($g['q_action'] ?? '');
    if (in_array($act, ['keybox', 'manifest'], true)) { $w[] = 'action = ?'; $bind[] = $act; }
    $from = trim((string)($g['q_from'] ?? ''));
    $to   = trim((string)($g['q_to'] ?? ''));
    if ($from !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) { $w[] = 'at >= ?'; $bind[] = $from . ' 00:00:00'; }
    if ($to !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $to))   { $w[] = 'at <= ?'; $bind[] = $to . ' 23:59:59'; }
    return [implode(' AND ', $w), $bind];
}

/** 把当前筛选条件重新拼成 & 串（去掉 page/p/export），供分页与导出链接沿用。 */
function usage_querystring(array $g): string {
    $keep = ['q_ip', 'q_sha', 'q_serial', 'q_action', 'q_from', 'q_to'];
    $parts = [];
    foreach ($keep as $k) {
        if (isset($g[$k]) && (string)$g[$k] !== '') {
            $parts[] = urlencode($k) . '=' . urlencode((string)$g[$k]);
        }
    }
    return $parts ? ('&' . implode('&', $parts)) : '';
}

list($where, $bind) = usage_filters($_GET);
$sqlWhere = $where === '' ? '' : (' WHERE ' . $where);

// ---- CSV 导出：任何 HTML 之前发头并 exit。UTF-8 BOM 防 Excel 乱码。----
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="usage_log_' . gmdate('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF"); // BOM
    fputcsv($out, ['at(UTC)', 'ip', 'action', 'keybox_sha256', 'keybox_serials', 'ua']);
    $st = $pdo->prepare('SELECT at, ip, action, keybox_sha256, keybox_serials, ua FROM usage_log'
        . $sqlWhere . ' ORDER BY id DESC LIMIT 100000');
    $st->execute($bind);
    while ($r = $st->fetch()) {
        // 单元格逐行过 admin_csv_cell() 中和公式注入：IP / UA / 序列号全部是客户端可控输入（HTTP 头）。
        fputcsv($out, array_map('admin_csv_cell', [(string)$r['at'], (string)$r['ip'], (string)$r['action'],
            (string)$r['keybox_sha256'], (string)$r['keybox_serials'], (string)$r['ua']]));
    }
    fclose($out);
    exit;
}

// ---- 分页 ----
$perPage = 50;
$total = 0;
try {
    $st = $pdo->prepare('SELECT COUNT(*) c FROM usage_log' . $sqlWhere);
    $st->execute($bind);
    $total = (int)($st->fetch()['c'] ?? 0);
} catch (Throwable $e) { $total = 0; }
$pages = $total > 0 ? (int)ceil($total / $perPage) : 1;
$cur = isset($_GET['p']) ? (int)$_GET['p'] : 1;
if ($cur < 1) $cur = 1;
if ($cur > $pages) $cur = $pages;
$offset = ($cur - 1) * $perPage;

$rows = [];
try {
    $st = $pdo->prepare('SELECT at, ip, action, keybox_sha256, keybox_serials, ua FROM usage_log'
        . $sqlWhere . ' ORDER BY id DESC LIMIT ' . $perPage . ' OFFSET ' . $offset);
    $st->execute($bind);
    $rows = $st->fetchAll();
} catch (Throwable $e) { $rows = []; }

render_header('领取日志', 'usage');
?>
<div class="card"><h2>筛选</h2>
  <form class="inline" method="get" action="?page=usage">
    <input type="hidden" name="page" value="usage">
    <label>IP<input name="q_ip" value="<?=e((string)($_GET['q_ip'] ?? ''))?>"></label>
    <label>keybox sha256 前缀<input name="q_sha" value="<?=e((string)($_GET['q_sha'] ?? ''))?>"></label>
    <label>序列号包含<input name="q_serial" value="<?=e((string)($_GET['q_serial'] ?? ''))?>"></label>
    <label>动作<select name="q_action">
      <?php $a = (string)($_GET['q_action'] ?? ''); ?>
      <option value="">全部</option>
      <option value="keybox" <?=$a==='keybox'?'selected':''?>>keybox</option>
      <option value="manifest" <?=$a==='manifest'?'selected':''?>>manifest</option>
    </select></label>
    <label>起(UTC)<input type="date" name="q_from" value="<?=e((string)($_GET['q_from'] ?? ''))?>"></label>
    <label>止(UTC)<input type="date" name="q_to" value="<?=e((string)($_GET['q_to'] ?? ''))?>"></label>
    <button type="submit" class="pri">查询</button>
    <a class="btn" href="?page=usage&export=csv<?=e(usage_querystring($_GET))?>">导出 CSV</a>
  </form>
  <div class="note">共 <?=$total?> 条。CSV 导出沿用当前筛选条件。</div>
</div>

<div class="card">
  <?=table(['时间(UTC)', 'IP', '动作', 'keybox sha256', '序列号', 'UA'], array_map(function ($r) {
      return [
          (string)$r['at'],
          ['html' => '<code>' . e((string)$r['ip']) . '</code>'],
          (string)$r['action'],
          ['html' => '<code>' . e(substr((string)$r['keybox_sha256'], 0, 16)) . '</code>'],
          (string)$r['keybox_serials'],
          (string)$r['ua'],
      ];
  }, $rows))?>
  <div class="pager">
    <?php if ($cur > 1): ?><a class="btn" href="?page=usage&p=<?=$cur-1?><?=e(usage_querystring($_GET))?>">上一页</a><?php endif; ?>
    <span class="muted">第 <?=$cur?> / <?=$pages?> 页</span>
    <?php if ($cur < $pages): ?><a class="btn" href="?page=usage&p=<?=$cur+1?><?=e(usage_querystring($_GET))?>">下一页</a><?php endif; ?>
  </div>
</div>
<?php
render_footer();
