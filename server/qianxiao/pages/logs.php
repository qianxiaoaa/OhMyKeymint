<?php
/**
 * 时间线页 —— usage_log 与 audit 合并视图（UNION ALL，来源列区分）。
 * 可用变量：$pdo、$currentUser。只读 + CSV 导出。
 *
 * 搜索：关键字 q 同时命中领取日志的 IP/序列号/sha 与审计的 target/管理员/动作；
 * 设备台账里的 IMEI/指纹通过审计 target（设备操作会记 imei）与本下方的
 * 「设备快速定位」面板（直接查 device 表的 imei/fingerprint/note）双路可查。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

$q = trim((string)($_GET['q'] ?? ''));
// 关键字先过 admin_like() 转义 LIKE 元字符（% _ 反斜杠）再补通配符；下面每个 LIKE
// 都紧跟 ESCAPE '\'（ESCAPE 隶属 LIKE 子句，必须写在 LIKE 之后、AND/OR 之前），
// 否则搜一个 % 就能把整库时间线全部绕出来；输入框回填仍用原值。
// （PHP 字符串改用双引号只为写出一条反斜杠，SQL 里的字面量仍是单引号，见下方合并查询的注释。）
$like = '%' . admin_like($q) . '%';

$uWhere = '';
$aWhere = '';
$bindCount = [];
if ($q !== '') {
    $uWhere = " WHERE ip LIKE ? ESCAPE '\\' OR keybox_serials LIKE ? ESCAPE '\\'"
        . " OR keybox_sha256 LIKE ? ESCAPE '\\'";
    $aWhere = " WHERE target LIKE ? ESCAPE '\\' OR admin LIKE ? ESCAPE '\\'"
        . " OR act LIKE ? ESCAPE '\\'";
    for ($i = 0; $i < 3; $i++) { $bindCount[] = $like; }   // usage 侧
    for ($i = 0; $i < 3; $i++) { $bindCount[] = $like; }   // audit 侧
}

// 合并查询：统一成 at / src / who / act / detail 五列。UNION ALL 保留两份原始行。
// SQL 字符串一律用单引号（SQLite 默认把双引号当标识符/ANSI_QUOTES 风险）。
$union =
    "(SELECT at, 'usage' AS src, ip AS who, action AS act,"
    . " (CASE WHEN keybox_sha256 IS NULL THEN '' ELSE 'sha256:' || substr(keybox_sha256,1,12) || ' ' END)"
    . "  || (CASE WHEN keybox_serials IS NULL OR keybox_serials='' THEN '' ELSE 'serials:' || keybox_serials || ' ' END)"
    . "  || (CASE WHEN ua IS NULL THEN '' ELSE 'ua:' || ua END) AS detail"
    . " FROM usage_log" . $uWhere . ")"
    . " UNION ALL "
    . "(SELECT at, 'audit' AS src, (admin || CASE WHEN ip IS NULL OR ip='' THEN '' ELSE '@' || ip END) AS who, act,"
    . " COALESCE(target, '') AS detail FROM audit" . $aWhere . ")";

// ---- CSV 导出（HTML 之前）----
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="timeline_' . gmdate('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['at(UTC)', '来源', '主体', '动作', '详情']);
    $st = $pdo->prepare($union . ' ORDER BY at DESC LIMIT 100000');
    $st->execute($bindCount);
    while ($r = $st->fetch()) {
        // 单元格逐行过 admin_csv_cell() 中和公式注入：who/act/detail 里藏着 UA、
        // target 等客户端或写入时可控的内容，Excel 直接打开会当公式执行。
        fputcsv($out, array_map('admin_csv_cell', [(string)$r['at'], (string)$r['src'],
            (string)$r['who'], (string)$r['act'], (string)$r['detail']]));
    }
    fclose($out);
    exit;
}

// ---- 分页 ----
$perPage = 50;
$total = 0;
try {
    $st = $pdo->prepare('SELECT COUNT(*) c FROM (' . $union . ')');
    $st->execute($bindCount);
    $total = (int)($st->fetch()['c'] ?? 0);
} catch (Throwable $e) { $total = 0; }
$pages = $total > 0 ? (int)ceil($total / $perPage) : 1;
$cur = isset($_GET['p']) ? (int)$_GET['p'] : 1;
if ($cur < 1) $cur = 1;
if ($cur > $pages) $cur = $pages;
$offset = ($cur - 1) * $perPage;

$rows = [];
try {
    // LIMIT/OFFSET 为服务端算好的整数，非用户原值，直接内联安全
    $st = $pdo->prepare($union . ' ORDER BY at DESC LIMIT ' . $perPage . ' OFFSET ' . $offset);
    $st->execute($bindCount);
    $rows = $st->fetchAll();
} catch (Throwable $e) { $rows = []; }

// ---- 设备快速定位（查 device 表：imei / fingerprint / note）----
$dq = trim((string)($_GET['dq'] ?? ''));
$devs = [];
if ($dq !== '') {
    // 同上面的关键字处理：转义后再补通配符，SQL 里逐个 LIKE 跟 ESCAPE '\'。
    $dl = '%' . admin_like($dq) . '%';
    try {
        $st = $pdo->prepare('SELECT imei, fingerprint, note, enabled FROM device'
            . " WHERE imei LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\'"
            . " OR note LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 50");
        $st->execute([$dl, $dl, $dl]);
        $devs = $st->fetchAll();
    } catch (Throwable $e) { $devs = []; }
}

render_header('时间线', 'logs');
?>
<div class="card"><h2>合并时间线</h2>
  <form class="inline" method="get" action="?page=logs">
    <input type="hidden" name="page" value="logs">
    <label>关键字（IP / 序列号 / IMEI / 管理员 / 动作）<input name="q" value="<?=e($q)?>" style="min-width:280px"></label>
    <button type="submit" class="pri">查询</button>
    <a class="btn" href="?page=logs&export=csv<?=($q !== '' ? '&q=' . urlencode($q) : '')?>">导出 CSV</a>
  </form>
  <div class="note">共 <?=$total?> 条。领取(usage) 与 操作(audit) 合并按时间倒序；UTC 时间。</div>
</div>

<?php if ($dq !== ''): ?>
<div class="card"><h2>设备快速定位「<?=e($dq)?>」</h2>
  <?=table(['IMEI', '指纹', '备注', '状态'], array_map(function ($d) {
      return [
          ['html' => '<code>' . e((string)$d['imei']) . '</code>'],
          (string)$d['fingerprint'],
          (string)($d['note'] ?? ''),
          ['html' => ((int)$d['enabled'] === 1) ? '<span class="tag grn">启用</span>' : '<span class="tag red">禁用</span>'],
      ];
  }, $devs))?>
</div>
<?php endif; ?>

<div class="card">
  <form class="inline" method="get" action="?page=logs" style="margin-top:0">
    <input type="hidden" name="page" value="logs">
    <input type="hidden" name="q" value="<?=e($q)?>">
    <label>按设备台账定位（IMEI / 指纹 / 备注）<input name="dq" value="<?=e($dq)?>"></label>
    <button type="submit">查设备</button>
  </form>
  <?=table(['时间(UTC)', '来源', '主体', '动作', '详情'], array_map(function ($r) {
      $src = (string)$r['src'] === 'audit'
          ? '<span class="tag grn">操作</span>' : '<span class="tag amb">领取</span>';
      return [
          (string)$r['at'],
          ['html' => $src],
          (string)$r['who'],
          (string)$r['act'],
          (string)$r['detail'],
      ];
  }, $rows))?>
  <div class="pager">
    <?php if ($cur > 1): ?><a class="btn" href="?page=logs&p=<?=$cur-1?><?=($q !== '' ? '&q=' . urlencode($q) : '')?>">上一页</a><?php endif; ?>
    <span class="muted">第 <?=$cur?> / <?=$pages?> 页</span>
    <?php if ($cur < $pages): ?><a class="btn" href="?page=logs&p=<?=$cur+1?><?=($q !== '' ? '&q=' . urlencode($q) : '')?>">下一页</a><?php endif; ?>
  </div>
</div>
<?php
render_footer();
