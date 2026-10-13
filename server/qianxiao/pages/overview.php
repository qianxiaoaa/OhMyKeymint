<?php
/**
 * 概览页 —— keybox 当前状态、证书有效期/吊销、领取计数、公钥指纹、告警。
 * 只读，不写库、不触发任何 POST。
 *
 * 红线遵守：这里只 stat / hash 公钥文件 keys/ed25519.pub；私钥 ed25519.key
 * 连 stat 都不做（绝不读、不展示、不改动）。manifest 三字段只读不改。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

$serverRoot   = dirname(__DIR__, 2);            // server/
$manifestFile = $serverRoot . '/data/manifest.json';
$keyboxFile   = $serverRoot . '/data/keybox.xml';
$revFile      = $serverRoot . '/data/revocation.json';
$pubFile      = $serverRoot . '/keys/ed25519.pub';
$dataDir      = $serverRoot . '/data';

require_once $serverRoot . '/lib/keybox.php';
require_once $serverRoot . '/lib/revocation.php';

// config 里的吊销判定基准（手工序列号 + 在线缓存）
$cfg = require $serverRoot . '/config.php';

// ---- manifest：读 keybox 子对象的 sha256 / url / updated_at（只读）----
$manifest = is_file($manifestFile) ? json_decode((string)@file_get_contents($manifestFile), true) : null;
$kbMeta   = is_array($manifest) && isset($manifest['keybox']) && is_array($manifest['keybox']) ? $manifest['keybox'] : null;

// ---- 有效性报告：基于本地 keybox.xml + 吊销判定列表 ----
$revCache = rev_load($revFile);                 // null = 尚未拉取
$onlineRev = $revCache ? rev_to_revoked_list($revCache['entries'] ?? []) : [];
$revoked  = kb_normalize_revoked(array_merge((array)($cfg['revoked_serials'] ?? []), $onlineRev));

// 注意：kb_validity_report() 在 keybox.xml 缺 <AndroidAttestation> 或缺 <CertificateChain>
// 时会提前 return，那份报告里没有 serials / days_remaining / min_not_after 等键，
// 所以下面取这些键一律用 ?? 兜底（PHP8 下 count(null) 会直接抛 TypeError）。
$report    = null;
$keyboxExe = is_file($keyboxFile);
$kbBytes   = $keyboxExe ? (string)@file_get_contents($keyboxFile) : '';
if ($kbBytes !== '') {
    $report = kb_validity_report($kbBytes, $revoked);
}

// 命中吊销的序列号（对着缓存名单再查一遍，便于展示到底是哪几个）
$revHits = ($revCache && $report) ? rev_check($revCache['entries'] ?? [], $report['serials'] ?? []) : [];

// ---- 领取计数（usage_log，action=keybox 视作一次领取；库可能为空/未建，兜底 0）----
function ov_count(PDO $pdo, string $where, array $bind): int {
    try {
        $st = $pdo->prepare('SELECT COUNT(*) c FROM usage_log WHERE ' . $where);
        $st->execute($bind);
        return (int)($st->fetch()['c'] ?? 0);
    } catch (Throwable $e) { return 0; }
}
$today = gmdate('Y-m-d 00:00:00');
$week  = gmdate('Y-m-d H:i:s', time() - 7 * 86400);
$cntToday = ov_count($pdo, "action = 'keybox' AND at >= ?", [$today]);
$cntWeek  = ov_count($pdo, "action = 'keybox' AND at >= ?", [$week]);
$cntAll   = ov_count($pdo, "action = 'keybox'", []);

// ---- 公钥文件：仅公钥，展示存在性 + sha256 指纹；私钥绝不 stat ----
$pubExists = is_file($pubFile);
$pubSha    = $pubExists ? hash_file('sha256', $pubFile) : '';

// ---- 告警区 ----
$alerts = [];
if (!$keyboxExe) {
    $alerts[] = ['bad', 'data/keybox.xml 不存在，分发接口会 404。'];
} elseif ($report && ($report['level'] ?? '') === 'invalid') {
    $alerts[] = ['bad', 'keybox 判定无效：' . implode('；', $report['reasons'] ?? [])];
} elseif ($report && ($report['level'] ?? '') === 'warning') {
    $alerts[] = ['amb', 'keybox 有告警：' . implode('；', $report['warnings'] ?? [])];
}
if (($report['days_remaining'] ?? null) !== null && $report['days_remaining'] < 0) {
    $alerts[] = ['bad', '证书链已过期（剩余 ' . $report['days_remaining'] . ' 天）。'];
}
if ($revHits) {
    $alerts[] = ['bad', '命中吊销证书：' . implode(', ', array_keys($revHits)) . '。'];
}
if (!is_writable($dataDir)) {
    $alerts[] = ['bad', 'data 目录不可写：更新任务与后台都无法落库/落文件。'];
}
if (!$revCache) {
    $alerts[] = ['amb', '吊销名单尚未拉取（data/revocation.json 不存在），吊销判定仅依据手工列表。'];
}

render_header('概览', 'overview');
?>
<?php if ($alerts): ?>
  <div class="card"><h2>告警</h2>
    <?php foreach ($alerts as $a): ?>
      <div class="note"><span class="tag <?=$a[0]==='bad'?'red':'amb'?>"><?=e($a[1])?></span></div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<div class="grid">
  <div class="card"><h2>当前 keybox</h2>
    <div class="kv"><span class="k">状态</span><span>
      <?php if ($report): $lv=(string)($report['level'] ?? 'invalid'); ?>
        <span class="tag <?=in_array($lv,['valid'],true)?'grn':($lv==='warning'?'amb':'red')?>"><?=e($lv)?></span>
      <?php else: ?><span class="tag red">无</span><?php endif; ?>
    </span></div>
    <div class="kv"><span class="k">文件存在</span><span><?=e($keyboxExe ? '是' : '否')?></span></div>
    <div class="kv"><span class="k">剩余有效期</span><span><?=e(($report && ($report['days_remaining'] ?? null) !== null) ? $report['days_remaining'].' 天' : '—')?></span></div>
    <div class="kv"><span class="k">最早到期</span><span><?=e($report && ($report['min_not_after'] ?? '') ? $report['min_not_after'] : '—')?></span></div>
    <div class="kv"><span class="k">序列号数</span><span><?=e((string)($report ? count($report['serials'] ?? []) : 0))?></span></div>
    <?php if ($kbMeta): ?>
      <div class="kv"><span class="k">manifest sha256</span><span><code><?=e(substr((string)($kbMeta['sha256'] ?? ''), 0, 16))?>…</code></span></div>
      <div class="kv"><span class="k">下发 URL</span><span><code><?=e((string)($kbMeta['url'] ?? ''))?></code></span></div>
      <div class="kv"><span class="k">更新时间</span><span><?=e((string)($kbMeta['updated_at'] ?? ''))?> (服务器本地时间)</span></div>
    <?php endif; ?>
  </div>

  <div class="card"><h2>领取计数（action=keybox）</h2>
    <div class="kv"><span class="k">今日</span><span><?=e((string)$cntToday)?></span></div>
    <div class="kv"><span class="k">近 7 日</span><span><?=e((string)$cntWeek)?></span></div>
    <div class="kv"><span class="k">累计</span><span><?=e((string)$cntAll)?></span></div>
    <div class="note">分发接口匿名，日志只记 IP/UA，不含设备标识；设备对应关系看「设备台账」。</div>
  </div>

  <div class="card"><h2>签名公钥（仅公钥）</h2>
    <div class="kv"><span class="k">文件</span><span><code>keys/ed25519.pub</code></span></div>
    <div class="kv"><span class="k">存在</span><span><?=e($pubExists ? '是' : '否')?></span></div>
    <div class="kv"><span class="k">sha256 指纹</span><span><code><?=e($pubSha !== '' ? substr($pubSha, 0, 16) . '…' : '—')?></code></span></div>
    <div class="note">私钥 keys/ed25519.key 属红线，后台不读取、不展示、不改动。</div>
  </div>
</div>

<?php if ($report && !empty($report['serials'])): ?>
  <div class="card"><h2>证书序列号 / 吊销对照</h2>
    <div class="muted">名单来源：<?=e($revCache ? ((string)($revCache['source'] ?? '?')) . '（' . count($revCache['entries']) . ' 条）' : '未拉取（仅手工列表）')?></div>
    <table><thead><tr><th>序列号</th><th>吊销状态</th></tr></thead><tbody>
    <?php foreach ($report['serials'] as $sn): ?>
      <?php
        // $revHits 的键来自 rev_norm_hex（小写 + 去前导零），而 $report['serials'] 是
        // kb_norm_serial 的产物（大写 + 补齐整字节），直接拿 $sn 查表会对“去零后
        // 奇数长度”的序列号假阴性（漏报已吊销）。查表前统一用 rev_norm_hex 归一（本
        // 页顶部已 require lib/revocation.php）；全零序列号归一成 '0'，而名单不存 '0'
        // 键（rev_parse/rev_check 均跳过），不会因此误命中。展示仍用原始 $sn。
        $hit = isset($revHits[rev_norm_hex((string)$sn)]);
      ?>
      <tr><td><code><?=e($sn)?></code></td>
        <td><?php if ($hit): ?><span class="tag red">已吊销</span><?php else: ?><span class="tag grn">正常</span><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table>
  </div>
<?php endif; ?>
<?php
render_footer();
