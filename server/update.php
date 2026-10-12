<?php
/**
 * 定时更新脚本（供 crontab 调用）：
 *   1. 按 config 依次拉取上游 keybox 源并解码
 *   2. 对每个候选做**有效性校验**（证书解析/链验证/过期/吊销），不只是字符串检查
 *   3. 在有效候选里择优（剩余有效期最长的优先），写入 data/keybox.xml
 *   4. 生成/刷新 data/manifest.json（含 sha256 + Ed25519 签名 + 有效性报告 + 备用池）
 *
 * 用法（由 update.sh 包装，宝塔计划任务调用）:
 *   sudo -u www /www/server/php/84/bin/php /www/wwwroot/your-server.example.com/api/kernelsu/module/update.php
 * 建议每 30 分钟执行一次。
 *
 * 兼容性：所有新增字段都是附加的，旧客户端只读自己认识的键，行为不变。
 */

require __DIR__ . '/lib/sources.php';
require __DIR__ . '/lib/keybox.php';
require __DIR__ . '/lib/revocation.php';
require __DIR__ . '/lib/sign.php';
require __DIR__ . '/lib/packages.php';

// 测试可用 YYPM_TEST_CONFIG 指定替代配置（生产环境不传，行为不变）
$cfg = require(getenv('YYPM_TEST_CONFIG') ?: __DIR__ . '/config.php');

$dataDir = $cfg['data_dir'];
@mkdir($dataDir, 0755, true);

$keyboxFile = $dataDir . '/' . $cfg['keybox_in'];
$manifest   = $dataDir . '/manifest.json';
$poolDir    = $dataDir . '/pool';

$ts = '[' . date('Y-m-d H:i:s') . ']';

// ---- 吊销名单：手工列表 + 在线多源 ----
// 手工列表（config 里可维护，支持十进制/十六进制混写）
$manualRevoked = $cfg['revoked_serials'] ?? [];

// 在线名单（Google attestation/status 的多个镜像）。拉取失败时只用手工列表，
// 绝不因为网络问题把本来有效的 keybox 判死。
$revInfo = rev_fetch(
    $cfg['revocation_sources'] ?? [],
    (string)($cfg['github_accel'] ?? ''),
    $dataDir . '/revocation.json',
    (int)($cfg['timeout'] ?? 20),
    (int)($cfg['revocation_max_age'] ?? 86400)
);
echo "{$ts} 吊销名单：{$revInfo['source']}，" . count($revInfo['entries']) . " 条"
    . ($revInfo['fresh'] ? '' : '（未能刷新）') . "\n";
foreach ($revInfo['tried'] as $t) { echo "    - {$t}\n"; }

// rev_to_revoked_list() 会给十六进制串加 0x 前缀：否则纯数字的十六进制串会被
// kb_normalize_revoked() 当成十进制再转一次，静默失配。
$revoked = kb_normalize_revoked(array_merge($manualRevoked, rev_to_revoked_list($revInfo['entries'])));
$GLOBALS['YYPM_REV_INFO'] = $revInfo;

// ---- 0. 自动读取已发布模块包的版本 ----
// 历史教训：config.php 里的 version 是手工维护的，已经漂移过一次
// （模块都发到 v2.1.1 了，config 还写着 v2.0.0），导致 manifest 报出错误版本号。
// 这里直接以 data/module.zip 里的 module.prop 为准，config 仅作兜底。
$modVer = null;
$modVc  = null;
$moduleZip = $dataDir . '/' . ($cfg['module_pkg'] ?? 'module.zip');
if (is_file($moduleZip) && class_exists('ZipArchive')) {
    $z = new ZipArchive();
    if ($z->open($moduleZip) === true) {
        $prop = $z->getFromName('module.prop');
        $z->close();
        if ($prop !== false) {
            if (preg_match('/^version=(.+)$/m', $prop, $mm)) $modVer = trim($mm[1]);
            if (preg_match('/^versionCode=(\d+)$/m', $prop, $mm)) $modVc = (int)$mm[1];
        }
    }
}
if ($modVer === null) { $modVer = $cfg['version']; }
if ($modVc === null)  { $modVc  = $cfg['version_code']; }
echo "{$ts} 模块版本：{$modVer} ({$modVc})"
    . (($modVer === $cfg['version']) ? "" : "（config 写的是 {$cfg['version']}，以包内为准）") . "\n";

// ---- 1. 收集所有候选并逐个校验 ----
$candidates = [];
foreach ($cfg['sources'] as $name => $src) {
    if (empty($src['enabled'])) {
        continue;
    }
    echo "{$ts} 拉取源: {$name} ...\n";
    // 目录型源（github_dir）：内容不是单个 URL，而是从仓库目录里轮换取一个能用的。
    // 取样失败只是这一个源没有候选，不影响其它源。
    if (($src['type'] ?? '') === 'github_dir') {
        // 传深度校验回调：集合仓库里大部分文件是过期/被吊销的，只做基础 XML 校验
        // 等于随机撞一个。让它在目录里一直试到找到一份真正可用的。
        $pick = fetch_dir_source(
            $src,
            (string)$cfg['github_accel'],
            (int)$cfg['timeout'],
            (int)$cfg['download_retries'],
            15,
            function ($xml) use ($revoked) {
                $r = kb_validity_report($xml, $revoked);
                return !empty($r['ok']);
            }
        );
        if ($pick === false) {
            echo "    目录里没有取到可用 keybox，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '目录取样失败'];
            continue;
        }
        echo "    取自 {$pick['file']}（试了 " . ($pick['tried'] ?? 1) . " 个）\n";
        $name .= '/' . preg_replace('/\.xml$/i', '', $pick['file']);
        $dec = $pick['keybox'];
    } else {
        $raw = http_get($src['url'], $cfg['github_accel'], (int)$cfg['timeout'], (int)$cfg['download_retries']);
        if ($raw === false || $raw === '') {
            echo "    下载失败或为空，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '下载失败'];
            continue;
        }
        $dec = decode_keybox($raw, $src['type']);
        if ($dec === false) {
            echo "    解码失败，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '解码失败'];
            continue;
        }
    }
    if (!validate_keybox($dec)) {
        echo "    基础校验失败（非有效 keybox XML），跳过\n";
        $candidates[] = ['name' => $name, 'ok' => false, 'why' => '基础校验失败'];
        continue;
    }

    // 深度有效性校验
    $rep = kb_validity_report($dec, $revoked);
    $sha = hash('sha256', $dec);
    $candidates[] = [
        'name'      => $name,
        'priority'  => (int)($src['priority'] ?? 1),
        'ok'        => $rep['ok'],
        'why'       => $rep['ok'] ? '' : implode('；', $rep['reasons']),
        'keybox'    => $dec,
        'sha256'    => $sha,
        'validity'  => $rep,
        'serials'   => $rep['serials'],
    ];
    if ($rep['ok']) {
        echo "    通过：有效，剩余 {$rep['days_remaining']} 天，证书 " . count($rep['serials']) . " 个序列号\n";
    } else {
        echo "    *** 判定无效：" . implode('；', $rep['reasons']) . "\n";
    }
    if (!empty($rep['warnings'])) {
        echo "    提示：" . implode('；', $rep['warnings']) . "\n";
    }
}

// ---- 1.5 人工固定 keybox（A/B 实验 / 一键回滚）----
// config 里 keybox_pin 指向管理员手工验证过的一份 keybox：文件存在且校验通过时
// 永远优先于上游源，不再被每天的自动择优覆盖；删掉该文件即恢复自动择优。
// 校验与上游候选完全相同（validate_keybox + kb_validity_report：链验证/过期/吊销），
// 不另搞简化版 —— 固定一份坏 keybox 比没有固定更危险。
// 校验不过只打印原因并回退自动择优：绝不能因为固定文件坏了导致服务端没有 keybox。
$pinned = null;
$pinFile = (string)($cfg['keybox_pin'] ?? '');
if ($pinFile !== '' && is_file($pinFile) && @filesize($pinFile) > 0) {
    echo "{$ts} 检测到固定 keybox: {$pinFile}\n";
    $pinXml = (string)@file_get_contents($pinFile);
    if (!validate_keybox($pinXml)) {
        echo "{$ts} 固定 keybox 校验失败：基础校验失败（非有效 keybox XML），回退到自动择优\n";
    } else {
        $pinRep = kb_validity_report($pinXml, $revoked);
        if (!$pinRep['ok']) {
            echo "{$ts} 固定 keybox 校验失败：" . implode('；', $pinRep['reasons']) . "，回退到自动择优\n";
        } else {
            $pinned = [
                'name'      => 'pinned',
                'priority'  => 0,   // 0 = 人工作选，日志/快照里一眼可辨
                'ok'        => true,
                'why'       => '',
                'keybox'    => $pinXml,
                'sha256'    => hash('sha256', $pinXml),
                'validity'  => $pinRep,
                'serials'   => $pinRep['serials'],
            ];
            echo "{$ts} 固定 keybox 校验通过：有效，剩余 {$pinRep['days_remaining']} 天，将优先于所有上游源\n";
        }
    }
}

// ---- 2. 择优：有效的里挑剩余有效期最长的；并列时取配置靠前的 ----
$valid = array_values(array_filter($candidates, fn($c) => !empty($c['ok'])));
$chosen = null;
$fallbacks = [];
if (!empty($valid)) {
    // 排序：先按 priority（1 = 人工挑选验证过的源，2 = 集合仓库兜底），
    // 同一档里再比剩余有效期。
    //
    // 为什么 priority 优先于有效期：集合仓库（KeyboxHub 有 551 个文件）里能翻出
    // 剩余 2678 天的 keybox，比 yurikey 的 1456 天还长 —— 但那些文件来历不明、
    // 没在真机上验证过。让它们无声顶掉已经跑通的源是不负责任的；它们只在
    // priority 1 全部失效时才接管。
    //
    // 固定期间也要照常排序：它决定备用池（fallbacks）的顺序。
    usort($valid, function ($a, $b) {
        $pa = (int)($a['priority'] ?? 1);
        $pb = (int)($b['priority'] ?? 1);
        if ($pa !== $pb) return ($pa < $pb) ? -1 : 1;
        $da = $a['validity']['days_remaining'];
        $db = $b['validity']['days_remaining'];
        $da = ($da === null) ? -1 : $da;
        $db = ($db === null) ? -1 : $db;
        if ($da === $db) return 0;
        return ($da > $db) ? -1 : 1;
    });
}
if ($pinned !== null) {
    // 人工固定优先：上游源仍照常拉取/校验（上面的健康快照保持完整），
    // 但 chosen 固定为 pinned，不再被择优覆盖。
    $chosen = $pinned;
    echo "{$ts} 选中源: pinned（人工固定 keybox，优先级 0，剩余 {$pinned['validity']['days_remaining']} 天）\n";
    $pool = $valid;   // 固定期间所有有效上游候选都降级为备用池
} elseif (!empty($valid)) {
    $chosen = $valid[0];
    echo "{$ts} 选中源: {$chosen['name']}（优先级 {$chosen['priority']}，剩余 {$chosen['validity']['days_remaining']} 天）\n";
    $pool = array_slice($valid, 1);
} else {
    $pool = [];
}
// 备用池：除主用外的其余有效候选（客户端可在主用失效时回退）
foreach ($pool as $v) {
    $fallbacks[] = [
        'source'          => $v['name'],
        'sha256'          => $v['sha256'],
        'size'            => strlen($v['keybox']),
        'days_remaining'  => $v['validity']['days_remaining'],
        'min_not_after'   => $v['validity']['min_not_after'],
    ];
}

// ---- 3. 没有有效候选时保留上一份，但要把"当前这份还有效吗"如实写进 manifest ----
if ($chosen === null) {
    echo "{$ts} 本轮无有效候选，保留上一次的 keybox\n";
    if (!is_file($keyboxFile)) {
        echo "{$ts} 且本地也没有 keybox，结束\n";
        build_package_manifest($cfg);
        exit(0);
    }
    $keybox  = file_get_contents($keyboxFile);
    $sha256  = hash('sha256', $keybox);
    $recheck = kb_validity_report($keybox, $revoked);
    $sourceName = '(保留上一份)';
    echo "{$ts} 保留的这份有效性：{$recheck['level']}"
        . (empty($recheck['reasons']) ? '' : '，原因：' . implode('；', $recheck['reasons'])) . "\n";
    write_manifest($cfg, $dataDir, $manifest, $sourceName, $keybox, $sha256, $recheck, $fallbacks, $candidates, $revoked, $modVer, $modVc);
    build_package_manifest($cfg);
    exit(0);
}

// ---- 4. 写入并生成 manifest ----
file_put_contents($keyboxFile, $chosen['keybox']);
$recheck = $chosen['validity'];

// 候选池快照：便于排障时看"每个源当时为什么被选/被弃"
write_pool_snapshot($poolDir, $chosen, $candidates, $revoked);

echo "{$ts} 完成。keybox={$keyboxFile} sha256={$chosen['sha256']}\n";
write_manifest($cfg, $dataDir, $manifest, $chosen['name'], $chosen['keybox'], $chosen['sha256'], $recheck, $fallbacks, $candidates, $revoked, $modVer, $modVc);
build_package_manifest($cfg);

// ============================================================
// 辅助函数
// ============================================================

/**
 * 写 manifest.json。新增 keybox.validity（有效性报告）与 keybox.fallbacks（备用池）。
 * 这些是附加字段，旧客户端会忽略。
 * 版本号来自已发布包内的 module.prop（$modVer/$modVc），不是 config 的手工值。
 */
function write_manifest(array $cfg, string $dataDir, string $manifestFile, string $sourceName,
                        string $keybox, string $sha256, array $validity, array $fallbacks,
                        array $candidates, array $revoked, string $modVer, int $modVc): void {
    $entry = [
        'updated_at' => date('Y-m-d H:i:s'),
        'source'     => $sourceName,
        'size'       => strlen($keybox),
        'sha256'     => $sha256,
        'url'        => rtrim($cfg['base_url'], '/') . '/?action=keybox',
        // 有效性报告（客户端据此决定是否注入）
        'validity'   => [
            'level'          => $validity['level'],
            'ok'             => (bool)$validity['ok'],
            'reasons'        => $validity['reasons'],
            'warnings'       => $validity['warnings'],
            'checked_at'     => $validity['checked_at'],
            'min_not_after'  => $validity['min_not_after'],
            'days_remaining' => $validity['days_remaining'],
            'cert_count'     => $validity['cert_markers'] ?? null,
            'serial_count'   => count($validity['serials'] ?? []),
            'serials'        => $validity['serials'] ?? [],
            // 完整证书链明细（主题/签发者/序列号/起止日期）。
            // 设备端「密钥自检」直接展示这些，不需要在手机上解析 X.509。
            'chains'         => $validity['chains'] ?? [],
        ],
        // 备用池（其余有效候选；顺序 = 优选顺序）
        'fallbacks'  => $fallbacks,
    ];

    // 吊销名单快照：让 WebUI / 设备端能直接看出「这次是拿哪份名单判的、判了没判」
    $ri = $GLOBALS['YYPM_REV_INFO'] ?? null;
    if (is_array($ri)) {
        $entry['revocation'] = [
            'source'     => (string)($ri['source'] ?? ''),
            'count'      => count($ri['entries'] ?? []),
            'fresh'      => (bool)($ri['fresh'] ?? false),
            'fetched_at' => (int)($ri['fetched_at'] ?? 0),
            // 本次判定实际用的序列号总数（在线 + 手工），便于确认名单真的生效了
            'checked'    => count($revoked),
            'tried'      => $ri['tried'] ?? [],
        ];
    }

    if (!empty($cfg['sign_enable'])) {
        try {
            [$secret, $public] = sign_ensure_keys($cfg['keys_dir'], $cfg['sign_public_out'], $cfg['sign_secret_in']);
            $entry['signature'] = sign_data($secret, $keybox);
            $entry['sign_public'] = $public;
        } catch (Throwable $e) {
            echo "    签名失败（sodium?）: " . $e->getMessage() . "\n";
        }
    }

    // 数据源健康快照（供 WebUI 展示 ④）
    $health = [];
    foreach ($candidates as $c) {
        $health[] = [
            'source' => $c['name'],
            'ok'     => !empty($c['ok']),
            'why'    => $c['why'] ?? '',
        ];
    }

    $payload = [
        'version'       => $modVer,
        'version_code'  => $modVc,
        'base_url'      => $cfg['base_url'],
        'keybox'        => $entry,
    ];

    // 模块包本身的哈希 + Ed25519 签名：客户端自更新前用 verify_tool 验签
    // （与 keybox 同一把公钥）。信任根是公钥，zip 从任何镜像下载都安全 ——
    // 这是去中心化分发（多镜像/CDN）的前提。
    $moduleZipPath = $dataDir . '/' . ($cfg['module_pkg'] ?? 'module.zip');
    if (is_file($moduleZipPath)) {
        $mz = (string)@file_get_contents($moduleZipPath);
        $modEntry = [
            'sha256' => hash('sha256', $mz),
            'size'   => strlen($mz),
            'url'    => rtrim($cfg['base_url'], '/') . '/?action=module',
        ];
        if (!empty($cfg['sign_enable'])) {
            try {
                [$secret] = sign_ensure_keys($cfg['keys_dir'], $cfg['sign_public_out'], $cfg['sign_secret_in']);
                $modEntry['signature'] = sign_data($secret, $mz);
            } catch (Throwable $e) {
                echo "    模块包签名失败: " . $e->getMessage() . "\n";
            }
        }
        $payload['module'] = $modEntry;
    }

    $payload['server'] = [
        'updated_at'       => date('Y-m-d H:i:s'),
        'revoked_count'    => count($revoked),
        'sources'          => $health,
        'candidate_count'  => count($candidates),
        'valid_count'      => count(array_filter($candidates, fn($c) => !empty($c['ok']))),
    ];

    file_put_contents($manifestFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

/** 候选池快照：记录每个源当时的状态，便于事后排障 */
function write_pool_snapshot(string $poolDir, ?array $chosen, array $candidates, array $revoked): void {
    @mkdir($poolDir, 0755, true);
    $rows = [];
    foreach ($candidates as $c) {
        $rows[] = [
            'source'         => $c['name'],
            'ok'             => !empty($c['ok']),
            'why'            => $c['why'] ?? '',
            'sha256'         => $c['sha256'] ?? null,
            'days_remaining' => $c['validity']['days_remaining'] ?? null,
            'min_not_after'  => $c['validity']['min_not_after'] ?? null,
        ];
    }
    $snap = [
        'at'          => date('Y-m-d H:i:s'),
        'chosen'      => $chosen['name'] ?? null,
        'revoked'     => $revoked,
        'candidates'  => $rows,
    ];
    file_put_contents($poolDir . '/last_pool.json', json_encode($snap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    // 保留最近 30 份历史（按天滚动命名，便于对比"什么时候开始失效"）
    file_put_contents($poolDir . '/pool_' . date('Ymd') . '.json', json_encode($snap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $hist = glob($poolDir . '/pool_*.json');
    if (is_array($hist) && count($hist) > 30) {
        sort($hist);
        foreach (array_slice($hist, 0, count($hist) - 30) as $old) { @unlink($old); }
    }
}

/**
 * 扫描 package_dir 下所有 .zip 模块，生成客户端要读取的清单 package.json。
 * 清单结构：{ "updated_at": ..., "modules": { "文件名": {"sha256","size","url"} } }
 *
 * 注意：本函数**必须保留已有的版本扩展字段**（x-id / x-name / x-version 等，
 * 由 scan_packages.py 解析每个 zip 里的 module.prop 得到）。
 * 否则 update.php 每次运行都会把带版本信息的清单覆盖成"只有 sha256/size/url"的精简版，
 * 客户端就再也拿不到 x-versionCode，附属模块更新检查会退化成"全部重新下载"。
 * 与其依赖 update.sh 里"再跑一次 scan_packages"的顺序，不如在这里就保住数据。
 */
function build_package_manifest(array $cfg): void {
    $dir = $cfg['package_dir'];
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $jsonFile = $dir . '/' . $cfg['package_json'];

    // 先读出旧清单，把已有的扩展字段存下来
    $prev = [];
    if (is_file($jsonFile)) {
        $old = json_decode((string)@file_get_contents($jsonFile), true);
        if (is_array($old) && !empty($old['modules']) && is_array($old['modules'])) {
            $prev = $old['modules'];
        }
    }

    // 签名密钥：给每个 zip 的字节签名（与 keybox 同一把 Ed25519 私钥）。
    // 客户端安装前用 verify_tool 验签 —— zip 从任何镜像下载都安全。
    $secret = null;
    if (!empty($cfg['sign_enable'])) {
        try { [$secret] = sign_ensure_keys($cfg['keys_dir'], $cfg['sign_public_out'], $cfg['sign_secret_in']); }
        catch (Throwable $e) { $secret = null; }
    }

    // 组件来源元数据（fetch_packages.php 的 sources.json）：类型/自动安装/APK 包名
    $srcMeta = pkg_load_sources($dir);

    $files = array_merge(glob($dir . '/*.zip') ?: [], glob($dir . '/*.apk') ?: []);
    $modules = [];
    foreach ($files as $f) {
        $name = basename($f);
        if ($name === '.zip' || $name === '.apk') continue;
        $bytes = (string)@file_get_contents($f);
        $entry = [
            'sha256' => hash('sha256', $bytes),
            'size'   => strlen($bytes),
            'url'    => rtrim($cfg['base_url'], '/') . '/package/' . $name,
        ];
        if ($secret !== null) {
            try { $entry['signature'] = sign_data($secret, $bytes); } catch (Throwable $e) { /* 不阻断 */ }
        }
        // 来源元数据：x-type（默认 ksu-module）/ x-auto / x-package（APK 的应用包名）
        $sm = $srcMeta[$name] ?? null;
        $isApk = is_array($sm) && (($sm['type'] ?? '') === 'apk');
        if (is_array($sm)) {
            $entry['x-type'] = $isApk ? 'apk' : 'ksu-module';
            if (!empty($sm['auto'])) $entry['x-auto'] = 1;
            if (!empty($sm['package'])) $entry['x-package'] = (string)$sm['package'];
        }
        // x- 版本字段：zip 一律重新解析包内 module.prop —— 解析永远优先于沿用。
        // 教训（LSPosed v2.2.1，2026-10-05）：曾用「sha 没变就沿用旧 x- 字段」的捷径，
        // 一次带着「新 sha + 旧版本号」的清单生成后，后续每轮都判「没变」而沿用，
        // 旧版本号滞留、客户端永远看不到更新。对几个包重新解析的成本可忽略，
        // 正确性优先。（pkg_read_module_prop 自带 busybox 兜底，
        // zstd 等新压缩方法的包也能解析出 module.prop。）
        // APK 没有 module.prop，版本字段直接跳过（客户端按 sha256 判断更新）。
        if ($isApk) {
            // APK：版本信息无法从 module.prop 来，沿用旧清单里的 x-version（如果有）
            if (!empty($prev[$name]['x-version'])) $entry['x-version'] = $prev[$name]['x-version'];
        } else {
            $meta = pkg_read_module_prop($f);
            if ($meta !== null) {
                $entry['x-id'] = $meta['id'];
                if (!empty($meta['name'])) $entry['x-name'] = $meta['name'];
                if (!empty($meta['version'])) $entry['x-version'] = $meta['version'];
                if (isset($meta['versionCode']) && $meta['versionCode'] !== '') $entry['x-versionCode'] = (int)$meta['versionCode'];
            }
        }
        // 沿用旧清单里仍然缺失的 x- 字段（sources.json 来的 x-auto 等已在上面写入优先）
        if (!empty($prev[$name]) && is_array($prev[$name])) {
            foreach ($prev[$name] as $k => $v) {
                if (strpos((string)$k, 'x-') === 0 && !array_key_exists($k, $entry)) {
                    $entry[$k] = $v;
                }
            }
        }
        $modules[$name] = $entry;
    }
    $payload = [
        'updated_at' => date('Y-m-d H:i:s'),
        'count'      => count($modules),
        'modules'    => $modules,
    ];
    file_put_contents($jsonFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $withVer = 0;
    foreach ($modules as $m) { if (!empty($m['x-version'])) $withVer++; }
    echo '[' . date('Y-m-d H:i:s') . '] 生成模块清单：' . count($modules) . " 个模块（其中 {$withVer} 个带版本信息）\n";
}
