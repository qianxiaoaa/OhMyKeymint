<?php
/**
 * 第三方组件自动抓取（cron，由 update.sh 在 update.php 之前调用）。
 *
 * 按 package/sources.json 的定义，从上游 GitHub release 拉最新组件包：
 *   查询 release -> 匹配资产 -> 与状态文件比对（资产 URL 没变就跳过）
 *   -> 下载（加速器优先）-> 校验（模块必须有 module.prop；APK 必须是 PK 包且含 AndroidManifest）
 *   -> 原子落盘 package/ 目录
 * 之后 update.php 的 build_package_manifest 会统一算 sha256 + Ed25519 签名进清单。
 * 本脚本只负责「把对的文件放到目录里」，不碰清单。
 */

require __DIR__ . '/lib/packages.php';

// 测试可用 YYPM_TEST_CONFIG 指定替代配置（生产环境不传，行为不变）
$cfg = require(getenv('YYPM_TEST_CONFIG') ?: __DIR__ . '/config.php');
$dir = $cfg['package_dir'];
@mkdir($dir, 0755, true);

$sources = pkg_load_sources($dir);
if (!$sources) { exit(0); }

$stateFile = $dir . '/.sources-state.json';
$state = is_file($stateFile) ? (json_decode((string)@file_get_contents($stateFile), true) ?: []) : [];
$accel   = (string)($cfg['github_accel'] ?? '');
$timeout = (int)($cfg['timeout'] ?? 20);
$ts = '[' . date('Y-m-d H:i:s') . ']';

foreach ($sources as $name => $src) {
    if (!is_array($src) || empty($src['github_release'])) continue;
    if (!preg_match('/^[A-Za-z0-9._-]+\.(zip|apk)$/', (string)$name)) {
        echo "{$ts} {$name}：文件名不合法，跳过\n";
        continue;
    }
    $repo  = (string)$src['github_release'];
    $match = (string)($src['asset_match'] ?? '\\.zip$');
    $type  = (($src['type'] ?? '') === 'apk') ? 'apk' : 'ksu-module';

    $rel = pkg_github_latest($repo, $accel, $timeout);
    if ($rel === null) { echo "{$ts} {$name}：$repo release 查询失败\n"; continue; }

    $asset = null;
    foreach ($rel['assets'] as $a) {
        if (@preg_match('/' . str_replace('/', '\\/', $match) . '/', $a['name']) && preg_match('/' . str_replace('/', '\\/', $match) . '/', $a['name'])) { $asset = $a; break; }
    }
    if ($asset === null) { echo "{$ts} {$name}：{$rel['tag']} 没有匹配 /$match/ 的资产\n"; continue; }

    $prev = $state[$name] ?? [];
    if (($prev['asset_url'] ?? '') === $asset['url'] && is_file($dir . '/' . $name)) {
        continue;   // 资产没变，且本地文件还在
    }

    echo "{$ts} {$name}：发现新版本 {$rel['tag']}（{$repo}），下载 {$asset['name']}\n";
    $bytes = http_get($asset['url'], $accel, max($timeout, 60), 3);
    if (!is_string($bytes) || strlen($bytes) < 100) { echo "{$ts} {$name}：下载失败\n"; continue; }

    $tmpFile = tempnam(sys_get_temp_dir(), 'ypkg');
    file_put_contents($tmpFile, $bytes);

    $ok = false;
    if ($type === 'apk') {
        $ok = substr($bytes, 0, 2) === 'PK' && strpos($bytes, 'AndroidManifest') !== false;
    } else {
        $meta = pkg_read_module_prop($tmpFile);
        $ok = $meta !== null;
        if ($ok) echo "{$ts} {$name}：模块 {$meta['id']} {$meta['version']}\n";
    }
    if (!$ok) { echo "{$ts} {$name}：校验失败，丢弃\n"; @unlink($tmpFile); continue; }

    if (!@rename($tmpFile, $dir . '/' . $name)) {
        @copy($tmpFile, $dir . '/' . $name);
        @unlink($tmpFile);
    }
    @chmod($dir . '/' . $name, 0644);
    $state[$name] = [
        'asset_url'  => $asset['url'],
        'tag'        => $rel['tag'],
        'sha256'     => hash('sha256', $bytes),
        'fetched_at' => time(),
    ];
    echo "{$ts} {$name}：已落盘（" . strlen($bytes) . " 字节）\n";
}

file_put_contents($stateFile, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
