<?php
/**
 * Google 硬件证明证书吊销名单（attestation/status）—— 多源拉取 + 本地缓存。
 *
 * 为什么必须多源：
 *   官方地址 https://android.googleapis.com/attestation/status 在本服务器上完全
 *   连不通（curl 返回 000，多次实测）。但这份名单有若干 GitHub 镜像，而 GitHub
 *   走加速器是通的 —— 于是「服务器拉镜像、设备问服务器」这条路能把名单送到设备
 *   上，设备自己不需要能访问 Google。
 *
 * 名单格式（官方与镜像一致）：
 *   {"entries":{"<十进制序列号>":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}
 * 键是【十进制】，而证书链里的序列号是【十六进制】，两边都要能对上，所以这里
 * 统一换算成十六进制做键（附带保留十进制原值便于排障）。
 */

/**
 * 十进制字符串 -> 十六进制字符串。
 * 纯字符串长除法，不依赖 gmp / bcmath（宝塔面板的 PHP 不一定装了这两个扩展）。
 */
function rev_dec2hex(string $dec): string {
    $dec = ltrim($dec, '0');
    if ($dec === '') return '0';
    $hex = '';
    while ($dec !== '' && $dec !== '0') {
        $rem = 0;
        $q = '';
        $n = strlen($dec);
        for ($i = 0; $i < $n; $i++) {
            $cur = $rem * 10 + (int)$dec[$i];
            $qd  = intdiv($cur, 16);
            $rem = $cur % 16;
            if ($q !== '' || $qd !== 0) $q .= (string)$qd;
        }
        $hex = dechex($rem) . $hex;
        $dec = ($q === '') ? '0' : $q;
    }
    return $hex === '' ? '0' : $hex;
}

/** 序列号规范化：去掉 0x / 冒号 / 空格 / 横线，转小写，去前导零 */
function rev_norm_hex(string $s): string {
    $s = strtolower(preg_replace('/[^0-9a-fA-F]/', '', $s));
    $s = ltrim($s, '0');
    return $s === '' ? '0' : $s;
}

/**
 * 解析名单 JSON，返回以【十六进制序列号】为键的索引。
 * @return array<string,array>  hex => ['status'=>..,'reason'=>..,'dec'=>..]
 */
function rev_parse(string $json): array {
    $j = json_decode($json, true);
    if (!is_array($j) || !isset($j['entries']) || !is_array($j['entries'])) return [];
    $out = [];
    foreach ($j['entries'] as $serial => $info) {
        $serial = trim((string)$serial);
        if ($serial === '') continue;
        $isDec = ctype_digit($serial);
        $hex = $isDec ? rev_dec2hex($serial) : rev_norm_hex($serial);
        if ($hex === '0') continue;
        $out[$hex] = [
            'status' => is_array($info) ? (string)($info['status'] ?? 'REVOKED') : 'REVOKED',
            'reason' => is_array($info) ? (string)($info['reason'] ?? '') : '',
            'dec'    => $isDec ? $serial : '',
        ];
    }
    return $out;
}

/** 读取缓存文件，返回 ['fetched_at'=>int,'source'=>str,'entries'=>[...]] 或 null */
function rev_load(string $cacheFile): ?array {
    if (!is_file($cacheFile)) return null;
    $j = json_decode((string)@file_get_contents($cacheFile), true);
    if (!is_array($j) || empty($j['entries']) || !is_array($j['entries'])) return null;
    return $j;
}

/**
 * 多源拉取吊销名单（带缓存）。
 *
 * @param array  $sources    ['名字' => 'URL', ...]，按顺序尝试
 * @param string $accel      GitHub 加速前缀
 * @param string $cacheFile  缓存文件路径
 * @param int    $timeout    单次超时秒
 * @param int    $maxAge     缓存新鲜度（秒），未过期就直接用缓存
 * @return array ['entries'=>[hex=>...], 'source'=>str, 'fetched_at'=>int, 'fresh'=>bool, 'tried'=>[]]
 */
function rev_fetch(array $sources, string $accel, string $cacheFile, int $timeout = 20, int $maxAge = 86400): array {
    $cached = rev_load($cacheFile);
    if ($cached !== null && (time() - (int)($cached['fetched_at'] ?? 0)) < $maxAge) {
        return [
            'entries'    => $cached['entries'],
            'source'     => (string)($cached['source'] ?? '?') . '(缓存)',
            'fetched_at' => (int)($cached['fetched_at'] ?? 0),
            'fresh'      => true,
            'tried'      => [],
        ];
    }

    $tried = [];
    foreach ($sources as $name => $url) {
        $raw = http_get($url, $accel, $timeout, 2);
        if ($raw === false) { $tried[] = $name . ': 下载失败'; continue; }
        $entries = rev_parse($raw);
        // 残缺响应（错误页 / 限流页）直接跳过：真实名单有几百条
        if (count($entries) < 50) {
            $tried[] = $name . ': 只解析出 ' . count($entries) . ' 条，判定不完整，跳过';
            continue;
        }
        @file_put_contents($cacheFile, json_encode([
            'fetched_at' => time(),
            'source'     => $name,
            'url'        => $url,
            'count'      => count($entries),
            'entries'    => $entries,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return [
            'entries'    => $entries,
            'source'     => (string)$name,
            'fetched_at' => time(),
            'fresh'      => true,
            'tried'      => $tried,
        ];
    }

    // 全部源都失败：能用过期缓存也比没有强（吊销名单变化很慢）
    if ($cached !== null) {
        return [
            'entries'    => $cached['entries'],
            'source'     => (string)($cached['source'] ?? '?') . '(已过期缓存)',
            'fetched_at' => (int)($cached['fetched_at'] ?? 0),
            'fresh'      => false,
            'tried'      => $tried,
        ];
    }
    return ['entries' => [], 'source' => '(全部源不可用)', 'fetched_at' => 0, 'fresh' => false, 'tried' => $tried];
}

/**
 * 把十六进制序列号列表转成 kb_normalize_revoked() 能吃的形式。
 * 必须加 0x 前缀：否则纯数字的十六进制串会被误判成十进制再转一次。
 */
function rev_to_revoked_list(array $entries): array {
    $out = [];
    foreach (array_keys($entries) as $hex) {
        if ($hex === '' || $hex === '0') continue;
        $out[] = '0x' . $hex;
    }
    return $out;
}

/** 在名单里查一组序列号（十六进制或十进制混写都行） @return array [hex => 命中信息] */
function rev_check(array $entries, array $serials): array {
    $hit = [];
    foreach ($serials as $s) {
        $s = trim((string)$s);
        if ($s === '') continue;
        $hex = (strpos(strtolower($s), '0x') === 0)
            ? rev_norm_hex(substr($s, 2))
            : (ctype_digit($s) ? rev_dec2hex($s) : rev_norm_hex($s));
        if ($hex !== '0' && isset($entries[$hex])) $hit[$hex] = $entries[$hex];
    }
    return $hit;
}
