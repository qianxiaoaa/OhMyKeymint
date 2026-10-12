<?php
/**
 * 下载 + keybox 解码逻辑。
 * 下载支持 GitHub 加速（默认 fast.fumor.top）+ 失败重试 + 直连兜底。
 */

/**
 * 单次 HTTP GET。
 * @return string|false
 */
function http_get_once(string $url, int $timeout) {
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (yypm-downloader)',
        ]);
        $data = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 300 && $data !== false && $data !== '') {
            return $data;
        }
        return false;
    }
    $ctx = stream_context_create([
        'http' => ['timeout' => $timeout, 'user_agent' => 'Mozilla/5.0 (yypm-downloader)'],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $data = @file_get_contents($url, false, $ctx);
    return ($data !== false && $data !== '') ? $data : false;
}

/**
 * 下载（github 源先走加速前缀，失败重试多次，再直连重试多次）。
 *
 * @param string $url     目标 URL
 * @param string $accel   加速前缀，如 https://fast.fumor.top/
 * @param int    $timeout 超时秒
 * @param int    $retries 每个候选地址的重试次数
 * @return string|false
 */
function http_get(string $url, string $accel, int $timeout, int $retries = 3) {
    $isGithub = (strpos($url, 'github.com') !== false)
        || (strpos($url, 'raw.githubusercontent.com') !== false);

    // 候选地址：github 且配置了加速 -> [加速, 直连]；否则 [直连]
    $candidates = [];
    if ($isGithub && $accel !== '' && strpos($url, $accel) !== 0) {
        $candidates[] = rtrim($accel, '/') . '/' . ltrim($url, '/');
    }
    $candidates[] = $url;

    foreach ($candidates as $target) {
        for ($i = 1; $i <= $retries; $i++) {
            $data = http_get_once($target, $timeout);
            if ($data !== false) {
                return $data;
            }
        }
    }
    return false;
}

/**
 * 去除空白字符（空格 / 换行 / 回车 / tab）
 */
function strip_ws(string $s): string {
    return preg_replace('/\s+/', '', $s);
}

/**
 * 按类型解码 keybox 原始内容。
 * @return string|false
 */
function decode_keybox(string $raw, string $type) {
    // 只去掉真正的换行与制表符：空格要保留（hex_base64 的中间层可能解出
    // 带空格分组的 hex 串，剥掉空格会让 hex2bin 失败）。
    $raw = preg_replace('/[\r\n\t]+/', '', $raw);
    if ($raw === '') {
        return false;
    }
    switch ($type) {
        case 'base64': {
            $d = base64_decode($raw, true);
            return ($d === false || $d === '') ? false : $d;
        }
        case 'hex_base64': {
            // 支持两种实际出现过的形态：
            //   (a) 单层 hex：hex2bin 后直接是 XML（当前 integritybox 用的就是这种）
            //   (b) 双层：hex2bin 后是 base64，再解一次才是 XML
            // 两种都试，取能通过基础校验的那个，避免依赖对数据源的假设。
            $hex = preg_replace('/\s+/', '', $raw);
            if (strlen($hex) % 2 !== 0) return false;
            $h = @hex2bin($hex);
            if ($h === false) return false;
            if (strpos($h, '<?xml') !== false || strpos($h, '<AndroidAttestation>') !== false) {
                return $h;
            }
            $d = base64_decode(preg_replace('/\s+/', '', $h), true);
            if ($d !== false && $d !== '' && (strpos($d, '<?xml') !== false || strpos($d, '<AndroidAttestation>') !== false)) {
                return $d;
            }
            return $h;   // 都不是则原样返回，交由上层 validate_keybox 判定
        }
        case 'multi_base64_hex_rot13': {
            $d = $raw;
            for ($i = 0; $i < 10; $i++) {
                // 每轮都重新剥掉上一轮引入的换行/制表符/空白：
                // 否则累积到最后的十六进制串会变成奇数长度，hex2bin 直接失败。
                $d = preg_replace('/\s+/', '', $d);
                if ($d === '') return false;
                $dec = base64_decode($d, true);
                if ($dec === false || $dec === '') return false;
                $d = $dec;
            }
            $d = preg_replace('/\s+/', '', $d);
            if (strlen($d) % 2 !== 0) return false;
            $h = @hex2bin($d);
            if ($h === false) return false;
            $out = str_rot13($h);
            return ($out === '' || $out === false) ? false : $out;
        }
        default:
            return false;
    }
}

/**
 * 校验 keybox 是否为可用的 XML。
 */

/**
 * 把可能带 BOM / UTF-16 的文本统一成 UTF-8。
 *
 * 为什么需要：shall0e/KeyboxHub 里的 keybox 文件是 UTF-16LE 带 BOM 存的
 * （每个 ASCII 字符后面跟一个 0x00），直接拿 ASCII 去匹配 "<?xml" 永远匹配不到，
 * 整个目录源会静默失效。
 */
function kb_to_utf8(string $s): string {
    if (strncmp($s, "\xFF\xFE", 2) === 0) {
        $s = substr($s, 2);
        $enc = 'UTF-16LE';
    } elseif (strncmp($s, "\xFE\xFF", 2) === 0) {
        $s = substr($s, 2);
        $enc = 'UTF-16BE';
    } elseif (strncmp($s, "\xEF\xBB\xBF", 3) === 0) {
        return substr($s, 3);   // 纯 UTF-8 BOM
    } else {
        return $s;               // 本来就是 UTF-8 / ASCII
    }
    if (function_exists('mb_convert_encoding')) {
        return mb_convert_encoding($s, 'UTF-8', $enc);
    }
    if (function_exists('iconv')) {
        $r = @iconv($enc, 'UTF-8//IGNORE', $s);
        if ($r !== false) return $r;
    }
    // 兜底：手工按码元转。keybox 的内容全是 ASCII（PEM/base64），够用。
    $out = '';
    $n = strlen($s) - 1;
    for ($i = 0; $i < $n; $i += 2) {
        $cp = ($enc === 'UTF-16LE')
            ? (ord($s[$i]) | (ord($s[$i + 1]) << 8))
            : ((ord($s[$i]) << 8) | ord($s[$i + 1]));
        if ($cp === 0) continue;
        $out .= ($cp < 0x80) ? chr($cp) : '?';
    }
    return $out;
}

function validate_keybox(string $kb): bool {
    if ($kb === '' || strlen($kb) < 64) return false;
    return strpos($kb, '<?xml') !== false
        && strpos($kb, '<AndroidAttestation>') !== false
        && strpos($kb, 'BEGIN CERTIFICATE') !== false;
}

/**
 * 目录型源：仓库里存着一大批 keybox XML（例如 shall0e/KeyboxHub 有几百个）。
 * 固定某一个文件没意义（随时可能过期或被吊销），所以列出目录后按「日期轮换」
 * 取样若干个，返回第一个能通过基础校验的。
 *
 * 用 GitHub contents API：无需 token，未认证限额 60 次/小时，按天跑的 update 足够。
 * download_url 直接就是 raw.githubusercontent.com 地址，交给 http_get 走加速。
 *
 * $accept 回调让调用方做「深度校验」（证书链/过期/吊销）。不传的话只做基础 XML
 * 校验 —— 但集合仓库里绝大多数文件是过期或已吊销的，只做基础校验基本等于随机
 * 撞一个，所以 update.php 一定会传这个回调。
 *
 * @return array|false  ['keybox'=>XML, 'file'=>文件名, 'tried'=>试了几个] 或 false
 */
function fetch_dir_source(array $src, string $accel, int $timeout, int $retries = 3, int $tryCount = 10, ?callable $accept = null) {
    $repo = trim((string)($src['repo'] ?? ''), '/');
    $dir  = trim((string)($src['dir'] ?? ''), '/');
    if ($repo === '') return false;

    $api = 'https://api.github.com/repos/' . $repo . '/contents/' . $dir;

    // 先直连再走加速（与 http_get 的顺序相反）。原因：api.github.com 在国内
    // 是通的（实测 1.0s / 200），而加速器对大响应会截断 —— KeyboxHub 的目录
    // 列表 533920 字节被截成 481573 字节，JSON 直接不完整，整个源就废了。
    $raw  = http_get_once($api, $timeout);
    $list = ($raw === false) ? null : json_decode($raw, true);
    if (!is_array($list)) {
        $raw  = http_get($api, $accel, $timeout, 2);
        $list = ($raw === false) ? null : json_decode($raw, true);
    }
    if (!is_array($list)) return false;

    // 只保留 XML，且必须带 download_url
    $files = [];
    foreach ($list as $it) {
        if (!is_array($it)) continue;
        $nm = (string)($it['name'] ?? '');
        $dl = (string)($it['download_url'] ?? '');
        if ($dl === '' || !preg_match('/\.xml$/i', $nm)) continue;
        $files[] = ['name' => $nm, 'url' => $dl];
    }
    if (empty($files)) return false;

    // 按日期轮换起点：每天换一批，避免长期只盯着同样几个文件
    $off = ((int)date('z')) % count($files);
    $n   = min($tryCount, count($files));
    for ($i = 0; $i < $n; $i++) {
        $f = $files[($off + $i) % count($files)];
        $xml = http_get($f['url'], $accel, $timeout, 1);
        if ($xml === false) continue;
        // 这些文件是明文 XML，但编码不统一：KeyboxHub 用 UTF-16LE + BOM 存，
        // 不归一化的话 ASCII 匹配 "<?xml" 永远失败，整个源静默失效。
        $xml = kb_to_utf8(trim($xml));
        $xml = trim($xml);
        if (!validate_keybox($xml)) continue;
        if ($accept !== null && !$accept($xml)) continue;   // 深度校验不过就换下一个
        return ['keybox' => $xml, 'file' => $f['name'], 'tried' => $i + 1];
    }
    return false;
}

