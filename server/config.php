<?php
/**
 * 全局配置 —— 部署在网站目录 /api/omk/ 下，自包含。
 * update.php（cron/web 调用）与 index.php（web）都会加载本文件。
 *
 * 这是 OhMyKeymint（OMK）适配版：服务端把 keybox 与模块包下发给 OMK 客户端
 * 的 [remote_keybox] 特性。源码基于 yypm 的 PHP 服务端。
 *
 * 说明：
 *   - 所有数据（keybox.xml / manifest.json / module.zip）与密钥都在本目录内。
 *   - 私钥 keys/ed25519.key 由 www 用户持有（600），并通过 nginx 规则禁止 web 直接访问。
 *   - 首次运行 update.php 会生成密钥并把公钥写入 keys/ed25519.pub；
 *     把该公钥填入 OMK 客户端 src/remote_keybox.rs 的 TRUSTED_PUBKEY_B64 后重新编译。
 */
return [
    // 对客户端可见的 API 基础地址
    'base_url' => 'https://your-server.example.com/api/omk',

    // 数据目录（keybox.xml / manifest.json / module.zip）
    'data_dir' => __DIR__ . '/data',

    // 密钥目录（Ed25519 私钥/公钥）
    'keys_dir' => __DIR__ . '/keys',

    'module_pkg'   => 'module.zip',
    'keybox_in'    => 'keybox.xml',

    // 人工固定 keybox：文件存在且校验通过时，update.php 永远优先用它，
    // 不再被上游源覆盖（A/B 实验/回滚用：删掉该文件即恢复自动择优）。
    'keybox_pin' => __DIR__ . '/data/keybox.pinned.xml',

    // 兜底版本号：manifest 里的 version/version_code 优先取自 data/module.zip 内的
    // module.prop。只有当包缺失或解析不到时才回退到这里。
    'version'      => '1.3.6',
    'version_code' => 1,

    // GitHub 加速前缀（github.com 源先走此加速，失败再直连）
    'github_accel' => 'https://fast.fumor.top/',

    // 模块目录：package.json 在此目录内，自动下载的模块也存这里
    'package_dir'  => __DIR__ . '/package',
    'package_json' => 'package.json',

    // 下载重试次数
    'download_retries' => 3,

    // keybox 上游源（与 1.zip 脚本一致）
    'sources' => [
        'yurikey' => [
            'enabled' => true,
            'url'      => 'https://raw.githubusercontent.com/Yurii0307/yurikey/main/key',
            'type'     => 'base64',
            // 优先级：1 = 人工挑选并长期验证过的源，永远优先；
            //         2 = 集合仓库（成百上千个文件，按日期轮换取样），只在 1 全挂时兜底。
            'priority' => 1,
        ],
        'integritybox' => [
            'enabled' => true,
            // 数据是 10 轮 base64 -> hex -> rot13 的嵌套编码。
            // 注意：解码器必须每轮都重新剥掉上一轮引入的换行，否则累积到
            // 最后的十六进制串会变成奇数长度、hex2bin 失败（历史上该源一直
            // 静默失败就是这个原因，已在 lib/sources.php 修正）。
            'url'      => 'https://raw.githubusercontent.com/MeowDump/MeowDump/refs/heads/main/NullVoid/OptimusPrime',
            'type'     => 'multi_base64_hex_rot13',
            'priority' => 1,
        ],
        'megatron' => [
            'enabled' => true,
            // 与 integritybox 同一套编码（10 轮 base64 -> hex -> rot13）。
            // 实测 447322 字节，解码后是完整 XML，明文里能看到
            // "fetched from https://keybo..." 的注释。
            'url'      => 'https://raw.githubusercontent.com/MeowDump/MeowDump/main/Megatron',
            'type'     => 'multi_base64_hex_rot13',
            'priority' => 1,
        ],
        'tricky_addon' => [
            // 2026-10 实测该地址返回 0 字节（源已失效），保持关闭；
            // 保留配置是为了它复活时能一键打开。
            'enabled' => false,
            'url'     => 'https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/keybox/.extra',
            'type'    => 'hex_base64',
        ],

        // ---- 目录型源：一个仓库里存着成百上千个 keybox，按日期轮换取样 ----
        // 这两个仓库本身是「keybox 收集站」，单个固定文件没意义（会过期），
        // 所以由 fetch_dir_source() 列目录后轮流试，取第一个通过校验的。
        'keyboxhub' => [
            'enabled' => true,
            'type'     => 'github_dir',
            'priority' => 2,
            'repo'     => 'shall0e/KeyboxHub',
            'dir'      => 'KeyboxHub',
        ],
        'keyboxstatus' => [
            'enabled' => true,
            'type'     => 'github_dir',
            'priority' => 2,
            'repo'     => 'SSM-FX/KeyboxStatus',
            'dir'      => '',
        ],
    ],

    /**
     * 吊销名单（Google attestation/status）的多源配置。
     *
     * 官方地址在国内服务器上完全连不通（curl 返回 000），所以顺序上把 GitHub
     * 镜像排在前面，官方地址放最后作为形式上的兜底。镜像由各自仓库的 GitHub
     * Actions 定时同步，通常比官方只落后几小时。
     *
     * 服务器拉下来后缓存在 data/revocation.json，设备通过 ?action=revocation
     * 取走自己缓存 —— 设备端同样不需要能访问 Google。
     */
    'revocation_sources' => [
        'purainity' => 'https://raw.githubusercontent.com/purainity/keybox-tools/main/res/status.json',
        'kimmyxyc'  => 'https://raw.githubusercontent.com/KimmyXYC/KeyboxChecker/main/res/json/status.json',
        'google'    => 'https://android.googleapis.com/attestation/status',
    ],

    // 吊销名单缓存新鲜度（秒）。名单变化很慢，一天一次足够。
    'revocation_max_age' => 86400,

    // 防盗签名（Ed25519，需 sodium）
    'sign_enable'     => true,
    'sign_public_out' => 'ed25519.pub',
    'sign_secret_in'  => 'ed25519.key',

    /**
     * 已知被吊销的证书序列号。
     * 支持十进制或十六进制（带不带 0x、大小写、带 : 分隔都行），服务端会统一规范化。
     * 用途：Google 吊销某份 keybox 后，把它证书链里的序列号填在这里，
     * 服务端会判定该源无效并自动切换到其它源。
     */
    'revoked_serials' => [
        // '64DEAA4D53885472AFAC267BDBD4A472',
        // '12214718865605971583567181966175043249',   // 十进制写法同样支持
    ],

    'timeout' => 60,
];
