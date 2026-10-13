<?php
/**
 * 后台渲染助手 —— 深色简洁风格，配色沿用 dashboard/index.php。
 * 所有对外输出必须走 e()；需要内嵌 HTML（操作按钮、表单）的表格单元格用
 * ['html' => ...] 显式声明，其余一律转义，杜绝“忘记 e()”造成的 XSS。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

/** HTML 转义。 */
function e(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

/** 隐藏 CSRF 输入，供所有写操作表单复用。 */
function csrf_field(): string {
    return '<input type="hidden" name="csrf" value="' . e(auth_csrf_issue()) . '">';
}

/** 顶部导航；$active 命中项高亮。 */
function nav_html(string $active): string {
    $items = [
        'overview' => '概览',
        'usage'    => '领取日志',
        'logs'     => '时间线',
        'devices'  => '设备台账',
        'users'    => '账号',
    ];
    $html = '<nav class="nav">';
    foreach ($items as $k => $label) {
        $cls = $k === $active ? 'on' : '';
        $html .= '<a class="' . $cls . '" href="?page=' . e($k) . '">' . e($label) . '</a>';
    }
    return $html . '</nav>';
}

/** 页头：doctype + 样式 + 顶栏（标题、当前用户、退出）。 */
function render_header(string $title, string $activeNav = ''): void {
    $user = (string)($_SESSION['admin'] ?? '');
    ?><!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?=e($title)?> · OMK 管理后台</title>
<style>
:root{--bg:#111318;--card:#1b1e24;--fg:#e6e1e5;--dim:#a8a2a8;--line:#33363d;--red:#f2b8b5;--redbg:#8c1d18;--grn:#b7f0c0;--grnbg:#1e3a24;--amb:#f5d888;--ambbg:#4a3a12}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.top{border-bottom:1px solid var(--line);background:#0e1015}
.top .in{max-width:1080px;margin:0 auto;padding:14px 16px;display:flex;justify-content:space-between;align-items:center}
.top b{font-size:16px}
.nav{max-width:1080px;margin:0 auto;padding:0 16px;display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.nav a{color:var(--dim);text-decoration:none;padding:10px 14px;font-size:13px;border-bottom:2px solid transparent}
.nav a:hover{color:var(--fg)}
.nav a.on{color:var(--fg);border-bottom-color:#5c5470}
.wrap{max-width:1080px;margin:0 auto;padding:20px 16px 60px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid var(--line);font-size:13px}
.kv:last-child{border-bottom:0}
.kv .k{color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:12px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.tag.red{background:var(--redbg);color:var(--red)}
.tag.grn{background:var(--grnbg);color:var(--grn)}
.tag.amb{background:var(--ambbg);color:var(--amb)}
button,a.btn{background:#2a2e36;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:6px 12px;font-size:13px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,a.btn:hover{background:#343943}
button.pri,a.btn.pri{background:#4a4458;border-color:#5c5470}
button.danger{background:var(--redbg);border-color:#a52a24;color:var(--red)}
input,select,textarea{background:#0e1015;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:8px 12px;font-size:14px}
input[name]{min-width:160px}
form.inline{display:flex;gap:10px;flex-wrap:wrap;align-items:end;margin-bottom:14px}
form.inline label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--dim)}
.muted{color:var(--dim);font-size:12.5px}
.note{color:var(--dim);font-size:12.5px;border-left:2px solid var(--line);padding-left:10px;margin:10px 0}
.empty{color:var(--dim);padding:18px 0;text-align:center}
.err{color:var(--red);margin:8px 0}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:14px;font-size:13px}
.flash.ok{background:var(--grnbg);color:var(--grn)}
.flash.bad{background:var(--redbg);color:var(--red)}
.pager{display:flex;gap:8px;align-items:center;margin-top:12px;font-size:13px}
</style>
</head><body>
<div class="top"><div class="in">
  <b>OMK 管理后台</b>
  <span class="muted"><?=e($user)?> · <form method="post" action="?page=<?=e($activeNav)?>" style="display:inline"><input type="hidden" name="csrf" value="<?=e(auth_csrf_issue())?>"><input type="hidden" name="logout" value="1"><button type="submit" style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:14px;padding:0;text-decoration:underline">退出</button></form></span>
</div></div>
<?=nav_html($activeNav)?>
<div class="wrap">
<?php
}

/**
 * 公开页头（登录页用）：只出样式与标题，不含导航/当前用户/退出。
 * 复用与 render_header 相同的 <style>，保证视觉一致。
 */
function render_public_header(string $title): void {
    ?><!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?=e($title)?> · OMK 管理后台</title>
<style>
:root{--bg:#111318;--card:#1b1e24;--fg:#e6e1e5;--dim:#a8a2a8;--line:#33363d;--red:#f2b8b5;--redbg:#8c1d18}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:60px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
h1{font-size:20px;margin:0 0 4px}
input{background:#0e1015;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:8px 12px;font-size:14px;width:100%}
button{background:#4a4458;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:6px 14px;font-size:13px;cursor:pointer}
.err{color:var(--red);margin-top:8px}
.note{color:var(--dim);font-size:12.5px;border-left:2px solid var(--line);padding-left:10px;margin:10px 0}
</style>
</head><body><div class="wrap">
<h1>OMK 管理后台</h1>
<div style="color:var(--dim);font-size:13px;margin-bottom:20px">管理后台</div>
<?php
}

/** 页脚：关标签 + 版本注释。 */
function render_footer(): void {
    echo "</div>\n";
    // 版本注释：便于在浏览器源码里确认部署的是哪一版后台
    echo "<!-- OMK qianxiao 1.0 -->\n";
    echo "</body></html>\n";
}

/**
 * 通用表格。$headers 为列标题数组；$rows 为行数组，每行是与列对齐的单元格数组。
 * 单元格：标量 -> 走 e() 转义；['html'=>...] -> 原样输出（调用方自己保证已转义/构造）。
 */
function table(array $headers, array $rows): string {
    $h = '<table><thead><tr>';
    foreach ($headers as $c) $h .= '<th>' . e((string)$c) . '</th>';
    $h .= '</tr></thead><tbody>';
    if (!$rows) {
        $col = count($headers);
        return $h . '<tr><td colspan="' . $col . '"><div class="empty">没有记录</div></td></tr></tbody></table>';
    }
    foreach ($rows as $row) {
        $h .= '<tr>';
        foreach ($row as $cell) {
            if (is_array($cell) && isset($cell['html'])) $h .= '<td>' . $cell['html'] . '</td>';
            else $h .= '<td>' . e((string)$cell) . '</td>';
        }
        $h .= '</tr>';
    }
    return $h . '</tbody></table>';
}

/** 一次性提示条。 */
function flash(string $msg, string $type = 'ok'): string {
    $cls = $type === 'bad' ? 'bad' : 'ok';
    return '<div class="flash ' . $cls . '">' . e($msg) . '</div>';
}
