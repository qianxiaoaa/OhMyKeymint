<?php
/**
 * 登录页。可用变量：$pdo、$loginErr。
 * 错误文案通用化（auth_login 已保证不区分用户不存在/口令错）。
 */
declare(strict_types=1);

// 入口守卫：本文件只能由 qianxiao/index.php（已 define ADMIN_BOOT）纳入，
// 防 nginx try_files $uri 形态下被直连执行（直连靠 Fatal 偶然 fail-closed，display_errors 开启还会泄露路径）。
if (!defined('ADMIN_BOOT')) { http_response_code(403); exit; }

render_public_header('登录');
?>
<div class="card" style="max-width:380px">
  <form method="post" action="?page=login" autocomplete="off">
    <input name="user" placeholder="用户名" autofocus style="margin-bottom:8px" autocomplete="username">
    <input type="password" name="pass" placeholder="口令" autocomplete="current-password">
    <div style="margin-top:12px"><button type="submit">进入</button></div>
  </form>
  <?php if ($loginErr !== ''): ?>
    <div class="err"><?=e($loginErr)?></div>
  <?php endif; ?>
  <div class="note">口令以 bcrypt 存在本机 SQLite 里，服务器磁盘上没有明文口令文件。连续失败 5 次会锁 15 分钟。</div>
</div>
<?php
render_footer();
