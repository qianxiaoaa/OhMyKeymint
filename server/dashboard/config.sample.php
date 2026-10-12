<?php
/**
 * yypm 私有配置 —— 这个文件【必须】放在网站根目录之外，且不要进任何仓库。
 * nginx 的 root 是 /www/wwwroot/your-server.example.com，这里是它的兄弟目录，
 * 不在 web 可达范围内。
 */
return [
    'dsn'  => 'mysql:host=127.0.0.1;dbname=yypm;charset=utf8mb4',
    'user' => 'yypm',
    'pass' => 'CHANGE_ME',
];
