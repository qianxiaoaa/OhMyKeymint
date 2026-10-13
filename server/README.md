# OhMyKeymint 远程 keybox 服务端（PHP）

本目录是 OhMyKeymint（OMK）的远程 keybox / 模块分发服务端，由 yypm 的 PHP
服务端适配而来。它对外发布一份带签名的 `keybox.xml`，供 OMK 客户端的
`[remote_keybox]` 特性消费（拉取并验签、去中心化镜像）；同时也能提供带签名的
模块包（`?action=module`），当前 OMK 客户端暂不消费它。

它是独立的部署组件。模块构建与发行（`build.py`、CI）从不读取本目录，因此构建
或发布模块都不会构建、打包或携带服务端。请把它单独部署在 PHP 主机上。

所有数据与密钥都存放在本目录内。除 PHP 的 `sodium`、`curl`、`openssl` 扩展外，
没有其他外部依赖。

## 目录结构

| 路径 | 用途 |
| --- | --- |
| `config.php` | 服务端配置：公网 `base_url`、数据/密钥路径、固定 keybox、上游 keybox 源。 |
| `public/index.php` | Web 接口入口，通过 `?action=` 路由。 |
| `update.php` | 定时任务：从上游拉取 keybox、校验、写出 `data/keybox.xml`，再重建 `data/manifest.json`。 |
| `fetch_packages.php` | 定时任务：按 `package/sources.json` 抓取模块/APK 资产到 `package/`。 |
| `lib/sign.php` | Ed25519 密钥管理与分离签名（`sign_ensure_keys`、`sign_data`）。 |
| `lib/keybox.php` | keybox 校验/择优辅助。 |
| `lib/sources.php` | 上游 keybox 源定义与采集。 |
| `lib/revocation.php` | 吊销名单检查。 |
| `lib/packages.php` | 包清单辅助。 |
| `dashboard/` | 可选运维面板（把 `config.sample.php` 复制为 `config.php` 使用）。 |
| `qianxiao/` | 管理后台（公网可访问，三级访问控制，详见下方宝塔部署指南）。 |
| `migrations/` | 可选的上报数据库 SQL 迁移。 |

## 接口

`public/index.php` 通过 `?action=` 分发：

| action | 返回 |
| --- | --- |
| `manifest` | `data/manifest.json`（版本、keybox 的 sha256 与 Ed25519 签名、模块块、备用池）。 |
| `keybox` | `data/keybox.xml`，响应头带 `X-Signature`、`X-SHA256`。 |
| `module` | `data/module.zip`。 |
| `pubkey` | base64 编码的 Ed25519 公钥。 |
| `revocation` | 吊销名单。 |

静态镜像可以直接提供 `manifest.json`、`keybox.xml`、`module.zip`。OMK 客户端会在
每个配置的 base URL 上同时尝试 `?action=...` 形式与静态文件形式，因此既能用本
PHP 服务端，也能用静态 CDN 镜像。

## 部署

前置：PHP 8.x（7.4+ 可用），需 `sodium`、`curl`、`openssl` 扩展；一台 Web 服务器；
cron。`python3` 仅在 `fetch_packages.php` / `scan_packages.sh` 用到。

因为 `public/index.php` 读取 `__DIR__/data`，需平铺部署到同一个 Web 目录：

```
/api/omk/                 <- Web 目录，base_url 指向这里
├── index.php             <- 从 public/index.php 复制过来
├── update.php
├── fetch_packages.php
├── scan_packages.sh、scan_packages.py
├── update.sh
├── config.php
├── lib/
├── dashboard/            （可选）
├── qianxiao/             （管理后台，公网可访问）
├── migrations/           （可选）
├── package/              （package.json、sources.json、下载的资产）
├── data/                 （运行时生成：keybox.xml、manifest.json、module.zip）
└── keys/                 （运行时生成：ed25519.key、ed25519.pub）
```

1. 把本目录内容上传到例如 `/www/wwwroot/<你的域名>/api/omk`，并把
   `public/index.php` 移到该目录顶层（与 `data/` 同级）。
2. 编辑 `config.php`：把 `base_url` 设为该目录的公网地址，并检查 `sources` 与
   `revocation_sources`。
3. 创建并授权可写目录：
   `mkdir -p data keys package && chown -R www:www data keys package`。
4. 首次运行（以 Web 用户身份）：`sudo -u www php update.php`。它会生成密钥对、
   从你的上游源选一份有效 keybox，并写出 `data/keybox.xml` 与
   `data/manifest.json`。打印 `keys/ed25519.pub`，它就是客户端信任锚。随后
   `chmod 600 keys/ed25519.key`。
5. 可选：把模块包放到 `data/module.zip`（用本仓 `python3 build.py --release`
   产出）。不放时，版本号 `version`/`version_code` 回退到 `config.php`。
6. 禁止 Web 访问 `keys/`，并把目录路由到 `index.php`：

   ```nginx
   location ^~ /api/omk/keys/ { deny all; }
   location /api/omk/ {
       index index.php;
       try_files $uri /api/omk/index.php?$query_string;
   }
   ```

7. 配置刷新计划任务。先按你的主机改 `update.sh` 里的 `PHP=` 与 `DIR=`，再用
   cron 执行（脚本会先跑 `fetch_packages.php`，再跑 `update.php`）：

   ```cron
   0 */6 * * * /www/wwwroot/<你的域名>/api/omk/update.sh >> /www/wwwroot/<你的域名>/api/omk/data/cron.log 2>&1
   ```

8. 验证：

   ```sh
   curl -s  "https://<你的域名>/api/omk/?action=manifest" | head
   curl -sI "https://<你的域名>/api/omk/?action=keybox"
   ```

## 客户端接入（本项目的模块）

模块通过两处配置消费服务端，服务端文件不会进入模块包。

1. `src/remote_keybox.rs`：把编译期信任锚设为服务端公钥：

   ```rust
   const TRUSTED_PUBKEY_B64: &str = "<server keys/ed25519.pub 的内容>";
   ```

   改完需重新编译模块。

2. `/data/misc/keystore/omk/config.toml`：

   ```toml
   [remote_keybox]
   enabled = true
   base_urls = ["https://<你的域名>/api/omk"]
   interval_secs = 86400
   auto_apply = true
   ```

3. 构建并安装模块：`python3 build.py --release`，然后刷入生成的
   `OhMyKeymint-*.zip`（或使用 `scripts/deploy_hot_update.py`）。

模块构建（`build.py`、CI）从不读取本目录，所以服务端始终单独部署在 PHP 主机上，
不会被构建进模块 zip。

## 去中心化镜像

把 OMK 客户端的 `[remote_keybox].base_urls` 指向一个或多个镜像。每一项既可以是
PHP API 基址（`?action=...`），也可以是提供静态 `manifest.json` / `keybox.xml` /
`module.zip` 的镜像根目录。某次拉取失败时，客户端会按顺序回退到下一项。

## 说明

- `data/` 与 `keys/` 已被 git 忽略；切勿提交私钥或下载的资产。
- 可选的上报动作（`keyboxreport`、`acreport`）依赖 `dashboard/config.php` 里单独
  配置的运维数据库；未配置时它们处于停用状态。

## 管理后台（qianxiao/）

`qianxiao/` 是公网上可访问的运维后台：看当前 keybox 状态与证书有效期/吊销、
领取日志、操作时间线、设备台账、管理员账号。它与分发接口共用一个轻量 SQLite，
不依赖 MySQL，也不改动 `update.php` / `lib/sign.php` 的任何签名逻辑。

### 访问控制三级策略

后台顶部守卫按 `qianxiao/config.php`（从 `config.sample.php` 复制）决定谁能访问：

| 模式 | 条件 | 行为 |
| --- | --- | --- |
| 公网（默认） | `config.php` 不存在，或 `allow_loopback_only=false` 且 `allow_ips=[]` | 任意 IP 可达登录页 |
| IP 白名单 | `allow_ips` 非空 | 仅白名单 + 回环可达，其余 403 `forbidden` |
| 仅回环 | `allow_loopback_only=true` | 仅 127.0.0.1/::1（紧急收紧/SSH 隧道用） |

只信 `REMOTE_ADDR`，不信 X-Forwarded-For（可伪造）。

### 目录结构

| 路径 | 用途 |
| --- | --- |
| `qianxiao/index.php` | 单入口：三级访问守卫 + `?page=` 白名单路由 + 登录门槛 + 统一 CSRF。 |
| `qianxiao/config.sample.php` | 访问控制配置模板（复制为 config.php 生效，已 .gitignore 不入库）。 |
| `qianxiao/lib/db.php` | SQLite 懒连 + 首跑自愈建表（`admin_user`/`usage_log`/`device`/`audit`/`login_fail`）。 |
| `qianxiao/lib/auth.php` | 会话/bcrypt/CSRF/按 IP 登录限流/审计/空闲超时 4h。 |
| `qianxiao/lib/page.php` | 渲染助手（`e()` 转义、表格、表单、深色内联样式）。 |
| `qianxiao/pages/*.php` | `login`/`overview`/`usage`/`logs`/`devices`/`users` 六个页面。 |
| `qianxiao/cli.php` | 仅 CLI：`init-admin`/`passwd`/`prune-logs`。 |
| `lib/usage_log.php` | 领取埋点共享库（被 `public/index.php` 以 fail-safe 方式调用）。 |
| `data/admin.sqlite` | 后台与领取日志的数据文件（历史命名，与目录名无关；`data/` 已被 git 忽略）。 |
| `data/devices/<hash>.json` | 设备台账的镜像文件（与 `device` 表双写）。 |
| `migrations/2026-10-14-admin-schema.sql` | 迁库参考；实际运行用 SQLite 自愈建表。 |

### 宝塔部署步骤

前置：PHP 8.4（宝塔 → 软件商店 → 安装 PHP-8.4）；需 `sodium`、`curl`、`openssl`、`pdo_sqlite` 扩展。

#### 1. 创建站点并平铺部署

沿用现有 `/api/omk/` 平铺结构，把 `qianxiao/` 一并复制到同层：

```
/www/wwwroot/<你的域名>/api/omk/
├── index.php             ← 从 public/index.php 复制
├── update.php
├── fetch_packages.php
├── config.php
├── lib/
├── qianxiao/             ← 后台目录
├── dashboard/
├── package/
├── data/                 ← 运行时生成：keybox.xml、manifest.json、admin.sqlite
└── keys/                 ← 运行时生成：ed25519.key、ed25519.pub
```

#### 2. PHP 扩展确认

宝塔 → 软件商店 → PHP-8.4 → 设置 → 安装扩展 → 确认以下已开启：
- `pdo_sqlite`（后台 SQLite 必须）
- `sodium`、`curl`、`openssl`（分发接口签名必须）

#### 3. 安全必做：nginx 禁止敏感目录 web 访问

宝塔 → 站点 → 设置 → 配置文件，在 `server { }` 内加入：

```nginx
# 禁止 web 读取数据文件（keybox.xml/admin.sqlite/私钥）
location ~ ^/api/omk/(data|keys)/ { deny all; }

# 禁止直连后台内部文件（应用层另有 ADMIN_BOOT 守卫兖底）
location ~ ^/api/omk/qianxiao/(pages|lib)/ { deny all; }
```

> 注意不要写成 `location ^~ /api/omk/qianxiao/`，^~ 会跳过正则检查，deny 就失效了。

#### 4. 开启强制 HTTPS

宝塔 → 站点 → 设置 → SSL → 申请/部署证书 → 开启「强制 HTTPS」。
后台会话 Cookie 的 Secure 标志依赖 `$_SERVER['HTTPS']`，php-fpm 在 HTTPS 站点下会自动透传。

#### 5. open_basedir

宝塔默认开启 `open_basedir`（防跨站攻击），后台与 data/ 在同一站点目录内不受影响，保持默认即可。

#### 6. cron 计划任务

用现成的 `update.sh`（它已配置为宝塔 PHP 8.4 路径）：

```
0 */6 * * * /www/wwwroot/<你的域名>/api/omk/update.sh >> /www/wwwroot/<你的域名>/api/omk/data/cron.log 2>&1
```

宝塔 → 计划任务 → Shell 脚本，填入同上路径即可。

### 初始化

```sh
# 以 www 用户执行（站点目录内）
cd /www/wwwroot/<你的域名>/api/omk
sudo -u www /www/server/php/84/bin/php qianxiao/cli.php init-admin <admin_user> '<strong_pass>'
```

建号后浏览器打开 `https://<你的域名>/api/omk/qianxiao/` 登录。建议登录后立即在「账号」页重置口令为新的强口令（≥ 16 位，大小写+数字+符号）。

日志清理：`php qianxiao/cli.php prune-logs 90`（删 90 天前的领取日志）。

本机调试可用 `./qianxiao-start.sh`（默认 127.0.0.1:8787，环境变量 `QX_HOST`/`QX_PORT`/`PHP` 可覆盖）。

### 冒烟清单（需在目标主机验证）

1. `php -l` 逐个语法检查 `qianxiao/*.php`、`qianxiao/lib/*.php`、`qianxiao/pages/*.php`、
   `lib/usage_log.php`、`public/index.php`。
2. 确认 `pdo_sqlite` 扩展可用；`data/` 对 www 用户可写。
3. `php qianxiao/cli.php init-admin` 能建表并创建首个管理员。
4. 公网可达：从外部网络 `curl -sI "https://<你的域名>/api/omk/qianxiao/?page=login"` 应返回 200 + HTML。
5. 三级守卫验证：
   - 无 config.php → 任意 IP 可达登录页。
   - 设 `allow_ips=['1.2.3.4']` → 非白名单 IP 收到 403 `forbidden`，白名单可达。
   - 设 `allow_loopback_only=true` → 仅服务器本机可达，外部 403。
6. 登录会话：登录后访问概览页确认显示 keybox 状态；空闲超 4h 后自动失效回到登录页。
7. 退出登录：确认是 POST 而非 GET（浏览器源码查看导航栏的退出是表单按钮）。
8. 走一次 `?action=keybox`/`?action=manifest`，回后台「领取日志」应看到新行。
9. 设备台账增/改/删后，`data/devices/<hash>.json` 与 `device` 表保持一致。
10. 内部文件不可直连：`curl -s -o /dev/null -w '%{http_code}\n' "https://<域名>/api/omk/qianxiao/pages/login.php"`
    与 `.../qianxiao/lib/db.php` 都应返回 403。
11. CSV 公式注入已中和：用 UA 为 `=1+1` 的客户端触发一次领取，再到「领取日志」导出 CSV 确认前置单引号。

### 红线

- **私钥 `keys/ed25519.key` 不可读、不可展示、不可改**；后台只在概览页展示
  公钥 `keys/ed25519.pub` 的存在性与 sha256 指纹。
- **不改动 `update.php` / `lib/sign.php`，也不影响 `data/manifest.json` 中
  `keybox.{url,sha256,signature}` 三字段的生成语义。**

### 领取日志说明

分发接口（`?action=keybox`/`manifest`）是**匿名**的：埋点只能记录来源 IP、UA、
本次下发 keybox 的 sha256 与序列号串，**无法**关联到具体设备。设备与领取的对应
关系需另行维护，见「设备台账」页（`data/devices/` 镜像 JSON）。

### 风险告知

公网后台是密码学之外的攻击面，请注意：

- 使用强口令（后台 CLI 建号强制 ≥ 10 位，建议实际部署用 ≥ 16 位复合口令）。
- 定期查看「时间线」审计页，确认无异常登录。
- 考虑配置 IP 白名单（`qianxiao/config.php` 的 `allow_ips`）限制访问源。
- 临时收紧可设 `allow_loopback_only=true` + SSH 隧道访问：`ssh -L 8787:127.0.0.1:8787 user@server`。
- 可选加强：宝塔免费 WAF、fail2ban 监控登录失败日志、站点层限制 qianxiao/ 的访问频率。

### 已知限制

- `data/admin.sqlite` 文件名保持不变（历史命名，与后台目录名无关），以避免牵连 `lib/usage_log.php`（它不在本次改动范围内）。
- `?action=manifest` 分支的埋点多读一次 `data/manifest.json`：热路径可后续在
  `manifestKeybox()` 里加 `static` 缓存同一请求内的解析结果（`keybox` 分支只读一次，无此问题）。
- 会话空闲超时 4h 为纯 session 侧实现，不记入 DB；清除浏览器 Cookie 等同立即失效。
