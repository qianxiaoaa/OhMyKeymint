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
