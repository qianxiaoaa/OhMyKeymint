# Oh My Keymint（第三方版本）

> 本仓库基于 [ITxiao6666/OhMyKeymint](https://github.com/ITxiao6666/OhMyKeymint) 二改构建，其上游为 [qwq233/OhMyKeymint](https://github.com/qwq233/OhMyKeymint)。**不是官方版本，也不代表上游维护者**。本版本的问题请反馈至[本仓库](https://github.com/qianxiaoaa/OhMyKeymint/issues)。

面向 Android 的自定义 Keystore / KeyMint 实现，提供应用配置、Keybox 管理及配套 WebUI。

## 安装与使用

需要 **Android 12 及以上**，以及 KernelSU 或 Magisk。自本版本起强制 Android 12 及以上（API 31），更低的系统版本在安装时会被拒绝。

1. 从本仓库的 [Releases](https://github.com/qianxiaoaa/OhMyKeymint/releases) 下载并安装模块。
2. 打开 WebUI，选择需要使用 OMK 的应用，按需导入 Keybox。
3. 高级设置及生效条件请参阅[配置指南](docs/CONFIGURATION.md)。

KernelSU 可直接从模块列表打开 WebUI；Magisk 需自行安装 KSUWebUIStandalone 或 WebUI X。
Zygisk 相关功能需另行安装并启用 Zygisk Next。

## 主要功能

- 应用包名、多用户及应用独立安全补丁配置。
- RSA / EC Keybox 导入与证书链信息查看。
- 安全补丁同步与恢复、Pixel PIF 配置 Soter HAL、本地软件 TA、远程中继及 Tencent Soter
- 运行状态诊断、主题与语言设置。

Keybox 至少需要一个完整的 RSA 或 EC 条目，私钥必须与证书链匹配。
详细配置位于 `/data/misc/keystore/omk/`，请勿公开密钥
## 注意事项

- 软件实现不能替代真实 TEE 或生物认证，不保证通过检测或支付认证。
- 使用前请备份重要数据，实验性功能请谨慎开启。
- 卸载会删除 OMK 配置及密钥数据，可能需要相关应用重新登录或注册；禁用模块不会删除这些数据。
- 卸载会先停止伪装：软件 Soter TA 回滚到原厂 HAL，常驻守护进程随 pidfile 停止，keystore2 会被重启以回到原厂 KeyMint 通路；仍建议卸载后重启一次。
- 卸载脚本清理 `/data/adb/omk` 与 `/data/misc/keystore/omk` 两个目录，KernelSU 与 Magisk 宿主（APatch 需以 Magisk 兼容模式安装）清理范围一致；手动删除模块目录不会执行这些清理。

## 日志

模块与 Rust 组件的日志位于 `/data/misc/keystore/omk/logs/`：

- `keymint.log`（及轮转的 `keymint.log.1`）来自 KeyMint 服务，`injector.log`（及 `injector.log.1`）来自注入器，`service.log`（及轮转的 `service.log.1`）来自 service.sh 启动阶段；六个文件在正常运行下合计约 24 MB。
- 软件 Soter TA 的错误输出位于 `/data/misc/keystore/omk/data/soterta/soterta.err`。
- 反馈问题时请提供复现时刻的上述日志，以及同一时间的 `logcat -d -s OhMyKeymint` 输出；不要上传整个数据目录或 `keybox.xml`。

## Restarting keymint and injector

需要手动重启服务时，可执行对应命令：

```sh
touch /data/adb/omk/restart.keymint
touch /data/adb/omk/restart.injector
touch /data/adb/omk/restart.all
```

哪些设置需要重启服务或设备，请参阅[生效说明](docs/CONFIGURATION.md#how-changes-are-loaded)。

## 版本号与更新通道

构建标识形如 `1.3.6-220-b60dfc9-release`，各段含义：

- `1.3.6`：`Cargo.toml` 中的版本号。
- `220`：提交数（`git rev-list --count HEAD`），同时作为模块 `versionCode`。
- `b60dfc9`：构建所用提交的短哈希，工作区存在未提交改动时带有 `-dirty` 后缀。
- `release` 或 `debug`：构建类型；模块名与包文件名使用同一顺序。

对应的 Release tag 为 `v1.3.6-220-b60dfc9`。浅克隆会得到错误的极小提交数，`build.py` 以
`MIN_VERSION_CODE` 为下限拒绝此类构建，避免发出「降级」的模块。

## 关于本 fork

- 模块 `id` 与上游一致（`oh_my_keymint`），**不能与上游模块共存**：两者会被 root 框架视为同一个模块，同时安装将互相覆盖。
- 更新通道独立：`template/module.prop` 的 `updateJson` 指向本仓库 `changelog` 分支上的 `update.json`，只跟随本仓库的 Release，不会推送上游的更新提示，反之亦然。
- 本仓库由 `Sync upstreams` 工作流定期同步 [ITxiao6666/OhMyKeymint](https://github.com/ITxiao6666/OhMyKeymint)（及其 php-server 组件）后自行构建并发布，版本号首段仅表示同步时的上游版本。

## 许可与致谢

使用前须同时同意 [AGPL-3.0-or-later](LICENSE.md) 和 [Oh My Keymint License](LICENSE-2)。
本软件按原样提供，不作任何担保。

Copyright (C) 2025 James Clef <qwq233@qwq2333.top>
二改作者 Id：浅笑呐

部分代码来自 [AOSP](https://source.android.com/)，采用 [Apache-2.0](template/AOSP.Apache-license-2.0.txt)。

Copyright 2022, The Android Open Source Project

其他第三方来源与许可见[第三方软件说明](docs/THIRD_PARTY.md)。

## 如愿意支持 1.88也是爱 
<img width="1280" height="1280" alt="786affb3c334400a31134945dd5e6515" src="https://github.com/user-attachments/assets/9ac6bc4c-b4a8-492a-9b86-8b7a3417745e" />
