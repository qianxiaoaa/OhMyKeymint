本次更新：

- 模块脚本与 Rust 侧健壮性修复：
  - 安装最低要求对齐 Android 12（API 31），并补齐 ARCH/API 缺失校验与 webroot 资产路径校验。
  - service.sh 重写 resetprop 多管理器回退链（KernelSU/Magisk/APatch/ksud），启动改为探测 `dev.bootcomplete`，新增日志轮转与更严格的进程匹配。
  - daemon / daemon-injector 新增崩溃指数退避。
  - 卸载改为按 pidfile 停止守护进程并重启 keystore2 回到原厂通路。
  - keybox 证书链过期告警（仅日志）。
- 构建与 CI：浅克隆拒绝打包（`MIN_VERSION_CODE`），新增 lint job，停止覆写 changelog.md，清理误提交的构建产物。
- 服务端：新增独立部署的 qianxiao 管理后台与领取使用埋点（不进入模块包）。

模块构建：GitHub Actions（arm64-v8a，debug/release）。

