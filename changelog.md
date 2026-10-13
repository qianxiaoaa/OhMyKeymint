# Changelog

本文件记录 OhMyKeymint 第三方构建（fork）的变更历史，格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

版本段标题使用发布标识 `上游版本-提交数-短哈希`，与 Release tag（如
`v1.3.6-220-b60dfc9`）和模块 `versionCode`（提交数）一致。
该发布标识占据的正是 Keep a Changelog 惯例中 ISO 日期（`## [1.2.3] - 2017-06-22`）
的位置，属有意选择而非遗漏。

## [1.3.6] - 220-b60dfc9

### Requires

- 最低支持 Android 12（API 31）。此前 `customize.sh` 的 `MIN_SDK=29` 与 README
  「需要 Android 12 及以上」的口径不一致，本次修正后 Android 10/11 的安装会被拒绝。

### Fixed

- 修复 WebUI「伪装 PIF 指纹」失败：旧 bot feed 的扩展 JSON 会被当成 unknown key。

### Changed

- 指纹源改为 Elcapitanoe/PIF-Config-Generator 最新 GitHub Release。
- 下载先走 https://gh-proxy.com/，失败再直连 GitHub。
- 只取 FINGERPRINT、MANUFACTURER、MODEL、SECURITY_PATCH，忽略其余字段。

构建：GitHub Actions（arm64-v8a，debug/release）。
