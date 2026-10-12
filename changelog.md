本次更新：

- 修复 WebUI「伪装 PIF 指纹」失败：旧 bot feed 的扩展 JSON 会被当成 unknown key。
- 指纹源改为 Elcapitanoe/PIF-Config-Generator 最新 GitHub Release。
- 下载先走 https://gh-proxy.com/，失败再直连 GitHub。
- 只取 FINGERPRINT、MANUFACTURER、MODEL、SECURITY_PATCH，忽略其余字段。

构建：GitHub Actions（arm64-v8a，debug/release）。
