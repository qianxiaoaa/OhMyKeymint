本次更新：

- 修复 PIF 指纹下载受 `api.github.com` 限流导致的 403：未认证 REST API 每 IP 每小时仅 60 次，共享出口 IP 会被限流。
  - 改用 `github.com` HTML 端点：`releases/latest` 的 302 `Location` 取当前 tag，`releases/expanded_assets/<tag>` 扫描并校验 JSON 资产名，`releases.atom` 作为 tag 回退。
  - 资产下载仍沿用 gh-proxy 优先、`github.com` 直连回退的策略；`github.com` 下载重定向到 `release-assets.githubusercontent.com` / `objects.githubusercontent.com` 的签名 CDN 链接照常放行。

模块构建：GitHub Actions（arm64-v8a，debug/release）。

**Full Changelog**: https://github.com/qianxiaoaa/OhMyKeymint/compare/v1.3.6-223-49ad8e6...v1.3.6-225-5dbe86b

