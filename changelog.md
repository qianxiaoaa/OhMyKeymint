本次更新：

- 新增远程 Keybox 分发：按镜像列表拉取签名清单，校验 SHA-256 与 Ed25519 后安装或暂存。
- WebUI 增加立即刷新 Keybox，以及本地壁纸支持。
- 默认镜像为 `https://omk.novapi.cc/api/omk`，更换 keybox 时刷新已钉住的 vbmeta 值。
- 对齐 CI WebUI 产物，并修复远程 Keybox 暂存路径类型。

构建：GitHub Actions（arm64-v8a，debug/release）。
