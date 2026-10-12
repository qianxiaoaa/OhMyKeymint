本次更新：

- 修复重启后 `ro.boot.vbmeta` 值漂移导致的 InvalidKeyBlob：`vb_key`/`vb_hash` 为 auto 时首次解析后写回实际值，更换 keybox 时自动刷新。
- 版本号 1.3.6。

构建：GitHub Actions（arm64-v8a，debug/release）。
