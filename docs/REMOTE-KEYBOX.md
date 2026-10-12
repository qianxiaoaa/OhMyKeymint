# Remote keybox distribution

OMK can pull its `keybox.xml` from one or more network mirrors instead of relying
only on the bundled or manually installed file. The feature is decentralized: the
client tries an ordered list of mirrors and accepts the first payload that
verifies against a public key compiled into the binary.

This document covers the trust model, the client configuration, the client
change points, and the server.

## Trust model

- The signing key is the trust root. Only the holder of the Ed25519 private key
  can publish a keybox that the client accepts.
- The client verifies both the SHA-256 of the keybox bytes and an Ed25519
  signature over those bytes against the compiled public key.
- The manifest is untrusted transport. A mirror can serve a stale or corrupted
  payload, but it cannot forge a different keybox.
- Transport is HTTPS only. A compromised mirror or CDN cannot substitute a
  different keybox, and cannot downgrade the client to a plaintext source.

## Manifest schema

The client consumes the nested manifest produced by the PHP server. Unknown
fields (`version`, `module`, `keybox.validity`, `keybox.fallbacks`, ...) are
ignored, so the server can add reporting data without breaking the client.

```json
{
  "version": "1.3.6",
  "version_code": 207,
  "base_url": "https://example.com/api/omk",
  "keybox": {
    "sha256": "<64 hex chars>",
    "signature": "<base64 Ed25519 over the keybox bytes>",
    "url": "https://example.com/api/omk/?action=keybox"
  }
}
```

Only `keybox.sha256` and `keybox.signature` are required. `keybox.url` is
optional; when it is relative it resolves against the serving mirror, and when
it is absent the client falls back to `<base>/?action=keybox` and
`<base>/keybox.xml`.

## Client configuration

Add a `[remote_keybox]` block to `/data/misc/keystore/omk/config.toml`:

```toml
[remote_keybox]
enabled = true
base_urls = [
  "https://keybox.example.com/api/omk",
  "https://fastly.jsdelivr.net/gh/<user>/<repo>@<branch>"
]
interval_secs = 86400
auto_apply = true
```

Each `base_urls` entry may be either a live PHP API base or a static mirror root.
The client tries both forms per mirror, so one ordered list covers both. See
`docs/CONFIGURATION.md` for the full field reference.

Besides the scheduled refresh, the module WebUI exposes an **Update Keybox**
action that triggers one immediate refresh through the same flow. It is shown
only while `enabled` is true and reports whether a newer keybox was applied or
the active one was already current.

## Client change points

Two things must be set on the client side.

1. The trusted public key, in `src/remote_keybox.rs`:

   ```rust
   const TRUSTED_PUBKEY_B64: &str = "<base64 Ed25519 public key>";
   ```

   The server prints this value on its first run. Copy it verbatim and rebuild
   the module. While the value is empty, all remote fetches fail closed and the
   on-device keybox is used unchanged.

2. The mirror list, in `config.toml` under `[remote_keybox].base_urls`. No
   rebuild is needed to change mirrors; the background task reads the live
   configuration on every refresh.

## Server

The server lives in `server/`. It is the yypm PHP service adapted to OMK, has no
external dependencies beyond PHP (`sodium`, `curl`, `openssl`), and serves the
nested manifest above. See `server/README.md` for deployment, endpoints, and the
first-run key generation.

To publish to a static mirror such as GitHub raw or jsDelivr, run `update.php`
once, then copy `data/keybox.xml` and `data/manifest.json` into the branch the
`base_urls` point at. Never copy `keys/` to the mirror.

## Refresh flow

1. Read `[remote_keybox]` from the live configuration.
2. For each `base_urls` entry in order, fetch the manifest from
   `<base>/?action=manifest`, then `<base>/manifest.json`.
3. Build keybox candidates from `keybox.url`, `<base>/?action=keybox`, and
   `<base>/keybox.xml`; download the first one that succeeds.
4. Verify the SHA-256 and Ed25519 signature against the compiled public key.
5. If the verified keybox differs from the active one and `auto_apply` is true,
   install it; the running keymint reloads it and re-pins vbmeta values.
6. Otherwise, log the outcome and retry on the next interval.

## Scope

This feature delivers yypm features 1 (pull and verify a signed keybox) and 4
(decentralized mirroring). It intentionally does not consume the manifest's
`module` object: OMK does not self-update its module package from the network.

## Safety notes

- Changing the keybox identity retires key entries bound to the previous keybox
  and clears attestation caches. Keys signed under the old keybox stop working.
- A mirror that serves a mismatched or unsigned payload is skipped; the loop
  fails closed and the active keybox is left untouched.
- `auto_apply = false` stages a verified keybox under
  `/data/misc/keystore/omk/data/remote_keybox/` without activating it, which is
  useful for reviewing a new keybox before rollout.
