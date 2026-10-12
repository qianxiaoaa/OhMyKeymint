# OhMyKeymint remote keybox server (PHP)

This directory is the OhMyKeymint (OMK) remote keybox / module distribution server.
It is the yypm PHP service adapted to OMK: it publishes a signed `keybox.xml` that
the OMK client consumes through the `[remote_keybox]` feature (keybox fetch and
verify, decentralized mirroring). It can also serve a signed module package
(`?action=module`), which the OMK client does not currently consume.

It is a standalone deployment component. The module build and release (`build.py`,
CI) never reads this directory, so building or publishing the module does not
build, package, or ship the server. Deploy it separately on a PHP host.

All data and keys live inside this directory. It has no external dependencies
beyond PHP with the standard `sodium`, `curl` and `openssl` extensions.

## Layout

| Path | Purpose |
| --- | --- |
| `config.php` | Server configuration: public `base_url`, data/keys paths, pinned keybox identity, upstream keybox sources. |
| `public/index.php` | Web API entry point. Route with `?action=`. |
| `update.php` | Cron/web job: collect an upstream keybox, validate it, write `data/keybox.xml`, then rebuild `data/manifest.json`. |
| `fetch_packages.php` | Cron job: fetch module/APK assets listed in `package/sources.json` into `package/`. |
| `lib/sign.php` | Ed25519 key management and detached signing (`sign_ensure_keys`, `sign_data`). |
| `lib/keybox.php` | Keybox validation/selection helpers. |
| `lib/sources.php` | Upstream keybox source definitions and collection. |
| `lib/revocation.php` | Revocation list checks. |
| `lib/packages.php` | Package manifest helpers. |
| `dashboard/` | Optional operator dashboard (copy `config.sample.php` to `config.php`). |
| `migrations/` | Optional SQL migrations for the report database. |

## API

`public/index.php` dispatches on `?action=`:

| Action | Returns |
| --- | --- |
| `manifest` | `data/manifest.json` (version, keybox sha256 + Ed25519 signature, module block, fallbacks). |
| `keybox` | `data/keybox.xml` with `X-Signature` and `X-SHA256` headers. |
| `module` | `data/module.zip`. |
| `pubkey` | Base64 Ed25519 public key. |
| `revocation` | Revocation list. |

Static mirrors can serve `manifest.json`, `keybox.xml`, `module.zip` directly.
The OMK client tries the query form (`?action=...`) and the static form on each
configured base URL, so both the PHP server and a static CDN mirror work.

## First run

1. Edit `config.php`; set `base_url` to the public address of this directory and
   adjust `sources` to the upstream keybox sources you trust.
2. Run `update.php` once. On first run `lib/sign.php` generates
   `keys/ed25519.key` (private, `600`, web-inaccessible) and `keys/ed25519.pub`.
3. Build the OMK module package and drop it in as `data/module.zip`, or set
   `module_pkg` to its source path. The manifest reads `version`/`version_code`
   from the package's `module.prop`; `config.php` values are only a fallback.
4. Copy `keys/ed25519.pub` into the OMK client trust anchor: set
   `TRUSTED_PUBKEY_B64` in `src/remote_keybox.rs` and rebuild. The client verifies
   both `sha256` and the Ed25519 signature before installing anything.
5. Schedule `update.php` and `fetch_packages.php` (cron or a web hook) to refresh
   the keybox and packages.

## Decentralized mirrors

Point the OMK client's `[remote_keybox].base_urls` at one or more mirrors. Each
entry may be a PHP API base (`?action=...`) or a static mirror root serving
`manifest.json` / `keybox.xml` / `module.zip`. The client uses them as ordered
fallbacks when a fetch fails.

## Notes

- `data/` and `keys/` are git-ignored; never commit private keys or downloaded assets.
- The optional report actions (`keyboxreport`, `acreport`) require the separate
  operator database configured in `dashboard/config.php`; they are inert when unset.
