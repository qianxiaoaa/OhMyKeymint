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

## Deployment

Requirements: PHP 8.x (7.4+ works) with the `sodium`, `curl` and `openssl`
extensions, a web server, and cron. `python3` is only needed for
`fetch_packages.php` / `scan_packages.sh`.

Deploy flat into one web directory, because `public/index.php` reads
`__DIR__/data`:

```
/api/omk/                 <- the web directory base_url points at
├── index.php             <- copied from public/index.php
├── update.php
├── fetch_packages.php
├── scan_packages.sh, scan_packages.py
├── update.sh
├── config.php
├── lib/
├── dashboard/            (optional)
├── migrations/           (optional)
├── package/              (package.json, sources.json, downloaded assets)
├── data/                 (created at runtime: keybox.xml, manifest.json, module.zip)
└── keys/                 (created at runtime: ed25519.key, ed25519.pub)
```

1. Upload the contents of this directory to e.g.
   `/www/wwwroot/<your-domain>/api/omk`, and move `public/index.php` up into that
   same directory (next to `data/`).
2. Edit `config.php`: set `base_url` to the public URL of this directory, and
   review `sources` and `revocation_sources`.
3. Create and own the writable directories:
   `mkdir -p data keys package && chown -R www:www data keys package`.
4. First run as the web user: `sudo -u www php update.php`. It generates the
   keypair, selects a valid keybox from your sources, and writes
   `data/keybox.xml` plus `data/manifest.json`. Print `keys/ed25519.pub`; that is
   the client trust anchor. Then `chmod 600 keys/ed25519.key`.
5. Optionally drop a module package at `data/module.zip` (build one from this
   repo with `python3 build.py --release`). Without it, `version`/`version_code`
   fall back to `config.php`.
6. Deny web access to `keys/` and route the directory to `index.php`:

   ```nginx
   location = /api/omk/keys { deny all; }
   location ^~ /api/omk/keys/ { deny all; }
   location /api/omk/ {
       index index.php;
       try_files $uri /api/omk/index.php?$query_string;
   }
   ```

7. Schedule refreshes. Edit `PHP=` and `DIR=` in `update.sh` to match your host,
   then run it from cron (it runs `fetch_packages.php` then `update.php`):

   ```cron
   0 */6 * * * /www/wwwroot/<your-domain>/api/omk/update.sh >> /www/wwwroot/<your-domain>/api/omk/data/cron.log 2>&1
   ```

8. Verify:

   ```sh
   curl -s  "https://<your-domain>/api/omk/?action=manifest" | head
   curl -sI "https://<your-domain>/api/omk/?action=keybox"
   ```

## Client integration (this repo's module)

The module consumes the server through two settings; no server file is copied
into the module package.

1. `src/remote_keybox.rs`: set the compiled trust anchor to the server's public
   key:

   ```rust
   const TRUSTED_PUBKEY_B64: &str = "<contents of server keys/ed25519.pub>";
   ```

   Rebuild the module afterwards.

2. `/data/misc/keystore/omk/config.toml`:

   ```toml
   [remote_keybox]
   enabled = true
   base_urls = ["https://<your-domain>/api/omk"]
   interval_secs = 86400
   auto_apply = true
   ```

3. Build and install the module: `python3 build.py --release`, then flash the
   resulting `OhMyKeymint-*.zip` (or use `scripts/deploy_hot_update.py`).

The module build (`build.py`, CI) never reads this directory, so the server is
deployed separately on the PHP host and is never bundled into the module zip.

## Decentralized mirrors

Point the OMK client's `[remote_keybox].base_urls` at one or more mirrors. Each
entry may be a PHP API base (`?action=...`) or a static mirror root serving
`manifest.json` / `keybox.xml` / `module.zip`. The client uses them as ordered
fallbacks when a fetch fails.

## Notes

- `data/` and `keys/` are git-ignored; never commit private keys or downloaded assets.
- The optional report actions (`keyboxreport`, `acreport`) require the separate
  operator database configured in `dashboard/config.php`; they are inert when unset.
