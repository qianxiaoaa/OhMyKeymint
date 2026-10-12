//! Decentralized remote keybox distribution.
//!
//! Enabled by `[remote_keybox]` in `config.toml`. OMK polls an ordered list of
//! mirror base URLs, downloads the server's `manifest.json`, and reads the
//! nested `keybox` object (`url`, `sha256`, `signature`). It fetches the
//! referenced `keybox.xml`, verifies the payload SHA-256 and an Ed25519
//! signature against a public key compiled into the binary, and installs the
//! verified keybox as `/data/misc/keystore/omk/keybox.xml`.
//!
//! The manifest is the yypm server schema:
//!
//! ```json
//! {
//!   "version": "1.3.6",
//!   "version_code": 207,
//!   "base_url": "https://example.com/api/omk",
//!   "keybox": {
//!     "sha256": "<64 hex chars>",
//!     "signature": "<base64 Ed25519 over the keybox bytes>",
//!     "url": "https://example.com/api/omk/?action=keybox",
//!     "validity": { "...": "..." },
//!     "fallbacks": [ "..." ]
//!   },
//!   "module": { "...": "..." }
//! }
//! ```
//!
//! Unknown fields (`validity`, `fallbacks`, `module`, ...) are ignored. The
//! signature is the trust root: a mirror cannot substitute a different keybox,
//! even when it controls the manifest, because the manifest is verified against
//! the compiled public key. Each configured base URL is tried both as a live
//! API (`?action=...`) and as a static mirror root (`manifest.json` /
//! `keybox.xml`), so a single list of mirrors covers both deployment styles.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use ring::{
    digest::{digest, SHA256},
    signature::{UnparsedPublicKey, ED25519},
};
use serde::Deserialize;
use ureq::http::Uri;

use crate::{config, keybox, webui_http};

/// Public key trusted for remote keybox manifests: a 32-byte Ed25519 public key
/// encoded as base64. Replace this with the public key matching the server's
/// signing key before building. An empty value disables remote keybox fetches.
const TRUSTED_PUBKEY_B64: &str = "";

const MANIFEST_FILE: &str = "manifest.json";
const KEYBOX_FILE: &str = "keybox.xml";
const MANIFEST_ACTION: &str = "?action=manifest";
const KEYBOX_ACTION: &str = "?action=keybox";
const STAGING_DIR: &str = crate::root_path!("data/remote_keybox");
const STAGING_KEYBOX: &str = crate::root_path!("data/remote_keybox/keybox.xml");

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_KEYBOX_BYTES: usize = keybox::MAX_KEYBOX_XML_BYTES;
const MAX_REDIRECTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_DELAY: Duration = Duration::from_secs(30);
const MIN_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Deserialize)]
struct Manifest {
    /// The nested `keybox` object emitted by the server. Unknown sibling fields
    /// (`version`, `module`, `base_url`, ...) are ignored.
    #[serde(default)]
    keybox: Option<KeyboxEntry>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct KeyboxEntry {
    /// Keybox location. Absolute when it starts with `https://`, otherwise
    /// resolved against the serving mirror base URL.
    #[serde(default)]
    url: Option<String>,
    /// Hex-encoded SHA-256 of the raw keybox payload.
    #[serde(default)]
    sha256: Option<String>,
    /// Base64 Ed25519 signature over the raw keybox payload bytes.
    #[serde(default)]
    signature: Option<String>,
}

/// Spawn the background refresh loop.
pub fn spawn_worker() {
    std::thread::spawn(|| {
        std::thread::sleep(INITIAL_DELAY);
        loop {
            match refresh_once() {
                Ok(true) => log::info!("remote keybox refreshed from a mirror"),
                Ok(false) => log::debug!("remote keybox refresh made no change"),
                Err(error) => log::warn!("remote keybox refresh failed: {error:#}"),
            }
            std::thread::sleep(Duration::from_secs(current_interval_secs()));
        }
    });
}

fn current_interval_secs() -> u64 {
    config::config()
        .read()
        .map(|config| config.remote_keybox.interval_secs.max(MIN_INTERVAL_SECS))
        .unwrap_or(MIN_INTERVAL_SECS)
}

/// Fetch, verify, and (when configured) install one keybox from the first
/// reachable mirror. Returns whether the active keybox was replaced.
pub fn refresh_once() -> Result<bool> {
    let remote = match config::config().read() {
        Ok(config) => config.remote_keybox.clone(),
        Err(_) => bail!("config lock poisoned while reading remote keybox settings"),
    };
    if !remote.enabled {
        return Ok(false);
    }
    if remote.base_urls.is_empty() {
        bail!("remote keybox is enabled but no mirrors are configured");
    }

    let pubkey = trusted_pubkey()?;
    let bases = normalized_bases(&remote.base_urls)?;
    let mut failures = Vec::new();
    for base in &bases {
        match refresh_from_mirror(base, &bases, &pubkey) {
            Ok(installed) => return Ok(installed),
            Err(error) => failures.push(format!("{base}: {error:#}")),
        }
    }
    bail!("all remote keybox mirrors failed: {}", failures.join("; "))
}

/// Normalize and validate the configured mirror base URLs, returning them
/// without a trailing slash.
fn normalized_bases(base_urls: &[String]) -> Result<Vec<String>> {
    let mut bases = Vec::with_capacity(base_urls.len());
    for url in base_urls {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("remote keybox mirror URL is invalid: {url:?}"))?;
        if uri.scheme_str() != Some("https") || uri.authority().is_none() || uri.query().is_some() {
            bail!("remote keybox mirror must be an absolute https URL without a query: {url:?}");
        }
        bases.push(url.trim_end_matches('/').to_string());
    }
    Ok(bases)
}

fn refresh_from_mirror(base: &str, bases: &[String], pubkey: &[u8; 32]) -> Result<bool> {
    let manifest = fetch_manifest(base, bases)?;
    let entry = manifest
        .keybox
        .ok_or_else(|| anyhow!("remote keybox manifest has no keybox object"))?;

    let mut failures = Vec::new();
    let mut payload = None;
    for url in keybox_candidates(base, &entry) {
        match fetch_keybox(&url, bases) {
            Ok(bytes) => {
                payload = Some(bytes);
                break;
            }
            Err(error) => failures.push(format!("{url}: {error:#}")),
        }
    }
    let payload = match payload {
        Some(payload) => payload,
        None => bail!("every remote keybox source failed: {}", failures.join("; ")),
    };

    verify_payload(pubkey, &entry, payload.as_bytes())?;

    if sha256_hex(payload.as_bytes()) == sha256_hex(&payload_of(keybox::KEYBOX_PATH)?) {
        return Ok(false);
    }

    let remote = config::config()
        .read()
        .map(|config| config.remote_keybox.clone())
        .unwrap_or_default();
    if remote.auto_apply {
        keybox::install_keybox_xml(payload.as_bytes())
            .context("failed to install the verified remote keybox")?;
    } else {
        stage_keybox(payload.as_bytes())?;
        log::info!("verified remote keybox staged at {STAGING_KEYBOX} (auto_apply is disabled)");
    }
    Ok(true)
}

fn sha256_hex(payload: &[u8]) -> String {
    hex::encode(digest(&SHA256, payload).as_ref())
}

fn payload_of(path: &str) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("failed to read {path}")),
    }
}

fn fetch_manifest(base: &str, bases: &[String]) -> Result<Manifest> {
    let mut failures = Vec::new();
    for url in [format!("{base}/{MANIFEST_ACTION}"), format!("{base}/{MANIFEST_FILE}")] {
        match download_url(&url, MAX_MANIFEST_BYTES, "remote keybox manifest", "64 KiB", bases) {
            Ok(contents) => {
                let manifest = serde_json::from_str(&contents)
                    .context("failed to parse the remote keybox manifest")?;
                return Ok(manifest);
            }
            Err(error) => failures.push(format!("{url}: {error:#}")),
        }
    }
    bail!("failed to fetch the remote keybox manifest: {}", failures.join("; "));
}

/// Ordered keybox download candidates for one manifest entry: the server-
/// declared URL first, then the live API and static mirror locations.
fn keybox_candidates(base: &str, entry: &KeyboxEntry) -> Vec<String> {
    let mut urls = Vec::new();
    if let Some(url) = entry.url.as_deref() {
        let url = url.trim();
        if url.starts_with("https://") {
            urls.push(url.to_string());
        } else if !url.is_empty() && !url.contains("://") {
            urls.push(format!("{base}/{}", url.trim_start_matches('/')));
        }
    }
    urls.push(format!("{base}/{KEYBOX_ACTION}"));
    urls.push(format!("{base}/{KEYBOX_FILE}"));
    urls.dedup();
    urls
}

fn fetch_keybox(url: &str, bases: &[String]) -> Result<String> {
    download_url(url, MAX_KEYBOX_BYTES, "remote keybox", "64 KiB", bases)
}

fn download_url(
    url: &str,
    max_bytes: usize,
    label: &'static str,
    size_label: &'static str,
    bases: &[String],
) -> Result<String> {
    let uri: Uri = url.parse().with_context(|| format!("{label} URL is invalid"))?;
    let allowed: Vec<String> = bases.iter().filter_map(|base| host_of(base)).collect();
    let policy = webui_http::DownloadPolicy {
        resource: label,
        redirect_allowlist: "the configured remote keybox mirrors",
        max_bytes,
        max_size_label: size_label,
        max_redirects: MAX_REDIRECTS,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    };
    let is_allowed = |uri: &Uri| is_allowed_mirror_uri(uri, &allowed);
    if !is_allowed(&uri) {
        bail!("{label} URL is not on a configured remote keybox mirror");
    }
    webui_http::download_https_utf8(uri, &policy, is_allowed)
}

fn host_of(url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    let authority = uri.authority()?;
    let authority = authority.as_str();
    let host = authority.strip_suffix(":443").unwrap_or(authority);
    Some(host.to_ascii_lowercase())
}

fn is_allowed_mirror_uri(uri: &Uri, allowed_hosts: &[String]) -> bool {
    if uri.scheme_str() != Some("https") {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority = authority.as_str();
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority.contains(':') => return false,
        None => authority,
    };
    allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn verify_payload(pubkey: &[u8; 32], entry: &KeyboxEntry, payload: &[u8]) -> Result<()> {
    let expected = entry
        .sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("remote keybox manifest keybox.sha256 is missing"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("remote keybox manifest keybox.sha256 is not a 64-character hex digest");
    }
    let observed = hex::encode(digest(&SHA256, payload).as_ref());
    if !observed.eq_ignore_ascii_case(expected) {
        bail!("remote keybox payload does not match the manifest SHA-256");
    }

    let signature = entry
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("remote keybox manifest keybox.signature is missing"))?;
    let signature = BASE64_STANDARD
        .decode(signature)
        .context("remote keybox signature is not valid base64")?;
    UnparsedPublicKey::new(&ED25519, pubkey)
        .verify(payload, &signature)
        .map_err(|_| anyhow!("remote keybox Ed25519 signature verification failed"))?;
    Ok(())
}

fn trusted_pubkey() -> Result<[u8; 32]> {
    let decoded = BASE64_STANDARD
        .decode(TRUSTED_PUBKEY_B64.trim())
        .context("the compiled remote keybox public key is not valid base64")?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the compiled remote keybox public key must be 32 bytes"))
}

fn stage_keybox(payload: &[u8]) -> Result<()> {
    std::fs::create_dir_all(STAGING_DIR)
        .with_context(|| format!("failed to create remote keybox staging directory {STAGING_DIR}"))?;
    atomic_replace_preserving_metadata(STAGING_KEYBOX, payload, 0o600, KEYSTORE_UID, KEYSTORE_GID)
        .with_context(|| format!("failed to stage the verified remote keybox at {STAGING_KEYBOX}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 Ed25519 test vector 1 (empty message).
    const RFC8032_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_SIGNATURE_HEX: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555",
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );

    fn pubkey() -> [u8; 32] {
        let bytes = hex::decode(RFC8032_PUBKEY_HEX).unwrap();
        bytes.as_slice().try_into().unwrap()
    }

    fn entry_for(payload: &[u8]) -> KeyboxEntry {
        KeyboxEntry {
            url: None,
            sha256: Some(hex::encode(digest(&SHA256, payload).as_ref())),
            signature: Some(BASE64_STANDARD.encode(hex::decode(RFC8032_SIGNATURE_HEX).unwrap())),
        }
    }

    #[test]
    fn verifies_a_valid_payload_and_rejects_tampering() {
        let payload = b"";
        let entry = entry_for(payload);
        assert!(verify_payload(&pubkey(), &entry, payload).is_ok());

        let tampered = b"x";
        assert!(verify_payload(&pubkey(), &entry, tampered).is_err());
    }

    #[test]
    fn rejects_a_mismatched_sha256_before_signature_check() {
        let mut entry = entry_for(b"");
        entry.sha256 = Some("0".repeat(64));
        let error = verify_payload(&pubkey(), &entry, b"").unwrap_err();
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn rejects_a_malformed_or_absent_sha256() {
        let mut entry = entry_for(b"");
        entry.sha256 = Some("abc".to_string());
        assert!(verify_payload(&pubkey(), &entry, b"").is_err());

        entry.sha256 = None;
        assert!(verify_payload(&pubkey(), &entry, b"").is_err());
    }

    #[test]
    fn rejects_a_missing_signature() {
        let mut entry = entry_for(b"");
        entry.signature = None;
        assert!(verify_payload(&pubkey(), &entry, b"").is_err());
    }

    #[test]
    fn parses_the_nested_manifest_and_ignores_sibling_fields() {
        let manifest: Manifest = serde_json::from_str(
            r#"{
                "version": "1.3.6",
                "version_code": 207,
                "base_url": "https://example.com/api/omk",
                "keybox": {
                    "sha256": "abc",
                    "signature": "c2ln",
                    "url": "https://example.com/api/omk/?action=keybox",
                    "validity": { "ok": true },
                    "fallbacks": ["x"]
                },
                "module": { "sha256": "deadbeef" }
            }"#,
        )
        .unwrap();
        let keybox = manifest.keybox.expect("keybox object");
        assert_eq!(keybox.sha256.as_deref(), Some("abc"));
        assert_eq!(keybox.url.as_deref(), Some("https://example.com/api/omk/?action=keybox"));

        let empty: Manifest = serde_json::from_str(r#"{"version_code":1}"#).unwrap();
        assert!(empty.keybox.is_none());
    }

    #[test]
    fn builds_keybox_candidates_from_entry_and_base() {
        let base = "https://example.com/api/omk";
        let absolute = KeyboxEntry {
            url: Some("https://mirror.example/keybox.xml".to_string()),
            ..Default::default()
        };
        assert_eq!(
            keybox_candidates(base, &absolute),
            vec![
                "https://mirror.example/keybox.xml".to_string(),
                "https://example.com/api/omk/?action=keybox".to_string(),
                "https://example.com/api/omk/keybox.xml".to_string(),
            ]
        );

        let relative = KeyboxEntry {
            url: Some("dist/keybox.xml".to_string()),
            ..Default::default()
        };
        assert_eq!(
            keybox_candidates(base, &relative),
            vec![
                "https://example.com/api/omk/dist/keybox.xml".to_string(),
                "https://example.com/api/omk/?action=keybox".to_string(),
                "https://example.com/api/omk/keybox.xml".to_string(),
            ]
        );

        assert_eq!(
            keybox_candidates(base, &KeyboxEntry::default()),
            vec![
                "https://example.com/api/omk/?action=keybox".to_string(),
                "https://example.com/api/omk/keybox.xml".to_string(),
            ]
        );
    }

    #[test]
    fn mirror_allowlist_accepts_only_https_on_configured_hosts() {
        let allowed = vec![
            "fastly.jsdelivr.net".to_string(),
            "raw.githubusercontent.com".to_string(),
        ];
        for url in [
            "https://fastly.jsdelivr.net/gh/u/r@main/manifest.json",
            "https://fastly.jsdelivr.net/?action=manifest",
            "https://fastly.jsdelivr.net:443/gh/u/r@main/manifest.json",
            "https://raw.githubusercontent.com/u/r/main/keybox.xml",
        ] {
            assert!(is_allowed_mirror_uri(&url.parse().unwrap(), &allowed), "{url}");
        }
        for url in [
            "http://fastly.jsdelivr.net/gh/u/r@main/manifest.json",
            "https://fastly.jsdelivr.net:444/gh/u/r@main/manifest.json",
            "https://user@fastly.jsdelivr.net/gh/u/r@main/manifest.json",
            "https://evil.example/gh/u/r@main/manifest.json",
        ] {
            assert!(!is_allowed_mirror_uri(&url.parse().unwrap(), &allowed), "{url}");
        }
    }

    #[test]
    fn trusted_pubkey_requires_base64_of_thirty_two_bytes() {
        assert!(trusted_pubkey().is_err(), "empty default must not resolve");
    }
}
