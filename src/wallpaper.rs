//! Local WebUI wallpaper storage.
//!
//! The module WebUI paints a user-selected image as its global background. The
//! image is stored once under `data/wallpaper` and read back from disk, so the
//! WebUI never refetches a remote URL. When no image has been stored yet, the
//! default remote wallpaper is downloaded once and cached locally.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ureq::http::Uri;

use crate::{root_path, webui_http};

/// Default wallpaper downloaded and cached locally when no image is stored.
pub const DEFAULT_WALLPAPER_URL: &str =
    "https://106.55.19.150:1314/down/ZHI0jZPFllR2.jpg";

const WALLPAPER_PATH: &str = root_path!("data/wallpaper");
const WALLPAPER_TMP_PATH: &str = root_path!("data/wallpaper.tmp");
const STORAGE_ROOT: &str = "/storage/emulated/0";
/// Largest wallpaper the WebUI bridge will store or return.
pub const MAX_WALLPAPER_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FETCH_DELAY: Duration = Duration::from_secs(20);

/// Detect the MIME type of a supported wallpaper image from its magic bytes.
pub fn mime_of(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

/// Read the stored wallpaper, returning `None` when nothing is stored.
pub fn load_wallpaper() -> Option<Vec<u8>> {
    std::fs::read(WALLPAPER_PATH)
        .ok()
        .filter(|bytes| !bytes.is_empty())
}

/// Encode the stored wallpaper as base64 for the WebUI bridge, or an empty
/// string when no wallpaper is stored.
pub fn load_wallpaper_base64() -> Result<String> {
    match load_wallpaper() {
        Some(bytes) => Ok(BASE64_STANDARD.encode(bytes)),
        None => Ok(String::new()),
    }
}

/// Validate an image payload and return its MIME type.
fn validate_image(bytes: &[u8]) -> Result<&'static str> {
    if bytes.is_empty() {
        bail!("wallpaper image is empty");
    }
    if bytes.len() > MAX_WALLPAPER_BYTES {
        bail!("wallpaper image exceeds the {MAX_WALLPAPER_BYTES} byte limit");
    }
    mime_of(bytes).ok_or_else(|| anyhow!("wallpaper must be a JPEG, PNG, or WebP image"))
}

fn write_wallpaper(bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::File::create(WALLPAPER_TMP_PATH)
        .with_context(|| format!("failed to create {WALLPAPER_TMP_PATH}"))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {WALLPAPER_TMP_PATH}"))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {WALLPAPER_TMP_PATH}"))?;
    drop(file);
    std::fs::rename(WALLPAPER_TMP_PATH, WALLPAPER_PATH)
        .with_context(|| format!("failed to install {WALLPAPER_PATH}"))
}

/// Resolve a user-selected shared-storage path and confirm it points at a
/// regular file below `/storage/emulated/0`.
fn resolve_storage_file(path: &str) -> Result<std::path::PathBuf> {
    if path.is_empty() || !path.starts_with(STORAGE_ROOT) {
        bail!("wallpaper path must be inside {STORAGE_ROOT}");
    }
    if path.split('/').any(|segment| segment == "..") {
        bail!("wallpaper path must not contain '..'");
    }
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("failed to resolve the wallpaper path {path:?}"))?;
    if !resolved.starts_with(Path::new(STORAGE_ROOT)) {
        bail!("wallpaper path resolves outside {STORAGE_ROOT}");
    }
    if !resolved.is_file() {
        bail!("wallpaper path is not a regular file");
    }
    Ok(resolved)
}

/// Copy a user-selected shared-storage image into local wallpaper storage.
pub fn store_from_path(path: &str) -> Result<()> {
    let resolved = resolve_storage_file(path)?;
    let metadata = std::fs::metadata(&resolved)
        .with_context(|| format!("failed to stat {path:?}"))?;
    if metadata.len() == 0 {
        bail!("wallpaper image is empty");
    }
    if metadata.len() > MAX_WALLPAPER_BYTES as u64 {
        bail!("wallpaper image exceeds the {MAX_WALLPAPER_BYTES} byte limit");
    }
    let bytes = std::fs::read(&resolved).with_context(|| format!("failed to read {path:?}"))?;
    validate_image(&bytes)?;
    write_wallpaper(&bytes)
}

/// Download the default wallpaper once when nothing is stored locally.
pub fn ensure_default_wallpaper() -> Result<bool> {
    if load_wallpaper().is_some() {
        return Ok(false);
    }
    let uri: Uri = DEFAULT_WALLPAPER_URL
        .parse()
        .context("default wallpaper URL is invalid")?;
    let policy = webui_http::DownloadPolicy {
        resource: "default wallpaper",
        redirect_allowlist: "106.55.19.150:1314",
        max_bytes: MAX_WALLPAPER_BYTES,
        max_size_label: "8 MiB",
        max_redirects: 0,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    };
    let bytes = webui_http::download_https_bytes(uri, &policy, |uri| {
        uri.scheme_str() == Some("https") && uri.authority().is_some_and(|a| a.as_str() == "106.55.19.150:1314")
    })
    .context("failed to download the default wallpaper")?;
    validate_image(&bytes)?;
    write_wallpaper(&bytes)?;
    log::info!("cached the default WebUI wallpaper");
    Ok(true)
}

/// Spawn a one-shot background fetch for the default wallpaper.
pub fn spawn_default_fetcher() {
    std::thread::spawn(|| {
        std::thread::sleep(DEFAULT_FETCH_DELAY);
        if let Err(error) = ensure_default_wallpaper() {
            log::warn!("failed to cache the default WebUI wallpaper: {error:#}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_supported_image_magic() {
        assert_eq!(mime_of(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(
            mime_of(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("image/png")
        );
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBP");
        assert_eq!(mime_of(&webp), Some("image/webp"));
    }

    #[test]
    fn rejects_unknown_image_formats() {
        assert_eq!(mime_of(b"not an image"), None);
        assert!(validate_image(b"not an image").is_err());
        assert!(validate_image(&[]).is_err());
    }
}
