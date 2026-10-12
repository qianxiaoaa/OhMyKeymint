use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use pif_common::{
    validate_product, DeviceEntry, PifProfile, MAX_CATALOG_ENTRIES, MAX_PROFILE_BYTES,
    MAX_PROP_BYTES,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::{root_path, security_patch, webui_http};

const PROFILE_PATH: &str = root_path!("data/pif_fingerprint.json");
const FEED_OWNER: &str = "Elcapitanoe";
const FEED_REPO: &str = "PIF-Config-Generator";
const RELEASE_API_URL: &str =
    "https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest";
const PROXY_HOST: &str = "gh-proxy.com";
const API_HOST: &str = "api.github.com";
const GITHUB_HOST: &str = "github.com";
const RELEASE_ASSET_HOSTS: [&str; 2] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const MAX_RELEASE_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_NAMES: [&[u8]; 2] = [b"com.google.android.gms.unstable", b"com.android.vending"];

#[derive(Debug, Clone)]
enum FeedResource {
    Release,
    Profile { tag: String, asset: String },
}

impl FeedResource {
    fn max_bytes(&self) -> usize {
        match self {
            Self::Release => MAX_RELEASE_BYTES,
            Self::Profile { .. } => MAX_PROP_BYTES,
        }
    }

    fn size_label(&self) -> &'static str {
        match self {
            Self::Release => "256 KiB",
            Self::Profile { .. } => "4 KiB",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Release => "PIF release catalog",
            Self::Profile { .. } => "PIF device profile",
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
}

#[derive(Debug, Serialize)]
struct DisabledState {
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct EnabledState<'a> {
    enabled: bool,
    model: &'a str,
    product: &'a str,
    fingerprint: &'a str,
    security_patch: &'a str,
}

pub fn list_devices() -> Result<String> {
    let entries = load_feed()?
        .into_iter()
        .map(|(device, _)| device)
        .collect::<Vec<_>>();
    serde_json::to_string(&entries).context("failed to serialize PIF device catalog")
}

pub fn fingerprint_state() -> Result<String> {
    state_json(load_profile(Path::new(PROFILE_PATH))?.as_ref())
}

pub fn apply_fingerprint(product: &str) -> Result<String> {
    validate_product(product).map_err(anyhow::Error::msg)?;
    let profile = load_feed()?
        .into_iter()
        .find(|(device, _)| device.product == product)
        .map(|(_, profile)| profile)
        .ok_or_else(|| anyhow!("selected product is not present in the current PIF catalog"))?;

    let path = Path::new(PROFILE_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    persist_profile(path, &profile, KEYSTORE_UID, KEYSTORE_GID)?;
    refresh_target_processes()?;
    state_json(Some(&profile))
}

pub fn disable_fingerprint() -> Result<String> {
    let path = Path::new(PROFILE_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    remove_profile(path)?;
    refresh_target_processes()?;
    state_json(None)
}

fn load_feed() -> Result<Vec<(DeviceEntry, PifProfile)>> {
    let contents = download_feed(&FeedResource::Release)?;
    let release: GithubRelease = serde_json::from_str(&contents)
        .context("failed to parse the PIF release catalog")?;
    if !is_release_tag(&release.tag_name) {
        bail!("PIF release tag is invalid");
    }

    let mut entries = Vec::new();
    let mut products = BTreeSet::new();
    for asset in &release.assets {
        if !is_profile_asset_name(&asset.name) {
            continue;
        }
        if entries.len() >= MAX_CATALOG_ENTRIES {
            bail!("PIF device catalog contains more than {MAX_CATALOG_ENTRIES} entries");
        }
        let resource = FeedResource::Profile {
            tag: release.tag_name.clone(),
            asset: asset.name.clone(),
        };
        let profile_json = download_feed(&resource)?;
        let profile = PifProfile::from_feed(profile_json.as_bytes())
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("downloaded PIF profile {} failed validation", asset.name))?;
        let device = DeviceEntry {
            model: profile.model.clone(),
            product: profile.product.clone(),
        };
        device.validate().map_err(anyhow::Error::msg)?;
        if !products.insert(device.product.clone()) {
            bail!(
                "PIF device catalog contains duplicate product {}",
                device.product
            );
        }
        entries.push((device, profile));
    }
    if entries.is_empty() {
        bail!("PIF device catalog is empty");
    }
    Ok(entries)
}

fn github_url(resource: &FeedResource) -> Result<String> {
    Ok(match resource {
        FeedResource::Release => RELEASE_API_URL.to_string(),
        FeedResource::Profile { tag, asset } => {
            if !is_release_tag(tag) || !is_profile_asset_name(asset) {
                bail!("{} URL is outside the fixed feed paths", resource.label());
            }
            format!("https://github.com/{FEED_OWNER}/{FEED_REPO}/releases/download/{tag}/{asset}")
        }
    })
}

fn proxy_url(origin: &str) -> String {
    format!("https://{PROXY_HOST}/{origin}")
}

fn download_feed(resource: &FeedResource) -> Result<String> {
    let origin = github_url(resource)?;
    let primary = proxy_url(&origin);
    let policy = webui_http::DownloadPolicy {
        resource: resource.label(),
        redirect_allowlist: "the fixed PIF-Config-Generator release paths",
        max_bytes: resource.max_bytes(),
        max_size_label: resource.size_label(),
        max_redirects: MAX_REDIRECTS,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    };
    let fetch = |url: &str| -> Result<String> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("{} URL is invalid", resource.label()))?;
        if !is_allowed_feed_uri(&uri, resource) {
            bail!("{} URL is outside the fixed feed paths", resource.label());
        }
        webui_http::download_https_utf8(uri, &policy, |uri| is_allowed_feed_uri(uri, resource))
    };
    match fetch(&primary) {
        Ok(contents) => Ok(contents),
        Err(primary_error) => fetch(&origin).with_context(|| {
            format!("both PIF feed sources failed; primary source error: {primary_error:#}")
        }),
    }
}

fn is_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_profile_asset_name(name: &str) -> bool {
    name.ends_with(".json")
        && name.len() > ".json".len()
        && name.len() <= 126
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn feed_host(uri: &Uri) -> Option<&str> {
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let authority = uri.authority()?.as_str();
    if authority.contains('@') {
        return None;
    }
    Some(match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return None,
        None if authority.contains(':') => return None,
        None => authority,
    })
}

fn is_allowed_feed_uri(uri: &Uri, resource: &FeedResource) -> bool {
    let Some(host) = feed_host(uri) else {
        return false;
    };
    match resource {
        FeedResource::Release => {
            uri.query().is_none()
                && ((host.eq_ignore_ascii_case(PROXY_HOST)
                    && uri.path() == format!("/{RELEASE_API_URL}"))
                    || (host.eq_ignore_ascii_case(API_HOST)
                        && uri.path()
                            == format!("/repos/{FEED_OWNER}/{FEED_REPO}/releases/latest")))
        }
        FeedResource::Profile { tag, asset } => {
            if !is_release_tag(tag) || !is_profile_asset_name(asset) {
                return false;
            }
            let origin =
                format!("https://github.com/{FEED_OWNER}/{FEED_REPO}/releases/download/{tag}/{asset}");
            let github_path = format!("/{FEED_OWNER}/{FEED_REPO}/releases/download/{tag}/{asset}");
            if host.eq_ignore_ascii_case(PROXY_HOST) {
                uri.query().is_none() && uri.path() == format!("/{origin}")
            } else if host.eq_ignore_ascii_case(GITHUB_HOST) {
                uri.query().is_none() && uri.path() == github_path
            } else if RELEASE_ASSET_HOSTS
                .iter()
                .any(|allowed| host.eq_ignore_ascii_case(allowed))
            {
                !uri.path().is_empty() && !uri.path().contains("..")
            } else {
                false
            }
        }
    }
}

fn state_json(profile: Option<&PifProfile>) -> Result<String> {
    match profile {
        Some(profile) => {
            profile.validate().map_err(anyhow::Error::msg)?;
            serde_json::to_string(&EnabledState {
                enabled: true,
                model: &profile.model,
                product: &profile.product,
                fingerprint: &profile.fingerprint,
                security_patch: &profile.security_patch,
            })
        }
        None => serde_json::to_string(&DisabledState { enabled: false }),
    }
    .context("failed to serialize PIF fingerprint state")
}

fn load_profile(path: &Path) -> Result<Option<PifProfile>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect PIF profile {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("PIF profile path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        bail!("PIF profile exceeds the 4 KiB limit");
    }
    let contents =
        fs::read(path).with_context(|| format!("failed to read PIF profile {}", path.display()))?;
    let profile = PifProfile::from_json(&contents).map_err(anyhow::Error::msg)?;
    let canonical = profile.to_canonical_json().map_err(anyhow::Error::msg)?;
    if contents != canonical.as_bytes() {
        bail!("PIF profile is not canonical JSON");
    }
    Ok(Some(profile))
}

fn persist_profile(path: &Path, profile: &PifProfile, uid: u32, gid: u32) -> Result<()> {
    let contents = profile.to_canonical_json().map_err(anyhow::Error::msg)?;
    validate_profile_target(path)?;
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, uid, gid).with_context(
        || {
            format!(
                "failed to atomically replace PIF profile {}",
                path.display()
            )
        },
    )?;
    validate_profile_target(path)?;
    enforce_profile_metadata(path, uid, gid)?;
    let saved = load_profile(path)?.ok_or_else(|| anyhow!("PIF profile vanished after write"))?;
    if &saved != profile {
        bail!("PIF profile read-back does not match the requested profile");
    }
    Ok(())
}

fn validate_profile_target(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect PIF state directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        bail!(
            "PIF state parent is not a real directory: {}",
            parent.display()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!("PIF profile path is not a regular file: {}", path.display());
        }
    }
    Ok(())
}

fn enforce_profile_metadata(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to reopen PIF profile {}", path.display()))?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile owner");
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile mode");
    }
    file.sync_all()
        .context("failed to sync PIF profile metadata")?;
    Ok(())
}

fn remove_profile(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            bail!("PIF profile path is not a regular file: {}", path.display())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect PIF profile before removal"),
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    fs::remove_file(path)
        .with_context(|| format!("failed to remove PIF profile {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync PIF state directory after removal")
}

fn refresh_target_processes() -> Result<()> {
    let entries = fs::read_dir("/proc").context("failed to scan processes after PIF update")?;
    let mut failures = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let name = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        if !is_target_process_name(name) {
            continue;
        }
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            // A matching process can exit between the /proc scan and kill.
            // Treat that expected race as an already-refreshed process.
            if error.raw_os_error() != Some(libc::ESRCH) {
                failures.push(format!(
                    "{} (pid {pid}): {error}",
                    String::from_utf8_lossy(name)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to stop PIF target process(es): {}",
            failures.join("; ")
        );
    }
}

fn is_target_process_name(name: &[u8]) -> bool {
    PROCESS_NAMES.iter().any(|base| {
        name == *base
            || (name.len() > base.len() + 1 && name.starts_with(base) && name[base.len()] == b':')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn sample_profile() -> PifProfile {
        PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6".to_string(),
                product: "oriole_beta".to_string(),
            },
            b"FINGERPRINT=google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel 6\nSECURITY_PATCH=2026-08-05\n",
        )
        .unwrap()
    }

    #[test]
    fn release_tag_and_asset_name_reject_path_syntax() {
        for tag in ["v2026.10.11", "v2026.01.01"] {
            assert!(is_release_tag(tag), "{tag}");
        }
        for tag in ["2026.10.11", "v2026.10", "v2026.10.11.1", "v2026.10.11a", "v../10.11"] {
            assert!(!is_release_tag(tag), "{tag}");
        }
        for name in [
            "Akita_CP3A.261005.005.json",
            "Oriole_CP3A.261005.002.A1.json",
        ] {
            assert!(is_profile_asset_name(name), "{name}");
        }
        for name in [
            "",
            ".json",
            "Akita.json.txt",
            "../Akita.json",
            "Akita/CP3A.json",
            "Akita.json?x=1",
        ] {
            assert!(!is_profile_asset_name(name), "{name}");
        }
    }

    #[test]
    fn feed_allowlist_accepts_only_exact_resource_paths() {
        let catalog = FeedResource::Release;
        for url in [
            "https://gh-proxy.com/https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://gh-proxy.com:443/https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://api.github.com:443/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
        ] {
            assert!(
                is_allowed_feed_uri(&url.parse().unwrap(), &catalog),
                "{url}"
            );
        }
        for url in [
            "http://gh-proxy.com/https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://gh-proxy.com/https://api.github.com/repos/other/PIF-Config-Generator/releases/latest",
            "https://api.github.com/repos/Elcapitanoe/PIF-Config-Generator/releases/latest?page=1",
            "https://api.github.com.evil.example/repos/Elcapitanoe/PIF-Config-Generator/releases/latest",
        ] {
            assert!(!is_allowed_feed_uri(&url.parse().unwrap(), &catalog), "{url}");
        }
    }

    #[test]
    fn profile_allowlist_binds_the_validated_release_asset_to_the_path() {
        let profile = FeedResource::Profile {
            tag: "v2026.10.11".to_string(),
            asset: "Oriole_CP3A.261005.002.A1.json".to_string(),
        };
        assert!(is_allowed_feed_uri(
            &"https://gh-proxy.com/https://github.com/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Oriole_CP3A.261005.002.A1.json"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Oriole_CP3A.261005.002.A1.json"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(is_allowed_feed_uri(
            &"https://release-assets.githubusercontent.com/github-production-release-asset/1?sp=r"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(!is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Raven_CP3A.261005.002.A1.json"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(!is_allowed_feed_uri(
            &"https://gh-proxy.com/https://github.com/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Raven_CP3A.261005.002.A1.json"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(!is_allowed_feed_uri(
            &"https://evil.example/Oriole_CP3A.261005.002.A1.json"
                .parse()
                .unwrap(),
            &profile
        ));
    }

    #[test]
    fn state_json_matches_the_webui_canonical_contract() {
        let profile = sample_profile();
        assert_eq!(state_json(None).unwrap(), r#"{"enabled":false}"#);
        assert_eq!(
            state_json(Some(&profile)).unwrap(),
            r#"{"enabled":true,"model":"Pixel 6","product":"oriole_beta","fingerprint":"google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys","security_patch":"2026-08-05"}"#
        );
    }

    #[test]
    fn profile_persistence_is_atomic_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pif_fingerprint.json");
        let profile = sample_profile();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        fs::write(&path, b"stale").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        persist_profile(&path, &profile, uid, gid).unwrap();
        assert_eq!(load_profile(&path).unwrap(), Some(profile));
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
    }

    #[test]
    fn loader_rejects_symlinks_and_noncanonical_json() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::write(&real, sample_profile().to_canonical_json().unwrap()).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_profile(&link).is_err());

        let noncanonical = temp.path().join("noncanonical");
        fs::write(
            &noncanonical,
            format!("{}\n", sample_profile().to_canonical_json().unwrap()),
        )
        .unwrap();
        assert!(load_profile(&noncanonical).is_err());
    }

    #[test]
    fn refresh_matching_accepts_supported_colon_processes_only() {
        for name in [
            b"com.google.android.gms.unstable".as_slice(),
            b"com.google.android.gms.unstable:background".as_slice(),
            b"com.android.vending".as_slice(),
            b"com.android.vending:instant".as_slice(),
        ] {
            assert!(
                is_target_process_name(name),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        for name in [
            b"com.google.android.gms".as_slice(),
            b"com.google.android.gms.unstable2".as_slice(),
            b"com.google.android.gms.unstable:".as_slice(),
            b"com.android.vending.evil".as_slice(),
            b"com.android.vending/child".as_slice(),
        ] {
            assert!(
                !is_target_process_name(name),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }
}
