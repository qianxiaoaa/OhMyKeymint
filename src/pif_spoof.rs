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
use serde::Serialize;
use ureq::http::Uri;

use crate::{root_path, security_patch, webui_http};

const PROFILE_PATH: &str = root_path!("data/pif_fingerprint.json");
const FEED_OWNER: &str = "Elcapitanoe";
const FEED_REPO: &str = "PIF-Config-Generator";
// The feed metadata is read from the `github.com` HTML endpoints rather than
// the REST API. The unauthenticated `api.github.com` quota is only 60 requests
// per hour per IP, so a shared carrier NAT exhausts it and answers HTTP 403;
// the HTML `releases/latest` redirect and the `expanded_assets` fragment carry
// the same tag and asset list without that limit.
const LATEST_RELEASE_PATH: &str = "/Elcapitanoe/PIF-Config-Generator/releases/latest";
const RELEASE_FEED_PATH: &str = "/Elcapitanoe/PIF-Config-Generator/releases.atom";
const RELEASE_TAG_PREFIX: &str = "/Elcapitanoe/PIF-Config-Generator/releases/tag/";
const EXPANDED_ASSETS_PREFIX: &str = "/Elcapitanoe/PIF-Config-Generator/releases/expanded_assets/";
const PROXY_HOST: &str = "gh-proxy.com";
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
    LatestTag,
    ReleaseFeed,
    AssetList { tag: String },
    Profile { tag: String, asset: String },
}

impl FeedResource {
    fn max_bytes(&self) -> usize {
        match self {
            Self::LatestTag => MAX_RELEASE_BYTES,
            Self::ReleaseFeed => MAX_RELEASE_BYTES,
            Self::AssetList { .. } => MAX_RELEASE_BYTES,
            Self::Profile { .. } => MAX_PROP_BYTES,
        }
    }

    fn size_label(&self) -> &'static str {
        match self {
            Self::LatestTag => "256 KiB",
            Self::ReleaseFeed => "256 KiB",
            Self::AssetList { .. } => "256 KiB",
            Self::Profile { .. } => "4 KiB",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::LatestTag => "PIF release channel",
            Self::ReleaseFeed => "PIF release feed",
            Self::AssetList { .. } => "PIF release asset list",
            Self::Profile { .. } => "PIF device profile",
        }
    }
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
    let tag = latest_release_tag()?;
    let asset_resource = FeedResource::AssetList { tag: tag.clone() };
    let asset_html = download_feed(&asset_resource)?;
    let names = parse_asset_names(&asset_html, &tag);
    if names.is_empty() {
        bail!("PIF device catalog is empty");
    }
    if names.len() > MAX_CATALOG_ENTRIES {
        bail!("PIF device catalog contains more than {MAX_CATALOG_ENTRIES} entries");
    }

    let mut entries = Vec::new();
    let mut products = BTreeSet::new();
    for asset in names {
        let resource = FeedResource::Profile {
            tag: tag.clone(),
            asset: asset.clone(),
        };
        let profile_json = download_feed(&resource)?;
        let profile = PifProfile::from_feed(profile_json.as_bytes())
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("downloaded PIF profile {asset} failed validation"))?;
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
    Ok(entries)
}

/// Resolve the current release tag without the rate-limited REST API.
///
/// `releases/latest` answers with a 302 whose `Location` ends in
/// `releases/tag/<tag>`. The `releases.atom` feed is used as a fallback for the
/// rare network where the redirect is stripped.
fn latest_release_tag() -> Result<String> {
    let channel = FeedResource::LatestTag;
    let origin = github_url(&channel)?;
    let policy = download_policy(&channel);
    let from_redirect = |url: &str| -> Result<String> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("{} URL is invalid", channel.label()))?;
        if !is_allowed_feed_uri(&uri, &channel) {
            bail!("{} URL is outside the fixed feed paths", channel.label());
        }
        let location = webui_http::fetch_redirect_location(uri, &policy, |uri| {
            is_allowed_feed_uri(uri, &channel)
        })?;
        let base: Uri = origin
            .parse()
            .with_context(|| format!("{} URL is invalid", channel.label()))?;
        let resolved = webui_http::resolve_redirect(&base, &location, channel.label())?;
        let tag = resolved
            .path()
            .strip_prefix(RELEASE_TAG_PREFIX)
            .ok_or_else(|| {
                anyhow!(
                    "{} redirected outside the release tag path",
                    channel.label()
                )
            })?;
        if !is_release_tag(tag) {
            bail!("PIF release tag is invalid");
        }
        Ok(tag.to_string())
    };

    let mut primary_error = None;
    for url in feed_candidates(&origin) {
        match from_redirect(&url) {
            Ok(tag) => return Ok(tag),
            Err(error) => primary_error = Some(error),
        }
    }

    let feed = FeedResource::ReleaseFeed;
    let feed_origin = github_url(&feed)?;
    let feed_policy = download_policy(&feed);
    let from_atom = |url: &str| -> Result<String> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("{} URL is invalid", feed.label()))?;
        if !is_allowed_feed_uri(&uri, &feed) {
            bail!("{} URL is outside the fixed feed paths", feed.label());
        }
        let body = webui_http::download_https_utf8(uri, &feed_policy, |uri| {
            is_allowed_feed_uri(uri, &feed)
        })?;
        atom_first_tag(&body).ok_or_else(|| anyhow!("PIF release feed has no usable tag"))
    };
    let mut atom_error = None;
    for url in feed_candidates(&feed_origin) {
        match from_atom(&url) {
            Ok(tag) => return Ok(tag),
            Err(error) => atom_error = Some(error),
        }
    }

    let primary_error = primary_error
        .map(|error| format!("{error:#}"))
        .unwrap_or_else(|| "no candidate succeeded".to_string());
    let atom_error = atom_error
        .map(|error| format!("{error:#}"))
        .unwrap_or_else(|| "no candidate succeeded".to_string());
    bail!(
        "both PIF feed sources failed; primary source error: {primary_error}; feed fallback error: {atom_error}"
    )
}

/// Extract the newest tag from a GitHub `releases.atom` feed. Entries are
/// ordered newest-first, so the first `releases/tag/<tag>` occurrence wins. The
/// repository tags carry a leading `v` (for example `v2026.10.11`).
fn atom_first_tag(body: &str) -> Option<String> {
    for tail in body.split("releases/tag/").skip(1) {
        let rest = tail.strip_prefix('v').unwrap_or(tail);
        let digits: String = rest
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '.')
            .collect();
        let tag = format!("v{digits}");
        if is_release_tag(&tag) {
            return Some(tag);
        }
    }
    None
}

/// Collect the validated `.json` asset names referenced by a
/// `releases/expanded_assets/<tag>` fragment.
fn parse_asset_names(html: &str, tag: &str) -> Vec<String> {
    let needle = format!("/releases/download/{tag}/");
    let mut names = BTreeSet::new();
    for tail in html.split(&needle).skip(1) {
        let name: String = tail
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
            .collect();
        if is_profile_asset_name(&name) {
            names.insert(name);
        }
    }
    names.into_iter().collect()
}

fn github_url(resource: &FeedResource) -> Result<String> {
    Ok(match resource {
        FeedResource::LatestTag => format!("https://{GITHUB_HOST}{LATEST_RELEASE_PATH}"),
        FeedResource::ReleaseFeed => format!("https://{GITHUB_HOST}{RELEASE_FEED_PATH}"),
        FeedResource::AssetList { tag } => {
            if !is_release_tag(tag) {
                bail!("{} URL is outside the fixed feed paths", resource.label());
            }
            format!("https://{GITHUB_HOST}{EXPANDED_ASSETS_PREFIX}{tag}")
        }
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

/// Proxy first, then the origin, matching the module-wide "prefer gh-proxy for
/// GitHub" policy. The metadata endpoints cannot be proxied, so the second
/// candidate is the one that normally answers.
fn feed_candidates(origin: &str) -> [String; 2] {
    [proxy_url(origin), origin.to_string()]
}

fn download_policy(resource: &FeedResource) -> webui_http::DownloadPolicy {
    webui_http::DownloadPolicy {
        resource: resource.label(),
        redirect_allowlist: "the fixed PIF-Config-Generator release paths",
        max_bytes: resource.max_bytes(),
        max_size_label: resource.size_label(),
        max_redirects: MAX_REDIRECTS,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    }
}

fn download_feed(resource: &FeedResource) -> Result<String> {
    let origin = github_url(resource)?;
    let policy = download_policy(resource);
    let fetch = |url: &str| -> Result<String> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("{} URL is invalid", resource.label()))?;
        if !is_allowed_feed_uri(&uri, resource) {
            bail!("{} URL is outside the fixed feed paths", resource.label());
        }
        webui_http::download_https_utf8(uri, &policy, |uri| is_allowed_feed_uri(uri, resource))
    };
    let [primary, origin] = feed_candidates(&origin);
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
        FeedResource::LatestTag => {
            uri.query().is_none() && exact_github_path(host, uri.path(), LATEST_RELEASE_PATH)
        }
        FeedResource::ReleaseFeed => {
            uri.query().is_none() && exact_github_path(host, uri.path(), RELEASE_FEED_PATH)
        }
        FeedResource::AssetList { tag } => {
            uri.query().is_none()
                && is_release_tag(tag)
                && exact_github_path(host, uri.path(), &format!("{EXPANDED_ASSETS_PREFIX}{tag}"))
        }
        FeedResource::Profile { tag, asset } => {
            if !is_release_tag(tag) || !is_profile_asset_name(asset) {
                return false;
            }
            let github_path = format!("/{FEED_OWNER}/{FEED_REPO}/releases/download/{tag}/{asset}");
            if uri.query().is_none() && exact_github_path(host, uri.path(), &github_path) {
                true
            } else {
                // The GitHub download redirect lands on a signed CDN URL that
                // carries a query string, so those hosts are matched by name.
                RELEASE_ASSET_HOSTS
                    .iter()
                    .any(|allowed| host.eq_ignore_ascii_case(allowed))
                    && !uri.path().is_empty()
                    && !uri.path().contains("..")
            }
        }
    }
}

/// Accept the direct `github.com/<github_path>` form and the gh-proxy
/// `gh-proxy.com/https://github.com/<github_path>` form for one fixed path.
fn exact_github_path(host: &str, path: &str, github_path: &str) -> bool {
    if host.eq_ignore_ascii_case(GITHUB_HOST) {
        path == github_path
    } else if host.eq_ignore_ascii_case(PROXY_HOST) {
        path == format!("/https://{GITHUB_HOST}{github_path}")
    } else {
        false
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
        for tag in [
            "2026.10.11",
            "v2026.10",
            "v2026.10.11.1",
            "v2026.10.11a",
            "v../10.11",
        ] {
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
        let channel = FeedResource::LatestTag;
        for url in [
            "https://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://github.com:443/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://gh-proxy.com/https://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest",
        ] {
            assert!(
                is_allowed_feed_uri(&url.parse().unwrap(), &channel),
                "{url}"
            );
        }
        for url in [
            "http://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest/",
            "https://github.com/other/PIF-Config-Generator/releases/latest",
            "https://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest?page=1",
            "https://github.com.evil.example/Elcapitanoe/PIF-Config-Generator/releases/latest",
            "https://gh-proxy.com/https://github.com/Elcapitanoe/PIF-Config-Generator/releases/latest?page=1",
        ] {
            assert!(!is_allowed_feed_uri(&url.parse().unwrap(), &channel), "{url}");
        }

        let feed = FeedResource::ReleaseFeed;
        assert!(is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases.atom"
                .parse()
                .unwrap(),
            &feed
        ));
        assert!(!is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases.atom?page=2"
                .parse()
                .unwrap(),
            &feed
        ));

        let assets = FeedResource::AssetList {
            tag: "v2026.10.11".to_string(),
        };
        assert!(is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases/expanded_assets/v2026.10.11"
                .parse()
                .unwrap(),
            &assets
        ));
        assert!(!is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases/expanded_assets/v2026.10.03"
                .parse()
                .unwrap(),
            &assets
        ));
        assert!(!is_allowed_feed_uri(
            &"https://github.com/Elcapitanoe/PIF-Config-Generator/releases/expanded_assets/v../10.11"
                .parse()
                .unwrap(),
            &assets
        ));
    }

    #[test]
    fn asset_names_are_extracted_from_the_expanded_assets_fragment() {
        let html = r#"
            <a href="/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Akita_CP3A.261005.005.json">Akita</a>
            <a href="/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/Oriole_CP3A.261005.002.A1.json">Oriole</a>
            <a href="/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.03/Stale_CP3A.261005.001.json">Stale</a>
            <a href="/Elcapitanoe/PIF-Config-Generator/releases/download/v2026.10.11/notes.txt">notes</a>
        "#;
        let names = parse_asset_names(html, "v2026.10.11");
        assert_eq!(
            names,
            vec![
                "Akita_CP3A.261005.005.json".to_string(),
                "Oriole_CP3A.261005.002.A1.json".to_string(),
            ]
        );
    }

    #[test]
    fn atom_feed_yields_the_newest_valid_tag() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <feed><entry><id>tag:github.com,2008:Repository/1/v2026.10.11</id>
            <link href="https://github.com/Elcapitanoe/PIF-Config-Generator/releases/tag/v2026.10.11"/></entry>
            <entry><id>tag:github.com,2008:Repository/1/v2026.10.03</id></entry></feed>"#;
        assert_eq!(atom_first_tag(body).unwrap(), "v2026.10.11");
        assert!(atom_first_tag("no tags here").is_none());
        assert!(atom_first_tag("releases/tag/beta").is_none());
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
