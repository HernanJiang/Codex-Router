use anyhow::{bail, Context};
use codex_router_lib::backend::config_compiler as cli_compiler;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const RELEASE_API_URL: &str =
    "https://api.github.com/repos/HernanJiang/CodexRouter/releases/latest";
const REPOSITORY_URL: &str = "https://github.com/HernanJiang/CodexRouter";
const RELEASE_API_MIRRORS: &[&str] = &[
    "https://ghfast.top/https://api.github.com/repos/HernanJiang/CodexRouter/releases/latest",
    "https://ghproxy.net/https://api.github.com/repos/HernanJiang/CodexRouter/releases/latest",
    "https://mirror.ghproxy.com/https://api.github.com/repos/HernanJiang/CodexRouter/releases/latest",
];
const DOWNLOAD_MIRROR_PREFIXES: &[&str] = &[
    "https://ghfast.top/",
    "https://ghproxy.net/",
    "https://mirror.ghproxy.com/",
];
const HOST_REWRITE_MIRRORS: &[&str] = &["kkgithub.com"];
const RELEASE_DOWNLOAD_PREFIXES: &[&str] = &[
    "/HernanJiang/CodexRouter/releases/download/",
    "/HernanJiang/Codex-Router/releases/download/",
];
const USER_AGENT_VALUE: &str = "CodexRouter-Updater";
const MAX_ARCHIVE_ENTRIES: usize = 50_000;
const MAX_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const APPLY_PARENT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RESTART_STABILITY_WINDOW: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateInfo {
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) current_version: String,
    #[serde(default)]
    pub(crate) latest_version: String,
    #[serde(default)]
    pub(crate) release_name: String,
    #[serde(default)]
    pub(crate) release_notes: String,
    #[serde(default)]
    pub(crate) release_url: String,
    #[serde(default)]
    pub(crate) asset_name: String,
    #[serde(default)]
    pub(crate) download_url: String,
    #[serde(default)]
    pub(crate) asset_size: u64,
    #[serde(default)]
    pub(crate) asset_sha256: String,
    #[serde(default)]
    pub(crate) download_path: String,
    #[serde(default)]
    pub(crate) staged_path: String,
    #[serde(default)]
    pub(crate) message: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DownloadProgress {
    pub(crate) downloaded_bytes: u64,
    pub(crate) total_bytes: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallResult {
    pub(crate) installed: bool,
    pub(crate) install_root: String,
    pub(crate) version: String,
    pub(crate) shortcut: bool,
    pub(crate) user_data: String,
}

/// Return the per-user installation directory used by a fresh install.
/// Keeping this in the updater prevents the interactive wizard and the
/// command-line installer from drifting to different defaults.
pub(crate) fn default_install_root(version: &str) -> anyhow::Result<PathBuf> {
    let version = sanitize_version(version.trim());
    if version.is_empty() {
        bail!("the installer version is empty");
    }
    Ok(dirs::data_local_dir()
        .context("the current user has no local application-data directory")?
        .join("Programs")
        .join("CodexRouter")
        .join(version))
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    #[serde(default)]
    digest: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseManifestEntry {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct AppliedUpdate {
    router_root: PathBuf,
    staged_root: PathBuf,
    backup_root: PathBuf,
    preserved_paths: Vec<PathBuf>,
}

pub(crate) fn check_for_updates(current_version: &str) -> anyhow::Result<UpdateInfo> {
    let client = update_http_client()?;
    let mut last_error: Option<anyhow::Error> = None;
    for (index, url) in release_query_urls().into_iter().enumerate() {
        match fetch_latest_release(&client, &url) {
            Ok(release) => {
                let mut info = update_info_from_release(current_version, release)?;
                if index > 0 && info.message.is_empty() {
                    info.message = "GitHub official API was unavailable; fetched through a public mirror.".to_owned();
                }
                return Ok(info);
            }
            Err(error) if error.not_found => {
                return Ok(UpdateInfo {
                    status: "no_release".to_owned(),
                    current_version: current_version.to_owned(),
                    release_url: REPOSITORY_URL.to_owned(),
                    message: "The official GitHub repository has not published a Release yet."
                        .to_owned(),
                    ..Default::default()
                });
            }
            Err(error) => {
                last_error = Some(error.source);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("GitHub Release query failed"))).context(
        "class=update_request_failure | GitHub and public mirrors could not return the latest release",
    )
}

struct ReleaseFetchError {
    not_found: bool,
    source: anyhow::Error,
}

fn release_query_urls() -> Vec<String> {
    let mut urls = vec![RELEASE_API_URL.to_owned()];
    urls.extend(RELEASE_API_MIRRORS.iter().map(|url| (*url).to_owned()));
    urls
}

fn fetch_latest_release(client: &Client, url: &str) -> Result<GitHubRelease, ReleaseFetchError> {
    let response = client
        .get(url)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .map_err(|error| ReleaseFetchError {
            not_found: false,
            source: anyhow::Error::new(error)
                .context("class=update_request_failure | GitHub Release query failed"),
        })?;
    let status = response.status().as_u16();
    if status == 404 {
        return Err(ReleaseFetchError {
            not_found: true,
            source: anyhow::anyhow!("GitHub Release was not found"),
        });
    }
    if !response.status().is_success() {
        return Err(ReleaseFetchError {
            not_found: false,
            source: anyhow::anyhow!(
                "class=update_request_failure | GitHub Release query was rejected with status {status}"
            ),
        });
    }
    response.json().map_err(|error| ReleaseFetchError {
        not_found: false,
        source: anyhow::Error::new(error)
            .context("class=update_response_invalid | GitHub returned invalid Release metadata"),
    })
}

pub(crate) fn download_and_stage_update<F>(
    router_root: &Path,
    info: &UpdateInfo,
    mut on_progress: F,
) -> anyhow::Result<UpdateInfo>
where
    F: FnMut(DownloadProgress),
{
    validate_download_metadata(info)?;
    let cache_root = update_cache_root();
    fs::create_dir_all(&cache_root).context("could not create the update download directory")?;
    cleanup_incomplete_downloads(&cache_root);

    let client = update_http_client()?;
    let destination = cache_root.join(&info.asset_name);
    let mut last_error: Option<anyhow::Error> = None;
    let mut archive = None;
    for url in download_candidate_urls(&info.download_url) {
        match client
            .get(&url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ACCEPT, "application/octet-stream")
            .send()
        {
            Ok(response) if response.status().is_success() => {
                match receive_verified_payload(
                    response,
                    &destination,
                    info.asset_size,
                    &info.asset_sha256,
                    &mut on_progress,
                ) {
                    Ok(path) => {
                        archive = Some(path);
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error);
                        let _ = fs::remove_file(&destination);
                    }
                }
            }
            Ok(response) => {
                last_error = Some(anyhow::anyhow!(
                    "class=update_download_failure | update asset request was rejected with status {}",
                    response.status().as_u16()
                ));
            }
            Err(error) => {
                last_error = Some(
                    anyhow::Error::new(error)
                        .context("class=update_download_failure | update download failed"),
                );
            }
        }
    }
    let archive = archive.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow::anyhow!("update download failed"))
    })?;
    let staged_root = extract_and_verify_archive(router_root, &archive, &info.latest_version)?;

    let mut prepared = info.clone();
    prepared.status = "ready_to_install".to_owned();
    prepared.download_path = archive.to_string_lossy().into_owned();
    prepared.staged_path = staged_root.to_string_lossy().into_owned();
    prepared.message =
        "The update was downloaded, verified, and staged for automatic installation.".to_owned();
    Ok(prepared)
}

pub(crate) fn spawn_apply_helper(
    router_root: &Path,
    staged_root: &Path,
    parent_pid: u32,
) -> anyhow::Result<()> {
    let current_exe =
        std::env::current_exe().context("could not locate the running updater binary")?;
    let helper_root = update_cache_root().join("helpers");
    fs::create_dir_all(&helper_root).context("could not create the update helper directory")?;
    cleanup_old_helpers(&helper_root, None);
    let helper = helper_root.join(cli_compiler::executable_file_name(&format!(
        "Codex-Router-Updater-{parent_pid}-{}",
        unique_suffix()
    )));
    fs::copy(&current_exe, &helper).context("could not prepare the detached update helper")?;
    // The VC++ runtime sidecar only exists in the Windows portable tree.
    #[cfg(windows)]
    for runtime in ["VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"] {
        let source = router_root.join(runtime);
        if source.is_file() {
            fs::copy(&source, helper_root.join(runtime)).with_context(|| {
                format!("could not prepare the detached updater runtime: {runtime}")
            })?;
        }
    }

    let mut command = Command::new(&helper);
    command
        .arg("--apply-staged-update")
        .arg(format!("--parent-pid={parent_pid}"))
        .arg(format!("--router-root={}", router_root.display()))
        .arg(format!("--staged-root={}", staged_root.display()))
        .current_dir(&helper_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
        .spawn()
        .context("could not start the detached update helper")?;
    Ok(())
}

pub(crate) fn apply_staged_update(
    router_root: &Path,
    staged_root: &Path,
    parent_pid: u32,
) -> anyhow::Result<()> {
    let router_root = absolute_clean_path(router_root)?;
    let staged_root = absolute_clean_path(staged_root)?;
    if paths_overlap(&router_root, &staged_root) {
        bail!("the staged update must be outside the active Router directory");
    }
    verify_release_root(&staged_root, true)?;
    wait_for_process_exit(parent_pid, APPLY_PARENT_TIMEOUT)?;

    let transaction = begin_update_transaction(&router_root, &staged_root)?;
    match launch_updated_app(&router_root) {
        Ok(()) => transaction.commit(),
        Err(launch_error) => match transaction.rollback() {
            Ok(()) => Err(launch_error).context("the new version did not start; the previous version was restored"),
            Err(rollback_error) => bail!(
                "the new version did not start ({launch_error:#}) and rollback failed ({rollback_error:#})"
            ),
        },
    }
}

pub(crate) fn install_portable_archive(
    archive_path: &Path,
    version: &str,
    install_root: Option<&Path>,
    no_shortcut: bool,
) -> anyhow::Result<InstallResult> {
    let archive_path = if archive_path.is_absolute() {
        archive_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(archive_path)
    }
    .canonicalize()
    .context("the installer payload ZIP does not exist")?;
    let version = sanitize_version(version.trim());
    if version.is_empty() {
        bail!("the installer version is empty");
    }
    let default_root = default_install_root(&version)?;
    let requested_root = install_root.unwrap_or(&default_root);
    let parent = requested_root
        .parent()
        .context("the installation directory has no parent")?;
    fs::create_dir_all(parent).context("could not create the installation parent directory")?;
    let parent = parent
        .canonicalize()
        .context("could not resolve the installation parent directory")?;
    let leaf = requested_root
        .file_name()
        .context("the installation directory has no final component")?;
    let install_root = parent.join(leaf);
    if install_root.is_file() {
        bail!("the installation destination is a file");
    }

    let staged_root = extract_and_verify_archive(&install_root, &archive_path, &version)?;
    let staged_container = staged_root.parent().map(Path::to_path_buf);
    let shortcut_requested = !no_shortcut;
    let install_result = (|| -> anyhow::Result<()> {
        if install_root.exists() {
            let transaction = begin_update_transaction(&install_root, &staged_root)
                .context("could not replace the existing verified installation")?;
            match create_shortcuts(&install_root, shortcut_requested) {
                Ok(()) => transaction.commit(),
                Err(error) => match transaction.rollback() {
                    Ok(()) => Err(error).context(
                        "could not create the Start menu shortcut; the previous installation was restored",
                    ),
                    Err(rollback_error) => bail!(
                        "shortcut creation failed ({error:#}) and installation rollback failed ({rollback_error:#})"
                    ),
                },
            }
        } else {
            fs::rename(&staged_root, &install_root)
                .context("could not activate the verified installation")?;
            if let Err(error) = create_shortcuts(&install_root, shortcut_requested) {
                let _ = fs::rename(&install_root, &staged_root);
                Err(error).context("could not create the Start menu shortcut")
            } else {
                if let Some(container) = &staged_container {
                    let _ = fs::remove_dir(container);
                }
                Ok(())
            }
        }
    })();
    if install_result.is_err() {
        if let Some(container) = &staged_container {
            let _ = fs::remove_dir_all(container);
        }
    }
    install_result?;

    Ok(InstallResult {
        installed: true,
        install_root: display_path(&install_root),
        version,
        shortcut: shortcut_requested,
        user_data: dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("Codex-Router")
            .join("UserData")
            .to_string_lossy()
            .into_owned(),
    })
}

fn display_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(network) = value.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{network}");
    }
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
}

#[cfg(windows)]
fn create_desktop_shortcut(install_root: &Path) -> anyhow::Result<PathBuf> {
    let desktop = dirs::desktop_dir().context("the current user has no desktop directory")?;
    let shortcut_path = desktop.join("CodexRouter.lnk");
    create_windows_shortcut(install_root, &shortcut_path)
        .context("could not create the desktop shortcut")?;
    Ok(shortcut_path)
}

#[cfg(windows)]
fn create_start_menu_shortcut(install_root: &Path) -> anyhow::Result<PathBuf> {
    let start_menu = dirs::config_dir()
        .context("the current user has no roaming application-data directory")?
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("CodexRouter");
    fs::create_dir_all(&start_menu).context("could not create the Start menu directory")?;
    let shortcut_path = start_menu.join("CodexRouter.lnk");
    create_windows_shortcut(install_root, &shortcut_path)
        .context("could not create the Start menu shortcut")?;
    Ok(shortcut_path)
}

#[cfg(windows)]
fn create_shortcuts(install_root: &Path, enabled: bool) -> anyhow::Result<()> {
    if !enabled {
        return Ok(());
    }
    let desktop_shortcut = create_desktop_shortcut(install_root)?;
    if let Err(error) = create_start_menu_shortcut(install_root) {
        let _ = fs::remove_file(&desktop_shortcut);
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn create_windows_shortcut(install_root: &Path, shortcut_path: &Path) -> anyhow::Result<()> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    if let Some(parent) = shortcut_path.parent() {
        fs::create_dir_all(parent).context("could not create the shortcut directory")?;
    }
    let target = install_root.join("Codex-Router.exe");
    let wide = |value: &Path| {
        display_path(value)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let target_wide = wide(&target);
    let working_wide = wide(install_root);
    let shortcut_wide = wide(shortcut_path);
    let description = "CodexRouter\0".encode_utf16().collect::<Vec<_>>();

    unsafe {
        let initialized = CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_ok();
        let result = (|| -> anyhow::Result<()> {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
                .context("could not initialize the Windows shortcut service")?;
            link.SetPath(PCWSTR(target_wide.as_ptr()))
                .context("could not set the shortcut target")?;
            link.SetWorkingDirectory(PCWSTR(working_wide.as_ptr()))
                .context("could not set the shortcut working directory")?;
            link.SetDescription(PCWSTR(description.as_ptr()))
                .context("could not set the shortcut description")?;
            link.SetIconLocation(PCWSTR(target_wide.as_ptr()), 0)
                .context("could not set the shortcut icon")?;
            let persist: IPersistFile = link.cast()?;
            persist
                .Save(PCWSTR(shortcut_wide.as_ptr()), true)
                .context("could not save the Start menu shortcut")?;
            Ok(())
        })();
        if initialized {
            CoUninitialize();
        }
        result
    }
}

#[cfg(not(windows))]
fn create_shortcuts(_install_root: &Path, enabled: bool) -> anyhow::Result<()> {
    if enabled {
        bail!("Start menu shortcut creation is only available on Windows")
    }
    Ok(())
}

fn update_http_client() -> anyhow::Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(10 * 60))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .context("could not initialize the native update client")
}

fn update_info_from_release(
    current_version: &str,
    release: GitHubRelease,
) -> anyhow::Result<UpdateInfo> {
    let latest_version = release.tag_name.trim_start_matches('v').to_owned();
    let has_update =
        compare_versions(&latest_version, current_version)? == std::cmp::Ordering::Greater;
    let selected = release
        .assets
        .into_iter()
        .filter_map(|asset| asset_score(&asset).map(|score| (score, asset)))
        .max_by_key(|(score, _)| *score)
        .map(|(_, asset)| asset);
    let (asset_name, download_url, asset_size, asset_sha256, message) = match selected {
        Some(asset) => {
            validate_official_download_url(&asset.browser_download_url, &asset.name)?;
            let digest = normalize_sha256(&asset.digest).with_context(|| {
                format!("GitHub did not publish a SHA-256 digest for {}", asset.name)
            })?;
            (
                asset.name,
                asset.browser_download_url,
                asset.size,
                digest,
                String::new(),
            )
        }
        None => (
            String::new(),
            String::new(),
            0,
            String::new(),
            if has_update {
                "A new release exists, but it has no verified Windows x64 portable package."
                    .to_owned()
            } else {
                String::new()
            },
        ),
    };
    Ok(UpdateInfo {
        status: if has_update {
            "update_available".to_owned()
        } else {
            "current".to_owned()
        },
        current_version: current_version.to_owned(),
        latest_version,
        release_name: release.name,
        release_notes: release.body,
        release_url: if release.html_url.is_empty() {
            REPOSITORY_URL.to_owned()
        } else {
            release.html_url
        },
        asset_name,
        download_url,
        asset_size,
        asset_sha256,
        message,
        ..Default::default()
    })
}

fn asset_score(asset: &GitHubAsset) -> Option<i32> {
    let name = asset.name.to_ascii_lowercase();
    if !name.ends_with(".zip")
        || !name.contains("portable")
        || !(name.contains("windows") || name.contains("win"))
        || !(name.contains("x64") || name.contains("amd64"))
        || name.contains("source")
        || name.contains("symbols")
        || name.contains("debug")
        || normalize_sha256(&asset.digest).is_none()
    {
        return None;
    }
    Some(100 + i32::from(name.contains("codex-router") || name.contains("codexrouter")) * 20)
}

fn compare_versions(left: &str, right: &str) -> anyhow::Result<std::cmp::Ordering> {
    fn parse(value: &str) -> anyhow::Result<[u64; 3]> {
        let normalized = value.trim().trim_start_matches('v');
        let core = normalized
            .split_once('-')
            .map_or(normalized, |(core, _)| core);
        let parts = core.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            bail!("invalid semantic version: {value}");
        }
        Ok([
            parts[0].parse().context("invalid major version")?,
            parts[1].parse().context("invalid minor version")?,
            parts[2].parse().context("invalid patch version")?,
        ])
    }
    Ok(parse(left)?.cmp(&parse(right)?))
}

fn normalize_sha256(value: &str) -> Option<String> {
    let digest = value.trim().strip_prefix("sha256:").unwrap_or(value.trim());
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| digest.to_ascii_lowercase())
}

fn validate_download_metadata(info: &UpdateInfo) -> anyhow::Result<()> {
    if info.asset_size == 0 {
        bail!("the selected update asset has no declared size");
    }
    if normalize_sha256(&info.asset_sha256).is_none() {
        bail!("the selected update asset has no valid SHA-256 digest");
    }
    validate_official_download_url(&info.download_url, &info.asset_name)
}

fn official_github_download_url(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
        && RELEASE_DOWNLOAD_PREFIXES
            .iter()
            .any(|prefix| url.path().starts_with(prefix))
}

fn canonical_github_download_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value).context("the update download URL is invalid")?;
    if official_github_download_url(&url) {
        return Ok(url);
    }
    if url.scheme() != "https" {
        bail!("the update download URL is not HTTPS");
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if HOST_REWRITE_MIRRORS
        .iter()
        .any(|candidate| host.eq_ignore_ascii_case(candidate))
        && RELEASE_DOWNLOAD_PREFIXES
            .iter()
            .any(|prefix| url.path().starts_with(prefix))
    {
        let mut rewritten = url.clone();
        rewritten
            .set_host(Some("github.com"))
            .context("could not rewrite the mirrored GitHub download host")?;
        return Ok(rewritten);
    }
    let nested = url
        .as_str()
        .split_once("/https://")
        .map(|(_, rest)| format!("https://{rest}"))
        .or_else(|| {
            url.query_pairs().find_map(|(key, value)| {
                if key == "url" || key == "q" {
                    Some(value.into_owned())
                } else {
                    None
                }
            })
        });
    if let Some(nested) = nested {
        let nested = url::Url::parse(&nested)
            .context("the mirrored update download URL is invalid")?;
        if official_github_download_url(&nested) {
            return Ok(nested);
        }
    }
    bail!("the update download URL is not an official CodexRouter GitHub release URL")
}

fn validate_official_download_url(value: &str, expected_name: &str) -> anyhow::Result<()> {
    let url = canonical_github_download_url(value)?;
    let safe_name = Path::new(expected_name)
        .file_name()
        .and_then(|name| name.to_str())
        .context("the update asset name is invalid")?;
    if safe_name != expected_name || !safe_name.to_ascii_lowercase().ends_with(".zip") {
        bail!("the update asset is not a supported portable ZIP package");
    }
    let url_name = url
        .path_segments()
        .and_then(Iterator::last)
        .context("the update download URL has no asset name")?;
    if percent_decode(url_name)? != expected_name {
        bail!("the update asset name does not match its official URL");
    }
    Ok(())
}

fn download_candidate_urls(official: &str) -> Vec<String> {
    let Ok(canonical) = canonical_github_download_url(official) else {
        return vec![official.to_owned()];
    };
    let official = canonical.as_str().to_owned();
    let mut urls = vec![official.clone()];
    for prefix in DOWNLOAD_MIRROR_PREFIXES {
        urls.push(format!("{prefix}{official}"));
    }
    let mut kkgithub = canonical.clone();
    if kkgithub.set_host(Some("kkgithub.com")).is_ok() {
        urls.push(kkgithub.as_str().to_owned());
    }
    urls
}

fn percent_decode(value: &str) -> anyhow::Result<String> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("the update URL contains invalid percent encoding");
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])?;
            output.push(u8::from_str_radix(hex, 16).context("invalid URL percent encoding")?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).context("the update URL asset name is not UTF-8")
}

fn receive_verified_payload<F>(
    response: Response,
    destination: &Path,
    expected_size: u64,
    expected_sha256: &str,
    on_progress: &mut F,
) -> anyhow::Result<PathBuf>
where
    F: FnMut(DownloadProgress),
{
    if let Some(length) = response.content_length() {
        if length != expected_size {
            bail!("the server reported an unexpected update size");
        }
    }
    receive_verified_reader(
        response,
        destination,
        expected_size,
        expected_sha256,
        on_progress,
    )
}

fn receive_verified_reader<R, F>(
    mut reader: R,
    destination: &Path,
    expected_size: u64,
    expected_sha256: &str,
    on_progress: &mut F,
) -> anyhow::Result<PathBuf>
where
    R: Read,
    F: FnMut(DownloadProgress),
{
    let temporary = destination.with_extension("zip.download");
    if temporary.exists() {
        fs::remove_file(&temporary).context("could not clear an incomplete update download")?;
    }
    let result = (|| -> anyhow::Result<()> {
        let mut file = File::create(&temporary).context("could not create the update download")?;
        let mut hasher = Sha256::new();
        let mut downloaded = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        on_progress(DownloadProgress {
            downloaded_bytes: 0,
            total_bytes: expected_size,
        });
        loop {
            let count = reader
                .read(&mut buffer)
                .context("the update download stream ended unexpectedly")?;
            if count == 0 {
                break;
            }
            file.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
            downloaded = downloaded.saturating_add(count as u64);
            if downloaded > expected_size {
                bail!("the downloaded update is larger than its declared size");
            }
            on_progress(DownloadProgress {
                downloaded_bytes: downloaded,
                total_bytes: expected_size,
            });
        }
        file.flush()?;
        if downloaded != expected_size {
            bail!(
                "downloaded update size mismatch (expected {expected_size}, received {downloaded})"
            );
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected_sha256.to_ascii_lowercase() {
            bail!("downloaded update SHA-256 mismatch");
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if destination.exists() {
        fs::remove_file(destination).context("could not replace the previous update package")?;
    }
    fs::rename(&temporary, destination)
        .context("could not finalize the verified update package")?;
    Ok(destination.to_path_buf())
}

fn extract_and_verify_archive(
    router_root: &Path,
    archive_path: &Path,
    version: &str,
) -> anyhow::Result<PathBuf> {
    let parent = router_root
        .parent()
        .context("the Router directory has no writable parent")?;
    let container = parent.join(format!(
        ".codex-router-update-{}-{}",
        sanitize_version(version),
        unique_suffix()
    ));
    fs::create_dir(&container).context("could not create the same-volume update staging area")?;
    let result = (|| -> anyhow::Result<PathBuf> {
        let archive_file = File::open(archive_path).context("could not open the update ZIP")?;
        let mut archive =
            zip::ZipArchive::new(archive_file).context("the update ZIP is invalid")?;
        if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
            bail!("the update ZIP has an invalid number of entries");
        }
        let mut root_name: Option<String> = None;
        let mut seen = BTreeSet::new();
        let mut total_size = 0_u64;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .context("could not read an update ZIP entry")?;
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                bail!("the update ZIP contains a symbolic link");
            }
            let name = safe_archive_name(entry.name())?;
            let canonical = name.trim_end_matches('/').to_ascii_lowercase();
            if !seen.insert(canonical) {
                bail!("the update ZIP contains duplicate case-insensitive paths");
            }
            let first = name
                .trim_end_matches('/')
                .split('/')
                .next()
                .context("the update ZIP contains an empty path")?;
            match &root_name {
                Some(root) if !root.eq_ignore_ascii_case(first) => {
                    bail!("the update ZIP contains more than one release root")
                }
                None => root_name = Some(first.to_owned()),
                _ => {}
            }
            total_size = total_size
                .checked_add(entry.size())
                .context("the update ZIP size overflowed")?;
            if total_size > MAX_UNCOMPRESSED_BYTES {
                bail!("the update ZIP exceeds the safe uncompressed-size limit");
            }
            let destination = name
                .trim_end_matches('/')
                .split('/')
                .fold(container.clone(), |path, segment| path.join(segment));
            if entry.is_dir() || entry.name().ends_with('/') {
                fs::create_dir_all(&destination)?;
                continue;
            }
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = File::create(&destination)?;
            std::io::copy(&mut entry, &mut output)?;
            output.flush()?;
        }
        let staged_root = container.join(root_name.context("the update ZIP has no release root")?);
        verify_release_root(&staged_root, true)?;
        Ok(staged_root)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&container);
    }
    result
}

fn safe_archive_name(value: &str) -> anyhow::Result<String> {
    if value.is_empty()
        || value.contains('\\')
        || value.starts_with('/')
        || value.bytes().any(|byte| byte < 0x20)
    {
        bail!("the update ZIP contains an absolute or invalid path");
    }
    let directory = value.ends_with('/');
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("the update ZIP contains an empty path");
    }
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains(':') {
            bail!("the update ZIP contains a non-canonical or traversal path");
        }
    }
    Ok(if directory {
        format!("{trimmed}/")
    } else {
        trimmed.to_owned()
    })
}

fn load_release_manifest(root: &Path) -> anyhow::Result<Vec<ReleaseManifestEntry>> {
    let path = root.join("release-manifest.json");
    let bytes = fs::read(&path).context("release-manifest.json is missing")?;
    serde_json::from_slice(&bytes).context("release-manifest.json is invalid")
}

fn verify_release_root(root: &Path, reject_unmanaged_files: bool) -> anyhow::Result<()> {
    let entries = load_release_manifest(root)?;
    if entries.is_empty() {
        bail!("release-manifest.json is empty");
    }
    let mut expected = BTreeMap::new();
    for entry in entries {
        let relative = safe_manifest_path(&entry.path)?;
        let key = path_key(&relative);
        if expected.insert(key, relative.clone()).is_some() {
            bail!("release-manifest.json contains duplicate paths");
        }
        let file = root.join(&relative);
        let metadata = fs::metadata(&file)
            .with_context(|| format!("release file is missing: {}", entry.path))?;
        if !metadata.is_file() || metadata.len() != entry.bytes {
            bail!("release file size mismatch: {}", entry.path);
        }
        let expected_hash = normalize_sha256(&entry.sha256)
            .with_context(|| format!("release file has an invalid SHA-256: {}", entry.path))?;
        if sha256_file(&file)? != expected_hash {
            bail!("release file SHA-256 mismatch: {}", entry.path);
        }
    }
    if !root.join(cli_compiler::gui_executable_file_name()).is_file() {
        bail!(
            "the staged release does not contain {}",
            cli_compiler::gui_executable_file_name()
        );
    }
    if reject_unmanaged_files {
        let mut actual = BTreeSet::new();
        collect_files(root, root, &mut actual)?;
        actual.remove(&path_key(Path::new("release-manifest.json")));
        let expected = expected.into_keys().collect::<BTreeSet<_>>();
        if actual != expected {
            let detail = actual
                .difference(&expected)
                .next()
                .cloned()
                .or_else(|| expected.difference(&actual).next().cloned())
                .unwrap_or_else(|| "unknown".to_owned());
            bail!("the staged release does not match its file manifest: {detail}");
        }
    }
    Ok(())
}

fn safe_manifest_path(value: &str) -> anyhow::Result<PathBuf> {
    if value.is_empty() || value.contains('\\') || value.ends_with('/') {
        bail!("release-manifest.json contains an invalid path");
    }
    let path = Path::new(value);
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.to_string_lossy().contains(':') => clean.push(part),
            _ => bail!("release-manifest.json contains an unsafe path"),
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("release-manifest.json contains an empty path");
    }
    Ok(clean)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if metadata.is_file() {
            let relative = entry.path().strip_prefix(root)?.to_path_buf();
            output.insert(path_key(&relative));
        } else {
            bail!("the release contains an unsupported filesystem entry");
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn begin_update_transaction(
    router_root: &Path,
    staged_root: &Path,
) -> anyhow::Result<AppliedUpdate> {
    verify_release_root(router_root, false).context("the installed release failed validation")?;
    verify_release_root(staged_root, true).context("the staged release failed validation")?;
    let old_managed = managed_paths(router_root)?;
    let new_managed = managed_paths(staged_root)?;
    let preserve = maximal_unmanaged_paths(router_root, &old_managed)?;
    for relative in &preserve {
        if new_managed
            .iter()
            .any(|managed| paths_overlap(relative, managed))
        {
            bail!(
                "the new release conflicts with preserved user data: {}",
                relative.display()
            );
        }
    }
    let backup_root = router_root.with_file_name(format!(
        "{}.rollback-{}",
        router_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Codex-Router"),
        unique_suffix()
    ));
    if backup_root.exists() {
        bail!("the unique update rollback directory already exists");
    }
    fs::rename(router_root, &backup_root)
        .context("could not move the installed release to backup")?;
    if let Err(error) = fs::rename(staged_root, router_root) {
        let _ = fs::rename(&backup_root, router_root);
        return Err(error).context("could not activate the staged release");
    }

    let mut transaction = AppliedUpdate {
        router_root: router_root.to_path_buf(),
        staged_root: staged_root.to_path_buf(),
        backup_root,
        preserved_paths: Vec::new(),
    };
    for relative in preserve {
        let source = transaction.backup_root.join(&relative);
        let destination = transaction.router_root.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Err(error) = fs::rename(&source, &destination) {
            let rollback = transaction.rollback();
            return match rollback {
                Ok(()) => Err(error).with_context(|| {
                    format!("could not preserve user data: {}", relative.display())
                }),
                Err(rollback_error) => bail!(
                    "could not preserve user data ({error}) and rollback failed ({rollback_error:#})"
                ),
            };
        }
        transaction.preserved_paths.push(relative);
    }
    if let Err(error) = verify_release_root(&transaction.router_root, false) {
        let detail = format!("activated release validation failed: {error:#}");
        match transaction.rollback() {
            Ok(()) => bail!("{detail}; the previous version was restored"),
            Err(rollback_error) => bail!("{detail}; rollback failed: {rollback_error:#}"),
        }
    }
    Ok(transaction)
}

impl AppliedUpdate {
    fn rollback(mut self) -> anyhow::Result<()> {
        for relative in self.preserved_paths.iter().rev() {
            let source = self.router_root.join(relative);
            let destination = self.backup_root.join(relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            if source.exists() {
                fs::rename(&source, &destination).with_context(|| {
                    format!("could not restore preserved data: {}", relative.display())
                })?;
            }
        }
        self.preserved_paths.clear();
        if self.staged_root.exists() {
            bail!("the original update staging path unexpectedly exists during rollback");
        }
        fs::rename(&self.router_root, &self.staged_root)
            .context("could not move the failed update back to staging")?;
        fs::rename(&self.backup_root, &self.router_root)
            .context("could not restore the previous release directory")?;
        Ok(())
    }

    fn commit(self) -> anyhow::Result<()> {
        fs::remove_dir_all(&self.backup_root)
            .context("the update succeeded, but its rollback backup could not be removed")?;
        if let Some(container) = self.staged_root.parent() {
            let _ = fs::remove_dir(container);
        }
        Ok(())
    }
}

fn managed_paths(root: &Path) -> anyhow::Result<BTreeSet<PathBuf>> {
    let mut paths = load_release_manifest(root)?
        .into_iter()
        .map(|entry| safe_manifest_path(&entry.path))
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    paths.insert(PathBuf::from("release-manifest.json"));
    Ok(paths)
}

fn maximal_unmanaged_paths(
    root: &Path,
    managed: &BTreeSet<PathBuf>,
) -> anyhow::Result<Vec<PathBuf>> {
    fn visit(
        root: &Path,
        relative: &Path,
        managed: &BTreeSet<PathBuf>,
        output: &mut Vec<PathBuf>,
    ) -> anyhow::Result<()> {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("the installed directory contains an unsupported symbolic link");
        }
        let relative_key = path_key(relative);
        let descendant_prefix = format!("{relative_key}/");
        let is_managed = managed.iter().any(|item| path_key(item) == relative_key);
        let has_managed_descendant = managed
            .iter()
            .any(|item| path_key(item).starts_with(&descendant_prefix));
        if !is_managed && !has_managed_descendant {
            output.push(relative.to_path_buf());
            return Ok(());
        }
        if metadata.is_dir() {
            for child in fs::read_dir(path)? {
                let child = child?;
                visit(root, &relative.join(child.file_name()), managed, output)?;
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        visit(root, Path::new(&entry.file_name()), managed, &mut output)?;
    }
    output.sort_by_key(|left| path_key(left));
    Ok(output)
}

fn launch_updated_app(router_root: &Path) -> anyhow::Result<()> {
    let executable = router_root.join(cli_compiler::gui_executable_file_name());
    let mut child = Command::new(&executable)
        .current_dir(router_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("could not restart Codex-Router after updating")?;
    let started = std::time::Instant::now();
    while started.elapsed() < RESTART_STABILITY_WINDOW {
        if let Some(status) = child.try_wait()? {
            bail!("the updated Codex-Router exited immediately with {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

#[cfg(windows)]
fn wait_for_process_exit(process_id: u32, timeout: Duration) -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
    };
    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, process_id);
        if handle.is_null() {
            let error = GetLastError();
            if error == ERROR_INVALID_PARAMETER {
                return Ok(());
            }
            bail!("could not verify the running Codex-Router process (Windows error {error})");
        }
        let milliseconds = timeout.as_millis().min(u32::MAX as u128) as u32;
        let result = WaitForSingleObject(handle, milliseconds);
        CloseHandle(handle);
        match result {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => {
                bail!("the running Codex-Router did not exit before the update timeout")
            }
            other => bail!("waiting for the running Codex-Router failed with status {other}"),
        }
    }
}

#[cfg(not(windows))]
fn wait_for_process_exit(_process_id: u32, _timeout: Duration) -> anyhow::Result<()> {
    bail!("automatic update application is not implemented for this platform")
}

fn update_cache_root() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Codex-Router")
        .join("Updates")
}

fn cleanup_incomplete_downloads(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".download")
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn cleanup_old_helpers(root: &Path, keep: Option<&Path>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if keep.is_some_and(|keep| keep == path) {
            continue;
        }
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("Codex-Router-Updater-")
        {
            let _ = fs::remove_file(path);
        }
    }
}

fn cleanup_old_helpers_on_startup() {
    cleanup_old_helpers(
        &update_cache_root().join("helpers"),
        std::env::current_exe().ok().as_deref(),
    );
}

pub(crate) fn startup_housekeeping() {
    cleanup_old_helpers_on_startup();
}

fn absolute_clean_path(path: &Path) -> anyhow::Result<PathBuf> {
    if !path.is_absolute() {
        bail!("update paths must be absolute");
    }
    path.canonicalize()
        .with_context(|| format!("update path does not exist: {}", path.display()))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    fn components(path: &Path) -> Vec<String> {
        path.components()
            .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect()
    }
    let left = components(left);
    let right = components(right);
    left == right || left.starts_with(&right) || right.starts_with(&left)
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn sanitize_version(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("codex-router-updater-{label}-{}", unique_suffix()))
    }

    fn write_release(root: &Path, files: &[(&str, &[u8])]) {
        fs::create_dir_all(root).unwrap();
        let mut manifest = Vec::new();
        for (relative, content) in files {
            let path = root.join(relative.replace('/', "\\"));
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, content).unwrap();
            manifest.push(serde_json::json!({
                "path": relative,
                "bytes": content.len(),
                "sha256": sha256_file(&path).unwrap(),
            }));
        }
        fs::write(
            root.join("release-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn write_release_archive(source: &Path, archive: &Path, package_root: &str) {
        fn files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    files(root, &entry.path(), output);
                } else {
                    output.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
                }
            }
        }

        let mut relative_files = Vec::new();
        files(source, source, &mut relative_files);
        relative_files.sort_by_key(|path| path_key(path));
        let output = File::create(archive).unwrap();
        let mut writer = zip::ZipWriter::new(output);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for relative in relative_files {
            writer
                .start_file(format!("{package_root}/{}", path_key(&relative)), options)
                .unwrap();
            writer
                .write_all(&fs::read(source.join(relative)).unwrap())
                .unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn official_github_rate_limit_is_not_private_auth() {
        let official = "https://github.com/HernanJiang/CodexRouter/releases/download/v2.1.3/Codex-Router-Portable-2.1.3-windows-x64.zip";
        validate_official_download_url(
            official,
            "Codex-Router-Portable-2.1.3-windows-x64.zip",
        )
        .unwrap();
        validate_official_download_url(
            &format!("https://ghfast.top/{official}"),
            "Codex-Router-Portable-2.1.3-windows-x64.zip",
        )
        .unwrap();
        validate_official_download_url(
            "https://kkgithub.com/HernanJiang/CodexRouter/releases/download/v2.1.3/Codex-Router-Portable-2.1.3-windows-x64.zip",
            "Codex-Router-Portable-2.1.3-windows-x64.zip",
        )
        .unwrap();
        let urls = download_candidate_urls(official);
        assert_eq!(urls[0], official);
        assert!(urls.iter().any(|url| url.starts_with("https://ghfast.top/")));
        assert!(urls.iter().any(|url| url.contains("kkgithub.com")));
    }

    #[test]
    fn release_selection_requires_verified_portable_windows_zip() {
        let release = GitHubRelease {
            tag_name: "v1.5.9".to_owned(),
            name: "Codex-Router v1.5.9".to_owned(),
            body: String::new(),
            html_url: "https://github.com/HernanJiang/Codex-Router/releases/tag/v1.5.9"
                .to_owned(),
            assets: vec![
                GitHubAsset {
                    name: "Codex-Router-Installer-1.5.9-windows-x64.exe".to_owned(),
                    browser_download_url: "https://github.com/HernanJiang/Codex-Router/releases/download/v1.5.9/Codex-Router-Installer-1.5.9-windows-x64.exe".to_owned(),
                    size: 10,
                    digest: format!("sha256:{}", "a".repeat(64)),
                },
                GitHubAsset {
                    name: "Codex-Router-Portable-1.5.9-windows-x64.zip".to_owned(),
                    browser_download_url: "https://github.com/HernanJiang/Codex-Router/releases/download/v1.5.9/Codex-Router-Portable-1.5.9-windows-x64.zip".to_owned(),
                    size: 20,
                    digest: format!("sha256:{}", "b".repeat(64)),
                },
            ],
        };
        let info = update_info_from_release("1.5.8", release).unwrap();
        assert_eq!(info.status, "update_available");
        assert!(info.asset_name.contains("Portable"));
        assert_eq!(info.asset_sha256, "b".repeat(64));
    }

    #[test]
    fn verified_stream_reports_progress_and_rejects_hash_mismatch() {
        let root = temporary_dir("download");
        fs::create_dir_all(&root).unwrap();
        let bytes = vec![0x5a; 150_000];
        let expected = format!("{:x}", Sha256::digest(&bytes));
        let destination = root.join("release.zip");
        let mut progress = Vec::new();
        receive_verified_reader(
            std::io::Cursor::new(&bytes),
            &destination,
            bytes.len() as u64,
            &expected,
            &mut |value| progress.push(value),
        )
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(progress.first().unwrap().downloaded_bytes, 0);
        assert_eq!(progress.last().unwrap().downloaded_bytes, 150_000);

        let bad = root.join("bad.zip");
        let result = receive_verified_reader(
            std::io::Cursor::new(vec![1_u8; 8]),
            &bad,
            8,
            &"0".repeat(64),
            &mut |_| {},
        );
        assert!(result.unwrap_err().to_string().contains("SHA-256"));
        assert!(!bad.exists());
        assert!(!bad.with_extension("zip.download").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_paths_reject_traversal_and_windows_separators() {
        assert!(safe_archive_name("release/../secret").is_err());
        assert!(safe_archive_name("release\\secret").is_err());
        assert!(safe_archive_name("C:/secret").is_err());
        assert_eq!(
            safe_archive_name("release/app/file.exe").unwrap(),
            "release/app/file.exe"
        );
    }

    #[cfg(windows)]
    #[test]
    fn verified_release_zip_extracts_into_same_volume_staging() {
        let parent = temporary_dir("archive");
        let source = parent.join("source");
        let active = parent.join("Codex-Router");
        let archive = parent.join("release.zip");
        fs::create_dir_all(&active).unwrap();
        write_release(
            &source,
            &[
                ("Codex-Router.exe", b"new"),
                ("app/cli-proxy-api.exe", b"cli"),
            ],
        );
        write_release_archive(&source, &archive, "Codex-Router-New");

        let staged = extract_and_verify_archive(&active, &archive, "1.5.9").unwrap();

        assert_eq!(fs::read(staged.join("Codex-Router.exe")).unwrap(), b"new");
        assert!(staged.join("app/cli-proxy-api.exe").is_file());
        assert_eq!(staged.parent().unwrap().parent().unwrap(), parent);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_installer_verifies_and_replaces_portable_release_without_shortcut() {
        let parent = temporary_dir("native-install");
        let source = parent.join("source");
        let archive = parent.join("release.zip");
        let install_root = parent.join("Programs/Codex-Router/1.5.8");
        fs::create_dir_all(&parent).unwrap();
        write_release(
            &source,
            &[
                ("Codex-Router.exe", b"first"),
                ("app/cli-proxy-api.exe", b"cli"),
            ],
        );
        write_release_archive(&source, &archive, "Codex-Router-Portable-1.5.8");

        let result =
            install_portable_archive(&archive, "1.5.8", Some(&install_root), true).unwrap();
        assert!(result.installed);
        assert!(!result.shortcut);
        assert_eq!(
            fs::read(install_root.join("Codex-Router.exe")).unwrap(),
            b"first"
        );

        fs::write(install_root.join("user-note.txt"), b"preserve").unwrap();
        fs::remove_dir_all(&source).unwrap();
        write_release(
            &source,
            &[
                ("Codex-Router.exe", b"second"),
                ("app/cli-proxy-api.exe", b"cli"),
            ],
        );
        write_release_archive(&source, &archive, "Codex-Router-Portable-1.5.8");

        install_portable_archive(&archive, "1.5.8", Some(&install_root), true).unwrap();
        assert_eq!(
            fs::read(install_root.join("Codex-Router.exe")).unwrap(),
            b"second"
        );
        assert_eq!(
            fs::read(install_root.join("user-note.txt")).unwrap(),
            b"preserve"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_installer_cleans_staging_when_existing_installation_is_invalid() {
        let parent = temporary_dir("native-install-invalid-existing");
        let source = parent.join("source");
        let archive = parent.join("release.zip");
        let install_root = parent.join("Programs/Codex-Router/1.5.8");
        write_release(
            &source,
            &[
                ("Codex-Router.exe", b"new"),
                ("app/cli-proxy-api.exe", b"cli"),
            ],
        );
        write_release_archive(&source, &archive, "Codex-Router-Portable-1.5.8");
        fs::create_dir_all(&install_root).unwrap();
        fs::write(install_root.join("unmanaged.txt"), b"preserve").unwrap();

        let error =
            install_portable_archive(&archive, "1.5.8", Some(&install_root), true).unwrap_err();

        assert!(error
            .to_string()
            .contains("could not replace the existing verified installation"));
        let staging_parent = install_root.parent().unwrap();
        let staging_entries = fs::read_dir(staging_parent)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-router-update-")
            })
            .collect::<Vec<_>>();
        assert!(
            staging_entries.is_empty(),
            "failed installation left staging directories behind"
        );
        assert_eq!(
            fs::read(install_root.join("unmanaged.txt")).unwrap(),
            b"preserve"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_shortcut_is_created_in_an_isolated_directory() {
        let root = temporary_dir("native-shortcut");
        let install_root = root.join("installed");
        let shortcut = root.join("shortcuts/Codex-Router.lnk");
        fs::create_dir_all(&install_root).unwrap();
        fs::write(install_root.join("Codex-Router.exe"), b"test").unwrap();
        let install_root = install_root.canonicalize().unwrap();

        create_windows_shortcut(&install_root, &shortcut).unwrap();

        assert!(shortcut.is_file());
        assert!(fs::metadata(&shortcut).unwrap().len() > 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn update_transaction_preserves_unmanaged_state_and_can_rollback() {
        let parent = temporary_dir("transaction");
        let root = parent.join("Codex-Router");
        let staged_container = parent.join("staging");
        let staged = staged_container.join("Codex-Router-New");
        write_release(
            &root,
            &[
                ("Codex-Router.exe", b"old"),
                ("config/default.json", b"old-default"),
            ],
        );
        fs::create_dir_all(root.join("data/postgres")).unwrap();
        fs::write(root.join("data/postgres/PG_VERSION"), b"17").unwrap();
        fs::write(root.join("config/model-catalog.json"), b"user-catalog").unwrap();
        write_release(
            &staged,
            &[
                ("Codex-Router.exe", b"new"),
                ("config/default.json", b"new-default"),
                ("app/cli-proxy-api.exe", b"new-cli"),
            ],
        );

        let transaction = begin_update_transaction(&root, &staged).unwrap();
        assert_eq!(fs::read(root.join("Codex-Router.exe")).unwrap(), b"new");
        assert_eq!(
            fs::read(root.join("data/postgres/PG_VERSION")).unwrap(),
            b"17"
        );
        assert_eq!(
            fs::read(root.join("config/model-catalog.json")).unwrap(),
            b"user-catalog"
        );
        transaction.rollback().unwrap();

        assert_eq!(fs::read(root.join("Codex-Router.exe")).unwrap(), b"old");
        assert_eq!(
            fs::read(root.join("data/postgres/PG_VERSION")).unwrap(),
            b"17"
        );
        assert!(staged.join("app/cli-proxy-api.exe").is_file());
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn update_transaction_commit_keeps_state_and_removes_old_release() {
        let parent = temporary_dir("commit");
        let root = parent.join("Codex-Router");
        let staged = parent.join("staging/Codex-Router-New");
        write_release(&root, &[("Codex-Router.exe", b"old"), ("old.txt", b"old")]);
        fs::write(root.join("user.json"), b"state").unwrap();
        write_release(
            &staged,
            &[("Codex-Router.exe", b"new"), ("new.txt", b"new")],
        );

        let transaction = begin_update_transaction(&root, &staged).unwrap();
        transaction.commit().unwrap();

        assert_eq!(fs::read(root.join("Codex-Router.exe")).unwrap(), b"new");
        assert_eq!(fs::read(root.join("user.json")).unwrap(), b"state");
        assert!(!root.join("old.txt").exists());
        assert!(root.join("new.txt").is_file());
        fs::remove_dir_all(parent).unwrap();
    }
}
