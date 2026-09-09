//! Credential access for headless Router Host.
//! Windows uses the Credential Manager, macOS uses the Keychain via the
//! system `security` CLI. Both expose the same read/write/delete surface.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use zeroize::Zeroizing;

#[cfg(windows)]
use std::ptr::null_mut;
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
#[cfg(windows)]
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

/// UserData-scoped prefix so CodexRouter keys do not collide with CraftStation
/// or another Router copy that uses a different state root. Empty = legacy
/// `CodexRouter/{name}` targets (tests and pre-scope processes).
static CREDENTIAL_SCOPE: OnceLock<String> = OnceLock::new();

/// Pin Windows credential names to this installation's UserData root.
/// Safe to call more than once; the first non-empty scope wins.
pub fn set_scope_from_root(router_root: &Path) {
    let scope = credential_scope(router_root);
    if scope.is_empty() {
        return;
    }
    let _ = CREDENTIAL_SCOPE.set(scope);
}

fn credential_scope(router_root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let root = credential_state_root(router_root);
    let canonical = std::fs::canonicalize(&root).unwrap_or(root);
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    digest
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn credential_state_root(router_root: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("CODEX_ROUTER_USER_DATA_ROOT") {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return path;
        }
    }
    if std::env::var_os("CODEX_ROUTER_PORTABLE_STATE").is_some_and(|value| value == "1") {
        return router_root.to_path_buf();
    }
    if router_root.join("release-manifest.json").is_file() {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data)
                .join("Codex-Router")
                .join("UserData");
        }
    }
    router_root.to_path_buf()
}

pub fn wincred_target(name: &str) -> String {
    match CREDENTIAL_SCOPE.get() {
        Some(scope) if !scope.is_empty() => format!("CodexRouter/{scope}/{name}"),
        _ => format!("CodexRouter/{name}"),
    }
}

pub fn legacy_wincred_target(name: &str) -> String {
    format!("CodexRouter/{name}")
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn environment_override(name: &str) -> Option<&'static str> {
    match name {
        "AdminPassword" => Some("CODEX_ROUTER_ADMIN_PASSWORD"),
        "LocalApiKey" => Some("CODEX_ROUTER_LOCAL_API_KEY"),
        "CliManagementSecret" => Some("CODEX_ROUTER_CLI_MANAGEMENT_SECRET"),
        _ => None,
    }
}

pub fn read_text(name: &str) -> Result<Option<Zeroizing<String>>> {
    if let Some(value) = environment_override(name)
        .and_then(|variable| std::env::var(variable).ok())
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(Some(Zeroizing::new(value)));
    }
    if let Some(value) = read_target(&wincred_target(name))? {
        return Ok(Some(value));
    }
    let scoped = CREDENTIAL_SCOPE
        .get()
        .is_some_and(|scope| !scope.is_empty());
    if scoped {
        if let Some(value) = read_target(&legacy_wincred_target(name))? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn read_target(target_name: &str) -> Result<Option<Zeroizing<String>>> {
    let target = wide(target_name);
    let mut credential: *mut CREDENTIALW = null_mut();
    let found = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if found == 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            Ok(None)
        } else {
            Err(error).context("Windows Credential Manager read failed")
        };
    }
    if credential.is_null() {
        bail!("Windows Credential Manager returned an empty record");
    }
    let result = unsafe {
        let record = &*credential;
        if !record.CredentialBlobSize.is_multiple_of(2) || record.CredentialBlob.is_null() {
            bail!("Windows credential contains invalid UTF-16 data");
        }
        let units = std::slice::from_raw_parts(
            record.CredentialBlob.cast::<u16>(),
            record.CredentialBlobSize as usize / 2,
        );
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16(&units[..end]).map(Zeroizing::new)
    };
    unsafe { CredFree(credential.cast()) };
    Ok(Some(
        result.context("Windows credential contains invalid UTF-16")?,
    ))
}

#[cfg(target_os = "macos")]
fn read_target(target_name: &str) -> Result<Option<Zeroizing<String>>> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", target_name, "-w"])
        .output()
        .context("could not query the macOS Keychain")?;
    if !output.status.success() {
        return Ok(None);
    }
    let secret = String::from_utf8(output.stdout)
        .context("Keychain returned non-UTF-8 data")?
        .trim_end_matches('\n')
        .to_owned();
    Ok(Some(Zeroizing::new(secret)))
}

pub fn write_text(name: &str, secret: &str) -> Result<()> {
    if environment_override(name).is_some_and(|variable| std::env::var_os(variable).is_some()) {
        bail!("environment-overridden credential is read-only");
    }
    if name.trim().is_empty() || name.contains('\0') {
        bail!("credential name is invalid");
    }
    write_target(&wincred_target(name), secret)
}

#[cfg(windows)]
fn write_target(target_name: &str, secret: &str) -> Result<()> {
    let mut target = wide(target_name);
    let mut username = wide(&std::env::var("USERNAME").unwrap_or_default());
    let mut secret: Vec<u16> = secret.encode_utf16().collect();
    let blob_size = u32::try_from(secret.len().saturating_mul(std::mem::size_of::<u16>()))
        .context("Windows credential is too large")?;
    if blob_size > 2560 {
        bail!("Windows credential exceeds 2560 bytes");
    }
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob_size,
        CredentialBlob: secret.as_ptr().cast_mut().cast::<u8>(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: username.as_mut_ptr(),
        ..Default::default()
    };
    let written = unsafe { CredWriteW(&credential, 0) } != 0;
    secret.fill(0);
    if !written {
        return Err(std::io::Error::last_os_error())
            .context("Windows Credential Manager write failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_target(target_name: &str, secret: &str) -> Result<()> {
    let mut child = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            target_name,
            "-a",
            "CodexRouter",
            "-w",
            secret,
            "-U",
        ])
        .spawn()
        .context("could not spawn the macOS Keychain write")?;
    let status = child
        .wait()
        .context("could not await the macOS Keychain write")?;
    if !status.success() {
        bail!("macOS Keychain write failed with {status}");
    }
    Ok(())
}

pub fn delete_text(name: &str) -> Result<()> {
    delete_target(&wincred_target(name))?;
    if CREDENTIAL_SCOPE
        .get()
        .is_some_and(|scope| !scope.is_empty())
    {
        delete_target(&legacy_wincred_target(name))?;
    }
    Ok(())
}

#[cfg(windows)]
fn delete_target(target_name: &str) -> Result<()> {
    let target = wide(target_name);
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0;
    if !deleted {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            return Ok(());
        }
        return Err(error).context("Windows Credential Manager delete failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn delete_target(target_name: &str) -> Result<()> {
    let status = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", target_name])
        .status()
        .context("could not spawn the macOS Keychain delete")?;
    // Keychain reports a non-zero status when the item is absent; that is a
    // successful no-op for our callers.
    let _ = status;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_host_runtime_credentials_have_environment_overrides() {
        assert_eq!(
            environment_override("AdminPassword"),
            Some("CODEX_ROUTER_ADMIN_PASSWORD")
        );
        assert_eq!(
            environment_override("LocalApiKey"),
            Some("CODEX_ROUTER_LOCAL_API_KEY")
        );
        assert_eq!(
            environment_override("CliManagementSecret"),
            Some("CODEX_ROUTER_CLI_MANAGEMENT_SECRET")
        );
        assert_eq!(environment_override("AccountKey-1"), None);
    }

    #[test]
    fn unscope_targets_keep_the_legacy_codex_router_prefix() {
        assert_eq!(wincred_target("LocalApiKey"), "CodexRouter/LocalApiKey");
        assert_eq!(
            legacy_wincred_target("LocalApiKey"),
            "CodexRouter/LocalApiKey"
        );
    }
}
