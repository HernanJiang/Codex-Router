//! Autostart registration.
//!
//! Windows writes the `HKCU\...\Run` registry value (plus legacy shortcut/schtask
//! cleanup). macOS first-version does not yet implement launchd autostart, so
//! the API is a safe no-op there — tracked in `docs/mac-adaptation-TODO.md`.

#[cfg(windows)]
mod win {
    use anyhow::{bail, Context};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegSetValueExW,
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    };

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "Codex Router";
    const LEGACY_TASK: &str = "Codex Router Health Monitor";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn wide_str(value: &str) -> Vec<u16> {
        wide(std::ffi::OsStr::new(value))
    }

    fn run_command(executable: &Path) -> anyhow::Result<String> {
        let path = executable
            .to_str()
            .context("Codex-Router executable path is not valid Unicode")?;
        if path.contains('"') {
            bail!("Codex-Router executable path contains an invalid quote");
        }
        Ok(format!("\"{path}\" --background"))
    }

    fn set_run_value(command: &str) -> anyhow::Result<()> {
        let subkey = wide_str(RUN_KEY);
        let name = wide_str(RUN_VALUE);
        let mut key = std::ptr::null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if result != ERROR_SUCCESS {
            bail!("could not open the current-user autostart registry key: {result}");
        }
        let data = wide_str(command);
        let byte_len = u32::try_from(data.len().saturating_mul(std::mem::size_of::<u16>()))
            .context("autostart command is too long")?;
        let result = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                byte_len,
            )
        };
        unsafe { RegCloseKey(key) };
        if result != ERROR_SUCCESS {
            bail!("could not write the current-user autostart registry value: {result}");
        }
        Ok(())
    }

    fn remove_run_value() -> anyhow::Result<()> {
        let subkey = wide_str(RUN_KEY);
        let name = wide_str(RUN_VALUE);
        let mut key = std::ptr::null_mut();
        let result = unsafe {
            windows_sys::Win32::System::Registry::RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut key,
            )
        };
        if matches!(result, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(());
        }
        if result != ERROR_SUCCESS {
            bail!("could not open the current-user autostart registry key: {result}");
        }
        let result = unsafe { RegDeleteValueW(key, name.as_ptr()) };
        unsafe { RegCloseKey(key) };
        if !matches!(
            result,
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND
        ) {
            bail!("could not remove the current-user autostart registry value: {result}");
        }
        Ok(())
    }

    fn run_value_exists() -> bool {
        let subkey = wide_str(RUN_KEY);
        let name = wide_str(RUN_VALUE);
        let mut byte_len = 0u32;
        (unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut byte_len,
            )
        }) == ERROR_SUCCESS
            && byte_len >= 2
    }

    fn local_state_root() -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Codex-Router"))
    }

    fn legacy_shortcut_path() -> Option<PathBuf> {
        std::env::var_os("APPDATA").map(PathBuf::from).map(|path| {
            path.join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup")
                .join("Codex Router.lnk")
        })
    }

    fn remove_legacy_task() {
        let executable = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .map(|root| root.join("System32").join("schtasks.exe"))
            .filter(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("schtasks.exe"));
        let _ = std::process::Command::new(executable)
            .args(["/Delete", "/TN", LEGACY_TASK, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    fn remove_file_if_present(path: &Path) -> anyhow::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn set_enabled(router_root: &Path, enabled: bool) -> anyhow::Result<()> {
        let executable = router_root.join("Codex-Router.exe");
        if enabled && !executable.is_file() {
            bail!("Codex-Router.exe is missing from the selected installation root");
        }

        let pid_root = crate::user_data::data_root(router_root).join("pids");
        remove_file_if_present(&pid_root.join("health-monitor.enabled"))?;
        remove_file_if_present(&pid_root.join("health-monitor.paused"))?;

        let state_root = local_state_root().context("LOCALAPPDATA is unavailable")?;
        std::fs::create_dir_all(&state_root)?;
        let install_root = state_root.join("install-root.txt");
        if enabled {
            let command = run_command(&executable)?;
            set_run_value(&command)?;
            crate::config::atomic_write(&install_root, router_root.to_string_lossy().as_bytes())?;
        } else {
            remove_run_value()?;
            remove_file_if_present(&install_root)?;
        }

        if let Some(shortcut) = legacy_shortcut_path() {
            remove_file_if_present(&shortcut)?;
        }
        remove_legacy_task();
        Ok(())
    }

    pub fn is_registered() -> bool {
        run_value_exists() || legacy_shortcut_path().is_some_and(|path| path.is_file())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn native_autostart_command_quotes_the_executable_and_uses_background_mode() {
            let executable = Path::new(r"D:\Program Files\Codex Router\Codex-Router.exe");
            assert_eq!(
                run_command(executable).unwrap(),
                r#""D:\Program Files\Codex Router\Codex-Router.exe" --background"#
            );
        }

        #[test]
        fn native_autostart_command_rejects_quote_injection() {
            assert!(run_command(Path::new("D:\\bad\"path\\Codex-Router.exe")).is_err());
        }
    }
}

/// macOS first-version: autostart is not yet implemented (launchd plist comes
/// later). These are safe no-ops that keep the API surface identical.
#[cfg(not(windows))]
pub fn set_enabled(_router_root: &std::path::Path, _enabled: bool) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn is_registered() -> bool {
    false
}

#[cfg(windows)]
pub fn set_enabled(router_root: &std::path::Path, enabled: bool) -> anyhow::Result<()> {
    win::set_enabled(router_root, enabled)
}

#[cfg(windows)]
pub fn is_registered() -> bool {
    win::is_registered()
}
