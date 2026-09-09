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
mod mac {
    use anyhow::Context;
    use std::path::{Path, PathBuf};

    const LAUNCHD_LABEL: &str = "com.github.hernanjiang.codexrouter";
    const PLIST_FILE_NAME: &str = "com.github.hernanjiang.codexrouter.plist";

    fn agents_dir() -> PathBuf {
        // Test hook: point the plist at a scratch directory and skip the
        // launchctl service calls.
        if let Some(dir) = std::env::var_os("CODEX_ROUTER_LAUNCHD_DIR") {
            return PathBuf::from(dir);
        }
        dirs::home_dir()
            .map(|home| home.join("Library").join("LaunchAgents"))
            .unwrap_or_else(std::env::temp_dir)
    }

    fn plist_path() -> PathBuf {
        agents_dir().join(PLIST_FILE_NAME)
    }

    fn manage_service() -> bool {
        std::env::var_os("CODEX_ROUTER_LAUNCHD_DIR").is_none()
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    fn plist_document(executable: &Path) -> String {
        let executable = xml_escape(&executable.to_string_lossy());
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
                "<plist version=\"1.0\">\n",
                "<dict>\n",
                "\t<key>Label</key>\n",
                "\t<string>{label}</string>\n",
                "\t<key>ProgramArguments</key>\n",
                "\t<array>\n",
                "\t\t<string>{executable}</string>\n",
                "\t\t<string>--background</string>\n",
                "\t</array>\n",
                "\t<key>RunAtLoad</key>\n",
                "\t<true/>\n",
                "</dict>\n",
                "</plist>\n"
            ),
            label = LAUNCHD_LABEL,
            executable = executable,
        )
    }

    fn gui_domain() -> String {
        let uid = unsafe { libc::getuid() };
        format!("gui/{uid}")
    }

    fn launchctl(args: &[&str]) {
        // Best effort: the plist in ~/Library/LaunchAgents is what persists
        // across logins. A failing bootstrap/bootout is logged, never fatal.
        let status = std::process::Command::new("launchctl").args(args).status();
        match status {
            Ok(status) if status.success() => {}
            other => eprintln!("[autostart] launchctl {args:?} -> {other:?}"),
        }
    }

    pub fn set_enabled(router_root: &Path, enabled: bool) -> anyhow::Result<()> {
        use codex_router_lib::backend::config_compiler as cli_compiler;

        let executable = router_root.join(cli_compiler::gui_executable_file_name());
        if enabled && !executable.is_file() {
            anyhow::bail!(
                "{} is missing from the selected installation root",
                cli_compiler::gui_executable_file_name()
            );
        }
        let plist = plist_path();
        if enabled {
            if let Some(parent) = plist.parent() {
                std::fs::create_dir_all(parent).context("could not create LaunchAgents directory")?;
            }
            // Atomic write so loginwindow never reads a half-written plist.
            let temporary = plist.with_extension("plist.tmp");
            std::fs::write(&temporary, plist_document(&executable))
                .context("could not write the launchd plist")?;
            std::fs::rename(&temporary, &plist).context("could not install the launchd plist")?;
            if manage_service() {
                launchctl(&["bootstrap", &gui_domain(), &plist.to_string_lossy()]);
            }
        } else {
            if manage_service() {
                launchctl(&["bootout", &format!("{}/{}", gui_domain(), LAUNCHD_LABEL)]);
            }
            match std::fs::remove_file(&plist) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("could not remove the launchd plist"),
            }
        }
        Ok(())
    }

    pub fn is_registered() -> bool {
        plist_path().is_file()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{Mutex, OnceLock};

        fn test_env(dir: &Path) -> Vec<(String, String)> {
            vec![(
                "CODEX_ROUTER_LAUNCHD_DIR".to_owned(),
                dir.to_string_lossy().into_owned(),
            )]
        }

        fn with_env(dir: &Path, run: impl FnOnce()) {
            // Process-wide env is shared by parallel tests; serialize.
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let _guard = LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let saved = std::env::var_os("CODEX_ROUTER_LAUNCHD_DIR");
            for (key, value) in test_env(dir) {
                std::env::set_var(&key, &value);
            }
            run();
            match saved {
                Some(value) => std::env::set_var("CODEX_ROUTER_LAUNCHD_DIR", value),
                None => std::env::remove_var("CODEX_ROUTER_LAUNCHD_DIR"),
            }
        }

        fn scratch(label: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "codex-router-launchd-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn enable_writes_a_valid_plist_and_disable_removes_it() {
            let scope = scratch("cycle");
            let root = scope.join("CodexRouter");
            std::fs::create_dir_all(root.join("app")).unwrap();
            #[cfg(windows)]
            let gui = "Codex-Router.exe";
            #[cfg(not(windows))]
            let gui = "Codex-Router";
            std::fs::write(root.join(gui), b"stub").unwrap();
            with_env(&scope, || {
                assert!(!is_registered());
                set_enabled(&root, true).unwrap();
                assert!(is_registered());
                let plist = std::fs::read_to_string(plist_path()).unwrap();
                assert!(plist.contains(LAUNCHD_LABEL));
                assert!(plist.contains("--background"));
                assert!(plist.contains(&xml_escape(&root.join(gui).to_string_lossy())));
                // Idempotent: enabling twice keeps a single valid plist.
                set_enabled(&root, true).unwrap();
                assert!(is_registered());
                set_enabled(&root, false).unwrap();
                assert!(!is_registered());
                // Disabling twice is a no-op success.
                set_enabled(&root, false).unwrap();
            });
            let _ = std::fs::remove_dir_all(scope);
        }

        #[test]
        fn enable_refuses_a_root_without_gui_binary() {
            let scope = scratch("missing");
            let root = scope.join("Empty");
            std::fs::create_dir_all(&root).unwrap();
            with_env(&scope, || {
                assert!(set_enabled(&root, true).is_err());
                assert!(!is_registered());
            });
            let _ = std::fs::remove_dir_all(scope);
        }
    }
}

/// macOS autostart through a user LaunchAgents plist (see `mac` above).
#[cfg(not(windows))]
pub fn set_enabled(router_root: &std::path::Path, enabled: bool) -> anyhow::Result<()> {
    mac::set_enabled(router_root, enabled)
}

/// macOS autostart is registered while the LaunchAgents plist is installed.
#[cfg(not(windows))]
pub fn is_registered() -> bool {
    mac::is_registered()
}

#[cfg(windows)]
pub fn set_enabled(router_root: &std::path::Path, enabled: bool) -> anyhow::Result<()> {
    win::set_enabled(router_root, enabled)
}

#[cfg(windows)]
pub fn is_registered() -> bool {
    win::is_registered()
}
