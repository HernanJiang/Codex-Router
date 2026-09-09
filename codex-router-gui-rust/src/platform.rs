use anyhow::{bail, Context};
#[cfg(windows)]
use std::collections::{HashMap, HashSet};
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows::core::HSTRING;
#[cfg(windows)]
use windows::Win32::UI::Shell::ShellExecuteW;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, HWND, INVALID_HANDLE_VALUE, LPARAM, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};
use zeroize::Zeroizing;

#[cfg(windows)]
const CHATGPT_EXECUTABLE: &str = "ChatGPT.exe";
#[cfg(windows)]
const CODEX_PACKAGE_PREFIX: &str = "OpenAI.Codex_";
#[cfg(windows)]
const CODEX_APP_USER_MODEL_ID: &str = "OpenAI.Codex_2p2nqsd0c76g0!App";
#[cfg(windows)]
const GRACEFUL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const RELAUNCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexRestartOutcome {
    NotRunning,
    Restarted,
    RelaunchSkipped,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct DesktopProcess {
    process_id: u32,
    parent_process_id: u32,
    executable: Option<PathBuf>,
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum RestartTarget {
    PackagedApp { app_user_model_id: String },
    Executable(PathBuf),
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessOpenDisposition {
    AlreadyExited,
    Failed,
}

pub(crate) fn external_https_url(requested_url: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(requested_url).context("class=invalid_response")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("class=invalid_response")
    }
    Ok(url.into())
}

pub(crate) fn open_external_https_url(requested_url: &str) -> anyhow::Result<()> {
    let url = external_https_url(requested_url)?;
    open_validated_url(&url)
}

#[cfg(windows)]
fn open_validated_url(url: &str) -> anyhow::Result<()> {
    let url = HSTRING::from(url);
    let operation = HSTRING::from("open");
    let result = unsafe { ShellExecuteW(None, &operation, &url, None, None, SW_SHOWNORMAL) };
    if result.0 as isize <= 32 {
        bail!("class=process_failure")
    }
    Ok(())
}

#[cfg(not(windows))]
fn open_validated_url(url: &str) -> anyhow::Result<()> {
    let status = Command::new("open")
        .arg(url)
        .status()
        .context("could not open url in the default browser")?;
    if !status.success() {
        bail!("class=process_failure")
    }
    Ok(())
}

pub fn copy_router_credential(name: &str, prefix: Option<&str>) -> anyhow::Result<()> {
    let secret = crate::logic::read_router_credential_text(name)?
        .with_context(|| format!("Windows credential {name} is unavailable"))?;
    let mut text = Zeroizing::new(prefix.unwrap_or_default().to_owned());
    text.push_str(&secret);
    let mut clipboard = arboard::Clipboard::new().context("could not open the system clipboard")?;
    clipboard
        .set_text(text.as_str().to_owned())
        .context("could not write to the system clipboard")
}

#[cfg(windows)]
pub fn restart_codex_desktop() -> anyhow::Result<CodexRestartOutcome> {
    let processes = codex_desktop_processes()?;
    if processes.is_empty() {
        return Ok(CodexRestartOutcome::NotRunning);
    }
    let restart_target = processes
        .iter()
        .filter_map(|process| process.executable.as_ref())
        .find_map(|path| restart_target_for_path(path));

    request_graceful_close(&processes)?;
    let close_deadline = Instant::now() + GRACEFUL_CLOSE_TIMEOUT;
    while Instant::now() < close_deadline && !all_processes_exited(&processes) {
        std::thread::sleep(Duration::from_millis(100));
    }

    for process_id in shutdown_process_ids(&processes) {
        let process = processes
            .iter()
            .find(|process| process.process_id == process_id)
            .context("desktop shutdown plan referenced an unknown process")?;
        terminate_codex_desktop(process)?;
    }

    let Some(target) = restart_target else {
        return Ok(CodexRestartOutcome::RelaunchSkipped);
    };
    launch_restart_target(&target)?;
    let launch_deadline = Instant::now() + RELAUNCH_TIMEOUT;
    while Instant::now() < launch_deadline {
        if !codex_desktop_processes()?.is_empty() {
            return Ok(CodexRestartOutcome::Restarted);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("Codex / ChatGPT desktop did not start within 10 seconds")
}

#[cfg(not(windows))]
pub fn restart_codex_desktop() -> anyhow::Result<CodexRestartOutcome> {
    let targets = chatgpt_processes()?;
    if targets.is_empty() {
        return Ok(CodexRestartOutcome::NotRunning);
    }
    for pid in &targets {
        signal_process(*pid, libc::SIGTERM);
    }
    if !wait_processes_gone(&targets, GRACEFUL_CLOSE_TIMEOUT) {
        for pid in &targets {
            signal_process(*pid, libc::SIGKILL);
        }
        if !wait_processes_gone(&targets, RELAUNCH_TIMEOUT) {
            anyhow::bail!("Codex / ChatGPT desktop did not exit within 10 seconds")
        }
    }
    // Relaunch whatever bundle the running processes came from; fall back to
    // the conventional install locations resolved by name.
    let app = targets
        .iter()
        .filter_map(|pid| process_command(*pid).ok())
        .find_map(|command| app_bundle_from_command(&command))
        .unwrap_or_else(|| "ChatGPT".to_owned());
    std::process::Command::new("open")
        .args(["-a", &app])
        .stdin(std::process::Stdio::null())
        .spawn()
        .context("could not relaunch Codex / ChatGPT desktop")?;
    let deadline = std::time::Instant::now() + RELAUNCH_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if !chatgpt_processes().unwrap_or_default().is_empty() {
            return Ok(CodexRestartOutcome::Restarted);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("Codex / ChatGPT desktop did not start within 10 seconds")
}

#[cfg(not(windows))]
const GRACEFUL_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(not(windows))]
const RELAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// PIDs whose executable name is exactly `ChatGPT` (the
/// `/Applications/ChatGPT.app` process). Never matches prefix siblings.
#[cfg(not(windows))]
fn chatgpt_processes() -> anyhow::Result<Vec<u32>> {
    let output = std::process::Command::new("pgrep")
        .args(["-x", "ChatGPT"])
        .stdin(std::process::Stdio::null())
        .output()
        .context("could not enumerate processes")?;
    // pgrep exits 1 when nothing matches: not an error here.
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(parse_pgrep_output(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(not(windows))]
fn parse_pgrep_output(text: &str) -> Vec<u32> {
    text.split_whitespace()
        .filter_map(|token| token.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .collect()
}

#[cfg(not(windows))]
fn process_command(process_id: u32) -> anyhow::Result<String> {
    let output = std::process::Command::new("ps")
        .args(["-p", &process_id.to_string(), "-o", "command="])
        .stdin(std::process::Stdio::null())
        .output()
        .context("could not query the process table")?;
    if !output.status.success() {
        anyhow::bail!("process {process_id} is not running");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// `/Applications/ChatGPT.app/Contents/MacOS/ChatGPT ...` -> the `.app` bundle.
#[cfg(not(windows))]
fn app_bundle_from_command(command: &str) -> Option<String> {
    let executable = command.split_whitespace().next()?;
    let marker = ".app/";
    let end = executable.find(marker)? + ".app".len();
    let bundle = &executable[..end];
    if bundle.is_empty() {
        return None;
    }
    Some(bundle.to_owned())
}

#[cfg(not(windows))]
fn signal_process(process_id: u32, signal: libc::c_int) {
    unsafe {
        libc::kill(process_id as libc::pid_t, signal);
    }
}

#[cfg(not(windows))]
fn wait_processes_gone(processes: &[u32], timeout: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if processes
            .iter()
            .all(|pid| unsafe { libc::kill(*pid as libc::pid_t, 0) } != 0)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    processes
        .iter()
        .all(|pid| unsafe { libc::kill(*pid as libc::pid_t, 0) } != 0)
}

#[cfg(not(windows))]
pub fn codex_desktop_running() -> bool {
    chatgpt_processes().is_ok_and(|processes| !processes.is_empty())
}

#[cfg(windows)]
pub fn codex_desktop_running() -> bool {
    codex_desktop_processes().is_ok_and(|processes| !processes.is_empty())
}

#[cfg(windows)]
fn codex_desktop_processes() -> anyhow::Result<Vec<DesktopProcess>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("could not enumerate processes");
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut processes = Vec::new();
    let mut available = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while available {
        let name = utf16_c_string(&entry.szExeFile);
        if is_codex_desktop_executable(&name) {
            processes.push(DesktopProcess {
                process_id: entry.th32ProcessID,
                parent_process_id: entry.th32ParentProcessID,
                executable: process_path(entry.th32ProcessID).ok(),
            });
        }
        available = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    Ok(processes)
}

#[cfg(windows)]
fn process_path(process_id: u32) -> anyhow::Result<PathBuf> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error()).context("could not inspect desktop process");
    }
    let mut path = vec![0_u16; 32_768];
    let mut length = path.len() as u32;
    let result = unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) };
    unsafe { CloseHandle(handle) };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).context("could not read desktop process path");
    }
    path.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&path)))
}

#[cfg(windows)]
fn terminate_codex_desktop(process: &DesktopProcess) -> anyhow::Result<()> {
    let Some(expected_path) = process.executable.as_deref() else {
        bail!("refusing to terminate an unverified Codex / ChatGPT process")
    };
    if !is_codex_desktop_path(expected_path) {
        bail!("refusing to terminate a process that is not Codex / ChatGPT desktop")
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            process.process_id,
        )
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return match classify_open_process_error(error) {
            ProcessOpenDisposition::AlreadyExited => Ok(()),
            ProcessOpenDisposition::Failed => {
                Err(std::io::Error::last_os_error()).context("could not open desktop process")
            }
        };
    }
    if unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
        unsafe { CloseHandle(handle) };
        return Ok(());
    }
    let current_path = process_path_from_handle(handle);
    if current_path.is_err() && unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
        unsafe { CloseHandle(handle) };
        return Ok(());
    }
    let current_path = current_path?;
    if !paths_equal(&current_path, expected_path) || !is_codex_desktop_path(&current_path) {
        unsafe { CloseHandle(handle) };
        bail!("desktop process identity changed before restart")
    }
    let terminated = unsafe { TerminateProcess(handle, 0) } != 0;
    let waited = unsafe { WaitForSingleObject(handle, 10_000) } == WAIT_OBJECT_0;
    unsafe { CloseHandle(handle) };
    if !terminated && !waited {
        return Err(std::io::Error::last_os_error())
            .context("could not stop Codex / ChatGPT desktop");
    }
    if !waited {
        bail!("Codex / ChatGPT desktop did not exit within 10 seconds")
    }
    Ok(())
}

#[cfg(windows)]
fn classify_open_process_error(error: std::io::Error) -> ProcessOpenDisposition {
    if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
        ProcessOpenDisposition::AlreadyExited
    } else {
        ProcessOpenDisposition::Failed
    }
}

#[cfg(windows)]
fn process_has_exited(process_id: u32) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process_id) };
    if handle.is_null() {
        return classify_open_process_error(std::io::Error::last_os_error())
            == ProcessOpenDisposition::AlreadyExited;
    }
    let exited = unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0;
    unsafe { CloseHandle(handle) };
    exited
}

#[cfg(windows)]
fn all_processes_exited(processes: &[DesktopProcess]) -> bool {
    processes
        .iter()
        .all(|process| process_has_exited(process.process_id))
}

#[cfg(windows)]
struct CloseWindowContext<'a> {
    process_ids: &'a HashSet<u32>,
}

#[cfg(windows)]
unsafe extern "system" fn close_codex_window(window: HWND, parameter: LPARAM) -> i32 {
    let context = &*(parameter as *const CloseWindowContext<'_>);
    let mut process_id = 0_u32;
    GetWindowThreadProcessId(window, &mut process_id);
    if context.process_ids.contains(&process_id) {
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    1
}

#[cfg(windows)]
fn request_graceful_close(processes: &[DesktopProcess]) -> anyhow::Result<()> {
    let process_ids = processes
        .iter()
        .map(|process| process.process_id)
        .collect::<HashSet<_>>();
    let context = CloseWindowContext {
        process_ids: &process_ids,
    };
    if unsafe {
        EnumWindows(
            Some(close_codex_window),
            (&context as *const CloseWindowContext<'_>) as LPARAM,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("could not request Codex / ChatGPT desktop to close");
    }
    Ok(())
}

#[cfg(windows)]
fn shutdown_process_ids(processes: &[DesktopProcess]) -> Vec<u32> {
    let parents = processes
        .iter()
        .map(|process| (process.process_id, process.parent_process_id))
        .collect::<HashMap<_, _>>();
    let mut planned = processes
        .iter()
        .map(|process| {
            let mut depth = 0_usize;
            let mut current = process.process_id;
            let mut seen = HashSet::new();
            while seen.insert(current) {
                let Some(parent) = parents.get(&current).copied() else {
                    break;
                };
                if !parents.contains_key(&parent) {
                    break;
                }
                depth += 1;
                current = parent;
            }
            (depth, process.process_id)
        })
        .collect::<Vec<_>>();
    planned.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    planned
        .into_iter()
        .map(|(_, process_id)| process_id)
        .collect()
}

#[cfg(windows)]
fn restart_target_for_path(path: &Path) -> Option<RestartTarget> {
    if !is_codex_desktop_path(path) {
        return None;
    }
    let packaged = path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| name.starts_with(CODEX_PACKAGE_PREFIX))
    });
    if packaged {
        Some(RestartTarget::PackagedApp {
            app_user_model_id: CODEX_APP_USER_MODEL_ID.to_owned(),
        })
    } else if path.is_file() {
        Some(RestartTarget::Executable(path.to_owned()))
    } else {
        None
    }
}

#[cfg(windows)]
fn launch_restart_target(target: &RestartTarget) -> anyhow::Result<()> {
    match target {
        RestartTarget::PackagedApp { app_user_model_id } => {
            Command::new("explorer.exe")
                .arg(format!(r"shell:AppsFolder\{app_user_model_id}"))
                .spawn()
                .context("could not activate the packaged Codex desktop app")?;
        }
        RestartTarget::Executable(path) => {
            Command::new(path)
                .spawn()
                .context("could not relaunch Codex / ChatGPT desktop")?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn process_path_from_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> anyhow::Result<PathBuf> {
    let mut path = vec![0_u16; 32_768];
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not verify desktop process path");
    }
    path.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&path)))
}

#[cfg(windows)]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(right.to_string_lossy().trim_start_matches(r"\\?\"))
}

#[cfg(windows)]
fn is_codex_desktop_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_codex_desktop_executable)
}

#[cfg(windows)]
fn is_codex_desktop_executable(name: &str) -> bool {
    name.eq_ignore_ascii_case(CHATGPT_EXECUTABLE)
}

#[cfg(windows)]
fn utf16_c_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

#[cfg(all(test, not(windows)))]
mod unix_tests {
    use super::*;

    #[test]
    fn pgrep_output_parses_pids_and_ignores_junk() {
        assert_eq!(parse_pgrep_output("1477\n"), vec![1477]);
        assert_eq!(parse_pgrep_output(""), Vec::<u32>::new());
        assert_eq!(parse_pgrep_output("abc\n0\n42\n"), vec![42]);
    }

    #[test]
    fn app_bundle_resolves_from_process_command() {
        assert_eq!(
            app_bundle_from_command(
                "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT --some-flag"
            )
            .as_deref(),
            Some("/Applications/ChatGPT.app")
        );
        assert_eq!(
            app_bundle_from_command("/Users/x/Applications/ChatGPT.app/Contents/MacOS/ChatGPT")
                .as_deref(),
            Some("/Users/x/Applications/ChatGPT.app")
        );
        assert!(app_bundle_from_command("/usr/bin/sleep 60").is_none());
        assert!(app_bundle_from_command("").is_none());
    }

    #[test]
    fn desktop_running_probe_does_not_fail() {
        // Value depends on the machine (ChatGPT may or may not run here);
        // this pins the probe wiring only.
        let _ = codex_desktop_running();
        let _ = chatgpt_processes();
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn desktop_match_excludes_codex_cli() {
        assert!(is_codex_desktop_executable("ChatGPT.exe"));
        assert!(is_codex_desktop_executable("chatgpt.EXE"));
        assert!(!is_codex_desktop_executable("codex.exe"));
        assert!(!is_codex_desktop_executable("codex-code-mode-host.exe"));
        assert!(!is_codex_desktop_executable("Codex-Router.exe"));
    }

    #[test]
    fn packaged_codex_restart_plan_uses_apps_folder_activation() {
        let path = PathBuf::from(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_26.803.5235.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
        );
        assert_eq!(
            restart_target_for_path(&path),
            Some(RestartTarget::PackagedApp {
                app_user_model_id: "OpenAI.Codex_2p2nqsd0c76g0!App".to_owned(),
            })
        );
    }

    #[test]
    fn desktop_processes_shutdown_children_before_parent_without_touching_cli() {
        let desktop = PathBuf::from(r"C:\Program Files\WindowsApps\OpenAI.Codex\ChatGPT.exe");
        let processes = vec![
            DesktopProcess {
                process_id: 10,
                parent_process_id: 1,
                executable: Some(desktop.clone()),
            },
            DesktopProcess {
                process_id: 11,
                parent_process_id: 10,
                executable: Some(desktop.clone()),
            },
            DesktopProcess {
                process_id: 12,
                parent_process_id: 11,
                executable: Some(desktop),
            },
        ];
        assert_eq!(shutdown_process_ids(&processes), vec![12, 11, 10]);
    }

    #[test]
    fn already_exited_child_does_not_fail_restart() {
        assert_eq!(
            classify_open_process_error(std::io::Error::from_raw_os_error(87)),
            ProcessOpenDisposition::AlreadyExited
        );
    }
}
