use crate::config::RouterConfig;
use crate::{config, logic, user_data};
use anyhow::{bail, Context};
use codex_router_lib::backend::config_compiler as cli_compiler;
use serde::Serialize;
#[cfg(windows)]
use std::collections::HashSet;
#[cfg(windows)]
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
#[cfg(any(windows, test))]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::FromRawHandle;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN,
    TCP_TABLE_OWNER_PID_ALL,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AF_INET;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_ALWAYS};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    CREATE_NEW_PROCESS_GROUP, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DEFAULT_CLI_PORT: u16 = 18_081;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecyclePorts {
    /// Public compatibility port served by the Router Host (18080 by default).
    pub host: u16,
    /// Private CLIProxyAPI port managed by the Router Host (18081 by default).
    pub cli: u16,
}

/// Alternate host-port candidates tried when the configured port is owned by
/// another Router installation or program. Candidates step by 3 so each pick
/// also reserves the derived CLIProxyAPI port (host+1) and the in-process
/// responses gateway port (host+2) without overlapping the next candidate.
const ADOPT_HOST_PORT_CANDIDATES: &[u16] = &[
    28_080, 28_083, 28_086, 28_089, 28_092, 28_095, 28_098, 28_101,
];

pub fn adopt_isolated_host_if_foreign(
    router_root: &Path,
    config: &mut RouterConfig,
) -> Option<String> {
    adopt_isolated_host_if_foreign_with_candidates(
        router_root,
        config,
        ADOPT_HOST_PORT_CANDIDATES,
    )
}

fn adopt_isolated_host_if_foreign_with_candidates(
    router_root: &Path,
    config: &mut RouterConfig,
    candidates: &[u16],
) -> Option<String> {
    let Ok(ports) = LifecyclePorts::from_config(config) else {
        return None;
    };
    let expected_host = host_executable(router_root);
    let expected_cli = cli_executable(router_root);
    let host_pid = host_pid_file(router_root);
    let configured_group_conflicts =
        claim_managed_listener(
            ports.host,
            &expected_host,
            ServiceKind::RouterHost,
            &host_pid,
        )
        .is_err_and(|error| is_port_conflict_error(&error))
            || claim_managed_cli(ports.cli, &expected_cli, &expected_host, &host_pid)
                .is_err_and(|error| is_port_conflict_error(&error))
            || !gateway_port_usable(ports.host.saturating_add(2));
    if !configured_group_conflicts {
        return None;
    }
    for candidate in candidates {
        let candidate = *candidate;
        if candidate == ports.host || candidate < 1024 {
            continue;
        }
        // The host port itself is usable when it is free or already owned by
        // this installation's host (for example after a config rewrite).
        let host_usable =
            listener_process_id(candidate, &expected_host, ServiceKind::RouterHost).is_ok();
        // The derived CLIProxyAPI port must not belong to another install.
        let cli_usable = listener_process_id(
            candidate.saturating_add(1),
            &expected_cli,
            ServiceKind::CliProxyApi,
        )
        .is_ok();
        // The responses gateway is served by this GUI process; the port is
        // usable when nothing listens or only this process does.
        let gateway_usable = gateway_port_usable(candidate.saturating_add(2));
        if host_usable && cli_usable && gateway_usable {
            config.deploy.sub2api_host = format!("http://127.0.0.1:{candidate}");
            return Some(config.deploy.sub2api_host.clone());
        }
    }
    None
}

fn is_port_conflict_error(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("ROUTER_INSTALL_ROOT_CONFLICT") || text.contains("ROUTER_PORT_CONFLICT")
}

fn gateway_port_usable(port: u16) -> bool {
    #[cfg(windows)]
    {
        let Ok(rows) = tcp_rows() else {
            return false;
        };
        let current = std::process::id();
        return rows
            .into_iter()
            .filter(|row| row.dwState == MIB_TCP_STATE_LISTEN as u32 && row_port(row) == port)
            .all(|row| row.dwOwningPid == current);
    }
    #[cfg(not(windows))]
    {
        let _ = port;
        // Non-Windows first version: no TCP owner table; assume the port is
        // usable so port adoption does not spuriously rewrite the config.
        true
    }
}

/// Listener owned by *this* installation. A foreign Router copy or an
/// unrelated program holding the port is reported as `None` (nothing of ours
/// to stop or show) instead of an error, so Stop/Status/exit never fail just
/// because another installation is running.
fn owned_listener_or_none(
    port: u16,
    expected_path: &Path,
    kind: ServiceKind,
) -> anyhow::Result<Option<u32>> {
    match listener_process_id(port, expected_path, kind) {
        Ok(process_id) => Ok(process_id),
        Err(error) if is_port_conflict_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

impl LifecyclePorts {
    fn from_config(config: &RouterConfig) -> anyhow::Result<Self> {
        let configured = loopback_base_uri(&config.deploy.sub2api_host)?
            .port_or_known_default()
            .context("ROUTER_CONFIG_INVALID_BASE_URI: Router Host port is missing")?;
        let host = environment_port("CODEX_ROUTER_HOST_PORT", configured)?;
        Ok(Self {
            host,
            cli: environment_port("CODEX_ROUTER_CLI_PORT", default_cli_port(host))?,
        })
    }
}

/// The CLIProxyAPI port sits next to the Router Host port. The default pair is
/// 18080/18081; when this installation adopts an alternate host port because
/// 18080 is owned by another Router copy or program, the CLI moves along to
/// host+1 so two installations never fight over 18081.
fn default_cli_port(host: u16) -> u16 {
    if host == 18_080 {
        DEFAULT_CLI_PORT
    } else {
        host.saturating_add(1)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub component: String,
    pub endpoint: String,
    pub running: bool,
    pub ready: bool,
    pub process_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStatus {
    pub services: Vec<ServiceStatus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceKind {
    RouterHost,
    CliProxyApi,
}

impl ServiceKind {
    fn name(self) -> &'static str {
        match self {
            Self::RouterHost => "Router Host",
            Self::CliProxyApi => "CLIProxyAPI",
        }
    }
}

#[derive(Debug)]
pub struct LifecycleLock {
    _file: Option<File>,
    lock_path: Option<PathBuf>,
}

impl LifecycleLock {
    fn inherited() -> Self {
        Self {
            _file: None,
            lock_path: None,
        }
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        // Releasing the lock must free it for the next owner on every
        // platform. Windows leans on the open-handle share lock, but the
        // `create_new` file on other platforms persists after close, so
        // remove it — but only when it still carries our own PID, otherwise
        // a successor's lock file could be deleted out from under it.
            if let Some(path) = self.lock_path.take() {
            let ours = format!("pid={}", std::process::id());
            let owned = std::fs::read_to_string(&path)
                .map(|content| content.lines().next() == Some(ours.as_str()))
                .unwrap_or(false);
            if owned {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

pub fn acquire_lifecycle_lock(
    router_root: &Path,
    timeout: Duration,
    operation: &str,
) -> anyhow::Result<LifecycleLock> {
    let lock_directory = user_data::data_root(router_root).join("locks");
    std::fs::create_dir_all(&lock_directory)?;
    let lock_path = lock_directory.join("service-lifecycle.lock");
    #[cfg(windows)]
    {
        let lock_path_wide = wide(&lock_path);
        let started = Instant::now();
        loop {
            let handle = unsafe {
                CreateFileW(
                    lock_path_wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                let mut file = unsafe { File::from_raw_handle(handle) };
                file.set_len(0)?;
                write!(
                    file,
                    "pid={}\r\noperation={}\r\n",
                    std::process::id(),
                    operation
                )?;
                file.sync_all()?;
                return Ok(LifecycleLock {
                    _file: Some(file),
                    lock_path: Some(lock_path),
                });
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_SHARING_VIOLATION as i32) {
                return Err(error).context("ROUTER_LIFECYCLE_LOCK_FAILED");
            }
            if started.elapsed() >= timeout {
                bail!("ROUTER_LIFECYCLE_BUSY: Timed out waiting for another Start, Stop, Apply, or OAuth startup operation.");
            }
            std::thread::sleep(Duration::from_millis(75));
        }
    }
    #[cfg(not(windows))]
    {
        // Non-Windows lock: create the lock file exclusively. `create_new(true)`
        // fails with AlreadyExists when another process holds it, which keeps
        // the same acquire/timeout semantics as the Windows share violation,
        // without the Windows-only `File::from_raw_handle`.
        let started = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    write!(
                        file,
                        "pid={}\noperation={}\n",
                        std::process::id(),
                        operation
                    )?;
                    file.sync_all()?;
                    return Ok(LifecycleLock {
                        _file: Some(file),
                        lock_path: Some(lock_path),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if started.elapsed() >= timeout {
                        bail!("ROUTER_LIFECYCLE_BUSY: Timed out waiting for another Start, Stop, Apply, or OAuth startup operation.");
                    }
                    std::thread::sleep(Duration::from_millis(75));
                }
                Err(error) => {
                    return Err(error).context("ROUTER_LIFECYCLE_LOCK_FAILED");
                }
            }
        }
    }
}
fn environment_port(name: &str, fallback: u16) -> anyhow::Result<u16> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .with_context(|| format!("{name} is not a valid TCP port")),
        _ => Ok(fallback),
    }
}

fn loopback_base_uri(value: &str) -> anyhow::Result<url::Url> {
    let value = if value.trim().is_empty() {
        "http://127.0.0.1:18080"
    } else {
        value.trim()
    };
    let mut url = url::Url::parse(value).context("ROUTER_CONFIG_INVALID_BASE_URI")?;
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|address| address.is_loopback())
        || url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("localhost"));
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default().is_none()
    {
        bail!("ROUTER_CONFIG_INVALID_BASE_URI: Router Host must use loopback HTTP");
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

#[cfg(windows)]
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn normalized_path(path: &Path) -> anyhow::Result<PathBuf> {
    Ok(std::fs::canonicalize(path)
        .or_else(|_| Ok::<PathBuf, std::io::Error>(path.to_path_buf()))
        .map(|value| PathBuf::from(value.to_string_lossy().trim_start_matches(r"\\?\")))?)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = normalized_path(left).unwrap_or_else(|_| left.to_path_buf());
    let right = normalized_path(right).unwrap_or_else(|_| right.to_path_buf());
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(windows)]
fn process_path(process_id: u32) -> anyhow::Result<PathBuf> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not inspect process {process_id}"));
    }
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    let queried =
        unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) } != 0;
    unsafe { CloseHandle(handle) };
    if !queried {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not read process {process_id} image path"));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16(&buffer)?))
}

#[cfg(not(windows))]
fn process_path(process_id: u32) -> anyhow::Result<PathBuf> {
    // Unix: resolve argv[0] through `ps`. A full image path needs elevated
    // APIs; argv[0] carries the absolute path for processes we spawn ourselves
    // (host/CLI), which is what the same-service-image check needs. Anything
    // unresolvable (reaped PID, foreign command line) reports unavailable so
    // callers treat the process as unmanaged.
    let output = Command::new("ps")
        .args(["-p", &process_id.to_string(), "-o", "command="])
        .stdin(Stdio::null())
        .output()
        .context("could not query the process table")?;
    if !output.status.success() {
        bail!("process {process_id} is not running");
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let executable = line.split_whitespace().next().unwrap_or_default();
    if executable.is_empty() {
        bail!("process {process_id} has no executable");
    }
    Ok(PathBuf::from(executable))
}

fn process_exists(process_id: u32) -> bool {
    #[cfg(windows)]
    {
        process_path(process_id).is_ok()
    }
    #[cfg(not(windows))]
    {
        // signal 0 performs no action; ESRCH means absent, EPERM means a
        // process exists but belongs to another user.
        let pid = process_id as libc::pid_t;
        if pid <= 0 {
            return false;
        }
        let probe = unsafe { libc::kill(pid, 0) };
        probe == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM as i32)
    }
}

#[cfg(windows)]
fn tcp_rows() -> anyhow::Result<Vec<MIB_TCPROW_OWNER_PID>> {
    let mut required = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut required,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER || required < 4 {
        bail!(
            "ROUTER_LIFECYCLE_SAFETY_CHECK_FAILED: Windows TCP table size query failed ({first})"
        );
    }
    let mut buffer = vec![0u32; (required as usize).div_ceil(std::mem::size_of::<u32>())];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut required,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != 0 {
        bail!("ROUTER_LIFECYCLE_SAFETY_CHECK_FAILED: Windows TCP table query failed ({result})");
    }
    let count = buffer[0] as usize;
    let rows_bytes = required as usize - std::mem::size_of::<u32>();
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    if count > rows_bytes / row_size {
        bail!("ROUTER_LIFECYCLE_SAFETY_CHECK_FAILED: Windows TCP table is malformed");
    }
    let first_row = unsafe { buffer.as_ptr().cast::<u8>().add(4) };
    Ok((0..count)
        .map(|index| unsafe { std::ptr::read_unaligned(first_row.add(index * row_size).cast()) })
        .collect())
}

#[cfg(windows)]
fn row_port(row: &MIB_TCPROW_OWNER_PID) -> u16 {
    u16::from_be((row.dwLocalPort & 0xffff) as u16)
}
#[cfg(windows)]
fn listener_process_id(
    port: u16,
    expected_path: &Path,
    kind: ServiceKind,
) -> anyhow::Result<Option<u32>> {
    let listeners = tcp_rows()?
        .into_iter()
        .filter(|row| row.dwState == MIB_TCP_STATE_LISTEN as u32 && row_port(row) == port)
        .collect::<Vec<_>>();
    if listeners.is_empty() {
        return Ok(None);
    }
    let loopback = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    if listeners.iter().any(|row| row.dwLocalAddr != loopback) {
        bail!(
            "ROUTER_PORT_CONFLICT: {} has a non-loopback listener on port {port}",
            kind.name()
        );
    }
    let process_ids = listeners
        .iter()
        .map(|row| row.dwOwningPid)
        .collect::<HashSet<_>>();
    if process_ids.len() != 1 {
        bail!(
            "ROUTER_PORT_CONFLICT: {} port {port} has ambiguous owners",
            kind.name()
        );
    }
    let process_id = *process_ids.iter().next().unwrap();
    let actual = process_path(process_id).map_err(|_| {
        anyhow::anyhow!(
            "ROUTER_PORT_CONFLICT: {} port {port} is owned by an unidentified process",
            kind.name()
        )
    })?;
    if !paths_equal(&actual, expected_path) {
        let same_binary = actual
            .file_name()
            .zip(expected_path.file_name())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right));
        if same_binary {
            bail!("ROUTER_INSTALL_ROOT_CONFLICT: {} port {port} belongs to another Codex-Router installation", kind.name());
        }
        bail!(
            "ROUTER_PORT_CONFLICT: {} port {port} belongs to another program",
            kind.name()
        );
    }
    Ok(Some(process_id))
}

#[cfg(not(windows))]
fn listener_process_id(
    port: u16,
    expected_path: &Path,
    kind: ServiceKind,
) -> anyhow::Result<Option<u32>> {
    let Some(occupant) = loopback_listener_pid(port)? else {
        return Ok(None);
    };
    // Same taxonomy as the Windows owner-table path so callers behave
    // identically: foreign listeners are hard errors, same-installation
    // listeners are claimed, other Router copies surface as conflicts.
    let actual = process_path(occupant).map_err(|_| {
        anyhow::anyhow!(
            "ROUTER_PORT_CONFLICT: {} port {port} is owned by an unidentified process",
            kind.name()
        )
    })?;
    if paths_equal(&actual, expected_path) {
        return Ok(Some(occupant));
    }
    if same_service_image(&actual, expected_path) {
        bail!("ROUTER_INSTALL_ROOT_CONFLICT: {} port {port} belongs to another Codex-Router installation", kind.name());
    }
    bail!(
        "ROUTER_PORT_CONFLICT: {} port {port} belongs to another program",
        kind.name()
    );
}

/// Unix loopback listener lookup through `lsof`. Missing `lsof` (minimal
/// Linux containers) degrades to "no listener", the same as the old no-op;
/// a busy port then surfaces as a bind error instead of a managed sweep.
/// Mirrors the Windows `loopback_listener_pid` contract: non-loopback or
/// ambiguous listeners report `None` instead of erroring.
#[cfg(not(windows))]
fn loopback_listener_pid(port: u16) -> anyhow::Result<Option<u32>> {
    let output = match Command::new("lsof")
        .args([
            format!("-iTCP:{port}"),
            "-sTCP:LISTEN".to_owned(),
            "-P".to_owned(),
            "-n".to_owned(),
            "-Fn".to_owned(),
        ])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if !output.status.success() {
        return Ok(None);
    }
    // Endpoint forms: `127.0.0.1:18080`, `[::1]:18080`, `*:18080`.
    fn is_loopback(endpoint: &str) -> bool {
        endpoint.starts_with("127.0.0.1:")
            || endpoint.starts_with("localhost:")
            || endpoint.starts_with("[::1]:")
    }
    let mut owners = std::collections::HashSet::new();
    let mut current: Option<u32> = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(pid) = line.strip_prefix('p') {
            current = pid.parse::<u32>().ok();
        } else if let Some(endpoint) = line.strip_prefix('n') {
            if !is_loopback(endpoint) {
                return Ok(None);
            }
            if let Some(pid) = current {
                owners.insert(pid);
            }
        }
    }
    if owners.len() == 1 {
        Ok(owners.into_iter().next())
    } else {
        Ok(None)
    }
}

pub fn established_connection_count(process_id: u32, port: u16) -> anyhow::Result<usize> {
    #[cfg(windows)]
    {
        return tcp_rows()
            .map(|rows| {
                rows.into_iter()
                    .filter(|row| {
                        row.dwState == MIB_TCP_STATE_ESTAB as u32
                            && row.dwOwningPid == process_id
                            && row_port(row) == port
                    })
                    .count()
            })
            .context("ROUTER_LIFECYCLE_SAFETY_CHECK_FAILED");
    }
    #[cfg(not(windows))]
    {
        let _ = (process_id, port);
        // Safe degradation: established-connection counting is not implemented
        // without the TCP owner table; report zero active connections.
        Ok(0)
    }
}

fn assert_interruption_allowed(process_id: u32, port: u16, operation: &str) -> anyhow::Result<()> {
    let active = established_connection_count(process_id, port)?;
    if active > 0 {
        bail!("ROUTER_LIFECYCLE_DEFERRED: {operation} was deferred because Router Host PID {process_id} has {active} active Established connection(s). Router Host and CLIProxyAPI were left unchanged; retry after active requests finish.");
    }
    Ok(())
}

fn terminate_verified_process(process_id: u32, expected_path: &Path) -> anyhow::Result<()> {
    terminate_managed_process(process_id, expected_path, None)
}

#[cfg(windows)]
fn terminate_managed_process(
    process_id: u32,
    expected_path: &Path,
    pid_file: Option<&Path>,
) -> anyhow::Result<()> {
    let actual = match process_path(process_id) {
        Ok(path) => path,
        Err(_) if !process_exists(process_id) => return Ok(()),
        Err(error) => return Err(error),
    };
    let allowed = paths_equal(&actual, expected_path)
        || pid_file.is_some_and(|path| process_is_managed(process_id, expected_path, path));
    if !allowed {
        bail!("refusing to terminate an unverified process");
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("could not open verified service process");
    }
    let terminated = unsafe { TerminateProcess(handle, 1) } != 0;
    let waited = unsafe { WaitForSingleObject(handle, 10_000) } == WAIT_OBJECT_0;
    unsafe { CloseHandle(handle) };
    if !terminated && process_exists(process_id) {
        return Err(std::io::Error::last_os_error())
            .context("could not terminate verified service process");
    }
    if !waited && process_exists(process_id) {
        bail!("verified service process did not exit within 10 seconds");
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_managed_process(
    process_id: u32,
    expected_path: &Path,
    pid_file: Option<&Path>,
) -> anyhow::Result<()> {
    let pid_file = pid_file.unwrap_or_else(|| Path::new(""));
    if !process_is_managed(process_id, expected_path, pid_file) {
        if !process_exists(process_id) {
            return Ok(());
        }
        bail!("refusing to terminate an unverified process");
    }
    unix_terminate_process(process_id)
}

/// True once a process is gone. A SIGKILLed child of this process lingers as
/// a zombie until reaped, and `kill(pid, 0)` still reports zombies as alive,
/// so reap our own children with `waitpid(WNOHANG)`; anything else falls back
/// to the existence probe (reparented orphans are reaped by init).
#[cfg(not(windows))]
fn reaped_or_gone(process_id: u32) -> bool {
    let mut status = 0 as libc::c_int;
    let waited = unsafe { libc::waitpid(process_id as libc::pid_t, &mut status, libc::WNOHANG) };
    if waited == process_id as libc::pid_t {
        return true;
    }
    if waited == 0 {
        return false;
    }
    !process_exists(process_id)
}

/// SIGTERM, wait up to 10s, then SIGKILL. Shared by the managed and
/// same-image Unix termination paths.
#[cfg(not(windows))]
fn unix_terminate_process(process_id: u32) -> anyhow::Result<()> {    fn signal(pid: u32, number: libc::c_int) {
        unsafe {
            libc::kill(pid as libc::pid_t, number);
        }
    }
    fn wait_exit(process_id: u32, timeout: Duration) -> bool {
        let started = Instant::now();
        while !reaped_or_gone(process_id) {
            if started.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }
    if !process_exists(process_id) {
        return Ok(());
    }
    signal(process_id, libc::SIGTERM);    if !wait_exit(process_id, Duration::from_secs(10)) {
        signal(process_id, libc::SIGKILL);
        if !wait_exit(process_id, Duration::from_secs(10)) {
            bail!("verified service process did not exit within 10 seconds");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_same_image_process(process_id: u32, expected_path: &Path) -> anyhow::Result<()> {
    let actual = match process_path(process_id) {
        Ok(path) => path,
        Err(_) if !process_exists(process_id) => return Ok(()),
        Err(error) => return Err(error),
    };
    if paths_equal(&actual, expected_path) {
        return terminate_managed_process(process_id, expected_path, None);
    }
    if !same_service_image(&actual, expected_path) {
        bail!("refusing to terminate an unverified process");
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("could not open verified service process");
    }
    let terminated = unsafe { TerminateProcess(handle, 1) } != 0;
    let waited = unsafe { WaitForSingleObject(handle, 10_000) } == WAIT_OBJECT_0;
    unsafe { CloseHandle(handle) };
    if !terminated && process_exists(process_id) {
        return Err(std::io::Error::last_os_error())
            .context("could not terminate verified service process");
    }
    if !waited && process_exists(process_id) {
        bail!("verified service process did not exit within 10 seconds");
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_same_image_process(process_id: u32, expected_path: &Path) -> anyhow::Result<()> {
    let actual = match process_path(process_id) {
        Ok(path) => path,
        Err(_) if !process_exists(process_id) => return Ok(()),
        Err(error) => return Err(error),
    };
    if !paths_equal(&actual, expected_path) && !same_service_image(&actual, expected_path) {
        bail!("refusing to terminate an unverified process");
    }
    unix_terminate_process(process_id)
}

fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|process_id| *process_id > 0)
}

fn rotate_log(path: &Path) {
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
        let previous = path.with_file_name(format!(
            "{}.previous.log",
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("service")
        ));
        let _ = std::fs::remove_file(&previous);
        let _ = std::fs::rename(path, previous);
    }
}

fn host_executable(router_root: &Path) -> PathBuf {
    router_root
        .join("app")
        .join(cli_compiler::host_executable_file_name())
}

fn cli_executable(router_root: &Path) -> PathBuf {
    router_root
        .join("app")
        .join(cli_compiler::cli_executable_file_name())
}

fn host_pid_file(router_root: &Path) -> PathBuf {
    user_data::data_root(router_root)
        .join("pids")
        .join("router-host.pid")
}

fn same_service_image(actual: &Path, expected: &Path) -> bool {
    actual
        .file_name()
        .zip(expected.file_name())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn process_is_managed(process_id: u32, expected_path: &Path, _pid_file: &Path) -> bool {
    let Ok(actual) = process_path(process_id) else {
        return false;
    };
    paths_equal(&actual, expected_path) || same_service_image(&actual, expected_path)
}

fn router_host_port_candidates(configured_host: u16) -> Vec<u16> {
    let mut ports = vec![18_080, configured_host];
    ports.extend(ADOPT_HOST_PORT_CANDIDATES.iter().copied());
    ports.retain(|port| *port >= 1_024);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Older portables share UserData but listen on hopped ports. Closing the GUI
/// must free those listeners; starting a new portable must not leave them.
fn sweep_stale_router_listeners(
    expected_host: &Path,
    expected_cli: &Path,
    configured_host: u16,
    keep_host_pid: Option<u32>,
) -> anyhow::Result<()> {
    let keep_cli_port = default_cli_port(configured_host);
    for host_port in router_host_port_candidates(configured_host) {
        if let Some(pid) = loopback_listener_pid(host_port)? {
            if keep_host_pid != Some(pid)
                && process_path(pid)
                    .ok()
                    .is_some_and(|path| same_service_image(&path, expected_host))
            {
                terminate_same_image_process(pid, expected_host)?;
            }
        }
        let cli_port = default_cli_port(host_port);
        if keep_host_pid.is_some() && cli_port == keep_cli_port {
            continue;
        }
        if let Some(pid) = loopback_listener_pid(cli_port)? {
            if process_path(pid)
                .ok()
                .is_some_and(|path| same_service_image(&path, expected_cli))
            {
                terminate_same_image_process(pid, expected_cli)?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn loopback_listener_pid(port: u16) -> anyhow::Result<Option<u32>> {
    let listeners = tcp_rows()?
        .into_iter()
        .filter(|row| row.dwState == MIB_TCP_STATE_LISTEN as u32 && row_port(row) == port)
        .collect::<Vec<_>>();
    if listeners.is_empty() {
        return Ok(None);
    }
    let loopback = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    if listeners.iter().any(|row| row.dwLocalAddr != loopback) {
        return Ok(None);
    }
    let process_ids = listeners
        .iter()
        .map(|row| row.dwOwningPid)
        .collect::<HashSet<_>>();
    if process_ids.len() != 1 {
        return Ok(None);
    }
    Ok(process_ids.into_iter().next())
}

/// Treat a previous portable's host/CLI as this UserData's process when the
/// image name matches. Version upgrades share UserData but have different
/// install paths; hopping ports would start a second stack against the same
/// sqlite/locks.
fn claim_managed_listener(
    port: u16,
    expected_path: &Path,
    kind: ServiceKind,
    _pid_file: &Path,
) -> anyhow::Result<Option<u32>> {
    match listener_process_id(port, expected_path, kind) {
        Ok(value) => Ok(value),
        Err(error) if error.to_string().contains("ROUTER_INSTALL_ROOT_CONFLICT") => {
            let Some(occupant) = loopback_listener_pid(port)? else {
                return Err(error);
            };
            if process_path(occupant)
                .ok()
                .is_some_and(|path| same_service_image(&path, expected_path))
            {
                Ok(Some(occupant))
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn claim_managed_cli(
    port: u16,
    expected_cli: &Path,
    _expected_host: &Path,
    _host_pid_file: &Path,
) -> anyhow::Result<Option<u32>> {
    match listener_process_id(port, expected_cli, ServiceKind::CliProxyApi) {
        Ok(value) => Ok(value),
        Err(error) if error.to_string().contains("ROUTER_INSTALL_ROOT_CONFLICT") => {
            let Some(occupant) = loopback_listener_pid(port)? else {
                return Err(error);
            };
            let Ok(actual) = process_path(occupant) else {
                return Err(error);
            };
            if same_service_image(&actual, expected_cli) {
                Ok(Some(occupant))
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}
fn host_health(base_uri: &url::Url, timeout: Duration) -> bool {
    let mut health = base_uri.clone();
    health.set_path("/health");
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .and_then(|client| client.get(health).send())
        .is_ok_and(|response| response.status().is_success())
}

fn host_health_stable(base_uri: &url::Url) -> bool {
    for attempt in 0..3 {
        if host_health(base_uri, Duration::from_millis(1500)) {
            return true;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    false
}

fn cli_health(port: u16, timeout: Duration) -> bool {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .and_then(|client| {
            client
                .get(format!("http://127.0.0.1:{port}/healthz"))
                .send()
        })
        .is_ok_and(|response| response.status().is_success())
}

fn ensure_required_layout(router_root: &Path) -> anyhow::Result<()> {
    for relative in cli_compiler::required_runtime_relative_paths() {
        if !router_root.join(relative).is_file() {
            bail!("Portable runtime is incomplete; missing: {relative}");
        }
    }
    Ok(())
}

fn ensure_directories(router_root: &Path) -> anyhow::Result<()> {
    let data_root = user_data::data_root(router_root);
    for directory in [
        data_root.clone(),
        data_root.join("pids"),
        data_root.join("locks"),
        user_data::logs_root(router_root),
    ] {
        std::fs::create_dir_all(directory)?;
    }
    Ok(())
}

fn start_router_host(
    router_root: &Path,
    ports: LifecyclePorts,
    proxy_url: Option<&str>,
    desktop_auth_path: &Path,
) -> anyhow::Result<u32> {
    let data_root = user_data::data_root(router_root);
    let logs = user_data::logs_root(router_root);
    let stdout_path = logs.join("router-host-stdout.log");
    let stderr_path = logs.join("router-host-stderr.log");
    rotate_log(&stdout_path);
    rotate_log(&stderr_path);
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let executable = host_executable(router_root);
    let mut command = Command::new(&executable);
    command
        .arg(format!("--root={}", router_root.display()))
        .arg(format!("--host-port={}", ports.host))
        .arg(format!("--cli-port={}", ports.cli))
        .arg(format!("--desktop-auth={}", desktop_auth_path.display()))
        .current_dir(router_root.join("app"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    if let Some(proxy_url) = proxy_url.filter(|value| !value.trim().is_empty()) {
        command.env("CODEX_ROUTER_PROXY_URL", proxy_url);
    } else {
        command.env_remove("CODEX_ROUTER_PROXY_URL");
    }
    let child = command.spawn().context("could not start Router Host")?;
    let process_id = child.id();
    drop(child);
    config::atomic_write(
        &data_root.join("pids").join("router-host.pid"),
        process_id.to_string().as_bytes(),
    )?;
    Ok(process_id)
}

fn wait_host_ready(
    router_root: &Path,
    ports: LifecyclePorts,
    base_uri: &url::Url,
    process_id: u32,
    cancel: &AtomicBool,
) -> anyhow::Result<()> {
    let host_expected = host_executable(router_root);
    let cli_expected = cli_executable(router_root);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        if cancel.load(Ordering::Acquire) {
            bail!("Router startup was cancelled");
        }
        if !process_exists(process_id) {
            bail!("Router Host exited during startup");
        }
        if !host_health(base_uri, Duration::from_secs(3))
            || !cli_health(ports.cli, Duration::from_secs(2))
        {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        // A healthy answer can briefly win the race against the Windows TCP
        // owner table on a busy machine; treat a missing listener as "not
        // ready yet" instead of failing the whole startup. A listener owned
        // by a different process is a real conflict and stays a hard error.
        let host_listener =
            listener_process_id(ports.host, &host_expected, ServiceKind::RouterHost)?;
        let cli_listener = listener_process_id(ports.cli, &cli_expected, ServiceKind::CliProxyApi)?;
        let (Some(host_listener), Some(_)) = (host_listener, cli_listener) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        if host_listener != process_id {
            bail!("Router Host PID file and listener do not refer to the same process");
        }
        return Ok(());
    }
    bail!("Router Host or CLIProxyAPI did not become ready within 120 seconds")
}

fn inspect_existing_host(
    router_root: &Path,
    ports: LifecyclePorts,
    base_uri: &url::Url,
    repair: bool,
) -> anyhow::Result<Option<u32>> {
    let pid_file = host_pid_file(router_root);
    let expected = host_executable(router_root);
    let saved_raw = read_pid_file(&pid_file);
    let saved_process = saved_raw.filter(|&process_id| process_is_managed(process_id, &expected, &pid_file));
    if saved_raw.is_some() && saved_process.is_none() {
        let _ = std::fs::remove_file(&pid_file);
    }
    let listener = claim_managed_listener(
        ports.host,
        &expected,
        ServiceKind::RouterHost,
        &pid_file,
    )?;

    if let Some(process_id) = saved_process {
        match listener {
            Some(listener_id) if listener_id != process_id => {
                bail!("Router Host PID file and listener refer to different processes");
            }
            None if !repair => {
                bail!("ROUTER_LIFECYCLE_DEFERRED: Router Host PID {process_id} is running but its listener is temporarily unavailable. No Router service was changed.");
            }
            None => {
                terminate_managed_process(process_id, &expected, Some(&pid_file))?;
                let _ = std::fs::remove_file(&pid_file);
                return Ok(None);
            }
            Some(_) => {}
        }
    }

    let Some(process_id) = listener.or(saved_process) else {
        return Ok(None);
    };
    if saved_process.is_none() {
        config::atomic_write(&pid_file, process_id.to_string().as_bytes())?;
    }
    let same_install = process_path(process_id)
        .ok()
        .is_some_and(|path| paths_equal(&path, &expected));
    if repair && !same_install {
        // Predecessor from another portable that shares this UserData (upgrade).
        // Replace it with this install's host instead of hopping ports.
        terminate_managed_process(process_id, &expected, Some(&pid_file))?;
        let _ = std::fs::remove_file(&pid_file);
        return Ok(None);
    }
    if !host_health_stable(base_uri) {
        if !repair {
            bail!("ROUTER_LIFECYCLE_DEFERRED: Router Host PID {process_id} did not pass the bounded health observation. It was not terminated.");
        }
        terminate_managed_process(process_id, &expected, Some(&pid_file))?;
        let _ = std::fs::remove_file(&pid_file);
        return Ok(None);
    }
    // The host health contract already includes the CLI probe; verify the
    // private port ownership so a foreign CLIProxyAPI install cannot hide
    // behind a healthy host.
    claim_managed_cli(
        ports.cli,
        &cli_executable(router_root),
        &expected,
        &pid_file,
    )?
    .context("CLIProxyAPI is not listening on its expected private port")?;
    Ok(Some(process_id))
}

fn load_config(router_root: &Path) -> anyhow::Result<RouterConfig> {
    RouterConfig::load(&user_data::config_path(router_root))
        .context("could not load the applied Router configuration")
}
pub fn ensure_services(
    router_root: &Path,
    repair: bool,
    cancel: &AtomicBool,
    lock_inherited: bool,
) -> anyhow::Result<LifecycleStatus> {
    let mut config = load_config(router_root)?;
    // Self-heal the persisted ports before touching any process: when another
    // Router copy owns the configured port, move to a free port group and save
    // it so Status/Stop and the next launch agree with this start.
    if adopt_isolated_host_if_foreign(router_root, &mut config).is_some() {
        config
            .save(&user_data::config_path(router_root))
            .context("could not persist the adopted Router Host port")?;
    }
    ensure_services_with_config(router_root, &config, repair, cancel, lock_inherited)
}

pub fn ensure_services_with_config(
    router_root: &Path,
    config: &RouterConfig,
    repair: bool,
    cancel: &AtomicBool,
    lock_inherited: bool,
) -> anyhow::Result<LifecycleStatus> {
    let _lock = if lock_inherited {
        LifecycleLock::inherited()
    } else {
        acquire_lifecycle_lock(router_root, Duration::from_secs(10), "Start Router")?
    };
    let ports = LifecyclePorts::from_config(config)?;
    let base_uri = loopback_base_uri(&config.deploy.sub2api_host)?;
    let proxy_runtime = logic::resolve_proxy_runtime(config)?;
    if proxy_runtime.settings.has_credentials {
        bail!("ROUTER_PROXY_CREDENTIAL_STORAGE_UNSUPPORTED: authenticated proxy settings cannot be copied into CLIProxyAPI");
    }
    ensure_required_layout(router_root)?;
    ensure_directories(router_root)?;
    if cancel.load(Ordering::Acquire) {
        bail!("Router initialization was cancelled");
    }
    let existing = inspect_existing_host(router_root, ports, &base_uri, repair)?;
    sweep_stale_router_listeners(
        &host_executable(router_root),
        &cli_executable(router_root),
        ports.host,
        existing,
    )?;
    if existing.is_none() {
        let process_id = start_router_host(
            router_root,
            ports,
            proxy_runtime.settings.proxy_url.as_deref(),
            &logic::resolve_codex_home(config).join("auth.json"),
        )?;
        if let Err(error) = wait_host_ready(router_root, ports, &base_uri, process_id, cancel) {
            let expected = host_executable(router_root);
            let _ = terminate_verified_process(process_id, &expected);
            // The kill-on-close Job Object normally ends the CLI together
            // with the host; sweep the private port in case the assignment
            // failed on this machine.
            let cli_expected = cli_executable(router_root);
            if let Ok(Some(cli_pid)) =
                listener_process_id(ports.cli, &cli_expected, ServiceKind::CliProxyApi)
            {
                let _ = terminate_verified_process(cli_pid, &cli_expected);
            }
            let _ = std::fs::remove_file(
                user_data::data_root(router_root)
                    .join("pids")
                    .join("router-host.pid"),
            );
            return Err(error);
        }
    }
    logic::responses_gateway::set_gateway_log_path(
        user_data::logs_root(router_root).join("gateway-requests.jsonl"),
    );
    user_data::set_diagnostic_events_path(
        user_data::logs_root(router_root).join("router-events.jsonl"),
    );
    logic::responses_gateway::set_max_output_tokens_map(logic::max_output_tokens_map(config));
    logic::responses_gateway::set_context_budget_map(logic::context_budget_map(config));
    logic::responses_gateway::ensure_responses_gateway(
        base_uri.as_str(),
        config.rate_limit_max_retries,
    )
    .context("failed to start the responses compatibility gateway")?;
    status_services_with_config(router_root, config)
}

pub fn stop_services(
    router_root: &Path,
    force: bool,
    lock_inherited: bool,
) -> anyhow::Result<LifecycleStatus> {
    let config = load_config(router_root).unwrap_or_default();
    stop_services_with_config(router_root, &config, force, lock_inherited)
}

pub fn stop_services_with_config(
    router_root: &Path,
    config: &RouterConfig,
    force: bool,
    lock_inherited: bool,
) -> anyhow::Result<LifecycleStatus> {
    let _lock = if lock_inherited {
        LifecycleLock::inherited()
    } else {
        acquire_lifecycle_lock(
            router_root,
            if force {
                Duration::from_millis(1500)
            } else {
                Duration::from_secs(10)
            },
            "Stop Router",
        )?
    };
    logic::responses_gateway::stop_responses_gateway()
        .context("failed to stop the responses compatibility gateway")?;
    let ports = LifecyclePorts::from_config(config)?;
    let data_root = user_data::data_root(router_root);
    let host_path = host_executable(router_root);
    let pid_file = host_pid_file(router_root);
    let saved_host = read_pid_file(&pid_file)
        .filter(|process_id| process_is_managed(*process_id, &host_path, &pid_file));
    // A listener owned by another Router installation or program is not ours
    // to stop; treat the port as foreign-owned and leave it running. A
    // predecessor portable that still owns this UserData PID is ours.
    let listening_host = match claim_managed_listener(
        ports.host,
        &host_path,
        ServiceKind::RouterHost,
        &pid_file,
    ) {
        Ok(value) => value,
        Err(error) if is_port_conflict_error(&error) => None,
        Err(error) => return Err(error),
    };
    if saved_host.is_some()
        && listening_host.is_some()
        && saved_host != listening_host
    {
        bail!("Router Host PID file and listener refer to different processes");
    }
    let cli_path = cli_executable(router_root);
    let listening_cli = match claim_managed_cli(ports.cli, &cli_path, &host_path, &pid_file) {
        Ok(value) => value,
        Err(error) if is_port_conflict_error(&error) => None,
        Err(error) => return Err(error),
    };
    if let Some(process_id) = saved_host.or(listening_host) {
        if !force {
            assert_interruption_allowed(process_id, ports.host, "Stop Router")?;
        }
        terminate_managed_process(process_id, &host_path, Some(&pid_file))?;
    }
    // The CLI is bound to the host through a kill-on-close Job Object and
    // normally dies with it; sweep the private port anyway in case the job
    // assignment failed or an older build left an orphan behind.
    if let Some(captured_process_id) = listening_cli {
        match claim_managed_cli(ports.cli, &cli_path, &host_path, &pid_file) {
            Ok(Some(current_process_id)) if current_process_id == captured_process_id => {
                terminate_same_image_process(current_process_id, &cli_path)?;
            }
            Ok(Some(_)) => bail!("CLIProxyAPI listener owner changed during shutdown"),
            Ok(None) => {}
            Err(error) if is_port_conflict_error(&error) => {}
            Err(error) => return Err(error),
        }
    }
    sweep_stale_router_listeners(&host_path, &cli_path, ports.host, None)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        let status = status_services_with_config(router_root, config)?;
        let host_alive = saved_host.is_some_and(process_exists);
        if !host_alive && status.services.iter().all(|service| !service.running) {
            break status;
        }
        if Instant::now() >= deadline {
            bail!("ROUTER_SHUTDOWN_INCOMPLETE: managed processes or listeners are still active");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = std::fs::remove_file(pid_file);
    // Drop stale pre-2.0 bookkeeping left behind by an upgraded installation.
    let _ = std::fs::remove_file(data_root.join("pids").join("sub2api.pid"));
    let _ = std::fs::remove_file(data_root.join("pids").join("sub2api-network.hmac"));
    Ok(status)
}

pub fn status_services(router_root: &Path) -> anyhow::Result<LifecycleStatus> {
    let config = load_config(router_root).unwrap_or_default();
    status_services_with_config(router_root, &config)
}

fn status_services_with_config(
    router_root: &Path,
    config: &RouterConfig,
) -> anyhow::Result<LifecycleStatus> {
    let ports = LifecyclePorts::from_config(config)?;
    let base_uri = loopback_base_uri(&config.deploy.sub2api_host)?;
    // Status answers "are *this* installation's services up". A port owned by
    // another Router copy or program therefore reads as not running here.
    let host = owned_listener_or_none(
        ports.host,
        &host_executable(router_root),
        ServiceKind::RouterHost,
    )?;
    let cli = owned_listener_or_none(
        ports.cli,
        &cli_executable(router_root),
        ServiceKind::CliProxyApi,
    )?;
    Ok(LifecycleStatus {
        services: vec![
            ServiceStatus {
                component: "Router Host".to_owned(),
                endpoint: base_uri.as_str().trim_end_matches('/').to_owned(),
                running: host.is_some(),
                ready: host.is_some() && host_health(&base_uri, Duration::from_secs(4)),
                process_id: host,
            },
            ServiceStatus {
                component: "CLIProxyAPI".to_owned(),
                endpoint: format!("http://127.0.0.1:{}", ports.cli),
                running: cli.is_some(),
                ready: cli.is_some() && cli_health(ports.cli, Duration::from_secs(3)),
                process_id: cli,
            },
        ],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    #[cfg(windows)]
    use std::net::TcpStream;
    use std::sync::{Mutex, OnceLock};

    fn port_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(windows)]
    fn wait_for_test_listener(port: u16) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if loopback_listener_pid(port).ok().flatten() == Some(std::process::id()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "test listener on port {port} never reached the Windows TCP owner table"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codex-router-native-lifecycle-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn lifecycle_lock_excludes_a_second_owner() {
        let root = temporary_root("lock");
        let first = acquire_lifecycle_lock(&root, Duration::from_millis(100), "first").unwrap();
        let error = acquire_lifecycle_lock(&root, Duration::from_millis(150), "second")
            .unwrap_err()
            .to_string();
        assert!(error.contains("ROUTER_LIFECYCLE_BUSY"));
        drop(first);
        acquire_lifecycle_lock(&root, Duration::from_secs(1), "third").unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_tcp_table_finds_this_process_listener_and_active_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (server, _) = listener.accept().unwrap();
        let expected = std::env::current_exe().unwrap();
        let process_id = listener_process_id(port, &expected, ServiceKind::RouterHost)
            .unwrap()
            .unwrap();
        assert_eq!(process_id, std::process::id());
        let started = Instant::now();
        let count = loop {
            let count = established_connection_count(process_id, port).unwrap();
            if count > 0 || started.elapsed() >= Duration::from_secs(2) {
                break count;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(count > 0);
        drop(server);
        drop(client);
    }

    #[test]
    fn lifecycle_ports_follow_the_configured_host_port() {
        let mut config = RouterConfig::default();
        config.deploy.sub2api_host = "http://127.0.0.1:19090".to_owned();
        let ports = LifecyclePorts::from_config(&config).unwrap();
        assert_eq!(ports.host, 19_090);
        if std::env::var_os("CODEX_ROUTER_CLI_PORT").is_none() {
            // An adopted host port drags the private CLI port along so two
            // installations never share 18081.
            assert_eq!(ports.cli, 19_091);
        }
        config.deploy.sub2api_host = "http://0.0.0.0:8080".to_owned();
        assert!(LifecyclePorts::from_config(&config).is_err());
    }

    fn find_free_port_triple() -> u16 {
        for _ in 0..64 {
            let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            if !(1024..=65_532).contains(&port) {
                continue;
            }
            let next_free = TcpListener::bind((Ipv4Addr::LOCALHOST, port + 1)).is_ok();
            let gateway_free = TcpListener::bind((Ipv4Addr::LOCALHOST, port + 2)).is_ok();
            if next_free && gateway_free {
                return port;
            }
        }
        panic!("could not find three consecutive free loopback ports");
    }

    #[test]
    fn adopt_leaves_a_free_configured_port_alone() {
        let _guard = port_test_lock();
        let root = temporary_root("adopt-free");
        let port = find_free_port_triple();
        let mut config = RouterConfig::default();
        config.deploy.sub2api_host = format!("http://127.0.0.1:{port}");
        assert!(adopt_isolated_host_if_foreign(&root, &mut config).is_none());
        assert_eq!(
            config.deploy.sub2api_host,
            format!("http://127.0.0.1:{port}")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn adopt_scans_past_ports_owned_by_other_processes() {
        let _guard = port_test_lock();
        let root = temporary_root("adopt-scan");
        // The configured port and the first candidate are both owned by this
        // test process, which is foreign to the expected Router Host binary.
        let configured = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let configured_port = configured.local_addr().unwrap().port();
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        wait_for_test_listener(configured_port);
        wait_for_test_listener(busy_port);
        let free_triple = find_free_port_triple();
        let mut config = RouterConfig::default();
        config.deploy.sub2api_host = format!("http://127.0.0.1:{configured_port}");

        let adopted = adopt_isolated_host_if_foreign_with_candidates(
            &root,
            &mut config,
            &[busy_port, free_triple],
        );
        assert_eq!(
            adopted,
            Some(format!("http://127.0.0.1:{free_triple}")),
            "adoption must skip the busy candidate and keep a fully free port group"
        );
        assert_eq!(
            config.deploy.sub2api_host,
            format!("http://127.0.0.1:{free_triple}")
        );
        drop(configured);
        drop(busy);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn adopt_moves_when_only_the_derived_cli_port_is_foreign() {
        let _guard = port_test_lock();
        let root = temporary_root("adopt-cli-conflict");
        let configured = find_free_port_triple();
        let cli = TcpListener::bind((Ipv4Addr::LOCALHOST, configured + 1)).unwrap();
        wait_for_test_listener(configured + 1);
        let replacement = find_free_port_triple();
        let mut config = RouterConfig::default();
        config.deploy.sub2api_host = format!("http://127.0.0.1:{configured}");

        let adopted = adopt_isolated_host_if_foreign_with_candidates(
            &root,
            &mut config,
            &[replacement],
        );
        assert_eq!(
            adopted,
            Some(format!("http://127.0.0.1:{replacement}"))
        );
        drop(cli);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn same_service_image_matches_filename_across_install_roots() {
        // Forward slashes parse as separators on every platform, so this
        // verifies the filename comparison on Windows and macOS alike.
        assert!(same_service_image(
            Path::new("D:/Work/CodexRouter/Release/3.0.17/app/codex-router-host.exe"),
            Path::new("D:/Work/CodexRouter/Release/3.0.18/app/codex-router-host.exe"),
        ));
        assert!(!same_service_image(
            Path::new("D:/Work/CodexRouter/Release/3.0.17/app/codex-router-host.exe"),
            Path::new("D:/Work/CodexRouter/Release/3.0.18/app/cli-proxy-api.exe"),
        ));
        let ports = router_host_port_candidates(28_080);
        assert!(ports.contains(&18_080));
        assert!(ports.contains(&28_080));
        assert!(ports.contains(&28_083));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_process_primitives_see_this_process_and_reaped_children() {
        assert!(process_exists(std::process::id()));
        assert!(!process_exists(0));
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_exists(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!process_exists(pid));
        assert!(process_path(std::process::id())
            .unwrap()
            .file_name()
            .is_some());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_terminate_managed_process_stops_a_matching_sleep() {
        let mut child = std::process::Command::new("sleep")
            .arg("120")
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(process_exists(pid));
        let expected = PathBuf::from("sleep");
        assert!(process_is_managed(pid, &expected, Path::new("")));
        terminate_managed_process(pid, &expected, None).unwrap();
        assert!(!process_exists(pid));
        let _ = child.wait();
        // launchd is never our image: refusal must come before any signal.
        assert!(terminate_managed_process(1, &expected, None).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_listener_lookup_resolves_this_process_listener() {
        let _guard = port_test_lock();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            loopback_listener_pid(port).unwrap(),
            Some(std::process::id())
        );
        let expected = std::env::current_exe().unwrap();
        match listener_process_id(port, &expected, ServiceKind::RouterHost) {
            Ok(owner) => assert_eq!(owner, Some(std::process::id())),
            // Acceptable when the test harness invokes the binary through a
            // bare name: ownership still resolved, only exact-path equality
            // could not be proven from argv[0].
            Err(error) => assert!(
                error.to_string().contains("ROUTER_INSTALL_ROOT_CONFLICT"),
                "{error}"
            ),
        }
        drop(listener);
        assert_eq!(loopback_listener_pid(port).unwrap(), None);
    }

    #[test]
    fn required_layout_matches_current_platform() {
        let root = temporary_root("layout");
        // Empty tree is incomplete on every platform.
        assert!(ensure_required_layout(&root).is_err());
        assert!(!RouterConfig::is_router_root(&root));
        for relative in cli_compiler::required_runtime_relative_paths() {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"stub").unwrap();
        }
        assert!(ensure_required_layout(&root).is_ok());
        assert!(RouterConfig::is_router_root(&root));
        assert!(host_executable(&root).is_file());
        assert!(cli_executable(&root).is_file());
        assert_eq!(
            host_pid_file(&root),
            user_data::data_root(&root)
                .join("pids")
                .join("router-host.pid")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn userdata_predecessor_requires_matching_pid_file() {
        let root = temporary_root("predecessor-pid");
        let pid_file = root.join("router-host.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        assert_eq!(read_pid_file(&pid_file), Some(4242));
        assert!(!process_is_managed(
            1,
            Path::new(r"D:\app\codex-router-host.exe"),
            &pid_file
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
