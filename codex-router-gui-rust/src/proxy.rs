use crate::config::ProxyConfig;
use anyhow::{bail, Context};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use url::Url;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{GlobalFree, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpGetDefaultProxyConfiguration, WinHttpGetIEProxyConfigForCurrentUser,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};
use zeroize::Zeroize;

#[cfg(windows)]
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const REQUIRED_NO_PROXY: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

#[derive(Default)]
struct InternetSettings {
    proxy_enabled: bool,
    proxy_server: String,
    proxy_override: String,
}

#[derive(Default)]
struct WinHttpSettings {
    proxy: String,
    bypass: String,
}

#[derive(Default)]
struct ProxySources {
    environment: BTreeMap<String, String>,
    internet: Option<InternetSettings>,
    current_user: Option<WinHttpSettings>,
    machine: Option<WinHttpSettings>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProxySettings {
    pub mode: String,
    pub source: String,
    pub proxy_url: Option<String>,
    pub no_proxy: String,
    pub has_credentials: bool,
    pub supports_account_binding: bool,
    pub diagnostic: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyTargetPolicy {
    pub bypass: bool,
    pub direct_fallback: bool,
}

pub struct ProxyRuntime {
    pub settings: ProxySettings,
    pub targets: BTreeMap<String, ProxyTargetPolicy>,
}

impl std::fmt::Debug for ProxySettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxySettings")
            .field("mode", &self.mode)
            .field("source", &self.source)
            .field("proxy_url", &self.proxy_url.as_ref().map(|_| "<REDACTED>"))
            .field("no_proxy", &self.no_proxy)
            .field("has_credentials", &self.has_credentials)
            .field("supports_account_binding", &self.supports_account_binding)
            .field("diagnostic", &self.diagnostic)
            .finish()
    }
}

impl Drop for ProxySettings {
    fn drop(&mut self) {
        if let Some(value) = &mut self.proxy_url {
            value.zeroize();
        }
    }
}

#[derive(Default)]
struct ProxyServerCandidates {
    http: Option<String>,
    https: Option<String>,
    all: Option<String>,
}

fn normalize_proxy_url(value: &str, default_scheme: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("proxy URL is empty or contains a line break");
    }
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("{default_scheme}://{value}")
    };
    let url = Url::parse(&candidate).context("proxy URL is invalid")?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host_str().is_none_or(str::is_empty)
        || url.port_or_known_default().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("proxy URL has an unsupported scheme, authority, or path");
    }
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn valid_no_proxy_entry(value: &str) -> bool {
    let (host, prefix) = value
        .rsplit_once('/')
        .map_or((value, None), |(host, prefix)| (host, Some(prefix)));
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._*:[]-".contains(c))
    {
        return false;
    }
    prefix.is_none_or(|value| {
        !value.is_empty() && value.len() <= 3 && value.chars().all(|c| c.is_ascii_digit())
    })
}

pub fn merge_no_proxy<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let mut entries = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();
    for required in REQUIRED_NO_PROXY {
        seen.insert(required.to_owned());
        entries.push(required.to_owned());
    }
    for value in values {
        for raw in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let mut entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(without_star) = entry.strip_prefix("*.") {
                entry = &raw[1..];
                debug_assert_eq!(entry, format!(".{without_star}"));
            }
            if entry != "<local>" && entry != "*" && !valid_no_proxy_entry(entry) {
                continue;
            }
            let identity = entry.to_ascii_lowercase();
            if seen.insert(identity) {
                entries.push(entry.to_owned());
            }
        }
    }
    entries.join(",")
}

fn ip_in_cidr(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(address) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(address) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let expression = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
    regex::RegexBuilder::new(&expression)
        .case_insensitive(true)
        .build()
        .is_ok_and(|regex| regex.is_match(value))
}

pub fn proxy_bypasses(target_uri: &str, no_proxy: &str) -> bool {
    let Ok(uri) = Url::parse(target_uri) else {
        return false;
    };
    let Some(host) = uri.host_str() else {
        return false;
    };
    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let target_address = host.parse::<IpAddr>().ok();
    if host == "localhost" || target_address.is_some_and(|address| address.is_loopback()) {
        return true;
    }
    let target_port = uri.port_or_known_default();

    for raw in no_proxy.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let mut candidate = raw.trim();
        if candidate.is_empty() {
            continue;
        }
        if candidate == "*" {
            return true;
        }
        if candidate.eq_ignore_ascii_case("<local>") {
            if target_address.is_none() && !host.contains('.') {
                return true;
            }
            continue;
        }
        if let Some((network, prefix)) = candidate.rsplit_once('/') {
            if let (Some(address), Ok(network), Ok(prefix)) = (
                target_address,
                network.trim_matches(['[', ']']).parse::<IpAddr>(),
                prefix.parse::<u8>(),
            ) {
                if ip_in_cidr(address, network, prefix) {
                    return true;
                }
            }
            continue;
        }

        if candidate.starts_with('[') {
            if let Some(end) = candidate.find(']') {
                candidate = &candidate[1..end];
            }
        } else if candidate.matches(':').count() == 1 {
            let (name, port) = candidate.split_once(':').unwrap_or_default();
            if let Ok(port) = port.parse::<u16>() {
                if target_port != Some(port) {
                    continue;
                }
                candidate = name;
            }
        }
        let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
        let candidate = candidate
            .strip_prefix("*.")
            .map(|value| format!(".{value}"))
            .unwrap_or(candidate);
        if let Some(suffix) = candidate.strip_prefix('.') {
            if host == suffix || host.ends_with(&candidate) {
                return true;
            }
        } else if candidate.contains('*') {
            if wildcard_matches(&candidate, &host) {
                return true;
            }
        } else if host == candidate.trim_matches(['[', ']']) {
            return true;
        }
    }
    false
}

pub fn is_loopback_proxy(proxy_url: Option<&str>) -> bool {
    let Some(proxy_url) = proxy_url else {
        return false;
    };
    let Ok(url) = Url::parse(proxy_url) else {
        return false;
    };
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

pub fn direct_target_reachable(target_uri: &str, timeout: Duration) -> bool {
    let Ok(mut probe) = Url::parse(target_uri) else {
        return false;
    };
    if !matches!(probe.scheme(), "http" | "https") {
        return false;
    }
    let path = format!("{}/models", probe.path().trim_end_matches('/'));
    probe.set_path(&path);
    probe.set_query(None);
    probe.set_fragment(None);
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .and_then(|client| client.get(probe).send())
        .is_ok()
}

pub fn direct_fallback_eligible(
    settings: &ProxySettings,
    target_uri: &str,
    direct_reachable: bool,
) -> bool {
    settings.mode == "proxy"
        && direct_reachable
        && settings.source != "explicit"
        && is_loopback_proxy(settings.proxy_url.as_deref())
        && !proxy_bypasses(target_uri, &settings.no_proxy)
}

pub fn evaluate_targets<'a>(
    settings: &ProxySettings,
    targets: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, ProxyTargetPolicy> {
    let mut policies = BTreeMap::new();
    for target in targets {
        let target = target.trim().trim_end_matches('/');
        if target.is_empty() || policies.contains_key(target) {
            continue;
        }
        let bypass = proxy_bypasses(target, &settings.no_proxy);
        let direct_reachable = settings.mode == "proxy"
            && !bypass
            && direct_target_reachable(target, Duration::from_secs(3));
        policies.insert(
            target.to_owned(),
            ProxyTargetPolicy {
                bypass,
                direct_fallback: direct_fallback_eligible(settings, target, direct_reachable),
            },
        );
    }
    policies
}

fn parse_proxy_server(value: &str) -> ProxyServerCandidates {
    let value = value.trim();
    if value.is_empty() {
        return ProxyServerCandidates::default();
    }
    if !value.contains('=') {
        let all = normalize_proxy_url(value, "http").ok();
        return ProxyServerCandidates {
            http: all.clone(),
            https: all.clone(),
            all,
        };
    }
    let mut mapping = BTreeMap::<String, String>::new();
    for part in value.split(';') {
        if let Some((name, value)) = part.split_once('=') {
            if !value.trim().is_empty() {
                mapping.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }
    }
    let http = mapping
        .get("http")
        .and_then(|value| normalize_proxy_url(value, "http").ok());
    let https = mapping
        .get("https")
        .and_then(|value| normalize_proxy_url(value, "http").ok());
    let all = mapping
        .get("socks5")
        .or_else(|| mapping.get("socks"))
        .and_then(|value| normalize_proxy_url(value, "socks5").ok());
    ProxyServerCandidates { http, https, all }
}

fn preferred_candidate(candidates: ProxyServerCandidates) -> Option<String> {
    candidates.https.or(candidates.all).or(candidates.http)
}

/// User-visible source label for the OS-level (non-environment) proxy slot:
/// Windows registry/WinHTTP vs macOS SystemConfiguration.
fn system_proxy_source_label() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "system"
    }
}

fn resolve(
    config: &ProxyConfig,
    password: Option<&str>,
    sources: &ProxySources,
) -> anyhow::Result<ProxySettings> {
    let mut bypass = Vec::<String>::new();
    for name in ["NO_PROXY", "no_proxy"] {
        if let Some(value) = sources
            .environment
            .get(name)
            .filter(|value| !value.trim().is_empty())
        {
            bypass.push(value.clone());
        }
    }
    let mut proxy_url = None;
    let mut source = "direct".to_owned();
    if config.enabled {
        let scheme = config.proxy_type.trim().to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "socks5" | "socks5h") {
            bail!("unsupported proxy type");
        }
        let host = config
            .host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = config.port.trim().parse::<u16>().ok();
        if host.is_empty()
            || port.is_none_or(|value| value == 0)
            || host.contains(['\r', '\n', '/', '@'])
        {
            bail!("proxy host or port is invalid");
        }
        let authority_host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let mut url = Url::parse(&format!("{scheme}://{authority_host}:{}", port.unwrap()))?;
        if !config.username.trim().is_empty() {
            url.set_username(config.username.trim())
                .map_err(|_| anyhow::anyhow!("proxy username is invalid"))?;
            url.set_password(Some(password.unwrap_or_default()))
                .map_err(|_| anyhow::anyhow!("proxy password is invalid"))?;
        }
        proxy_url = Some(normalize_proxy_url(url.as_str(), &scheme)?);
        source = "explicit".to_owned();
    } else if config.auto_detect {
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            if let Some(candidate) = sources.environment.get(name) {
                if let Ok(value) = normalize_proxy_url(candidate, "http") {
                    proxy_url = Some(value);
                    source = "environment".to_owned();
                    break;
                }
            }
        }
        if proxy_url.is_none() {
            if let Some(settings) = &sources.internet {
                if settings.proxy_enabled {
                    proxy_url = preferred_candidate(parse_proxy_server(&settings.proxy_server));
                    if proxy_url.is_some() {
                        source = system_proxy_source_label().to_owned();
                        bypass.push(settings.proxy_override.clone());
                    }
                }
            }
        }
        if proxy_url.is_none() {
            if let Some(settings) = &sources.current_user {
                proxy_url = preferred_candidate(parse_proxy_server(&settings.proxy));
                if proxy_url.is_some() {
                    source = "windows-user".to_owned();
                    bypass.push(settings.bypass.clone());
                }
            }
        }
        if proxy_url.is_none() {
            if let Some(settings) = &sources.machine {
                proxy_url = preferred_candidate(parse_proxy_server(&settings.proxy));
                if proxy_url.is_some() {
                    source = "winhttp-machine".to_owned();
                    bypass.push(settings.bypass.clone());
                }
            }
        }
    }
    let has_credentials = proxy_url
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .is_some_and(|url| !url.username().is_empty() || url.password().is_some());
    Ok(ProxySettings {
        mode: if proxy_url.is_some() {
            "proxy"
        } else {
            "direct"
        }
        .to_owned(),
        source,
        no_proxy: merge_no_proxy(bypass.iter().map(String::as_str)),
        supports_account_binding: proxy_url.is_some() && !has_credentials,
        has_credentials,
        proxy_url,
        diagnostic: String::new(),
    })
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(windows)]
fn registry_dword(name: &str) -> Option<u32> {
    let subkey = wide(INTERNET_SETTINGS);
    let name = wide(name);
    let mut value = 0u32;
    let mut bytes = std::mem::size_of::<u32>() as u32;
    (unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut bytes,
        )
    } == ERROR_SUCCESS)
        .then_some(value)
}

#[cfg(windows)]
fn registry_string(name: &str) -> Option<String> {
    let subkey = wide(INTERNET_SETTINGS);
    let name = wide(name);
    let mut bytes = 0u32;
    if unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    } != ERROR_SUCCESS
        || bytes < 2
    {
        return None;
    }
    let mut buffer = vec![0u16; bytes.div_ceil(2) as usize];
    if unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).ok()
}

#[cfg(windows)]
unsafe fn take_global_string(pointer: *mut u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) });
    unsafe { GlobalFree(pointer.cast()) };
    value
}

#[cfg(windows)]
fn current_user_winhttp() -> Option<WinHttpSettings> {
    let mut settings = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut settings) } == 0 {
        return None;
    }
    let proxy = unsafe { take_global_string(settings.lpszProxy) };
    let bypass = unsafe { take_global_string(settings.lpszProxyBypass) };
    let _ = unsafe { take_global_string(settings.lpszAutoConfigUrl) };
    Some(WinHttpSettings { proxy, bypass })
}

#[cfg(windows)]
fn machine_winhttp() -> Option<WinHttpSettings> {
    let mut settings = WINHTTP_PROXY_INFO::default();
    if unsafe { WinHttpGetDefaultProxyConfiguration(&mut settings) } == 0 {
        return None;
    }
    Some(WinHttpSettings {
        proxy: unsafe { take_global_string(settings.lpszProxy) },
        bypass: unsafe { take_global_string(settings.lpszProxyBypass) },
    })
}

#[cfg(target_os = "macos")]
fn macos_system_proxy() -> Option<InternetSettings> {
    let output = std::process::Command::new("scutil")
        .args(["--proxy"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_scutil_proxy(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse `scutil --proxy` plist-style output into the shared
/// `InternetSettings` shape (enabled flag, `proto=host:port` server list,
/// `;`-joined bypass list). Pure function so it is unit-testable without
/// touching the system configuration.
#[cfg(target_os = "macos")]
fn parse_scutil_proxy(text: &str) -> InternetSettings {
    fn push_exception(out: &mut Vec<String>, raw: &str) {
        // Item forms: `*.local`, `0 : 127.0.0.1`, `<local>`.
        let item = raw.trim();
        let item = match item.split_once(':') {
            Some((index, pattern))
                if index.trim().chars().all(|c| c.is_ascii_digit()) =>
            {
                pattern.trim()
            }
            _ => item,
        };
        if !item.is_empty() && item != "<array>" && item != "{" && item != "}" {
            out.push(item.to_owned());
        }
    }

    let mut values = std::collections::BTreeMap::<String, String>::new();
    let mut exceptions = Vec::<String>::new();
    let mut in_exceptions = false;
    for line in text.lines() {
        let line = line.trim();
        if in_exceptions {
            if line.starts_with('}') {
                in_exceptions = false;
                continue;
            }
            for item in line.split(',') {
                push_exception(&mut exceptions, item);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("ExceptionsList") {
            in_exceptions = true;
            // Same-line items, if any: `... { 0 : *.local, ... }`.
            if let Some((_, tail)) = rest.split_once('{') {
                for item in tail.split([',', '}']) {
                    push_exception(&mut exceptions, item);
                }
                if rest.contains('}') {
                    in_exceptions = false;
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        values.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    let flag = |key: &str| values.get(key).is_some_and(|v| v == "1");
    let endpoint = |proto: &str| {
        let (host_key, port_key) = match proto {
            "http" => ("HTTPProxy", "HTTPPort"),
            "https" => ("HTTPSProxy", "HTTPSPort"),
            "socks" => ("SOCKSProxy", "SOCKSPort"),
            _ => return None,
        };
        let host = values.get(host_key)?.trim();
        let port = values.get(port_key)?.trim().parse::<u16>().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        Some(format!("{proto}={host}:{port}"))
    };
    let mut servers = Vec::new();
    for proto in ["http", "https", "socks"] {
        let enabled = match proto {
            "http" => flag("HTTPEnable"),
            "https" => flag("HTTPSEnable"),
            _ => flag("SOCKSEnable"),
        };
        if enabled {
            servers.extend(endpoint(proto));
        }
    }
    InternetSettings {
        proxy_enabled: !servers.is_empty(),
        proxy_server: servers.join(";"),
        proxy_override: exceptions.join(";"),
    }
}

fn current_sources() -> ProxySources {
    let mut environment = BTreeMap::new();
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.to_owned(), value);
        }
    }
    #[cfg(windows)]
    let (internet, current_user, machine) = (
        Some(InternetSettings {
            proxy_enabled: registry_dword("ProxyEnable") == Some(1),
            proxy_server: registry_string("ProxyServer").unwrap_or_default(),
            proxy_override: registry_string("ProxyOverride").unwrap_or_default(),
        }),
        current_user_winhttp(),
        machine_winhttp(),
    );
    #[cfg(target_os = "macos")]
    let (internet, current_user, machine) = (macos_system_proxy(), None, None);
    #[cfg(not(any(windows, target_os = "macos")))]
    let (internet, current_user, machine) = (None, None, None);
    ProxySources {
        environment,
        internet,
        current_user,
        machine,
    }
}

pub fn resolve_current(
    config: &ProxyConfig,
    password: Option<&str>,
) -> anyhow::Result<ProxySettings> {
    resolve(config, password, &current_sources())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auto_config() -> ProxyConfig {
        ProxyConfig {
            auto_detect: true,
            enabled: false,
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn explicit_proxy_takes_precedence_and_supports_ipv6_credentials() {
        let config = ProxyConfig {
            enabled: true,
            auto_detect: true,
            proxy_type: "socks5h".into(),
            host: "::1".into(),
            port: "1080".into(),
            username: "test-user".into(),
            ..ProxyConfig::default()
        };
        let mut sources = ProxySources::default();
        sources
            .environment
            .insert("HTTPS_PROXY".into(), "http://127.0.0.1:9080".into());
        let settings = resolve(&config, Some("test-password"), &sources).unwrap();
        let url = Url::parse(settings.proxy_url.as_deref().unwrap()).unwrap();
        assert_eq!(settings.source, "explicit");
        assert_eq!(url.scheme(), "socks5h");
        assert_eq!(url.host_str(), Some("[::1]").or(Some("::1")));
        assert_eq!(url.port(), Some(1080));
        assert_eq!(url.username(), "test-user");
        assert!(settings.has_credentials);
    }

    #[test]
    fn discovery_precedence_matches_environment_windows_user_and_machine_sources() {
        let mut sources = ProxySources::default();
        sources
            .environment
            .insert("HTTPS_PROXY".into(), "http://127.0.0.1:2080".into());
        sources
            .environment
            .insert("NO_PROXY".into(), ".example.cn".into());
        sources.internet = Some(InternetSettings {
            proxy_enabled: true,
            proxy_server: "http=127.0.0.1:3080;https=127.0.0.1:3081;socks=127.0.0.1:1080".into(),
            proxy_override: "*.cn;<local>;10.0.0.0/8".into(),
        });
        let environment = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(environment.source, "environment");
        assert_eq!(
            environment.proxy_url.as_deref(),
            Some("http://127.0.0.1:2080")
        );
        assert!(environment.no_proxy.contains(".example.cn"));

        sources.environment.clear();
        let windows = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(windows.source, system_proxy_source_label());
        assert_eq!(windows.proxy_url.as_deref(), Some("http://127.0.0.1:3081"));
        assert!(windows.no_proxy.contains(".cn"));
        assert!(windows.no_proxy.contains("10.0.0.0/8"));

        sources.internet = Some(InternetSettings::default());
        sources.current_user = Some(WinHttpSettings {
            proxy: "http=127.0.0.1:6080;https=127.0.0.1:6081".into(),
            bypass: "*.internal.test;<local>".into(),
        });
        sources.machine = Some(WinHttpSettings {
            proxy: "127.0.0.1:7080".into(),
            bypass: "build.internal".into(),
        });
        let current_user = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(current_user.source, "windows-user");
        assert_eq!(
            current_user.proxy_url.as_deref(),
            Some("http://127.0.0.1:6081")
        );
        assert!(current_user.no_proxy.contains(".internal.test"));

        sources.current_user = Some(WinHttpSettings::default());
        let machine = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(machine.source, "winhttp-machine");
        assert_eq!(machine.proxy_url.as_deref(), Some("http://127.0.0.1:7080"));
        assert!(machine.no_proxy.contains("build.internal"));
    }

    #[test]
    fn direct_mode_ignores_detected_proxies_and_keeps_loopback_bypass() {
        let config = ProxyConfig {
            auto_detect: false,
            enabled: false,
            ..ProxyConfig::default()
        };
        let mut sources = ProxySources::default();
        sources
            .environment
            .insert("HTTPS_PROXY".into(), "http://127.0.0.1:4080".into());
        let settings = resolve(&config, None, &sources).unwrap();
        assert_eq!(settings.mode, "direct");
        assert!(settings.proxy_url.is_none());
        for required in REQUIRED_NO_PROXY {
            assert!(settings.no_proxy.split(',').any(|entry| entry == required));
        }
    }

    #[test]
    fn invalid_environment_proxy_falls_back_to_system_slot() {
        let mut sources = ProxySources::default();
        sources
            .environment
            .insert("HTTPS_PROXY".into(), "not a proxy URL".into());
        sources.internet = Some(InternetSettings {
            proxy_enabled: true,
            proxy_server: "127.0.0.1:5080".into(),
            proxy_override: String::new(),
        });
        let settings = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(settings.source, system_proxy_source_label());
        assert_eq!(settings.proxy_url.as_deref(), Some("http://127.0.0.1:5080"));
    }

    #[test]
    fn system_slot_uses_the_platform_source_label() {
        let mut sources = ProxySources::default();
        sources.internet = Some(InternetSettings {
            proxy_enabled: true,
            proxy_server: "https=127.0.0.1:8081".into(),
            proxy_override: "*.example".into(),
        });
        let settings = resolve(&auto_config(), None, &sources).unwrap();
        assert_eq!(settings.source, system_proxy_source_label());
        assert_eq!(
            settings.proxy_url.as_deref(),
            Some("http://127.0.0.1:8081")
        );
        assert!(settings.no_proxy.contains(".example"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scutil_proxy_parses_endpoints_and_bypass_list() {
        // Multi-line form as printed by the real `scutil --proxy`.
        let text = "<dictionary> {
  ExceptionsList : <array> {
    0 : 127.0.0.1
    1 : 10.0.0.0/8
    2 : *.example.com
    3 : <local>
  }
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 0
  SOCKSPort : 0
}";
        let settings = parse_scutil_proxy(text);
        assert!(settings.proxy_enabled);
        assert_eq!(
            preferred_candidate(parse_proxy_server(&settings.proxy_server)).as_deref(),
            Some("http://127.0.0.1:7890")
        );
        assert!(settings.proxy_override.contains("*.example.com"));
        assert!(settings.proxy_override.contains("10.0.0.0/8"));
        assert!(settings.proxy_override.contains("<local>"));

        let disabled = parse_scutil_proxy("<dictionary> {\n  HTTPEnable : 0\n}");
        assert!(!disabled.proxy_enabled);
        assert!(disabled.proxy_server.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scutil_proxy_live_query_runs_without_panicking() {
        // Values depend on the machine; this only pins the wiring.
        let _ = macos_system_proxy();
        let _ = resolve_current(&auto_config(), None).map(|settings| settings.mode.clone());
    }

    #[test]
    fn bypass_supports_loopback_domains_cidr_ports_and_local_names() {
        assert!(proxy_bypasses("http://127.0.0.1:18080/v1", ""));
        assert!(proxy_bypasses("http://[::1]:18080/v1", ""));
        assert!(proxy_bypasses("https://api.example.cn/v1", ".example.cn"));
        assert!(proxy_bypasses("https://10.23.4.5/v1", "10.0.0.0/8"));
        assert!(proxy_bypasses("http://intranet/v1", "<local>"));
        assert!(proxy_bypasses(
            "https://api.example.com:8443/v1",
            "api.example.com:8443"
        ));
        assert!(!proxy_bypasses("https://api.example.com/v1", ".example.cn"));
    }

    #[test]
    fn only_auto_detected_loopback_proxy_allows_verified_direct_fallback() {
        let settings = ProxySettings {
            mode: "proxy".into(),
            source: "windows".into(),
            proxy_url: Some("http://127.0.0.1:7897".into()),
            no_proxy: merge_no_proxy(std::iter::empty()),
            has_credentials: false,
            supports_account_binding: true,
            diagnostic: String::new(),
        };
        assert!(direct_fallback_eligible(
            &settings,
            "https://api.example.com/v1",
            true
        ));
        assert!(!direct_fallback_eligible(
            &settings,
            "https://api.example.com/v1",
            false
        ));
        assert!(!direct_fallback_eligible(
            &settings,
            "http://127.0.0.1/v1",
            true
        ));
    }

    #[test]
    fn direct_runtime_policy_deduplicates_targets_without_network_probes() {
        let settings = ProxySettings {
            mode: "direct".into(),
            source: "direct".into(),
            proxy_url: None,
            no_proxy: merge_no_proxy([".internal.test"]),
            has_credentials: false,
            supports_account_binding: false,
            diagnostic: String::new(),
        };
        let policies = evaluate_targets(
            &settings,
            [
                "https://api.internal.test/v1/",
                "https://api.internal.test/v1",
                "https://api.example.com/v1",
            ],
        );
        assert_eq!(policies.len(), 2);
        assert!(policies["https://api.internal.test/v1"].bypass);
        assert!(!policies["https://api.example.com/v1"].bypass);
        assert!(policies.values().all(|policy| !policy.direct_fallback));
    }
}
