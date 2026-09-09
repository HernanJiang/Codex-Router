//! Typed compiler for the locked CLIProxyAPI v7.2.135 runtime configuration.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CLI_PROXY_VERSION: &str = "7.2.135";
pub const CLI_PROXY_COMMIT: &str = "856ddd8df746a38a6033dbbf6c140974bf5aea0f";
pub const CLI_PROXY_PACKAGE_SHA256_WINDOWS: &str =
    "80eef3e63e229405362c0f302abba50909cd53f10f6036c438d3f4f765144d34";
/// Upstream `CLIProxyAPI_7.2.135_darwin_aarch64.tar.gz` archive hash, verified
/// against upstream `checksums.txt` on 2026-09-09.
pub const CLI_PROXY_PACKAGE_SHA256_MACOS: &str =
    "c5f6e785cf7568c177d5c31aa75c389c4bb1b1dee9e0133887b9bce3200475dd";
#[cfg(windows)]
pub const CLI_PROXY_PACKAGE_SHA256: &str = CLI_PROXY_PACKAGE_SHA256_WINDOWS;
#[cfg(not(windows))]
pub const CLI_PROXY_PACKAGE_SHA256: &str = CLI_PROXY_PACKAGE_SHA256_MACOS;
pub const CLI_PROXY_SHA256_WINDOWS: &str =
    "0a8ffc52dfb2a466baa1b006341b350bdb1f76fc70b6cc80375bb99afdff697b";
/// `cli-proxy-api` Mach-O arm64 executable hash from the darwin_aarch64
/// package above (single-file package, no plugin bundled).
pub const CLI_PROXY_SHA256_MACOS: &str =
    "5f24ebf3ed2caeee6ff63b5eaba7ccdb66f3ccb7af273ba1f70d68dc2f3531fb";
#[cfg(windows)]
pub const CLI_PROXY_SHA256: &str = CLI_PROXY_SHA256_WINDOWS;
#[cfg(not(windows))]
pub const CLI_PROXY_SHA256: &str = CLI_PROXY_SHA256_MACOS;
pub const GEMINI_PLUGIN_VERSION: &str = "1.0.5";
pub const GEMINI_PLUGIN_SHA256_WINDOWS: &str =
    "c1d849f13270329bff9f4d8ab8ef7507eba57642402beb19c60e66ecc2e40cee";
/// `gemini-cli.dylib` (Mach-O arm64) from the upstream
/// `cpa-plugin-gemini-cli` v1.0.5 `darwin_arm64` asset, verified live on
/// Apple Silicon (plugin registers, `gemini-cli-auth-url` answers 200).
pub const GEMINI_PLUGIN_SHA256_MACOS: &str =
    "4fbac8a964467c477db9975f9ec38e35254ea60fb950b67418a063b2cde20f1b";
/// Upstream `gemini-cli_1.0.5_darwin_arm64.zip` archive hash (matches the
/// release `checksums.txt`).
pub const GEMINI_PLUGIN_PACKAGE_SHA256_MACOS: &str =
    "3c771ff57e607b40bf95753e0ad2fb01127a296fe4cbff79b49116cd2327b5bb";
#[cfg(windows)]
pub const GEMINI_PLUGIN_SHA256: &str = GEMINI_PLUGIN_SHA256_WINDOWS;
#[cfg(target_os = "macos")]
pub const GEMINI_PLUGIN_SHA256: &str = GEMINI_PLUGIN_SHA256_MACOS;
#[cfg(not(any(windows, target_os = "macos")))]
pub const GEMINI_PLUGIN_SHA256: &str = GEMINI_PLUGIN_SHA256_WINDOWS;

/// Cross-platform executable / layout helpers. Windows binaries carry `.exe`,
/// macOS binaries have no suffix. Forward slashes are used for relative
/// paths so `Path::join` stays correct on both platforms.
pub fn executable_file_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

pub fn gui_executable_file_name() -> &'static str {
    if cfg!(windows) {
        "Codex-Router.exe"
    } else {
        "Codex-Router"
    }
}

pub fn host_executable_file_name() -> &'static str {
    if cfg!(windows) {
        "codex-router-host.exe"
    } else {
        "codex-router-host"
    }
}

pub fn cli_executable_file_name() -> &'static str {
    if cfg!(windows) {
        "cli-proxy-api.exe"
    } else {
        "cli-proxy-api"
    }
}

/// Relative path of the Gemini CLI plugin inside the portable tree.
/// Windows: `app/plugins/windows/amd64/gemini-cli-v1.0.5.dll`;
/// macOS: `app/plugins/darwin/arm64/gemini-cli.dylib` (upstream
/// `cpa-plugin-gemini-cli` v1.0.5 darwin_arm64 asset, verified live:
/// the plugin registers and `gemini-cli-auth-url` answers 200).
/// Other platforms ship no plugin and must skip the plugin lock.
pub fn gemini_plugin_relative_path() -> Option<&'static std::path::Path> {
    #[cfg(windows)]
    {
        Some(std::path::Path::new(
            "app/plugins/windows/amd64/gemini-cli-v1.0.5.dll",
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Some(std::path::Path::new(
            "app/plugins/darwin/arm64/gemini-cli.dylib",
        ))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

/// Normalize a freshly built runtime config for the current platform before
/// it is written or pushed to CLIProxyAPI. Windows and macOS bundle the
/// locked Gemini plugin entry (enforced by `validate`); other platforms must
/// not point the CLI at a plugin directory that does not exist in theirs.
pub fn apply_platform_runtime_policy(config: &mut CliProxyConfig) {
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        config.plugins.enabled = false;
        config.plugins.configs.clear();
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        let _ = config;
    }
}

/// Portable runtime files that must exist before the Router Host starts.
pub fn required_runtime_relative_paths() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &[
            "app/codex-router-host.exe",
            "app/cli-proxy-api.exe",
            "app/plugins/windows/amd64/gemini-cli-v1.0.5.dll",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            "app/codex-router-host",
            "app/cli-proxy-api",
            "app/plugins/darwin/arm64/gemini-cli.dylib",
        ]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        &["app/codex-router-host", "app/cli-proxy-api"]
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteTarget {
    pub route_id: String,
    pub public_model: String,
    pub upstream_model: String,
    pub platform: String,
    pub base_url: Option<String>,
    pub credential_ref: String,
    pub priority: i32,
    pub weight: i32,
    pub proxy_url: Option<String>,
    pub openai_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteManagement {
    #[serde(rename = "allow-remote", default)]
    pub allow_remote: bool,
    #[serde(rename = "secret-key", default)]
    pub secret_key: String,
    #[serde(rename = "disable-control-panel", default)]
    pub disable_control_panel: bool,
}

impl Default for RemoteManagement {
    fn default() -> Self {
        Self {
            allow_remote: false,
            secret_key: String::new(),
            disable_control_panel: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingConfig {
    pub strategy: String,
    #[serde(rename = "session-affinity")]
    pub session_affinity: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelMapping {
    pub name: String,
    pub alias: String,
    #[serde(rename = "force-mapping", default)]
    pub force_mapping: bool,
    /// CLIProxyAPI only routes `/v1/images/*` traffic to models flagged
    /// `image: true`; the Router sets it for upstream image models.
    #[serde(rename = "image", default, skip_serializing_if = "is_false")]
    pub image: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Upstream models whose name advertises image generation are compiled with
/// the CLI `image: true` flag so `/v1/images/*` requests can reach them.
pub fn is_image_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("image")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeminiApiKey {
    #[serde(rename = "api-key")]
    pub api_key: String,
    pub prefix: Option<String>,
    pub weight: Option<i32>,
    pub priority: Option<i32>,
    #[serde(rename = "proxy-url")]
    pub proxy_url: Option<String>,
    pub models: Vec<ModelMapping>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeApiKey {
    #[serde(rename = "api-key")]
    pub api_key: String,
    pub prefix: Option<String>,
    pub weight: Option<i32>,
    pub priority: Option<i32>,
    #[serde(rename = "proxy-url")]
    pub proxy_url: Option<String>,
    pub models: Vec<ModelMapping>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexApiKey {
    #[serde(rename = "api-key")]
    pub api_key: String,
    pub prefix: Option<String>,
    pub weight: Option<i32>,
    pub priority: Option<i32>,
    #[serde(rename = "proxy-url")]
    pub proxy_url: Option<String>,
    pub models: Vec<ModelMapping>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct XaiApiKey {
    #[serde(rename = "api-key")]
    pub api_key: String,
    pub prefix: Option<String>,
    pub weight: Option<i32>,
    pub priority: Option<i32>,
    #[serde(rename = "proxy-url")]
    pub proxy_url: Option<String>,
    pub models: Vec<ModelMapping>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiCompatibility {
    pub name: String,
    pub prefix: String,
    #[serde(rename = "base-url")]
    pub base_url: String,
    #[serde(rename = "request-retry", default)]
    pub request_retry: i32,
    #[serde(rename = "api-key-entries")]
    pub api_key_entries: Vec<OpenAiCompatKeyEntry>,
    pub priority: Option<i32>,
    #[serde(
        rename = "openai-capabilities",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub openai_capabilities: Vec<String>,
    pub models: Vec<ModelMapping>,
}

/// CLIProxyAPI v7.2.135 stores OpenAI-compatible credentials under
/// `api-key-entries`; entry-level `api-key` is silently ignored upstream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiCompatKeyEntry {
    #[serde(rename = "api-key")]
    pub api_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
    #[serde(rename = "proxy-url", skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginConfig {
    pub enabled: bool,
    pub dir: String,
    pub configs: BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CliProxyConfig {
    pub host: String,
    pub port: u16,
    #[serde(rename = "proxy-url", skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    #[serde(rename = "remote-management")]
    pub remote_management: RemoteManagement,
    #[serde(rename = "auth-dir")]
    pub auth_dir: String,
    #[serde(rename = "api-keys")]
    pub api_keys: Vec<String>,
    #[serde(rename = "usage-statistics-enabled")]
    pub usage_statistics_enabled: bool,
    #[serde(rename = "request-retry")]
    pub request_retry: i32,
    #[serde(rename = "max-retry-credentials")]
    pub max_retry_credentials: i32,
    pub routing: RoutingConfig,
    #[serde(rename = "gemini-api-key", skip_serializing_if = "Vec::is_empty")]
    pub gemini_api_key: Vec<GeminiApiKey>,
    #[serde(rename = "claude-api-key", skip_serializing_if = "Vec::is_empty")]
    pub claude_api_key: Vec<ClaudeApiKey>,
    #[serde(rename = "codex-api-key", skip_serializing_if = "Vec::is_empty")]
    pub codex_api_key: Vec<CodexApiKey>,
    #[serde(rename = "xai-api-key", skip_serializing_if = "Vec::is_empty")]
    pub xai_api_key: Vec<XaiApiKey>,
    #[serde(rename = "openai-compatibility", skip_serializing_if = "Vec::is_empty")]
    pub openai_compatibility: Vec<OpenAiCompatibility>,
    pub plugins: PluginConfig,
}

impl Default for CliProxyConfig {
    fn default() -> Self {
        let mut gemini_config = BTreeMap::new();
        gemini_config.insert("enabled".to_owned(), serde_yaml::Value::Bool(true));
        let mut configs = BTreeMap::new();
        configs.insert("gemini-cli".to_owned(), gemini_config);
        Self {
            host: "127.0.0.1".to_owned(),
            port: 18081,
            proxy_url: None,
            remote_management: RemoteManagement {
                allow_remote: false,
                secret_key: String::new(),
                disable_control_panel: true,
            },
            auth_dir: "./auth".to_owned(),
            api_keys: Vec::new(),
            usage_statistics_enabled: true,
            request_retry: 1,
            max_retry_credentials: 4,
            routing: RoutingConfig {
                strategy: "weighted-round-robin".to_owned(),
                session_affinity: false,
            },
            gemini_api_key: Vec::new(),
            claude_api_key: Vec::new(),
            codex_api_key: Vec::new(),
            xai_api_key: Vec::new(),
            openai_compatibility: Vec::new(),
            plugins: PluginConfig {
                enabled: true,
                dir: "plugins".to_owned(),
                configs,
            },
        }
    }
}

pub fn pool_id(route_id: &str, platform: &str) -> String {
    format!("cr/{route_id}/{}", normalize_platform(platform))
}

pub fn pool_prefix(route_id: &str, platform: &str) -> String {
    format!(
        "cr_{}_{}",
        sanitize_route_id(route_id),
        normalize_platform(platform)
    )
}

fn sanitize_route_id(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    output.trim_matches('_').to_owned()
}

pub fn normalize_platform(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "chatgpt" | "openai" => "openai".to_owned(),
        "claude" | "anthropic" => "anthropic".to_owned(),
        "google" | "gemini" => "gemini".to_owned(),
        "grok" | "xai" => "xai".to_owned(),
        other => other.to_owned(),
    }
}

/// Compute CLIProxyAPI's stable auth index for a config-synthesized API key
/// credential. Mirrors `Auth.indexSeed`/`stableAuthIndex` in the locked CLI
/// source: seed = `<prefix>:<base-url>+<api-key>`, index = hex(sha256[:8]).
/// `platform`/`base_url` must be the same values the compiler used to choose
/// the target config list, otherwise the index will not join with the
/// X-CPA-TRACE-ID header returned by the CLI data plane.
pub fn cli_key_auth_index(platform: &str, base_url: Option<&str>, api_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let normalized = normalize_platform(platform);
    let base = base_url.map(str::trim).filter(|value| !value.is_empty());
    let (prefix, base) = match (normalized.as_str(), base) {
        ("openai", None) => ("codex-api-key", ""),
        ("anthropic", None) => ("claude-api-key", ""),
        ("gemini", None) => ("gemini-api-key", ""),
        ("xai", None) => ("xai-api-key", ""),
        (_, Some(base)) => ("openai-compatibility", base),
        (_, None) => ("openai-compatibility", ""),
    };
    let seed = format!("{prefix}:{base}+{}", api_key.trim());
    let digest = Sha256::digest(seed.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Auth index for file-based (OAuth) credentials: seed = `<type>:<abs path>`.
pub fn cli_file_auth_index(auth_type: &str, file_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let seed = format!(
        "{}:{}",
        auth_type.trim().to_ascii_lowercase(),
        file_path.trim()
    );
    let digest = Sha256::digest(seed.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Parse the CLI `X-CPA-TRACE-ID` header (`<ts>-<authIndex>-<requestId>`) and
/// return the embedded auth index segment.
pub fn parse_cpa_trace_auth_index(trace: &str) -> Option<&str> {
    let after_timestamp = trace.split_once('-')?.1;
    let (auth_index, _) = after_timestamp.split_once('-')?;
    if auth_index.is_empty() {
        None
    } else {
        Some(auth_index)
    }
}

/// Fold historical hidden tiers (P10 -> 2010, P100 -> 2100) back to the
/// explicit 1..=999 card order before compiling CLI credentials.
pub fn display_priority(legacy_priority: i32) -> i32 {
    let folded = if legacy_priority.abs() >= 1000 {
        legacy_priority.abs() % 1000
    } else {
        legacy_priority.abs()
    };
    if folded == 0 {
        1
    } else {
        folded.clamp(1, 999)
    }
}

/// Sub2API uses smaller numbers first; CLIProxyAPI uses larger numbers first.
pub fn cli_priority(legacy_priority: i32) -> i32 {
    (1_000_000i32 - display_priority(legacy_priority)).max(1)
}

pub fn compile(
    targets: &[RouteTarget],
    downstream_key: &str,
    management_secret: &str,
    auth_dir: &str,
) -> Result<CliProxyConfig> {
    if targets.is_empty() {
        bail!("no servable route target supplied to CLI config compiler");
    }
    if downstream_key.trim().is_empty() || management_secret.trim().is_empty() {
        bail!("downstream and management credentials must be non-empty");
    }
    let mut config = CliProxyConfig {
        auth_dir: auth_dir.to_owned(),
        remote_management: RemoteManagement {
            secret_key: management_secret.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    };
    config.api_keys.push(downstream_key.to_owned());
    let mut public_models = BTreeSet::new();
    for target in targets {
        public_models.insert(target.public_model.clone());
        let prefix = pool_prefix(&target.route_id, &target.platform);
        let mapping = ModelMapping {
            name: target.upstream_model.clone(),
            alias: target.public_model.clone(),
            force_mapping: true,
            image: is_image_model(&target.upstream_model),
        };
        let priority = Some(cli_priority(target.priority));
        let weight = Some(target.weight.clamp(1, 1_000_000));
        match normalize_platform(&target.platform).as_str() {
            "gemini" if target.base_url.is_none() => config.gemini_api_key.push(GeminiApiKey {
                api_key: target.credential_ref.clone(),
                prefix: Some(prefix),
                weight,
                priority,
                proxy_url: target.proxy_url.clone(),
                models: vec![mapping],
            }),
            "anthropic" if target.base_url.is_none() => config.claude_api_key.push(ClaudeApiKey {
                api_key: target.credential_ref.clone(),
                prefix: Some(prefix),
                weight,
                priority,
                proxy_url: target.proxy_url.clone(),
                models: vec![mapping],
            }),
            "openai" if target.base_url.is_none() => config.codex_api_key.push(CodexApiKey {
                api_key: target.credential_ref.clone(),
                prefix: Some(prefix),
                weight,
                priority,
                proxy_url: target.proxy_url.clone(),
                models: vec![mapping],
            }),
            "xai" if target.base_url.is_none() => config.xai_api_key.push(XaiApiKey {
                api_key: target.credential_ref.clone(),
                prefix: Some(prefix),
                weight,
                priority,
                proxy_url: target.proxy_url.clone(),
                models: vec![mapping],
            }),
            _ => {
                let Some(base_url) = target
                    .base_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                else {
                    bail!("platform {} requires an API base URL", target.platform);
                };
                config.openai_compatibility.push(OpenAiCompatibility {
                    name: prefix.clone(),
                    prefix,
                    base_url: base_url.to_owned(),
                    request_retry: 1,
                    api_key_entries: vec![OpenAiCompatKeyEntry {
                        api_key: target.credential_ref.clone(),
                        weight,
                        proxy_url: target.proxy_url.clone(),
                    }],
                    priority,
                    openai_capabilities: target.openai_capabilities.clone(),
                    models: vec![mapping],
                });
            }
        }
    }
    // BTreeSet already deduplicates; distinct public models are the
    // normal multi-pool case and must all reach the CLI config.
    for model in &public_models {
        if model.trim().is_empty() {
            bail!("public model cannot be empty");
        }
    }
    validate(&config)?;
    Ok(config)
}

pub fn validate(config: &CliProxyConfig) -> Result<()> {
    if config.host != "127.0.0.1" && config.host != "localhost" {
        bail!("CLIProxyAPI must bind loopback");
    }
    if !config.remote_management.secret_key.is_empty() && config.remote_management.allow_remote {
        bail!("remote management cannot be enabled for CodexRouter");
    }
    if config.api_keys.iter().any(|key| key.is_empty()) {
        bail!("CLI downstream API keys cannot be empty");
    }
    // Multiple credentials may share one pool prefix: the prefix identifies the
    // pool, not the credential. Only unsafe slash prefixes are rejected.
    let native_prefixes = config
        .gemini_api_key
        .iter()
        .map(|entry| entry.prefix.as_deref())
        .chain(
            config
                .claude_api_key
                .iter()
                .map(|entry| entry.prefix.as_deref()),
        )
        .chain(
            config
                .codex_api_key
                .iter()
                .map(|entry| entry.prefix.as_deref()),
        )
        .chain(
            config
                .xai_api_key
                .iter()
                .map(|entry| entry.prefix.as_deref()),
        );
    for prefix in native_prefixes {
        let prefix = prefix.unwrap_or_default();
        if prefix.starts_with("cr/") || prefix.contains("..") {
            bail!("unsafe internal prefix leaked into CLI config: {prefix}");
        }
    }
    // The Gemini CLI plugin ships for Windows and macOS (upstream
    // `cpa-plugin-gemini-cli` publishes both); other platforms run without it.
    #[cfg(any(windows, target_os = "macos"))]
    if !config.plugins.enabled || !config.plugins.configs.contains_key("gemini-cli") {
        bail!("locked Gemini CLI plugin is required");
    }
    if config.request_retry < 0 || config.max_retry_credentials < 0 {
        bail!("retry values cannot be negative");
    }
    Ok(())
}

pub fn to_yaml(config: &CliProxyConfig) -> Result<String> {
    serde_yaml::to_string(config).context("serialize typed CLIProxyAPI config")
}

pub fn from_yaml(text: &str) -> Result<CliProxyConfig> {
    let config: CliProxyConfig =
        serde_yaml::from_str(text).context("parse typed CLIProxyAPI config")?;
    validate(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_key_auth_index_matches_locked_cli_derivation() {
        // Verified against CLIProxyAPI v7.2.135 live X-CPA-TRACE-ID:
        // seed "openai-compatibility:http://127.0.0.1:29090/v1+mock-key-123".
        assert_eq!(
            super::cli_key_auth_index("openai", Some("http://127.0.0.1:29090/v1"), "mock-key-123"),
            "912f6f1a719b10a5"
        );
        assert_eq!(
            super::parse_cpa_trace_auth_index("20260818082331-912f6f1a719b10a5-7aae64c8"),
            Some("912f6f1a719b10a5")
        );
    }

    use super::*;

    #[test]
    fn priority_direction_and_pool_prefixes_are_explicit() {
        assert!(cli_priority(1) > cli_priority(10));
        assert!(cli_priority(1) > cli_priority(2));
        assert!(cli_priority(2) > cli_priority(3));
        assert_eq!(display_priority(2100), 100);
        assert_eq!(display_priority(2010), 10);
        assert_eq!(cli_priority(100), cli_priority(2100));
        assert!(cli_priority(1) > cli_priority(2100));
        assert_eq!(pool_prefix("gpt-route", "ChatGPT"), "cr_gpt_route_openai");
        assert_eq!(pool_id("gpt-route", "ChatGPT"), "cr/gpt-route/openai");
    }

    #[test]
    fn typed_config_round_trips_and_keeps_plugin_lock() {
        let target = RouteTarget {
            route_id: "gpt".into(),
            public_model: "gpt-public".into(),
            upstream_model: "gpt-upstream".into(),
            platform: "openai".into(),
            credential_ref: "secret-api-key".into(),
            priority: 2,
            weight: 7,
            ..Default::default()
        };
        let config = compile(&[target], "sk-downstream", "management-secret", "./auth").unwrap();
        let yaml = to_yaml(&config).unwrap();
        assert!(yaml.contains("cr_gpt_openai"));
        assert!(yaml.contains("gemini-cli"));
        let parsed = from_yaml(&yaml).unwrap();
        assert_eq!(parsed, config);
        assert!(!config.routing.session_affinity);
        assert!(!yaml.contains("session-affinity: true"));
    }
    #[test]
    fn multiple_public_models_compile_side_by_side() {
        let targets = vec![
            RouteTarget {
                route_id: "r1".into(),
                public_model: "gpt-public".into(),
                upstream_model: "gpt-upstream".into(),
                platform: "openai".into(),
                credential_ref: "key-a".into(),
                ..Default::default()
            },
            RouteTarget {
                route_id: "r2".into(),
                public_model: "claude-public".into(),
                upstream_model: "claude-upstream".into(),
                platform: "anthropic".into(),
                credential_ref: "key-b".into(),
                ..Default::default()
            },
        ];
        let config = compile(&targets, "sk-downstream", "management-secret", "./auth").unwrap();
        assert_eq!(config.codex_api_key.len(), 1);
        assert_eq!(config.claude_api_key.len(), 1);
        let yaml = to_yaml(&config).unwrap();
        assert!(yaml.contains("gpt-public"));
        assert!(yaml.contains("claude-public"));
    }

    #[test]
    fn openai_compatible_capabilities_reach_yaml() {
        let target = RouteTarget {
            route_id: "deepseek".into(),
            public_model: "deepseek-v4-pro".into(),
            upstream_model: "DeepSeek-V4-Pro".into(),
            platform: "openai".into(),
            base_url: Some("https://school.example/v1".into()),
            credential_ref: "credential".into(),
            openai_capabilities: vec!["chat_completions".into()],
            ..Default::default()
        };
        let config = compile(&[target], "downstream", "management", "./auth").unwrap();
        assert_eq!(
            config.openai_compatibility[0].openai_capabilities,
            ["chat_completions"]
        );
        let yaml = to_yaml(&config).unwrap();
        assert!(yaml.contains("openai-capabilities:\n  - chat_completions"));
    }

    #[test]
    fn legacy_openai_compatibility_without_capabilities_still_loads() {
        let yaml = r#"
host: 127.0.0.1
port: 18081
remote-management: {}
auth-dir: ./auth
openai-compatibility:
  - name: legacy
    prefix: legacy
    base-url: https://example.com/v1
    api-key-entries:
      - api-key: placeholder
    models:
      - name: upstream
        alias: public
        force-mapping: true
plugins:
  enabled: true
  dir: ./plugins
  configs:
    gemini-cli:
      enabled: true
"#;

        let config = from_yaml(yaml).unwrap();
        assert!(config.openai_compatibility[0]
            .openai_capabilities
            .is_empty());
        assert!(to_yaml(&config).unwrap().contains("openai-compatibility:"));
    }

    #[test]
    fn compiler_rejects_empty_routes_and_loopback_violations() {
        assert!(compile(&[], "k", "s", "./auth").is_err());
        let config = CliProxyConfig {
            host: "0.0.0.0".into(),
            ..Default::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn platform_executable_names_match_current_target() {
        #[cfg(windows)]
        {
            assert_eq!(
                super::executable_file_name("cli-proxy-api"),
                "cli-proxy-api.exe"
            );
            assert_eq!(super::gui_executable_file_name(), "Codex-Router.exe");
            assert_eq!(super::host_executable_file_name(), "codex-router-host.exe");
            assert_eq!(super::cli_executable_file_name(), "cli-proxy-api.exe");
            assert_eq!(super::CLI_PROXY_SHA256, super::CLI_PROXY_SHA256_WINDOWS);
            assert!(super::gemini_plugin_relative_path().is_some());
            assert!(super::required_runtime_relative_paths()
                .iter()
                .any(|path| path.ends_with(".dll")));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                super::executable_file_name("cli-proxy-api"),
                "cli-proxy-api"
            );
            assert_eq!(super::gui_executable_file_name(), "Codex-Router");
            assert_eq!(super::host_executable_file_name(), "codex-router-host");
            assert_eq!(super::cli_executable_file_name(), "cli-proxy-api");
            assert_eq!(super::CLI_PROXY_SHA256, super::CLI_PROXY_SHA256_MACOS);
            assert_eq!(
                super::CLI_PROXY_PACKAGE_SHA256,
                super::CLI_PROXY_PACKAGE_SHA256_MACOS
            );
            assert_eq!(
                super::GEMINI_PLUGIN_SHA256,
                super::GEMINI_PLUGIN_SHA256_MACOS
            );
            assert_eq!(
                super::gemini_plugin_relative_path(),
                Some(std::path::Path::new(
                    "app/plugins/darwin/arm64/gemini-cli.dylib"
                ))
            );
            assert!(super::required_runtime_relative_paths()
                .iter()
                .any(|path| path.ends_with(".dylib")));
            assert!(!super::required_runtime_relative_paths()
                .iter()
                .any(|path| path.ends_with(".exe")));
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            assert_eq!(
                super::executable_file_name("cli-proxy-api"),
                "cli-proxy-api"
            );
            assert_eq!(super::gui_executable_file_name(), "Codex-Router");
            assert_eq!(super::host_executable_file_name(), "codex-router-host");
            assert_eq!(super::cli_executable_file_name(), "cli-proxy-api");
            assert!(super::gemini_plugin_relative_path().is_none());
            assert!(!super::required_runtime_relative_paths()
                .iter()
                .any(|path| path.ends_with(".dll") || path.ends_with(".exe")));
        }
        for hash in [
            super::CLI_PROXY_SHA256,
            super::CLI_PROXY_PACKAGE_SHA256,
            super::GEMINI_PLUGIN_SHA256,
            super::GEMINI_PLUGIN_SHA256_MACOS,
        ] {
            assert_eq!(hash.len(), 64);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn plugin_free_config_fails_where_plugin_ships() {
        let mut config = CliProxyConfig::default();
        config.plugins.enabled = false;
        config.plugins.configs.clear();
        #[cfg(any(windows, target_os = "macos"))]
        assert!(validate(&config).is_err());
        #[cfg(not(any(windows, target_os = "macos")))]
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn platform_runtime_policy_disables_plugins_where_none_ships() {
        let mut config = CliProxyConfig::default();
        super::apply_platform_runtime_policy(&mut config);
        #[cfg(any(windows, target_os = "macos"))]
        assert!(config.plugins.enabled);
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            assert!(!config.plugins.enabled);
            assert!(config.plugins.configs.is_empty());
            assert!(validate(&config).is_ok());
        }
    }
}
