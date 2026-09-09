use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;

pub(crate) fn atomic_write(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("codex-router-config");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.{}.{nonce}.tmp", std::process::id()));

    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            reserved1: *mut std::ffi::c_void,
            reserved2: *mut std::ffi::c_void,
        ) -> i32;
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    const REPLACEFILE_WRITE_THROUGH: u32 = 0x0000_0001;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    let source_w: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let dest_w: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    for attempt in 0..5 {
        let replaced = unsafe {
            ReplaceFileW(
                dest_w.as_ptr(),
                source_w.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if replaced != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(-1);
        if code == ERROR_FILE_NOT_FOUND {
            // Destination missing — fallback to MoveFileExW which preserves DACL on first create via inherited ACL.
            let moved = unsafe {
                MoveFileExW(
                    source_w.as_ptr(),
                    dest_w.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if moved != 0 {
                return Ok(());
            }
            let move_err = std::io::Error::last_os_error();
            if move_err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) && attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(75));
                continue;
            }
            return Err(move_err);
        }
        if code == ERROR_SHARING_VIOLATION && attempt < 4 {
            std::thread::sleep(std::time::Duration::from_millis(75));
            continue;
        }
        return Err(err);
    }
    Err(std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION))
}

#[cfg(not(windows))]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseBehavior {
    #[default]
    Ask,
    MinimizeToTray,
    Exit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiPreferences {
    #[serde(default)]
    pub close_behavior: CloseBehavior,
    #[serde(default)]
    pub close_warning_version: u8,
    #[serde(default)]
    pub active_profile_id: String,
    #[serde(default)]
    pub monitor_subscription_order: Vec<i64>,
    #[serde(default)]
    pub monitor_api_order: Vec<i64>,
    #[serde(default = "default_true")]
    pub share_codex_state: bool,
    /// User intent for the dashboard Codex route switch. Kept separately from
    /// the live config.toml probe so third-party tools that rewrite
    /// model_providers.custom cannot silently flip the switch off.
    #[serde(default)]
    pub prefer_router_mode: bool,
    /// Set only when the user explicitly switches back to the official Codex
    /// route. An externally rewritten config.toml must not look like intent.
    #[serde(default)]
    pub official_mode_selected: bool,
    /// After first successful post-setup OAuth login, the "add models" tip is
    /// shown once and then suppressed.
    #[serde(default)]
    pub oauth_model_hint_seen: bool,
    /// The user's choice on the "Codex config was overwritten externally"
    /// prompt: "" (undecided), "keep" (leave the overwritten file untouched),
    /// or "factory" (Codex factory defaults were restored).
    #[serde(default)]
    pub codex_overwrite_decision: String,
    /// Fingerprint of the overwritten config.toml the decision refers to. A
    /// new external overwrite produces a different fingerprint and re-prompts.
    #[serde(default)]
    pub codex_overwrite_fingerprint: String,
    #[serde(default)]
    pub window_width: f32,
    #[serde(default)]
    pub window_height: f32,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            close_behavior: CloseBehavior::default(),
            close_warning_version: 0,
            active_profile_id: String::new(),
            monitor_subscription_order: Vec::new(),
            monitor_api_order: Vec::new(),
            share_codex_state: true,
            prefer_router_mode: false,
            official_mode_selected: false,
            oauth_model_hint_seen: false,
            codex_overwrite_decision: String::new(),
            codex_overwrite_fingerprint: String::new(),
            window_width: 0.0,
            window_height: 0.0,
        }
    }
}

impl UiPreferences {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        atomic_write(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployConfig {
    #[serde(default)]
    pub codex_home: String,
    #[serde(default = "default_sub2api_host")]
    pub sub2api_host: String,
    #[serde(default = "default_true")]
    pub generate_isolation: bool,
    #[serde(default = "default_true")]
    pub start_with_windows: bool,
}

pub fn default_router_host() -> String {
    match std::env::var("CODEX_ROUTER_HOST_PORT") {
        Ok(value) => value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .map(|port| format!("http://127.0.0.1:{port}"))
            .unwrap_or_else(|| "http://127.0.0.1:18080".to_string()),
        _ => "http://127.0.0.1:18080".to_string(),
    }
}

fn default_sub2api_host() -> String {
    default_router_host()
}

fn default_true() -> bool {
    true
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            codex_home: String::new(),
            sub2api_host: default_sub2api_host(),
            generate_isolation: true,
            start_with_windows: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthFallback {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(
        default = "default_true",
        rename = "preferOAuth",
        alias = "preferOauth"
    )]
    pub prefer_oauth: bool,
    #[serde(default)]
    pub official_priority: i32,
    #[serde(default = "default_100")]
    pub fallback_priority: i32,
}

fn default_100() -> i32 {
    100
}

impl Default for OAuthFallback {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_oauth: true,
            official_priority: 1,
            fallback_priority: 100,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasoningConfig {
    #[serde(default = "default_auto")]
    pub mode: String,
    #[serde(default)]
    pub levels: Vec<String>,
    #[serde(default)]
    pub default_level: String,
    #[serde(default)]
    pub supports_fast: bool,
}

fn default_auto() -> String {
    "auto".to_string()
}

impl Default for ReasoningConfig {
    fn default() -> Self {
        Self {
            mode: "auto".to_string(),
            levels: vec![],
            default_level: String::new(),
            supports_fast: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    /// New installations follow the current user's proxy automatically. This
    /// field intentionally uses serde's false default so an existing explicit
    /// proxy object keeps its previous direct/manual behavior after upgrade.
    #[serde(default)]
    pub auto_detect: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http", alias = "type")]
    pub proxy_type: String,
    #[serde(default = "default_localhost")]
    pub host: String,
    #[serde(default = "default_7890")]
    pub port: String,
    #[serde(default)]
    pub username: String,
    /// Runtime-only input. The persisted value lives in Windows Credential Manager.
    #[serde(skip_serializing, default)]
    pub password: String,
    #[serde(default = "default_proxy_credential")]
    pub password_credential: String,
}

fn default_proxy_credential() -> String {
    "ProxyPassword".to_string()
}

fn default_http() -> String {
    "http".to_string()
}

fn default_localhost() -> String {
    "127.0.0.1".to_string()
}

fn default_7890() -> String {
    "7890".to_string()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            auto_detect: true,
            enabled: false,
            proxy_type: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: "7890".to_string(),
            username: String::new(),
            password: String::new(),
            password_credential: default_proxy_credential(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelConfig {
    pub model: String,
    #[serde(default)]
    pub alias: String,
    /// `Some(true)` means the user edited the display name. `Some(false)` is
    /// an automatic recommendation that may adapt to OAuth merge state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_customized: Option<bool>,
    #[serde(default, alias = "baseURL")]
    pub base_url: String,
    /// Runtime-only input. API keys are never serialized to project files.
    #[serde(skip_serializing, default)]
    pub api_key: String,
    /// Runtime-only Volcengine control-plane Access Key ID. Stored in Windows
    /// Credential Manager so Coding Plan usage can query weekly/monthly quota.
    #[serde(skip_serializing, default)]
    pub volcengine_access_key_id: String,
    /// Runtime-only Volcengine control-plane Secret Access Key.
    #[serde(skip_serializing, default)]
    pub volcengine_secret_access_key: String,
    #[serde(default)]
    pub credential_name: String,
    #[serde(default = "default_10")]
    pub priority: i32,
    #[serde(default = "default_1")]
    pub weight: i32,
    #[serde(default = "default_empty_json")]
    pub extra: String,
    #[serde(default = "default_auto")]
    pub multimodal: String,
    /// Zero selects the documented default detected from the model id.
    #[serde(default)]
    pub context_window: i64,
    /// Zero keeps the upstream/model default output token limit (the field is
    /// not sent); a positive value is injected into every request for this
    /// model by the local Responses gateway.
    #[serde(default)]
    pub max_output_tokens: i64,
    #[serde(default = "default_auto_compact_percent")]
    pub auto_compact_percent: i32,
    /// Per-model reasoning configuration. `auto` uses the documented preset.
    #[serde(default = "default_auto")]
    pub reasoning_mode: String,
    #[serde(default)]
    pub reasoning_levels: Vec<String>,
    #[serde(default)]
    pub default_reasoning_level: String,
    /// Manual-mode capability override; auto mode detects this from the model id.
    #[serde(default)]
    pub fast_supported: bool,
    /// Select Fast as the default service tier for new Codex tasks.
    #[serde(default)]
    pub fast_mode: bool,
    /// `apikey` creates a managed upstream channel; `oauth` references an
    /// account whose credentials remain inside Sub2API.
    #[serde(default = "default_apikey")]
    pub source: String,
    #[serde(default)]
    pub oauth_account_id: i64,
    #[serde(default)]
    pub oauth_platform: String,
    /// True only after the user explicitly adds this OAuth model to a profile.
    #[serde(default, skip_serializing_if = "is_false")]
    pub user_selected: bool,
}

fn default_10() -> i32 {
    10
}

fn default_1() -> i32 {
    1
}

fn default_empty_json() -> String {
    "{}".to_string()
}

fn default_apikey() -> String {
    "apikey".to_string()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_auto_compact_percent() -> i32 {
    95
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model: String::new(),
            alias: String::new(),
            alias_customized: None,
            base_url: String::new(),
            api_key: String::new(),
            volcengine_access_key_id: String::new(),
            volcengine_secret_access_key: String::new(),
            credential_name: String::new(),
            priority: 10,
            weight: 1,
            extra: "{}".to_string(),
            multimodal: "auto".to_string(),
            context_window: 0,
            max_output_tokens: 0,
            auto_compact_percent: default_auto_compact_percent(),
            reasoning_mode: default_auto(),
            reasoning_levels: vec![],
            default_reasoning_level: String::new(),
            fast_supported: false,
            fast_mode: false,
            source: default_apikey(),
            oauth_account_id: 0,
            oauth_platform: String::new(),
            user_selected: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_oauth")]
    pub auth_mode: String,
    #[serde(default = "default_ui_theme")]
    pub ui_theme: String,
    #[serde(default)]
    pub accept_compliance: bool,
    #[serde(default)]
    pub accepted_terms_version: String,
    /// Runtime-only compatibility field. The generated local key is kept in
    /// Windows Credential Manager and only copied into local integrations.
    #[serde(skip_serializing, default)]
    pub local_api_key: String,
    #[serde(default)]
    pub deploy: DeployConfig,
    #[serde(default)]
    pub oauth_fallback: OAuthFallback,
    /// `None` preserves legacy Sub2API bindings until the user first opens the
    /// OAuth manager. `Some([])` intentionally disables OAuth for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_account_ids: Option<Vec<i64>>,
    /// Accounts already considered for automatic profile enrollment. Keeping
    /// this separate lets a user disable an account without it being enabled
    /// again on the next refresh.
    #[serde(default)]
    pub oauth_seen_account_ids: Vec<i64>,
    /// Per canonical OAuth model, the stable API-key channel keys selected as
    /// fallbacks. A missing model key keeps automatic same-name matching;
    /// an explicit empty list disables API fallback for that model.
    #[serde(default)]
    pub fallback_channel_selections: BTreeMap<String, Vec<String>>,
    /// Per model-identity key (`provider:real_id`): `subscription_first`,
    /// `api_first`, or `subscription_only`. Missing keys keep subscription first.
    #[serde(default)]
    pub model_route_policies: BTreeMap<String, String>,
    #[serde(default)]
    pub reasoning: ReasoningConfig,
    /// Maximum automatic retries when an upstream answers 429, a transient
    /// network error, or Sub2API reports the account pool drained as 503.
    /// The first retry waits 5s and every further retry multiplies the wait
    /// by five (5s, 25s, 125s, 625s, ...), capped at one hour per step.
    #[serde(default = "default_rate_limit_max_retries")]
    pub rate_limit_max_retries: u32,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    #[serde(default)]
    pub default_model: String,
    #[serde(default)]
    pub model_catalog: Vec<serde_json::Value>,
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_oauth() -> String {
    "chatgpt_oauth".to_string()
}

fn default_ui_theme() -> String {
    "sky".to_string()
}

fn default_rate_limit_max_retries() -> u32 {
    crate::logic::responses_gateway::DEFAULT_RATE_LIMIT_RETRIES
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            auth_mode: "chatgpt_oauth".to_string(),
            ui_theme: default_ui_theme(),
            accept_compliance: false,
            accepted_terms_version: String::new(),
            local_api_key: String::new(),
            deploy: DeployConfig::default(),
            oauth_fallback: OAuthFallback::default(),
            oauth_account_ids: None,
            oauth_seen_account_ids: Vec::new(),
            fallback_channel_selections: BTreeMap::new(),
            model_route_policies: BTreeMap::new(),
            reasoning: ReasoningConfig::default(),
            rate_limit_max_retries: default_rate_limit_max_retries(),
            proxy: ProxyConfig::default(),
            models: vec![],
            default_model: String::new(),
            model_catalog: vec![],
        }
    }
}

impl RouterConfig {
    pub fn is_router_root(path: &std::path::Path) -> bool {
        use codex_router_lib::backend::config_compiler as cli_compiler;
        path.join("app")
            .join(cli_compiler::host_executable_file_name())
            .is_file()
            && path
                .join("app")
                .join(cli_compiler::cli_executable_file_name())
                .is_file()
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut value: serde_json::Value = serde_json::from_str(&content)?;
        normalize_legacy_model_numbers(&mut value)?;
        let incoming_version = value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut cfg: Self = serde_json::from_value(value)?;
        for model in &mut cfg.models {
            if model.model.eq_ignore_ascii_case("gpt-5.6") {
                model.model = "gpt-5.6-sol".to_owned();
                if model.alias.eq_ignore_ascii_case("gpt-5.6")
                    || model.alias.eq_ignore_ascii_case("gpt-5.6 (sol)")
                {
                    model.alias = "ChatGPT-5.6-Sol".to_owned();
                }
            }
        }
        if cfg.default_model.eq_ignore_ascii_case("gpt-5.6") {
            cfg.default_model = "gpt-5.6-sol".to_owned();
        }
        if migrate_legacy_bulk_oauth_catalog(&mut cfg) {
            crate::logic::normalize_default_model(&mut cfg);
        }
        let compact_migrated =
            migrate_auto_compact_percent_to_official(&incoming_version, &mut cfg);
        let grok_window_migrated =
            migrate_stale_grok_context_window(&incoming_version, &mut cfg);
        if compact_migrated {
            crate::logic::normalize_default_model(&mut cfg);
        }
        cfg.version = env!("CARGO_PKG_VERSION").to_owned();
        if compact_migrated || grok_window_migrated {
            let _ = cfg.save(path);
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        atomic_write(path, content.as_bytes())
    }

    pub fn find_router_root() -> std::path::PathBuf {
        if let Ok(exe) = std::env::current_exe() {
            let exe_dir = exe.parent().unwrap_or(std::path::Path::new("."));
            if let Some(root) = exe_dir
                .ancestors()
                .take(5)
                .find(|candidate| Self::is_router_root(candidate))
            {
                return root.to_path_buf();
            }
            return exe_dir.to_path_buf();
        }
        std::path::PathBuf::from(".")
    }
}

const LEGACY_BULK_OAUTH_CATALOG_THRESHOLD: usize = 12;

fn version_is_before_official_compact_migrate(version: &str) -> bool {
    let version = version.trim();
    if version.is_empty() {
        return true;
    }
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major < 2 || (major == 2 && minor < 1),
        (Some(major), None) => major < 2,
        _ => true,
    }
}

fn migrate_auto_compact_percent_to_official(version: &str, cfg: &mut RouterConfig) -> bool {
    if !version_is_before_official_compact_migrate(version) {
        return false;
    }
    let target = default_auto_compact_percent();
    let mut changed = false;
    for model in &mut cfg.models {
        if model.auto_compact_percent != target {
            model.auto_compact_percent = target;
            changed = true;
        }
    }
    changed
}

fn version_is_before_grok46_500k_window(version: &str) -> bool {
    let version = version.trim();
    if version.is_empty() {
        return true;
    }
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    let patch = parts.next().and_then(|part| part.parse::<u32>().ok());
    match (major, minor, patch) {
        (Some(major), Some(minor), Some(patch)) => {
            major < 3 || (major == 3 && minor < 2) || (major == 3 && minor == 2 && patch < 8)
        }
        (Some(major), Some(minor), None) => major < 3 || (major == 3 && minor < 2),
        (Some(major), None, None) => major < 3,
        _ => true,
    }
}

fn is_stale_grok46_context_window(model: &str, window: i64) -> bool {
    let name = model.trim().to_ascii_lowercase();
    name.contains("grok-4.6") && matches!(window, 200_000 | 256_000)
}

fn migrate_stale_grok_context_window(version: &str, cfg: &mut RouterConfig) -> bool {
    if !version_is_before_grok46_500k_window(version) {
        return false;
    }
    let mut changed = false;
    for model in &mut cfg.models {
        if is_stale_grok46_context_window(&model.model, model.context_window) {
            model.context_window = 0;
            changed = true;
        }
    }
    changed
}


fn migrate_legacy_bulk_oauth_catalog(cfg: &mut RouterConfig) -> bool {
    if !matches!(cfg.version.trim(), "1.6.4" | "1.6.5" | "1.6.6") {
        return false;
    }

    let bulk_catalog_count = cfg
        .models
        .iter()
        .filter(|model| legacy_auto_discovered_oauth_model(model))
        .count();
    let mut changed = false;
    if bulk_catalog_count >= LEGACY_BULK_OAUTH_CATALOG_THRESHOLD {
        let before = cfg.models.len();
        cfg.models
            .retain(|model| !legacy_auto_discovered_oauth_model(model));
        changed = cfg.models.len() != before;
    }

    // Small legacy OAuth lists and customized entries cannot be distinguished
    // from deliberate selections. Preserve them and mark their provenance so a
    // later migration can never interpret them as automatic catalog entries.
    for model in &mut cfg.models {
        if model.source.eq_ignore_ascii_case("oauth") && !model.user_selected {
            model.user_selected = true;
            changed = true;
        }
    }
    changed
}

fn legacy_auto_discovered_oauth_model(model: &ModelConfig) -> bool {
    model.source.eq_ignore_ascii_case("oauth")
        && !model.user_selected
        && model.oauth_account_id > 0
        && !model.oauth_platform.trim().is_empty()
        && model
            .base_url
            .trim()
            .to_ascii_lowercase()
            .starts_with("sub2api oauth / ")
        && model.alias_customized == Some(false)
        && model.priority == 1
        && model.weight == 1
        && matches!(model.extra.trim(), "" | "{}")
        && model.multimodal.eq_ignore_ascii_case("auto")
        && model.context_window == 0
        && model.auto_compact_percent == default_auto_compact_percent()
        && model.reasoning_mode.eq_ignore_ascii_case("auto")
        && model.reasoning_levels.is_empty()
        && model.default_reasoning_level.trim().is_empty()
        && !model.fast_supported
        && !model.fast_mode
        && model.credential_name.trim().is_empty()
}

fn normalize_legacy_model_numbers(value: &mut serde_json::Value) -> anyhow::Result<()> {
    let Some(models) = value
        .get_mut("models")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(());
    };
    for model in models {
        let Some(fields) = model.as_object_mut() else {
            continue;
        };
        for key in [
            "priority",
            "weight",
            "autoCompactPercent",
            "contextWindow",
            "oauthAccountId",
        ] {
            let Some(number) = fields.get(key).and_then(serde_json::Value::as_f64) else {
                continue;
            };
            if !number.is_finite() || number.fract() != 0.0 {
                anyhow::bail!("model field {key} must be an integer");
            }
            let integer = number as i64;
            if integer as f64 != number {
                anyhow::bail!("model field {key} is outside the supported integer range");
            }
            fields.insert(key.to_owned(), serde_json::Value::Number(integer.into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_never_serialized() {
        let mut config = RouterConfig {
            local_api_key: "sk-local-secret".into(),
            ..RouterConfig::default()
        };
        config.proxy.password = "proxy-secret".into();
        let model = ModelConfig {
            model: "test-model".into(),
            api_key: "sk-provider-secret".into(),
            volcengine_access_key_id: "volc-ak-secret".into(),
            volcengine_secret_access_key: "volc-sk-secret".into(),
            credential_name: "ModelApiKey-test".into(),
            ..ModelConfig::default()
        };
        config.models.push(model);
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("sk-local-secret"));
        assert!(!json.contains("proxy-secret"));
        assert!(!json.contains("sk-provider-secret"));
        assert!(!json.contains("volc-ak-secret"));
        assert!(!json.contains("volc-sk-secret"));
        assert!(json.contains("ModelApiKey-test"));
    }

    #[test]
    fn legacy_proxy_type_is_accepted() {
        let config: RouterConfig = serde_json::from_str(r#"{"proxy":{"type":"socks5"}}"#).unwrap();
        assert_eq!(config.proxy.proxy_type, "socks5");
        assert!(!config.proxy.auto_detect);
    }

    #[test]
    fn new_configs_auto_detect_proxy_without_changing_legacy_proxy_objects() {
        assert!(RouterConfig::default().proxy.auto_detect);
        let legacy: RouterConfig = serde_json::from_str(r#"{"proxy":{"enabled":false}}"#).unwrap();
        assert!(!legacy.proxy.auto_detect);
    }

    #[test]
    fn sky_is_the_default_theme() {
        assert_eq!(RouterConfig::default().ui_theme, "sky");
        let config: RouterConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.ui_theme, "sky");
    }

    #[test]
    fn deploy_defaults_enable_start_with_windows() {
        let config: RouterConfig = serde_json::from_str(r#"{"deploy":{}}"#).unwrap();
        assert!(config.deploy.start_with_windows);
    }

    #[test]
    fn oauth_routing_preference_defaults_to_oauth_for_legacy_configs() {
        let legacy: RouterConfig = serde_json::from_str(
            r#"{"oauthFallback":{"enabled":true,"officialPriority":1,"fallbackPriority":100}}"#,
        )
        .unwrap();
        assert!(legacy.oauth_fallback.prefer_oauth);

        let mut api_first = RouterConfig::default();
        api_first.oauth_fallback.prefer_oauth = false;
        let json = serde_json::to_string(&api_first).unwrap();
        assert!(json.contains(r#""preferOAuth":false"#));
        let restored: RouterConfig = serde_json::from_str(&json).unwrap();
        assert!(!restored.oauth_fallback.prefer_oauth);
    }

    #[test]
    fn fallback_channel_selections_preserve_automatic_and_explicit_empty_states() {
        let legacy: RouterConfig = serde_json::from_str("{}").unwrap();
        assert!(legacy.fallback_channel_selections.is_empty());

        let configured: RouterConfig = serde_json::from_str(
            r#"{"fallbackChannelSelections":{"gpt-5.6-sol":[],"gpt-5.6-luna":["gpt-5.6-luna|https://api.example/v1"]}}"#,
        )
        .unwrap();
        assert_eq!(
            configured.fallback_channel_selections.get("gpt-5.6-sol"),
            Some(&Vec::new())
        );
        assert_eq!(
            configured.fallback_channel_selections.get("gpt-5.6-luna"),
            Some(&vec!["gpt-5.6-luna|https://api.example/v1".to_owned()])
        );
    }

    #[test]
    fn model_route_policies_round_trip_and_default_empty() {
        let legacy: RouterConfig = serde_json::from_str("{}").unwrap();
        assert!(legacy.model_route_policies.is_empty());
        let configured: RouterConfig = serde_json::from_str(
            r#"{"modelRoutePolicies":{"x-ai:grok-4.5":"api_first"}}"#,
        )
        .unwrap();
        assert_eq!(
            configured.model_route_policies.get("x-ai:grok-4.5"),
            Some(&"api_first".to_owned())
        );
    }

    #[test]
    fn legacy_model_gets_conservative_compaction_defaults() {
        let model: ModelConfig = serde_json::from_str(r#"{"model":"legacy"}"#).unwrap();
        assert_eq!(model.context_window, 0);
        assert_eq!(model.auto_compact_percent, 95);
        assert_eq!(model.reasoning_mode, "auto");
        assert!(model.reasoning_levels.is_empty());
        assert!(!model.fast_mode);
    }

    #[test]
    fn legacy_bare_gpt_56_is_migrated_to_sol_on_load() {
        let path =
            std::env::temp_dir().join(format!("codex-router-gpt56-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"models":[{"model":"gpt-5.6","alias":"GPT-5.6 (Sol)"}],"defaultModel":"gpt-5.6"}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(config.models[0].model, "gpt-5.6-sol");
        assert_eq!(config.models[0].alias, "ChatGPT-5.6-Sol");
        assert_eq!(config.default_model, "gpt-5.6-sol");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_integral_floats_and_base_url_spelling_are_normalized_on_load() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-legacy-numbers-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        std::fs::write(
            &path,
            r#"{"models":[{"model":"test","baseURL":"https://example.test/v1","priority":90.0,"weight":1.0,"autoCompactPercent":80.0,"contextWindow":128000.0,"oauthAccountId":0.0}]}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models[0].base_url, "https://example.test/v1");
        assert_eq!(config.models[0].priority, 90);
        assert_eq!(config.models[0].weight, 1);
        assert_eq!(config.models[0].auto_compact_percent, 95);
        assert_eq!(config.models[0].context_window, 128_000);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pre_2_1_configs_raise_auto_compact_percent_to_official_95() {
        let path = std::env::temp_dir().join(format!(
            "codex-router-compact-migrate-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"{"version":"2.0.19","models":[{"model":"grok-4.6","autoCompactPercent":80},{"model":"glm-latest","autoCompactPercent":90}]}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models[0].auto_compact_percent, 95);
        assert_eq!(config.models[1].auto_compact_percent, 95);
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["models"][0]["autoCompactPercent"], 95);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pre_3_2_8_grok46_256k_window_is_reset_to_documented_default() {
        let path = std::env::temp_dir().join(format!(
            "codex-router-grok-window-migrate-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"{"version":"3.2.7","models":[{"model":"grok-4.6","contextWindow":256000},{"model":"gemini-3.8-flash","contextWindow":256000}]}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models[0].context_window, 0);
        assert_eq!(config.models[1].context_window, 256_000);
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["models"][0]["contextWindow"], 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn post_3_2_8_manual_grok_window_is_preserved() {
        let path = std::env::temp_dir().join(format!(
            "codex-router-grok-window-keep-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"{"version":"3.2.8","models":[{"model":"grok-4.6","contextWindow":256000}]}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models[0].context_window, 256_000);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn post_2_1_manual_auto_compact_percent_is_preserved() {
        let path = std::env::temp_dir().join(format!(
            "codex-router-compact-keep-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"{"version":"2.1.0","models":[{"model":"grok-4.6","autoCompactPercent":80}]}"#,
        )
        .unwrap();
        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models[0].auto_compact_percent, 80);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn per_model_reasoning_settings_round_trip() {
        let model = ModelConfig {
            model: "custom-reasoner".into(),
            reasoning_mode: "manual".into(),
            reasoning_levels: vec!["low".into(), "xhigh".into()],
            default_reasoning_level: "xhigh".into(),
            fast_supported: true,
            fast_mode: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&model).unwrap();
        let restored: ModelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.reasoning_mode, "manual");
        assert_eq!(restored.reasoning_levels, vec!["low", "xhigh"]);
        assert_eq!(restored.default_reasoning_level, "xhigh");
        assert!(restored.fast_supported);
        assert!(restored.fast_mode);
    }

    #[test]
    fn oauth_models_and_profile_account_selection_round_trip_without_tokens() {
        let mut config = RouterConfig {
            oauth_account_ids: Some(vec![7, 11]),
            oauth_seen_account_ids: vec![7, 11],
            ..Default::default()
        };
        config.models.push(ModelConfig {
            model: "gpt-5.6-sol".into(),
            source: "oauth".into(),
            oauth_account_id: 7,
            oauth_platform: "openai".into(),
            ..Default::default()
        });
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""oauthAccountIds":[7,11]"#));
        assert!(json.contains(r#""source":"oauth""#));
        assert!(!json.contains("access_token"));
        let restored: RouterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.oauth_account_ids, Some(vec![7, 11]));
        assert_eq!(restored.oauth_seen_account_ids, vec![7, 11]);
        assert_eq!(restored.models[0].oauth_account_id, 7);
    }

    #[test]
    fn default_model_round_trips_without_breaking_legacy_configs() {
        let legacy: RouterConfig = serde_json::from_str(r#"{"models":[]}"#).unwrap();
        assert!(legacy.default_model.is_empty());

        let config = RouterConfig {
            default_model: "gpt-5.6-sol".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""defaultModel":"gpt-5.6-sol""#));
    }

    #[test]
    fn ui_close_behavior_defaults_to_ask_and_round_trips() {
        let legacy: UiPreferences = serde_json::from_str("{}").unwrap();
        assert_eq!(legacy.close_behavior, CloseBehavior::Ask);
        assert_eq!(legacy.close_warning_version, 0);
        assert!(legacy.share_codex_state);

        let preferences = UiPreferences {
            close_behavior: CloseBehavior::MinimizeToTray,
            close_warning_version: 1,
            active_profile_id: "local-test".into(),
            monitor_subscription_order: vec![8, 3],
            monitor_api_order: vec![4, 1],
            share_codex_state: false,
            prefer_router_mode: true,
            official_mode_selected: false,
            oauth_model_hint_seen: true,
            codex_overwrite_decision: "keep".into(),
            codex_overwrite_fingerprint: "abc123".into(),
            window_width: 1064.0,
            window_height: 820.0,
        };
        let json = serde_json::to_string(&preferences).unwrap();
        assert!(json.contains(r#""closeBehavior":"minimize_to_tray""#));
        let restored: UiPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.close_behavior, CloseBehavior::MinimizeToTray);
        assert_eq!(restored.close_warning_version, 1);
        assert_eq!(restored.active_profile_id, "local-test");
        assert_eq!(restored.monitor_subscription_order, vec![8, 3]);
        assert_eq!(restored.monitor_api_order, vec![4, 1]);
        assert!(!restored.share_codex_state);
        assert!(restored.prefer_router_mode);
        assert!(!restored.official_mode_selected);
        assert_eq!(restored.codex_overwrite_decision, "keep");
        assert_eq!(restored.codex_overwrite_fingerprint, "abc123");
        assert_eq!(restored.window_width, 1064.0);
        assert_eq!(restored.window_height, 820.0);
        let legacy_no_prefer: UiPreferences =
            serde_json::from_str(r#"{"shareCodexState":true}"#).unwrap();
        assert!(!legacy_no_prefer.prefer_router_mode);
        assert!(!legacy_no_prefer.official_mode_selected);
        assert!(legacy_no_prefer.codex_overwrite_decision.is_empty());
        assert!(legacy_no_prefer.codex_overwrite_fingerprint.is_empty());
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_leaving_temporary_state() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codex-router-atomic-write-{}-{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_bulk_oauth_catalog_is_not_loaded_as_user_selected_routes() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-legacy-oauth-catalog-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        let mut models = vec![serde_json::json!({
            "model": "user-api-model",
            "alias": "User API model",
            "source": "apikey",
            "baseUrl": "https://api.example.test/v1",
            "aliasCustomized": true
        })];
        for index in 0..49 {
            let platform = if index < 9 {
                "openai"
            } else if index < 31 {
                "grok"
            } else {
                "antigravity"
            };
            models.push(serde_json::json!({
                "model": format!("discovered-{index}"),
                "alias": format!("Discovered {index}"),
                "aliasCustomized": false,
                "baseUrl": format!("Sub2API OAuth / {platform}"),
                "priority": 1,
                "source": "oauth",
                "oauthAccountId": index + 1,
                "oauthPlatform": platform
            }));
        }
        std::fs::write(
            &path,
            serde_json::json!({
                "version": "1.6.5",
                "models": models,
                "defaultModel": "discovered-0"
            })
            .to_string(),
        )
        .unwrap();

        let config = RouterConfig::load(&path).unwrap();
        assert_eq!(config.models.len(), 1);
        assert_eq!(config.models[0].model, "user-api-model");
        assert_eq!(config.default_model, "user-api-model");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_bulk_oauth_migration_keeps_explicit_and_customized_routes() {
        let mut config = RouterConfig {
            version: "1.6.5".into(),
            models: (0..LEGACY_BULK_OAUTH_CATALOG_THRESHOLD)
                .map(|index| ModelConfig {
                    model: format!("discovered-{index}"),
                    alias: format!("Discovered {index}"),
                    alias_customized: Some(false),
                    base_url: "Sub2API OAuth / antigravity".into(),
                    priority: 1,
                    source: "oauth".into(),
                    oauth_account_id: 7,
                    oauth_platform: "antigravity".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        config.models.push(ModelConfig {
            model: "explicit-oauth".into(),
            alias: "Explicit OAuth".into(),
            alias_customized: Some(false),
            base_url: "Sub2API OAuth / antigravity".into(),
            priority: 1,
            source: "oauth".into(),
            oauth_account_id: 7,
            oauth_platform: "antigravity".into(),
            user_selected: true,
            ..Default::default()
        });
        config.models.push(ModelConfig {
            model: "customized-oauth".into(),
            alias: "My Antigravity route".into(),
            alias_customized: Some(true),
            base_url: "Sub2API OAuth / antigravity".into(),
            priority: 1,
            source: "oauth".into(),
            oauth_account_id: 7,
            oauth_platform: "antigravity".into(),
            ..Default::default()
        });

        assert!(migrate_legacy_bulk_oauth_catalog(&mut config));
        assert_eq!(config.models.len(), 2);
        assert!(config.models.iter().all(|model| model.user_selected));
        assert!(config
            .models
            .iter()
            .any(|model| model.model == "explicit-oauth"));
        assert!(config
            .models
            .iter()
            .any(|model| model.model == "customized-oauth"));
    }

    #[test]
    fn small_legacy_oauth_selection_is_preserved() {
        let mut config = RouterConfig {
            version: "1.6.5".into(),
            models: vec![ModelConfig {
                model: "gpt-5.6-sol".into(),
                alias: "ChatGPT-5.6-Sol".into(),
                alias_customized: Some(false),
                base_url: "Sub2API OAuth / openai".into(),
                priority: 1,
                source: "oauth".into(),
                oauth_account_id: 42,
                oauth_platform: "openai".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        assert!(migrate_legacy_bulk_oauth_catalog(&mut config));
        assert_eq!(config.models.len(), 1);
        assert!(config.models[0].user_selected);
    }
}
