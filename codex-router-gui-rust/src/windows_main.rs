mod autostart;
mod config;
#[allow(dead_code)]
mod credentials;
mod lifecycle;
mod lifecycle_cutover;
mod logic;
mod platform;
mod profiles;
mod proxy;
mod runtime_logs;
mod theme;
mod ui;
mod updater;
mod user_data;

use anyhow::Context;
use config::{CloseBehavior, ModelConfig, RouterConfig, UiPreferences};
use eframe::egui;
use profiles::{IsolationKind, IsolationProfile};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
#[cfg(all(test, windows))]
use std::io::{Seek, SeekFrom};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(all(test, windows))]
use std::os::windows::process::CommandExt;
#[cfg(all(test, windows))]
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use zeroize::Zeroizing;

use updater::UpdateInfo as GitHubUpdateInfo;

const APP_ICON_ICO: &[u8] = include_bytes!("../assets/logo.ico");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_TITLE: &str = concat!("CodexRouter v", env!("CARGO_PKG_VERSION"));
const TRAY_TOOLTIP_ZH: &str = concat!(
    "CodexRouter v",
    env!("CARGO_PKG_VERSION"),
    " - 轻量托盘模式（仅保留转发保护）"
);
const TRAY_TOOLTIP_EN: &str = concat!(
    "CodexRouter v",
    env!("CARGO_PKG_VERSION"),
    " - lightweight tray mode (forwarding protection only)"
);
const CURRENT_CONFIG_VERSION: &str = APP_VERSION;
const CURRENT_TERMS_VERSION: &str = "codex-router-terms-v1.3.0-2026-08-18";
const OFFICIAL_GITHUB_URL: &str = "https://github.com/HernanJiang/CodexRouter";
const MAX_LOG_BYTES: usize = 256 * 1024;
const RETAIN_LOG_BYTES: usize = 192 * 1024;
#[cfg(all(test, windows))]
const CREATE_NO_WINDOW: u32 = 0x08000000;
const HEALTHY_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const FAILED_PROBE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const APPLY_SETTLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const RECOVERY_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const BACKGROUND_SELF_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3 * 60);
const OAUTH_RECOVERY_MAX_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5 * 60 * 60);
const DEFAULT_ROUTER_REQUIRES_OPENAI_AUTH: bool = false;
const HEALTH_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
const API_MODEL_VALIDATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const EXIT_CONFIG_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const EXIT_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(all(test, windows))]
const EXIT_PROCESS_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(all(test, windows))]
const EXIT_HELPER_OUTPUT_LIMIT: usize = 64 * 1024;
const BACKGROUND_USAGE_REFRESH_INTERVAL: std::time::Duration = BACKGROUND_SELF_CHECK_INTERVAL;
// Logical points, not physical pixels. Startup is fitted to the primary
// monitor's work area, so ordinary displays retain the comfortable desktop
// size while 200%-scaled displays receive a usable compact window.
const DEFAULT_WINDOW_LOGICAL_SIZE: [f32; 2] = [1200.0, 760.0];
const COMPACT_WINDOW_LOGICAL_SIZE: [f32; 2] = [800.0, 560.0];
const MIN_WINDOW_LOGICAL_SIZE: [f32; 2] = [720.0, 380.0];
const WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE: [f32; 2] = [960.0, 492.0];
const WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE: [f32; 2] = [16.0, 40.0];
// `ViewportInfo::monitor_size` includes the taskbar area. Reserve both normal
// window chrome and a 48-point taskbar when clamping after a DPI transition.
const WINDOWS_RUNTIME_MONITOR_ALLOWANCE: [f32; 2] = [16.0, 88.0];

fn fit_window_to_work_area(preferred: [f32; 2], work_area: [f32; 2]) -> [f32; 2] {
    let maximum = [
        (work_area[0] - WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE[0]).max(1.0),
        (work_area[1] - WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE[1]).max(1.0),
    ];
    [preferred[0].min(maximum[0]), preferred[1].min(maximum[1])]
}

fn window_size_is_usable(size: [f32; 2]) -> bool {
    size[0] + 1.0 >= MIN_WINDOW_LOGICAL_SIZE[0] && size[1] + 1.0 >= MIN_WINDOW_LOGICAL_SIZE[1]
}

fn restored_window_size(last: [f32; 2]) -> [f32; 2] {
    [
        last[0].max(MIN_WINDOW_LOGICAL_SIZE[0]),
        last[1].max(MIN_WINDOW_LOGICAL_SIZE[1]),
    ]
}

fn should_leave_tray_lightweight(
    lightweight: bool,
    minimized: bool,
    maximized: bool,
    size: Option<[f32; 2]>,
) -> bool {
    if !lightweight {
        return false;
    }
    maximized || !minimized || size.is_some_and(|size| !window_size_is_usable(size))
}

fn advance_overwrite_countdown(
    deadline: &mut Option<std::time::Instant>,
    paused_at: &mut Option<std::time::Instant>,
    now: std::time::Instant,
    foreground_focused: bool,
) -> bool {
    let Some(current_deadline) = *deadline else {
        *paused_at = None;
        return false;
    };
    if !foreground_focused {
        paused_at.get_or_insert(now);
        return false;
    }
    if let Some(paused) = paused_at.take() {
        *deadline = Some(current_deadline + now.saturating_duration_since(paused));
    }
    if deadline.is_some_and(|deadline| now >= deadline) {
        *deadline = None;
        return true;
    }
    false
}

fn fit_window_to_monitor(current: [f32; 2], monitor: [f32; 2]) -> [f32; 2] {
    let maximum = [
        (monitor[0] - WINDOWS_RUNTIME_MONITOR_ALLOWANCE[0]).max(1.0),
        (monitor[1] - WINDOWS_RUNTIME_MONITOR_ALLOWANCE[1]).max(1.0),
    ];
    [current[0].min(maximum[0]), current[1].min(maximum[1])]
}

fn should_clamp_window_to_monitor(current: [f32; 2], monitor: [f32; 2]) -> bool {
    if monitor[0] <= 0.0 || monitor[1] <= 0.0 || current[0] <= 0.0 || current[1] <= 0.0 {
        return false;
    }
    // Some Windows DPI reports expose the window size as the monitor size.
    if (monitor[0] - current[0]).abs() < 48.0 && (monitor[1] - current[1]).abs() < 48.0 {
        return false;
    }
    current[0] > monitor[0] || current[1] > monitor[1]
}

pub(crate) fn clamp_window_to_current_monitor(ctx: &egui::Context) {
    let viewport = ctx.input(|input| {
        let viewport = input.viewport();
        (
            viewport.monitor_size,
            viewport.inner_rect.map(|rect| rect.size()),
            viewport.maximized == Some(true),
            viewport.fullscreen == Some(true),
            viewport.minimized == Some(true),
        )
    });
    let (Some(monitor), Some(current), false, false, false) = viewport else {
        return;
    };
    if !should_clamp_window_to_monitor([current.x, current.y], [monitor.x, monitor.y]) {
        return;
    }
    let fitted = fit_window_to_monitor([current.x, current.y], [monitor.x, monitor.y]);
    if fitted[0] + 8.0 < current.x || fitted[1] + 8.0 < current.y {
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            fitted[0], fitted[1],
        )));
    }
}

#[cfg(windows)]
fn primary_work_area_logical_size() -> Option<[f32; 2]> {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
    use windows_sys::Win32::UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETWORKAREA};

    let mut work_area: RECT = unsafe { std::mem::zeroed() };
    let available = unsafe {
        SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut work_area as *mut RECT).cast(), 0)
    } != 0;
    let dpi = unsafe { GetDpiForSystem() };
    let width = work_area.right.saturating_sub(work_area.left);
    let height = work_area.bottom.saturating_sub(work_area.top);
    if !available || dpi == 0 || width <= 0 || height <= 0 {
        return None;
    }
    let points_per_pixel = 96.0 / dpi as f32;
    Some([
        width as f32 * points_per_pixel,
        height as f32 * points_per_pixel,
    ])
}

#[cfg(not(windows))]
fn primary_work_area_logical_size() -> Option<[f32; 2]> {
    None
}

fn stored_window_size(width: f32, height: f32) -> Option<[f32; 2]> {
    if (height - 720.0).abs() < 1.0
        && ((width - 860.0).abs() < 1.0 || (width - 980.0).abs() < 1.0)
    {
        return None;
    }
    let size = [width, height];
    window_size_is_usable(size).then_some(size)
}

fn initial_window_logical_size(compact: bool) -> [f32; 2] {
    initial_window_logical_size_from(compact, None)
}

fn initial_window_logical_size_from(compact: bool, stored: Option<[f32; 2]>) -> [f32; 2] {
    let preferred = if compact {
        COMPACT_WINDOW_LOGICAL_SIZE
    } else {
        stored.unwrap_or(DEFAULT_WINDOW_LOGICAL_SIZE)
    };
    let work_area =
        primary_work_area_logical_size().unwrap_or(WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE);
    fit_window_to_work_area(preferred, work_area)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Page {
    Welcome,
    Project,
    Auth,
    Model,
    Proxy,
    Finish,
    Dashboard,
    Profiles,
    OAuth,
    Monitor,
}

impl Page {
    fn is_setup_wizard(self) -> bool {
        matches!(
            self,
            Page::Welcome | Page::Project | Page::Auth | Page::Model | Page::Proxy | Page::Finish
        )
    }
}

fn terms_are_current(accept_compliance: bool, accepted_terms_version: &str) -> bool {
    accept_compliance && accepted_terms_version == CURRENT_TERMS_VERSION
}

fn runtime_probes_allowed(
    configured: bool,
    applying: bool,
    page: Page,
    terms_ok: bool,
) -> bool {
    configured && terms_ok && !applying && !page.is_setup_wizard()
}

fn initial_page_for_config(config: Option<&RouterConfig>) -> (Page, bool) {
    let configured = config.is_some_and(user_data::config_looks_configured);
    let page = if configured {
        Page::Dashboard
    } else {
        Page::Welcome
    };
    (page, configured)
}

fn codex_user_model_is_invalid_first(config: &RouterConfig) -> bool {
    let path = logic::resolve_codex_home(config).join("config.toml");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|document| {
            document
                .get("model")
                .and_then(toml_edit::Item::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|model| model.eq_ignore_ascii_case("first"))
}

fn router_mode_enabled_on_startup(
    prefer_router_mode: bool,
    official_mode_selected: bool,
    configured_router_mode: bool,
    configured: bool,
    has_models: bool,
    invalid_first_model: bool,
) -> bool {
    !official_mode_selected
        && (prefer_router_mode
            || configured_router_mode
            || configured && has_models && invalid_first_model)
}

fn recover_single_profile_binding(
    generate_isolation: bool,
    active_profile_id: &str,
    profiles: &[IsolationProfile],
) -> Option<String> {
    (generate_isolation && active_profile_id.trim().is_empty() && profiles.len() == 1)
        .then(|| profiles[0].id.clone())
}

#[derive(Clone, Debug)]
struct UiAuditOptions {
    scenario: String,
    language: String,
    theme: String,
    compact: bool,
    screenshot_path: Option<PathBuf>,
}

impl UiAuditOptions {
    fn from_args() -> Option<Self> {
        let arguments = std::env::args().collect::<Vec<_>>();
        let encoded = std::env::current_exe()
            .ok()
            .and_then(|path| path.file_stem().map(|value| value.to_owned()))
            .and_then(|value| value.to_str().map(str::to_owned))
            .and_then(|name| {
                name.to_ascii_lowercase()
                    .strip_prefix("codex-router-ui-audit__")
                    .map(|suffix| suffix.split("__").map(str::to_owned).collect::<Vec<_>>())
            });
        let scenario = arguments
            .iter()
            .find_map(|argument| {
                argument
                    .strip_prefix("--ui-audit=")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
            .or_else(|| encoded.as_ref().and_then(|items| items.first().cloned()))?;
        let value = |prefix: &str| {
            arguments.iter().find_map(|argument| {
                argument
                    .strip_prefix(prefix)
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
            })
        };
        let language = value("--ui-language=")
            .or_else(|| encoded.as_ref().and_then(|items| items.get(1).cloned()))
            .filter(|item| matches!(item.as_str(), "zh" | "en"))
            .unwrap_or_else(|| "zh".to_owned());
        let theme = value("--ui-theme=")
            .or_else(|| encoded.as_ref().and_then(|items| items.get(2).cloned()))
            .filter(|item| matches!(item.as_str(), "sky" | "coffee"))
            .unwrap_or_else(|| "sky".to_owned());
        let compact = arguments.iter().any(|argument| argument == "--ui-compact")
            || encoded
                .as_ref()
                .is_some_and(|items| items.iter().any(|item| item == "compact"));
        let screenshot_path = value("--ui-screenshot=").map(PathBuf::from);
        Some(Self {
            scenario,
            language,
            theme,
            compact,
            screenshot_path,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthModelSummary {
    id: String,
    display_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthAccountSummary {
    id: i64,
    name: String,
    platform: String,
    status: String,
    email: String,
    plan: String,
    priority: i32,
    bound_to_router: bool,
    error: String,
    expires_at: String,
    #[serde(default)]
    models: Vec<OAuthModelSummary>,
    #[serde(default)]
    models_error: String,
}

fn listed_api_model_ids(payload: &serde_json::Value) -> Vec<String> {
    let entries = payload
        .get("data")
        .and_then(serde_json::Value::as_array)
        .or_else(|| payload.get("models").and_then(serde_json::Value::as_array))
        .or_else(|| payload.as_array());
    let Some(entries) = entries else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for entry in entries {
        let raw = entry
            .get("id")
            .or_else(|| entry.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim();
        if raw.is_empty() {
            continue;
        }
        if !ids.iter().any(|seen: &String| seen.eq_ignore_ascii_case(raw)) {
            ids.push(raw.to_owned());
        }
    }
    ids
}

fn oauth_platform_matches(account_platform: &str, requested_provider: &str) -> bool {
    let normalize = |value: &str| match value.trim().to_ascii_lowercase().as_str() {
        "chatgpt" => "openai".to_owned(),
        "claude" => "anthropic".to_owned(),
        "xai" | "x-ai" => "grok".to_owned(),
        value => value.to_owned(),
    };
    normalize(account_platform) == normalize(requested_provider)
}

fn auto_enable_first_oauth_model(
    config: &mut RouterConfig,
    accounts: &[OAuthAccountSummary],
    provider: &str,
) -> Option<String> {
    if !config.models.is_empty() {
        return None;
    }
    let account = accounts.iter().find(|account| {
        account.bound_to_router
            && oauth_platform_matches(&account.platform, provider)
            && !account.models.is_empty()
    })?;
    let model = account.models.first()?;
    let model_id = if account.platform.eq_ignore_ascii_case("openai")
        && model.id.eq_ignore_ascii_case("gpt-5.6")
    {
        "gpt-5.6-sol".to_owned()
    } else {
        model.id.clone()
    };
    let display_name = if model.display_name.trim().is_empty() {
        model_id.clone()
    } else {
        model.display_name.clone()
    };
    config.models.push(ModelConfig {
        model: model_id,
        alias: display_name.clone(),
        alias_customized: Some(false),
        base_url: format!("Router OAuth / {}", account.platform),
        priority: config.oauth_fallback.official_priority,
        source: "oauth".to_owned(),
        oauth_account_id: account.id,
        oauth_platform: account.platform.clone(),
        user_selected: true,
        multimodal: "auto".to_owned(),
        ..Default::default()
    });
    let selected = config.oauth_account_ids.get_or_insert_with(Vec::new);
    if !selected.contains(&account.id) {
        selected.push(account.id);
    }
    logic::normalize_default_model(config);
    Some(display_name)
}

fn fallback_oauth_model_id(platform: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "openai" | "chatgpt" => "gpt-5.6-sol",
        "anthropic" | "claude" => "claude-sonnet-4-5",
        "gemini" => "gemini-3.1-pro",
        "antigravity" => "gemini-3.1-pro",
        "grok" | "xai" | "x-ai" => "grok-4.5",
        _ => "grok-4.5",
    }
}

fn oauth_catalog_model_id(platform: &str, model_id: &str) -> String {
    if platform.eq_ignore_ascii_case("openai") && model_id.eq_ignore_ascii_case("gpt-5.6") {
        "gpt-5.6-sol".to_owned()
    } else {
        model_id.to_owned()
    }
}

fn existing_oauth_pool_models<'a>(
    config: &'a RouterConfig,
    account: &OAuthAccountSummary,
) -> Vec<&'a ModelConfig> {
    config
        .models
        .iter()
        .filter(|existing| {
            existing.source == "oauth"
                && oauth_platform_matches(&existing.oauth_platform, &account.platform)
        })
        .collect()
}

fn push_oauth_model_channel(
    config: &mut RouterConfig,
    account: &OAuthAccountSummary,
    model_id: String,
    display_name: String,
    template: Option<&ModelConfig>,
) -> bool {
    if config.models.iter().any(|existing| {
        existing.source == "oauth"
            && existing.oauth_account_id == account.id
            && logic::canonical_route_model_id(&existing.model)
                == logic::canonical_route_model_id(&model_id)
    }) {
        return false;
    }
    let mut channel = template.cloned().unwrap_or_else(|| ModelConfig {
        alias_customized: Some(false),
        base_url: format!("Router OAuth / {}", account.platform),
        priority: config.oauth_fallback.official_priority,
        source: "oauth".to_owned(),
        user_selected: true,
        multimodal: "auto".to_owned(),
        ..Default::default()
    });
    channel.model = model_id;
    if template.is_none() || template.is_some_and(|item| item.alias_customized != Some(true)) {
        channel.alias = display_name;
        channel.alias_customized = Some(false);
    }
    channel.source = "oauth".to_owned();
    channel.oauth_account_id = account.id;
    channel.oauth_platform = account.platform.clone();
    channel.user_selected = true;
    if channel.base_url.trim().is_empty() {
        channel.base_url = format!("Router OAuth / {}", account.platform);
    }
    config.models.push(channel);
    true
}

fn import_oauth_account_default_model(
    config: &mut RouterConfig,
    account: &OAuthAccountSummary,
) -> Option<String> {
    if !account.bound_to_router {
        return None;
    }
    let selected = config.oauth_account_ids.get_or_insert_with(Vec::new);
    if !selected.contains(&account.id) {
        selected.push(account.id);
    }

    let pool_models = existing_oauth_pool_models(config, account)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut imported = Vec::new();

    if !pool_models.is_empty() {
        // Same provider pool: attach this account to every existing route card
        // (Grok 4.5 + Grok 4.6 share the three-account pool).
        for template in &pool_models {
            if push_oauth_model_channel(
                config,
                account,
                template.model.clone(),
                template.alias.clone(),
                Some(template),
            ) {
                imported.push(template.alias.clone());
            }
        }
    }

    let catalog: Vec<(String, String)> = if account.models.is_empty() {
        if pool_models.is_empty() {
            let model_id = fallback_oauth_model_id(&account.platform).to_owned();
            vec![(model_id.clone(), model_id)]
        } else {
            Vec::new()
        }
    } else {
        account
            .models
            .iter()
            .map(|model| {
                let model_id = oauth_catalog_model_id(&account.platform, &model.id);
                let display_name = if model.display_name.trim().is_empty() {
                    model_id.clone()
                } else {
                    model.display_name.clone()
                };
                (model_id, display_name)
            })
            .collect()
    };

    for (model_id, display_name) in catalog {
        let template = pool_models
            .iter()
            .find(|existing| {
                logic::canonical_route_model_id(&existing.model)
                    == logic::canonical_route_model_id(&model_id)
            })
            .cloned();
        if push_oauth_model_channel(
            config,
            account,
            model_id,
            display_name.clone(),
            template.as_ref(),
        ) {
            imported.push(display_name);
        }
    }

    if imported.is_empty() {
        return None;
    }
    logic::normalize_default_model(config);
    imported.sort();
    imported.dedup();
    Some(imported.join("、"))
}

fn auto_import_new_oauth_models(
    config: &mut RouterConfig,
    accounts: &[OAuthAccountSummary],
    provider: Option<&str>,
    previous_ids: &[i64],
) -> Vec<String> {
    let mut imported = Vec::new();
    for account in accounts {
        if !account.bound_to_router {
            continue;
        }
        if previous_ids.contains(&account.id) {
            continue;
        }
        if let Some(requested) = provider {
            if !oauth_platform_matches(&account.platform, requested) {
                continue;
            }
        }
        if let Some(name) = import_oauth_account_default_model(config, account) {
            imported.push(name);
        }
    }
    imported
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageModelSummary {
    #[serde(default)]
    name: String,
    #[serde(default)]
    requests: i64,
    #[serde(default)]
    input_tokens: i64,
    #[serde(default)]
    output_tokens: i64,
    #[serde(default)]
    cache_read_tokens: i64,
    #[serde(default)]
    cache_creation_tokens: i64,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    cost: f64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageTotals {
    #[serde(default)]
    requests: i64,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    cost: f64,
    #[serde(default)]
    models: Vec<UsageModelSummary>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageWindow {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    used_percent: Option<f32>,
    #[serde(default)]
    reset_at: String,
    #[serde(default = "negative_one")]
    remaining_seconds: i64,
    #[serde(default)]
    requests: i64,
    #[serde(default)]
    tokens: i64,
    #[serde(default)]
    remaining_amount: Option<f64>,
    #[serde(default)]
    limit_amount: Option<f64>,
    #[serde(default)]
    used_amount: Option<f64>,
    #[serde(default)]
    currency: String,
}

fn negative_one() -> i64 {
    -1
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageAccount {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    health: String,
    #[serde(default)]
    status_detail: String,
    #[serde(default)]
    query_note: String,
    #[serde(default)]
    last_used_at: String,
    #[serde(default)]
    updated_at: String,
    #[serde(default)]
    totals: UsageTotals,
    #[serde(default)]
    windows: Vec<UsageWindow>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageSnapshot {
    #[serde(default)]
    profile_name: String,
    #[serde(default)]
    queried_at: String,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    total_requests: i64,
    #[serde(default)]
    total_cost: f64,
    #[serde(default)]
    subscriptions: Vec<UsageAccount>,
    #[serde(default)]
    api_channels: Vec<UsageAccount>,
    /// True when the usage pass changed OAuth schedulability or recovery
    /// state and the backend routing table must be synchronized. This is an
    /// internal signal; it never requires rewriting Codex config.toml.
    #[serde(default)]
    routing_changed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageMonitorCache {
    profile_key: String,
    snapshot: UsageSnapshot,
}

fn fallback_transition_notification(
    previous: Option<&UsageSnapshot>,
    current: &UsageSnapshot,
    config: &RouterConfig,
) -> Option<(i64, String, String)> {
    for subscription in &current.subscriptions {
        let Some(previous) = previous else {
            // Startup has no prior snapshot. Already-exhausted accounts must
            // not pop as if they just ran out.
            continue;
        };
        if subscription.health != "quotaExhausted"
            || previous.subscriptions.iter().any(|account| {
                account.id == subscription.id && account.health == "quotaExhausted"
            })
        {
            continue;
        }
        let oauth_models = config
            .models
            .iter()
            .filter(|model| model.source == "oauth" && model.oauth_account_id == subscription.id);
        for oauth_model in oauth_models {
            if let Some(fallback) = config
                .models
                .iter()
                .filter(|candidate| {
                    candidate.source != "oauth"
                        && logic::same_model_identity(&oauth_model.model, &candidate.model)
                        && logic::is_eligible_oauth_api_fallback(config, oauth_model, candidate)
                })
                .min_by_key(|candidate| candidate.priority)
            {
                let source = if subscription.name.trim().is_empty() {
                    logic::recommended_model_display_name(&oauth_model.model)
                } else {
                    subscription.name.trim().to_owned()
                };
                let target = if fallback.alias.trim().is_empty() {
                    logic::recommended_model_display_name(&fallback.model)
                } else {
                    fallback.alias.trim().to_owned()
                };
                return Some((subscription.id, source, target));
            }
        }
    }
    None
}

fn failover_account_id(record: &str) -> Option<i64> {
    if !record.contains("openai.upstream_failover_switching")
        || !(record.contains("upstream_status=402") || record.contains("upstream_status=429"))
    {
        return None;
    }
    record.split_whitespace().find_map(|field| {
        field
            .strip_prefix("account_id=")
            .and_then(|value| value.trim_end_matches('|').parse().ok())
    })
}

fn fallback_names_for_account(
    config: &RouterConfig,
    oauth_accounts: &[OAuthAccountSummary],
    account_id: i64,
) -> Option<(String, String)> {
    let oauth_model = config
        .models
        .iter()
        .find(|model| model.source == "oauth" && model.oauth_account_id == account_id)?;
    let fallback = config
        .models
        .iter()
        .filter(|candidate| {
            candidate.source != "oauth"
                && logic::same_model_identity(&oauth_model.model, &candidate.model)
                && logic::is_eligible_oauth_api_fallback(config, oauth_model, candidate)
        })
        .min_by_key(|candidate| candidate.priority)?;
    let source = oauth_accounts
        .iter()
        .find(|account| account.id == account_id)
        .map(|account| account.name.trim())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| logic::recommended_model_display_name(&oauth_model.model));
    let target = if fallback.alias.trim().is_empty() {
        logic::recommended_model_display_name(&fallback.model)
    } else {
        fallback.alias.trim().to_owned()
    };
    Some((source, target))
}

fn show_fallback_notification(zh: bool, source: String, target: String) {
    let title = if zh {
        "Codex-Router 已自动切换"
    } else {
        "Codex-Router switched automatically"
    }
    .to_owned();
    let description = if zh {
        format!("{source} 订阅额度已用完，现在已自动切换到 {target} 渠道。")
    } else {
        format!("The {source} subscription quota is exhausted. Routing switched automatically to {target}.")
    };
    std::thread::spawn(move || {
        let _ = rfd::MessageDialog::new()
            .set_title(&title)
            .set_description(&description)
            .set_level(rfd::MessageLevel::Info)
            .show();
    });
}

/// Detect an OAuth subscription that recovered from quota exhaustion and has
/// rejoined the preferred routing path. Returns (account_id, name). The
/// account must have been non-healthy in the previous snapshot to avoid
/// popping for accounts that were always healthy.
fn rejoined_account_notification(
    previous: Option<&UsageSnapshot>,
    current: &UsageSnapshot,
) -> Option<(i64, String)> {
    let previous = previous?;
    for subscription in &current.subscriptions {
        if subscription.health != "healthy" {
            continue;
        }
        let previous_account = previous
            .subscriptions
            .iter()
            .find(|account| account.id == subscription.id)?;
        // A local schedulable flip also makes the account look healthy. It is
        // not a provider quota recovery, especially for ChatGPT Desktop
        // where recover-state intentionally performs no upstream probe.
        let was_recovering = previous_account.health == "quotaExhausted"
            && quota_windows_recovered(previous_account, subscription);
        if was_recovering {
            let name = if subscription.name.trim().is_empty() {
                subscription.platform.trim().to_owned()
            } else {
                subscription.name.trim().to_owned()
            };
            return Some((subscription.id, name));
        }
    }
    None
}

fn quota_windows_recovered(previous: &UsageAccount, current: &UsageAccount) -> bool {
    let provider = previous.platform.trim().to_ascii_lowercase();
    if !matches!(provider.as_str(), "openai" | "chatgpt") {
        // Providers without quota windows have no stronger signal available;
        // keep the historical health transition behavior for those accounts.
        return true;
    }
    // Desktop OpenAI can report a local healthy state while the quota query
    // is stale or unavailable. Missing windows therefore cannot confirm a
    // provider-side recovery.
    if previous.windows.is_empty() || current.windows.is_empty() {
        return false;
    }

    previous.windows.iter().any(|old_window| {
        let was_full = old_window
            .used_percent
            .is_some_and(|value| value >= 99.999);
        if !was_full {
            return false;
        }
        current.windows.iter().any(|new_window| {
            new_window.kind == old_window.kind
                && (new_window
                    .used_percent
                    .is_some_and(|value| value < 99.999)
                    || (!old_window.reset_at.trim().is_empty()
                        && old_window.reset_at != new_window.reset_at))
        })
    })
}

fn show_rejoined_pool_notification(zh: bool, name: String) {
    let title = if zh {
        "Codex-Router 账号已回归号池"
    } else {
        "Codex-Router account rejoined the pool"
    }
    .to_owned();
    let description = if zh {
        format!("账号「{name}」额度已恢复，已重新加入号池，优先走订阅路由。")
    } else {
        format!(
            "Account '{name}' quota recovered and rejoined the pool; it is preferred again for routing."
        )
    };
    std::thread::spawn(move || {
        let _ = rfd::MessageDialog::new()
            .set_title(&title)
            .set_description(&description)
            .set_level(rfd::MessageLevel::Info)
            .show();
    });
}

/// Parse a Router Host pool-failover event into (from_pool, reason).
/// Record looks like: "[Router events] ... event=request.pool_failover |
/// from_pool=cr/r10a56/xai | reason=auth_unavailable".
fn pool_failover_parts(record: &str) -> Option<(String, String)> {
    if !record.contains("event=request.pool_failover") {
        return None;
    }
    let from_pool = record.split_whitespace().find_map(|field| {
        field
            .strip_prefix("from_pool=")
            .map(|value| value.trim_end_matches('|').to_owned())
    })?;
    let reason = record
        .split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix("reason=")
                .map(|value| value.trim_end_matches('|').to_owned())
        })
        .unwrap_or_else(|| "pool_exhausted".to_owned());
    Some((from_pool, reason))
}

/// True when a Router Host event reports that every pool for a model is
/// currently unavailable (no auth available at all).
fn pool_unavailable_model(record: &str) -> Option<String> {
    if !record.contains("event=request.pool_unavailable") {
        return None;
    }
    record.split_whitespace().find_map(|field| {
        field
            .strip_prefix("model=")
            .map(|value| value.trim_end_matches('|').to_owned())
    })
}

/// Extract an OAuth account id from a pool id like `cr/r10a56/xai` where the
/// route segment is `r{route}a{account}`.
fn account_id_from_pool_id(pool_id: &str) -> Option<i64> {
    let route = pool_id.split('/').nth(1)?;
    let account = route.strip_prefix('r')?;
    let account = account.split('a').next_back()?;
    if account.is_empty() || account.chars().any(|character| !character.is_ascii_digit()) {
        return None;
    }
    account.parse().ok()
}

fn pool_account_label(oauth_accounts: &[OAuthAccountSummary], pool_id: &str) -> String {
    account_id_from_pool_id(pool_id)
        .and_then(|id| {
            oauth_accounts
                .iter()
                .find(|account| account.id == id)
                .map(|account| account.name.clone())
        })
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| pool_id.to_owned())
}

fn show_pool_switch_notification(zh: bool, from_label: String, reason: String) {
    let title = if zh {
        "Codex-Router 已自动切换账号"
    } else {
        "Codex-Router switched account"
    }
    .to_owned();
    let reason_text = match reason.as_str() {
        "auth_unavailable" if zh => "认证不可用",
        "auth_unavailable" => "auth unavailable",
        _ if zh => "额度或限流耗尽",
        _ => "quota exhausted",
    };
    let description = if zh {
        format!(
            "账号「{from_label}」不可用（{reason_text}），已自动切换到下一个可用账号。"
        )
    } else {
        format!(
            "Account '{from_label}' is unavailable ({reason_text}); routing switched to the next available account."
        )
    };
    std::thread::spawn(move || {
        let _ = rfd::MessageDialog::new()
            .set_title(&title)
            .set_description(&description)
            .set_level(rfd::MessageLevel::Info)
            .show();
    });
}

fn show_pool_unavailable_notification(zh: bool, model: String) {
    let title = if zh {
        "Codex-Router 账号池不可用"
    } else {
        "Codex-Router pool unavailable"
    }
    .to_owned();
    let description = if zh {
        format!(
            "模型 {model} 的所有可用账号当前都不可用（没有可用认证）。请检查账号额度，或重新导入 / 启用账号后再试。"
        )
    } else {
        format!(
            "All accounts serving {model} are currently unavailable (no auth available). Please check quota or re-import / enable an account."
        )
    };
    std::thread::spawn(move || {
        let _ = rfd::MessageDialog::new()
            .set_title(&title)
            .set_description(&description)
            .set_level(rfd::MessageLevel::Warning)
            .show();
    });
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthRecoverySchedule {
    #[serde(default = "default_oauth_recovery_seconds")]
    #[allow(dead_code)]
    next_check_seconds: u64,
    #[serde(default)]
    summary: String,
}

fn default_oauth_recovery_seconds() -> u64 {
    OAUTH_RECOVERY_MAX_INTERVAL.as_secs()
}

fn oauth_recovery_schedule_delay(next_check_seconds: u64) -> Option<std::time::Duration> {
    (next_check_seconds > 0).then(|| {
        std::time::Duration::from_secs(next_check_seconds.clamp(
            BACKGROUND_SELF_CHECK_INTERVAL.as_secs(),
            OAUTH_RECOVERY_MAX_INTERVAL.as_secs(),
        ))
    })
}

const OAUTH_RECOVERY_BUSY_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const OAUTH_ACCOUNT_BUSY_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default)]
struct AdminTaskActivity {
    applying: bool,
    router_mode_switching: bool,
    usage_loading: bool,
    oauth_loading: bool,
    routing_sync_running: bool,
    health_probe_running: bool,
    health_recovery_running: bool,
    provider_oauth_preparing: bool,
    provider_oauth_running: bool,
    oauth_recovery_running: bool,
}

fn scheduled_oauth_recovery_can_start(activity: AdminTaskActivity) -> bool {
    !activity.applying
        && !activity.router_mode_switching
        && !activity.usage_loading
        && !activity.oauth_loading
        && !activity.routing_sync_running
        && !activity.health_probe_running
        && !activity.health_recovery_running
        && !activity.provider_oauth_preparing
        && !activity.provider_oauth_running
}

fn oauth_account_refresh_can_start(activity: AdminTaskActivity) -> bool {
    !activity.oauth_recovery_running
        && !activity.routing_sync_running
        && !activity.applying
        && !activity.router_mode_switching
        && !activity.health_recovery_running
}

fn next_background_usage_refresh(now: std::time::Instant) -> std::time::Instant {
    now + BACKGROUND_USAGE_REFRESH_INTERVAL
}

fn queue_oauth_catalog_refresh(pending: &mut bool) {
    *pending = true;
}

fn queue_self_check_account_maintenance(
    oauth_catalog_refresh_pending: &mut bool,
    quota_refresh_pending: &mut bool,
) {
    queue_oauth_catalog_refresh(oauth_catalog_refresh_pending);
    *quota_refresh_pending = true;
}

fn scheduled_usage_refresh_is_due(
    _tray_lightweight_mode: bool,
    due: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    due.is_some_and(|due| now >= due)
}

fn next_failed_oauth_recovery(now: std::time::Instant) -> std::time::Instant {
    now + BACKGROUND_SELF_CHECK_INTERVAL
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackgroundOAuthSyncAction {
    None,
    LiveRouterOnly,
}

fn background_oauth_sync_action(
    router_mode_enabled: bool,
    applying: bool,
    router_mode_switching: bool,
) -> BackgroundOAuthSyncAction {
    if router_mode_enabled && !applying && !router_mode_switching {
        BackgroundOAuthSyncAction::LiveRouterOnly
    } else {
        BackgroundOAuthSyncAction::None
    }
}

#[derive(Clone)]
struct ApplyUiRollback {
    config: RouterConfig,
    active_profile_id: String,
    pending_profile_activation: Option<String>,
    configured: bool,
    router_mode_enabled: bool,
}

#[derive(Clone)]
struct ApplyTransactionBackup {
    point: profiles::RestorePoint,
    config: RouterConfig,
}

enum AppEvent {
    Log(String),
    ExitShutdownFinished(Result<(), String>),
    AutostartFinished {
        enabled: bool,
        rollback_to: Option<bool>,
        result: Result<(), String>,
    },
    Complete,
    Error(String),
    Tray(TrayAction),
    OAuthAccountsLoaded(Vec<OAuthAccountSummary>),
    OAuthAccountsError(String),
    ProviderOAuthPrepared {
        provider: String,
        generation: u64,
    },
    ProviderOAuthPrepareError {
        provider: String,
        generation: u64,
        error: String,
    },
    ProviderOAuthPrompt {
        prompt: logic::oauth::Prompt,
        response: Sender<logic::oauth::PromptResponse>,
    },
    ProviderOAuthFinished,
    ProviderOAuthError(String),
    UsageLoaded {
        profile_key: String,
        generation: u64,
        snapshot: Box<UsageSnapshot>,
    },
    UsageError {
        profile_key: String,
        generation: u64,
        error: String,
    },
    PreviousConfigurationRestored {
        config: Box<RouterConfig>,
        outcome: profiles::RestoreOutcome,
        label: String,
    },
    PreviousConfigurationRestoreError(String),
    RouterModeDisabled(profiles::RestoreOutcome),
    RouterModeSwitchError(String),
    OAuthRecoveryFinished(OAuthRecoverySchedule),
    OAuthRecoveryError(String),
    GrokSsoImported,
    GrokSsoImportError(String),
    OAuthAccountRevoked {
        account_id: i64,
        account_name: String,
    },
    OAuthAccountRevokeError(String),
    OAuthAccountPriorityUpdated {
        account_id: i64,
        priority: i32,
    },
    OAuthAccountPriorityError(String),
    ApiModelValidationFinished {
        model: Box<ModelConfig>,
        editing_model: Option<usize>,
        model_from_wizard: bool,
        result: Result<(), String>,
        available_models: Vec<String>,
    },
    UpdateProgress(updater::DownloadProgress),
    UpdateResult(Box<GitHubUpdateInfo>),
    UpdateError(String),
    RouterHealthProbeFinished(Result<(), String>),
    RouterHealthRecoveryFinished(Result<(), String>),
    RoutingSyncFinished(Result<(), String>),
    /// Self-check overwrite detection: `Some(fingerprint)` means Codex's
    /// config.toml was overwritten by an external program and needs a user
    /// decision instead of the old silent auto-repair.
    CodexBindingProbeFinished(Result<logic::codex_toml::CodexBindingProbe, String>),
    /// Factory-reset from the overwrite prompt; bool = valid ChatGPT login
    /// still available afterwards.
    CodexFactoryResetFinished(Result<bool, String>),
}

struct ProviderOAuthPromptState {
    prompt: logic::oauth::Prompt,
    response: Sender<logic::oauth::PromptResponse>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResultDialogKind {
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrayAction {
    RestoreWindow,
    HideWindow,
    OpenConsole,
    ChooseProfile,
    ApplyCurrent,
    StartForwarding,
    StopForwarding,
    Exit,
}

fn set_api_model_protocol(model: &mut ModelConfig, protocol: logic::UpstreamProtocol) {
    let mut extra = serde_json::from_str::<serde_json::Value>(&model.extra)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    extra.insert(
        "openai_responses_mode".to_owned(),
        serde_json::Value::String(protocol.responses_mode().to_owned()),
    );
    extra.insert(
        "codex_router_upstream_protocol".to_owned(),
        serde_json::Value::String(protocol.as_str().to_owned()),
    );
    model.extra = serde_json::to_string(&extra).unwrap_or_else(|_| "{}".to_owned());
}

/// 添加 API 模型时是否值得换一种协议再探一次。
/// 401/403/429/超时/网络错误换协议也救不了，直接返回才能给出准确原因；
/// 只有 404/5xx/其它 HTTP 异常才说明“这个协议不通，换一个试试”。
fn api_probe_should_try_alternative(code: &str) -> bool {
    matches!(
        code,
        "probe_not_found" | "probe_upstream" | "probe_http"
    )
}

fn validate_api_model_connection(
    cfg: &RouterConfig,
    model: &mut ModelConfig,
) -> Result<(), String> {
    let base = reqwest::Url::parse(model.base_url.trim()).map_err(|_| "invalid_url".to_owned())?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err("invalid_url".to_owned());
    }
    let mut models_url = base.clone();
    models_url.set_path(&format!("{}/models", base.path().trim_end_matches('/')));
    models_url.set_query(None);
    models_url.set_fragment(None);

    let api_key = if !model.api_key.trim().is_empty() {
        Zeroizing::new(model.api_key.trim().to_owned())
    } else if !model.credential_name.trim().is_empty() {
        logic::read_router_credential_text(&model.credential_name)
            .map_err(|_| "credential_read".to_owned())?
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "credential_missing".to_owned())?
    } else {
        return Err("credential_missing".to_owned());
    };

    let runtime = logic::resolve_proxy_runtime(cfg).map_err(|_| "proxy_config".to_owned())?;
    let target = model.base_url.trim().trim_end_matches('/');
    let policy = runtime.targets.get(target);
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(API_MODEL_VALIDATION_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if policy.is_some_and(|policy| policy.bypass) || runtime.settings.proxy_url.is_none() {
        builder = builder.no_proxy();
    } else if let Some(proxy_url) = runtime.settings.proxy_url.as_deref() {
        builder = builder.proxy(
            reqwest::Proxy::all(proxy_url).map_err(|_| "proxy_config".to_owned())?,
        );
    }
    let client = builder.build().map_err(|_| "client_build".to_owned())?;
    let response = client
        .get(models_url)
        .bearer_auth(api_key.as_str())
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                "timeout".to_owned()
            } else if error.is_connect() {
                "network".to_owned()
            } else {
                "request".to_owned()
            }
        })?;
    match response.status().as_u16() {
        200..=299 => {}
        401 => return Err("unauthorized".to_owned()),
        403 => return Err("forbidden".to_owned()),
        404 => return Err("models_not_found".to_owned()),
        429 => return Err("rate_limited".to_owned()),
        500..=599 => return Err("upstream".to_owned()),
        _ => return Err("http".to_owned()),
    }
    let payload = response
        .json::<serde_json::Value>()
        .map_err(|_| "invalid_response".to_owned())?;
    let ids = listed_api_model_ids(&payload);
    if ids.is_empty()
        && payload
            .get("data")
            .and_then(serde_json::Value::as_array)
            .or_else(|| payload.get("models").and_then(serde_json::Value::as_array))
            .or_else(|| payload.as_array())
            .is_none()
    {
        return Err("invalid_response".to_owned());
    }
    let expected = logic::canonical_route_model_id(&model.model);
    if !ids
        .iter()
        .any(|id| logic::canonical_route_model_id(id) == expected)
    {
        return Err(if ids.is_empty() {
            "model_missing".to_owned()
        } else {
            format!("model_missing:{}", ids.join("\n"))
        });
    }

    let probe = |protocol: logic::UpstreamProtocol| -> Result<(), String> {
        let (probe_path, probe_body) = match protocol {
            logic::UpstreamProtocol::Responses => (
            "responses",
            // 注意：不要带 max_output_tokens。部分推理网关（含 opencode Go 的
            // muse-spark）在极小输出预算下直接回 5xx；"ping" 的回包本身只有几个 token。
            serde_json::json!({
                "model": model.model.trim(),
                "input": "ping",
                "stream": false,
            }),
        ),
            logic::UpstreamProtocol::ChatCompletions | logic::UpstreamProtocol::Anthropic => (
            "chat/completions",
            serde_json::json!({
                "model": model.model.trim(),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                "stream": false,
            }),
            ),
        };
        let mut probe_url = base.clone();
        probe_url.set_path(&format!(
            "{}/{probe_path}",
            probe_url.path().trim_end_matches('/')
        ));
        probe_url.set_query(None);
        probe_url.set_fragment(None);
        let response = client
            .post(probe_url)
            .bearer_auth(api_key.as_str())
            // 部分网关（opencode Go 会监控滥用流量）要求客户端自标识，
            // 带上固定 UA 和标题，避免被当成匿名批量流量。
            .header("User-Agent", format!("Codex-Router/{APP_VERSION}"))
            .header("X-Title", "Codex-Router")
            .json(&probe_body)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    "timeout".to_owned()
                } else if error.is_connect() {
                    "network".to_owned()
                } else {
                    "request".to_owned()
                }
            })?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 => Err("unauthorized".to_owned()),
            403 => Err("forbidden".to_owned()),
            404 => Err("probe_not_found".to_owned()),
            429 => Err("rate_limited".to_owned()),
            500..=599 => Err("probe_upstream".to_owned()),
            _ => Err("probe_http".to_owned()),
        }
    };
    // 添加模型固定先探 /responses：通了就按 responses 保存；
    // 只有 404/5xx/其它 HTTP 异常才回落到 /chat/completions 再探，通了按 chat 保存。
    // 两种协议对应互斥的 wire_api，探通哪个就存哪个，避免运行时再猜一次。
    // 401/403/429/超时/网络错误直接返回，换协议也救不了，还能保留准确的错误原因。
    let probe_order = [
        logic::UpstreamProtocol::Responses,
        logic::UpstreamProtocol::ChatCompletions,
    ];
    match probe(probe_order[0]) {
        Ok(()) => {
            set_api_model_protocol(model, probe_order[0]);
            Ok(())
        }
        Err(first_error) if api_probe_should_try_alternative(&first_error) => {
            probe(probe_order[1])?;
            set_api_model_protocol(model, probe_order[1]);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn split_model_missing_code(code: &str) -> (&str, Vec<String>) {
    if let Some(rest) = code.strip_prefix("model_missing:") {
        (
            "model_missing",
            rest.split('\n')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        )
    } else {
        (code, Vec::new())
    }
}

fn api_model_validation_message(code: &str, zh: bool) -> &'static str {
    match (code, zh) {
        ("invalid_url", true) => "Base URL 无效，请填写完整的 http/https 地址",
        ("invalid_url", false) => "The Base URL is not a valid HTTP/HTTPS address",
        ("credential_missing" | "credential_read", true) => {
            "API Key 不存在或无法从 Windows 凭据管理器读取"
        }
        ("credential_missing" | "credential_read", false) => {
            "The API key is missing or could not be read from Credential Manager"
        }
        ("unauthorized", true) => "API Key 验证失败（HTTP 401）",
        ("unauthorized", false) => "The API key was rejected (HTTP 401)",
        ("forbidden", true) => "该账号无权访问模型接口（HTTP 403）",
        ("forbidden", false) => "The account cannot access the models endpoint (HTTP 403)",
        ("models_not_found", true) => "Base URL 没有提供 /models 接口（HTTP 404）",
        ("models_not_found", false) => "The Base URL has no /models endpoint (HTTP 404)",
        ("probe_not_found", true) => "模型已列出，但实际生成接口不存在（HTTP 404）",
        ("probe_not_found", false) => {
            "The model was listed, but its generation endpoint returned HTTP 404"
        }
        ("probe_upstream", true) => "模型已列出，但实际调用时上游返回 HTTP 5xx",
        ("probe_upstream", false) => {
            "The model was listed, but an actual request returned HTTP 5xx"
        }
        ("model_missing", true) => "连接成功，但模型列表中没有填写的模型 ID",
        ("model_missing", false) => "Connected, but the configured model ID was not listed",
        ("rate_limited", true) => "接口当前被限流（HTTP 429），请稍后重试",
        ("rate_limited", false) => "The endpoint is rate limited (HTTP 429); try again later",
        ("upstream", true) => "上游服务当前不可用（HTTP 5xx）",
        ("upstream", false) => "The upstream service is unavailable (HTTP 5xx)",
        ("timeout", true) => "连接测试超时，请检查网络、VPN 或代理",
        ("timeout", false) => "The connection test timed out; check the network, VPN, or proxy",
        ("network", true) => "无法连接或解析 Base URL，请检查校园网、VPN、DNS 或代理",
        ("network", false) => {
            "Could not resolve or connect to the Base URL; check VPN, DNS, or proxy"
        }
        ("proxy_config", true) => "代理配置无效，无法执行连接测试",
        ("proxy_config", false) => "The proxy configuration is invalid",
        (_, true) => "API 返回格式不兼容或连接测试失败",
        (_, false) => "The API response is incompatible or the connection test failed",
    }
}

struct CodexRouterApp {
    ui_audit_mode: bool,
    ui_audit_screenshot_path: Option<PathBuf>,
    ui_audit_frame_count: u8,
    ui_audit_screenshot_requested: bool,
    page: Page,
    router_root: PathBuf,
    project_path_input: String,
    config: RouterConfig,
    temp_model: ModelConfig,
    editing_model: Option<usize>,
    model_from_wizard: bool,
    api_model_validation_running: bool,
    api_model_choice_open: bool,
    api_model_choice_ids: Vec<String>,
    api_model_choice_model: Option<Box<ModelConfig>>,
    api_model_choice_editing: Option<usize>,
    api_model_choice_from_wizard: bool,
    proxy_from_wizard: bool,
    status_text: String,
    status_expires_at: Option<std::time::Instant>,
    logs: String,
    event_rx: Receiver<AppEvent>,
    event_tx: Sender<AppEvent>,
    runtime_log_rx: Receiver<runtime_logs::RuntimeLogBatch>,
    applying: bool,
    apply_cancel: Arc<AtomicBool>,
    apply_settle_until: Option<std::time::Instant>,
    configured: bool,
    logo_texture: Option<egui::TextureHandle>,
    fonts_loaded: bool,
    /// Throttles CJK font reinstall retries after a transient read failure.
    fonts_retry_after: Option<std::time::Instant>,
    tray_icon: Option<tray_icon::TrayIcon>,
    last_page: Page,
    profiles_return_page: Page,
    page_changed_at: std::time::Instant,
    installed_theme: String,
    installed_compact_layout: bool,
    ui_language: String,
    terms_open: bool,
    terms_scroll_complete: bool,
    terms_scroll_reset_pending: bool,
    advanced_json_open: bool,
    advanced_json_draft: String,
    reasoning_open: bool,
    reasoning_mode_draft: String,
    reasoning_levels_draft: String,
    reasoning_default_draft: String,
    reasoning_fast_supported_draft: bool,
    reasoning_fast_mode_draft: bool,
    close_behavior: CloseBehavior,
    autostart_switching: bool,
    close_prompt_open: bool,
    apply_success_dialog_open: bool,
    apply_success_is_subscription: bool,
    result_dialog_open: bool,
    result_dialog_kind: ResultDialogKind,
    result_dialog_title: String,
    result_dialog_body: String,
    remember_close_choice: bool,
    exit_after_prompt: bool,
    exit_shutdown_in_progress: bool,
    exit_shutdown_error: String,
    local_profile_name_input: String,
    isolation_profiles: Vec<IsolationProfile>,
    active_profile_id: String,
    pending_profile_activation: Option<String>,
    profile_delete_target: Option<IsolationProfile>,
    profile_create_open: bool,
    pending_apply_rollback: Option<ApplyUiRollback>,
    oauth_accounts: Vec<OAuthAccountSummary>,
    oauth_loading: bool,
    oauth_catalog_refresh_pending: bool,
    oauth_error: String,
    oauth_retry_due: Option<std::time::Instant>,
    oauth_retry_attempts: u8,
    oauth_return_page: Page,
    oauth_provider_draft: String,
    provider_oauth_running: bool,
    oauth_post_login_prompt_open: bool,
    oauth_model_hint_seen: bool,
    pending_oauth_provider: Option<String>,
    oauth_auto_enable_provider: Option<String>,
    oauth_in_flight_provider: Option<String>,
    oauth_known_account_ids: Vec<i64>,
    oauth_success_pending: bool,
    provider_oauth_preparing: bool,
    provider_oauth_preparing_provider: Option<String>,
    provider_oauth_prepare_generation: u64,
    provider_oauth_prepared_provider: Option<String>,
    provider_oauth_prepare_error: String,
    provider_oauth_prepare_cancel: Arc<AtomicBool>,
    provider_oauth_cancel: Arc<AtomicBool>,
    provider_oauth_prompt: Option<ProviderOAuthPromptState>,
    provider_oauth_code_draft: String,
    provider_oauth_gemini_code_assist: bool,
    provider_oauth_project_draft: String,
    oauth_revoke_target: Option<OAuthAccountSummary>,
    oauth_revoke_candidates: Vec<OAuthAccountSummary>,
    oauth_revoking: bool,
    oauth_priority_target: Option<OAuthAccountSummary>,
    oauth_priority_draft: i32,
    oauth_priority_saving: bool,
    oauth_fallback_picker_target: Option<OAuthAccountSummary>,
    oauth_fallback_picker_draft: BTreeMap<String, Option<Vec<String>>>,
    model_route_policy_target: Option<usize>,
    model_route_policy_draft: logic::ModelRoutePolicy,
    model_priority_dialog_target: Option<String>,
    model_priority_order: Vec<usize>,
    usage_snapshot: Option<UsageSnapshot>,
    usage_snapshot_profile_key: String,
    usage_loading: bool,
    usage_request_generation: u64,
    usage_error: String,
    usage_return_page: Page,
    usage_refresh_due: Option<std::time::Instant>,
    self_check_quota_refresh_pending: bool,
    notified_quota_accounts: BTreeSet<i64>,
    /// False until the first usage snapshot is applied. Startup must not pop
    /// quota dialogs for accounts that were already exhausted.
    usage_notifications_ready: bool,
    /// De-duplicates the "switched account" popup so one dead pool does not
    /// spawn a notification on every retried request.
    notified_pool_failovers: BTreeSet<String>,
    /// De-duplicates the "quota recovered / rejoined pool" popup so one
    /// account only pops once per recovery cycle (recovered -> exhausted ->
    /// recovered).
    rejoined_pool_notified: BTreeSet<i64>,
    monitor_subscription_order: Vec<i64>,
    monitor_api_order: Vec<i64>,
    share_codex_state: bool,
    router_mode_enabled: bool,
    official_mode_selected: bool,
    router_mode_switching: bool,
    codex_account_mode_status: profiles::CodexAccountModeStatus,
    codex_account_mode_switching: bool,
    oauth_recovery_due: Option<std::time::Instant>,
    oauth_recovery_running: bool,
    oauth_recovery_cancel: Arc<AtomicBool>,
    grok_sso_dialog_open: bool,
    grok_sso_draft: String,
    grok_sso_importing: bool,
    grok_sso_error: String,
    grok_sso_auto_select_pending: bool,
    channel_preset_dialog_open: bool,
    recommended_platform_dialog_open: bool,
    log_scroll_to_bottom: bool,
    log_follow_latest: bool,
    log_dialog_open: bool,
    runtime_log_stop: Arc<AtomicBool>,
    runtime_log_paused: Arc<AtomicBool>,
    tray_lightweight_mode: bool,
    background_hide_until: Option<std::time::Instant>,
    tray_restore_guard_until: Option<std::time::Instant>,
    last_normal_window_size: [f32; 2],
    health_probe_due: Option<std::time::Instant>,
    health_probe_running: bool,
    health_probe_failures: u32,
    health_recovery_running: bool,
    health_recovery_cancel: Arc<AtomicBool>,
    routing_sync_running: bool,
    routing_sync_pending: bool,
    codex_binding_repair_running: bool,
    /// Run the exact binding check once per manual or scheduled self-check.
    /// The next self-check clears this flag before queueing a new worker.
    codex_binding_check_completed: bool,
    /// Last user-layer fingerprint for which a "stripped but system-bound"
    /// log line was emitted, so the three-minute self-check does not spam.
    codex_binding_safe_strip_logged: Option<String>,
    /// The "Codex config overwritten externally" prompt state.
    codex_overwrite_prompt_open: bool,
    /// Foreground countdown; writing Router config fires when this elapses.
    codex_overwrite_auto_apply_at: Option<std::time::Instant>,
    /// Start of the current unfocused/minimized/tray pause. The deadline is
    /// shifted by this duration when the window returns to the foreground.
    codex_overwrite_countdown_paused_at: Option<std::time::Instant>,
    codex_overwrite_pending_fingerprint: String,
    codex_overwrite_action_running: bool,
    /// Persisted user decision ("", "keep", "factory") plus the fingerprint it
    /// refers to; a matching pair suppresses the prompt until the file changes.
    codex_overwrite_decision: String,
    codex_overwrite_decision_fingerprint: String,
    update_checking: bool,
    update_downloading: bool,
    update_downloaded_bytes: u64,
    update_total_bytes: u64,
    update_installing: bool,
    update_dialog_open: bool,
    update_info: Option<GitHubUpdateInfo>,
}

#[cfg(all(test, windows))]
fn wait_for_child_exit(child: &mut std::process::Child, timeout: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

#[cfg(all(test, windows))]
fn terminate_child_process_tree(child: &mut std::process::Child) {
    let taskkill = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32").join("taskkill.exe"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("taskkill.exe"));
    if let Ok(mut killer) = std::process::Command::new(taskkill)
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        if !wait_for_child_exit(&mut killer, EXIT_PROCESS_KILL_TIMEOUT) {
            let _ = killer.kill();
        }
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    // Never turn a bounded shutdown into an unbounded GUI exit. Dropping a
    // still-running Child handle is safe; the tree-kill request above remains
    // the primary cleanup mechanism.
    let _ = wait_for_child_exit(child, EXIT_PROCESS_KILL_TIMEOUT);
}

fn stop_router_for_exit_with_timeout(
    router_root: &Path,
    config: &RouterConfig,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    lifecycle::stop_services_with_config(router_root, config, true, false).map(|_| ())?;
    if started.elapsed() > timeout {
        anyhow::bail!(
            "Router shutdown exceeded its {} second time budget",
            timeout.as_secs_f32()
        );
    }
    Ok(())
}

fn stop_router_for_exit(router_root: &Path, config: &RouterConfig) -> anyhow::Result<()> {
    stop_router_for_exit_with_timeout(router_root, config, EXIT_SHUTDOWN_TIMEOUT)
}

struct ExitTransactionMarker {
    path: PathBuf,
}

impl ExitTransactionMarker {
    fn create(router_root: &Path) -> anyhow::Result<Self> {
        let directory = user_data::data_root(router_root).join("pids");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join("gui-exit.pid");
        std::fs::write(&path, std::process::id().to_string())?;
        Ok(Self { path })
    }
}

impl Drop for ExitTransactionMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn restore_codex_and_stop_router_for_exit(
    router_root: &Path,
    config: &RouterConfig,
    share_codex_state: bool,
) -> anyhow::Result<()> {
    restore_codex_and_stop_router_for_exit_with(
        router_root,
        config,
        share_codex_state,
        &logic::codex_toml::codex_system_config_path(),
        stop_router_for_exit,
    )
}

fn restore_codex_and_stop_router_for_exit_with<F>(
    router_root: &Path,
    fallback_config: &RouterConfig,
    share_codex_state: bool,
    system_config_path: &Path,
    stop_router: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&Path, &RouterConfig) -> anyhow::Result<()>,
{
    // Wait for any in-flight Apply to finish first (exit already signalled its
    // cancel flag). Only then do we own both the config file and the services.
    let _config_lock = profiles::acquire_config_apply_lock(router_root, EXIT_CONFIG_LOCK_TIMEOUT)
        .context("could not acquire the Router configuration lock during exit")?;
    let config_path = user_data::config_path(router_root);
    if !config_path.is_file() {
        // Router was never applied from this data root: nothing to restore,
        // only local services (if any) need to stop.
        return stop_router(router_root, fallback_config);
    }
    let stop_config = match RouterConfig::load(&config_path) {
        Ok(applied_config) => applied_config,
        Err(error) => {
            // A broken saved Router config must not block the service
            // shutdown; report it after stopping instead of skipping it.
            let stop_result = stop_router(router_root, fallback_config);
            let load_error = error
                .context("could not load the last applied Router configuration during exit");
            return match stop_result {
                Ok(()) => Err(load_error),
                Err(stop_error) => Err(anyhow::anyhow!(
                    "Router shutdown failed: {stop_error}; saved Router config was also unreadable: {load_error}"
                )),
            };
        }
    };

    // Stop first: while any managed service is still running, the Codex binding
    // must stay in place so the desktop client keeps working. A failed stop
    // therefore returns early with the Codex configuration untouched. Only a
    // fully stopped stack is followed by the config restore, so Codex never
    // ends up pointing at a dead local gateway.
    stop_router(router_root, &stop_config)?;
    let router_mode_configured = logic::codex_router_mode_configured(&stop_config);
    restore_codex_for_exit(
        router_root,
        &stop_config,
        share_codex_state,
        router_mode_configured,
    )?;
    persist_legal_system_binding_for_exit(router_root, &stop_config, system_config_path)
}

fn persist_legal_system_binding_for_exit(
    router_root: &Path,
    config: &RouterConfig,
    system_config_path: &Path,
) -> anyhow::Result<()> {
    // No system config layer exists off Windows; nothing to persist.
    #[cfg(not(windows))]
    {
        let _ = (router_root, config, system_config_path);
        return Ok(());
    }
    // Closing Router used to delete %ProgramData%\OpenAI\Codex\config.toml.
    // Desktop then falls through to ChatGPT OAuth (`requires_openai_auth=true`)
    // the next time it strips the user file, which is the login loop. Keep a
    // legal system identity instead; factory restore still removes it.
    match codex_router_lib::control_plane::desktop_session::repair_provider_identity_file(
        system_config_path,
    ) {
        codex_router_lib::control_plane::desktop_session::IdentityRepair::AlreadyLegal
        | codex_router_lib::control_plane::desktop_session::IdentityRepair::Repaired => {
            return Ok(());
        }
        codex_router_lib::control_plane::desktop_session::IdentityRepair::Missing
        | codex_router_lib::control_plane::desktop_session::IdentityRepair::Failed => {}
    }
    let local_key = match logic::ensure_local_api_key() {
        Ok(key) if !key.trim().is_empty() => key,
        _ => return Ok(()),
    };
    let base_url = logic::responses_gateway::responses_gateway_url(&config.deploy.sub2api_host)
        .unwrap_or_else(|_| config.deploy.sub2api_host.clone());
    logic::codex_toml::write_codex_system_binding_to(
        system_config_path,
        &user_data::state_root(router_root).join("model-catalog.json"),
        &local_key,
        &base_url,
        false,
        false,
        config.rate_limit_max_retries,
    )
}

fn restore_codex_for_exit(
    router_root: &Path,
    config: &RouterConfig,
    share_codex_state: bool,
    router_mode_configured: bool,
) -> anyhow::Result<()> {
    if router_mode_configured {
        profiles::restore_original_codex(router_root, config, share_codex_state)
            .map(|_| ())
            .context("could not restore the Codex configuration used before Router")?;
    }
    Ok(())
}

fn update_autostart_registration(router_root: &Path, enabled: bool) -> anyhow::Result<()> {
    autostart::set_enabled(router_root, enabled)
}

fn legacy_autostart_shortcut_exists() -> bool {
    autostart::is_registered()
}

#[cfg(windows)]
fn hide_current_process_windows() {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, ShowWindow, SW_HIDE,
    };

    unsafe extern "system" fn hide_owned_window(hwnd: HWND, owner_pid: LPARAM) -> i32 {
        let mut window_pid = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut window_pid);
            if window_pid == owner_pid as u32 {
                ShowWindow(hwnd, SW_HIDE);
            }
        }
        1
    }

    unsafe {
        EnumWindows(Some(hide_owned_window), GetCurrentProcessId() as LPARAM);
    }
}

#[cfg(not(windows))]
fn hide_current_process_windows() {}

fn decode_icon() -> anyhow::Result<(Vec<u8>, u32, u32)> {
    let image =
        image::load_from_memory_with_format(APP_ICON_ICO, image::ImageFormat::Ico)?.to_rgba8();
    let (width, height) = image.dimensions();

    // Use the compact Windows icon artwork for title-bar and tray sizes, then
    // trim its transparent border so the robot remains recognizable at 16 px.
    let mut min_x = width;
    let mut min_y = height;
    let mut max_x = 0;
    let mut max_y = 0;
    for (x, y, pixel) in image.enumerate_pixels() {
        if pixel[3] >= 16 {
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
    }
    if min_x > max_x || min_y > max_y {
        return Ok((image.into_raw(), width, height));
    }

    let content_width = max_x - min_x + 1;
    let content_height = max_y - min_y + 1;
    let side = content_width
        .max(content_height)
        .saturating_add((content_width.max(content_height) as f32 * 0.04) as u32)
        .min(width.min(height));
    let center_x = (min_x + max_x) / 2;
    let center_y = (min_y + max_y) / 2;
    let crop_x = center_x.saturating_sub(side / 2).min(width - side);
    let crop_y = center_y.saturating_sub(side / 2).min(height - side);
    let cropped = image::imageops::crop_imm(&image, crop_x, crop_y, side, side).to_image();
    Ok((cropped.into_raw(), side, side))
}

#[cfg(windows)]
fn system_ui_language() -> String {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }

    // LANGID uses the low ten bits for the primary language. Chinese is 0x04
    // for both simplified and traditional variants; every non-Chinese system
    // defaults to English as the common fallback.
    let primary_language = unsafe { GetUserDefaultUILanguage() } & 0x03ff;
    if primary_language == 0x04 {
        "zh".to_owned()
    } else {
        "en".to_owned()
    }
}

#[cfg(not(windows))]
fn system_ui_language() -> String {
    "en".to_owned()
}

/// Normal Apply progress that is not one of the `[N/7]` stage headers. These
/// lines report success, so they must never be relabeled as a diagnostic and
/// run through the error classifier (which used to tag them
/// `class=unclassified_error` and made a healthy deploy look broken).
fn deployment_progress_line(zh: bool, line: &str) -> Option<String> {
    struct Progress {
        marker: &'static str,
        zh: &'static str,
        en: &'static str,
    }
    const PROGRESS: &[Progress] = &[
        Progress {
            marker: "Router compliance acknowledgement recorded",
            zh: "已记录本机管理员的合规确认",
            en: "Recorded the compliance acknowledgement for this local administrator",
        },
        Progress {
            marker: "Router administrator ready",
            zh: "本地管理员已就绪",
            en: "Local administrator is ready",
        },
        Progress {
            marker: "Codex model catalog generated",
            zh: "已生成 Codex 模型目录",
            en: "Generated the Codex model catalog",
        },
        Progress {
            marker: "Composite routes",
            zh: "已同步组合路由",
            en: "Synchronized composite routes",
        },
        Progress {
            marker: "Updated channel:",
            zh: "已更新模型渠道",
            en: "Updated a model channel",
        },
        Progress {
            marker: "Created channel:",
            zh: "已创建模型渠道",
            en: "Created a model channel",
        },
        Progress {
            marker: "Skipped channel:",
            zh: "已跳过缺少 API Key 的模型渠道，其余配置继续应用",
            en: "Skipped a model channel with no saved API key; the rest of the configuration is still being applied",
        },
        Progress {
            marker: "isolated until recovery",
            zh: "OAuth 账号已隔离，等待额度恢复",
            en: "An OAuth account is isolated until its quota recovers",
        },
        Progress {
            marker: "Outbound proxy reconciliation",
            zh: "出站代理配置已核对完成",
            en: "Reconciled the outbound proxy configuration",
        },
        Progress {
            marker: "Catalog availability filter",
            zh: "已过滤当前不可用的模型",
            en: "Filtered models that cannot currently serve traffic",
        },
        Progress {
            marker: "OAuth on-demand recovery delegated",
            zh: "OAuth 按需恢复已交由 Codex-Router 管理",
            en: "OAuth on-demand recovery is handled by Codex-Router",
        },
        Progress {
            marker: "Autostart registered",
            zh: "已注册开机自启",
            en: "Registered autostart",
        },
        Progress {
            marker: "Autostart removed",
            zh: "已移除开机自启",
            en: "Removed autostart",
        },
        Progress {
            marker: "will start directly in lightweight tray mode",
            zh: "下次登录后将直接进入轻量托盘模式",
            en: "Will start directly in lightweight tray mode next sign-in",
        },
        Progress {
            marker: "model channel(s).",
            zh: "模型渠道数量已确认",
            en: "Model channel count confirmed",
        },
        Progress {
            marker: "Codex configuration written to",
            zh: "已写入 Codex 配置",
            en: "Wrote the Codex configuration",
        },
        Progress {
            marker: "Local access key is stored in Windows Credential Manager",
            zh: "本机访问密钥已保存到 Windows 凭据管理器",
            en: "Stored the local access key in Windows Credential Manager",
        },
        Progress {
            marker: "Codex Router is running at",
            zh: "本地 Router 服务已启动",
            en: "Local Router services are running",
        },
        Progress {
            marker: "Codex Router secrets and data directory",
            zh: "本地凭据与数据库目录已就绪",
            en: "Local secrets and database directory are ready",
        },
        Progress {
            marker: "Codex Router is stopped",
            zh: "本地 Router 服务已停止",
            en: "Local Router services are stopped",
        },
        Progress {
            marker: "Configured ",
            zh: "模型渠道数量已确认",
            en: "Model channel count confirmed",
        },
    ];
    PROGRESS
        .iter()
        .find(|progress| line.contains(progress.marker))
        .map(|progress| if zh { progress.zh } else { progress.en }.to_owned())
}

/// Stable per-step deployment flags. Every Apply stage and every routing
/// decision emits one, so the activity log stays diagnosable and searchable:
/// the code is always kept verbatim next to a human explanation.
fn localized_router_flag(zh: bool, rest: &str) -> String {
    let mut parts = rest.trim().splitn(2, ' ');
    let code = parts.next().unwrap_or_default().trim();
    let data = parts.next().unwrap_or_default().trim();
    let meaning = match code {
        "STAGE-01-INIT-OK" => (
            "步骤 1/7 完成：本地凭据与数据库已就绪",
            "Step 1/7 done: local credentials and database are ready",
        ),
        "STAGE-02-SERVICES-OK" => (
            "步骤 2/7 完成：Router Host / CLIProxyAPI 已启动",
            "Step 2/7 done: Router Host and CLIProxyAPI are running",
        ),
        "STAGE-03-ADMIN-OK" => (
            "步骤 3/7 完成：管理接口登录成功",
            "Step 3/7 done: signed in to the admin API",
        ),
        "STAGE-04-COMPLIANCE-OK" => (
            "步骤 4/7 完成：合规状态已确认",
            "Step 4/7 done: compliance state confirmed",
        ),
        "STAGE-06-CODEX-OK" => (
            "步骤 6/7 完成：Codex 配置与本地密钥已写入",
            "Step 6/7 done: Codex configuration and local key written",
        ),
        "STAGE-07-DONE" => ("步骤 7/7 完成：部署成功", "Step 7/7 done: deployment succeeded"),
        "OAUTH-PRIMARY" => (
            "订阅额度可用：优先使用该 OAuth 账号",
            "Subscription quota available: this OAuth account is preferred",
        ),
        "OAUTH-PARKED-WITH-FALLBACK" => (
            "订阅额度已用完：暂停该账号，改用同名第三方 API 兜底",
            "Subscription quota exhausted: account parked, same-model API channel serves instead",
        ),
        "OAUTH-PARKED-NO-FALLBACK" => (
            "订阅额度已用完且没有同名第三方兜底：该模型暂时下线",
            "Subscription quota exhausted with no same-model API fallback: the model is temporarily offline",
        ),
        "OAUTH-SKIP-UNSELECTED" => (
            "该 OAuth 账号未加入当前配置，不参与路由",
            "This OAuth account is not part of the active profile and does not route",
        ),
        "OAUTH-SKIP-NO-MODELS" => (
            "该 OAuth 账号未导入任何模型，继续使用模型列表中的第三方渠道",
            "No OAuth models imported for this account; third-party channels keep serving",
        ),
        "API-CHANNEL" => (
            "已配置独立第三方 API 渠道",
            "Configured a standalone third-party API channel",
        ),
        "API-FALLBACK-CHANNEL" => (
            "已配置同名第三方兜底渠道（OAuth 用尽时接管）",
            "Configured a same-model API fallback channel (takes over when OAuth is exhausted)",
        ),
        "CATALOG-MODEL" => (
            "模型已写入 Codex 菜单",
            "Model written into the Codex menu",
        ),
        "CATALOG-DROPPED" => (
            "模型暂时移出 Codex 菜单（当前无可用账号）",
            "Model temporarily removed from the Codex menu (no serviceable account)",
        ),
        "CATALOG-FILTER" => (
            "Codex 菜单可用性过滤完成",
            "Codex menu availability filter finished",
        ),
        "FALLBACK-ACTIVE" => (
            "已触发兜底：该模型改由第三方 API 提供",
            "Fallback active: this model is now served by a third-party API channel",
        ),
        "COMPOSITE-SYNC" => ("组合路由已同步", "Composite routes synchronized"),
        "COMPOSITE-ROUTE" => ("组合路由项已就绪", "Composite route entry is ready"),
        "ROUTING-SYNC-OK" => (
            "额度状态变化后已重新同步路由与 Codex 菜单",
            "Routing and the Codex menu were re-synchronized after a quota change",
        ),
        "ROUTING-SYNC-MODEL" => (
            "路由同步：模型当前的服务来源",
            "Routing sync: current serving source for this model",
        ),
        "ROUTING-SYNC-SKIPPED" => (
            "路由同步已跳过",
            "Routing sync was skipped",
        ),
        "ROUTING-SYNC-FAILED" => (
            "路由同步未完成，下次应用会重新对齐",
            "Routing sync did not finish; the next Apply realigns it",
        ),
        "ROUTING-SYNC-ACCOUNT-UNREADABLE" => (
            "路由同步：无法读取该 OAuth 账号状态",
            "Routing sync: could not read this OAuth account state",
        ),
        "OAUTH-REJOINED" => (
            "订阅额度已恢复：该账号重新回到优先路由",
            "Subscription quota recovered: this account is preferred again",
        ),
        "OAUTH-PARKED" => (
            "订阅额度不可用：该账号已移出请求路径",
            "Subscription quota unavailable: this account left the request path",
        ),
        _ => ("部署事件", "Deployment event"),
    };
    let text = if zh { meaning.0 } else { meaning.1 };
    if data.is_empty() {
        format!("[{code}] {text}")
    } else {
        format!("[{code}] {text} · {data}")
    }
}

fn localized_deployment_line(zh: bool, line: String) -> String {
    if let Some(rest) = line.trim().strip_prefix("CR-FLAG ") {
        return localized_router_flag(zh, rest);
    }
    let localized = [
        (
            "[1/7]",
            "[1/7] 正在初始化本地凭据与数据库…",
            "[1/7] Initializing local credentials and database…",
        ),
        (
            "[2/7]",
            "[2/7] 正在启动 Router Host 与 CLIProxyAPI…",
            "[2/7] Starting Router Host and CLIProxyAPI…",
        ),
        (
            "[3/7]",
            "[3/7] 本地服务已就绪，正在登录管理接口…",
            "[3/7] Local services are ready; signing in to the admin API…",
        ),
        (
            "[4/7]",
            "[4/7] 正在确认本地合规状态…",
            "[4/7] Confirming local compliance state…",
        ),
        (
            "[5/7]",
            "[5/7] 正在创建或更新模型渠道…",
            "[5/7] Creating or updating model channels…",
        ),
        (
            "[6/7]",
            "[6/7] 正在写入 Codex 配置与本地访问密钥…",
            "[6/7] Writing Codex configuration and local access key…",
        ),
        ("[7/7]", "[7/7] 部署完成。", "[7/7] Deployment complete."),
    ];
    localized
        .into_iter()
        .find_map(|(prefix, chinese, english)| {
            line.starts_with(prefix)
                .then(|| if zh { chinese } else { english }.to_owned())
        })
        .or_else(|| deployment_progress_line(zh, &line))
        .unwrap_or_else(|| {
            if let Some(rest) = line
                .strip_prefix("deployment_warning ")
                .or_else(|| line.strip_prefix("deployment_diagnostic "))
            {
                let label = if line.starts_with("deployment_warning ") {
                    if zh {
                        "部署提示"
                    } else {
                        "Deployment note"
                    }
                } else if zh {
                    "部署诊断"
                } else {
                    "Deployment diagnostic"
                };
                format!("{label}: {}", localized_error_summary(zh, rest))
            } else {
                format!(
                    "{}: {}",
                    if zh {
                        "部署诊断"
                    } else {
                        "Deployment diagnostic"
                    },
                    localized_error_summary(zh, &line)
                )
            }
        })
}

fn localized_error_summary(zh: bool, text: &str) -> String {
    for (marker, chinese, english) in [
        (
            "ROUTER_CONFIG_SAVE_LOCK_FAILED",
            "无法取得配置保存锁。可能有另一个 Router 操作仍在进行，请完全退出重复运行的 Router 后重试。",
            "Could not acquire the configuration save lock. Another Router operation may still be running; fully exit duplicate Router processes and retry.",
        ),
        (
            "ROUTER_CONFIG_SAVE_CODEX_SNAPSHOT_FAILED",
            "无法保存 Codex 原始配置快照。请关闭正在运行的 Codex 后再点击保存并应用。",
            "Could not save the original Codex configuration snapshot. Close Codex completely, then click Save and Apply again.",
        ),
        (
            "ROUTER_CONFIG_SAVE_BACKUP_FAILED",
            "无法创建应用前配置备份。请检查 UserData 目录是否可写，并关闭占用配置文件的程序。",
            "Could not create the pre-apply configuration backup. Check that UserData is writable and close programs holding the configuration files.",
        ),
        (
            "ROUTER_CONFIG_SAVE_CREDENTIALS_FAILED",
            "无法写入 Windows 凭据管理器。请以当前用户重新启动 Router 后重试，不会覆盖现有配置。",
            "Could not write Windows Credential Manager entries. Restart Router as the current user and retry; the existing configuration was not overwritten.",
        ),
        (
            "ROUTER_CONFIG_SAVE_FILES_FAILED",
            "无法提交 Router 配置文件。请关闭 Codex-Router 后重新打开 LAB 版本再试。",
            "Could not commit Router configuration files. Close Codex-Router, reopen the LAB version, and retry.",
        ),
        (
            "ROUTER_CONFIG_SAVE_APPLY_SCRIPT_FAILED",
            "配置文件已写入，但 Router 应用脚本失败。请查看活动日志中的 STAGE 或 CR-FLAG 原因。",
            "The configuration files were written, but the Router apply script failed. Check the activity log for the STAGE or CR-FLAG reason.",
        ),
        (
            "ROUTER_CONFIG_SAVE_DEPLOY_FAILED",
            "保存配置事务失败，已保留应用前配置。请查看活动日志中的具体保存阶段。",
            "The configuration transaction failed and the previously applied configuration was preserved. Check the activity log for the exact save stage.",
        ),
        (
            "ROUTER_DEPLOY_NO_MODELS",
            "当前配置没有可部署的模型。请在模型卡片中添加 API 渠道，或在 OAuth 账号卡片中点击「＋ 模型」把官方模型加入本配置后再试。",
            "This configuration has no deployable model. Add an API channel from the model card, or add an official model from the OAuth account card, then retry.",
        ),
        (
            "CR-VAL-0003",
            "本地合规确认未通过。请回到完成页勾选本机使用承诺后再保存并应用。",
            "Local compliance was not accepted. Return to the finish page, accept the local-use commitment, then save and apply.",
        ),
        (
            "ROUTER_DEPLOY_COMPLIANCE",
            "本地合规确认未通过。请回到完成页勾选本机使用承诺后再保存并应用。",
            "Local compliance was not accepted. Return to the finish page, accept the local-use commitment, then save and apply.",
        ),
        (
            "CR-CFG-0005",
            "本地 CLI 配置热加载失败。请查看活动日志后再次保存并应用；不要同时打开另一份 Router。",
            "CLI configuration hot-reload failed. Check the activity log, then save and apply again. Do not run another Router at the same time.",
        ),
        (
            "CR-CFG-0004",
            "候选路由配置未通过校验。请检查模型 ID 和渠道地址后重试。",
            "The candidate routing configuration failed validation. Check model IDs and channel URLs, then retry.",
        ),
        (
            "class=admin_session",
            "管理会话未就绪。请等待本机服务启动完成后再保存并应用，不必重新登录授权页。",
            "The admin session is not ready. Wait for local services to finish starting, then save and apply. You do not need to sign in again.",
        ),
        (
            "ROUTER_DEPLOY_ADMIN_ACCOUNTS_FAILED",
            "无法读取本机账号清单。请确认 Router Host 已启动后再保存并应用。",
            "Could not read the local account list. Make sure Router Host is running, then save and apply.",
        ),
        (
            "CR-LFC-0006",
            "本机 CLI 尚未就绪，路由组写入超时。请等几秒后再点保存并应用，不要同时打开另一份 Router。",
            "The local CLI was not ready and the routing-group write timed out. Wait a few seconds and click Save & apply again. Do not run another Router at the same time.",
        ),
        (
            "class=timeout",
            "本机服务响应超时。请等 Router Host 启动完成后再保存并应用。",
            "The local service timed out. Wait until Router Host has finished starting, then save and apply.",
        ),
        (
            "ROUTER_DEPLOY_GROUP_SYNC_FAILED",
            "无法同步本机路由组。请查看活动日志中的 CR 错误码后重试。",
            "Could not synchronize the local routing group. Check the CR error code in the activity log and retry.",
        ),
        (
            "ROUTER_DEPLOY_API_CHANNELS_FAILED",
            "无法写入 API 渠道。请检查密钥和渠道地址后再次保存并应用。",
            "Could not write API channels. Check API keys and channel URLs, then save and apply again.",
        ),
        (
            "Missing API Key for model",
            "有模型缺少 Windows 凭据管理器中的 API Key。该渠道已跳过，其余模型和 Codex 绑定仍会继续应用。",
            "An API key is missing from Windows Credential Manager for one model. That channel was skipped; the remaining models and Codex binding are still applied.",
        ),
        (
            "ROUTER_DEPLOY_OAUTH_SYNC_FAILED",
            "无法同步 OAuth 账号到路由组。请稍后重试；不要在部署过程中关闭本机服务。",
            "Could not synchronize OAuth accounts into the routing group. Retry shortly and do not stop local services during apply.",
        ),
        (
            "ROUTER_DEPLOY_COMPOSITE_FAILED",
            "无法写入复合路由。请查看活动日志中的 CR 错误码后重试。",
            "Could not write composite routes. Check the CR error code in the activity log and retry.",
        ),
        (
            "ROUTER_CONFIG_SAVE_NATIVE_APPLY_FAILED",
            "配置文件已写入，但本机路由应用失败。请查看活动日志中的 CR 错误码或 STAGE 后再试。",
            "Configuration files were written, but native apply failed. Check the CR error code or STAGE in the activity log, then retry.",
        ),
        (
            "ROUTER_OAUTH_ACCOUNTS_UNAVAILABLE",
            "暂时无法读取 OAuth 账号。请确认本地 Router 已启动并完成初始化，然后点击「刷新」。",
            "Could not load OAuth accounts. Make sure the local Router is running and initialized, then click Refresh.",
        ),
        (
            "ROUTER_OAUTH_ACCOUNTS_PARSE",
            "OAuth 账号清单格式异常。请点击「刷新」重试；若仍失败，请重启 Codex-Router 后再试。",
            "The OAuth account list could not be parsed. Click Refresh; if it still fails, restart Codex-Router and try again.",
        ),
        (
            "ROUTER_PROFILE_CREDENTIAL_MISSING",
            "无法读取已保存的 API Key。请返回模型页面重新输入并保存后再试。",
            "A saved API key is missing. Re-enter and save it on the Models page, then retry.",
        ),
        (
            "ROUTER_PROFILE_CREDENTIAL_READ_FAILED",
            "Windows 凭据管理器暂时无法读取 API Key。请重新输入并保存 Key 后再试。",
            "Windows Credential Manager could not read an API key. Re-enter and save the key, then retry.",
        ),
        (
            "ROUTER_PROFILE_CREDENTIAL_WRITE_FAILED",
            "Windows 凭据管理器无法创建隔离凭据；已回滚本次操作。请重试，或重新输入并保存 API Key。",
            "Windows Credential Manager could not create isolated credentials. This attempt was rolled back. Retry or re-enter and save the API key.",
        ),
        (
            "ROUTER_PROFILE_SAVE_FAILED",
            "隔离配置未能完整保存；已回滚本次操作，现有配置未被覆盖。",
            "The isolated profile could not be saved completely. This attempt was rolled back without overwriting the current profile.",
        ),
        (
            "ROUTER_PROFILE_ROLLBACK_INCOMPLETE",
            "隔离配置保存失败，且自动回滚未完全完成。请导出诊断信息后重启程序。",
            "The isolated profile failed to save and automatic rollback was incomplete. Export diagnostics and restart the app.",
        ),
    ] {
        if text.contains(marker) {
            return if zh { chinese } else { english }.to_owned();
        }
    }
    let summary = runtime_logs::summarize_error_for_display(text);
    if summary.contains("class=install_root_conflict") {
        return if zh {
            "另一份 Codex-Router 正在占用本地服务端口。请关闭另一份，或改用当前已运行的安装目录。"
        } else {
            "Another Codex-Router installation owns a required local port. Close it or use the installation that is already running."
        }
        .to_owned();
    }
    if summary.contains("class=port_conflict") {
        return if zh {
            "Codex-Router 所需的本地端口已被其他程序占用。请关闭占用程序后重试。"
        } else {
            "A local port required by Codex-Router is owned by another program. Close that program and retry."
        }
        .to_owned();
    }
    for (marker, chinese, english) in [
        (
            "ROUTER_OAUTH_PREPARE_LIFECYCLE_BUSY",
            "另一项 Router 操作占用时间过长。程序已自动重试，请等待片刻后再次准备。",
            "Another Router operation remained busy after automatic retries. Wait a moment and prepare again.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_ROUTER_START",
            "本地 Router 未能稳定启动。请查看活动日志中的启动阶段，再点击重新准备环境。",
            "The local Router did not start reliably. Check the startup stage in the activity log, then prepare again.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_ADMIN_LOGIN",
            "本地 Router 已启动，但管理会话未就绪。程序不会打开浏览器，请稍后重新准备。",
            "The local Router started, but its admin session was not ready. No browser was opened; prepare again shortly.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_COMPLIANCE",
            "本地 Router 已启动，但授权前检查未完成。请重新准备环境。",
            "The local Router started, but the pre-authorization check did not finish. Prepare the environment again.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_COMPONENTS",
            "OAuth 本地组件未能加载。请确认发布包完整后重新准备。",
            "The local OAuth components could not be loaded. Verify the release package and prepare again.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_TIMEOUT",
            "首次启动超过了安全准备时限，已清理残留进程。请再次准备；后续启动通常会更快。",
            "First startup exceeded the preparation budget and leftover processes were cleaned up. Prepare again; later starts are usually faster.",
        ),
        (
            "ROUTER_OAUTH_PREPARE_PROCESS",
            "OAuth 准备进程未正常完成，且没有返回有效阶段信息。请重新准备环境。",
            "The OAuth preparation process did not finish and returned no valid stage information. Prepare again.",
        ),
    ] {
        if text.contains(marker) {
            return if zh { chinese } else { english }.to_owned();
        }
    }
    summary
}

#[cfg(all(test, windows))]
fn oauth_prepare_error_from_output(output: &std::process::Output) -> String {
    for raw in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(raw);
        for line in text
            .lines()
            .rev()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let code = value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .filter(|code| code.starts_with("ROUTER_OAUTH_PREPARE_"))
                .unwrap_or("ROUTER_OAUTH_PREPARE_PROCESS");
            let stage = value
                .get("stage")
                .and_then(serde_json::Value::as_str)
                .filter(|stage| {
                    !stage.is_empty()
                        && stage.len() <= 48
                        && stage
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
                .unwrap_or("unknown");
            return format!("{code} stage={stage}");
        }
    }
    "ROUTER_OAUTH_PREPARE_PROCESS stage=unknown".to_owned()
}

fn oauth_prepare_error_from_native(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    for marker in [
        "ROUTER_OAUTH_PREPARE_LIFECYCLE_BUSY",
        "ROUTER_OAUTH_PREPARE_ROUTER_START",
        "ROUTER_OAUTH_PREPARE_ADMIN_LOGIN",
        "ROUTER_OAUTH_PREPARE_COMPLIANCE",
        "ROUTER_OAUTH_PREPARE_COMPONENTS",
        "ROUTER_OAUTH_PREPARE_TIMEOUT",
        "ROUTER_OAUTH_PREPARE_PROCESS",
    ] {
        if text.contains(marker) {
            return format!("{marker} stage=native");
        }
    }
    if text.contains("ROUTER_LIFECYCLE_BUSY") || text.contains("ROUTER_LIFECYCLE_DEFERRED") {
        "ROUTER_OAUTH_PREPARE_LIFECYCLE_BUSY stage=native".to_owned()
    } else if text.contains("class=authentication") || text.contains("class=rate_limit") {
        "ROUTER_OAUTH_PREPARE_ADMIN_LOGIN stage=native".to_owned()
    } else if text.contains("class=configuration") {
        "ROUTER_OAUTH_PREPARE_COMPONENTS stage=native".to_owned()
    } else if text.contains("initdb")
        || text.contains("PostgreSQL")
        || text.contains("Redis")
        || text.contains("Sub2API")
        || text.contains("did not become ready")
        || text.contains("failed to start the responses compatibility gateway")
    {
        "ROUTER_OAUTH_PREPARE_ROUTER_START stage=native".to_owned()
    } else {
        "ROUTER_OAUTH_PREPARE_PROCESS stage=native".to_owned()
    }
}

fn oauth_prepare_error_is_retryable(error: &str) -> bool {
    error.contains("ROUTER_OAUTH_PREPARE_LIFECYCLE_BUSY")
        || error.contains("ROUTER_LIFECYCLE_DEFERRED")
        || error.contains("ROUTER_OAUTH_PREPARE_ROUTER_START")
        || error.contains("ROUTER_OAUTH_PREPARE_ADMIN_LOGIN")
        || error.contains("ROUTER_OAUTH_PREPARE_COMPLIANCE")
        || error.contains("ROUTER_OAUTH_PREPARE_PROCESS")
}

fn oauth_accounts_error_is_retryable(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("router_oauth_accounts_unavailable")
        || lower.contains("router_oauth_accounts_configuration")
        || lower.contains("class=configuration")
        || lower.contains("class=connection_refused")
        || lower.contains("class=connection_closed")
        || lower.contains("class=timeout")
        || lower.contains("class=lifecycle_busy")
        || lower.contains("class=lifecycle_deferred")
        || lower.contains("class=authentication")
        || lower.contains("admin session")
        || lower.contains("health check failed")
        || lower.contains("actively refused")
        || lower.contains("connection refused")
        || lower.contains("rate-limited")
        || lower.contains("no access token")
        || lower.contains("429")
        || lower.contains("503")
}

/// Returns the usage-error text shown on the quota monitor banner. When a
/// successful snapshot is already on screen, a failed refresh degrades to a
/// soft "retry-keep" notice (rendered yellow) instead of a red banner, so a
/// transient failure right after a provider reset does not replace live data.
fn usage_error_for_ui(has_previous_snapshot: bool, detail: String) -> String {
    if has_previous_snapshot {
        format!("RETRY-KEEP:{detail}")
    } else {
        detail
    }
}

fn usage_error_for_display(zh: bool, text: &str) -> String {
    let trimmed = text.trim();
    let summary = if trimmed.starts_with("class=")
        && !trimmed.contains('\r')
        && !trimmed.contains('\n')
        && trimmed.len() <= 512
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'=' | b'_' | b'+' | b'|' | b' ' | b'-' | b'.')
        }) {
        trimmed.to_owned()
    } else {
        runtime_logs::summarize_error_for_display(trimmed)
    };
    if summary.contains("marker=ROUTER_KIMI_CREDENTIAL_REJECTED") {
        return if zh {
            "Kimi API Key 无效或没有 Coding Plan 权限，请在 Kimi Code 控制台新建 Key 后重新填写。"
                .to_owned()
        } else {
            "The Kimi API Key is invalid or lacks Coding Plan access. Create a new key in the Kimi Code Console and enter it again."
                .to_owned()
        };
    }
    let class = summary
        .split('|')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("class="))
        .unwrap_or("unclassified_error");
    match (zh, class) {
        (true, "configuration") => {
            "本地用量配置正在更新，请稍后重新查询。已保留上次成功数据。".to_owned()
        }
        (false, "configuration") => {
            "The local usage configuration is being updated. Retry shortly; the last successful data is retained."
                .to_owned()
        }
        (true, "connection_refused" | "connection_closed" | "process_failure") => {
            "本地 Router 正在启动或恢复，请稍后重新查询。".to_owned()
        }
        (false, "connection_refused" | "connection_closed" | "process_failure") => {
            "The local Router is starting or recovering. Retry shortly.".to_owned()
        }
        (true, "timeout" | "network" | "dns" | "proxy" | "tls") => {
            "上游额度服务暂时不可用，已保留上次成功数据。".to_owned()
        }
        (false, "timeout" | "network" | "dns" | "proxy" | "tls") => {
            "The upstream quota service is temporarily unavailable; the last successful data is retained."
                .to_owned()
        }
        (true, "admin_session") => {
            "本地额度查询的管理会话已失效，请稍后刷新。不必前往授权页重新登录。".to_owned()
        }
        (false, "admin_session") => {
            "The local usage admin session expired. Refresh shortly; you do not need to sign in again on the authorization page."
                .to_owned()
        }
        (true, "quota_denied" | "permission") => {
            "上游额度接口拒绝了此次查询（可能是套餐权限或额度策略），已保留上次成功数据。".to_owned()
        }
        (false, "quota_denied" | "permission") => {
            "The upstream quota endpoint denied this query. The last successful data is retained."
                .to_owned()
        }
        (true, "authentication") => {
            "该账号的额度凭据已失效，请在授权页面重新登录或检查 API Key。".to_owned()
        }
        (false, "authentication") => {
            "This account's quota credential is no longer valid. Sign in again or check the API key."
                .to_owned()
        }
        (true, _) => "用量查询暂时失败，已保留上次成功数据，请稍后重试。".to_owned(),
        (false, _) => {
            "The usage query temporarily failed. The last successful data is retained; retry shortly."
                .to_owned()
        }
    }
}

fn usage_account_message_for_display(zh: bool, text: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    let summary = runtime_logs::summarize_error_for_display(text);
    if summary == "class=unclassified_error" {
        return String::new();
    }
    usage_error_for_display(zh, &summary)
}

fn normalize_usage_account_messages(zh: bool, account: &mut UsageAccount) {
    let status_detail = usage_account_message_for_display(zh, &account.status_detail);
    let query_note = usage_account_message_for_display(zh, &account.query_note);
    account.status_detail = if query_note.is_empty() {
        status_detail
    } else {
        query_note
    };
    account.query_note.clear();
}

fn clear_stale_oauth_account_errors(
    accounts: &mut [OAuthAccountSummary],
    snapshot: Option<&UsageSnapshot>,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    for account in accounts {
        if !account.status.eq_ignore_ascii_case("active") {
            continue;
        }
        let error = account.error.to_ascii_lowercase();
        let transient =
            error.contains("class=request_failure") || error.contains("class=unclassified_error");
        if !transient {
            continue;
        }
        let healthy = snapshot.subscriptions.iter().any(|usage| {
            usage.id == account.id
                && usage.health.eq_ignore_ascii_case("healthy")
                && usage.status.eq_ignore_ascii_case("active")
        });
        if healthy {
            account.error.clear();
        }
    }
}

fn retain_last_good_oauth_models(
    previous: &[OAuthAccountSummary],
    refreshed: &mut [OAuthAccountSummary],
) {
    for account in refreshed {
        if !account.models.is_empty() || account.models_error.is_empty() {
            continue;
        }
        if let Some(last_good) = previous
            .iter()
            .find(|candidate| candidate.id == account.id && !candidate.models.is_empty())
        {
            account.models.clone_from(&last_good.models);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestResultDisposition {
    Ignore,
    RefreshCurrent,
    Apply,
}

fn request_result_disposition(
    current_generation: u64,
    current_key: &str,
    event_generation: u64,
    event_key: &str,
) -> RequestResultDisposition {
    if event_generation != current_generation {
        RequestResultDisposition::Ignore
    } else if event_key != current_key {
        RequestResultDisposition::RefreshCurrent
    } else {
        RequestResultDisposition::Apply
    }
}

fn next_request_generation(current: &mut u64) -> u64 {
    *current = current.wrapping_add(1).max(1);
    *current
}

fn profile_binding_ready(
    generate_isolation: bool,
    active_profile_id: &str,
    pending_profile_activation: Option<&str>,
    isolation_profiles: &[IsolationProfile],
) -> bool {
    if !generate_isolation {
        return true;
    }
    let profile_id = pending_profile_activation
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| active_profile_id.trim());
    !profile_id.is_empty()
        && isolation_profiles
            .iter()
            .any(|profile| profile.id == profile_id)
}

fn restore_apply_ui_fields(
    config: &mut RouterConfig,
    active_profile_id: &mut String,
    pending_profile_activation: &mut Option<String>,
    configured: &mut bool,
    router_mode_enabled: &mut bool,
    rollback: ApplyUiRollback,
) {
    *config = rollback.config;
    *active_profile_id = rollback.active_profile_id;
    *pending_profile_activation = rollback.pending_profile_activation;
    *configured = rollback.configured;
    *router_mode_enabled = rollback.router_mode_enabled;
}

fn deploy_router_config<F>(
    cfg: &mut RouterConfig,
    router_root: &Path,
    cancel: &AtomicBool,
    zh: bool,
    extra_oauth_accounts: &[(i64, String)],
    mut on_log: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    if cancel.load(Ordering::Acquire) {
        anyhow::bail!("deployment cancelled because Codex-Router is exiting");
    }
    // Apply-Router.ps1 refuses a catalog without channels. Failing here keeps
    // `store_credentials` and `write_all_files` from replacing a working
    // catalog and channel manifest with empty ones.
    if cfg.models.is_empty() {
        anyhow::bail!(
            "ROUTER_DEPLOY_NO_MODELS: the configuration has no model channel, so nothing can be deployed"
        );
    }
    let previous_host = cfg.deploy.sub2api_host.clone();
    if let Some(host) = lifecycle::adopt_isolated_host_if_foreign(router_root, cfg) {
        on_log(
            if zh {
                format!("检测到 {previous_host} 已被另一份 Router 或程序占用，本次改用 {host}")
            } else {
                format!(
                    "Port(s) for {previous_host} belong to another Router or program; this apply uses {host}"
                )
            },
        );
    }
    logic::replicate_oauth_slots_for_accounts(cfg, extra_oauth_accounts);
    logic::assign_sequential_oauth_account_priorities(cfg);
    let proxy_runtime =
        logic::resolve_proxy_runtime(cfg).context("ROUTER_CONFIG_RESOLVE_PROXY_FAILED")?;
    let updated_model_keys = logic::store_credentials(cfg, router_root)
        .context("ROUTER_CONFIG_SAVE_CREDENTIALS_FAILED")?;
    on_log(match (zh, updated_model_keys) {
        (true, 0) => "未输入新的 API Key；已保留 Windows 凭据管理器中的现有 Key".to_owned(),
        (false, 0) => {
            "No new API key was entered; existing Windows credentials were preserved".to_owned()
        }
        (true, count) => format!("已安全更新 {count} 个 API Key 到 Windows 凭据管理器"),
        (false, count) => {
            format!("Updated {count} API key(s) securely in Windows Credential Manager")
        }
    });
    logic::write_all_files(cfg, router_root).context("ROUTER_CONFIG_SAVE_FILES_FAILED")?;
    on_log(
        if zh {
            "无密钥配置和模型目录已写入"
        } else {
            "Secret-free configuration and model catalog were written"
        }
        .to_owned(),
    );
    if profiles::recover_missing_chatgpt_auth(router_root, cfg)
        .context("ROUTER_CONFIG_RECOVER_CODEX_AUTH_FAILED")?
    {
        on_log(
            if zh {
                "已从本机加密快照恢复缺失的 ChatGPT 登录状态"
            } else {
                "Recovered the missing ChatGPT login from a local encrypted snapshot"
            }
            .to_owned(),
        );
    }
    let _lifecycle_lock = lifecycle::acquire_lifecycle_lock(
        router_root,
        std::time::Duration::from_secs(10),
        "Apply Router configuration",
    )?;
    logic::deployment::apply_native(router_root, cfg, &proxy_runtime, cancel, |line| {
        on_log(localized_deployment_line(zh, line))
    })
    .context("ROUTER_CONFIG_SAVE_NATIVE_APPLY_FAILED")?;
    update_autostart_registration(router_root, cfg.deploy.start_with_windows)
        .context("ROUTER_CONFIG_SAVE_AUTOSTART_FAILED")
}

/// Redeploys a configuration recovered from a restore point.
///
/// A restore point can predate any successful deployment, for example the first
/// apply of a fresh install. Restoring the Codex snapshot is then the whole
/// operation: running the deployment script would only fail on the empty model
/// list and replace the current catalog and channel manifest with empty ones.
fn redeploy_restored_config<F>(
    restored: &RouterConfig,
    router_root: &Path,
    cancel: &AtomicBool,
    zh: bool,
    on_log: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    if restored.models.is_empty() {
        on_log(
            if zh {
                "该备份没有可部署的 Router 配置，仅恢复 Codex 配置快照"
            } else {
                "That backup holds no deployable Router configuration; only the Codex snapshot was restored"
            }
            .to_owned(),
        );
        return Ok(());
    }
    let mut restored = restored.clone();
    deploy_router_config(&mut restored, router_root, cancel, zh, &[], on_log)
}

fn rollback_failed_deployment<F>(
    router_root: &Path,
    backup: &ApplyTransactionBackup,
    share_codex_state: bool,
    zh: bool,
    mut on_log: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    on_log(
        if zh {
            "部署失败，正在恢复应用前配置…"
        } else {
            "Deployment failed; restoring the previously applied configuration…"
        }
        .to_owned(),
    );
    let rollback_cancel = AtomicBool::new(false);
    profiles::restore_point_config_and_deploy(
        router_root,
        &backup.point,
        &backup.config,
        share_codex_state,
        |restored| {
            redeploy_restored_config(restored, router_root, &rollback_cancel, zh, &mut on_log)
        },
    )?;
    on_log(
        if zh {
            "已恢复应用前配置"
        } else {
            "The previously applied configuration was restored"
        }
        .to_owned(),
    );
    Ok(())
}

fn append_bounded_log(logs: &mut String, message: &str) {
    logs.push_str(message);
    logs.push('\n');
    if logs.len() <= MAX_LOG_BYTES {
        return;
    }

    let mut start = logs.len().saturating_sub(RETAIN_LOG_BYTES);
    while start < logs.len() && !logs.is_char_boundary(start) {
        start += 1;
    }
    start = logs[start..]
        .find('\n')
        .map_or(logs.len(), |newline| start + newline + 1);

    let mut retained = String::with_capacity(logs.len().saturating_sub(start));
    retained.push_str(&logs[start..]);
    *logs = retained;
}

#[cfg(windows)]
#[allow(dead_code)]
fn read_windows_credential(target: &str) -> Result<String, String> {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target_wide = target
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
        return Err(format!(
            "Windows Credential Manager read failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if credential.is_null() {
        return Err("Windows Credential Manager returned an empty record".to_owned());
    }

    let result = (|| {
        let record = unsafe { &*credential };
        if record.CredentialBlobSize == 0 || record.CredentialBlob.is_null() {
            return Err("The local Router credential is empty".to_owned());
        }
        if record.CredentialBlobSize % 2 != 0 {
            return Err("The local Router credential has an invalid encoding".to_owned());
        }
        let units = unsafe {
            std::slice::from_raw_parts(
                record.CredentialBlob.cast::<u16>(),
                record.CredentialBlobSize as usize / 2,
            )
        };
        String::from_utf16(units)
            .map_err(|_| "The local Router credential has an invalid encoding".to_owned())
    })();
    unsafe { CredFree(credential.cast()) };
    result
}

fn router_deep_health(base_uri: &str, timeout: std::time::Duration) -> Result<(), String> {
    let base = url::Url::parse(base_uri).map_err(|_| "Router URL is invalid".to_owned())?;
    if base.scheme() != "http" {
        return Err("Router health checks require a local HTTP URL".to_owned());
    }
    let host = base
        .host_str()
        .ok_or_else(|| "Router URL has no host".to_owned())?;
    let local_host = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !local_host {
        return Err("Router health checks refuse non-local addresses".to_owned());
    }
    let port = base
        .port_or_known_default()
        .ok_or_else(|| "Router URL has no port".to_owned())?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("Router address resolution failed: {error}"))?
        .filter(|address| address.ip().is_loopback())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("Router URL did not resolve to a loopback address".to_owned());
    }

    let started = std::time::Instant::now();
    let mut last_error = None;
    let mut stream = None;
    for address in addresses {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        format!(
            "Router connection failed: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "timeout".to_owned())
        )
    })?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("Router health check timed out".to_owned());
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("Router read timeout setup failed: {error}"))?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|error| format!("Router write timeout setup failed: {error}"))?;

    let api_key = crate::credentials::read_text("LocalApiKey")
        .map_err(|error| error.to_string())?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "The local Router credential is missing".to_owned())?;
    let api_key = api_key.as_str();
    if api_key.contains(['\r', '\n']) {
        return Err("The local Router credential contains invalid characters".to_owned());
    }
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!(
        "GET /v1/models HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {api_key}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let write_result = stream.write_all(&request);
    request.fill(0);
    write_result.map_err(|error| format!("Router health request failed: {error}"))?;

    let mut response = [0u8; 1024];
    let read = stream
        .read(&mut response)
        .map_err(|error| format!("Router health response failed: {error}"))?;
    if read == 0 {
        return Err("Router health response was empty".to_owned());
    }
    let first_line_end = response[..read]
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(read);
    let status_line = String::from_utf8_lossy(&response[..first_line_end]);
    if status_line.starts_with("HTTP/1.1 200 ") || status_line.starts_with("HTTP/1.0 200 ") {
        Ok(())
    } else {
        Err(format!("Router health returned {status_line}"))
    }
}

fn classify_router_health_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        format!("class=timeout | code=CR-LFC-0006 | {error}")
    } else if lower.contains("refused")
        || lower.contains("connect")
        || lower.contains("not currently reachable")
    {
        format!("class=connection_refused | code=CR-LFC-0004 | {error}")
    } else if lower.contains("http/1.") || lower.contains("returned") {
        format!("class=health_http | code=CR-LFC-0006 | {error}")
    } else if lower.contains("empty") {
        format!("class=empty_response | code=CR-LFC-0006 | {error}")
    } else {
        format!("class=request_failure | code=CR-LFC-0006 | {error}")
    }
}

fn router_health_failure_recoverable(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    !(normalized.contains("credential")
        || normalized.contains("router url")
        || normalized.contains("non-local")
        || normalized.contains("invalid encoding")
        || normalized.contains("http/1.1 401")
        || normalized.contains("http/1.0 401")
        || normalized.contains("http/1.1 403")
        || normalized.contains("http/1.0 403"))
}

/// Returns the platform font directory, the Latin font specs, and the CJK
/// candidate file names. Windows reads the per-user/machine Fonts dir;
/// macOS reads `/System/Library/Fonts` (Hiragino Sans GB / STHeiti provide
/// Simplified-Chinese glyph coverage in place of Microsoft YaHei).
fn platform_font_sources() -> (PathBuf, Vec<(&'static str, &'static str)>, Vec<&'static str>) {
    #[cfg(windows)]
    {
        let font_dir = std::env::var_os("WINDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("Fonts");
        let specs = vec![
            ("segoe", "segoeui.ttf"),
            ("segoe-symbol", "seguisym.ttf"),
            ("arial-black", "ariblk.ttf"),
            ("georgia-italic", "georgiai.ttf"),
            ("consolas", "consola.ttf"),
        ];
        let cjk = vec!["msyh.ttc", "msyh.ttf", "msyhbd.ttc", "simsun.ttc", "simhei.ttf", "Deng.ttf"];
        (font_dir, specs, cjk)
    }
    #[cfg(target_os = "macos")]
    {
        let font_dir = PathBuf::from("/System/Library/Fonts");
        let specs = vec![
            // Latin UI fonts with macOS system counterparts.
            ("segoe", "Helvetica.ttc"),
            ("arial-black", "HelveticaNeue.ttc"),
            ("georgia-italic", "NewYorkItalic.ttf"),
            ("consolas", "Menlo.ttc"),
        ];
        let cjk = vec![
            "Hiragino Sans GB.ttc",
            "STHeiti Light.ttc",
            "STHeiti Medium.ttc",
        ];
        (font_dir, specs, cjk)
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        // Non-Windows/non-macOS: no bundled fonts, rely on egui defaults only.
        (PathBuf::new(), Vec::new(), Vec::new())
    }
}

/// Installs the full font set. Returns false when no CJK font could be read
/// so callers keep retrying instead of freezing the UI in tofu boxes.
fn install_app_fonts(ctx: &egui::Context) -> bool {
    let mut fonts = egui::FontDefinitions::default();
    let (font_dir, font_specs, cjk_candidates) = platform_font_sources();
    for (name, file_name) in font_specs {
        if let Ok(data) = std::fs::read(font_dir.join(file_name)) {
            fonts
                .font_data
                .insert(name.into(), egui::FontData::from_owned(data).into());
        }
    }
    // CJK coverage is what keeps the Chinese UI from turning into tofu. A
    // transient read failure (file lock, pending Windows update) must not
    // mark the full font set as installed, so try several CJK candidates and
    // report whether any of them landed.
    let mut cjk_name = "msyh";
    for file_name in cjk_candidates {
        if let Ok(data) = std::fs::read(font_dir.join(file_name)) {
            fonts
                .font_data
                .insert(cjk_name.into(), egui::FontData::from_owned(data).into());
            break;
        }
    }
    if fonts.font_data.contains_key("segoe") {
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "segoe".into());
    }
    if fonts.font_data.contains_key("msyh") {
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "msyh".into());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, "msyh".into());
    }
    if fonts.font_data.contains_key("segoe-symbol") {
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push("segoe-symbol".into());
    }
    if fonts.font_data.contains_key("consolas") {
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, "consolas".into());
    }
    let mut display_fonts = Vec::new();
    if fonts.font_data.contains_key("arial-black") {
        display_fonts.push("arial-black".into());
    }
    if fonts.font_data.contains_key("msyh") {
        display_fonts.push("msyh".into());
    }
    if fonts.font_data.contains_key("segoe-symbol") {
        display_fonts.push("segoe-symbol".into());
    }
    fonts
        .families
        .insert(theme::display_family(), display_fonts);
    let mut serif_fonts = Vec::new();
    if fonts.font_data.contains_key("georgia-italic") {
        serif_fonts.push("georgia-italic".into());
    }
    if fonts.font_data.contains_key("msyh") {
        serif_fonts.push("msyh".into());
    }
    fonts.families.insert(theme::serif_family(), serif_fonts);
    let cjk_loaded = fonts.font_data.contains_key("msyh");
    ctx.set_fonts(fonts);
    cjk_loaded
}

fn install_lightweight_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let fallback = fonts
        .families
        .get(&egui::FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    fonts
        .families
        .insert(theme::display_family(), fallback.clone());
    fonts.families.insert(theme::serif_family(), fallback);
    ctx.set_fonts(fonts);
}

/// Lightweight tray mode drops CJK glyphs. Any path that makes the window
/// visible again must restore the full font set first, otherwise the UI turns
/// into tofu boxes (the "zombie" window after a failed full exit).
pub(crate) fn ensure_full_ui_fonts(app: &mut CodexRouterApp, ctx: &egui::Context) {
    if !app.fonts_loaded {
        if app
            .fonts_retry_after
            .is_some_and(|deadline| std::time::Instant::now() < deadline)
        {
            return;
        }
        if install_app_fonts(ctx) {
            app.fonts_loaded = true;
            app.fonts_retry_after = None;
            app.installed_theme.clear();
        } else {
            // No CJK font this time (transient lock or missing fonts);
            // keep fonts_loaded=false and retry instead of sticking in tofu.
            app.fonts_retry_after =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
        }
    }
    if app.tray_lightweight_mode && app.fonts_loaded {
        app.tray_lightweight_mode = false;
    }
}

impl CodexRouterApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        start_in_background: bool,
        ui_audit: Option<UiAuditOptions>,
    ) -> Self {
        if let Some(options) = ui_audit {
            return Self::new_ui_audit(cc, options);
        }
        let (event_tx, event_rx) = channel();
        let (runtime_log_tx, runtime_log_rx) = runtime_logs::bounded_channel();
        let router_root = RouterConfig::find_router_root();
        let _ = user_data::prepare(&router_root);
        crate::credentials::set_scope_from_root(&router_root);
        let ui_preferences_path = user_data::preferences_path(&router_root);
        let mut ui_preferences = UiPreferences::load(&ui_preferences_path).unwrap_or_default();
        // Bump forces the minimize-to-tray first-close prompt once more after
        // upgrades that previously remembered Exit.
        if ui_preferences.close_warning_version < 2 {
            ui_preferences.close_behavior = CloseBehavior::Ask;
            ui_preferences.close_warning_version = 2;
        }
        // Rewrite legacy preference files once so newly defaulted fields are
        // explicit and portable across subsequent versions.
        let _ = ui_preferences.save(&ui_preferences_path);
        let close_behavior = ui_preferences.close_behavior;
        let mut active_profile_id = ui_preferences.active_profile_id.clone();
        let monitor_subscription_order = ui_preferences.monitor_subscription_order.clone();
        let monitor_api_order = ui_preferences.monitor_api_order.clone();
        let share_codex_state = ui_preferences.share_codex_state;
        let oauth_model_hint_seen = ui_preferences.oauth_model_hint_seen;
        let isolation_profiles = profiles::list_profiles(&router_root).unwrap_or_default();
        let config_path = user_data::config_path(&router_root);
        let (mut config, mut page, configured) = match RouterConfig::load(&config_path) {
            Ok(cfg) => {
                let (page, configured) = initial_page_for_config(Some(&cfg));
                if configured {
                    (cfg, page, true)
                } else {
                    // Partial leftover JSON must not skip the welcome wizard.
                    let mut fresh = RouterConfig::default();
                    if !cfg.ui_theme.trim().is_empty() {
                        fresh.ui_theme = cfg.ui_theme;
                    }
                    (fresh, page, false)
                }
            }
            Err(_) => {
                let (page, configured) = initial_page_for_config(None);
                (RouterConfig::default(), page, configured)
            }
        };
        if let Some(recovered) = recover_single_profile_binding(
            config.deploy.generate_isolation,
            &active_profile_id,
            &isolation_profiles,
        ) {
            active_profile_id = recovered;
            ui_preferences.active_profile_id.clone_from(&active_profile_id);
            let _ = ui_preferences.save(&ui_preferences_path);
        }
        if std::env::var_os("CODEX_ROUTER_FORCE_WELCOME").is_some_and(|value| value == "1")
            || !user_data::config_looks_configured(&config)
        {
            page = Page::Welcome;
        }
        config.version = CURRENT_CONFIG_VERSION.to_owned();
        if config.ui_theme.trim().is_empty()
            || !matches!(config.ui_theme.as_str(), "sky" | "coffee")
        {
            config.ui_theme = "sky".to_owned();
        }
        logic::normalize_default_model(&mut config);
        if configured {
            let _ = logic::sync_model_catalog_compact_percent(&config, &router_root);
        }
        // Upgrade/startup is the safest repair window: reconcile immediately
        // only when the entire Codex package is already stopped. If Codex is
        // running, the background reconciler waits for a later clean exit.
        if configured && !platform::codex_desktop_running() {
            let _ = profiles::reconcile_codex_archives_offline(&config);
        }
        if !configured {
            // Fresh installs always start on 雾蓝 unless the user toggles later.
            config.ui_theme = "sky".to_owned();
        }
        if let Some(saved_theme) = cc
            .storage
            .and_then(|storage| storage.get_string("codex-router-ui-theme-v3"))
        {
            if configured && matches!(saved_theme.as_str(), "coffee" | "sky") {
                config.ui_theme = saved_theme;
            }
        }
        let ui_language = cc
            .storage
            .and_then(|storage| storage.get_string("codex-router-ui-language-v1"))
            .filter(|language| matches!(language.as_str(), "zh" | "en"))
            .unwrap_or_else(system_ui_language);
        let startup_fonts_loaded = if !start_in_background {
            install_app_fonts(&cc.egui_ctx)
        } else {
            install_lightweight_fonts(&cc.egui_ctx);
            false
        };
        theme::install(&cc.egui_ctx, &theme::palette(&config.ui_theme));
        let installed_theme = config.ui_theme.clone();
        let installed_compact_layout = cc.egui_ctx.content_rect().height() < 700.0;
        let tray_menu = tray_icon::menu::Menu::new();
        let menu_text = |zh_text, en_text| {
            if ui_language == "zh" {
                zh_text
            } else {
                en_text
            }
        };
        let open_console =
            tray_icon::menu::MenuItem::new(menu_text("打开控制台", "Open console"), true, None);
        let choose_profile = tray_icon::menu::MenuItem::new(
            menu_text("选择配置", "Choose configuration"),
            true,
            None,
        );
        let apply_current = tray_icon::menu::MenuItem::new(
            menu_text("保存并应用当前配置", "Save and apply current configuration"),
            true,
            None,
        );
        let start_forwarding =
            tray_icon::menu::MenuItem::new(menu_text("启动转发", "Start forwarding"), true, None);
        let stop_forwarding =
            tray_icon::menu::MenuItem::new(menu_text("关闭转发", "Stop forwarding"), true, None);
        let hide_window = tray_icon::menu::MenuItem::new(
            menu_text("关闭配置窗口", "Close configuration window"),
            true,
            None,
        );
        let exit_app = tray_icon::menu::MenuItem::new(menu_text("退出软件", "Exit"), true, None);
        for item in [
            &open_console,
            &choose_profile,
            &apply_current,
            &start_forwarding,
            &stop_forwarding,
            &hide_window,
            &exit_app,
        ] {
            let _ = tray_menu.append(item);
        }
        let open_console_id = open_console.id().clone();
        let choose_profile_id = choose_profile.id().clone();
        let apply_current_id = apply_current.id().clone();
        let start_forwarding_id = start_forwarding.id().clone();
        let stop_forwarding_id = stop_forwarding.id().clone();
        let hide_window_id = hide_window.id().clone();
        let exit_app_id = exit_app.id().clone();

        let tray = decode_icon().ok().and_then(|(rgba, width, height)| {
            tray_icon::Icon::from_rgba(rgba, width, height)
                .ok()
                .and_then(|icon| {
                    tray_icon::TrayIconBuilder::new()
                        .with_tooltip(APP_TITLE)
                        .with_icon(icon)
                        .with_menu(Box::new(tray_menu))
                        .with_menu_on_left_click(false)
                        .build()
                        .ok()
                })
        });
        if let Some(tray_icon) = &tray {
            let tray_id = tray_icon.id().clone();
            let tray_ctx = cc.egui_ctx.clone();
            let tray_tx = event_tx.clone();
            tray_icon::TrayIconEvent::set_event_handler(Some(
                move |event: tray_icon::TrayIconEvent| {
                    if event.id() != &tray_id {
                        return;
                    }
                    let restore = matches!(
                        event,
                        tray_icon::TrayIconEvent::Click {
                            button: tray_icon::MouseButton::Left,
                            button_state: tray_icon::MouseButtonState::Up,
                            ..
                        } | tray_icon::TrayIconEvent::DoubleClick {
                            button: tray_icon::MouseButton::Left,
                            ..
                        }
                    );
                    if restore {
                        tray_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        tray_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        tray_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        let _ = tray_tx.send(AppEvent::Tray(TrayAction::RestoreWindow));
                        tray_ctx.request_repaint();
                    }
                },
            ));
        }
        let menu_ctx = cc.egui_ctx.clone();
        let menu_tx = event_tx.clone();
        tray_icon::menu::MenuEvent::set_event_handler(Some(
            move |event: tray_icon::menu::MenuEvent| {
                let action = if event.id() == &open_console_id {
                    Some(TrayAction::OpenConsole)
                } else if event.id() == &choose_profile_id {
                    Some(TrayAction::ChooseProfile)
                } else if event.id() == &apply_current_id {
                    Some(TrayAction::ApplyCurrent)
                } else if event.id() == &start_forwarding_id {
                    Some(TrayAction::StartForwarding)
                } else if event.id() == &stop_forwarding_id {
                    Some(TrayAction::StopForwarding)
                } else if event.id() == &hide_window_id {
                    Some(TrayAction::HideWindow)
                } else if event.id() == &exit_app_id {
                    Some(TrayAction::Exit)
                } else {
                    None
                };
                if let Some(action) = action {
                    let _ = menu_tx.send(AppEvent::Tray(action));
                    menu_ctx.request_repaint();
                }
            },
        ));
        let project_path_input = router_root.to_string_lossy().to_string();
        let configured_router_mode = logic::codex_router_mode_configured(&config);
        // Prefer the explicit dashboard switch intent. Third-party tools that
        // rewrite model_providers.custom must not silently disable Router mode.
        let router_mode_enabled = router_mode_enabled_on_startup(
            ui_preferences.prefer_router_mode,
            ui_preferences.official_mode_selected,
            configured_router_mode,
            configured,
            !config.models.is_empty(),
            codex_user_model_is_invalid_first(&config),
        );
        let codex_account_mode_status = profiles::codex_account_mode_status(&router_root, &config);
        let has_selected_oauth = config
            .oauth_account_ids
            .as_ref()
            .is_some_and(|accounts| !accounts.is_empty())
            || config.models.iter().any(|model| model.source == "oauth");
        let oauth_recovery_due = (configured && router_mode_enabled && has_selected_oauth)
            .then(|| std::time::Instant::now() + std::time::Duration::from_secs(300));
        let startup_router_recovery = configured && router_mode_enabled;
        let runtime_log_paused = Arc::new(AtomicBool::new(start_in_background));
        let mut app = Self {
            ui_audit_mode: false,
            ui_audit_screenshot_path: None,
            ui_audit_frame_count: 0,
            ui_audit_screenshot_requested: false,
            page,
            router_root,
            project_path_input,
            config,
            temp_model: ModelConfig::default(),
            editing_model: None,
            model_from_wizard: true,
            api_model_validation_running: false,
            api_model_choice_open: false,
            api_model_choice_ids: Vec::new(),
            api_model_choice_model: None,
            api_model_choice_editing: None,
            api_model_choice_from_wizard: false,
            proxy_from_wizard: true,
            status_text: String::new(),
            status_expires_at: None,
            logs: String::new(),
            event_rx,
            event_tx,
            runtime_log_rx,
            applying: false,
            apply_cancel: Arc::new(AtomicBool::new(false)),
            apply_settle_until: None,
            configured,
            logo_texture: None,
            fonts_loaded: startup_fonts_loaded,
            fonts_retry_after: None,
            tray_icon: tray,
            last_page: page,
            profiles_return_page: Page::Dashboard,
            page_changed_at: std::time::Instant::now(),
            installed_theme,
            installed_compact_layout,
            ui_language,
            terms_open: false,
            terms_scroll_complete: false,
            terms_scroll_reset_pending: false,
            advanced_json_open: false,
            advanced_json_draft: String::new(),
            reasoning_open: false,
            reasoning_mode_draft: "auto".to_owned(),
            reasoning_levels_draft: String::new(),
            reasoning_default_draft: String::new(),
            reasoning_fast_supported_draft: false,
            reasoning_fast_mode_draft: false,
            close_behavior,
            autostart_switching: false,
            close_prompt_open: false,
            apply_success_dialog_open: false,
            apply_success_is_subscription: false,
            result_dialog_open: false,
            result_dialog_kind: ResultDialogKind::Success,
            result_dialog_title: String::new(),
            result_dialog_body: String::new(),
            remember_close_choice: false,
            exit_after_prompt: false,
            exit_shutdown_in_progress: false,
            exit_shutdown_error: String::new(),
            local_profile_name_input: String::new(),
            isolation_profiles,
            active_profile_id,
            pending_profile_activation: None,
            profile_delete_target: None,
            profile_create_open: false,
            pending_apply_rollback: None,
            oauth_accounts: Vec::new(),
            oauth_loading: false,
            oauth_catalog_refresh_pending: false,
            oauth_error: String::new(),
            oauth_retry_due: None,
            oauth_retry_attempts: 0,
            oauth_return_page: Page::Dashboard,
            oauth_provider_draft: "openai".to_owned(),
            provider_oauth_running: false,
            oauth_post_login_prompt_open: false,
            oauth_model_hint_seen,
            pending_oauth_provider: None,
            oauth_auto_enable_provider: None,
            oauth_in_flight_provider: None,
            oauth_known_account_ids: Vec::new(),
            oauth_success_pending: false,
            provider_oauth_preparing: false,
            provider_oauth_preparing_provider: None,
            provider_oauth_prepare_generation: 0,
            provider_oauth_prepared_provider: None,
            provider_oauth_prepare_error: String::new(),
            provider_oauth_prepare_cancel: Arc::new(AtomicBool::new(false)),
            provider_oauth_cancel: Arc::new(AtomicBool::new(false)),
            provider_oauth_prompt: None,
            provider_oauth_code_draft: String::new(),
            provider_oauth_gemini_code_assist: false,
            provider_oauth_project_draft: String::new(),
            oauth_revoke_target: None,
            oauth_revoke_candidates: Vec::new(),
            oauth_revoking: false,
            oauth_priority_target: None,
            oauth_priority_draft: 1,
            oauth_priority_saving: false,
            oauth_fallback_picker_target: None,
            oauth_fallback_picker_draft: BTreeMap::new(),
            model_route_policy_target: None,
            model_route_policy_draft: logic::ModelRoutePolicy::SubscriptionFirst,
            model_priority_dialog_target: None,
            model_priority_order: Vec::new(),
            usage_snapshot: None,
            usage_snapshot_profile_key: String::new(),
            usage_loading: false,
            usage_request_generation: 0,
            usage_error: String::new(),
            usage_return_page: Page::Dashboard,
            // Repair an externally overwritten Codex binding immediately on
            // startup; subsequent checks retain the three-minute cadence.
            usage_refresh_due: (configured && router_mode_enabled).then(std::time::Instant::now),
            self_check_quota_refresh_pending: false,
            notified_quota_accounts: BTreeSet::new(),
            usage_notifications_ready: false,
            notified_pool_failovers: BTreeSet::new(),
            rejoined_pool_notified: BTreeSet::new(),
            monitor_subscription_order,
            monitor_api_order,
            share_codex_state,
            router_mode_enabled,
            official_mode_selected: ui_preferences.official_mode_selected,
            router_mode_switching: false,
            codex_account_mode_status,
            codex_account_mode_switching: false,
            oauth_recovery_due,
            oauth_recovery_running: false,
            oauth_recovery_cancel: Arc::new(AtomicBool::new(false)),
            grok_sso_dialog_open: false,
            grok_sso_draft: String::new(),
            grok_sso_importing: false,
            grok_sso_error: String::new(),
            grok_sso_auto_select_pending: false,
            channel_preset_dialog_open: false,
            recommended_platform_dialog_open: false,
            log_scroll_to_bottom: true,
            log_follow_latest: true,
            log_dialog_open: false,
            runtime_log_stop: Arc::new(AtomicBool::new(false)),
            runtime_log_paused,
            tray_lightweight_mode: start_in_background,
            background_hide_until: start_in_background
                .then(|| std::time::Instant::now() + std::time::Duration::from_secs(2)),
            tray_restore_guard_until: None,
            last_normal_window_size: stored_window_size(
                ui_preferences.window_width,
                ui_preferences.window_height,
            )
            .unwrap_or_else(|| initial_window_logical_size(false)),
            health_probe_due: (configured && router_mode_enabled)
                .then(|| std::time::Instant::now() + HEALTHY_PROBE_INTERVAL),
            health_probe_running: false,
            health_probe_failures: 0,
            health_recovery_running: startup_router_recovery,
            health_recovery_cancel: Arc::new(AtomicBool::new(false)),
            routing_sync_running: false,
            routing_sync_pending: false,
            codex_binding_repair_running: false,
            codex_binding_check_completed: false,
            codex_binding_safe_strip_logged: None,
            codex_overwrite_prompt_open: false,
            codex_overwrite_auto_apply_at: None,
            codex_overwrite_countdown_paused_at: None,
            codex_overwrite_pending_fingerprint: String::new(),
            codex_overwrite_action_running: false,
            codex_overwrite_decision: ui_preferences.codex_overwrite_decision.clone(),
            codex_overwrite_decision_fingerprint: ui_preferences
                .codex_overwrite_fingerprint
                .clone(),
            update_checking: false,
            update_downloading: false,
            update_downloaded_bytes: 0,
            update_total_bytes: 0,
            update_installing: false,
            update_dialog_open: false,
            update_info: None,
        };
        if startup_router_recovery {
            let root = app.router_root.clone();
            let tx = app.event_tx.clone();
            let cancel = app.health_recovery_cancel.clone();
            std::thread::spawn(move || {
                let result = lifecycle::ensure_services(&root, true, &cancel, false)
                    .map(|_| ())
                    .map_err(|error| error.to_string());
                tx.send(AppEvent::RouterHealthRecoveryFinished(result)).ok();
            });
        }
        if !start_in_background {
            app.load_usage_monitor_cache();
            if configured {
                app.refresh_oauth_accounts();
            }
        } else if let Some(tray) = &app.tray_icon {
            let _ = tray.set_tooltip(Some(if app.ui_language == "zh" {
                TRAY_TOOLTIP_ZH
            } else {
                TRAY_TOOLTIP_EN
            }));
        }
        runtime_logs::spawn(
            app.router_root.clone(),
            runtime_log_tx,
            cc.egui_ctx.clone(),
            app.runtime_log_stop.clone(),
            app.runtime_log_paused.clone(),
        );
        if configured {
            profiles::spawn_codex_archive_reconciler(
                app.config.clone(),
                app.runtime_log_stop.clone(),
            );
        }
        if configured || legacy_autostart_shortcut_exists() {
            app.reconcile_autostart_registration();
        }
        if router_mode_enabled && !ui_preferences.prefer_router_mode {
            // Migrate older installs that already bind Codex to Router.
            let _ = app.persist_ui_preferences();
        }
        app
    }

    fn new_ui_audit(cc: &eframe::CreationContext<'_>, options: UiAuditOptions) -> Self {
        let (event_tx, event_rx) = channel();
        let (runtime_log_tx, runtime_log_rx) = runtime_logs::bounded_channel();
        drop(runtime_log_tx);

        let _ = install_app_fonts(&cc.egui_ctx);
        let mut config = RouterConfig {
            version: CURRENT_CONFIG_VERSION.to_owned(),
            ui_theme: options.theme.clone(),
            accept_compliance: true,
            accepted_terms_version: CURRENT_TERMS_VERSION.to_owned(),
            oauth_account_ids: Some(vec![101, 202]),
            oauth_seen_account_ids: vec![101, 202, 303],
            models: vec![
                ModelConfig {
                    model: "gpt-5.6-sol".to_owned(),
                    alias: "ChatGPT-5.6-Sol".to_owned(),
                    base_url: "Router OAuth / openai".to_owned(),
                    priority: 1,
                    reasoning_mode: "manual".to_owned(),
                    reasoning_levels: vec![
                        "low".to_owned(),
                        "medium".to_owned(),
                        "high".to_owned(),
                        "xhigh".to_owned(),
                        "max".to_owned(),
                        "ultra".to_owned(),
                    ],
                    default_reasoning_level: "max".to_owned(),
                    fast_supported: true,
                    fast_mode: true,
                    source: "oauth".to_owned(),
                    oauth_account_id: 101,
                    oauth_platform: "openai".to_owned(),
                    ..Default::default()
                },
                ModelConfig {
                    model: "gpt-5.6-sol".to_owned(),
                    alias: "ChatGPT-5.6-Sol".to_owned(),
                    base_url: "https://api.430123.xyz/v1".to_owned(),
                    credential_name: "OpenAiAuditBackupKey".to_owned(),
                    priority: 10,
                    source: "apikey".to_owned(),
                    ..Default::default()
                },
                ModelConfig {
                    model: "claude-opus-4-6".to_owned(),
                    alias: "Claude Opus 4.6 / API backup".to_owned(),
                    base_url: "https://api.anthropic.com".to_owned(),
                    credential_name: "AnthropicAuditKey".to_owned(),
                    priority: 100,
                    weight: 2,
                    source: "apikey".to_owned(),
                    ..Default::default()
                },
                ModelConfig {
                    model: "kimi-for-coding".to_owned(),
                    alias: "Kimi for Coding / fallback".to_owned(),
                    base_url: "https://api.kimi.com/coding/v1".to_owned(),
                    credential_name: "KimiAuditKey".to_owned(),
                    priority: 120,
                    source: "apikey".to_owned(),
                    ..Default::default()
                },
            ],
            default_model: "gpt-5.6-sol".to_owned(),
            ..Default::default()
        };
        theme::install(&cc.egui_ctx, &theme::palette(&config.ui_theme));

        let oauth_accounts = vec![
            OAuthAccountSummary {
                id: 101,
                name: "OpenAI Pro / primary".to_owned(),
                platform: "openai".to_owned(),
                status: "active".to_owned(),
                email: "router.qa@example.com".to_owned(),
                plan: "pro".to_owned(),
                priority: 1,
                bound_to_router: true,
                error: String::new(),
                expires_at: "2026-08-31T16:00:00Z".to_owned(),
                models: vec![
                    OAuthModelSummary {
                        id: "gpt-5.6-sol".to_owned(),
                        display_name: "ChatGPT-5.6-Sol".to_owned(),
                    },
                    OAuthModelSummary {
                        id: "gpt-5.6-terra".to_owned(),
                        display_name: "ChatGPT-5.6-Terra".to_owned(),
                    },
                    OAuthModelSummary {
                        id: "gpt-5.6-luna".to_owned(),
                        display_name: "ChatGPT-5.6-Luna".to_owned(),
                    },
                ],
                models_error: String::new(),
            },
            OAuthAccountSummary {
                id: 202,
                name: "Gemini workspace".to_owned(),
                platform: "gemini".to_owned(),
                status: "warning".to_owned(),
                email: "very-long-account-name-for-layout@example.com".to_owned(),
                plan: "workspace enterprise".to_owned(),
                priority: 20,
                bound_to_router: false,
                error: "Token refresh will be retried automatically".to_owned(),
                expires_at: "2026-08-04T03:15:00Z".to_owned(),
                models: vec![OAuthModelSummary {
                    id: "gemini-3.6-pro-preview".to_owned(),
                    display_name: "Gemini 3.6 Pro Preview".to_owned(),
                }],
                models_error: String::new(),
            },
        ];

        let usage_snapshot = UsageSnapshot {
            profile_name: "Production / long configuration name".to_owned(),
            queried_at: "2026-08-03T03:45:00Z".to_owned(),
            total_tokens: 12_845_930,
            total_requests: 842,
            total_cost: 18.4271,
            routing_changed: false,
            subscriptions: vec![
                UsageAccount {
                    id: 101,
                    name: "OpenAI Pro / primary".to_owned(),
                    kind: "subscription".to_owned(),
                    platform: "openai".to_owned(),
                    status: "active".to_owned(),
                    health: "quotaExhausted".to_owned(),
                    status_detail: "The account quota has been exhausted.".to_owned(),
                    query_note: "Live quota returned by provider".to_owned(),
                    updated_at: "2026-08-03T03:45:00Z".to_owned(),
                    totals: UsageTotals {
                        requests: 512,
                        total_tokens: 9_842_331,
                        cost: 0.0,
                        models: Vec::new(),
                    },
                    windows: vec![
                        UsageWindow {
                            kind: "fiveHour".to_owned(),
                            display_name: String::new(),
                            used_percent: Some(62.0),
                            reset_at: "2026-08-03T08:30:00Z".to_owned(),
                            remaining_seconds: 14_400,
                            requests: 148,
                            tokens: 2_300_400,
                            ..Default::default()
                        },
                        UsageWindow {
                            kind: "weekly".to_owned(),
                            display_name: String::new(),
                            used_percent: Some(100.0),
                            reset_at: "2026-08-08T03:45:00Z".to_owned(),
                            remaining_seconds: 432_000,
                            requests: 512,
                            tokens: 9_842_331,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                UsageAccount {
                    id: 202,
                    name: "Antigravity workspace / shared quota".to_owned(),
                    kind: "subscription".to_owned(),
                    platform: "antigravity".to_owned(),
                    status: "active".to_owned(),
                    health: "healthy".to_owned(),
                    status_detail: "Several models share this server-side quota pool.".to_owned(),
                    query_note: "Three live models reported the same quota window.".to_owned(),
                    updated_at: "2026-08-03T03:45:00Z".to_owned(),
                    totals: UsageTotals {
                        requests: 74,
                        total_tokens: 1_540_000,
                        cost: 0.0,
                        models: Vec::new(),
                    },
                    windows: vec![UsageWindow {
                        kind: "sharedPool".to_owned(),
                        display_name: "Antigravity shared quota".to_owned(),
                        used_percent: Some(27.0),
                        reset_at: "2026-08-08T03:34:00Z".to_owned(),
                        remaining_seconds: 431_340,
                        requests: 74,
                        tokens: 1_540_000,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            api_channels: vec![UsageAccount {
                id: 303,
                name: "Anthropic API backup channel".to_owned(),
                kind: "api".to_owned(),
                platform: "anthropic".to_owned(),
                status: "active".to_owned(),
                health: "healthy".to_owned(),
                updated_at: "2026-08-03T03:45:00Z".to_owned(),
                totals: UsageTotals {
                    requests: 256,
                    total_tokens: 1_463_599,
                    cost: 18.4271,
                    models: vec![UsageModelSummary {
                        name: "claude-opus-4-6".to_owned(),
                        requests: 256,
                        input_tokens: 1_100_000,
                        output_tokens: 240_000,
                        cache_read_tokens: 100_000,
                        cache_creation_tokens: 23_599,
                        total_tokens: 1_463_599,
                        cost: 18.4271,
                    }],
                },
                ..Default::default()
            }],
        };

        let page = match options.scenario.as_str() {
            "welcome" => Page::Welcome,
            "project" => Page::Project,
            "auth" => Page::Auth,
            "model"
            | "advanced-json"
            | "reasoning"
            | "channel-preset"
            | "model-priority"
            | "recommended-platforms" => Page::Model,
            "proxy-auto" | "proxy-manual" => Page::Proxy,
            "finish"
            | "terms"
            | "oauth-terms-preparing"
            | "oauth-terms-ready"
            | "oauth-terms-error" => Page::Finish,
            "profiles" | "profiles-empty" => Page::Profiles,
            "oauth" | "oauth-loading" | "oauth-error" | "oauth-revoke" | "oauth-fallback"
            | "grok-sso" | "sub2api" => Page::OAuth,
            "monitor" | "monitor-loading" | "monitor-error" => Page::Monitor,
            _ => Page::Dashboard,
        };
        if options.scenario == "proxy-manual" {
            config.proxy.auto_detect = false;
            config.proxy.enabled = true;
            config.proxy.proxy_type = "socks5".to_owned();
            config.proxy.host = "proxy.office.example".to_owned();
            config.proxy.port = "1080".to_owned();
            config.proxy.username = "domain\\router-user".to_owned();
        }
        if matches!(
            options.scenario.as_str(),
            "terms" | "oauth-terms-preparing" | "oauth-terms-ready" | "oauth-terms-error"
        ) {
            config.accept_compliance = false;
            config.accepted_terms_version.clear();
        }
        if options.scenario == "dashboard-empty" {
            config.models.clear();
            config.default_model.clear();
        }

        let first_oauth_account = oauth_accounts.first().cloned();
        let mut app = Self {
            ui_audit_mode: true,
            ui_audit_screenshot_path: options.screenshot_path,
            ui_audit_frame_count: 0,
            ui_audit_screenshot_requested: false,
            page,
            router_root: std::env::temp_dir().join("codex-router-ui-audit-read-only"),
            project_path_input: r"C:\Tools\Codex-Router-Portable".to_owned(),
            temp_model: config.models.first().cloned().unwrap_or_default(),
            config,
            editing_model: None,
            model_from_wizard: true,
            api_model_validation_running: false,
            api_model_choice_open: false,
            api_model_choice_ids: Vec::new(),
            api_model_choice_model: None,
            api_model_choice_editing: None,
            api_model_choice_from_wizard: false,
            proxy_from_wizard: true,
            status_text: "UI audit mode: no system configuration will be changed.".to_owned(),
            status_expires_at: None,
            logs: "[03:44:58] Router health check: healthy\n[03:45:00] Usage data refreshed\n[03:45:02] OAuth fallback route is ready\n[03:45:04] Unicode check: 中文、模型、连接稳定\n".repeat(8),
            event_rx,
            event_tx,
            runtime_log_rx,
            applying: false,
            apply_cancel: Arc::new(AtomicBool::new(false)),
            apply_settle_until: None,
            configured: true,
            logo_texture: None,
            fonts_loaded: true,
            fonts_retry_after: None,
            tray_icon: None,
            last_page: page,
            profiles_return_page: Page::Dashboard,
            page_changed_at: std::time::Instant::now() - std::time::Duration::from_secs(1),
            installed_theme: options.theme,
            installed_compact_layout: options.compact,
            ui_language: options.language,
            terms_open: false,
            terms_scroll_complete: false,
            terms_scroll_reset_pending: false,
            advanced_json_open: false,
            advanced_json_draft: "{\n  \"temperature\": 0.2,\n  \"metadata\": {\"audit\": true}\n}".to_owned(),
            reasoning_open: false,
            reasoning_mode_draft: "manual".to_owned(),
            reasoning_levels_draft: "low, medium, high, xhigh, max, ultra".to_owned(),
            reasoning_default_draft: "max".to_owned(),
            reasoning_fast_supported_draft: true,
            reasoning_fast_mode_draft: true,
            close_behavior: CloseBehavior::Ask,
            autostart_switching: false,
            close_prompt_open: false,
            apply_success_dialog_open: false,
            apply_success_is_subscription: false,
            result_dialog_open: false,
            result_dialog_kind: ResultDialogKind::Success,
            result_dialog_title: String::new(),
            result_dialog_body: String::new(),
            remember_close_choice: false,
            exit_after_prompt: false,
            exit_shutdown_in_progress: false,
            exit_shutdown_error: String::new(),
            local_profile_name_input: "工作 / 独立账号配置".to_owned(),
            isolation_profiles: vec![
                IsolationProfile {
                    id: "profile-work".to_owned(),
                    name: "工作账号 / 稳定路由".to_owned(),
                    kind: IsolationKind::Local,
                    created_at: "2026-08-01T09:00:00Z".to_owned(),
                    updated_at: "2026-08-03T03:00:00Z".to_owned(),
                },
                IsolationProfile {
                    id: "profile-lab".to_owned(),
                    name: "实验室 / Very long profile name for compact layout".to_owned(),
                    kind: IsolationKind::Local,
                    created_at: "2026-08-02T09:00:00Z".to_owned(),
                    updated_at: "2026-08-03T03:00:00Z".to_owned(),
                },
            ],
            active_profile_id: "profile-work".to_owned(),
            pending_profile_activation: None,
            profile_delete_target: None,
            profile_create_open: false,
            pending_apply_rollback: None,
            oauth_accounts,
            oauth_loading: false,
            oauth_catalog_refresh_pending: false,
            oauth_error: String::new(),
            oauth_retry_due: None,
            oauth_retry_attempts: 0,
            oauth_return_page: Page::Dashboard,
            oauth_provider_draft: "openai".to_owned(),
            provider_oauth_running: false,
            oauth_post_login_prompt_open: false,
            oauth_model_hint_seen: false,
            pending_oauth_provider: None,
            oauth_auto_enable_provider: None,
            oauth_in_flight_provider: None,
            oauth_known_account_ids: Vec::new(),
            oauth_success_pending: false,
            provider_oauth_preparing: false,
            provider_oauth_preparing_provider: None,
            provider_oauth_prepare_generation: 0,
            provider_oauth_prepared_provider: None,
            provider_oauth_prepare_error: String::new(),
            provider_oauth_prepare_cancel: Arc::new(AtomicBool::new(false)),
            provider_oauth_cancel: Arc::new(AtomicBool::new(false)),
            provider_oauth_prompt: None,
            provider_oauth_code_draft: String::new(),
            provider_oauth_gemini_code_assist: false,
            provider_oauth_project_draft: String::new(),
            oauth_revoke_target: None,
            oauth_revoke_candidates: Vec::new(),
            oauth_revoking: false,
            oauth_priority_target: None,
            oauth_priority_draft: 1,
            oauth_priority_saving: false,
            oauth_fallback_picker_target: None,
            oauth_fallback_picker_draft: BTreeMap::new(),
            model_route_policy_target: None,
            model_route_policy_draft: logic::ModelRoutePolicy::SubscriptionFirst,
            model_priority_dialog_target: None,
            model_priority_order: Vec::new(),
            usage_snapshot: Some(usage_snapshot),
            usage_snapshot_profile_key: "profile-work".to_owned(),
            usage_loading: false,
            usage_request_generation: 0,
            usage_error: String::new(),
            usage_return_page: Page::Dashboard,
            usage_refresh_due: None,
            self_check_quota_refresh_pending: false,
            notified_quota_accounts: BTreeSet::new(),
            usage_notifications_ready: false,
            notified_pool_failovers: BTreeSet::new(),
            rejoined_pool_notified: BTreeSet::new(),
            monitor_subscription_order: vec![101, 202],
            monitor_api_order: vec![303],
            share_codex_state: true,
            router_mode_enabled: true,
            official_mode_selected: false,
            router_mode_switching: false,
            codex_account_mode_status: profiles::CodexAccountModeStatus {
                mode: profiles::CodexAccountMode::Official,
                official_snapshot_available: true,
            },
            codex_account_mode_switching: false,
            oauth_recovery_due: None,
            oauth_recovery_running: false,
            oauth_recovery_cancel: Arc::new(AtomicBool::new(false)),
            grok_sso_dialog_open: false,
            grok_sso_draft: "audit-token-hidden".to_owned(),
            grok_sso_importing: false,
            grok_sso_error: String::new(),
            grok_sso_auto_select_pending: false,
            channel_preset_dialog_open: false,
            recommended_platform_dialog_open: false,
            log_scroll_to_bottom: true,
            log_follow_latest: true,
            log_dialog_open: false,
            runtime_log_stop: Arc::new(AtomicBool::new(false)),
            runtime_log_paused: Arc::new(AtomicBool::new(true)),
            tray_lightweight_mode: false,
            background_hide_until: None,
            tray_restore_guard_until: None,
            last_normal_window_size: DEFAULT_WINDOW_LOGICAL_SIZE,
            health_probe_due: None,
            health_probe_running: false,
            health_probe_failures: 0,
            health_recovery_running: false,
            health_recovery_cancel: Arc::new(AtomicBool::new(false)),
            routing_sync_running: false,
            routing_sync_pending: false,
            codex_binding_repair_running: false,
            codex_binding_check_completed: false,
            codex_binding_safe_strip_logged: None,
            codex_overwrite_prompt_open: false,
            codex_overwrite_auto_apply_at: None,
            codex_overwrite_countdown_paused_at: None,
            codex_overwrite_pending_fingerprint: String::new(),
            codex_overwrite_action_running: false,
            codex_overwrite_decision: String::new(),
            codex_overwrite_decision_fingerprint: String::new(),
            update_checking: false,
            update_downloading: false,
            update_downloaded_bytes: 0,
            update_total_bytes: 0,
            update_installing: false,
            update_dialog_open: false,
            update_info: None,
        };

        match options.scenario.as_str() {
            "profiles-empty" => {
                app.isolation_profiles.clear();
                app.active_profile_id.clear();
                app.local_profile_name_input.clear();
            }
            "oauth-loading" => {
                app.oauth_accounts.clear();
                app.oauth_loading = true;
            }
            "oauth-error" => {
                app.oauth_accounts.clear();
                app.oauth_error =
                    "class=connection_refused | status=503 | retryable=true".to_owned();
            }
            "monitor-loading" => {
                app.usage_snapshot = None;
                app.usage_loading = true;
            }
            "monitor-error" => {
                app.usage_snapshot = None;
                app.usage_error = "class=upstream_timeout | status=504 | retryable=true".to_owned();
            }
            "close" => app.close_prompt_open = true,
            "codex-overwrite" => {
                app.codex_overwrite_prompt_open = true;
                app.codex_overwrite_pending_fingerprint =
                    "9f2c4a1d7e6b5f8a3c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
                        .to_owned();
            }
            "apply-success" => app.apply_success_dialog_open = true,
            "subscription-success" => {
                app.apply_success_dialog_open = true;
                app.apply_success_is_subscription = true;
            }
            "logs" => app.log_dialog_open = true,
            "channel-preset" => app.channel_preset_dialog_open = true,
            "model-priority" => {
                let target = app
                    .config
                    .models
                    .iter()
                    .find(|model| model.model.contains("gpt-5.6-sol"))
                    .map(|model| model.model.clone())
                    .unwrap_or_else(|| "gpt-5.6-sol".to_owned());
                let mut indices = app
                    .config
                    .models
                    .iter()
                    .enumerate()
                    .filter(|(_, model)| logic::same_model_identity(&model.model, &target))
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                if indices.len() < 2 {
                    let base = app.config.models.first().cloned().unwrap_or_default();
                    let mut duplicate = base.clone();
                    duplicate.source = "oauth".to_owned();
                    duplicate.oauth_platform = "openai".to_owned();
                    duplicate.oauth_account_id = 101;
                    app.config.models.push(duplicate);
                    indices = app
                        .config
                        .models
                        .iter()
                        .enumerate()
                        .filter(|(_, model)| logic::same_model_identity(&model.model, &target))
                        .map(|(index, _)| index)
                        .collect();
                }
                app.model_priority_dialog_target = Some(target);
                app.model_priority_order = indices;
            }
            "recommended-platforms" => app.recommended_platform_dialog_open = true,
            "grok-sso" => app.grok_sso_dialog_open = true,
            "terms" => {
                app.terms_open = true;
                app.terms_scroll_complete = false;
                app.terms_scroll_reset_pending = true;
            }
            "oauth-terms-preparing" => {
                app.terms_open = true;
                app.terms_scroll_complete = false;
                app.terms_scroll_reset_pending = true;
                app.pending_oauth_provider = Some("openai".to_owned());
                app.provider_oauth_preparing = true;
            }
            "oauth-terms-ready" => {
                app.terms_open = true;
                app.terms_scroll_complete = true;
                app.terms_scroll_reset_pending = true;
                app.pending_oauth_provider = Some("openai".to_owned());
                app.provider_oauth_prepared_provider = Some("openai".to_owned());
            }
            "oauth-terms-error" => {
                app.terms_open = true;
                app.terms_scroll_complete = true;
                app.terms_scroll_reset_pending = true;
                app.pending_oauth_provider = Some("openai".to_owned());
                app.provider_oauth_prepare_error =
                    "The local Router did not become ready within 120 seconds".to_owned();
            }
            "advanced-json" => app.advanced_json_open = true,
            "reasoning" => app.reasoning_open = true,
            "oauth-revoke" => app.oauth_revoke_target = first_oauth_account.clone(),
            "oauth-fallback" => {
                app.oauth_fallback_picker_target = first_oauth_account;
                app.oauth_fallback_picker_draft
                    .insert("gpt-5.6-sol".to_owned(), None);
            }
            "update-current" => {
                app.update_dialog_open = true;
                app.update_info = Some(GitHubUpdateInfo {
                    status: "current".to_owned(),
                    current_version: APP_VERSION.to_owned(),
                    latest_version: APP_VERSION.to_owned(),
                    release_url: OFFICIAL_GITHUB_URL.to_owned(),
                    ..Default::default()
                });
            }
            "update-available" | "update-downloading" => {
                app.update_dialog_open = true;
                if options.scenario == "update-downloading" {
                    app.update_downloading = true;
                    app.update_downloaded_bytes = 37_750_000;
                    app.update_total_bytes = 84_000_000;
                }
                app.update_info = Some(GitHubUpdateInfo {
                    status: "update_available".to_owned(),
                    current_version: APP_VERSION.to_owned(),
                    latest_version: "1.5.9".to_owned(),
                    release_name: "Codex-Router 1.5.9".to_owned(),
                    release_notes: "- Improve connection recovery\n- Reduce tray CPU usage\n- 修复中文布局与代理检测".to_owned(),
                    release_url: OFFICIAL_GITHUB_URL.to_owned(),
                    asset_name: "Codex-Router-Portable-1.5.9-windows-x64.zip".to_owned(),
                    download_url: "https://example.invalid/release.zip".to_owned(),
                    asset_size: 84_000_000,
                    message: "Signed portable release".to_owned(),
                    ..Default::default()
                });
            }
            "update-error" => {
                app.update_dialog_open = true;
                app.update_info = Some(GitHubUpdateInfo {
                    status: "error".to_owned(),
                    current_version: APP_VERSION.to_owned(),
                    message: "class=network_unavailable | retryable=true".to_owned(),
                    release_url: OFFICIAL_GITHUB_URL.to_owned(),
                    ..Default::default()
                });
            }
            "update-downloaded" => {
                app.update_dialog_open = true;
                app.update_info = Some(GitHubUpdateInfo {
                    status: "downloaded".to_owned(),
                    current_version: APP_VERSION.to_owned(),
                    latest_version: "1.0.1".to_owned(),
                    release_url: OFFICIAL_GITHUB_URL.to_owned(),
                    download_path: r"C:\Downloads\Codex-Router-Portable-1.0.1.zip".to_owned(),
                    ..Default::default()
                });
            }
            _ => {}
        }
        app
    }

    fn persist_close_behavior(&mut self) -> bool {
        if self.ui_audit_mode {
            return true;
        }
        let path = user_data::preferences_path(&self.router_root);
        let preferences = UiPreferences {
            close_behavior: self.close_behavior,
            close_warning_version: 2,
            active_profile_id: self.active_profile_id.clone(),
            monitor_subscription_order: self.monitor_subscription_order.clone(),
            monitor_api_order: self.monitor_api_order.clone(),
            share_codex_state: self.share_codex_state,
            prefer_router_mode: self.router_mode_enabled,
            official_mode_selected: self.official_mode_selected,
            oauth_model_hint_seen: self.oauth_model_hint_seen,
            codex_overwrite_decision: self.codex_overwrite_decision.clone(),
            codex_overwrite_fingerprint: self.codex_overwrite_decision_fingerprint.clone(),
            window_width: self.last_normal_window_size[0],
            window_height: self.last_normal_window_size[1],
        };
        match preferences.save(&path) {
            Ok(()) => true,
            Err(error) => {
                let message = if self.ui_language == "zh" {
                    format!("无法保存窗口关闭设置：{error}")
                } else {
                    format!("Could not save the window close setting: {error}")
                };
                self.report_error(message);
                false
            }
        }
    }

    fn persist_ui_preferences(&mut self) -> bool {
        self.persist_close_behavior()
    }

    fn start_autostart_update(&mut self, enabled: bool, rollback_to: Option<bool>) {
        if self.ui_audit_mode || self.autostart_switching {
            return;
        }
        self.autostart_switching = true;
        let router_root = self.router_root.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = update_autostart_registration(&router_root, enabled)
                .map_err(|error| error.to_string());
            tx.send(AppEvent::AutostartFinished {
                enabled,
                rollback_to,
                result,
            })
            .ok();
        });
    }

    fn set_start_with_windows(&mut self, enabled: bool) {
        if self.autostart_switching || self.config.deploy.start_with_windows == enabled {
            return;
        }
        let previous = self.config.deploy.start_with_windows;
        self.config.deploy.start_with_windows = enabled;
        let config_path = user_data::config_path(&self.router_root);
        if let Err(error) = self.config.save(&config_path) {
            self.config.deploy.start_with_windows = previous;
            self.report_error(if self.ui_language == "zh" {
                format!("无法保存开机自启设置：{error}")
            } else {
                format!("Could not save the autostart setting: {error}")
            });
            return;
        }
        self.start_autostart_update(enabled, Some(previous));
    }

    fn reconcile_autostart_registration(&mut self) {
        let enabled = self.config.deploy.start_with_windows;
        self.start_autostart_update(enabled, None);
    }

    fn refresh_isolation_profiles(&mut self) {
        if self.ui_audit_mode {
            return;
        }
        match profiles::list_profiles(&self.router_root) {
            Ok(items) => self.isolation_profiles = items,
            Err(error) => self.report_error(format!("无法读取隔离配置：{error}")),
        }
    }

    fn delete_isolation_profile(&mut self, profile: IsolationProfile) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: profile deletion is disabled.".to_owned();
            return;
        }
        if self.applying {
            return;
        }
        if self.active_profile_id == profile.id
            || self.pending_profile_activation.as_deref() == Some(profile.id.as_str())
        {
            self.report_error(
                "当前正在使用的配置不能直接删除；请先应用另一个配置或初始化 Codex 默认配置",
            );
            return;
        }
        let result = profiles::delete_profile(&self.router_root, &profile);
        self.refresh_isolation_profiles();
        match result {
            Ok(outcome) if outcome.credential_cleanup_complete => {
                self.status_text = format!("已删除隔离配置“{}”", profile.name);
            }
            Ok(_) => {
                self.status_text = format!(
                    "已删除隔离配置“{}”，但部分隔离凭据未能清理；其他配置和当前 Codex 状态未受影响",
                    profile.name
                );
            }
            Err(error) => self.report_error(format!("无法删除隔离配置“{}”：{error}", profile.name)),
        }
    }

    fn capture_apply_ui_rollback(&self) -> ApplyUiRollback {
        ApplyUiRollback {
            config: self.config.clone(),
            active_profile_id: self.active_profile_id.clone(),
            pending_profile_activation: self.pending_profile_activation.clone(),
            configured: self.configured,
            router_mode_enabled: self.router_mode_enabled,
        }
    }

    fn restore_pending_apply_ui_rollback(&mut self) -> bool {
        let Some(rollback) = self.pending_apply_rollback.take() else {
            return false;
        };
        restore_apply_ui_fields(
            &mut self.config,
            &mut self.active_profile_id,
            &mut self.pending_profile_activation,
            &mut self.configured,
            &mut self.router_mode_enabled,
            rollback,
        );
        true
    }

    fn open_profiles(&mut self) {
        if self.ui_audit_mode {
            self.profiles_return_page = self.page;
            self.page = Page::Profiles;
            return;
        }
        if self.page != Page::Profiles {
            self.profiles_return_page = self.page;
        }
        match profiles::ensure_original_codex_snapshot(&self.router_root, &self.config) {
            Ok(()) => {
                self.refresh_isolation_profiles();
                self.page = Page::Profiles;
            }
            Err(error) => {
                self.report_error(format!("无法建立 Codex 原始配置快照：{error}"));
                self.page = Page::Profiles;
            }
        }
    }

    fn create_isolation_profile(&mut self, kind: IsolationKind, requested_name: String) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: profile creation is disabled.".to_owned();
            return;
        }
        if self.applying {
            return;
        }
        if !self.config.accept_compliance
            || self.config.accepted_terms_version != CURRENT_TERMS_VERSION
        {
            self.report_error("请先阅读并同意当前使用与分发承诺，再创建可应用的隔离配置");
            return;
        }
        if self.config.models.is_empty() {
            self.report_error("请至少添加一个模型，再创建隔离配置");
            return;
        }
        let requested_name = requested_name.trim().to_owned();
        let ui_rollback = self.capture_apply_ui_rollback();
        match profiles::create_profile(&self.router_root, &requested_name, kind, &self.config) {
            Ok((profile, isolated_config)) => {
                let profile_id = profile.id.clone();
                self.pending_apply_rollback = Some(ui_rollback);
                self.config = isolated_config;
                self.pending_profile_activation = Some(profile_id);
                self.refresh_isolation_profiles();
                if self.apply_all_with_backup(true, None, None) {
                    if self.local_profile_name_input.trim() == requested_name {
                        self.local_profile_name_input.clear();
                    }
                    self.status_text = format!("正在创建并应用本地隔离配置“{}”…", profile.name);
                } else {
                    self.restore_pending_apply_ui_rollback();
                }
            }
            Err(error) => self.report_error(error.to_string()),
        }
    }

    fn apply_isolation_profile(&mut self, profile: &IsolationProfile) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: profile switching is disabled.".to_owned();
            return;
        }
        if self.applying {
            return;
        }
        let loaded = profiles::load_profile_config(&self.router_root, profile);
        let target_config = match loaded {
            Ok(config) => config,
            Err(error) => {
                self.report_error(format!("无法读取隔离配置“{}”：{error}", profile.name));
                return;
            }
        };
        if !target_config.accept_compliance
            || target_config.accepted_terms_version != CURRENT_TERMS_VERSION
            || target_config.models.is_empty()
        {
            self.report_error("该隔离配置缺少当前条款确认或模型，请先在控制台补全后再应用");
            return;
        }
        let config_lock = match profiles::acquire_config_apply_lock(
            &self.router_root,
            std::time::Duration::from_secs(10),
        ) {
            Ok(lock) => lock,
            Err(error) => {
                self.report_error(format!("无法开始配置切换：{error}"));
                return;
            }
        };
        let (rollback_point, rollback_config) = match profiles::capture_applied_restore_point(
            &self.router_root,
            &self.config,
            &format!("切换到“{}”之前", profile.name),
        ) {
            Ok(backup) => backup,
            Err(error) => {
                self.report_error(format!("切换前备份失败，已停止操作：{error}"));
                return;
            }
        };
        let transaction_backup = ApplyTransactionBackup {
            point: rollback_point,
            config: rollback_config,
        };
        let ui_rollback = self.capture_apply_ui_rollback();
        let state_outcome = match profiles::restore_profile_codex_state(
            &self.router_root,
            profile,
            &target_config,
            self.share_codex_state,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.report_error(format!(
                    "无法准备配置“{}”的 Codex 状态：{error}",
                    profile.name
                ));
                return;
            }
        };
        self.pending_apply_rollback = Some(ui_rollback);
        self.config = target_config;
        self.pending_profile_activation = Some(profile.id.clone());
        if self.apply_all_with_backup(false, Some(config_lock), Some(transaction_backup.clone())) {
            self.status_text = if state_outcome.account_changed {
                format!(
                    "检测到不同 Codex 账号，正在使用“{}”自己的登录与设置并应用路由…",
                    profile.name
                )
            } else if state_outcome.shared_state_preserved {
                format!(
                    "正在应用“{}”；当前账号、会话与个人设置保持共享…",
                    profile.name
                )
            } else {
                format!("正在直接应用隔离配置“{}”…", profile.name)
            };
        } else {
            let _ = profiles::restore_point_config(
                &self.router_root,
                &transaction_backup.point,
                &transaction_backup.config,
                self.share_codex_state,
            );
            self.restore_pending_apply_ui_rollback();
        }
    }

    fn restore_original_codex(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: Codex restore is disabled.".to_owned();
            return;
        }
        if self.applying {
            return;
        }
        let _config_lock = match profiles::acquire_config_apply_lock(
            &self.router_root,
            std::time::Duration::from_secs(10),
        ) {
            Ok(lock) => lock,
            Err(error) => {
                self.report_error(format!("无法开始初始化：{error}"));
                return;
            }
        };
        let result = profiles::initialize_codex_defaults(&self.router_root, &self.config)
            .and_then(|outcome| {
                logic::codex_toml::remove_codex_system_binding()
                    .context("无法移除 Codex 系统层的 Router 绑定")?;
                Ok(outcome)
            });
        match result {
            Ok(outcome) => {
                self.active_profile_id.clear();
                self.pending_profile_activation = None;
                self.router_mode_enabled = false;
                self.official_mode_selected = true;
                self.oauth_recovery_due = None;
                self.persist_ui_preferences();
                self.status_text = if outcome.auth_available {
                    "已初始化 Codex 默认配置：Router 的模型提供方与模型目录已移除，你的 Codex 登录、聊天记录、插件与权限设置保持不变。请完全退出并重新打开 Codex。".into()
                } else {
                    "已初始化 Codex 默认配置：Router 写入的配置已移除；未检测到有效登录，请重新打开 Codex 并按官方流程登录。".into()
                };
            }
            Err(error) => {
                self.report_error(format!("无法初始化 Codex 默认配置：{error}"));
            }
        }
    }

    fn restore_previous_codex(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: restore is disabled.".to_owned();
            return;
        }
        if self.applying {
            return;
        }
        let target = match profiles::list_restore_points(&self.router_root) {
            Ok(points) => points.into_iter().next(),
            Err(error) => {
                self.report_error(format!("无法读取应用前备份：{error}"));
                return;
            }
        };
        let Some(target) = target else {
            self.status_text = "还没有可还原的应用前配置".into();
            return;
        };
        self.pending_apply_rollback = Some(self.capture_apply_ui_rollback());
        self.applying = true;
        self.configured = false;
        let zh = self.ui_language == "zh";
        self.status_text = if zh {
            format!("正在恢复并重新部署上一次配置（{}）…", target.label)
        } else {
            format!(
                "Restoring and redeploying the previous configuration ({})…",
                target.label
            )
        };
        self.log(self.status_text.clone());

        let root = self.router_root.clone();
        let fallback = self.config.clone();
        let share_codex_state = self.share_codex_state;
        let tx = self.event_tx.clone();
        let apply_cancel = self.apply_cancel.clone();
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<(RouterConfig, profiles::RestoreOutcome)> {
                let _config_lock =
                    profiles::acquire_config_apply_lock(&root, std::time::Duration::from_secs(10))?;
                let (rollback_point, rollback_config) = profiles::capture_applied_restore_point(
                    &root,
                    &fallback,
                    "执行返回上一次配置之前",
                )?;
                let transaction_backup = ApplyTransactionBackup {
                    point: rollback_point,
                    config: rollback_config,
                };
                let restored = profiles::restore_point_config_and_deploy(
                    &root,
                    &target,
                    &fallback,
                    share_codex_state,
                    |restored| {
                        redeploy_restored_config(restored, &root, &apply_cancel, zh, &mut |line| {
                            tx.send(AppEvent::Log(line)).ok();
                        })
                    },
                );
                match restored {
                    Ok(value) => Ok(value),
                    Err(error) if apply_cancel.load(Ordering::Acquire) => Err(error),
                    Err(error) => {
                        let rollback = rollback_failed_deployment(
                            &root,
                            &transaction_backup,
                            share_codex_state,
                            zh,
                            |line| {
                                tx.send(AppEvent::Log(line)).ok();
                            },
                        );
                        match rollback {
                            Ok(()) => Err(error.context("已恢复还原操作前的配置")),
                            Err(rollback_error) => Err(error.context(format!(
                                "还原失败，且无法恢复还原前配置：{rollback_error}"
                            ))),
                        }
                    }
                }
            })();
            match result {
                Ok((config, outcome)) => {
                    tx.send(AppEvent::PreviousConfigurationRestored {
                        config: Box::new(config),
                        outcome,
                        label: target.label,
                    })
                    .ok();
                }
                Err(error) => {
                    tx.send(AppEvent::PreviousConfigurationRestoreError(format!(
                        "{error:#}"
                    )))
                    .ok();
                }
            }
        });
    }

    /// Codex only reloads `config.toml` and the model catalog on a cold start.
    /// Restarting the desktop client here saves the user from doing it manually
    /// after every apply. Only ChatGPT / Codex desktop processes are touched,
    /// and a failure never fails the apply.
    fn restart_codex_desktop(&mut self) {
        let zh = self.ui_language == "zh";
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let message = match platform::restart_codex_desktop() {
                Ok(platform::CodexRestartOutcome::Restarted) if zh => {
                    "已自动关闭并重启 Codex / ChatGPT 客户端，新模型目录已生效"
                }
                Ok(platform::CodexRestartOutcome::Restarted) => {
                    "Codex / ChatGPT was restarted automatically; the new model catalog is active"
                }
                Ok(platform::CodexRestartOutcome::NotRunning) if zh => {
                    "未检测到正在运行的 Codex / ChatGPT；下次打开即会加载新配置"
                }
                Ok(platform::CodexRestartOutcome::NotRunning) => {
                    "Codex / ChatGPT was not running; it will load the new configuration on next launch"
                }
                Ok(platform::CodexRestartOutcome::RelaunchSkipped) if zh => {
                    "已关闭 Codex / ChatGPT，但未能自动重新打开，请手动启动"
                }
                Ok(platform::CodexRestartOutcome::RelaunchSkipped) => {
                    "Codex / ChatGPT was closed but could not be relaunched automatically"
                }
                Err(_) if zh => "无法自动重启 Codex / ChatGPT，请手动完全退出并重新打开",
                Err(_) => {
                    "Could not restart Codex / ChatGPT automatically; quit and reopen it manually"
                }
            };
            tx.send(AppEvent::Log(message.to_owned())).ok();
        });
    }

    fn remember_usable_window_size(&mut self, ctx: &egui::Context) {
        let Some(size) = ctx.input(|input| {
            let viewport = input.viewport();
            if viewport.maximized == Some(true)
                || viewport.fullscreen == Some(true)
                || viewport.minimized == Some(true)
            {
                return None;
            }
            viewport.inner_rect.map(|rect| [rect.width(), rect.height()])
        }) else {
            return;
        };
        if window_size_is_usable(size) && self.last_normal_window_size != size {
            self.last_normal_window_size = size;
            let _ = self.persist_ui_preferences();
        }
    }

    fn ensure_usable_window_size(&mut self, ctx: &egui::Context) {
        let (maximized, minimized, size) = ctx.input(|input| {
            let viewport = input.viewport();
            (
                viewport.maximized == Some(true) || viewport.fullscreen == Some(true),
                viewport.minimized == Some(true),
                viewport.inner_rect.map(|rect| [rect.width(), rect.height()]),
            )
        });
        if maximized || minimized {
            return;
        }
        if size.is_some_and(window_size_is_usable) {
            return;
        }
        let restored = restored_window_size(self.last_normal_window_size);
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            restored[0], restored[1],
        )));
    }

    fn minimize_to_tray(&mut self, ctx: &egui::Context) {
        self.close_prompt_open = false;
        self.remember_close_choice = false;
        if self.tray_icon.is_some() {
            self.remember_usable_window_size(ctx);
            self.tray_lightweight_mode = true;
            self.tray_restore_guard_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(1));
            self.runtime_log_paused.store(true, Ordering::Relaxed);
            if self.fonts_loaded {
                install_lightweight_fonts(ctx);
                self.fonts_loaded = false;
                self.logo_texture = None;
            }
            if let Some(tray) = &self.tray_icon {
                let _ = tray.set_tooltip(Some(if self.ui_language == "zh" {
                    TRAY_TOOLTIP_ZH
                } else {
                    TRAY_TOOLTIP_EN
                }));
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        } else {
            self.status_text = if self.ui_language == "zh" {
                "系统托盘不可用，窗口保持打开".into()
            } else {
                "The system tray is unavailable, so the window was kept open".into()
            };
        }
    }

    fn restore_from_tray(&mut self, ctx: &egui::Context) {
        self.background_hide_until = None;
        let was_lightweight = self.tray_lightweight_mode;
        ensure_full_ui_fonts(self, ctx);
        self.tray_lightweight_mode = false;
        self.tray_restore_guard_until =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(1));
        self.load_logo_texture(ctx);
        self.runtime_log_paused.store(false, Ordering::Relaxed);
        if was_lightweight {
            // Run an immediate opportunistic recovery in addition to the
            // regular 15-minute usage and recovery maintenance.
            self.request_oauth_recovery_probe(std::time::Duration::from_secs(2));
        }
        if let Some(tray) = &self.tray_icon {
            let _ = tray.set_tooltip(Some(APP_TITLE));
        }
        if was_lightweight {
            if self.usage_snapshot.is_none() {
                self.load_usage_monitor_cache();
            }
            self.status_text = if self.ui_language == "zh" {
                "已退出托盘轻量模式；界面刷新、日志和账号维护已恢复".to_owned()
            } else {
                "Left lightweight tray mode; UI refresh, logs, and account maintenance resumed"
                    .to_owned()
            };
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        if ctx.input(|input| input.viewport().maximized != Some(true)) {
            let restored = restored_window_size(self.last_normal_window_size);
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                restored[0], restored[1],
            )));
        }
        ctx.request_repaint();
    }

    fn enforce_background_start_hidden(&mut self, ctx: &egui::Context) {
        let Some(deadline) = self.background_hide_until else {
            return;
        };
        if std::time::Instant::now() >= deadline || !self.tray_lightweight_mode {
            self.background_hide_until = None;
            return;
        }
        hide_current_process_windows();
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn request_exit(&mut self, ctx: &egui::Context) {
        if self.exit_shutdown_in_progress {
            return;
        }
        if self.ui_audit_mode {
            self.exit_after_prompt = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        self.close_prompt_open = true;
        self.remember_close_choice = false;
        let router_root = self.router_root.clone();
        let exit_marker = match ExitTransactionMarker::create(&router_root) {
            Ok(marker) => marker,
            Err(error) => {
                self.exit_shutdown_error = if self.ui_language == "zh" {
                    format!("无法建立安全退出事务，程序仍保持运行：{error}")
                } else {
                    format!("Could not establish the safe exit transaction; the app remains open: {error}")
                };
                self.status_text.clone_from(&self.exit_shutdown_error);
                ctx.request_repaint();
                return;
            }
        };
        self.exit_shutdown_in_progress = true;
        self.exit_shutdown_error.clear();
        self.apply_cancel.store(true, Ordering::Release);
        self.runtime_log_paused.store(true, Ordering::Relaxed);
        self.health_recovery_cancel.store(true, Ordering::Relaxed);
        self.provider_oauth_prepare_cancel
            .store(true, Ordering::Relaxed);
        self.provider_oauth_cancel.store(true, Ordering::Relaxed);
        self.oauth_recovery_cancel.store(true, Ordering::Relaxed);
        self.health_probe_due = None;
        self.oauth_recovery_due = None;
        self.status_text = if self.ui_language == "zh" {
            "正在恢复原 Codex 配置并彻底停止本地转发服务…".to_owned()
        } else {
            "Restoring the previous Codex configuration and stopping local forwarding services…"
                .to_owned()
        };
        if let Some(tray) = &self.tray_icon {
            let _ = tray.set_visible(false);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        let config = self.config.clone();
        let share_codex_state = self.share_codex_state;
        let tx = self.event_tx.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let _exit_marker = exit_marker;
            let result =
                restore_codex_and_stop_router_for_exit(&router_root, &config, share_codex_state)
                    .map_err(|error| error.to_string());
            tx.send(AppEvent::ExitShutdownFinished(result)).ok();
            repaint.request_repaint();
        });
        ctx.request_repaint();
    }

    fn handle_close_request(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.viewport().close_requested()) {
            return;
        }
        if self.exit_after_prompt {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        if self.exit_shutdown_in_progress {
            return;
        }
        match self.close_behavior {
            CloseBehavior::Ask => {
                ensure_full_ui_fonts(self, ctx);
                self.close_prompt_open = true;
                ctx.request_repaint();
            }
            CloseBehavior::MinimizeToTray => self.minimize_to_tray(ctx),
            CloseBehavior::Exit => self.request_exit(ctx),
        }
    }

    fn handle_native_minimize(&mut self, ctx: &egui::Context) {
        if self
            .tray_restore_guard_until
            .is_some_and(|deadline| std::time::Instant::now() < deadline)
        {
            return;
        }
        self.tray_restore_guard_until = None;
        let (minimized, maximized, size) = ctx.input(|input| {
            let viewport = input.viewport();
            (
                viewport.minimized == Some(true),
                viewport.maximized == Some(true) || viewport.fullscreen == Some(true),
                viewport.inner_rect.map(|rect| [rect.width(), rect.height()]),
            )
        });
        if should_leave_tray_lightweight(self.tray_lightweight_mode, minimized, maximized, size) {
            self.restore_from_tray(ctx);
            return;
        }
        if minimized {
            return;
        }
        self.remember_usable_window_size(ctx);
        if !self.fonts_loaded {
            ensure_full_ui_fonts(self, ctx);
        }
        self.ensure_usable_window_size(ctx);
    }

    fn process_app_events(&mut self, ctx: &egui::Context) {
        let zh = self.ui_language == "zh";
        let discard_background_events = self.exit_shutdown_in_progress;
        while let Ok(event) = self.event_rx.try_recv() {
            if discard_background_events && !matches!(&event, AppEvent::ExitShutdownFinished(_)) {
                continue;
            }
            match event {
                AppEvent::Log(message) => self.log(message),
                AppEvent::ExitShutdownFinished(result) => {
                    self.exit_shutdown_in_progress = false;
                    match result {
                        Ok(()) => {
                            self.exit_shutdown_error.clear();
                            self.router_mode_enabled = false;
                            self.exit_after_prompt = true;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        Err(error) => {
                            self.update_installing = false;
                            self.runtime_log_paused.store(false, Ordering::Relaxed);
                            self.health_probe_due = None;
                            self.tray_lightweight_mode = false;
                            ensure_full_ui_fonts(self, ctx);
                            if let Some(tray) = &self.tray_icon {
                                let _ = tray.set_visible(true);
                            }
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            let detail = if detail.contains("class=request_failure")
                                || detail.contains("class=unclassified_error")
                            {
                                if zh {
                                    "本地服务未能在安全时限内停止。若刚升级过便携包，请再试一次彻底退出；仍失败时请结束占用 18080 / 16379 / 15432 端口的旧进程后重试。"
                                } else {
                                    "Local services could not stop within the safety budget. After upgrading portable packages, retry full exit; if it still fails, stop older processes on ports 18080 / 16379 / 15432 and try again."
                                }
                            } else {
                                detail.as_str()
                            };
                            self.exit_shutdown_error = if zh {
                                format!("未能彻底关闭本地服务：{detail}")
                            } else {
                                format!("Could not stop all local services: {detail}")
                            };
                            self.status_text.clone_from(&self.exit_shutdown_error);
                            self.close_prompt_open = true;
                            self.log(self.status_text.clone());
                        }
                    }
                }
                AppEvent::AutostartFinished {
                    enabled,
                    rollback_to,
                    result,
                } => {
                    self.autostart_switching = false;
                    match result {
                        Ok(()) => {
                            self.status_text = if zh {
                                if enabled {
                                    "已开启开机静默启动；下次登录后将直接进入轻量托盘模式"
                                } else {
                                    "已关闭开机自启"
                                }
                            } else if enabled {
                                "Silent startup enabled; the app will enter lightweight tray mode after the next sign-in"
                            } else {
                                "Startup with Windows disabled"
                            }
                            .to_owned();
                        }
                        Err(error) => {
                            if let Some(previous) = rollback_to {
                                self.config.deploy.start_with_windows = previous;
                                let _ =
                                    self.config.save(&user_data::config_path(&self.router_root));
                            }
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            self.report_error(if zh {
                                format!("无法更新开机自启设置：{detail}")
                            } else {
                                format!("Could not update the autostart setting: {detail}")
                            });
                        }
                    }
                }
                AppEvent::Complete => {
                    let restart_codex_after_apply = self.codex_overwrite_action_running;
                    self.applying = false;
                    self.codex_overwrite_action_running = false;
                    self.codex_overwrite_prompt_open = false;
                    self.codex_overwrite_auto_apply_at = None;
                    self.codex_overwrite_countdown_paused_at = None;
                    if self.exit_shutdown_in_progress {
                        continue;
                    }
                    // The apply may have adopted a different local port group
                    // when the configured one was owned by another Router copy.
                    // Pull the committed value back so health probes, the
                    // gateway ensure, and future applies use the live port.
                    if let Ok(applied) =
                        RouterConfig::load(&user_data::config_path(&self.router_root))
                    {
                        if self.config.deploy.sub2api_host != applied.deploy.sub2api_host {
                            self.config.deploy.sub2api_host = applied.deploy.sub2api_host;
                        }
                    }
                    self.apply_success_dialog_open = true;
                    self.configured = true;
                    self.router_mode_enabled = true;
                    self.official_mode_selected = false;
                    self.persist_ui_preferences();
                    self.codex_account_mode_status =
                        profiles::codex_account_mode_status(&self.router_root, &self.config);
                    self.router_mode_switching = false;
                    self.start_apply_settle();
                    self.set_status(
                        if zh {
                            "配置完成：模型渠道、Codex 和所选集成均已生效"
                        } else {
                            "Configuration complete: model channels, Codex, and integrations are active"
                        },
                        12,
                    );
                    // Do not restart Codex automatically after Apply. Desktop
                    // reloads every restored thread as active; an immediate
                    // thread/archive request then only shuts the thread down
                    // and never reaches the archive move. The success dialog
                    // already tells the user to reopen Codex when a cold model
                    // catalog reload is actually needed.
                    self.log(if zh {
                        "配置完成"
                    } else {
                        "Configuration complete"
                    });
                    if restart_codex_after_apply {
                        self.restart_codex_desktop();
                    }
                    if self.routing_sync_pending {
                        self.routing_sync_pending = false;
                    }
                    if let Some(profile_id) = self.pending_profile_activation.take() {
                        match profiles::update_profile_state(
                            &self.router_root,
                            &profile_id,
                            &self.config,
                        ) {
                            Ok(()) => {
                                self.active_profile_id = profile_id;
                                self.persist_ui_preferences();
                                self.refresh_isolation_profiles();
                                // The profile switch result is already visible in the
                                // success dialog and activity log. Do not overwrite the
                                // transient dashboard status with a persistent banner.
                            }
                            Err(error) => {
                                // Deployment already committed the selected profile. Keep the
                                // active id aligned with the running route even if refreshing the
                                // profile snapshot itself failed.
                                self.active_profile_id = profile_id;
                                self.persist_ui_preferences();
                                self.refresh_isolation_profiles();
                                let detail =
                                    runtime_logs::summarize_error_for_display(&error.to_string());
                                self.status_text = format!(
                                    "{}；但无法更新隔离配置快照：{detail}",
                                    self.status_text
                                );
                                self.log(self.status_text.clone());
                            }
                        }
                    }
                    self.pending_apply_rollback = None;
                }
                AppEvent::Error(error) => {
                    let was_applying = self.applying;
                    let was_router_mode_switching = self.router_mode_switching;
                    self.applying = false;
                    self.codex_overwrite_action_running = false;
                    self.codex_overwrite_auto_apply_at = None;
                    self.codex_overwrite_countdown_paused_at = None;
                    if self.exit_shutdown_in_progress {
                        continue;
                    }
                    // A rolled-back attempt can report its failure after a later
                    // retry already succeeded. Keep that stale error out of the
                    // dashboard status line; it stays in the activity log.
                    if !was_applying && self.configured && self.router_mode_enabled {
                        self.log(format!(
                            "{}: {}",
                            if zh {
                                "已忽略过期的部署错误"
                            } else {
                                "Ignored a stale deployment error"
                            },
                            localized_error_summary(zh, &error)
                        ));
                        continue;
                    }
                    self.router_mode_switching = false;
                    if !self.restore_pending_apply_ui_rollback() {
                        self.router_mode_enabled = logic::codex_router_mode_active(&self.config);
                        self.pending_profile_activation = None;
                    } else if was_router_mode_switching {
                        // A failed automatic rebind must not retry every watchdog
                        // interval. A later manual Apply can enable Router mode again.
                        self.router_mode_enabled =
                            logic::codex_router_mode_configured(&self.config);
                        self.persist_ui_preferences();
                    }
                    let detail = localized_error_summary(zh, &error);
                    let message = format!(
                        "{}: {detail}",
                        if zh {
                            "配置失败"
                        } else {
                            "Configuration failed"
                        }
                    );
                    self.set_status(message, 20);
                    self.log(self.status_text.clone());
                    self.start_apply_settle();
                }
                AppEvent::PreviousConfigurationRestored {
                    config,
                    outcome,
                    label,
                } => {
                    self.applying = false;
                    self.pending_apply_rollback = None;
                    self.config = *config;
                    self.configured = true;
                    self.active_profile_id.clear();
                    self.pending_profile_activation = None;
                    self.router_mode_enabled = logic::codex_router_mode_active(&self.config);
                    self.codex_account_mode_status =
                        profiles::codex_account_mode_status(&self.router_root, &self.config);
                    self.oauth_recovery_due = self
                        .router_mode_enabled
                        .then(|| std::time::Instant::now() + std::time::Duration::from_secs(5));
                    self.persist_ui_preferences();
                    self.schedule_usage_refresh();
                    self.status_text = if outcome.shared_state_preserved {
                        if zh {
                            format!(
                                "已恢复并重新部署上一次配置（{label}）；当前账号、会话记录和个人设置保持共享。请完全退出并重新打开 Codex。"
                            )
                        } else {
                            format!(
                                "Restored and redeployed the previous configuration ({label}) while preserving the current account, tasks, and settings. Fully restart Codex."
                            )
                        }
                    } else if zh {
                        format!(
                            "已恢复并重新部署上一次配置（{label}）；检测到不同 Codex 账号，已使用该账号自己的完整快照。请完全退出并重新打开 Codex。"
                        )
                    } else {
                        format!(
                            "Restored and redeployed the previous configuration ({label}) with its own account snapshot. Fully restart Codex."
                        )
                    };
                    self.log(self.status_text.clone());
                }
                AppEvent::PreviousConfigurationRestoreError(error) => {
                    self.applying = false;
                    self.restore_pending_apply_ui_rollback();
                    let detail = localized_error_summary(zh, &error);
                    self.status_text = if zh {
                        format!("无法恢复并重新部署上一次配置：{detail}")
                    } else {
                        format!(
                            "Could not restore and redeploy the previous configuration: {detail}"
                        )
                    };
                    self.log(self.status_text.clone());
                }
                AppEvent::OAuthAccountsLoaded(mut accounts) => {
                    self.oauth_loading = false;
                    self.oauth_error.clear();
                    self.oauth_retry_due = None;
                    self.oauth_retry_attempts = 0;
                    for account in &mut accounts {
                        if !account.error.trim().is_empty() {
                            account.error =
                                runtime_logs::summarize_error_for_display(&account.error);
                        }
                        if !account.models_error.trim().is_empty() {
                            account.models_error =
                                runtime_logs::summarize_error_for_display(&account.models_error);
                        }
                    }
                    retain_last_good_oauth_models(&self.oauth_accounts, &mut accounts);
                    clear_stale_oauth_account_errors(&mut accounts, self.usage_snapshot.as_ref());
                    accounts.sort_by(|left, right| {
                        left.priority
                            .cmp(&right.priority)
                            .then(left.platform.cmp(&right.platform))
                            .then(left.id.cmp(&right.id))
                    });
                    let previous_ids = if self.oauth_known_account_ids.is_empty() {
                        self.oauth_accounts
                            .iter()
                            .filter(|account| account.bound_to_router)
                            .map(|account| account.id)
                            .collect::<Vec<_>>()
                    } else {
                        self.oauth_known_account_ids.clone()
                    };
                    let in_flight = self.oauth_in_flight_provider.clone();
                    let auto_enabled_model = self
                        .oauth_auto_enable_provider
                        .clone()
                        .and_then(|provider| {
                            auto_enable_first_oauth_model(
                                &mut self.config,
                                &accounts,
                                &provider,
                            )
                        });
                    if auto_enabled_model.is_some() {
                        self.oauth_auto_enable_provider = None;
                        self.apply_success_is_subscription = true;
                    }
                    let imported = if in_flight.is_some()
                        || self.oauth_success_pending
                        || self.provider_oauth_running
                    {
                        auto_import_new_oauth_models(
                            &mut self.config,
                            &accounts,
                            in_flight.as_deref(),
                            &previous_ids,
                        )
                    } else {
                        Vec::new()
                    };
                    let discovered_in_flight = in_flight.is_some()
                        && accounts.iter().any(|account| {
                            account.bound_to_router
                                && !previous_ids.contains(&account.id)
                                && in_flight.as_deref().is_none_or(|provider| {
                                    oauth_platform_matches(&account.platform, provider)
                                })
                        });
                    let mut selected = self.config.oauth_account_ids.clone().unwrap_or_default();
                    let mut seen = self.config.oauth_seen_account_ids.clone();
                    let bound_account_ids = accounts
                        .iter()
                        .filter(|account| account.bound_to_router)
                        .map(|account| account.id)
                        .collect::<Vec<_>>();
                    let auto_added = logic::enroll_unseen_oauth_accounts(
                        &mut selected,
                        &mut seen,
                        &bound_account_ids,
                    );
                    self.config.oauth_account_ids = Some(selected);
                    self.config.oauth_seen_account_ids = seen;
                    if self.grok_sso_auto_select_pending {
                        self.grok_sso_auto_select_pending = false;
                    }
                    self.oauth_accounts = accounts;
                    let extra_accounts = self
                        .oauth_accounts
                        .iter()
                        .map(|account| (account.id, account.platform.clone()))
                        .collect::<Vec<_>>();
                    let before_slots = self.config.models.len();
                    logic::replicate_oauth_slots_for_accounts(&mut self.config, &extra_accounts);
                    logic::assign_sequential_oauth_account_priorities(&mut self.config);
                    if self.config.models.len() != before_slots {
                        let _ = self
                            .config
                            .save(&crate::user_data::config_path(&self.router_root));
                    }
                    let should_announce = !imported.is_empty()
                        || discovered_in_flight
                        || (self.oauth_success_pending && !self.result_dialog_open);
                    if should_announce {
                        let provider = in_flight.clone().unwrap_or_default();
                        self.show_oauth_authorized_dialog(&provider, &imported);
                    }
                    if self.oauth_success_pending
                        || !imported.is_empty()
                        || discovered_in_flight
                    {
                        self.oauth_success_pending = false;
                        self.oauth_in_flight_provider = None;
                        self.oauth_known_account_ids.clear();
                        self.provider_oauth_running = false;
                    }
                    if auto_added > 0 || !imported.is_empty() {
                        let selected = self.config.oauth_account_ids.clone();
                        let seen = self.config.oauth_seen_account_ids.clone();
                        let models = self.config.models.clone();
                        let default_model = self.config.default_model.clone();
                        let config_path = user_data::config_path(&self.router_root);
                        let persist_models = !imported.is_empty();
                        let persisted = (|| -> anyhow::Result<()> {
                            let mut saved = if config_path.is_file() {
                                RouterConfig::load(&config_path)?
                            } else {
                                self.config.clone()
                            };
                            saved.oauth_account_ids = selected.clone();
                            saved.oauth_seen_account_ids = seen.clone();
                            if persist_models {
                                saved.models = models;
                                saved.default_model = default_model;
                            }
                            saved.save(&config_path)?;
                            if !self.active_profile_id.trim().is_empty() {
                                profiles::update_profile_oauth_selection(
                                    &self.router_root,
                                    &self.active_profile_id,
                                    selected,
                                    seen,
                                )?;
                            }
                            Ok(())
                        })();
                        if let Err(error) = persisted {
                            self.log(format!(
                                "OAuth 自动同步保存失败：{}",
                                runtime_logs::summarize_error_for_display(&error.to_string())
                            ));
                        }
                        if self.page != Page::OAuth {
                            self.schedule_usage_refresh();
                        }
                        if !self.result_dialog_open {
                            self.status_text = if zh {
                                format!(
                                    "已自动将 {auto_added} 个新 OAuth 账号加入当前配置，并刷新用量统计"
                                )
                            } else {
                                format!(
                                    "Added {auto_added} new OAuth account(s) to this profile and refreshed usage statistics"
                                )
                            };
                        }
                        // Discovering a new OAuth account is a background
                        // observation. Never invoke the full Apply path here:
                        // Apply rewrites Codex config/catalog and restarts the
                        // desktop client, which can interrupt an active task
                        // and make the user appear signed out. Reconcile only
                        // the live Router table; the user can explicitly use
                        // "Save & apply" when the model catalog should change.
                        if background_oauth_sync_action(
                            self.router_mode_enabled,
                            self.applying,
                            self.router_mode_switching,
                        ) == BackgroundOAuthSyncAction::LiveRouterOnly
                        {
                            self.request_routing_sync();
                        }
                    }
                    if self.page == Page::OAuth {
                        self.refresh_usage_monitor();
                    }
                    if let Some(model) = auto_enabled_model {
                        if !self.result_dialog_open {
                            self.status_text = if zh {
                                format!("订阅授权成功，已默认启用第一个可用模型：{model}")
                            } else {
                                format!("Subscription authorized. Enabled the first available model: {model}")
                            };
                        }
                    }
                }
                AppEvent::OAuthAccountsError(error) => {
                    self.oauth_loading = false;
                    let detail = localized_error_summary(zh, &error);
                    self.oauth_error.clone_from(&detail);
                    self.log(format!(
                        "{}: {detail}",
                        if zh {
                            "OAuth 账号加载失败"
                        } else {
                            "Could not load OAuth accounts"
                        }
                    ));
                    // Fresh starts and Apply leave the admin API briefly unavailable.
                    // Automatically retry a few times while the OAuth page is open so
                    // users do not have to mash Refresh during that window.
                    if self.page == Page::OAuth
                        && self.oauth_retry_attempts < 5
                        && oauth_accounts_error_is_retryable(&error)
                    {
                        self.oauth_retry_attempts = self.oauth_retry_attempts.saturating_add(1);
                        let delay_ms = 1200u64 + u64::from(self.oauth_retry_attempts) * 800;
                        self.oauth_retry_due = Some(
                            std::time::Instant::now() + std::time::Duration::from_millis(delay_ms),
                        );
                    } else {
                        self.oauth_retry_due = None;
                    }
                }
                AppEvent::ProviderOAuthPrepared {
                    provider,
                    generation,
                } => {
                    if request_result_disposition(
                        self.provider_oauth_prepare_generation,
                        self.provider_oauth_preparing_provider
                            .as_deref()
                            .unwrap_or_default(),
                        generation,
                        &provider,
                    ) != RequestResultDisposition::Apply
                    {
                        continue;
                    }
                    self.provider_oauth_preparing = false;
                    self.provider_oauth_preparing_provider = None;
                    self.provider_oauth_prepared_provider = Some(provider.clone());
                    self.provider_oauth_prepare_error.clear();
                    let terms_accepted = self.config.accept_compliance
                        && self.config.accepted_terms_version == CURRENT_TERMS_VERSION;
                    if self.pending_oauth_provider.as_deref() == Some(provider.as_str())
                        && terms_accepted
                    {
                        self.pending_oauth_provider = None;
                        self.terms_open = false;
                        self.launch_provider_oauth(&provider);
                    } else if self.pending_oauth_provider.as_deref() == Some(provider.as_str()) {
                        self.status_text = if zh {
                            "安全登录环境已准备好；阅读完条例后即可开始 OAuth".to_owned()
                        } else {
                            "The secure sign-in environment is ready. Finish reading the terms to start OAuth"
                                .to_owned()
                        };
                    }
                }
                AppEvent::ProviderOAuthPrepareError {
                    provider,
                    generation,
                    error,
                } => {
                    if request_result_disposition(
                        self.provider_oauth_prepare_generation,
                        self.provider_oauth_preparing_provider
                            .as_deref()
                            .unwrap_or_default(),
                        generation,
                        &provider,
                    ) != RequestResultDisposition::Apply
                    {
                        continue;
                    }
                    self.provider_oauth_preparing = false;
                    self.provider_oauth_preparing_provider = None;
                    self.provider_oauth_prepared_provider = None;
                    let detail = localized_error_summary(zh, &error);
                    self.provider_oauth_prepare_error.clone_from(&detail);
                    self.status_text = if zh {
                        format!("安全登录环境准备失败：{detail}")
                    } else {
                        format!("Could not prepare the secure sign-in environment: {detail}")
                    };
                    self.log(format!(
                        "{}: {detail}",
                        if zh {
                            "OAuth 后台准备未完成"
                        } else {
                            "OAuth background preparation did not finish"
                        },
                    ));
                }
                AppEvent::ProviderOAuthPrompt { prompt, response } => {
                    self.provider_oauth_code_draft.clear();
                    self.provider_oauth_gemini_code_assist = false;
                    self.provider_oauth_project_draft = match &prompt {
                        logic::oauth::Prompt::GeminiConfiguration {
                            detected_project_id,
                        } => detected_project_id.clone(),
                        logic::oauth::Prompt::AuthorizationCode { .. } => String::new(),
                    };
                    self.provider_oauth_prompt =
                        Some(ProviderOAuthPromptState { prompt, response });
                }
                AppEvent::ProviderOAuthFinished => {
                    self.provider_oauth_running = false;
                    self.provider_oauth_prompt = None;
                    self.provider_oauth_code_draft.clear();
                    self.provider_oauth_project_draft.clear();
                    self.oauth_success_pending = true;
                    self.status_text = if zh {
                        "授权已成功，正在同步账号和模型…".to_owned()
                    } else {
                        "Authorization succeeded. Syncing the account and models…".to_owned()
                    };
                    self.refresh_oauth_accounts();
                }
                AppEvent::ProviderOAuthError(error) => {
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    let cancelled = detail.to_ascii_lowercase().contains("cancelled")
                        || detail.to_ascii_lowercase().contains("class=cancelled");
                    if self.oauth_success_pending
                        || cancelled && self.oauth_in_flight_provider.is_none()
                    {
                        self.provider_oauth_running = false;
                        continue;
                    }
                    self.provider_oauth_running = false;
                    self.oauth_auto_enable_provider = None;
                    self.oauth_in_flight_provider = None;
                    self.oauth_success_pending = false;
                    self.provider_oauth_prompt = None;
                    self.provider_oauth_code_draft.clear();
                    self.provider_oauth_project_draft.clear();
                    self.show_result_dialog(
                        ResultDialogKind::Failure,
                        if zh {
                            "授权未完成"
                        } else {
                            "Authorization did not finish"
                        },
                        if zh {
                            format!("授权未完成，请检查配置后重试。{detail}")
                        } else {
                            format!("Authorization did not finish. Check the configuration and retry. {detail}")
                        },
                    );
                }
                AppEvent::UsageLoaded {
                    profile_key,
                    generation,
                    snapshot,
                } => {
                    match request_result_disposition(
                        self.usage_request_generation,
                        &self.active_route_profile_key(),
                        generation,
                        &profile_key,
                    ) {
                        RequestResultDisposition::Ignore => continue,
                        RequestResultDisposition::RefreshCurrent => {
                            self.usage_loading = false;
                            self.schedule_usage_refresh();
                            continue;
                        }
                        RequestResultDisposition::Apply => {}
                    }
                    self.usage_loading = false;
                    self.usage_error.clear();
                    let mut snapshot = *snapshot;
                    let zh = self.ui_language == "zh";
                    let routing_changed = snapshot.routing_changed;
                    for account in snapshot
                        .subscriptions
                        .iter_mut()
                        .chain(snapshot.api_channels.iter_mut())
                    {
                        normalize_usage_account_messages(zh, account);
                    }
                    clear_stale_oauth_account_errors(&mut self.oauth_accounts, Some(&snapshot));
                    Self::sort_usage_accounts(
                        &mut snapshot.subscriptions,
                        &self.monitor_subscription_order,
                    );
                    Self::sort_usage_accounts(&mut snapshot.api_channels, &self.monitor_api_order);
                    if let Err(error) = self.save_usage_monitor_cache(&profile_key, &snapshot) {
                        self.log(format!(
                            "用量监控缓存保存失败：{}",
                            runtime_logs::summarize_error_for_display(&error.to_string())
                        ));
                    }
                    let exhausted_ids = snapshot
                        .subscriptions
                        .iter()
                        .filter(|account| account.health == "quotaExhausted")
                        .map(|account| account.id)
                        .collect::<BTreeSet<_>>();
                    if self.usage_notifications_ready {
                        if let Some((account_id, source, target)) =
                            fallback_transition_notification(
                                self.usage_snapshot.as_ref(),
                                &snapshot,
                                &self.config,
                            )
                        {
                            // The runtime log can report the same upstream 429
                            // immediately after this snapshot. Share the dedupe
                            // set so one quota transition yields one notification.
                            // Keep the exact account selected by the helper: when
                            // several subscriptions exhaust in one pass, the
                            // first matching account is not necessarily the one
                            // that has a real fallback pair.
                            self.notified_quota_accounts.insert(account_id);
                            // Reset the rejoin dedupe so the next recovery pops
                            // the "quota recovered / rejoined pool" notification.
                            self.rejoined_pool_notified.remove(&account_id);
                            show_fallback_notification(self.ui_language == "zh", source, target);
                        }
                        if let Some((account_id, name)) =
                            rejoined_account_notification(self.usage_snapshot.as_ref(), &snapshot)
                        {
                            if self.rejoined_pool_notified.insert(account_id) {
                                show_rejoined_pool_notification(self.ui_language == "zh", name);
                            }
                        }
                    } else {
                        // First snapshot is the startup baseline: already-exhausted
                        // accounts must not pop as if they just ran out.
                        self.notified_quota_accounts.extend(exhausted_ids.iter().copied());
                        self.usage_notifications_ready = true;
                    }
                    self.notified_quota_accounts.retain(|account_id| {
                        exhausted_ids.contains(account_id)
                            || !quota_recovery_confirmed(
                                self.usage_snapshot.as_ref(),
                                &snapshot,
                                *account_id,
                            )
                    });
                    self.usage_snapshot = Some(snapshot);
                    self.usage_snapshot_profile_key = profile_key;
                    if self.self_check_quota_refresh_pending {
                        self.schedule_usage_refresh();
                        ctx.request_repaint();
                    } else {
                        self.schedule_next_background_usage_refresh(ctx);
                    }
                    if routing_changed {
                        self.request_routing_sync();
                    }
                    if self.oauth_catalog_refresh_pending {
                        self.oauth_catalog_refresh_pending = false;
                        self.refresh_oauth_accounts();
                    }
                    self.observe_codex_binding_state();
                }
                AppEvent::UsageError {
                    profile_key,
                    generation,
                    error,
                } => {
                    match request_result_disposition(
                        self.usage_request_generation,
                        &self.active_route_profile_key(),
                        generation,
                        &profile_key,
                    ) {
                        RequestResultDisposition::Ignore => continue,
                        RequestResultDisposition::RefreshCurrent => {
                            self.usage_loading = false;
                            self.schedule_usage_refresh();
                            continue;
                        }
                        RequestResultDisposition::Apply => {}
                    }
                    self.usage_loading = false;
                    if self.oauth_catalog_refresh_pending {
                        self.oauth_catalog_refresh_pending = false;
                        self.refresh_oauth_accounts();
                    }
                    let detail = usage_error_for_display(zh, &error);
                    // When a successful snapshot is already on screen, a
                    // failed refresh must not replace the live data with a
                    // red "query failed" banner (e.g. right after a provider
                    // reset while wham/other endpoints settle). Keep showing
                    // the last good data and render a soft yellow notice.
                    self.usage_error = usage_error_for_ui(
                        self.usage_snapshot.is_some(),
                        detail.clone(),
                    );
                    self.log(format!(
                        "{}: {detail}",
                        if zh {
                            "用量查询失败"
                        } else {
                            "Usage query failed"
                        }
                    ));
                    if self.self_check_quota_refresh_pending {
                        self.schedule_usage_refresh();
                        ctx.request_repaint();
                    } else {
                        self.schedule_next_background_usage_refresh(ctx);
                    }
                }
                AppEvent::RouterModeDisabled(outcome) => {
                    self.router_mode_switching = false;
                    self.router_mode_enabled = false;
                    self.official_mode_selected = true;
                    let _ = self.persist_ui_preferences();
                    self.codex_account_mode_status =
                        profiles::codex_account_mode_status(&self.router_root, &self.config);
                    self.oauth_recovery_due = None;
                    self.health_probe_due = None;
                    self.health_probe_failures = 0;
                    self.active_profile_id.clear();
                    self.pending_profile_activation = None;
                    self.persist_ui_preferences();
                    self.status_text = if zh {
                        if outcome.shared_state_preserved && outcome.auth_available {
                            "已切回 Codex 官方路由并停止本地转发；当前账号、会话与设置保持共享。请完全退出并重新打开 Codex。"
                        } else if outcome.auth_available {
                            "已切回 Codex 官方路由并停止本地转发。请完全退出并重新打开 Codex。"
                        } else {
                            "已切回 Codex 官方路由并停止本地转发；官方登录快照缺失或无效，请重新打开 Codex 后登录。"
                        }
                    } else if outcome.shared_state_preserved && outcome.auth_available {
                        "Restored the official Codex route and stopped local forwarding while preserving the current account, tasks, and settings. Fully restart Codex."
                    } else if outcome.auth_available {
                        "Restored the official Codex route and stopped local forwarding. Fully restart Codex."
                    } else {
                        "Restored the official Codex route and stopped local forwarding. The official login snapshot was unavailable; sign in after restarting Codex."
                    }
                    .to_owned();
                    self.log(if zh {
                        "已关闭 Router 路由，Codex 已恢复官方配置"
                    } else {
                        "Router mode disabled; Codex official configuration restored"
                    });
                }
                AppEvent::RouterModeSwitchError(error) => {
                    self.router_mode_switching = false;
                    self.router_mode_enabled = logic::codex_router_mode_active(&self.config);
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    self.status_text = if zh {
                        format!("路由切换失败：{detail}")
                    } else {
                        format!("Could not switch routes: {detail}")
                    };
                    self.log(self.status_text.clone());
                }
                AppEvent::OAuthRecoveryFinished(schedule) => {
                    self.oauth_recovery_running = false;
                    self.oauth_recovery_due =
                        oauth_recovery_schedule_delay(schedule.next_check_seconds)
                            .map(|delay| std::time::Instant::now() + delay);
                    let recovered = schedule.summary.to_ascii_lowercase().contains("recovered=")
                        && schedule
                            .summary
                            .split_whitespace()
                            .any(|part| part.starts_with("recovered=") && part != "recovered=0");
                    self.log(if zh {
                        format!("OAuth 恢复探测完成：{}", schedule.summary)
                    } else {
                        format!("OAuth recovery probe finished: {}", schedule.summary)
                    });
                    if recovered {
                        self.status_text = if zh {
                            "检测到 OAuth 额度已恢复，已重新接入官方账号".to_owned()
                        } else {
                            "OAuth quota recovered; official accounts were re-enabled".to_owned()
                        };
                        if self.page == Page::OAuth || self.page == Page::Monitor {
                            self.refresh_oauth_accounts();
                        }
                    }
                }
                AppEvent::OAuthRecoveryError(error) => {
                    self.oauth_recovery_running = false;
                    self.oauth_recovery_due =
                        Some(next_failed_oauth_recovery(std::time::Instant::now()));
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    self.log(if zh {
                        format!("OAuth 恢复探测未成功：{detail}")
                    } else {
                        format!("OAuth recovery probe did not succeed: {detail}")
                    });
                }
                AppEvent::GrokSsoImported => {
                    self.grok_sso_importing = false;
                    self.grok_sso_dialog_open = false;
                    self.grok_sso_draft.clear();
                    self.grok_sso_error.clear();
                    self.grok_sso_auto_select_pending = true;
                    self.oauth_in_flight_provider = Some("grok".to_owned());
                    self.oauth_success_pending = true;
                    self.oauth_known_account_ids = self
                        .oauth_accounts
                        .iter()
                        .filter(|account| account.bound_to_router)
                        .map(|account| account.id)
                        .collect();
                    self.status_text = if zh {
                        "Grok 授权码已导入；账号已加入当前路由配置".to_owned()
                    } else {
                        "Grok authorization imported and added to this route profile".to_owned()
                    };
                    self.log(self.status_text.clone());
                    self.refresh_oauth_accounts();
                }
                AppEvent::GrokSsoImportError(error) => {
                    self.grok_sso_importing = false;
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    self.grok_sso_error.clone_from(&detail);
                    self.log(format!(
                        "{}: {detail}",
                        if zh {
                            "Grok 授权导入失败"
                        } else {
                            "Grok authorization import failed"
                        }
                    ));
                }
                AppEvent::OAuthAccountRevoked {
                    account_id,
                    account_name,
                } => {
                    self.oauth_revoking = false;
                    self.oauth_revoke_target = None;
                    self.oauth_revoke_candidates.clear();
                    logic::remove_oauth_account_references(&mut self.config, account_id);
                    self.schedule_usage_refresh();
                    let mut cleanup_errors = Vec::new();
                    if let Err(error) = self.config.save(&user_data::config_path(&self.router_root))
                    {
                        cleanup_errors.push(format!(
                            "无法保存当前配置: {}",
                            runtime_logs::summarize_error_for_display(&error.to_string())
                        ));
                    }
                    if let Err(error) =
                        profiles::purge_oauth_account_references(&self.router_root, account_id)
                    {
                        cleanup_errors.push(format!(
                            "无法清理隔离配置: {}",
                            runtime_logs::summarize_error_for_display(&error.to_string())
                        ));
                    }
                    self.oauth_accounts
                        .retain(|account| account.id != account_id);
                    if cleanup_errors.is_empty() {
                        self.oauth_error.clear();
                        self.status_text = if zh {
                            format!("已撤销 {account_name} 的本机 OAuth，并清理所有配置引用")
                        } else {
                            format!(
                                "Revoked local OAuth for {account_name} and removed it from all profiles"
                            )
                        };
                    } else {
                        self.oauth_error = cleanup_errors.join("；");
                        self.status_text = if zh {
                            format!("{account_name} 的本机 OAuth 已删除，但部分配置引用清理失败")
                        } else {
                            format!(
                                "Local OAuth for {account_name} was deleted, but some profile references could not be cleaned"
                            )
                        };
                        self.log(self.oauth_error.clone());
                    }
                    self.refresh_oauth_accounts();
                }
                AppEvent::OAuthAccountRevokeError(error) => {
                    self.oauth_revoking = false;
                    self.oauth_revoke_target = None;
                    self.oauth_revoke_candidates.clear();
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    self.oauth_error.clone_from(&detail);
                    self.status_text = if zh {
                        format!("撤销 OAuth 失败：{detail}")
                    } else {
                        format!("Could not revoke OAuth: {detail}")
                    };
                    self.log(self.status_text.clone());
                }
                AppEvent::OAuthAccountPriorityUpdated {
                    account_id,
                    priority,
                } => {
                    self.oauth_priority_saving = false;
                    self.oauth_priority_target = None;
                    if let Some(account) = self
                        .oauth_accounts
                        .iter_mut()
                        .find(|account| account.id == account_id)
                    {
                        account.priority = priority;
                    }
                    for model in &mut self.config.models {
                        if model.source == "oauth" && model.oauth_account_id == account_id {
                            model.priority = priority;
                        }
                    }
                    let _ = self
                        .config
                        .save(&crate::user_data::config_path(&self.router_root));
                    self.oauth_accounts.sort_by(|left, right| {
                        left.priority
                            .cmp(&right.priority)
                            .then(left.platform.cmp(&right.platform))
                            .then(left.id.cmp(&right.id))
                    });
                    self.status_text = if zh {
                        format!("已将 OAuth 调度优先级更新为 P{priority}")
                    } else {
                        format!("Updated OAuth scheduling priority to P{priority}")
                    };
                    self.log(self.status_text.clone());
                }
                AppEvent::OAuthAccountPriorityError(error) => {
                    self.oauth_priority_saving = false;
                    let detail = localized_error_summary(zh, &error);
                    self.oauth_error = if zh {
                        format!("更新 OAuth 优先级失败：{detail}")
                    } else {
                        format!("Could not update OAuth priority: {detail}")
                    };
                    self.log(self.oauth_error.clone());
                }
                AppEvent::ApiModelValidationFinished {
                    model,
                    editing_model,
                    model_from_wizard,
                    result,
                    available_models,
                } => {
                    self.api_model_validation_running = false;
                    let draft_unchanged = self.page == Page::Model
                        && self.temp_model.model == model.model
                        && self.temp_model.base_url == model.base_url
                        && self.temp_model.api_key == model.api_key
                        && self.editing_model == editing_model;
                    if !draft_unchanged {
                        self.status_text = if zh {
                            "API 渠道内容已变化，已忽略过期的连接测试结果，请重新保存".to_owned()
                        } else {
                            "The API channel changed; the stale connection result was ignored. Save again."
                                .to_owned()
                        };
                        continue;
                    }
                    match result {
                        Ok(()) => {
                            self.temp_model = (*model).clone();
                            self.commit_model_draft(*model, editing_model, model_from_wizard);
                            if !model_from_wizard {
                                self.show_result_dialog(
                                    ResultDialogKind::Success,
                                    if zh {
                                        "添加成功"
                                    } else {
                                        "Added successfully"
                                    },
                                    if zh {
                                        "本配置有效，模型已添加。保存并应用后即可在 Codex 使用。"
                                    } else {
                                        "This configuration is valid and the model was added. Save & apply to use it in Codex."
                                    },
                                );
                            }
                        }
                        Err(code) => {
                            self.temp_model = (*model).clone();
                            let (code, listed) = split_model_missing_code(&code);
                            let available = if listed.is_empty() {
                                available_models
                            } else {
                                listed
                            };
                            if code == "model_missing" && !available.is_empty() {
                                self.api_model_choice_open = true;
                                self.api_model_choice_ids = available;
                                self.api_model_choice_model = Some(model);
                                self.api_model_choice_editing = editing_model;
                                self.api_model_choice_from_wizard = model_from_wizard;
                                self.status_text = if zh {
                                    "连接成功，但填写的模型 ID 不在上游列表中。请从返回的可用模型里选择一项。".to_owned()
                                } else {
                                    "Connected, but the typed model ID was not listed. Choose one of the models returned by the API.".to_owned()
                                };
                            } else {
                                let detail = api_model_validation_message(code, zh);
                                self.show_result_dialog(
                                    ResultDialogKind::Failure,
                                    if zh {
                                        "本配置无效"
                                    } else {
                                        "Configuration is invalid"
                                    },
                                    if zh {
                                        format!("本配置无效，请检查配置。{detail}")
                                    } else {
                                        format!("This configuration is invalid. Please check the settings. {detail}")
                                    },
                                );
                            }
                        }
                    }
                }

                AppEvent::UpdateProgress(progress) => {
                    self.update_downloaded_bytes = progress.downloaded_bytes;
                    self.update_total_bytes = progress.total_bytes;
                    ctx.request_repaint();
                }
                AppEvent::UpdateResult(info) => {
                    self.update_checking = false;
                    self.update_downloading = false;
                    let info = *info;
                    let ready_to_install = info.status == "ready_to_install";
                    let should_download = info.status == "update_available"
                        && !info.download_url.is_empty()
                        && !info.asset_name.is_empty();
                    self.update_info = Some(info.clone());
                    self.update_dialog_open = true;
                    if should_download {
                        self.download_update(&info, ctx);
                    } else if ready_to_install {
                        let result = updater::spawn_apply_helper(
                            &self.router_root,
                            Path::new(&info.staged_path),
                            std::process::id(),
                        );
                        match result {
                            Ok(()) => {
                                self.update_installing = true;
                                self.status_text = if zh {
                                    "更新包校验完成，正在安全退出；随后会自动覆盖并重启 Codex-Router…"
                                        .to_owned()
                                } else {
                                    "The update is verified. Codex-Router will exit safely, replace the installed files, and restart automatically…"
                                        .to_owned()
                                };
                                self.request_exit(ctx);
                            }
                            Err(error) => {
                                self.update_installing = false;
                                let detail =
                                    runtime_logs::summarize_error_for_display(&error.to_string());
                                self.update_info = Some(GitHubUpdateInfo {
                                    status: "error".to_owned(),
                                    current_version: APP_VERSION.to_owned(),
                                    release_url: info.release_url,
                                    message: detail.clone(),
                                    ..Default::default()
                                });
                                self.log(format!(
                                    "{}: {detail}",
                                    if zh {
                                        "无法启动自动更新事务"
                                    } else {
                                        "Could not start the automatic update transaction"
                                    }
                                ));
                            }
                        }
                    }
                }
                AppEvent::UpdateError(error) => {
                    self.update_checking = false;
                    self.update_downloading = false;
                    self.update_installing = false;
                    let detail = runtime_logs::summarize_error_for_display(&error);
                    self.update_info = Some(GitHubUpdateInfo {
                        status: "error".into(),
                        current_version: APP_VERSION.into(),
                        release_url: OFFICIAL_GITHUB_URL.into(),
                        message: detail.clone(),
                        ..Default::default()
                    });
                    self.update_dialog_open = true;
                    self.log(format!(
                        "{}: {}",
                        if zh {
                            "更新检查失败"
                        } else {
                            "Update check failed"
                        },
                        detail
                    ));
                }
                AppEvent::RouterHealthProbeFinished(result) => {
                    self.health_probe_running = false;
                    if self.exit_shutdown_in_progress {
                        continue;
                    }
                    if !self.router_mode_enabled || !self.runtime_probes_allowed() {
                        self.health_probe_due = None;
                        self.health_probe_failures = 0;
                        continue;
                    }
                    match result {
                        Ok(()) => {
                            self.health_probe_failures = 0;
                            self.health_probe_due =
                                Some(std::time::Instant::now() + HEALTHY_PROBE_INTERVAL);
                        }
                        Err(error) => {
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            if !router_health_failure_recoverable(&error) {
                                self.health_probe_failures = 0;
                                self.health_probe_due =
                                    Some(std::time::Instant::now() + RECOVERY_RETRY_INTERVAL);
                                self.log(if zh {
                                    format!("转发保护无法探测本机 Router 配置：{detail}")
                                } else {
                                    format!("Forwarding protection could not probe the local Router configuration: {detail}")
                                });
                                continue;
                            }
                            self.health_probe_failures =
                                self.health_probe_failures.saturating_add(1);
                            self.log(if zh {
                                format!(
                                    "本机 Router 健康探测失败（{}/3）：{detail}",
                                    self.health_probe_failures
                                )
                            } else {
                                format!(
                                    "Local Router health probe failed ({}/3): {detail}",
                                    self.health_probe_failures
                                )
                            });
                            if self.health_probe_failures >= 3 {
                                self.start_router_health_recovery(ctx);
                            } else {
                                self.health_probe_due =
                                    Some(std::time::Instant::now() + FAILED_PROBE_RETRY_INTERVAL);
                            }
                        }
                    }
                }
                AppEvent::RouterHealthRecoveryFinished(result) => {
                    self.health_recovery_running = false;
                    self.health_probe_failures = 0;
                    if self.exit_shutdown_in_progress {
                        continue;
                    }
                    if !self.router_mode_enabled || !self.runtime_probes_allowed() {
                        self.health_probe_due = None;
                        continue;
                    }
                    match result {
                        Ok(()) => {
                            self.health_probe_due =
                                Some(std::time::Instant::now() + HEALTHY_PROBE_INTERVAL);
                            self.set_status(
                                if zh {
                                    "已自动恢复本机转发，连接保护继续运行"
                                } else {
                                    "Local forwarding recovered automatically; connection protection remains active"
                                },
                                8,
                            );
                            self.log(self.status_text.clone());
                            self.oauth_retry_due = Some(std::time::Instant::now());
                            self.schedule_usage_refresh();
                            self.codex_binding_check_completed = false;
                            self.observe_codex_binding_state();
                        }
                        Err(error) => {
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            self.health_probe_due =
                                Some(std::time::Instant::now() + RECOVERY_RETRY_INTERVAL);
                            self.set_status(
                                if zh {
                                    format!("自动恢复本机转发未成功，稍后重试：{detail}")
                                } else {
                                    format!("Automatic local forwarding recovery did not succeed; retrying later: {detail}")
                                },
                                15,
                            );
                            self.log(self.status_text.clone());
                        }
                    }
                }
                AppEvent::RoutingSyncFinished(result) => {
                    self.routing_sync_running = false;
                    match result {
                        Ok(()) => {
                            self.log(if zh {
                                "额度状态已同步到本机实时路由；当前 Codex 任务无需重启即可继续"
                            } else {
                                "Quota state synchronized to live routing; the current Codex task continues without a restart"
                            });
                            // A second observation may have arrived while this sync was
                            // running. Coalesce it into one follow-up sync after success.
                            if self.routing_sync_pending {
                                self.routing_sync_pending = false;
                                self.request_routing_sync();
                            }
                        }
                        Err(error) => {
                            // Keep a failed backend-only reconciliation queued. The
                            // next three-minute self-check retries it even when Codex
                            // config.toml itself was not overwritten.
                            self.routing_sync_pending = true;
                            self.usage_refresh_due =
                                Some(std::time::Instant::now() + BACKGROUND_SELF_CHECK_INTERVAL);
                            self.log(if zh {
                                format!(
                                    "实时路由同步稍后重试：{}",
                                    runtime_logs::summarize_error_for_display(&error)
                                )
                            } else {
                                format!(
                                    "Live routing synchronization will retry: {}",
                                    runtime_logs::summarize_error_for_display(&error)
                                )
                            });
                        }
                    }
                }
                AppEvent::CodexBindingProbeFinished(result) => {
                    self.codex_binding_repair_running = false;
                    match result {
                        Ok(probe) if probe.binding_repair && (probe.user_layer_bound || probe.system_layer_bound) => {
                            self.codex_overwrite_prompt_open = false;
                            self.codex_overwrite_auto_apply_at = None;
                            if !self.codex_overwrite_decision.is_empty() {
                                self.codex_overwrite_decision.clear();
                                self.codex_overwrite_decision_fingerprint.clear();
                                let _ = self.persist_ui_preferences();
                            }
                            self.log(if zh {
                                "自检发现 Codex 原生配置被覆写，已自动写回 Router 绑定；UserData 未改动".to_owned()
                            } else {
                                "Self-check found Codex's native config was overwritten and restored the Router binding automatically. UserData was not changed.".to_owned()
                            });
                            if let Some((previous, repaired)) = &probe.model_repair {
                                let previous = previous
                                    .as_deref()
                                    .unwrap_or(if zh { "<未设置>" } else { "<unset>" });
                                self.log(if zh {
                                    format!(
                                        "同时将无效的用户层 model（{previous}）修复为默认模型 {repaired}"
                                    )
                                } else {
                                    format!(
                                        "Also repaired the invalid user-layer model ({previous}) to the default model {repaired}."
                                    )
                                });
                            }
                            if let Some(detail) = &probe.system_binding_error {
                                self.log(if zh {
                                    format!(
                                        "用户层绑定已恢复，但系统层写入失败：{detail}。请以管理员权限确认 %ProgramData%\\OpenAI\\Codex\\config.toml"
                                    )
                                } else {
                                    format!(
                                        "The user-layer binding was restored, but the system-layer write failed: {detail}. Confirm %ProgramData%\\OpenAI\\Codex\\config.toml with administrator rights."
                                    )
                                });
                            }
                        }
                        Ok(probe) if !probe.user_layer_bound && !probe.system_layer_bound => {
                            let fingerprint = probe.fingerprint;
                            let suppressed = !self.codex_overwrite_decision.is_empty()
                                && self.codex_overwrite_decision_fingerprint == fingerprint;
                            if !suppressed && !self.codex_overwrite_prompt_open {
                                self.codex_overwrite_pending_fingerprint = fingerprint;
                                self.codex_overwrite_prompt_open = true;
                                self.codex_overwrite_countdown_paused_at = None;
                                self.codex_overwrite_auto_apply_at = Some(
                                    std::time::Instant::now() + std::time::Duration::from_secs(3),
                                );
                                self.log(if zh {
                                    "自检发现 Codex 原生配置已被外部程序覆写。前台将在 3 秒后自动写回 Router 绑定；也可选择保持现状或恢复官方默认"
                                        .to_owned()
                                } else {
                                    "Self-check found Codex's native config was overwritten. The foreground dialog will write the Router binding back in 3 seconds, or you can keep the file or restore official defaults.".to_owned()
                                });
                            }
                        }
                        Ok(probe) => {
                            if let Some((previous, repaired)) = &probe.model_repair {
                                let previous = previous
                                    .as_deref()
                                    .unwrap_or(if zh { "<未设置>" } else { "<unset>" });
                                self.log(if zh {
                                    format!(
                                        "检测到 Codex 用户层 model 被改为无效值（{previous}），已自动修复为默认模型 {repaired}；路由绑定未受影响"
                                    )
                                } else {
                                    format!(
                                        "Codex's user-layer model was changed to an invalid value ({previous}); repaired to the default model {repaired}. Routing was not affected."
                                    )
                                });
                            }
                            if !probe.user_layer_bound
                                && self.codex_binding_safe_strip_logged.as_deref()
                                    != Some(probe.fingerprint.as_str())
                            {
                                self.codex_binding_safe_strip_logged =
                                    Some(probe.fingerprint.clone());
                                self.log(if zh {
                                    "Codex 用户层配置被外部重写；系统层绑定仍在，所有模型仍走本地路由，无需处理".to_owned()
                                } else {
                                    "Codex's user-layer config was rewritten externally; the system-layer binding still routes every model locally, no action needed".to_owned()
                                });
                            }
                            // Binding healthy again (user layer or mirrored
                            // system layer); close any stale prompt and forget
                            // any earlier keep/factory decision so a fresh
                            // full overwrite prompts again.
                            self.codex_overwrite_prompt_open = false;
                            self.codex_overwrite_auto_apply_at = None;
                            if !self.codex_overwrite_decision.is_empty() {
                                self.codex_overwrite_decision.clear();
                                self.codex_overwrite_decision_fingerprint.clear();
                                let _ = self.persist_ui_preferences();
                            }
                        }
                        Err(error) => {
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            self.log(if zh {
                                format!("Codex 配置覆写检测未成功，将在下次自检重试：{detail}")
                            } else {
                                format!(
                                    "Codex config overwrite detection did not succeed and will retry on the next self-check: {detail}"
                                )
                            });
                        }
                    }
                }
                AppEvent::CodexFactoryResetFinished(result) => {
                    self.codex_overwrite_action_running = false;
                    match result {
                        Ok(auth_available) => {
                            self.codex_overwrite_prompt_open = false;
                            self.active_profile_id.clear();
                            self.pending_profile_activation = None;
                            self.router_mode_enabled = false;
                            self.official_mode_selected = true;
                            self.oauth_recovery_due = None;
                            self.codex_overwrite_decision.clear();
                            self.codex_overwrite_decision_fingerprint.clear();
                            self.codex_overwrite_auto_apply_at = None;
                            let _ = self.persist_ui_preferences();
                            self.status_text = if auth_available {
                                if zh {
                                    "已恢复 Codex 官方默认配置：Router 绑定已移除。正在自动重启 Codex。".into()
                                } else {
                                    "Codex factory defaults restored and the Router binding was removed. Restarting Codex.".into()
                                }
                            } else if zh {
                                "已恢复 Codex 官方默认配置：Router 绑定已移除。正在自动重启 Codex；如未登录请按官方流程登录。".into()
                            } else {
                                "Codex factory defaults restored and the Router binding was removed. Restarting Codex; sign in through the official flow if needed.".into()
                            };
                            self.log(self.status_text.clone());
                            self.restart_codex_desktop();
                        }
                        Err(error) => {
                            let detail = runtime_logs::summarize_error_for_display(&error);
                            self.report_error(if zh {
                                format!("无法恢复 Codex 官方出厂默认配置：{detail}")
                            } else {
                                format!("Could not restore Codex factory defaults: {detail}")
                            });
                        }
                    }
                }
                AppEvent::Tray(action) if self.exit_shutdown_in_progress => {
                    let _ = action;
                }
                AppEvent::Tray(action) => match action {
                    TrayAction::RestoreWindow => self.restore_from_tray(ctx),
                    TrayAction::HideWindow => self.minimize_to_tray(ctx),
                    TrayAction::OpenConsole => {
                        self.restore_from_tray(ctx);
                        self.page = Page::Dashboard;
                    }
                    TrayAction::ChooseProfile => {
                        self.restore_from_tray(ctx);
                        self.open_profiles();
                    }
                    TrayAction::ApplyCurrent => self.apply_all(),
                    TrayAction::StartForwarding => {
                        self.enable_router_mode();
                    }
                    TrayAction::StopForwarding => {
                        self.disable_router_mode();
                    }
                    TrayAction::Exit => self.request_exit(ctx),
                },
            }
        }
        while let Ok(batch) = self.runtime_log_rx.try_recv() {
            for record in batch.into_records() {
                if !self.exit_shutdown_in_progress
                    && self.runtime_probes_allowed()
                    && self.router_mode_enabled
                    && runtime_logs::signals_router_health_failure(&record)
                    && !self.health_probe_running
                    && !self.health_recovery_running
                {
                    self.health_probe_due = Some(std::time::Instant::now());
                }
                if let Some(account_id) = failover_account_id(&record) {
                    self.routing_sync_pending = true;
                    self.request_routing_sync();
                    if self.usage_notifications_ready
                        && self.notified_quota_accounts.insert(account_id)
                    {
                        if let Some((source, target)) = fallback_names_for_account(
                            &self.config,
                            &self.oauth_accounts,
                            account_id,
                        ) {
                            show_fallback_notification(self.ui_language == "zh", source, target);
                        }
                    }
                }
                if let Some((from_pool, reason)) = pool_failover_parts(&record) {
                    if self.usage_notifications_ready
                        && self
                            .notified_pool_failovers
                            .insert(format!("failover:{from_pool}"))
                    {
                        let label = pool_account_label(&self.oauth_accounts, &from_pool);
                        show_pool_switch_notification(self.ui_language == "zh", label, reason);
                    }
                } else if let Some(model) = pool_unavailable_model(&record) {
                    if self.usage_notifications_ready
                        && self
                            .notified_pool_failovers
                            .insert(format!("unavailable:{model}"))
                    {
                        show_pool_unavailable_notification(self.ui_language == "zh", model);
                    }
                }
                if runtime_logs::runtime_record_is_actionable(&record) {
                    self.log(record);
                }
            }
        }
    }

    fn load_logo_texture(&mut self, ctx: &egui::Context) {
        if self.logo_texture.is_some() {
            return;
        }
        if let Ok((pixels, width, height)) = decode_icon() {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [width as usize, height as usize],
                &pixels,
            );
            self.logo_texture =
                Some(ctx.load_texture("codex-router-logo", image, egui::TextureOptions::LINEAR));
        }
    }

    /// Dashboard status text is a transient hint, not a log of past events.
    /// Assigning it through here stamps a TTL so a stale error or an old
    /// health-recovery message can never sit on the panel after the work has
    /// already finished. The full detail still goes to the activity log.
    fn set_status(&mut self, text: impl Into<String>, ttl_secs: u64) {
        self.status_text = text.into();
        self.status_expires_at = if ttl_secs == 0 {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs))
        };
    }

    fn log(&mut self, message: impl AsRef<str>) {
        let message = runtime_logs::redact_for_display(message.as_ref());
        if message.trim().is_empty() || !runtime_logs::runtime_record_is_actionable(&message) {
            return;
        }
        append_bounded_log(&mut self.logs, &message);
        self.log_scroll_to_bottom = self.log_follow_latest;
    }

    fn report_error(&mut self, message: impl Into<String>) {
        self.status_text = localized_error_summary(self.ui_language == "zh", &message.into());
        self.log(self.status_text.clone());
    }

    fn export_logs(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: log export is disabled.".to_owned();
            return;
        }
        let timestamp = chrono::Local::now();
        let default_name = format!(
            "codex-router-diagnostics-{}.log",
            timestamp.format("%Y%m%d-%H%M%S")
        );
        let Some(path) = rfd::FileDialog::new()
            .set_title(if self.ui_language == "zh" {
                "下载脱敏运行日志"
            } else {
                "Save redacted runtime log"
            })
            .set_file_name(&default_name)
            .add_filter("Log", &["log", "txt"])
            .save_file()
        else {
            return;
        };

        let content = runtime_logs::redact_for_display(&format!(
            "Codex-Router diagnostics v{APP_VERSION}\nExported: {}\nSecrets and request/response payloads are omitted.\n\n{}",
            timestamp.to_rfc3339(),
            self.logs
        ));
        match std::fs::write(path, content) {
            Ok(()) => {
                self.status_text = if self.ui_language == "zh" {
                    "脱敏运行日志已下载".to_owned()
                } else {
                    "Redacted runtime log saved".to_owned()
                };
            }
            Err(error) => {
                let message = if self.ui_language == "zh" {
                    format!("下载日志失败：{error}")
                } else {
                    format!("Could not save the runtime log: {error}")
                };
                self.report_error(message);
            }
        }
    }

    fn open_oauth_manager(&mut self) {
        if self.page != Page::OAuth {
            self.oauth_return_page = self.page;
        }
        self.usage_refresh_due = None;
        let profile_key = self.active_route_profile_key();
        if self.usage_snapshot_profile_key != profile_key {
            self.usage_snapshot = None;
            self.usage_snapshot_profile_key.clear();
            self.load_usage_monitor_cache();
        }
        self.page = Page::OAuth;
        if self.ui_audit_mode {
            return;
        }
        self.oauth_retry_attempts = 0;
        self.trigger_self_check();
    }

    fn refresh_oauth_accounts(&mut self) {
        if self.ui_audit_mode {
            return;
        }
        if self.oauth_loading {
            return;
        }
        if !oauth_account_refresh_can_start(AdminTaskActivity {
            oauth_recovery_running: self.oauth_recovery_running,
            routing_sync_running: self.routing_sync_running,
            applying: self.applying,
            router_mode_switching: self.router_mode_switching,
            health_recovery_running: self.health_recovery_running,
            ..AdminTaskActivity::default()
        }) {
            self.oauth_retry_due =
                Some(std::time::Instant::now() + OAUTH_ACCOUNT_BUSY_RETRY_INTERVAL);
            return;
        }
        self.oauth_loading = true;
        self.oauth_error.clear();
        self.oauth_retry_due = None;
        let root = self.router_root.clone();
        let config = self.config.clone();
        let configured = self.configured;
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = if configured {
                logic::load_oauth_accounts(&root)
            } else {
                logic::load_oauth_accounts_with_config(&root, &config)
            };
            match result {
                Ok(accounts) => {
                    tx.send(AppEvent::OAuthAccountsLoaded(accounts)).ok();
                }
                Err(error) => {
                    tx.send(AppEvent::OAuthAccountsError(error.to_string()))
                        .ok();
                }
            }
        });
    }

    fn process_scheduled_oauth_account_refresh(&mut self, ctx: &egui::Context) {
        let Some(due) = self.oauth_retry_due else {
            return;
        };
        if std::time::Instant::now() < due {
            ctx.request_repaint_after(due.saturating_duration_since(std::time::Instant::now()));
            return;
        }
        self.oauth_retry_due = None;
        if !self.oauth_loading {
            self.refresh_oauth_accounts();
        }
    }

    fn open_usage_monitor(&mut self) {
        if self.page != Page::Monitor {
            self.usage_return_page = self.page;
        }
        self.usage_refresh_due = None;
        let profile_key = self.active_route_profile_key();
        if self.usage_snapshot_profile_key != profile_key {
            self.usage_snapshot = None;
            self.usage_snapshot_profile_key.clear();
            self.load_usage_monitor_cache();
        }
        self.page = Page::Monitor;
        if self.ui_audit_mode {
            return;
        }
        self.trigger_self_check();
    }

    fn active_route_profile_key(&self) -> String {
        if !self.active_profile_id.trim().is_empty() {
            return format!("profile:{}", self.active_profile_id.trim());
        }
        "default".to_owned()
    }

    fn usage_monitor_cache_path(&self) -> PathBuf {
        user_data::data_root(&self.router_root)
            .join("ui")
            .join("usage-monitor-cache.json")
    }

    fn load_usage_monitor_cache(&mut self) {
        let path = self.usage_monitor_cache_path();
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(mut cache) = serde_json::from_str::<UsageMonitorCache>(&text) else {
            return;
        };
        if cache.profile_key != self.active_route_profile_key() {
            return;
        }
        Self::sort_usage_accounts(
            &mut cache.snapshot.subscriptions,
            &self.monitor_subscription_order,
        );
        Self::sort_usage_accounts(&mut cache.snapshot.api_channels, &self.monitor_api_order);
        self.usage_snapshot = Some(cache.snapshot);
        self.usage_snapshot_profile_key = cache.profile_key;
    }

    fn save_usage_monitor_cache(
        &self,
        profile_key: &str,
        snapshot: &UsageSnapshot,
    ) -> anyhow::Result<()> {
        if self.ui_audit_mode {
            return Ok(());
        }
        let path = self.usage_monitor_cache_path();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("监控缓存路径无效"))?;
        std::fs::create_dir_all(parent)?;
        let cache = UsageMonitorCache {
            profile_key: profile_key.to_owned(),
            snapshot: snapshot.clone(),
        };
        config::atomic_write(&path, &serde_json::to_vec_pretty(&cache)?)?;
        Ok(())
    }

    fn schedule_usage_refresh_after_close(&mut self, ctx: &egui::Context) {
        if self.usage_refresh_due.is_none() {
            self.schedule_next_background_usage_refresh(ctx);
        }
    }

    fn schedule_next_background_usage_refresh(&mut self, ctx: &egui::Context) {
        self.usage_refresh_due = Some(next_background_usage_refresh(std::time::Instant::now()));
        ctx.request_repaint_after(BACKGROUND_USAGE_REFRESH_INTERVAL);
    }

    fn process_scheduled_usage_refresh(&mut self, ctx: &egui::Context) {
        let Some(due) = self.usage_refresh_due else {
            return;
        };
        let now = std::time::Instant::now();
        if scheduled_usage_refresh_is_due(self.tray_lightweight_mode, Some(due), now) {
            if !self.router_mode_enabled || !self.runtime_probes_allowed() {
                self.schedule_next_background_usage_refresh(ctx);
                return;
            }
            if self.usage_loading {
                ctx.request_repaint_after(std::time::Duration::from_secs(1));
            } else {
                self.usage_refresh_due = None;
                self.trigger_self_check();
            }
        } else {
            ctx.request_repaint_after(due.saturating_duration_since(now));
        }
    }

    fn schedule_usage_refresh(&mut self) {
        self.usage_refresh_due = Some(std::time::Instant::now());
    }

    fn terms_are_current(&self) -> bool {
        !self.config.models.is_empty()
            || terms_are_current(
                self.config.accept_compliance,
                &self.config.accepted_terms_version,
            )
    }

    fn runtime_probes_allowed(&self) -> bool {
        runtime_probes_allowed(
            self.configured,
            self.applying,
            self.page,
            self.terms_are_current(),
        ) && self
            .apply_settle_until
            .is_none_or(|until| std::time::Instant::now() >= until)
    }

    fn open_terms_before_apply(&mut self) {
        self.terms_open = true;
        self.terms_scroll_complete = false;
        self.terms_scroll_reset_pending = true;
        self.set_status(
            if self.ui_language == "zh" {
                "请先打开条例并滚动到底部，由你本人点击同意后再保存并应用"
            } else {
                "Open the terms, scroll to the end, and accept them yourself before Save & apply"
            },
            12,
        );
        self.log(self.status_text.clone());
    }

    fn isolate_background_work_for_apply(&mut self) {
        self.health_recovery_cancel.store(true, Ordering::Relaxed);
        self.health_probe_due = None;
        self.health_probe_failures = 0;
        self.oauth_recovery_due = None;
        self.usage_refresh_due = None;
        self.self_check_quota_refresh_pending = false;
        self.apply_settle_until = None;
    }

    fn start_apply_settle(&mut self) {
        let until = std::time::Instant::now() + APPLY_SETTLE_INTERVAL;
        self.apply_settle_until = Some(until);
        self.health_probe_due = Some(until);
        self.health_probe_failures = 0;
        self.oauth_recovery_due = Some(until);
        self.usage_refresh_due = Some(until);
    }

    fn trigger_self_check(&mut self) {
        if self.ui_audit_mode || self.exit_shutdown_in_progress || !self.runtime_probes_allowed() {
            return;
        }
        // Failed binding repairs are retried only when a new self-check is
        // explicitly triggered, never from the completion of the same usage
        // query. This prevents a short retry loop when Codex owns the file.
        self.codex_binding_check_completed = false;
        queue_self_check_account_maintenance(
            &mut self.oauth_catalog_refresh_pending,
            &mut self.self_check_quota_refresh_pending,
        );
        // A failed live-route reconciliation is retried by the next self-check.
        // It must not spin in the event loop or wait for a full configuration Apply.
        if self.routing_sync_pending {
            self.request_routing_sync();
        }
        self.observe_codex_binding_state();
        if self.router_mode_enabled && !self.health_probe_running && !self.health_recovery_running {
            self.health_probe_due = Some(std::time::Instant::now() + std::time::Duration::from_secs(10));
            let host = self.config.deploy.sub2api_host.clone();
            let retries = self.config.rate_limit_max_retries;
            logic::responses_gateway::set_max_output_tokens_map(logic::max_output_tokens_map(
                &self.config,
            ));
            logic::responses_gateway::set_context_budget_map(logic::context_budget_map(
                &self.config,
            ));
            let _ = logic::responses_gateway::ensure_responses_gateway(&host, retries);
        }
        self.refresh_usage_monitor();
    }

    /// Queue a backend-only route reconciliation. It never calls Apply,
    /// rewrites Codex config, or restarts a desktop client.
    fn request_routing_sync(&mut self) {
        if self.ui_audit_mode || self.exit_shutdown_in_progress || !self.router_mode_enabled {
            return;
        }
        if self.applying || self.router_mode_switching || codex_setup_running() {
            self.routing_sync_pending = true;
            return;
        }
        if self.routing_sync_running {
            self.routing_sync_pending = true;
            return;
        }
        self.routing_sync_running = true;
        let root = self.router_root.clone();
        let config = self.config.clone();
        // Consume the queued request only when a worker is actually started.
        // A worker failure will put it back with the retry timer above.
        self.routing_sync_pending = false;
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = logic::deployment::sync_routing_only(&root, &config);
            tx.send(AppEvent::RoutingSyncFinished(
                result.map_err(|error| error.to_string()),
            ))
            .ok();
        });
    }

    /// Detect another process overwriting Codex's local Router binding. This
    /// only probes and never writes config.toml: a periodic rewrite reloads
    /// Codex Desktop's OAuth manager and can collide with OpenAI token
    /// rotation. The user decides through the overwrite prompt whether the
    /// Router standard config is written back, the overwritten file is kept,
    /// or Codex returns to its factory defaults. Never touches auth.json, so
    /// an active ChatGPT account and task remain intact.
    fn observe_codex_binding_state(&mut self) {
        if self.ui_audit_mode
            || !self.router_mode_enabled
            || self.official_mode_selected
            || !self.runtime_probes_allowed()
            || self.applying
            || self.router_mode_switching
            || codex_setup_running()
        {
            return;
        }
        if self.codex_binding_repair_running || self.codex_binding_check_completed {
            return;
        }
        self.codex_binding_repair_running = true;
        self.codex_binding_check_completed = true;
        let root = self.router_root.clone();
        let config = self.config.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<logic::codex_toml::CodexBindingProbe> {
                let _config_lock =
                    profiles::acquire_config_apply_lock(&root, std::time::Duration::from_secs(1))?;
                logic::codex_toml::probe_codex_binding_state(&config, &root)
            })();
            tx.send(AppEvent::CodexBindingProbeFinished(
                result.map_err(|error| format!("{error:#}")),
            ))
            .ok();
        });
    }

    fn process_codex_overwrite_countdown(&mut self, ctx: &egui::Context) {
        if !self.codex_overwrite_prompt_open
            || self.codex_overwrite_action_running
            || self.applying
        {
            self.codex_overwrite_auto_apply_at = None;
            self.codex_overwrite_countdown_paused_at = None;
            return;
        }
        let foreground_focused = !self.tray_lightweight_mode
            && ctx.input(|input| {
                let viewport = input.viewport();
                viewport.minimized != Some(true)
                    && viewport.occluded != Some(true)
                    && viewport.focused == Some(true)
            });
        if advance_overwrite_countdown(
            &mut self.codex_overwrite_auto_apply_at,
            &mut self.codex_overwrite_countdown_paused_at,
            std::time::Instant::now(),
            foreground_focused,
        ) {
            self.codex_overwrite_apply_router_config();
            return;
        }
        if self.codex_overwrite_auto_apply_at.is_some() && foreground_focused {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    /// Overwrite prompt option 1: write the CodexRouter standard configuration
    /// back over the externally overwritten file.
    fn codex_overwrite_apply_router_config(&mut self) {
        if self.ui_audit_mode || self.codex_overwrite_action_running || self.applying {
            return;
        }
        self.codex_overwrite_action_running = true;
        self.codex_overwrite_decision.clear();
        self.codex_overwrite_decision_fingerprint.clear();
        self.codex_overwrite_auto_apply_at = None;
        self.codex_overwrite_countdown_paused_at = None;
        let _ = self.persist_ui_preferences();
        if !self.apply_all_with_backup(true, None, None) {
            self.codex_overwrite_action_running = false;
            return;
        }
        self.codex_overwrite_prompt_open = false;
        self.codex_overwrite_auto_apply_at = None;
        self.codex_overwrite_countdown_paused_at = None;
        self.set_status(
            if self.ui_language == "zh" {
                "正在保存并写入当前 CodexRouter 配置，完成后会自动重启 Codex"
            } else {
                "Saving and writing the current CodexRouter configuration; Codex will restart when it finishes"
            },
            12,
        );
        self.log(self.status_text.clone());
    }

    /// Overwrite prompt option 2: keep the externally overwritten config as it
    /// is. Remembered by fingerprint so the prompt only returns after the file
    /// changes again.
    fn codex_overwrite_keep_current(&mut self) {
        if self.codex_overwrite_action_running {
            return;
        }
        self.codex_overwrite_decision = "keep".to_owned();
        self.codex_overwrite_decision_fingerprint =
            self.codex_overwrite_pending_fingerprint.clone();
        let _ = self.persist_ui_preferences();
        self.codex_overwrite_prompt_open = false;
        let zh = self.ui_language == "zh";
        let message = if zh {
            "已保持当前被覆写的 Codex 配置，未写入任何更改"
        } else {
            "Kept the overwritten Codex config unchanged"
        };
        self.set_status(message, 12);
        self.log(message);
        // Keep still refreshes the system-layer binding so non-ChatGPT models
        // remain routed through the local gateway even while the user file stays
        // as the externally overwritten version.
        let root = self.router_root.clone();
        let cfg = self.config.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let catalog_path = crate::user_data::state_root(&root).join("model-catalog.json");
            let local_key = match crate::logic::ensure_local_api_key() {
                Ok(key) => key,
                Err(error) => {
                    let detail = crate::runtime_logs::summarize_error_for_display(&error.to_string());
                    tx.send(AppEvent::Log(if zh {
                        format!("无法读取本地 Router 密钥，系统层绑定未刷新：{detail}")
                    } else {
                        format!("Could not read the local Router credential; system-layer binding was not refreshed: {detail}")
                    }))
                    .ok();
                    return;
                }
            };
            let base_url = match crate::logic::responses_gateway::responses_gateway_url(
                &cfg.deploy.sub2api_host,
            ) {
                Ok(url) => url,
                Err(error) => {
                    let detail = crate::runtime_logs::summarize_error_for_display(&error.to_string());
                    tx.send(AppEvent::Log(if zh {
                        format!("无法解析本地网关地址，系统层绑定未刷新：{detail}")
                    } else {
                        format!("Could not resolve the local gateway URL; system-layer binding was not refreshed: {detail}")
                    }))
                    .ok();
                    return;
                }
            };
            let display_openai_provider =
                crate::logic::codex_toml::login_prefers_chatgpt_identity(
                    &crate::logic::resolve_codex_home(&cfg),
                    &cfg,
                );
            match crate::logic::codex_toml::write_codex_system_binding(
                &catalog_path,
                &local_key,
                &base_url,
                display_openai_provider,
                display_openai_provider,
                cfg.rate_limit_max_retries,
            ) {
                Ok(()) => {
                    tx.send(AppEvent::Log(if zh {
                        "已刷新 Codex 系统层 Router 绑定，用户层配置保持不变".to_owned()
                    } else {
                        "Refreshed the Codex system-layer Router binding; the user-layer config was left unchanged".to_owned()
                    }))
                    .ok();
                }
                Err(error) => {
                    let detail = crate::runtime_logs::summarize_error_for_display(&error.to_string());
                    tx.send(AppEvent::Log(if zh {
                        format!("刷新 Codex 系统层绑定失败：{detail}。请以管理员权限确认 %ProgramData%\\OpenAI\\Codex\\config.toml")
                    } else {
                        format!("Failed to refresh the Codex system-layer binding: {detail}. Confirm %ProgramData%\\OpenAI\\Codex\\config.toml with administrator rights.")
                    }))
                    .ok();
                }
            }
        });
    }

    /// Overwrite prompt option 3: restore Codex to its official factory
    /// defaults (removes everything Router added, keeps unrelated settings).
    fn codex_overwrite_restore_factory(&mut self) {
        if self.ui_audit_mode || self.codex_overwrite_action_running {
            return;
        }
        self.codex_overwrite_action_running = true;
        let root = self.router_root.clone();
        let config = self.config.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<bool> {
                let _config_lock = profiles::acquire_config_apply_lock(
                    &root,
                    std::time::Duration::from_secs(10),
                )?;
                let outcome = profiles::initialize_codex_defaults(&root, &config)?;
                logic::codex_toml::remove_codex_system_binding()
                    .context("无法移除 Codex 系统层的 Router 绑定")?;
                Ok(outcome.auth_available)
            })();
            tx.send(AppEvent::CodexFactoryResetFinished(
                result.map_err(|error| format!("{error:#}")),
            ))
            .ok();
        });
    }

    fn process_router_health_protection(&mut self, ctx: &egui::Context) {
        if self.exit_shutdown_in_progress
            || !self.router_mode_enabled
            || !self.runtime_probes_allowed()
        {
            self.health_probe_due = None;
            self.health_probe_failures = 0;
            return;
        }
        if self.applying || self.router_mode_switching {
            self.health_probe_due = Some(std::time::Instant::now() + HEALTHY_PROBE_INTERVAL);
            ctx.request_repaint_after(HEALTHY_PROBE_INTERVAL);
            return;
        }
        if self.health_probe_running || self.health_recovery_running {
            return;
        }

        let now = std::time::Instant::now();
        let due = self
            .health_probe_due
            .get_or_insert_with(|| now + HEALTHY_PROBE_INTERVAL);
        if now < *due {
            ctx.request_repaint_after(due.saturating_duration_since(now));
            return;
        }

        self.health_probe_due = None;
        self.health_probe_running = true;
        let base_uri = self.config.deploy.sub2api_host.clone();
        let tx = self.event_tx.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let result = router_deep_health(&base_uri, HEALTH_PROBE_TIMEOUT)
                .map_err(|error| classify_router_health_error(&error));
            tx.send(AppEvent::RouterHealthProbeFinished(result)).ok();
            repaint.request_repaint();
        });
    }

    fn start_router_health_recovery(&mut self, ctx: &egui::Context) {
        if self.exit_shutdown_in_progress
            || self.health_recovery_running
            || !self.router_mode_enabled
            || !self.runtime_probes_allowed()
        {
            return;
        }
        self.health_probe_due = None;
        self.health_recovery_running = true;
        self.health_recovery_cancel.store(false, Ordering::Relaxed);
        self.set_status(
            if self.ui_language == "zh" {
                "连续 3 次健康探测失败，正在无窗口恢复本机转发…"
            } else {
                "Three health probes failed; recovering local forwarding without a console window…"
            },
            0,
        );
        self.log(self.status_text.clone());

        let root = self.router_root.clone();
        let base_uri = self.config.deploy.sub2api_host.clone();
        let tx = self.event_tx.clone();
        let repaint = ctx.clone();
        let cancel = self.health_recovery_cancel.clone();
        std::thread::spawn(move || {
            let repaired = lifecycle::ensure_services(&root, true, &cancel, false).is_ok();
            let result = if repaired {
                router_deep_health(&base_uri, HEALTH_PROBE_TIMEOUT)
            } else {
                Err("The verified recovery process failed or timed out".to_owned())
            };
            tx.send(AppEvent::RouterHealthRecoveryFinished(result)).ok();
            repaint.request_repaint();
        });
    }

    fn process_scheduled_oauth_recovery(&mut self, ctx: &egui::Context) {
        if self.exit_shutdown_in_progress {
            self.oauth_recovery_cancel.store(true, Ordering::Relaxed);
            self.oauth_recovery_due = None;
            return;
        }
        if !self.runtime_probes_allowed() {
            self.oauth_recovery_due = None;
            return;
        }
        if !self.router_mode_enabled
            || !(self
                .config
                .oauth_account_ids
                .as_ref()
                .is_some_and(|accounts| !accounts.is_empty())
                || self
                    .config
                    .models
                    .iter()
                    .any(|model| model.source == "oauth"))
        {
            self.oauth_recovery_due = None;
            return;
        }
        let Some(due) = self.oauth_recovery_due else {
            return;
        };
        let now = std::time::Instant::now();
        if now < due {
            ctx.request_repaint_after(due.saturating_duration_since(now));
            return;
        }
        if self.oauth_recovery_running {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
            return;
        }
        if !scheduled_oauth_recovery_can_start(AdminTaskActivity {
            applying: self.applying,
            router_mode_switching: self.router_mode_switching,
            usage_loading: self.usage_loading,
            oauth_loading: self.oauth_loading,
            routing_sync_running: self.routing_sync_running,
            health_probe_running: self.health_probe_running,
            health_recovery_running: self.health_recovery_running,
            provider_oauth_preparing: self.provider_oauth_preparing,
            provider_oauth_running: self.provider_oauth_running,
            oauth_recovery_running: self.oauth_recovery_running,
        }) {
            self.oauth_recovery_due = Some(now + OAUTH_RECOVERY_BUSY_RETRY_INTERVAL);
            ctx.request_repaint_after(OAUTH_RECOVERY_BUSY_RETRY_INTERVAL);
            return;
        }
        self.oauth_recovery_due = None;
        self.start_oauth_recovery_probe();
    }

    fn request_oauth_recovery_probe(&mut self, delay: std::time::Duration) {
        if self.ui_audit_mode || self.exit_shutdown_in_progress || !self.router_mode_enabled {
            return;
        }
        let has_selected_oauth = self
            .config
            .oauth_account_ids
            .as_ref()
            .is_some_and(|accounts| !accounts.is_empty())
            || self
                .config
                .models
                .iter()
                .any(|model| model.source == "oauth");
        if !has_selected_oauth {
            self.oauth_recovery_due = None;
            return;
        }
        if self.oauth_recovery_running {
            return;
        }
        let due = std::time::Instant::now() + delay;
        self.oauth_recovery_due = Some(match self.oauth_recovery_due {
            Some(existing) if existing <= due => existing,
            _ => due,
        });
    }

    fn start_oauth_recovery_probe(&mut self) {
        if self.oauth_recovery_running {
            return;
        }
        self.oauth_recovery_due = None;
        self.oauth_recovery_running = true;
        self.oauth_recovery_cancel.store(false, Ordering::Relaxed);
        let cwd = self.router_root.clone();
        let config = self.config.clone();
        let tx = self.event_tx.clone();
        let cancel = self.oauth_recovery_cancel.clone();
        std::thread::spawn(
            move || match logic::probe_oauth_recovery(&cwd, &config, &cancel) {
                Ok(result) => {
                    let schedule = OAuthRecoverySchedule {
                        next_check_seconds: result.next_check_seconds,
                        summary: result.summary,
                    };
                    tx.send(AppEvent::OAuthRecoveryFinished(schedule)).ok();
                }
                Err(error) => {
                    tx.send(AppEvent::OAuthRecoveryError(
                        runtime_logs::summarize_error_for_display(&error.to_string()),
                    ))
                    .ok();
                }
            },
        );
    }

    fn sort_usage_accounts(accounts: &mut [UsageAccount], order: &[i64]) {
        accounts.sort_by_key(|account| {
            order
                .iter()
                .position(|account_id| *account_id == account.id)
                .unwrap_or(usize::MAX)
        });
    }

    fn refresh_usage_monitor(&mut self) {
        if self.ui_audit_mode || !self.runtime_probes_allowed() {
            self.usage_loading = false;
            self.self_check_quota_refresh_pending = false;
            return;
        }
        if self.usage_loading {
            return;
        }
        self.usage_refresh_due = None;
        self.self_check_quota_refresh_pending = false;
        self.usage_loading = true;
        let generation = next_request_generation(&mut self.usage_request_generation);
        self.usage_error.clear();
        let root = self.router_root.clone();
        let profile_name = self.active_route_config_name(self.ui_language == "zh");
        let profile_key = self.active_route_profile_key();
        let config = self.config.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            match logic::load_usage_snapshot(&root, &profile_name, &config) {
                Ok(snapshot) => {
                    tx.send(AppEvent::UsageLoaded {
                        profile_key,
                        generation,
                        snapshot: Box::new(snapshot),
                    })
                    .ok();
                }
                Err(error) => {
                    tx.send(AppEvent::UsageError {
                        profile_key,
                        generation,
                        error: error.to_string(),
                    })
                    .ok();
                }
            }
        });
    }

    fn import_grok_sso(&mut self) {
        if self.ui_audit_mode {
            self.grok_sso_error = "UI audit mode: import is disabled.".to_owned();
            return;
        }
        if self.grok_sso_importing || self.grok_sso_draft.trim().is_empty() {
            return;
        }
        self.grok_sso_importing = true;
        self.grok_sso_error.clear();
        let root = self.router_root.clone();
        let authorization = self.grok_sso_draft.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(
            move || match logic::import_grok_sso(&root, &authorization) {
                Ok(_) => {
                    tx.send(AppEvent::GrokSsoImported).ok();
                }
                Err(error) => {
                    tx.send(AppEvent::GrokSsoImportError(error.to_string()))
                        .ok();
                }
            },
        );
    }

    fn revoke_oauth_account(&mut self, account: OAuthAccountSummary) {
        if self.ui_audit_mode {
            self.oauth_error = "UI audit mode: account revocation is disabled.".to_owned();
            return;
        }
        if self.oauth_revoking {
            return;
        }
        self.oauth_revoking = true;
        self.oauth_error.clear();
        let root = self.router_root.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(
            move || match logic::revoke_oauth_account(&root, account.id) {
                Ok(()) => {
                    tx.send(AppEvent::OAuthAccountRevoked {
                        account_id: account.id,
                        account_name: account.name,
                    })
                    .ok();
                }
                Err(error) => {
                    tx.send(AppEvent::OAuthAccountRevokeError(error.to_string()))
                        .ok();
                }
            },
        );
    }

    fn save_oauth_account_priority(&mut self) {
        if self.ui_audit_mode {
            self.oauth_error = "UI audit mode: priority changes are disabled.".to_owned();
            return;
        }
        let Some(account) = self.oauth_priority_target.clone() else {
            return;
        };
        if self.oauth_priority_saving {
            return;
        }
        let priority = self.oauth_priority_draft.clamp(1, 999);
        self.oauth_priority_draft = priority;
        self.oauth_priority_saving = true;
        self.oauth_error.clear();
        let root = self.router_root.clone();
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            match logic::set_oauth_account_priority(&root, account.id, priority) {
                Ok(saved) => {
                    tx.send(AppEvent::OAuthAccountPriorityUpdated {
                        account_id: account.id,
                        priority: saved,
                    })
                    .ok();
                }
                Err(error) => {
                    tx.send(AppEvent::OAuthAccountPriorityError(error.to_string()))
                        .ok();
                }
            }
        });
    }

    fn open_oauth_priority_editor(&mut self, account: OAuthAccountSummary) {
        self.oauth_priority_draft = account.priority.clamp(1, 999);
        if self.oauth_priority_draft < 1 {
            self.oauth_priority_draft = 1;
        }
        self.oauth_priority_target = Some(account);
        self.oauth_error.clear();
    }

    fn enable_router_mode(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: Router switching is disabled.".to_owned();
            return;
        }
        if self.router_mode_switching || self.applying {
            return;
        }
        if !self.ensure_profile_binding_for_apply(false) {
            return;
        }
        if self.router_mode_enabled && logic::codex_router_mode_active(&self.config) {
            self.status_text = if self.ui_language == "zh" {
                "当前已在使用 Codex-Router 路由"
            } else {
                "Codex-Router routing is already active"
            }
            .to_owned();
            return;
        }
        self.health_recovery_cancel.store(true, Ordering::Relaxed);
        self.router_mode_enabled = true;
        let _ = self.persist_ui_preferences();
        self.router_mode_switching = true;
        self.log(if self.ui_language == "zh" {
            "正在启用 Router 路由并应用当前配置…"
        } else {
            "Enabling Router mode and applying the current configuration…"
        });
        if !self.apply_all_with_backup(true, None, None) {
            self.router_mode_switching = false;
        }
    }

    fn disable_router_mode(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: Router switching is disabled.".to_owned();
            return;
        }
        if self.router_mode_switching || self.applying {
            return;
        }
        if !self.router_mode_enabled && !logic::codex_router_mode_active(&self.config) {
            self.status_text = if self.ui_language == "zh" {
                "当前已在使用 Codex 官方路由"
            } else {
                "The official Codex route is already active"
            }
            .to_owned();
            return;
        }
        self.health_recovery_cancel.store(true, Ordering::Relaxed);
        self.router_mode_switching = true;
        let root = self.router_root.clone();
        let config = self.config.clone();
        let share_codex_state = self.share_codex_state;
        let tx = self.event_tx.clone();
        self.status_text = if self.ui_language == "zh" {
            "正在恢复 Codex 官方配置，然后停止本地转发…"
        } else {
            "Restoring the official Codex configuration, then stopping local forwarding…"
        }
        .to_owned();
        self.log(self.status_text.clone());
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<profiles::RestoreOutcome> {
                let _config_lock =
                    profiles::acquire_config_apply_lock(&root, std::time::Duration::from_secs(10))?;
                profiles::capture_restore_point(
                    &root,
                    &config,
                    "关闭 Router 路由并恢复 Codex 官方配置之前",
                )?;
                let outcome = profiles::restore_original_codex(&root, &config, share_codex_state)?;
                logic::codex_toml::remove_codex_system_binding()
                    .context("无法移除 Codex 系统层的 Router 绑定")?;
                logic::run_stop_router_script(&root)?;
                Ok(outcome)
            })();
            match result {
                Ok(outcome) => {
                    tx.send(AppEvent::RouterModeDisabled(outcome)).ok();
                }
                Err(error) => {
                    tx.send(AppEvent::RouterModeSwitchError(error.to_string()))
                        .ok();
                }
            }
        });
    }

    fn apply_all(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: configuration apply is disabled.".to_owned();
            return;
        }
        if !self.ensure_profile_binding_for_apply(true) {
            return;
        }
        let active_profile_id =
            (!self.active_profile_id.trim().is_empty()).then(|| self.active_profile_id.clone());
        if self.apply_all_with_backup(true, None, None) && self.pending_profile_activation.is_none()
        {
            // A normal save made while an isolated profile is active must also
            // refresh that profile's RouterConfig snapshot. This keeps its
            // OAuth account bindings, imported models, and fallback policy
            // independent when the user switches away and back later.
            self.pending_profile_activation = active_profile_id;
        }
    }

    fn apply_all_with_backup(
        &mut self,
        capture_before_apply: bool,
        config_lock: Option<profiles::ConfigApplyLock>,
        transaction_backup: Option<ApplyTransactionBackup>,
    ) -> bool {
        if self.applying || self.exit_shutdown_in_progress {
            return false;
        }
        if !self.ensure_profile_binding_for_apply(false) {
            return false;
        }
        let zh = self.ui_language == "zh";
        if self.config.models.is_empty() && !self.terms_are_current() {
            self.open_terms_before_apply();
            return false;
        }
        if self.config.models.is_empty() {
            let message = if zh {
                "请至少添加一个模型"
            } else {
                "Add at least one model"
            };
            self.report_error(message);
            return false;
        }
        logic::normalize_default_model(&mut self.config);
        self.apply_cancel.store(false, Ordering::Release);
        self.isolate_background_work_for_apply();
        self.applying = true;
        self.configured = false;
        self.status_text = if zh {
            "正在安全保存凭据并配置本地 Router..."
        } else {
            "Saving credentials securely and configuring the local Router..."
        }
        .into();
        let mut cfg = self.config.clone();
        let oauth_accounts = self
            .oauth_accounts
            .iter()
            .map(|account| (account.id, account.platform.clone()))
            .collect::<Vec<_>>();
        let root = self.router_root.clone();
        let tx = self.event_tx.clone();
        let apply_cancel = self.apply_cancel.clone();
        let share_codex_state = self.share_codex_state;
        for model in &mut self.config.models {
            model.api_key.clear();
        }
        self.config.proxy.password.clear();
        std::thread::spawn(move || {
            let mut transaction_backup = transaction_backup;
            let result = (|| -> anyhow::Result<()> {
                if apply_cancel.load(Ordering::Acquire) {
                    anyhow::bail!("deployment cancelled because Codex-Router is exiting");
                }
                let _config_lock = match config_lock {
                    Some(lock) => lock,
                    None => profiles::acquire_config_apply_lock(
                        &root,
                        std::time::Duration::from_secs(10),
                    )?,
                };
                if apply_cancel.load(Ordering::Acquire) {
                    anyhow::bail!("deployment cancelled because Codex-Router is exiting");
                }
                profiles::ensure_original_codex_snapshot(&root, &cfg)?;
                if capture_before_apply {
                    let (point, config) = profiles::capture_applied_restore_point(
                        &root,
                        &cfg,
                        "应用 Router 配置之前",
                    )?;
                    transaction_backup = Some(ApplyTransactionBackup { point, config });
                }
                deploy_router_config(&mut cfg, &root, &apply_cancel, zh, &oauth_accounts, |line| {
                    tx.send(AppEvent::Log(line)).ok();
                })
            })();
            match result {
                Ok(()) => {
                    tx.send(AppEvent::Complete).ok();
                }
                Err(error) => {
                    let error = if apply_cancel.load(Ordering::Acquire) {
                        error
                    } else if let Some(backup) = transaction_backup.as_ref() {
                        match rollback_failed_deployment(
                            &root,
                            backup,
                            share_codex_state,
                            zh,
                            |line| {
                                tx.send(AppEvent::Log(line)).ok();
                            },
                        ) {
                            Ok(()) => error.context("已自动恢复应用前配置"),
                            Err(rollback_error) => {
                                error.context(format!("自动恢复应用前配置失败：{rollback_error}"))
                            }
                        }
                    } else {
                        error
                    };
                    // `to_string` would only surface the outermost rollback
                    // context and hide the deployment failure that caused it.
                    tx.send(AppEvent::Error(format!("{error:#}"))).ok();
                }
            }
        });
        true
    }

    fn ensure_profile_binding_for_apply(&mut self, focus_profiles: bool) -> bool {
        if profile_binding_ready(
            self.config.deploy.generate_isolation,
            &self.active_profile_id,
            self.pending_profile_activation.as_deref(),
            &self.isolation_profiles,
        ) {
            return true;
        }
        let zh = self.ui_language == "zh";
        let requested_id = self
            .pending_profile_activation
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| self.active_profile_id.trim());
        self.status_text = if requested_id.is_empty() && self.isolation_profiles.is_empty() {
            if zh {
                "已启用配置隔离。首次保存前请先创建并应用一个配置分组；已停止写入默认 Codex 配置。"
            } else {
                "Configuration isolation is enabled. Create and apply a profile before the first save; the default Codex configuration was not changed."
            }
        } else if requested_id.is_empty() {
            if zh {
                "检测到已有配置分组，但当前没有活动绑定。请选择一个配置分组后再应用；已停止写入默认 Codex 配置。"
            } else {
                "Profiles exist, but none is actively bound. Select a profile before applying; the default Codex configuration was not changed."
            }
        } else if zh {
            "当前绑定的配置分组不存在。请重新选择或创建配置分组；已停止写入默认 Codex 配置。"
        } else {
            "The bound profile no longer exists. Select or create a profile; the default Codex configuration was not changed."
        }
        .to_owned();
        if focus_profiles {
            self.page = Page::Profiles;
            if self.isolation_profiles.is_empty() {
                self.local_profile_name_input.clear();
            }
        }
        self.log(self.status_text.clone());
        false
    }

    fn copy_local_api_key(&mut self) {
        if self.ui_audit_mode {
            return;
        }
        let zh = self.ui_language == "zh";
        match platform::copy_router_credential("LocalApiKey", None) {
            Ok(()) => {
                self.status_text = if zh {
                    "本机 Router Key 已复制"
                } else {
                    "Local Router key copied"
                }
                .to_owned();
            }
            Err(error) => self.report_error(if zh {
                format!("无法复制本机 Router Key：{error}")
            } else {
                format!("Could not copy the local Router key: {error}")
            }),
        }
    }

    fn check_for_updates(&mut self) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: update checks are disabled.".to_owned();
            return;
        }
        if self.update_checking || self.update_downloading {
            return;
        }
        self.update_checking = true;
        self.update_downloaded_bytes = 0;
        self.update_total_bytes = 0;
        self.update_dialog_open = false;
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let result = updater::check_for_updates(APP_VERSION);
            match result {
                Ok(info) => tx.send(AppEvent::UpdateResult(Box::new(info))).ok(),
                Err(error) => tx.send(AppEvent::UpdateError(error.to_string())).ok(),
            };
        });
    }

    fn download_update(&mut self, info: &GitHubUpdateInfo, ctx: &egui::Context) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: downloads are disabled.".to_owned();
            return;
        }
        if self.update_downloading || info.download_url.is_empty() || info.asset_name.is_empty() {
            return;
        }
        self.update_downloading = true;
        self.update_downloaded_bytes = 0;
        self.update_total_bytes = info.asset_size;
        let router_root = self.router_root.clone();
        let tx = self.event_tx.clone();
        let info = info.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let result = updater::download_and_stage_update(&router_root, &info, |progress| {
                tx.send(AppEvent::UpdateProgress(progress)).ok();
                repaint.request_repaint();
            });
            match result {
                Ok(info) => tx.send(AppEvent::UpdateResult(Box::new(info))).ok(),
                Err(error) => tx.send(AppEvent::UpdateError(error.to_string())).ok(),
            };
            repaint.request_repaint();
        });
    }

    fn open_update_url(&self, requested_url: &str) {
        if self.ui_audit_mode {
            return;
        }
        let url = if requested_url.starts_with(OFFICIAL_GITHUB_URL) {
            requested_url
        } else {
            OFFICIAL_GITHUB_URL
        };
        let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
    }

    fn open_download_location(&self, requested_path: &str) {
        if self.ui_audit_mode {
            return;
        }
        let path = PathBuf::from(requested_path);
        if requested_path.is_empty() || !path.starts_with(self.router_root.join("updates")) {
            return;
        }
        let _ = std::process::Command::new("explorer.exe")
            .arg(format!("/select,{}", path.display()))
            .spawn();
    }


    fn show_result_dialog(
        &mut self,
        kind: ResultDialogKind,
        title: impl Into<String>,
        body: impl Into<String>,
    ) {
        self.result_dialog_kind = kind;
        self.result_dialog_title = title.into();
        self.result_dialog_body = body.into();
        self.result_dialog_open = true;
        self.status_text = self.result_dialog_body.clone();
        if kind == ResultDialogKind::Failure {
            self.status_expires_at = None;
        }
        self.log(self.result_dialog_body.clone());
    }

    fn show_oauth_authorized_dialog(&mut self, provider: &str, imported: &[String]) {
        let zh = self.ui_language == "zh";
        let provider_key = provider.trim().to_ascii_lowercase();
        let provider_label = match provider_key.as_str() {
            "openai" | "chatgpt" => "ChatGPT",
            "anthropic" | "claude" => "Claude",
            "gemini" => "Gemini",
            "antigravity" => "Antigravity",
            "grok" | "xai" | "x-ai" => "Grok",
            other if !other.is_empty() => other,
            _ => {
                if zh {
                    "订阅"
                } else {
                    "subscription"
                }
            }
        };
        let body = if zh {
            if imported.is_empty() {
                format!("{provider_label} 授权已成功。账号已加入当前配置；请在 OAuth 页选择要使用的模型后保存并应用。")
            } else {
                format!(
                    "{provider_label} 授权已成功，已将 {} 加入当前模型列表。保存并应用后即可在 Codex 使用。",
                    imported.join("、")
                )
            }
        } else if imported.is_empty() {
            format!("{provider_label} authorization succeeded. The account was added to this profile; choose models on the OAuth page, then Save & apply.")
        } else {
            format!(
                "{provider_label} authorization succeeded and added {} to this profile. Save & apply to use it in Codex.",
                imported.join(", ")
            )
        };
        self.show_result_dialog(
            ResultDialogKind::Success,
            if zh {
                "授权已成功"
            } else {
                "Authorization succeeded"
            },
            body,
        );
    }

    fn local_sub2api_base_url(&self) -> String {
        let fallback = crate::config::default_router_host();
        let candidate = self.config.deploy.sub2api_host.trim().trim_end_matches('/');
        let Ok(mut url) = url::Url::parse(candidate) else {
            return fallback.to_owned();
        };
        if url.scheme() != "http"
            || !matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port_or_known_default().is_none()
        {
            return fallback.to_owned();
        }
        url.set_path("");
        url.set_query(None);
        url.set_fragment(None);
        url.as_str().trim_end_matches('/').to_owned()
    }

    fn cancel_provider_oauth(&mut self) {
        if !self.provider_oauth_running && !self.provider_oauth_preparing {
            return;
        }
        self.provider_oauth_cancel.store(true, Ordering::Relaxed);
        self.provider_oauth_prepare_cancel
            .store(true, Ordering::Release);
        if let Some(prompt) = self.provider_oauth_prompt.take() {
            let _ = prompt
                .response
                .send(logic::oauth::PromptResponse::Cancelled);
        }
        self.provider_oauth_code_draft.clear();
        self.provider_oauth_project_draft.clear();
        self.provider_oauth_running = false;
        self.provider_oauth_preparing = false;
        self.provider_oauth_preparing_provider = None;
        self.pending_oauth_provider = None;
        self.oauth_auto_enable_provider = None;
        self.oauth_in_flight_provider = None;
        self.oauth_success_pending = false;
        self.status_text = if self.ui_language == "zh" {
            "已取消 OAuth 登录。关闭浏览器标签后可重新点击登录。".to_owned()
        } else {
            "OAuth login cancelled. Close the browser tab, then try signing in again.".to_owned()
        };
        self.log(self.status_text.clone());
    }

    fn start_provider_oauth(&mut self, provider: &str) {
        if self.ui_audit_mode {
            self.status_text = "UI audit mode: OAuth launch is disabled.".to_owned();
            return;
        }
        if self.provider_oauth_running {
            self.status_text = if self.ui_language == "zh" {
                "已有 OAuth 登录正在进行。可点击「取消 OAuth」后重试。".to_owned()
            } else {
                "An OAuth login is already in progress. Click Cancel OAuth, then retry.".to_owned()
            };
            return;
        }
        if !matches!(
            provider,
            "openai" | "anthropic" | "gemini" | "antigravity" | "grok"
        ) {
            self.report_error("不支持的 OAuth 平台".to_owned());
            return;
        }
        if self.page == Page::Auth && self.config.models.is_empty() {
            self.oauth_auto_enable_provider = Some(provider.to_owned());
        }
        if !self.config.accept_compliance
            || self.config.accepted_terms_version != CURRENT_TERMS_VERSION
        {
            self.pending_oauth_provider = Some(provider.to_owned());
            self.terms_open = true;
            self.terms_scroll_complete = false;
            self.terms_scroll_reset_pending = true;
            self.prewarm_provider_oauth(provider);
            self.status_text = if self.ui_language == "zh" {
                "首次 OAuth 前请先阅读并同意本地部署与使用条例；登录环境正在后台准备".to_owned()
            } else {
                "Read and accept the local deployment and use terms before the first OAuth login. The sign-in environment is preparing in the background".to_owned()
            };
            return;
        }
        self.launch_provider_oauth(provider);
    }

    fn prewarm_provider_oauth(&mut self, provider: &str) {
        if self.ui_audit_mode || self.provider_oauth_running {
            return;
        }
        if self.provider_oauth_prepared_provider.as_deref() == Some(provider) {
            if self.provider_oauth_preparing {
                self.cancel_provider_oauth_preparation(false);
            }
            return;
        }
        if self.provider_oauth_preparing
            && self.provider_oauth_preparing_provider.as_deref() == Some(provider)
        {
            return;
        }

        self.provider_oauth_prepare_cancel
            .store(true, Ordering::Release);
        let generation = next_request_generation(&mut self.provider_oauth_prepare_generation);
        let cancel = Arc::new(AtomicBool::new(false));
        self.provider_oauth_prepare_cancel = cancel.clone();
        let cwd = self.router_root.clone();
        let config = self.config.clone();
        let provider = provider.to_owned();
        let event_provider = provider.clone();
        let tx = self.event_tx.clone();
        self.provider_oauth_preparing = true;
        self.provider_oauth_preparing_provider = Some(provider.clone());
        self.provider_oauth_prepared_provider = None;
        self.provider_oauth_prepare_error.clear();
        std::thread::spawn(move || {
            let mut final_error = "ROUTER_OAUTH_PREPARE_PROCESS stage=unknown".to_owned();
            // First-run preparation on a new machine may serialize behind a
            // cold PostgreSQL initdb / service boot, so retry patiently with a
            // stepped backoff before surfacing an error to the wizard.
            const PREPARE_RETRY_DELAYS_SECS: [u64; 3] = [2, 5, 10];
            for attempt in 0..=PREPARE_RETRY_DELAYS_SECS.len() {
                match logic::oauth::prepare(&cwd, &config, &provider, &cancel) {
                    Ok(()) => {
                        tx.send(AppEvent::ProviderOAuthPrepared {
                            provider: event_provider,
                            generation,
                        })
                        .ok();
                        return;
                    }
                    Err(error) => final_error = oauth_prepare_error_from_native(&error),
                }
                if let Some(delay) = PREPARE_RETRY_DELAYS_SECS.get(attempt) {
                    if oauth_prepare_error_is_retryable(&final_error) {
                        std::thread::sleep(std::time::Duration::from_secs(*delay));
                        continue;
                    }
                }
                break;
            }
            tx.send(AppEvent::ProviderOAuthPrepareError {
                provider: event_provider,
                generation,
                error: final_error,
            })
            .ok();
        });
    }

    fn cancel_provider_oauth_preparation(&mut self, clear_prepared: bool) {
        self.provider_oauth_prepare_cancel
            .store(true, Ordering::Release);
        next_request_generation(&mut self.provider_oauth_prepare_generation);
        self.provider_oauth_prepare_cancel = Arc::new(AtomicBool::new(false));
        self.provider_oauth_preparing = false;
        self.provider_oauth_preparing_provider = None;
        self.provider_oauth_prepare_error.clear();
        if clear_prepared {
            self.provider_oauth_prepared_provider = None;
        }
    }

    fn continue_provider_oauth_after_terms(&mut self, provider: String) {
        if !self.provider_oauth_preparing
            && self.provider_oauth_prepared_provider.as_deref() == Some(provider.as_str())
        {
            self.pending_oauth_provider = None;
            self.terms_open = false;
            self.launch_provider_oauth(&provider);
            return;
        }

        // Terms are already accepted. Keep waiting for background prepare without
        // reopening the dialog or cancelling an in-flight first start.
        self.pending_oauth_provider = Some(provider.clone());
        self.terms_open = false;
        if !self.provider_oauth_preparing {
            self.prewarm_provider_oauth(&provider);
        }
        self.status_text = if self.ui_language == "zh" {
            "条例已确认，正在完成安全登录环境准备…".to_owned()
        } else {
            "Terms accepted. Finishing secure sign-in preparation…".to_owned()
        };
    }

    fn launch_provider_oauth(&mut self, provider: &str) {
        let cwd = self.router_root.clone();
        let config = self.config.clone();
        let provider = provider.to_owned();
        let tx = self.event_tx.clone();
        let cancel = self.provider_oauth_cancel.clone();
        cancel.store(false, Ordering::Relaxed);
        self.provider_oauth_running = true;
        self.oauth_in_flight_provider = Some(provider.clone());
        self.oauth_success_pending = false;
        self.oauth_known_account_ids = self
            .oauth_accounts
            .iter()
            .filter(|account| account.bound_to_router)
            .map(|account| account.id)
            .collect();
        self.status_text = if self.ui_language == "zh" {
            format!("正在打开 {provider} 官方授权页；请按新窗口提示完成登录")
        } else {
            format!("Opening the official {provider} authorization page. Follow the new window")
        };
        std::thread::spawn(move || {
            let prompt_tx = tx.clone();
            let prompt_cancel = cancel.clone();
            let result = logic::oauth::run(&cwd, &config, &provider, true, &cancel, move |prompt| {
                let (response_tx, response_rx) = channel();
                prompt_tx
                    .send(AppEvent::ProviderOAuthPrompt {
                        prompt,
                        response: response_tx,
                    })
                    .map_err(|_| anyhow::anyhow!("class=cancelled"))?;
                loop {
                    if prompt_cancel.load(Ordering::Acquire) {
                        anyhow::bail!("ROUTER_OAUTH_CANCELLED: class=cancelled");
                    }
                    match response_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                        Ok(response) => return Ok(response),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            anyhow::bail!("class=cancelled")
                        }
                    }
                }
            });
            match result {
                Ok(_) => {
                    tx.send(AppEvent::ProviderOAuthFinished).ok();
                }
                Err(error) => {
                    tx.send(AppEvent::ProviderOAuthError(format!(
                        "{provider} OAuth process did not complete: {error}"
                    )))
                    .ok();
                }
            }
        });
    }
}

impl Drop for CodexRouterApp {
    fn drop(&mut self) {
        self.apply_cancel.store(true, Ordering::Release);
        self.runtime_log_stop.store(true, Ordering::Relaxed);
        self.health_recovery_cancel.store(true, Ordering::Relaxed);
        self.provider_oauth_prepare_cancel
            .store(true, Ordering::Relaxed);
        self.provider_oauth_cancel.store(true, Ordering::Relaxed);
    }
}

#[cfg(any())]
impl eframe::App for CodexRouterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.load_logo_texture(ctx);
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::Log(message) => self.log(message),
                AppEvent::Complete => {
                    self.applying = false;
                    self.configured = true;
                    self.status_text = "配置完成：模型渠道、Codex 和所选集成均已生效".into();
                    self.log("配置完成");
                }
                AppEvent::Error(error) => {
                    self.applying = false;
                    self.status_text = format!("配置失败：{error}");
                    self.log(format!("错误: {error}"));
                }
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Welcome => self.show_welcome(ui),
            Page::Project => self.show_project(ui),
            Page::Auth => self.show_auth(ui),
            Page::Model => self.show_model(ui),
            Page::Proxy => self.show_proxy(ui),
            Page::Finish => self.show_finish(ui),
            Page::Dashboard => self.show_dashboard(ui),
        });
        if self.applying {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}

#[cfg(any())]
impl CodexRouterApp {
    fn header(&self, ui: &mut egui::Ui, title: &str) {
        ui.horizontal(|ui| {
            if let Some(texture) = &self.logo_texture {
                ui.image((texture.id(), egui::vec2(56.0, 56.0)));
            }
            ui.heading(title);
        });
        ui.separator();
        ui.add_space(8.0);
    }

    fn show_welcome(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "欢迎使用 Codex-Router");
        ui.label("本向导会配置单用户、多模型、多 API 渠道与自动兜底。所有操作都在本程序中完成。");
        ui.add_space(12.0);
        ui.label("第三方 API Key 和代理密码只进入当前 Windows 用户的凭据管理器，不会写入项目 JSON、日志或 EXE。");
        ui.label(
            "Sub2API、PostgreSQL 与 Redis 随便携包提供，无需单独安装 Python、Node.js 或 Rust。",
        );
        ui.add_space(28.0);
        if ui.button("开始配置").clicked() {
            self.page = Page::Project;
        }
    }

    fn show_project(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "1 / 5  确认项目目录");
        ui.label("通常无需修改：把 EXE 放在 Codex-Router 根目录即可自动识别。");
        ui.horizontal(|ui| {
            ui.label("项目目录:");
            let mut value = self.router_root.to_string_lossy().to_string();
            if ui.text_edit_singleline(&mut value).changed() {
                self.router_root = PathBuf::from(value);
            }
            if ui.button("浏览...").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.router_root = path;
                }
            }
        });
        let valid = config::RouterConfig::is_router_root(&self.router_root);
        if valid {
            ui.colored_label(egui::Color32::from_rgb(22, 163, 74), "已识别完整运行环境");
        } else {
            ui.colored_label(
                egui::Color32::from_rgb(220, 38, 38),
                format!(
                    "目录中缺少 app/{} 或 app/{}",
                    codex_router_lib::backend::config_compiler::host_executable_file_name(),
                    codex_router_lib::backend::config_compiler::cli_executable_file_name(),
                ),
            );
        }
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui.button("上一步").clicked() {
                self.page = Page::Welcome;
            }
            if ui.add_enabled(valid, egui::Button::new("下一步")).clicked() {
                self.page = Page::Auth;
            }
        });
    }

    fn show_auth(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "2 / 5  选择上游登录方式");
        ui.label("Codex 始终通过本机路由访问；这里决定是否额外接入 ChatGPT OAuth 渠道。");
        ui.radio_value(
            &mut self.config.auth_mode,
            "chatgpt_oauth".into(),
            "接入 ChatGPT 账号 OAuth，并允许同名第三方模型兜底",
        );
        ui.radio_value(
            &mut self.config.auth_mode,
            "local_api_key".into(),
            "只使用下面配置的第三方 API 渠道",
        );
        ui.checkbox(
            &mut self.config.oauth_fallback.enabled,
            "官方 OAuth 不可用时自动回退到第三方同名模型",
        );
        if self.config.oauth_fallback.enabled {
            ui.horizontal(|ui| {
                ui.label("OAuth 优先级");
                ui.add(
                    egui::DragValue::new(&mut self.config.oauth_fallback.official_priority)
                        .range(1..=999),
                );
                ui.label("第三方兜底优先级");
                ui.add(
                    egui::DragValue::new(&mut self.config.oauth_fallback.fallback_priority)
                        .range(1..=999),
                );
            });
        }
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui.button("上一步").clicked() {
                self.page = Page::Project;
            }
            if ui.button("下一步").clicked() {
                self.temp_model = ModelConfig::default();
                self.temp_model.priority = logic::next_api_channel_priority(&self.config);
                self.editing_model = None;
                self.model_from_wizard = true;
                self.page = Page::Model;
            }
        });
    }

    fn show_model(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            if self.model_from_wizard {
                "3 / 5  配置第一个模型"
            } else {
                "模型渠道设置"
            },
        );
        egui::Grid::new("model-form")
            .num_columns(2)
            .spacing([16.0, 10.0])
            .show(ui, |ui| {
                ui.label("模型名称 *");
                ui.text_edit_singleline(&mut self.temp_model.model);
                ui.end_row();
                ui.label("显示别名");
                ui.text_edit_singleline(&mut self.temp_model.alias);
                ui.end_row();
                ui.label("Base URL *");
                ui.text_edit_singleline(&mut self.temp_model.base_url);
                ui.end_row();
                ui.label("API Key");
                ui.add(
                    egui::TextEdit::singleline(&mut self.temp_model.api_key)
                        .password(true)
                        .hint_text(if self.temp_model.credential_name.is_empty() {
                            "输入 API Key"
                        } else {
                            "留空则保留已安全保存的 Key"
                        }),
                );
                ui.end_row();
                ui.label("优先级");
                ui.add(egui::DragValue::new(&mut self.temp_model.priority).range(1..=999));
                ui.end_row();
                ui.label("权重");
                ui.add(egui::DragValue::new(&mut self.temp_model.weight).range(1..=100));
                ui.end_row();
                ui.label("多模态");
                egui::ComboBox::from_id_salt("multimodal")
                    .selected_text(match self.temp_model.multimodal.as_str() {
                        "true" => "手动：支持",
                        "false" => "手动：不支持",
                        _ => "自动判断",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.temp_model.multimodal,
                            "auto".into(),
                            "自动判断",
                        );
                        ui.selectable_value(
                            &mut self.temp_model.multimodal,
                            "true".into(),
                            "支持图片/多模态",
                        );
                        ui.selectable_value(
                            &mut self.temp_model.multimodal,
                            "false".into(),
                            "不支持图片/多模态",
                        );
                    });
                ui.end_row();
                ui.label("其它参数 JSON");
                ui.text_edit_multiline(&mut self.temp_model.extra);
                ui.end_row();
            });
        ui.label(format!(
            "当前判定：{}",
            if logic::resolve_multimodal(&self.temp_model) {
                "支持多模态（图片将透传）"
            } else {
                "纯文本模型"
            }
        ));
        let json_valid = serde_json::from_str::<serde_json::Value>(&self.temp_model.extra)
            .map(|v| v.is_object())
            .unwrap_or(false);
        let valid = !self.temp_model.model.trim().is_empty()
            && !self.temp_model.base_url.trim().is_empty()
            && json_valid
            && (!self.temp_model.api_key.trim().is_empty()
                || !self.temp_model.credential_name.is_empty());
        if !json_valid {
            ui.colored_label(egui::Color32::RED, "其它参数必须是 JSON 对象，例如 {}");
        }
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui
                .button(if self.model_from_wizard {
                    "上一步"
                } else {
                    "取消"
                })
                .clicked()
            {
                self.page = if self.model_from_wizard {
                    Page::Auth
                } else {
                    Page::Dashboard
                };
            }
            if ui
                .add_enabled(
                    valid,
                    egui::Button::new(if self.model_from_wizard {
                        "下一步"
                    } else {
                        "保存模型"
                    }),
                )
                .clicked()
            {
                if self.model_from_wizard {
                    self.config.models = vec![self.temp_model.clone()];
                    self.proxy_from_wizard = true;
                    self.page = Page::Proxy;
                } else {
                    match self.editing_model {
                        Some(index) => self.config.models[index] = self.temp_model.clone(),
                        None => self.config.models.push(self.temp_model.clone()),
                    }
                    self.page = Page::Dashboard;
                }
            }
        });
    }

    fn show_proxy(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            if self.proxy_from_wizard {
                "4 / 5  网络代理"
            } else {
                "网络代理"
            },
        );
        ui.checkbox(
            &mut self.config.proxy.enabled,
            "让 Sub2API 的上游请求使用代理（兼容 Clash / V2Ray / SSR）",
        );
        if self.config.proxy.enabled {
            egui::Grid::new("proxy-form")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    ui.label("协议");
                    egui::ComboBox::from_id_salt("proxy-type")
                        .selected_text(&self.config.proxy.proxy_type)
                        .show_ui(ui, |ui| {
                            for value in ["http", "https", "socks5", "socks5h"] {
                                ui.selectable_value(
                                    &mut self.config.proxy.proxy_type,
                                    value.into(),
                                    value,
                                );
                            }
                        });
                    ui.end_row();
                    ui.label("地址");
                    ui.text_edit_singleline(&mut self.config.proxy.host);
                    ui.end_row();
                    ui.label("端口");
                    ui.text_edit_singleline(&mut self.config.proxy.port);
                    ui.end_row();
                    ui.label("用户名（可选）");
                    ui.text_edit_singleline(&mut self.config.proxy.username);
                    ui.end_row();
                    ui.label("密码（可选）");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.config.proxy.password)
                            .password(true)
                            .hint_text("留空则保留已保存密码"),
                    );
                    ui.end_row();
                });
        }
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            if ui
                .button(if self.proxy_from_wizard {
                    "上一步"
                } else {
                    "取消"
                })
                .clicked()
            {
                self.page = if self.proxy_from_wizard {
                    Page::Model
                } else {
                    Page::Dashboard
                };
            }
            if ui
                .button(if self.proxy_from_wizard {
                    "下一步"
                } else {
                    "保存"
                })
                .clicked()
            {
                self.page = if self.proxy_from_wizard {
                    Page::Finish
                } else {
                    Page::Dashboard
                };
            }
        });
    }

    fn show_finish(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "5 / 5  一键完成配置");
        ui.label("将自动初始化本地运行环境、配置真实 Sub2API 渠道并写入 Codex。网络代理为可选项。");
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.config.accept_compliance, "我已阅读、理解并同意 Sub2API 部署与运营合规承诺");
            if ui.link("查看中文承诺原文").clicked() {
                let _ = std::process::Command::new("cmd.exe").args(["/C", "start", "", "https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.zh.md"]).spawn();
            }
        });
        if !self.config.accept_compliance {
            ui.colored_label(
                egui::Color32::from_rgb(180, 83, 9),
                "首次使用必须由你本人确认合规承诺；程序不会替你静默接受。 ",
            );
        }
        ui.label(&self.status_text);
        if self.applying {
            ui.spinner();
        } else if ui
            .add_enabled(
                self.config.accept_compliance,
                egui::Button::new("一键完成配置"),
            )
            .clicked()
        {
            self.apply_all();
        }
        ui.add_space(14.0);
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                ui.monospace(&self.logs);
            });
        if self.configured && ui.button("进入控制台").clicked() {
            self.page = Page::Dashboard;
        }
    }

    fn show_dashboard(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "Codex-Router 控制台");
        ui.label(format!("项目目录: {}", self.router_root.display()));
        ui.horizontal(|ui| {
            if ui.button("启动路由").clicked() {
                self.run_script_new_console("Start-Router.ps1");
                self.log("正在启动路由...");
            }
            if ui.button("停止路由").clicked() {
                self.stop_router();
                self.log("正在停止路由...");
            }
            if self.config.auth_mode == "chatgpt_oauth"
                && ui.button("登录 / 更新 ChatGPT OAuth").clicked()
            {
                self.run_script_new_console("Start-ChatGPTOAuth.ps1");
            }
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.applying, egui::Button::new("保存并应用全部配置"))
                .clicked()
            {
                self.apply_all();
            }
            if ui.button("网络代理设置").clicked() {
                self.proxy_from_wizard = false;
                self.page = Page::Proxy;
            }
            if ui.button("重新运行首次向导").clicked() {
                self.page = Page::Welcome;
            }
        });
        if self.applying {
            ui.spinner();
        }
        if !self.status_text.is_empty() {
            ui.label(&self.status_text);
        }
        ui.separator();
        ui.heading("模型渠道");
        let mut edit = None;
        let mut delete = None;
        for (index, model) in self.config.models.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "{}  |  {}  |  优先级 {}  |  {}",
                    model.model,
                    model.base_url,
                    model.priority,
                    if logic::resolve_multimodal(model) {
                        "多模态"
                    } else {
                        "文本"
                    }
                ));
                if ui.button("编辑").clicked() {
                    edit = Some(index);
                }
                if ui.button("删除").clicked() {
                    delete = Some(index);
                }
            });
        }
        if let Some(index) = delete {
            self.config.models.remove(index);
        }
        if let Some(index) = edit {
            self.temp_model = self.config.models[index].clone();
            self.editing_model = Some(index);
            self.model_from_wizard = false;
            self.page = Page::Model;
        }
        if ui.button("+ 添加模型").clicked() {
            self.temp_model = ModelConfig::default();
            self.temp_model.priority = logic::next_api_channel_priority(&self.config);
            self.editing_model = None;
            self.model_from_wizard = false;
            self.page = Page::Model;
        }
        ui.separator();
        ui.heading("运行日志");
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                ui.monospace(&self.logs);
            });
    }
}

fn window_icon() -> egui::IconData {
    let (rgba, width, height) = decode_icon().expect("embedded logo is invalid");
    egui::IconData {
        rgba,
        width,
        height,
    }
}

#[cfg(all(test, windows))]
fn run_hidden_powershell_output(
    router_root: &Path,
    script_name: &str,
    arguments: &[&str],
    timeout: std::time::Duration,
    cancel: &AtomicBool,
) -> anyhow::Result<std::process::Output> {
    fn read_bounded_output(path: &Path) -> anyhow::Result<Vec<u8>> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("could not read helper output {}", path.display()))?;
        let length = file.metadata()?.len();
        if length > EXIT_HELPER_OUTPUT_LIMIT as u64 {
            file.seek(SeekFrom::Start(
                length.saturating_sub(EXIT_HELPER_OUTPUT_LIMIT as u64),
            ))?;
        }
        let mut output = Vec::with_capacity(length.min(EXIT_HELPER_OUTPUT_LIMIT as u64) as usize);
        file.read_to_end(&mut output)?;
        Ok(output)
    }

    let script = router_root.join("scripts").join(script_name);
    let output_root = user_data::data_root(router_root).join("process-output");
    std::fs::create_dir_all(&output_root)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let output_prefix = format!("helper-{}-{nonce}", std::process::id());
    let stdout_path = output_root.join(format!("{output_prefix}.stdout"));
    let stderr_path = output_root.join(format!("{output_prefix}.stderr"));

    let result = (|| -> anyhow::Result<std::process::Output> {
        let stdout_file = std::fs::File::create(&stdout_path)?;
        let stderr_file = std::fs::File::create(&stderr_path)?;
        let mut child = std::process::Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .args(arguments)
            .current_dir(router_root)
            .stdin(Stdio::null())
            // Long-lived Router services can inherit these handles. Files let
            // the helper finish without waiting for service-owned pipe EOF.
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .with_context(|| format!("could not start {script_name}"))?;

        let started = std::time::Instant::now();
        let status = loop {
            if cancel.load(Ordering::Relaxed) {
                terminate_child_process_tree(&mut child);
                anyhow::bail!("{script_name} was cancelled because Codex-Router is exiting");
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Ok(None) => {
                    terminate_child_process_tree(&mut child);
                    anyhow::bail!("{script_name} exceeded its time budget");
                }
                Err(error) => {
                    terminate_child_process_tree(&mut child);
                    return Err(error).with_context(|| format!("could not monitor {script_name}"));
                }
            }
        };
        Ok(std::process::Output {
            status,
            stdout: read_bounded_output(&stdout_path)?,
            stderr: read_bounded_output(&stderr_path)?,
        })
    })();

    for path in [&stdout_path, &stderr_path] {
        if std::fs::remove_file(path).is_err() {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path);
            let _ = std::fs::remove_file(path);
        }
    }
    result
}

#[cfg(windows)]
struct SingleInstanceGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn another_router_gui_running() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    unsafe {
        let current_pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        let mut has_entry = Process32FirstW(snapshot, &mut entry) != 0;
        while has_entry {
            let end = entry
                .szExeFile
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(entry.szExeFile.len());
            let executable = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if entry.th32ProcessID != current_pid
                && executable.eq_ignore_ascii_case("Codex-Router.exe")
            {
                found = true;
                break;
            }
            has_entry = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        found
    }
}

#[cfg(windows)]
fn codex_setup_running() -> bool {
    process_name_running(&["codex-windows-sandbox-setup.exe"])
}

#[cfg(not(windows))]
fn codex_setup_running() -> bool {
    false
}

fn quota_recovery_confirmed(
    previous: Option<&UsageSnapshot>,
    current: &UsageSnapshot,
    account_id: i64,
) -> bool {
    let Some(current_account) = current
        .subscriptions
        .iter()
        .find(|account| account.id == account_id)
    else {
        return false;
    };
    let Some(previous_account) = previous.and_then(|snapshot| {
        snapshot
            .subscriptions
            .iter()
            .find(|account| account.id == account_id)
    }) else {
        return false;
    };
    previous_account.health == "quotaExhausted"
        && current_account.health != "quotaExhausted"
        && quota_windows_recovered(previous_account, current_account)
}

#[cfg(windows)]
fn process_name_running(names: &[&str]) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            // Failing closed prevents a process-enumeration error from racing
            // the Windows setup helper.
            return true;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        let mut has_entry = Process32FirstW(snapshot, &mut entry) != 0;
        while has_entry {
            let end = entry
                .szExeFile
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(entry.szExeFile.len());
            let executable = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if names
                .iter()
                .any(|name| executable.eq_ignore_ascii_case(name))
            {
                found = true;
                break;
            }
            has_entry = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        found
    }
}

#[cfg(not(windows))]
fn show_already_running_message() {
    let _ = rfd::MessageDialog::new()
        .set_title("Codex-Router")
        .set_description(
            "Codex-Router 已经开启，请勿重复开启。\n\nCodex-Router is already running. Do not start another instance.",
        )
        .set_level(rfd::MessageLevel::Info)
        .show();
}

#[cfg(windows)]
fn show_already_running_message() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

    let title: Vec<u16> = "Codex-Router"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let message: Vec<u16> = "Codex-Router 已经开启，请勿重复开启。\n\nCodex-Router is already running. Do not start another instance."
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[cfg(not(windows))]
struct SingleInstanceGuard {
    _file: std::fs::File,
}

#[cfg(not(windows))]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    match lock_single_instance_file() {
        Ok(Some(file)) => Some(SingleInstanceGuard { _file: file }),
        _ => {
            show_already_running_message();
            None
        }
    }
}

/// Non-blocking exclusive lock without any UI: Ok(Some) = acquired,
/// Ok(None) = held elsewhere, Err = lock file unusable. Separated so tests
/// can exercise the semantics without popping a dialog.
#[cfg(not(windows))]
fn lock_single_instance_file() -> anyhow::Result<Option<std::fs::File>> {
    use std::os::unix::io::AsRawFd;

    // One GUI per user login, independent of the portable root (mirrors the
    // Windows global mutex). flock is kernel-released on process death, so a
    // crash can never leave a stale lock behind.
    let dir = dirs::data_local_dir()
        .map(|dir| dir.join("Codex-Router"))
        .context("could not locate the local application data directory")?;
    std::fs::create_dir_all(&dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.join("gui-single-instance.lock"))?;
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if !locked {
        return Ok(None);
    }
    Ok(Some(file))
}

#[cfg(windows)]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let mutex_name: Vec<u16> = "Local\\CodexRouterSingleInstanceV1"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mutex = CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr());
        if mutex.is_null() {
            return None;
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            windows_sys::Win32::Foundation::CloseHandle(mutex);
            show_already_running_message();
            return None;
        }
        if another_router_gui_running() {
            windows_sys::Win32::Foundation::CloseHandle(mutex);
            show_already_running_message();
            return None;
        }
        Some(SingleInstanceGuard(mutex))
    }
}

fn write_cli_result(value: &str) -> anyhow::Result<()> {
    if let Some(path) = std::env::var_os("CODEX_ROUTER_CLI_OUTPUT") {
        return config::atomic_write(Path::new(&path), value.as_bytes())
            .context("failed to write native CLI result");
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.as_bytes())
        .context("failed to write native CLI result")?;
    stdout
        .write_all(b"\n")
        .context("failed to finish native CLI result")?;
    stdout.flush().context("failed to flush native CLI result")
}

fn try_cli_mode() -> Option<anyhow::Result<()>> {
    let args = std::env::args().collect::<Vec<_>>();
    let write_codex_config = args
        .iter()
        .any(|argument| argument == "--write-codex-config");
    let routing_priorities = args
        .iter()
        .any(|argument| argument == "--routing-priorities");
    let effective_api_priority = args
        .iter()
        .any(|argument| argument == "--effective-api-priority");
    let ensure_router_services = args
        .iter()
        .any(|argument| argument == "--ensure-router-services");
    let stop_router_services = args
        .iter()
        .any(|argument| argument == "--stop-router-services");
    let router_status = args.iter().any(|argument| argument == "--router-status");
    let run_shadow_cutover = args
        .iter()
        .any(|argument| argument.starts_with("--run-shadow-cutover="));
    let refresh_codex_binding = args
        .iter()
        .any(|argument| argument == "--refresh-codex-binding");
    let prepare_provider_oauth = args
        .iter()
        .any(|argument| argument == "--prepare-provider-oauth");
    let apply_staged_update = args
        .iter()
        .any(|argument| argument == "--apply-staged-update");
    let import_legacy_export = args
        .iter()
        .any(|argument| argument.starts_with("--import-legacy-export="));
    let install_portable = args.iter().any(|argument| argument == "--install-portable");
    if !write_codex_config
        && !routing_priorities
        && !effective_api_priority
        && !ensure_router_services
        && !stop_router_services
        && !router_status
        && !run_shadow_cutover
        && !refresh_codex_binding
        && !prepare_provider_oauth
        && !apply_staged_update
        && !import_legacy_export
        && !install_portable
    {
        return None;
    }

    Some((|| -> anyhow::Result<()> {
        let argument_value = |prefix: &str| {
            args.iter()
                .find_map(|argument| argument.strip_prefix(prefix).map(str::to_owned))
        };
        let parse_i32 = |prefix: &str, default: Option<i32>| -> anyhow::Result<i32> {
            match argument_value(prefix) {
                Some(value) => value
                    .parse::<i32>()
                    .with_context(|| format!("invalid numeric argument {prefix}")),
                None => default.with_context(|| format!("missing argument {prefix}")),
            }
        };
        let parse_bool = |prefix: &str, default: bool| {
            argument_value(prefix)
                .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                .unwrap_or(default)
        };

        if apply_staged_update {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .context("--router-root is required for staged update application")?;
            let staged_root = argument_value("--staged-root=")
                .map(PathBuf::from)
                .context("--staged-root is required for staged update application")?;
            let parent_pid = argument_value("--parent-pid=")
                .context("--parent-pid is required for staged update application")?
                .parse::<u32>()
                .context("--parent-pid must be a valid process ID")?;
            updater::apply_staged_update(&router_root, &staged_root, parent_pid)?;
            write_cli_result("{\"status\":\"updated\"}")?;
            return Ok(());
        }

        if install_portable {
            let archive = argument_value("--install-package=")
                .map(PathBuf::from)
                .context("--install-package is required for portable installation")?;
            let version =
                argument_value("--install-version=").unwrap_or_else(|| APP_VERSION.to_owned());
            let install_root = argument_value("--install-root=").map(PathBuf::from);
            let result = updater::install_portable_archive(
                &archive,
                &version,
                install_root.as_deref(),
                args.iter().any(|argument| argument == "--no-shortcut"),
            )?;
            write_cli_result(&serde_json::to_string(&result)?)?;
            return Ok(());
        }

        if import_legacy_export {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .unwrap_or_else(RouterConfig::find_router_root);
            let export_path = argument_value("--import-legacy-export=")
                .map(PathBuf::from)
                .context("--import-legacy-export requires a JSON export path")?;
            let store = codex_router_lib::state::StateStore::open(
                user_data::data_root(&router_root).join("router-state.sqlite3"),
            )?;
            let migration_secret = match codex_router_lib::credentials::read_text(
                "MigrationHmacSecret",
            )? {
                Some(secret) if !secret.trim().is_empty() => secret,
                _ => {
                    let secret = zeroize::Zeroizing::new(
                        format!("cr-migration-{}", uuid::Uuid::now_v7().simple()),
                    );
                    codex_router_lib::credentials::write_text(
                        "MigrationHmacSecret",
                        secret.as_str(),
                    )?;
                    secret
                }
            };
            let summary = codex_router_lib::state::legacy_migration::import_legacy_export_file(
                &store,
                &export_path,
                migration_secret.as_bytes(),
            )?;
            write_cli_result(&serde_json::to_string(&serde_json::json!({
                "status": "imported",
                "source": export_path.file_name().and_then(|name| name.to_str()).unwrap_or("export.json"),
                "groupsImported": summary.groups_imported,
                "groupsSkipped": summary.groups_skipped,
                "routesImported": summary.routes_imported,
                "routesSkipped": summary.routes_skipped,
                "proxiesImported": summary.proxies_imported,
                "proxiesSkipped": summary.proxies_skipped,
                "keysImported": summary.keys_imported,
                "keysSkipped": summary.keys_skipped,
                "accountsImported": summary.accounts_imported,
                "accountsSkipped": summary.accounts_skipped,
            }))?)?;
            return Ok(());
        }

        if run_shadow_cutover {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .unwrap_or_else(RouterConfig::find_router_root);
            let manifest = argument_value("--run-shadow-cutover=")
                .map(PathBuf::from)
                .context("--run-shadow-cutover requires a manifest path")?;
            let _lock = lifecycle::acquire_lifecycle_lock(
                &router_root,
                std::time::Duration::from_secs(10),
                "Shadow Cutover",
            )?;
            let journal = lifecycle_cutover::run_shadow_cutover(&router_root, &manifest)?;
            write_cli_result(&serde_json::to_string(&journal)?)?;
            return Ok(());
        }

        if refresh_codex_binding {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .unwrap_or_else(RouterConfig::find_router_root);
            let config = RouterConfig::load(&crate::user_data::config_path(&router_root))?;
            logic::write_model_catalog(&config, &router_root)?;
            let repaired = logic::codex_toml::repair_codex_router_binding(&config, &router_root)?;
            write_cli_result(
                &serde_json::json!({"catalog": "refreshed", "bindingRepaired": repaired})
                    .to_string(),
            )?;
            return Ok(());
        }

        if prepare_provider_oauth {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .unwrap_or_else(RouterConfig::find_router_root);
            crate::credentials::set_scope_from_root(&router_root);
            let provider = argument_value("--provider=").unwrap_or_else(|| "openai".to_owned());
            let mut config = RouterConfig::default();
            if let Some(host) = argument_value("--sub2api-host=") {
                config.deploy.sub2api_host = host;
            }
            let cancel = AtomicBool::new(false);
            logic::oauth::prepare(&router_root, &config, &provider, &cancel)?;
            write_cli_result(&serde_json::json!({"status": "ready", "code": "ok"}).to_string())?;
            return Ok(());
        }

        if ensure_router_services || stop_router_services || router_status {
            let router_root = argument_value("--router-root=")
                .map(PathBuf::from)
                .unwrap_or_else(RouterConfig::find_router_root);
            let lock_inherited = args
                .iter()
                .any(|argument| argument == "--lifecycle-lock-inherited");
            let status = if ensure_router_services {
                let cancel = AtomicBool::new(false);
                lifecycle::ensure_services(
                    &router_root,
                    args.iter().any(|argument| argument == "--repair-unhealthy"),
                    &cancel,
                    lock_inherited,
                )?
            } else if stop_router_services {
                let force = args.iter().any(|argument| argument == "--force");
                if let Some(host) = argument_value("--sub2api-host=") {
                    let mut config = RouterConfig::default();
                    config.deploy.sub2api_host = host;
                    lifecycle::stop_services_with_config(
                        &router_root,
                        &config,
                        force,
                        lock_inherited,
                    )?
                } else {
                    lifecycle::stop_services(&router_root, force, lock_inherited)?
                }
            } else {
                lifecycle::status_services(&router_root)?
            };
            write_cli_result(&serde_json::to_string(&status)?)?;
            return Ok(());
        }

        if routing_priorities {
            let fallback = config::OAuthFallback {
                enabled: parse_bool("--fallback-enabled=", false),
                prefer_oauth: parse_bool("--prefer-oauth=", true),
                official_priority: parse_i32("--official-priority=", Some(1))?,
                fallback_priority: parse_i32("--fallback-priority=", Some(100))?,
            };
            let priorities = logic::oauth_routing_priorities(Some(&fallback));
            write_cli_result(
                &serde_json::json!({
                    "enabled": priorities.enabled,
                    "preferOAuth": priorities.prefer_oauth,
                    "oauthPriority": priorities.oauth_priority,
                    "apiPriority": priorities.api_priority,
                })
                .to_string(),
            )?;
            return Ok(());
        }

        if effective_api_priority {
            let value = logic::effective_api_priority(
                parse_i32("--configured-priority=", None)?,
                parse_i32("--minimum-matching-priority=", None)?,
                parse_i32("--api-base-priority=", None)?,
                parse_i32("--oauth-priority=", None)?,
                parse_bool("--prefer-oauth=", true),
            );
            write_cli_result(&value.to_string())?;
            return Ok(());
        }

        let mut codex_home = None;
        let mut model = None;
        let mut catalog = None;
        let mut base_url = "http://127.0.0.1:18082".to_owned();
        let mut reasoning_effort = "medium".to_owned();
        let mut fast_mode = false;
        let mut require_openai_auth = DEFAULT_ROUTER_REQUIRES_OPENAI_AUTH;
        let mut display_openai_provider = DEFAULT_ROUTER_REQUIRES_OPENAI_AUTH;
        let mut permission_source_path = None;
        let mut read_local_api_key_from_stdin = false;
        let mut max_retries = crate::logic::responses_gateway::DEFAULT_RATE_LIMIT_RETRIES;

        for argument in &args {
            if let Some(value) = argument.strip_prefix("--codex-home=") {
                codex_home = Some(value.to_owned());
            } else if let Some(value) = argument.strip_prefix("--model=") {
                model = Some(value.to_owned());
            } else if let Some(value) = argument.strip_prefix("--catalog=") {
                catalog = Some(value.to_owned());
            } else if let Some(value) = argument.strip_prefix("--base-url=") {
                base_url = value.to_owned();
            } else if let Some(value) = argument.strip_prefix("--reasoning-effort=") {
                reasoning_effort = value.to_owned();
            } else if argument == "--fast-mode" {
                fast_mode = true;
            } else if argument == "--no-fast-mode" {
                fast_mode = false;
            } else if argument == "--require-openai-auth" {
                require_openai_auth = true;
            } else if argument == "--no-require-openai-auth" {
                require_openai_auth = false;
            } else if matches!(
                argument.as_str(),
                "--display-openai-provider" | "--force-chatgpt-login"
            ) {
                display_openai_provider = true;
            } else if matches!(
                argument.as_str(),
                "--display-router-provider" | "--no-force-chatgpt-login"
            ) {
                display_openai_provider = false;
            } else if let Some(value) = argument.strip_prefix("--permission-source-path=") {
                permission_source_path = Some(value.to_owned());
            } else if argument == "--local-api-key-stdin" {
                read_local_api_key_from_stdin = true;
            } else if let Some(value) = argument.strip_prefix("--max-retries=") {
                max_retries = value.parse().unwrap_or(max_retries);
            }
        }

        let codex_home = codex_home.context("--codex-home is required")?;
        let model = model.context("--model is required")?;
        let catalog = catalog.context("--catalog is required")?;
        let local_key = if read_local_api_key_from_stdin {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .context("failed to read the local Router key from stdin")?;
            let value = value.trim_end_matches(['\r', '\n']).to_owned();
            if value.is_empty() {
                anyhow::bail!("the local Router key provided through stdin is empty");
            }
            value
        } else {
            crate::logic::ensure_local_api_key().context("failed to read local Router key")?
        };
        let permission_source = if let Some(path) = permission_source_path {
            Some(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read permission source file {path}"))?,
            )
        } else {
            None
        };

        let (require_openai_auth, display_openai_provider) =
            crate::logic::codex_toml::legal_codex_provider_identity(
                require_openai_auth,
                display_openai_provider,
            );
        crate::logic::codex_toml::write_codex_router_config(
            Path::new(&codex_home),
            &model,
            Path::new(&catalog),
            &local_key,
            &base_url,
            &reasoning_effort,
            fast_mode,
            require_openai_auth,
            display_openai_provider,
            max_retries,
            permission_source.as_deref(),
        )?;
        // CLI write-codex-config used to skip the system layer. Desktop 26.818
        // still loads %ProgramData%\OpenAI\Codex\config.toml; leaving
        // requires_openai_auth=true there re-arms getAuthStatus refresh.
        // A missing admin ACL must not fail the user-layer write.
        let _ = crate::logic::codex_toml::write_codex_system_binding(
            Path::new(&catalog),
            &local_key,
            &base_url,
            require_openai_auth,
            display_openai_provider,
            max_retries,
        );
        Ok(())
    })())
}

struct InstallerWizardApp {
    archive_path: PathBuf,
    version: String,
    install_root: String,
    create_desktop_shortcut: bool,
    installing: bool,
    completed: bool,
    status: String,
    event_rx: Receiver<Result<updater::InstallResult, String>>,
}

impl InstallerWizardApp {
    fn new(archive_path: PathBuf, version: String) -> Self {
        let default_root = updater::default_install_root(&version)
            .unwrap_or_else(|_| PathBuf::from("CodexRouter"));
        let (_event_tx, event_rx) = channel();
        Self {
            archive_path,
            version,
            install_root: default_root.to_string_lossy().into_owned(),
            create_desktop_shortcut: true,
            installing: false,
            completed: false,
            status: String::new(),
            event_rx,
        }
    }

    fn begin_install(&mut self) {
        let root = self.install_root.trim();
        if root.is_empty() {
            self.status = "请选择安装位置。".to_owned();
            return;
        }
        let install_root = PathBuf::from(root);
        let archive = self.archive_path.clone();
        let version = self.version.clone();
        let create_shortcut = self.create_desktop_shortcut;
        let (event_tx, event_rx) = channel();
        self.event_rx = event_rx;
        self.installing = true;
        self.status = "正在安装，请稍候…".to_owned();
        std::thread::spawn(move || {
            let result = updater::install_portable_archive(
                &archive,
                &version,
                Some(&install_root),
                !create_shortcut,
            )
            .map_err(|error| format!("{error:#}"));
            let _ = event_tx.send(result);
        });
    }
}

impl eframe::App for InstallerWizardApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.installing && ctx.input(|input| input.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.status = "正在安装，请等待完成后再关闭。".to_owned();
        }
    }

    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        if let Ok(result) = self.event_rx.try_recv() {
            self.installing = false;
            match result {
                Ok(info) => {
                    self.completed = true;
                    self.status =
                        format!("安装完成：{}\n版本：{}", info.install_root, info.version);
                }
                Err(error) => {
                    self.status = format!("安装失败：{error}");
                }
            }
        }

        egui::CentralPanel::default().show(root_ui, |ui| {
            ui.add_space(14.0);
            ui.heading(format!("CodexRouter {} 安装向导", self.version));
            ui.separator();
            if self.completed {
                ui.heading("安装已完成");
                ui.label("CodexRouter 已安装到你选择的位置。桌面快捷方式已按你的选择处理。");
            } else {
                ui.label("欢迎使用 CodexRouter。请先选择安装位置，再确认安装。");
                ui.add_space(10.0);
                ui.label("安装位置");
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [ui.available_width() - 92.0, 28.0],
                        egui::TextEdit::singleline(&mut self.install_root),
                    );
                    if ui.button("浏览…").clicked() && !self.installing {
                        let current = PathBuf::from(self.install_root.trim());
                        let dialog = if current.is_dir() {
                            rfd::FileDialog::new().set_directory(current)
                        } else {
                            rfd::FileDialog::new()
                        };
                        if let Some(path) = dialog.pick_folder() {
                            self.install_root = path.to_string_lossy().into_owned();
                        }
                    }
                });
                ui.checkbox(
                    &mut self.create_desktop_shortcut,
                    "创建桌面快捷方式（同时加入开始菜单）",
                );
                ui.add_space(8.0);
                ui.label("安装不会覆盖你的个人配置和运行数据。");
            }
            if !self.status.is_empty() {
                ui.add_space(10.0);
                ui.label(&self.status);
            }
            ui.add_space(18.0);
            ui.separator();
            ui.horizontal(|ui| {
                if self.completed {
                    if ui.button("完成").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                } else {
                    if ui
                        .add_enabled(!self.installing, egui::Button::new("取消"))
                        .clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui
                        .add_enabled(!self.installing, egui::Button::new("确认安装"))
                        .clicked()
                    {
                        self.begin_install();
                    }
                    if self.installing {
                        ui.spinner();
                    }
                }
            });
        });
        if self.installing {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn installer_wizard_args() -> Option<(PathBuf, String)> {
    let args = std::env::args().collect::<Vec<_>>();
    if !args.iter().any(|argument| argument == "--installer-wizard") {
        return None;
    }
    let package = args.iter().find_map(|argument| {
        argument
            .strip_prefix("--install-package=")
            .map(PathBuf::from)
    })?;
    let version = args
        .iter()
        .find_map(|argument| {
            argument
                .strip_prefix("--install-version=")
                .map(str::to_owned)
        })
        .unwrap_or_else(|| APP_VERSION.to_owned());
    Some((package, version))
}

fn run_installer_wizard(archive_path: PathBuf, version: String) -> eframe::Result<()> {
    let title = format!("CodexRouter {version} 安装向导");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([680.0, 430.0])
            .with_min_inner_size([560.0, 360.0])
            .with_resizable(false)
            .with_icon(window_icon()),
        centered: true,
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            let _ = install_app_fonts(&cc.egui_ctx);
            Ok(Box::new(InstallerWizardApp::new(archive_path, version)))
        }),
    )
}

fn main() -> eframe::Result<()> {
    if let Some((archive_path, version)) = installer_wizard_args() {
        return run_installer_wizard(archive_path, version);
    }
    if let Some(result) = try_cli_mode() {
        if let Err(error) = result {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    updater::startup_housekeeping();

    let ui_audit = UiAuditOptions::from_args();
    let _single_instance = if ui_audit.is_none() {
        let Some(guard) = acquire_single_instance() else {
            return Ok(());
        };
        Some(guard)
    } else {
        None
    };
    let start_in_background =
        std::env::args_os().any(|argument| argument == "--background" || argument == "--watchdog");
    let compact = ui_audit.as_ref().is_some_and(|options| options.compact);
    let stored_window = UiPreferences::load(&user_data::preferences_path(
        &crate::config::RouterConfig::find_router_root(),
    ))
    .ok()
    .and_then(|preferences| {
        stored_window_size(preferences.window_width, preferences.window_height)
    });
    // Keep every size in logical points and leave pixels_per_point unset. With
    // the PerMonitorV2 manifest, winit forwards live scale-factor changes to
    // eframe/egui whenever the window moves between monitors.
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(initial_window_logical_size_from(compact, stored_window))
            .with_min_inner_size(MIN_WINDOW_LOGICAL_SIZE)
            .with_resizable(true)
            .with_clamp_size_to_monitor_size(true)
            .with_visible(!start_in_background)
            .with_icon(window_icon()),
        centered: true,
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(move |cc| {
            Ok(Box::new(CodexRouterApp::new(
                cc,
                start_in_background,
                ui_audit,
            )))
        }),
    )
}

#[cfg(test)]
mod main_tests {
    use std::io::{Read, Write};

    #[cfg(windows)]
    use super::{oauth_prepare_error_from_output, run_hidden_powershell_output};
    #[cfg(not(windows))]
    use super::lock_single_instance_file;

    use super::{
        advance_overwrite_countdown, append_bounded_log, auto_enable_first_oauth_model,
        auto_import_new_oauth_models, classify_router_health_error,
        clear_stale_oauth_account_errors, decode_icon,
        default_oauth_recovery_seconds, deploy_router_config, failover_account_id,
        fallback_transition_notification, fit_window_to_monitor, fit_window_to_work_area,
        should_clamp_window_to_monitor,
        initial_page_for_config, initial_window_logical_size, localized_deployment_line,
        localized_error_summary, next_background_usage_refresh, next_failed_oauth_recovery,
        next_request_generation, normalize_usage_account_messages, oauth_account_refresh_can_start,
        oauth_prepare_error_from_native, oauth_prepare_error_is_retryable,
        oauth_recovery_schedule_delay, profile_binding_ready, request_result_disposition,
        restore_apply_ui_fields,         restore_codex_and_stop_router_for_exit_with,
        restore_codex_for_exit, restored_window_size, retain_last_good_oauth_models,
        recover_single_profile_binding, router_mode_enabled_on_startup, runtime_probes_allowed,
        should_leave_tray_lightweight, stored_window_size,
        scheduled_oauth_recovery_can_start, scheduled_usage_refresh_is_due,
        window_size_is_usable,
        usage_error_for_display, user_data, AdminTaskActivity, ApplyUiRollback, IsolationKind,
        IsolationProfile, ModelConfig, OAuthAccountSummary, OAuthModelSummary, Page,
        RequestResultDisposition, RouterConfig, UsageAccount, UsageSnapshot, UsageWindow, APP_TITLE,
        APP_VERSION, COMPACT_WINDOW_LOGICAL_SIZE, DEFAULT_WINDOW_LOGICAL_SIZE, MAX_LOG_BYTES,
        MIN_WINDOW_LOGICAL_SIZE, RETAIN_LOG_BYTES, WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE,
        WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE,
    };

    fn api_validation_fixture(
        status: &str,
        body: &str,
        probe_statuses: &[&str],
    ) -> (RouterConfig, ModelConfig) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let probe_statuses = probe_statuses
            .iter()
            .map(|status| (*status).to_owned())
            .collect::<Vec<_>>();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /v1/models HTTP/1.1"));
            assert!(request.contains("authorization: Bearer fixture-api-key"));
            stream.write_all(response.as_bytes()).unwrap();
            for (index, status) in probe_statuses.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                if index == 0 {
                    assert!(request.starts_with("POST /v1/responses HTTP/1.1"));
                    // /responses 探测不能带输出预算，避免推理网关在极小预算下 5xx。
                    assert!(!request.contains("max_output_tokens"));
                } else {
                    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
                }
                assert!(request.contains("authorization: Bearer fixture-api-key"));
                let body = r#"{"status":"completed","output":[]}"#;
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let cfg = RouterConfig {
            proxy: crate::config::ProxyConfig {
                auto_detect: false,
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let model = ModelConfig {
            model: "DeepSeek-V4-Flash".to_owned(),
            base_url: format!("http://{address}/v1"),
            api_key: "fixture-api-key".to_owned(),
            ..Default::default()
        };
        (cfg, model)
    }

    #[test]
    fn api_model_validation_accepts_case_insensitive_catalog_match() {
        let (cfg, mut model) =
            api_validation_fixture(
                "200 OK",
                r#"{"data":[{"id":"deepseek-v4-flash"}]}"#,
                &["200 OK"],
            );
        assert_eq!(super::validate_api_model_connection(&cfg, &mut model), Ok(()));
    }

    #[test]
    fn api_model_validation_rejects_auth_and_missing_model() {
        let (cfg, mut model) =
            api_validation_fixture("401 Unauthorized", r#"{"error":"secret"}"#, &[]);
        assert_eq!(
            super::validate_api_model_connection(&cfg, &mut model),
            Err("unauthorized".to_owned())
        );
        let (cfg, mut model) =
            api_validation_fixture("200 OK", r#"{"data":[{"id":"another-model"}]}"#, &[]);
        assert_eq!(
            super::validate_api_model_connection(&cfg, &mut model),
            Err("model_missing:another-model".to_owned())
        );
        assert!(!super::api_model_validation_message("unauthorized", true).contains("secret"));

        let (cfg, mut model) = api_validation_fixture(
            "200 OK",
            r#"{"data":[{"id":"deepseek-v4-flash"}]}"#,
            &["500 Internal Server Error", "200 OK"],
        );
        assert_eq!(
            super::validate_api_model_connection(&cfg, &mut model),
            Ok(())
        );
        let extra: serde_json::Value = serde_json::from_str(&model.extra).unwrap();
        assert_eq!(extra["openai_responses_mode"], "force_chat_completions");
    }

    #[test]
    fn api_model_validation_prefers_responses_and_persists_protocol() {
        // 只支持 /responses 的模型（如 opencode Go 的 muse-spark）：第一次探测就通，
        // 直接按 responses 保存，不再回落到 /chat/completions。
        let (cfg, mut model) = api_validation_fixture(
            "200 OK",
            r#"{"data":[{"id":"muse-spark-1.3-contributor"}]}"#,
            &["200 OK"],
        );
        model.model = "muse-spark-1.3-contributor".to_owned();
        assert_eq!(super::validate_api_model_connection(&cfg, &mut model), Ok(()));
        let extra: serde_json::Value = serde_json::from_str(&model.extra).unwrap();
        assert_eq!(extra["openai_responses_mode"], "force_responses");
        assert_eq!(extra["codex_router_upstream_protocol"], "responses");
    }

    #[test]
    fn api_probe_fallback_only_for_missing_or_upstream_errors() {
        assert!(super::api_probe_should_try_alternative("probe_not_found"));
        assert!(super::api_probe_should_try_alternative("probe_upstream"));
        assert!(super::api_probe_should_try_alternative("probe_http"));
        for code in [
            "unauthorized",
            "forbidden",
            "rate_limited",
            "timeout",
            "network",
            "request",
            "upstream",
            "http",
            "invalid_response",
            "credential_missing",
            "proxy_config",
        ] {
            assert!(!super::api_probe_should_try_alternative(code), "{code}");
        }
    }

    #[test]
    fn api_model_validation_lists_all_ids_when_expected_model_is_missing() {
        assert_eq!(
            super::listed_api_model_ids(&serde_json::json!({
                "data": [
                    {"id": "gpt-5.6"},
                    {"id": "gpt-5.4"},
                    {"name": "deepseek-v4-pro"}
                ]
            })),
            vec![
                "gpt-5.6".to_owned(),
                "gpt-5.4".to_owned(),
                "deepseek-v4-pro".to_owned()
            ]
        );
        assert_eq!(
            crate::logic::canonical_route_model_id("gpt-5.6"),
            crate::logic::canonical_route_model_id("gpt-5.6-sol")
        );

        let (cfg, mut model) = api_validation_fixture(
            "200 OK",
            r#"{"data":[{"id":"gpt-4.1"},{"id":"gpt-5.4"}]}"#,
            &[],
        );
        model.model = "gpt-5.6-sol".to_owned();
        let error = super::validate_api_model_connection(&cfg, &mut model).unwrap_err();
        assert!(error.starts_with("model_missing:"), "{error}");
        assert!(error.contains("gpt-4.1"));
        assert!(error.contains("gpt-5.4"));
        let (_code, listed) = super::split_model_missing_code(&error);
        assert_eq!(listed, vec!["gpt-4.1".to_owned(), "gpt-5.4".to_owned()]);
    }

    #[test]
    fn first_oauth_account_enables_exactly_one_model_only_for_empty_configs() {
        let account = OAuthAccountSummary {
            id: 7,
            name: "Subscription".to_owned(),
            platform: "openai".to_owned(),
            status: "active".to_owned(),
            email: String::new(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: vec![
                OAuthModelSummary {
                    id: "gpt-5.6".to_owned(),
                    display_name: "ChatGPT 5.6".to_owned(),
                },
                OAuthModelSummary {
                    id: "gpt-next".to_owned(),
                    display_name: "Next".to_owned(),
                },
            ],
            models_error: String::new(),
        };
        let mut config = RouterConfig::default();
        assert_eq!(
            auto_enable_first_oauth_model(&mut config, std::slice::from_ref(&account), "chatgpt"),
            Some("ChatGPT 5.6".to_owned())
        );
        assert_eq!(config.models.len(), 1);
        assert_eq!(config.models[0].model, "gpt-5.6-sol");
        assert_eq!(config.default_model, "gpt-5.6-sol");
        assert_eq!(config.oauth_account_ids, Some(vec![7]));

        assert_eq!(
            auto_enable_first_oauth_model(&mut config, &[account], "openai"),
            None
        );
        assert_eq!(config.models.len(), 1);
    }

    #[test]
    fn later_oauth_account_imports_its_default_model() {
        let first = OAuthAccountSummary {
            id: 11,
            name: "Grok one".to_owned(),
            platform: "grok".to_owned(),
            status: "active".to_owned(),
            email: String::new(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: vec![OAuthModelSummary {
                id: "grok-4.5".to_owned(),
                display_name: "Grok 4.5".to_owned(),
            }],
            models_error: String::new(),
        };
        let third = OAuthAccountSummary {
            id: 24,
            name: "Grok three".to_owned(),
            platform: "xai".to_owned(),
            status: "active".to_owned(),
            email: String::new(),
            plan: String::new(),
            priority: 3,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: vec![OAuthModelSummary {
                id: "grok-4.5".to_owned(),
                display_name: "Grok 4.5 Team".to_owned(),
            }],
            models_error: String::new(),
        };
        let mut config = RouterConfig::default();
        assert_eq!(
            auto_enable_first_oauth_model(&mut config, std::slice::from_ref(&first), "grok"),
            Some("Grok 4.5".to_owned())
        );
        config.models.push(ModelConfig {
            model: "grok-4.6".to_owned(),
            alias: "Grok 4.6".to_owned(),
            source: "oauth".to_owned(),
            oauth_account_id: 11,
            oauth_platform: "grok".to_owned(),
            ..Default::default()
        });
        let imported = auto_import_new_oauth_models(
            &mut config,
            &[first.clone(), third.clone()],
            Some("grok"),
            &[11],
        );
        assert!(imported.iter().any(|name| name.contains("Grok 4.5 Team") || name.contains("Grok 4.6")), "{imported:?}");
        assert_eq!(
            config
                .models
                .iter()
                .filter(|model| model.oauth_account_id == 24)
                .count(),
            2
        );
        assert!(config.models.iter().any(|model| {
            model.oauth_account_id == 24 && model.model == "grok-4.6"
        }));
        assert!(config.models.iter().any(|model| {
            model.oauth_account_id == 24 && model.model == "grok-4.5"
        }));
        assert_eq!(
            auto_import_new_oauth_models(&mut config, &[first, third], Some("grok"), &[11, 24]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn later_oauth_account_without_catalog_still_imports_a_route_slot() {
        let first = OAuthAccountSummary {
            id: 11,
            name: "Grok one".to_owned(),
            platform: "grok".to_owned(),
            status: "active".to_owned(),
            email: String::new(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: vec![OAuthModelSummary {
                id: "grok-4.5".to_owned(),
                display_name: "Grok 4.5".to_owned(),
            }],
            models_error: String::new(),
        };
        let third = OAuthAccountSummary {
            id: 36,
            name: "Grok OAuth (oauth.user@example.com)".to_owned(),
            platform: "x-ai".to_owned(),
            status: "active".to_owned(),
            email: "oauth.user@example.com".to_owned(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: Vec::new(),
            models_error: String::new(),
        };
        let mut config = RouterConfig::default();
        assert_eq!(
            auto_enable_first_oauth_model(&mut config, std::slice::from_ref(&first), "grok"),
            Some("Grok 4.5".to_owned())
        );
        config.models.push(ModelConfig {
            model: "grok-4.6".to_owned(),
            alias: "Grok 4.6".to_owned(),
            source: "oauth".to_owned(),
            oauth_account_id: 11,
            oauth_platform: "grok".to_owned(),
            ..Default::default()
        });
        let imported = auto_import_new_oauth_models(
            &mut config,
            &[first, third],
            Some("grok"),
            &[11],
        );
        assert!(!imported.is_empty());
        assert_eq!(
            config
                .models
                .iter()
                .filter(|model| model.oauth_account_id == 36)
                .count(),
            2
        );
        assert!(config.models.iter().any(|model| {
            model.oauth_account_id == 36 && model.model == "grok-4.6"
        }));
        assert!(config.models.iter().any(|model| {
            model.oauth_account_id == 36 && model.model == "grok-4.5"
        }));
    }

    #[test]
    fn grok_pool_accounts_attach_to_every_existing_route_card() {
        let first = OAuthAccountSummary {
            id: 42,
            name: "Grok one".to_owned(),
            platform: "grok".to_owned(),
            status: "active".to_owned(),
            email: "one@example.com".to_owned(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: vec![
                OAuthModelSummary {
                    id: "grok-4.5".to_owned(),
                    display_name: "Grok 4.5".to_owned(),
                },
                OAuthModelSummary {
                    id: "grok-4.6".to_owned(),
                    display_name: "Grok 4.6".to_owned(),
                },
            ],
            models_error: String::new(),
        };
        let second = OAuthAccountSummary {
            id: 43,
            name: "Grok two".to_owned(),
            platform: "x-ai".to_owned(),
            status: "active".to_owned(),
            email: "two@example.com".to_owned(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models: Vec::new(),
            models_error: String::new(),
        };
        let mut config = RouterConfig {
            models: vec![
                ModelConfig {
                    model: "grok-4.6".to_owned(),
                    alias: "Grok 4.6".to_owned(),
                    source: "oauth".to_owned(),
                    oauth_account_id: 42,
                    oauth_platform: "grok".to_owned(),
                    ..Default::default()
                },
                ModelConfig {
                    model: "grok-4.5".to_owned(),
                    alias: "Grok 4.5".to_owned(),
                    source: "oauth".to_owned(),
                    oauth_account_id: 42,
                    oauth_platform: "grok".to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let imported = auto_import_new_oauth_models(
            &mut config,
            &[first, second],
            Some("grok"),
            &[42],
        );
        assert!(!imported.is_empty());
        let grok46 = config
            .models
            .iter()
            .filter(|model| model.model == "grok-4.6")
            .map(|model| model.oauth_account_id)
            .collect::<Vec<_>>();
        let grok45 = config
            .models
            .iter()
            .filter(|model| model.model == "grok-4.5")
            .map(|model| model.oauth_account_id)
            .collect::<Vec<_>>();
        assert_eq!(grok46, vec![42, 43]);
        assert_eq!(grok45, vec![42, 43]);
        assert_eq!(crate::logic::dashboard_model_rows(&config.models)[0].account_count, 2);
    }

    #[test]
    fn first_launch_opens_the_first_welcome_page() {
        assert_eq!(initial_page_for_config(None), (Page::Welcome, false));
        assert_eq!(
            initial_page_for_config(Some(&RouterConfig::default())),
            (Page::Welcome, false)
        );
        assert!(!user_data::config_looks_configured(&RouterConfig::default()));

        let configured = RouterConfig {
            accept_compliance: true,
            accepted_terms_version: "accepted".to_owned(),
            models: vec![ModelConfig {
                model: "example-model".to_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            initial_page_for_config(Some(&configured)),
            (Page::Dashboard, true)
        );
        let models_only = RouterConfig {
            models: vec![ModelConfig {
                model: "example-model".to_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(user_data::config_looks_configured(&models_only));
        assert_eq!(
            initial_page_for_config(Some(&models_only)),
            (Page::Dashboard, true)
        );
    }

    #[test]
    fn self_check_runs_every_three_minutes_and_unknown_oauth_recovery_caps_at_five_hours() {
        let now = std::time::Instant::now();
        assert_eq!(
            next_background_usage_refresh(now).duration_since(now),
            std::time::Duration::from_secs(3 * 60)
        );
        assert_eq!(default_oauth_recovery_seconds(), 5 * 60 * 60);
        assert_eq!(
            next_failed_oauth_recovery(now).duration_since(now),
            std::time::Duration::from_secs(3 * 60)
        );
        const { assert!(!super::DEFAULT_ROUTER_REQUIRES_OPENAI_AUTH) };
        assert!(scheduled_usage_refresh_is_due(true, Some(now), now));
        assert_eq!(
            oauth_recovery_schedule_delay(1),
            Some(std::time::Duration::from_secs(3 * 60))
        );
        assert_eq!(
            oauth_recovery_schedule_delay(6 * 60 * 60),
            Some(std::time::Duration::from_secs(5 * 60 * 60))
        );
        assert_eq!(oauth_recovery_schedule_delay(0), None);
    }

    #[test]
    fn every_self_check_queues_a_live_oauth_model_catalog_refresh() {
        let mut pending = false;
        super::queue_oauth_catalog_refresh(&mut pending);
        assert!(pending);
    }

    #[test]
    fn every_self_check_queues_a_subscription_quota_refresh() {
        let mut catalog_pending = false;
        let mut quota_pending = false;
        super::queue_self_check_account_maintenance(
            &mut catalog_pending,
            &mut quota_pending,
        );
        assert!(catalog_pending);
        assert!(
            quota_pending,
            "a self-check must not drop the per-subscription quota pass"
        );
    }

    #[test]
    fn scheduled_oauth_recovery_waits_for_exclusive_admin_access() {
        assert!(scheduled_oauth_recovery_can_start(
            AdminTaskActivity::default()
        ));
        for busy_index in 0..9 {
            let mut activity = AdminTaskActivity::default();
            match busy_index {
                0 => activity.applying = true,
                1 => activity.router_mode_switching = true,
                2 => activity.usage_loading = true,
                3 => activity.oauth_loading = true,
                4 => activity.routing_sync_running = true,
                5 => activity.health_probe_running = true,
                6 => activity.health_recovery_running = true,
                7 => activity.provider_oauth_preparing = true,
                8 => activity.provider_oauth_running = true,
                _ => unreachable!(),
            }
            assert!(!scheduled_oauth_recovery_can_start(activity));
        }
    }

    #[test]
    fn oauth_account_refresh_waits_for_recovery_and_route_sync() {
        assert!(oauth_account_refresh_can_start(AdminTaskActivity::default()));
        for busy_index in 0..5 {
            let mut activity = AdminTaskActivity::default();
            match busy_index {
                0 => activity.oauth_recovery_running = true,
                1 => activity.routing_sync_running = true,
                2 => activity.applying = true,
                3 => activity.router_mode_switching = true,
                4 => activity.health_recovery_running = true,
                _ => unreachable!(),
            }
            assert!(!oauth_account_refresh_can_start(activity));
        }
    }

    #[test]
    fn background_oauth_discovery_never_requests_a_full_apply_or_codex_restart() {
        assert_eq!(
            super::background_oauth_sync_action(true, false, false),
            super::BackgroundOAuthSyncAction::LiveRouterOnly
        );
        assert_eq!(
            super::background_oauth_sync_action(true, true, false),
            super::BackgroundOAuthSyncAction::None
        );
        assert_eq!(
            super::background_oauth_sync_action(true, false, true),
            super::BackgroundOAuthSyncAction::None
        );
        assert_eq!(
            super::background_oauth_sync_action(false, false, false),
            super::BackgroundOAuthSyncAction::None
        );
    }

    #[test]
    fn native_window_title_contains_the_exact_package_version() {
        assert_eq!(APP_TITLE, format!("CodexRouter v{APP_VERSION}"));
    }

    #[test]
    fn usage_error_degrades_to_retry_keep_when_a_snapshot_is_on_screen() {
        assert!(
            super::usage_error_for_ui(true, "用量查询暂时失败".to_owned())
                .starts_with("RETRY-KEEP:")
        );
        assert_eq!(
            super::usage_error_for_ui(false, "用量查询暂时失败".to_owned()),
            "用量查询暂时失败"
        );
    }

    #[test]
    fn pool_failover_event_parts_are_parsed_from_router_records() {
        assert_eq!(
            super::pool_failover_parts(
                "[Router events] 2026-08-27T.. class=upstream | event=request.pool_failover | from_pool=cr/r10a56/xai | reason=auth_unavailable"
            ),
            Some(("cr/r10a56/xai".to_owned(), "auth_unavailable".to_owned()))
        );
        assert_eq!(
            super::pool_failover_parts(
                "[Router events] event=request.pool_failover | from_pool=cr/r13a52/antigravity | reason=pool_exhausted"
            ),
            Some((
                "cr/r13a52/antigravity".to_owned(),
                "pool_exhausted".to_owned()
            ))
        );
        assert_eq!(
            super::pool_failover_parts("[Router events] event=request_failure | status=503"),
            None
        );
        assert_eq!(
            super::pool_unavailable_model(
                "[Router events] event=request.pool_unavailable | model=grok-4.6 | reason=auth_unavailable"
            ),
            Some("grok-4.6".to_owned())
        );
        assert_eq!(super::pool_unavailable_model("[Router events] event=request.pool_failover"), None);
        assert_eq!(super::account_id_from_pool_id("cr/r10a56/xai"), Some(56));
        assert_eq!(super::account_id_from_pool_id("cr/r13f/xai"), None);
        assert_eq!(super::account_id_from_pool_id("cr/r10a56"), Some(56));
        assert_eq!(super::account_id_from_pool_id("cr/other/xai"), None);
    }

    #[test]
    fn rejoined_account_notification_fires_only_after_recovery() {
        let previous = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 4,
                name: "ChatGPT".into(),
                platform: "chatgpt".into(),
                health: "quotaExhausted".into(),
                windows: vec![UsageWindow {
                    kind: "fiveHour".into(),
                    used_percent: Some(100.0),
                    reset_at: "2026-08-29T01:00:00Z".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let current = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 4,
                name: "ChatGPT".into(),
                platform: "chatgpt".into(),
                health: "healthy".into(),
                windows: vec![UsageWindow {
                    kind: "fiveHour".into(),
                    used_percent: Some(20.0),
                    reset_at: "2026-08-29T02:00:00Z".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            super::rejoined_account_notification(Some(&previous), &current),
            Some((4, "ChatGPT".to_owned()))
        );
        // No pop for an account that was already healthy.
        assert_eq!(super::rejoined_account_notification(Some(&current), &current), None);
        // No pop while the account is still exhausted.
        assert_eq!(
            super::rejoined_account_notification(Some(&previous), &previous),
            None
        );
        // No pop without a previous snapshot.
        assert_eq!(super::rejoined_account_notification(None, &current), None);
    }

    #[test]
    fn rejoined_notification_rejects_status_only_flapping_without_a_quota_reset() {
        let windows = vec![
            UsageWindow {
                kind: "fiveHour".into(),
                used_percent: Some(74.0),
                ..Default::default()
            },
            UsageWindow {
                kind: "weekly".into(),
                used_percent: Some(75.0),
                ..Default::default()
            },
        ];
        let previous = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 61,
                name: "ChatGPT OAuth".into(),
                platform: "openai".into(),
                health: "quotaExhausted".into(),
                windows: windows.clone(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let current = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 61,
                name: "ChatGPT OAuth".into(),
                platform: "openai".into(),
                health: "healthy".into(),
                windows,
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            super::rejoined_account_notification(Some(&previous), &current),
            None,
            "a local schedulable flip is not proof that provider quota recovered"
        );
    }

    #[test]
    fn quota_notification_is_transition_based_and_requires_a_real_fallback_pair() {
        let mut config = RouterConfig {
            oauth_account_ids: Some(vec![4]),
            models: vec![
                ModelConfig {
                    model: "grok-4.5".into(),
                    source: "oauth".into(),
                    oauth_account_id: 4,
                    alias: "Grok OAuth".into(),
                    ..Default::default()
                },
                ModelConfig {
                    model: "x-ai/grok-4.5".into(),
                    source: "apikey".into(),
                    alias: "OpenRouter Grok".into(),
                    base_url: "https://openrouter.ai/api/v1".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let previous = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 4,
                name: "SuperGrok".into(),
                health: "healthy".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let exhausted = UsageSnapshot {
            subscriptions: vec![UsageAccount {
                id: 4,
                name: "SuperGrok".into(),
                health: "quotaExhausted".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            fallback_transition_notification(Some(&previous), &exhausted, &config),
            Some((4, "SuperGrok".into(), "OpenRouter Grok".into()))
        );
        assert_eq!(
            fallback_transition_notification(None, &exhausted, &config),
            None
        );
        assert_eq!(
            fallback_transition_notification(Some(&exhausted), &exhausted, &config),
            None
        );
        config.models[1].model = "x-ai/grok-4.3".into();
        assert_eq!(
            fallback_transition_notification(Some(&previous), &exhausted, &config),
            None
        );
    }

    #[test]
    fn quota_notification_uses_the_account_with_a_real_fallback_when_multiple_exhaust() {
        let config = RouterConfig {
            oauth_account_ids: Some(vec![4]),
            models: vec![
                ModelConfig {
                    model: "grok-4.5".into(),
                    source: "oauth".into(),
                    oauth_account_id: 4,
                    ..Default::default()
                },
                ModelConfig {
                    model: "x-ai/grok-4.5".into(),
                    source: "apikey".into(),
                    alias: "OpenRouter Grok".into(),
                    base_url: "https://openrouter.ai/api/v1".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let previous = UsageSnapshot {
            subscriptions: vec![
                UsageAccount {
                    id: 9,
                    health: "healthy".into(),
                    ..Default::default()
                },
                UsageAccount {
                    id: 4,
                    name: "SuperGrok".into(),
                    health: "healthy".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let current = UsageSnapshot {
            subscriptions: vec![
                UsageAccount {
                    id: 9,
                    health: "quotaExhausted".into(),
                    ..Default::default()
                },
                UsageAccount {
                    id: 4,
                    name: "SuperGrok".into(),
                    health: "quotaExhausted".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            fallback_transition_notification(Some(&previous), &current, &config),
            Some((4, "SuperGrok".into(), "OpenRouter Grok".into()))
        );
    }

    #[test]
    fn structured_429_failover_notification_is_precise_and_safe() {
        assert_eq!(
            failover_account_id("[Sub2API/WARN] openai.upstream_failover_switching | upstream_status=429 | account_id=7 | class=quota"),
            Some(7)
        );
        assert_eq!(
            failover_account_id("[Sub2API/WARN] openai.upstream_failover_switching | upstream_status=402 | account_id=8 | class=quota"),
            Some(8)
        );
        assert_eq!(
            failover_account_id("[Sub2API/WARN] openai.upstream_failover_switching | upstream_status=500 | account_id=7"),
            None
        );
        assert_eq!(failover_account_id("quota 429 account_id=7"), None);
    }

    #[test]
    fn native_window_policy_fits_a_1080p_work_area_at_200_percent() {
        for preferred in [DEFAULT_WINDOW_LOGICAL_SIZE, COMPACT_WINDOW_LOGICAL_SIZE] {
            let size = fit_window_to_work_area(preferred, WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE);
            assert!(MIN_WINDOW_LOGICAL_SIZE[0] <= preferred[0]);
            assert!(MIN_WINDOW_LOGICAL_SIZE[1] <= preferred[1]);
            assert!(
                size[0] + WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE[0]
                    <= WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE[0]
            );
            assert!(
                size[1] + WINDOWS_NON_CLIENT_LOGICAL_ALLOWANCE[1]
                    <= WINDOWS_1080P_200_WORK_AREA_LOGICAL_SIZE[1]
            );
        }
        let normal = initial_window_logical_size(false);
        let compact = initial_window_logical_size(true);
        assert!(normal[0] > 0.0 && normal[0] <= DEFAULT_WINDOW_LOGICAL_SIZE[0]);
        assert!(normal[1] > 0.0 && normal[1] <= DEFAULT_WINDOW_LOGICAL_SIZE[1]);
        assert!(compact[0] > 0.0 && compact[0] <= COMPACT_WINDOW_LOGICAL_SIZE[0]);
        assert!(compact[1] > 0.0 && compact[1] <= COMPACT_WINDOW_LOGICAL_SIZE[1]);
        assert_eq!(
            fit_window_to_work_area(DEFAULT_WINDOW_LOGICAL_SIZE, [1920.0, 1032.0]),
            DEFAULT_WINDOW_LOGICAL_SIZE
        );
    }

    #[test]
    fn cross_screen_move_clamps_only_when_the_target_monitor_is_smaller() {
        assert_eq!(
            fit_window_to_monitor([1280.0, 820.0], [1920.0, 1080.0]),
            [1280.0, 820.0]
        );
        assert_eq!(
            fit_window_to_monitor([1280.0, 820.0], [960.0, 540.0]),
            [944.0, 452.0]
        );
        assert_eq!(
            fit_window_to_monitor([800.0, 400.0], [960.0, 540.0]),
            [800.0, 400.0]
        );
        assert!(!should_clamp_window_to_monitor(
            [980.0, 720.0],
            [1920.0, 1080.0]
        ));
        assert!(!should_clamp_window_to_monitor(
            [1200.0, 800.0],
            [1240.0, 840.0]
        ));
        assert!(should_clamp_window_to_monitor(
            [1280.0, 820.0],
            [960.0, 540.0]
        ));
        assert!(!should_clamp_window_to_monitor(
            [800.0, 400.0],
            [820.0, 420.0]
        ));
    }

    #[test]
    fn tray_restore_rejects_tiny_windows_and_leaves_lightweight_mode() {
        assert!(!window_size_is_usable([40.0, 80.0]));
        assert!(window_size_is_usable(MIN_WINDOW_LOGICAL_SIZE));
        assert_eq!(
            restored_window_size([40.0, 80.0]),
            MIN_WINDOW_LOGICAL_SIZE
        );
        assert_eq!(stored_window_size(40.0, 80.0), None);
        assert_eq!(
            stored_window_size(1064.0, 820.0),
            Some([1064.0, 820.0])
        );
        assert!(should_leave_tray_lightweight(
            true,
            false,
            false,
            Some([40.0, 80.0])
        ));
        assert!(should_leave_tray_lightweight(true, false, true, None));
        assert!(!should_leave_tray_lightweight(
            true,
            true,
            false,
            Some(DEFAULT_WINDOW_LOGICAL_SIZE)
        ));
    }

    #[test]
    fn overwrite_countdown_only_advances_while_the_window_has_focus() {
        let started = std::time::Instant::now();
        let mut deadline = Some(started + std::time::Duration::from_secs(3));
        let mut paused_at = None;

        assert!(!advance_overwrite_countdown(
            &mut deadline,
            &mut paused_at,
            started + std::time::Duration::from_secs(1),
            true,
        ));
        assert!(!advance_overwrite_countdown(
            &mut deadline,
            &mut paused_at,
            started + std::time::Duration::from_secs(2),
            false,
        ));
        assert!(!advance_overwrite_countdown(
            &mut deadline,
            &mut paused_at,
            started + std::time::Duration::from_secs(12),
            false,
        ));
        assert!(!advance_overwrite_countdown(
            &mut deadline,
            &mut paused_at,
            started + std::time::Duration::from_secs(12),
            true,
        ));
        assert!(advance_overwrite_countdown(
            &mut deadline,
            &mut paused_at,
            started + std::time::Duration::from_secs(14),
            true,
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_resource_embeds_per_monitor_v2_dpi_awareness() {
        let manifest = include_str!(concat!(env!("OUT_DIR"), "/codex-router.manifest"));
        assert!(manifest.contains(
            "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>"
        ));
        assert!(manifest.contains(
            "<dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware>"
        ));
        assert!(manifest.contains("requestedExecutionLevel level=\"asInvoker\""));

        let resource = include_str!(concat!(env!("OUT_DIR"), "/codex-router.rc"));
        assert!(resource.lines().any(|line| line.starts_with("1 24 \"")));
    }

    #[cfg(windows)]
    use super::{stop_router_for_exit_with_timeout, ExitTransactionMarker};

    #[cfg(windows)]
    #[test]
    fn exit_transaction_marker_is_pid_scoped_and_removed_on_drop() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let marker = ExitTransactionMarker::create(&root).unwrap();
        assert_eq!(
            std::fs::read_to_string(&marker.path).unwrap(),
            std::process::id().to_string()
        );
        let marker_path = marker.path.clone();
        drop(marker);
        assert!(!marker_path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn exit_transaction_marker_creation_failure_is_reported() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-marker-failure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data"), b"not a directory").unwrap();
        assert!(ExitTransactionMarker::create(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_shutdown_reports_lifecycle_lock_contention_without_running_powershell() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let _lock = super::lifecycle::acquire_lifecycle_lock(
            &root,
            std::time::Duration::from_millis(100),
            "test owner",
        )
        .unwrap();

        let started = std::time::Instant::now();
        let result = stop_router_for_exit_with_timeout(
            &root,
            &RouterConfig::default(),
            std::time::Duration::from_millis(1500),
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("ROUTER_LIFECYCLE_BUSY"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        drop(_lock);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn small_system_icon_uses_most_of_its_canvas() {
        let (rgba, width, height) = decode_icon().expect("embedded icon should decode");
        assert_eq!(width, height);
        assert_eq!(rgba.len(), width as usize * height as usize * 4);

        let mut min_x = width;
        let mut max_x = 0;
        for (index, pixel) in rgba.as_chunks::<4>().0.iter().enumerate() {
            if pixel[3] >= 16 {
                let x = index as u32 % width;
                min_x = min_x.min(x);
                max_x = max_x.max(x);
            }
        }
        let occupied_width = max_x.saturating_sub(min_x).saturating_add(1);
        assert!(occupied_width as f32 / width as f32 >= 0.9);
    }

    #[test]
    fn full_exit_restores_the_codex_route_used_before_router() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-restore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let codex_home = root.join("codex-home");
        std::fs::create_dir_all(&codex_home).unwrap();
        let mut config = RouterConfig::default();
        config.deploy.codex_home = codex_home.to_string_lossy().into_owned();
        std::fs::write(
            codex_home.join("config.toml"),
            "model = \"official-before-router\"\napproval_policy = \"never\"\n",
        )
        .unwrap();
        super::profiles::ensure_original_codex_snapshot(&root, &config).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"sub2api\"\nmodel = \"router-model\"\n\
             [model_providers.sub2api]\nname = \"Codex-Router\"\nbase_url = \"http://127.0.0.1:18082/v1\"\n",
        )
        .unwrap();

        restore_codex_for_exit(&root, &config, true, true).unwrap();
        let restored = std::fs::read_to_string(codex_home.join("config.toml")).unwrap();
        assert!(restored.contains("official-before-router"));
        assert!(!restored.contains("sub2api"));
        assert!(!restored.contains("router-model"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exit_waits_for_an_inflight_apply_before_deciding_whether_to_restore() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-apply-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let codex_home = root.join("codex-home");
        std::fs::create_dir_all(&codex_home).unwrap();
        let mut config = RouterConfig::default();
        config.deploy.codex_home = codex_home.to_string_lossy().into_owned();
        config.deploy.sub2api_host = "http://127.0.0.1:18082".into();
        config.save(&root.join("codex-router-config.json")).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            "model = \"official-before-router\"\napproval_policy = \"never\"\n",
        )
        .unwrap();
        super::profiles::ensure_original_codex_snapshot(&root, &config).unwrap();
        let apply_lock =
            super::profiles::acquire_config_apply_lock(&root, std::time::Duration::from_secs(1))
                .unwrap();
        let system_binding = root.join("system-config.toml");
        let worker_root = root.clone();
        let worker_config = config.clone();
        let worker_system_binding = system_binding.clone();
        let exit = std::thread::spawn(move || {
            restore_codex_and_stop_router_for_exit_with(
                &worker_root,
                &worker_config,
                true,
                &worker_system_binding,
                |_, _| Ok(()),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        std::fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"codex_router\"\nmodel = \"router-model\"\n\
             model_catalog_json = \"C:/Users/test/.codex-router/model-catalog.json\"\n\
             [model_providers.codex_router]\nname = \"Codex-Router\"\n\
             base_url = \"http://127.0.0.1:18082/v1\"\nwire_api = \"responses\"\n\
             requires_openai_auth = true\n\
             experimental_bearer_token = \"local-router-test-key\"\n",
        )
        .unwrap();
        drop(apply_lock);

        exit.join().unwrap().unwrap();
        let restored = std::fs::read_to_string(codex_home.join("config.toml")).unwrap();
        assert!(restored.contains("official-before-router"));
        assert!(!restored.contains("router-model"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn exit_still_stops_router_when_codex_restore_input_is_invalid() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-invalid-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("codex-router-config.json"), b"{invalid-json").unwrap();
        let system_binding = root.join("system-config.toml");

        let mut stopped = false;
        let result = restore_codex_and_stop_router_for_exit_with(
            &root,
            &RouterConfig::default(),
            true,
            &system_binding,
            |_, _| {
            stopped = true;
            Ok(())
            },
        );
        assert!(
            result.is_err(),
            "the invalid restore input must still be reported"
        );
        assert!(
            stopped,
            "a restore failure skipped the mandatory Router shutdown"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_exit_shutdown_leaves_codex_config_and_system_binding_untouched() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-stop-failure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let codex_home = root.join("codex-home");
        std::fs::create_dir_all(&codex_home).unwrap();
        let mut config = RouterConfig::default();
        config.deploy.codex_home = codex_home.to_string_lossy().into_owned();
        config.save(&root.join("codex-router-config.json")).unwrap();
        let codex_config = "model_provider = \"codex_router\"\nmodel = \"router-model\"\n\
             [model_providers.codex_router]\nname = \"Codex-Router\"\n\
             base_url = \"http://127.0.0.1:18082/v1\"\n";
        std::fs::write(codex_home.join("config.toml"), codex_config).unwrap();
        let system_binding = root.join("system-config.toml");
        std::fs::write(&system_binding, "model_provider = \"codex_router\"\n").unwrap();

        let result = restore_codex_and_stop_router_for_exit_with(
            &root,
            &RouterConfig::default(),
            true,
            &system_binding,
            |_, _| Err(anyhow::anyhow!("simulated foreign-port conflict")),
        );

        assert!(result.is_err(), "the shutdown failure must be reported");
        // While any managed service is still up, Codex must keep pointing at
        // it: neither the user config nor the system binding may be touched.
        assert_eq!(
            std::fs::read_to_string(codex_home.join("config.toml")).unwrap(),
            codex_config
        );
        assert_eq!(
            std::fs::read_to_string(&system_binding).unwrap(),
            "model_provider = \"codex_router\"\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    // Windows-only: asserts the %ProgramData% system layer is preserved.
    #[cfg(windows)]
    #[test]
    fn exit_keeps_a_legal_system_identity_instead_of_deleting_it() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-exit-keep-system-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let codex_home = root.join("codex-home");
        std::fs::create_dir_all(&codex_home).unwrap();
        let mut config = RouterConfig::default();
        config.deploy.codex_home = codex_home.to_string_lossy().into_owned();
        config.deploy.sub2api_host = "http://127.0.0.1:18082".into();
        config.save(&root.join("codex-router-config.json")).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            "model = \"official-before-router\"\n",
        )
        .unwrap();
        super::profiles::ensure_original_codex_snapshot(&root, &config).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"codex_router\"\nmodel = \"router-model\"\n\
             [model_providers.codex_router]\nname = \"OpenAI\"\n\
             base_url = \"http://127.0.0.1:18082/v1\"\n\
             requires_openai_auth = true\n",
        )
        .unwrap();
        let system_binding = root.join("system-config.toml");
        std::fs::write(
            &system_binding,
            "[model_providers.codex_router]\nname = \"OpenAI\"\nrequires_openai_auth = true\n",
        )
        .unwrap();

        restore_codex_and_stop_router_for_exit_with(
            &root,
            &config,
            true,
            &system_binding,
            |_, _| Ok(()),
        )
        .unwrap();

        let system = std::fs::read_to_string(&system_binding).unwrap();
        assert!(system.contains("requires_openai_auth = false"));
        assert!(system.contains("name = \"Codex-Router\""));
        assert!(system_binding.is_file(), "exit must not delete the system layer");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deployment_output_is_allowlisted_before_reaching_the_log() {
        let safe_stage =
            localized_deployment_line(false, "[2/7] secret=must-not-survive".to_owned());
        assert_eq!(safe_stage, "[2/7] Starting Router Host and CLIProxyAPI…");

        let safe_error =
            localized_deployment_line(false, "upstream failed api_key=must-not-survive".to_owned());
        assert!(safe_error.contains("class="));
        assert!(!safe_error.contains("must-not-survive"));
    }

    #[test]
    fn successful_deployment_progress_is_never_reported_as_a_diagnostic() {
        // Every one of these is normal Apply output. Before this fix they were
        // relabeled "Deployment diagnostic: class=unclassified_error".
        for line in [
            "Router administrator ready: admin@admin.com",
            "Codex model catalog generated: C:\\catalog.json (5 models)",
            "Composite routes: desired=7; created=2; updated=1; removed=0",
            "Updated channel: Codex-Router / ChatGPT-5.6-Sol",
            "Created channel: Codex-Router / DeepSeek-V4-Flash",
            "Skipped channel: GLM-5.3-Tokenrouter",
            "OAuth account 1 isolated until recovery: OAuth quota exhausted until reset",
            "Outbound proxy reconciliation: source=environment; resource=reused",
            "Catalog availability filter: kept=5; removed-unavailable=gpt-5.6-terra",
            "OAuth on-demand recovery delegated to Codex-Router: account 1 / gpt-5.6-sol",
            "Autostart registered: C:\\Users\\x\\Startup\\Codex Router.lnk",
            "Configured 8 model channel(s).",
            "Codex configuration written to: C:\\Users\\x\\.codex\\config.toml",
            "Local access key is stored in Windows Credential Manager and the current user environment.",
            "Codex Router is running at http://127.0.0.1:18082",
            "Codex Router secrets and data directory are initialized.",
        ] {
            for zh in [true, false] {
                // Mimic the deploy pipeline: logic.rs first reduces the line to a
                // safe marker, then the UI localizes it.
                let reduced = if line.starts_with('[') {
                    line.chars().take(5).collect::<String>()
                } else {
                    // Keep the same markers logic.rs emits for progress lines.
                    [
                        "Router administrator ready",
                        "Codex model catalog generated",
                        "Composite routes",
                        "Updated channel:",
                        "Created channel:",
                        "Skipped channel:",
                        "isolated until recovery",
                        "Outbound proxy reconciliation",
                        "Catalog availability filter",
                        "OAuth on-demand recovery delegated",
                        "Autostart registered",
                        "model channel(s).",
                        "Codex configuration written to",
                        "Local access key is stored in Windows Credential Manager",
                        "Codex Router is running at",
                        "Codex Router secrets and data directory",
                        "Configured ",
                    ]
                    .into_iter()
                    .find(|marker| line.contains(marker))
                    .unwrap_or(line)
                    .to_owned()
                };
                let rendered = localized_deployment_line(zh, reduced);
                assert!(
                    !rendered.contains("class="),
                    "normal progress was classified as an error: {line} -> {rendered}"
                );
                assert!(
                    !rendered.contains("Deployment diagnostic") && !rendered.contains("部署诊断"),
                    "normal progress was labeled a diagnostic: {line} -> {rendered}"
                );
            }
        }
    }

    #[test]
    fn every_router_flag_keeps_a_searchable_code_and_a_human_meaning() {
        for (line, zh_needle) in [
            ("CR-FLAG STAGE-01-INIT-OK", "步骤 1/7"),
            (
                "CR-FLAG OAUTH-PRIMARY account=1 platform=openai priority=1 models=3 fallback=yes",
                "优先使用该 OAuth 账号",
            ),
            (
                "CR-FLAG OAUTH-PARKED-WITH-FALLBACK account=1 platform=openai reason=quota reset=2026-08-08T03:34:03Z models=3",
                "改用同名第三方 API 兜底",
            ),
            (
                "CR-FLAG FALLBACK-ACTIVE model=gpt-5.6-sol account=1 reason=subscription-quota-parked",
                "已触发兜底",
            ),
            (
                "CR-FLAG CATALOG-MODEL model=gemini-3.1-pro-high served=oauth suffix=oauth account=4",
                "模型已写入 Codex 菜单",
            ),
            (
                "CR-FLAG ROUTING-SYNC-OK models=8 listChanged=yes created=1 updated=0 removed=0 parked=1",
                "重新同步路由",
            ),
        ] {
            let zh_text = localized_deployment_line(true, line.to_owned());
            let en_text = localized_deployment_line(false, line.to_owned());
            let code = line
                .trim_start_matches("CR-FLAG ")
                .split(' ')
                .next()
                .unwrap();
            for rendered in [&zh_text, &en_text] {
                assert!(
                    rendered.contains(code),
                    "the searchable flag code disappeared: {line} -> {rendered}"
                );
                assert!(
                    !rendered.contains("class="),
                    "a deployment flag was classified as an error: {line} -> {rendered}"
                );
                assert!(
                    !rendered.contains("部署诊断") && !rendered.contains("Deployment diagnostic"),
                    "a deployment flag was labeled a diagnostic: {line} -> {rendered}"
                );
            }
            assert!(
                zh_text.contains(zh_needle),
                "missing Chinese meaning for {line}: {zh_text}"
            );
            assert_ne!(zh_text, en_text, "flag was not localized: {line}");
        }
    }

    #[test]
    fn install_root_conflicts_are_actionable_in_both_languages() {
        let marker = "ROUTER_INSTALL_ROOT_CONFLICT: Sub2API port 18080 is owned elsewhere";
        assert!(localized_error_summary(true, marker).contains("另一份 Codex-Router"));
        assert!(localized_error_summary(false, marker).contains("Another Codex-Router"));
    }

    #[test]
    fn deployment_refuses_an_empty_model_list_before_touching_any_file() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-deploy-no-models-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = RouterConfig::default();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut logs = Vec::new();
        let error = deploy_router_config(&mut config, &root, &cancel, true, &[], |line| logs.push(line))
            .expect_err("a configuration without models is not deployable");
        let chained = format!("{error:#}");
        assert!(chained.contains("ROUTER_DEPLOY_NO_MODELS"), "{chained}");
        // Credentials, the catalog, and the channel manifest must stay untouched
        // so a failed rollback cannot erase a working deployment.
        assert!(logs.is_empty());
        assert!(!root.join("config").exists());
        assert!(localized_error_summary(true, &chained).contains("没有可部署的模型"));
        assert!(localized_error_summary(false, &chained).contains("no deployable model"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preclassified_usage_errors_are_not_classified_a_second_time() {
        assert_eq!(
            usage_error_for_display(true, "class=connection_refused | status=503"),
            "本地 Router 正在启动或恢复，请稍后重新查询。"
        );
        assert_eq!(
            usage_error_for_display(false, "unsafe\napi_key=must-not-survive"),
            "The usage query temporarily failed. The last successful data is retained; retry shortly."
        );
        assert!(!usage_error_for_display(true, "class=configuration").contains("class="));
    }

    #[test]
    fn healthy_usage_clears_only_stale_transient_oauth_account_errors() {
        let account = |id, platform: &str, status: &str, error: &str| OAuthAccountSummary {
            id,
            name: format!("{platform}-{id}"),
            platform: platform.to_owned(),
            status: status.to_owned(),
            email: String::new(),
            plan: String::new(),
            priority: 1,
            bound_to_router: true,
            error: error.to_owned(),
            expires_at: String::new(),
            models: Vec::new(),
            models_error: String::new(),
        };
        let mut accounts = vec![
            account(24, "grok", "active", "class=request_failure"),
            account(4, "gemini", "active", "class=unclassified_error"),
            account(31, "grok", "active", "class=authentication | status=401"),
            account(32, "gemini", "active", "class=permission | status=403"),
            account(33, "grok", "active", "class=rate_limit | status=429"),
            account(34, "gemini", "disabled", "class=request_failure"),
            account(35, "grok", "active", "class=request_failure"),
        ];
        let mut subscriptions = accounts
            .iter()
            .map(|account| UsageAccount {
                id: account.id,
                platform: if account.id == 4 {
                    "antigravity".to_owned()
                } else {
                    account.platform.clone()
                },
                status: "active".to_owned(),
                health: "healthy".to_owned(),
                ..UsageAccount::default()
            })
            .collect::<Vec<_>>();
        subscriptions
            .iter_mut()
            .find(|account| account.id == 35)
            .expect("unhealthy account fixture")
            .health = "requestFailure".to_owned();
        let snapshot = UsageSnapshot {
            subscriptions,
            ..UsageSnapshot::default()
        };

        clear_stale_oauth_account_errors(&mut accounts, Some(&snapshot));

        assert!(accounts[0].error.is_empty(), "Grok stale error survived");
        assert!(accounts[1].error.is_empty(), "Gemini stale error survived");
        assert!(accounts[2].error.contains("authentication"));
        assert!(accounts[3].error.contains("permission"));
        assert!(accounts[4].error.contains("rate_limit"));
        assert!(accounts[5].error.contains("request_failure"));
        assert!(accounts[6].error.contains("request_failure"));
    }

    #[test]
    fn oauth_model_refresh_failure_retains_the_last_good_catalog() {
        let account = |models: Vec<OAuthModelSummary>, models_error: &str| OAuthAccountSummary {
            id: 4,
            name: "Antigravity account".to_owned(),
            platform: "antigravity".to_owned(),
            status: "active".to_owned(),
            email: String::new(),
            plan: "Google AI Pro".to_owned(),
            priority: 1,
            bound_to_router: true,
            error: String::new(),
            expires_at: String::new(),
            models,
            models_error: models_error.to_owned(),
        };
        let previous = vec![account(
            vec![OAuthModelSummary {
                id: "gemini-3.1-pro-high".to_owned(),
                display_name: "Gemini 3.1 Pro High".to_owned(),
            }],
            "",
        )];
        let mut refreshed = vec![account(Vec::new(), "class=request_failure")];

        retain_last_good_oauth_models(&previous, &mut refreshed);

        assert_eq!(refreshed[0].models.len(), 1);
        assert_eq!(refreshed[0].models[0].id, "gemini-3.1-pro-high");
        assert_eq!(refreshed[0].models[0].display_name, "Gemini 3.1 Pro High");
        assert_eq!(refreshed[0].models_error, "class=request_failure");
    }

    #[test]
    fn kimi_usage_errors_are_actionable_and_deduplicated() {
        let mut account = UsageAccount {
            status_detail: "Kimi Coding Plan quota query failed (HTTP 403).".to_owned(),
            query_note:
                "class=authentication | status=401 | marker=ROUTER_KIMI_CREDENTIAL_REJECTED"
                    .to_owned(),
            ..UsageAccount::default()
        };

        normalize_usage_account_messages(true, &mut account);

        assert_eq!(
            account.status_detail,
            "Kimi API Key 无效或没有 Coding Plan 权限，请在 Kimi Code 控制台新建 Key 后重新填写。"
        );
        assert!(account.query_note.is_empty());
        assert!(!account.status_detail.contains("class="));
        assert!(!account.status_detail.contains("rate_limit"));
    }

    #[test]
    fn failed_profile_apply_restores_every_field_needed_for_a_safe_retry() {
        let mut config = RouterConfig {
            auth_mode: "profile-b".to_owned(),
            ..RouterConfig::default()
        };
        let mut active_profile_id = "profile-a".to_owned();
        let mut pending_profile_activation = Some("profile-b".to_owned());
        let mut configured = false;
        let mut router_mode_enabled = false;

        let previous_config = RouterConfig {
            auth_mode: "profile-a".to_owned(),
            ..RouterConfig::default()
        };
        restore_apply_ui_fields(
            &mut config,
            &mut active_profile_id,
            &mut pending_profile_activation,
            &mut configured,
            &mut router_mode_enabled,
            ApplyUiRollback {
                config: previous_config,
                active_profile_id: "profile-a".to_owned(),
                pending_profile_activation: None,
                configured: true,
                router_mode_enabled: true,
            },
        );

        assert_eq!(config.auth_mode, "profile-a");
        assert_eq!(active_profile_id, "profile-a");
        assert_eq!(pending_profile_activation, None);
        assert!(configured);
        assert!(router_mode_enabled);
    }

    #[test]
    fn runtime_probes_stay_off_until_the_console_is_ready() {
        assert!(!runtime_probes_allowed(false, false, Page::Welcome, true));
        assert!(!runtime_probes_allowed(true, false, Page::Welcome, true));
        assert!(!runtime_probes_allowed(true, false, Page::Finish, true));
        assert!(!runtime_probes_allowed(true, true, Page::Dashboard, true));
        assert!(!runtime_probes_allowed(true, false, Page::Dashboard, false));
        assert!(runtime_probes_allowed(true, false, Page::Dashboard, true));
        assert!(runtime_probes_allowed(true, false, Page::Monitor, true));
    }

    #[test]
    fn invalid_first_model_recovers_router_mode_unless_official_mode_was_explicit() {
        assert!(router_mode_enabled_on_startup(
            false, false, false, true, true, true
        ));
        assert!(!router_mode_enabled_on_startup(
            false, true, false, true, true, true
        ));
        assert!(!router_mode_enabled_on_startup(
            false, false, false, true, true, false
        ));
        assert!(router_mode_enabled_on_startup(
            true, false, false, true, true, false
        ));
    }

    #[test]
    fn one_isolated_profile_recovers_a_missing_shared_binding() {
        let profiles = vec![IsolationProfile {
            id: "profile-only".to_owned(),
            name: "Only profile".to_owned(),
            kind: IsolationKind::Local,
            created_at: String::new(),
            updated_at: String::new(),
        }];
        assert_eq!(
            recover_single_profile_binding(true, "", &profiles).as_deref(),
            Some("profile-only")
        );
        assert!(recover_single_profile_binding(false, "", &profiles).is_none());
        assert!(recover_single_profile_binding(true, "already", &profiles).is_none());
        assert!(recover_single_profile_binding(true, "", &[]).is_none());
    }

    #[test]
    fn router_health_errors_keep_independent_classes() {
        assert!(classify_router_health_error("Router health check timed out")
            .contains("class=timeout"));
        assert!(classify_router_health_error("connection refused")
            .contains("class=connection_refused"));
        assert!(
            classify_router_health_error("Router health returned HTTP/1.1 400 Bad Request")
                .contains("class=health_http")
        );
        assert!(classify_router_health_error("Router health returned HTTP/1.1 400 Bad Request")
            .contains("CR-LFC-0006"));
    }

    #[test]
    fn isolation_requires_an_explicit_existing_profile_binding() {
        let profiles = vec![IsolationProfile {
            id: "profile-a".to_owned(),
            name: "Profile A".to_owned(),
            kind: IsolationKind::Local,
            created_at: "2026-08-11T00:00:00Z".to_owned(),
            updated_at: "2026-08-11T00:00:00Z".to_owned(),
        }];

        assert!(!profile_binding_ready(true, "", None, &profiles));
        assert!(profile_binding_ready(true, "profile-a", None, &profiles));
        assert!(!profile_binding_ready(true, "missing", None, &profiles));
        assert!(profile_binding_ready(
            true,
            "",
            Some("profile-a"),
            &profiles
        ));
        assert!(profile_binding_ready(false, "", None, &profiles));
    }

    #[test]
    fn oauth_prepare_results_are_scoped_to_provider_and_generation() {
        let current_generation = 42;
        assert_eq!(
            request_result_disposition(current_generation, "openai", 41, "grok"),
            RequestResultDisposition::Ignore
        );
        assert_eq!(
            request_result_disposition(current_generation, "openai", 42, "grok"),
            RequestResultDisposition::RefreshCurrent
        );
        assert_eq!(
            request_result_disposition(current_generation, "openai", 42, "openai"),
            RequestResultDisposition::Apply
        );

        let mut closed_generation = current_generation;
        next_request_generation(&mut closed_generation);
        assert_eq!(
            request_result_disposition(closed_generation, "", 42, "openai"),
            RequestResultDisposition::Ignore
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn single_instance_lock_excludes_a_second_holder() {
        let first = lock_single_instance_file().unwrap();
        assert!(first.is_some());
        assert!(lock_single_instance_file().unwrap().is_none());
        drop(first);
        assert!(lock_single_instance_file().unwrap().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn hidden_helper_completion_does_not_wait_for_inherited_service_handles() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-helper-output-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let scripts = root.join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(
            scripts.join("Start-ProviderOAuth.ps1"),
            r#"$child = Start-Process powershell.exe -ArgumentList @('-NoLogo','-NoProfile','-Command','Start-Sleep -Seconds 4') -NoNewWindow -PassThru
[ordered]@{ status = 'ready'; childPid = $child.Id } | ConvertTo-Json -Compress
"#,
        )
        .unwrap();

        let started = std::time::Instant::now();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let output = run_hidden_powershell_output(
            &root,
            "Start-ProviderOAuth.ps1",
            &[],
            std::time::Duration::from_secs(3),
            &cancel,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            oauth_prepare_error_from_output(&output)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["status"], "ready");
        if let Some(child_pid) = result["childPid"].as_u64() {
            let _ = std::process::Command::new("taskkill.exe")
                .args(["/PID", &child_pid.to_string(), "/T", "/F"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[ignore = "requires an explicitly selected packaged release"]
    fn packaged_native_runtime_excludes_powershell() {
        let root = std::env::var_os("CODEX_ROUTER_SMOKE_ROOT")
            .map(std::path::PathBuf::from)
            .expect("CODEX_ROUTER_SMOKE_ROOT must select the packaged release");
        let manifest_path = root.join("release-manifest.json");
        let executable_path = root.join("Codex-Router.exe");
        assert!(manifest_path.is_file());
        assert!(executable_path.is_file());
        assert!(!root.join("scripts").exists());

        let manifest: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        assert!(manifest.iter().all(|entry| {
            let path = entry["path"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            !path.ends_with(".ps1") && !path.ends_with(".psm1") && !path.ends_with(".psd1")
        }));

        let executable = std::fs::read(executable_path).unwrap();
        for needle in [
            b"powershell.exe".as_slice(),
            b"Start-ProviderOAuth.ps1".as_slice(),
            b"GitHub-Update.ps1".as_slice(),
        ] {
            assert!(!executable
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle)));
        }
    }

    #[test]
    fn cold_start_prepare_errors_map_to_router_start() {
        let error = anyhow::anyhow!("Sub2API or an authenticated dependency did not become ready within 180 seconds");
        let mapped = oauth_prepare_error_from_native(&error);
        assert_eq!(mapped, "ROUTER_OAUTH_PREPARE_ROUTER_START stage=native");
        assert!(localized_error_summary(true, &mapped).contains("未能稳定启动"));
    }

    #[cfg(windows)]
    #[test]
    fn oauth_prepare_errors_keep_only_safe_structured_stage_codes() {
        use std::os::windows::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: br#"{"status":"error","provider":"openai","stage":"admin_login","code":"ROUTER_OAUTH_PREPARE_ADMIN_LOGIN","unsafe":"token-value"}"#
                .to_vec(),
            stderr: Vec::new(),
        };
        let safe = oauth_prepare_error_from_output(&output);
        assert_eq!(safe, "ROUTER_OAUTH_PREPARE_ADMIN_LOGIN stage=admin_login");
        assert!(!safe.contains("token-value"));
        assert!(localized_error_summary(true, &safe).contains("管理会话"));
        assert!(localized_error_summary(false, &safe).contains("admin session"));
    }

    #[cfg(windows)]
    #[test]
    fn oauth_prepare_errors_are_found_in_stderr_when_stdout_contains_noise() {
        use std::os::windows::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: b"ordinary helper output\n".to_vec(),
            stderr: br#"{"status":"error","provider":"openai","stage":"router_start","code":"ROUTER_OAUTH_PREPARE_ROUTER_START","unsafe":"token-value"}"#
                .to_vec(),
        };
        let safe = oauth_prepare_error_from_output(&output);
        assert_eq!(safe, "ROUTER_OAUTH_PREPARE_ROUTER_START stage=router_start");
        assert!(!safe.contains("token-value"));
    }

    #[test]
    fn transient_oauth_prepare_failures_are_automatically_retried() {
        assert!(oauth_prepare_error_is_retryable(
            "ROUTER_OAUTH_PREPARE_LIFECYCLE_BUSY stage=lifecycle_lock"
        ));
        assert!(oauth_prepare_error_is_retryable(
            "ROUTER_OAUTH_PREPARE_ADMIN_LOGIN stage=admin_login"
        ));
        assert!(oauth_prepare_error_is_retryable(
            "ROUTER_OAUTH_PREPARE_PROCESS stage=unknown"
        ));
        assert!(!oauth_prepare_error_is_retryable(
            "ROUTER_OAUTH_PREPARE_COMPONENTS stage=components"
        ));
        assert!(!oauth_prepare_error_is_retryable(
            "ROUTER_OAUTH_PREPARE_TIMEOUT stage=router_start"
        ));
    }

    #[test]
    fn usage_results_from_profile_a_cannot_mutate_profile_b() {
        assert_eq!(
            request_result_disposition(8, "profile:b", 7, "profile:a"),
            RequestResultDisposition::Ignore,
            "an older A result must not clear B's loading state"
        );
        assert_eq!(
            request_result_disposition(8, "profile:b", 8, "profile:a"),
            RequestResultDisposition::RefreshCurrent,
            "a current request whose profile changed must schedule B"
        );
        assert_eq!(
            request_result_disposition(8, "profile:b", 8, "profile:b"),
            RequestResultDisposition::Apply
        );
    }

    #[test]
    fn gui_log_rebuilds_at_256_kib_and_keeps_complete_recent_records() {
        let mut logs = String::with_capacity(2 * 1024 * 1024);
        let original_capacity = logs.capacity();
        let mut index = 0;
        while logs.len() <= MAX_LOG_BYTES {
            logs.push_str(&format!("record-{index:05}|{}|end\n", "界🙂".repeat(12)));
            index += 1;
        }

        append_bounded_log(&mut logs, "record-latest|界🙂|end");
        assert!(logs.len() <= RETAIN_LOG_BYTES);
        assert!(logs.ends_with("record-latest|界🙂|end\n"));
        assert!(logs
            .lines()
            .all(|line| line.starts_with("record-") && line.ends_with("|end")));
        assert!(logs.capacity() < original_capacity);
        assert!(logs.capacity() <= MAX_LOG_BYTES);
    }
}
