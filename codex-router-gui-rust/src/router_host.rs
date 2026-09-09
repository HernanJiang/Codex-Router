//! Hidden CodexRouter compatibility host: 18080 public, CLIProxyAPI private on 18081.
//!
//! The host owns: old `/api/v1` admin contract, public model catalog, two-level
//! routing with continuation stickiness, protocol-safe model rewriting, the
//! exactly-once usage ledger and the structured JSONL event stream.

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{FromRef, Path as AxumPath, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use codex_router_lib::backend::cli_proxy::CliProxyManagementClient;
use codex_router_lib::backend::config_compiler::{self, CliProxyConfig};
use codex_router_lib::control_plane::http_compat as compat;
use codex_router_lib::control_plane::scheduler;
use codex_router_lib::control_plane::ControlState;
use codex_router_lib::data_ops;
use codex_router_lib::routing::{ContinuationBindings, PoolRoute, RouteTable};
use codex_router_lib::state::StateStore;
use codex_router_lib::telemetry::ledger as usage_ledger;
use codex_router_lib::telemetry::structured_log::{self, StructuredLogger, TerminalSpanGuard};
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

const DEFAULT_PUBLIC_PORT: u16 = 18080;
const DEFAULT_PRIVATE_PORT: u16 = 18081;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const CONTINUATION_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Clone)]
pub struct HostState {
    pub control: ControlState,
    pub local_key: Arc<Zeroizing<String>>,
    pub bindings: Arc<Mutex<ContinuationBindings>>,
    pub cli_base: Arc<String>,
    pub cli_child: Arc<Mutex<Option<Child>>>,
    pub cli_data: reqwest::Client,
}

impl FromRef<HostState> for ControlState {
    fn from_ref(state: &HostState) -> ControlState {
        state.control.clone()
    }
}

fn argument_value(prefix: &str) -> Option<String> {
    std::env::args().find_map(|argument| argument.strip_prefix(prefix).map(str::to_owned))
}

fn router_root() -> PathBuf {
    argument_value("--root=")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
                .ancestors()
                .find(|path| path.join("scripts").is_dir() || path.join("app").is_dir())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        })
}

fn router_state_root() -> PathBuf {
    let root = router_root();
    if let Some(override_root) = std::env::var_os("CODEX_ROUTER_USER_DATA_ROOT") {
        let override_root = PathBuf::from(override_root);
        if override_root.is_absolute() {
            return override_root;
        }
    }
    if std::env::var_os("CODEX_ROUTER_PORTABLE_STATE").is_some_and(|value| value == "1") {
        return root;
    }
    if root.join("release-manifest.json").is_file() {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data)
                .join("Codex-Router")
                .join("UserData");
        }
    }
    root
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn ensure_local_api_key() -> Result<Zeroizing<String>> {
    if let Some(key) = codex_router_lib::credentials::read_text("LocalApiKey")? {
        if !key.trim().is_empty() {
            return Ok(key);
        }
    }
    let key = Zeroizing::new(format!("sk-local-{}", uuid::Uuid::now_v7().simple()));
    codex_router_lib::credentials::write_text("LocalApiKey", &key)?;
    Ok(key)
}

fn ensure_management_secret() -> Result<Zeroizing<String>> {
    if let Some(secret) = codex_router_lib::credentials::read_text("CliManagementSecret")? {
        if !secret.trim().is_empty() {
            return Ok(secret);
        }
    }
    let secret = Zeroizing::new(format!("cr-mgmt-{}", uuid::Uuid::now_v7().simple()));
    codex_router_lib::credentials::write_text("CliManagementSecret", &secret)?;
    Ok(secret)
}

fn ensure_admin_password() -> Result<Zeroizing<String>> {
    if let Some(secret) = codex_router_lib::credentials::read_text("AdminPassword")? {
        if !secret.trim().is_empty() {
            return Ok(secret);
        }
    }
    let secret = Zeroizing::new(format!(
        "{}{}",
        uuid::Uuid::now_v7().simple(),
        uuid::Uuid::now_v7().simple()
    ));
    codex_router_lib::credentials::write_text("AdminPassword", &secret)?;
    Ok(secret)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn default_runtime_config(
    local_key: &str,
    management_secret: &str,
    port: u16,
    auth_dir: &Path,
) -> CliProxyConfig {
    let mut config = CliProxyConfig {
        port,
        auth_dir: auth_dir.to_string_lossy().to_string(),
        remote_management: config_compiler::RemoteManagement {
            secret_key: management_secret.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    };
    config.proxy_url = inherited_proxy_url();
    config.api_keys.push(local_key.to_owned());
    config_compiler::apply_platform_runtime_policy(&mut config);
    config
}

fn inherited_proxy_url() -> Option<String> {
    std::env::var("CODEX_ROUTER_PROXY_URL")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn reconcile_runtime_config(
    path: &Path,
    local_key: &str,
    management_secret: &str,
    port: u16,
    auth_dir: &Path,
) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let mut config: CliProxyConfig = serde_yaml::from_str(&text)?;
    let proxy_url = inherited_proxy_url();
    let auth_dir = auth_dir.to_string_lossy().to_string();
    let unchanged = config.port == port
        && config.auth_dir == auth_dir
        && config.remote_management.secret_key == management_secret
        && config.api_keys == [local_key]
        && config.proxy_url == proxy_url;
    if unchanged {
        return Ok(());
    }
    config.port = port;
    config.auth_dir = auth_dir;
    config.remote_management.secret_key = management_secret.to_owned();
    config.api_keys = vec![local_key.to_owned()];
    config.proxy_url = proxy_url;
    write_runtime_config(path, &config)
}

fn write_runtime_config(path: &Path, config: &CliProxyConfig) -> Result<()> {
    config_compiler::validate(config)?;
    let yaml = config_compiler::to_yaml(config)?;
    atomic_write(path, yaml.as_bytes())
}

async fn start_cli(root: &Path, config_path: &Path) -> Result<Child> {
    let executable = root
        .join("app")
        .join(config_compiler::cli_executable_file_name());
    if !executable.is_file() {
        bail!(
            "CR-CLI-0001: locked CLIProxyAPI executable is missing: {}",
            executable.display()
        );
    }
    let actual_hash = sha256_file(&executable)?;
    if !actual_hash.eq_ignore_ascii_case(config_compiler::CLI_PROXY_SHA256) {
        bail!(
            "CR-CLI-0001: CLIProxyAPI hash mismatch: expected {}, actual {}",
            config_compiler::CLI_PROXY_SHA256,
            actual_hash
        );
    }
    // The Gemini CLI plugin ships Windows-only; the upstream darwin package
    // bundles no plugin, so macOS skips the plugin lock.
    #[cfg(windows)]
    {
        let Some(plugin_relative) = config_compiler::gemini_plugin_relative_path() else {
            bail!("CR-CLI-0001: locked Gemini CLI plugin path is unavailable");
        };
        let plugin = root.join(plugin_relative);
        if !plugin.is_file() {
            bail!("CR-CLI-0001: locked Gemini CLI plugin is missing");
        }
        let plugin_hash = sha256_file(&plugin)?;
        if !plugin_hash.eq_ignore_ascii_case(config_compiler::GEMINI_PLUGIN_SHA256) {
            bail!("CR-CLI-0001: Gemini CLI plugin hash mismatch");
        }
    }
    let logs = router_state_root().join("logs");
    std::fs::create_dir_all(&logs)?;
    let stdout_path = logs.join("cli-proxy-stdout.log");
    let stderr_path = logs.join("cli-proxy-stderr.log");
    let mut child = Command::new(&executable)
        .arg("-config")
        .arg(config_path)
        .arg("-local-model")
        .current_dir(root.join("app"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("CR-CLI-0002: spawn {}", executable.display()))?;
    if let Some(stdout) = child.stdout.take() {
        relay_cli_output(stdout, stdout_path);
    }
    if let Some(stderr) = child.stderr.take() {
        relay_cli_output(stderr, stderr_path);
    }
    if let Err(err) = assign_kill_on_close_job(&child) {
        eprintln!("[router-host] warn: {err:#}");
    }
    Ok(child)
}

fn relay_cli_output<R>(reader: R, path: PathBuf)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;

        let Ok(mut output) = tokio::fs::File::create(path).await else {
            return;
        };
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let redacted = structured_log::redact_text(&line);
            if tokio::io::AsyncWriteExt::write_all(&mut output, format!("{redacted}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    });
}

/// Bind the CLI child to a kill-on-close Job Object so the CLI cannot outlive
/// this host, even when the host is terminated without running the ctrl-c
/// cleanup path. Failure is reported as CR-CLI-0011 but does not block
/// startup: port-based cleanup in the GUI lifecycle is the second net.
#[cfg(windows)]
fn assign_kill_on_close_job(child: &Child) -> Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    let process = child
        .raw_handle()
        .context("CR-CLI-0011: CLI child handle unavailable")?
        as windows_sys::Win32::Foundation::HANDLE;
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            bail!(
                "CR-CLI-0011: CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
        {
            CloseHandle(job);
            bail!(
                "CR-CLI-0011: SetInformationJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if AssignProcessToJobObject(job, process) == 0 {
            CloseHandle(job);
            bail!(
                "CR-CLI-0011: AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // Deliberately leak `job`: closing it now would kill the CLI. When this
        // host process exits (even via TerminateProcess) the OS closes the
        // handle and the Job Object terminates the CLI.
    }
    Ok(())
}

/// macOS has no Job Objects. The CLI child's orphan cleanup is left to the
/// GUI lifecycle's port-based cleanup (the documented second net), so this is
/// a safe no-op that preserves the failure-is-non-fatal contract.
#[cfg(not(windows))]
fn assign_kill_on_close_job(_child: &Child) -> Result<()> {
    Ok(())
}

async fn wait_cli_ready(cli: &CliProxyManagementClient) -> Result<()> {
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    while Instant::now() < deadline {
        if cli.health().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    bail!("CR-CLI-0003: CLIProxyAPI did not become healthy within 30s")
}

pub fn public_router(state: HostState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/login", post(compat::login))
        .route("/api/v1/admin/compliance", get(compat::compliance))
        .route(
            "/api/v1/admin/compliance/accept",
            post(compat::accept_compliance),
        )
        .route(
            "/api/v1/admin/oauth/capabilities",
            get(compat::oauth_capabilities),
        )
        .route(
            "/api/v1/admin/users/1",
            get(compat::user_detail).put(compat::update_user),
        )
        .route(
            "/api/v1/admin/settings",
            get(compat::settings).put(compat::update_settings),
        )
        .route("/api/v1/admin/groups/all", get(compat::groups_all))
        .route("/api/v1/admin/groups", post(compat::create_group))
        .route("/api/v1/admin/groups/{id}", put(compat::update_group))
        .route(
            "/api/v1/admin/groups/{id}/composite-routes",
            get(compat::list_composite_routes).post(compat::create_composite_route),
        )
        .route(
            "/api/v1/admin/groups/{id}/composite-routes/reconcile",
            put(compat::reconcile_composite_routes),
        )
        .route(
            "/api/v1/admin/groups/{group_id}/composite-routes/{id}",
            put(compat::update_composite_route).delete(compat::delete_composite_route),
        )
        .route(
            "/api/v1/admin/accounts",
            get(compat::accounts).post(compat::create_account),
        )
        .route(
            "/api/v1/admin/accounts/{id}",
            get(compat::account_detail)
                .put(compat::update_account)
                .delete(compat::delete_account),
        )
        .route(
            "/api/v1/admin/accounts/generate-auth-url",
            post(compat::oauth_auth_url_anthropic),
        )
        .route(
            "/api/v1/admin/accounts/exchange-code",
            post(compat::oauth_exchange_code_anthropic),
        )
        .route(
            "/api/v1/admin/accounts/{id}/scheduled-test-plans",
            get(compat::list_account_plans),
        )
        .route(
            "/api/v1/admin/accounts/{id}/models",
            get(compat::account_models),
        )
        .route(
            "/api/v1/admin/accounts/{id}/models/sync-upstream",
            post(compat::account_models_sync_upstream),
        )
        .route(
            "/api/v1/admin/accounts/{id}/{action}",
            post(compat::account_action).get(compat::account_action),
        )
        .route(
            "/api/v1/admin/openai/generate-auth-url",
            post(compat::oauth_auth_url_openai),
        )
        .route(
            "/api/v1/admin/openai/create-from-oauth",
            post(compat::openai_create_from_oauth),
        )
        .route(
            "/api/v1/admin/openai/accounts/{id}/quota",
            get(compat::account_quota),
        )
        .route(
            "/api/v1/admin/grok/sso-to-oauth",
            post(compat::grok_sso_to_oauth),
        )
        .route(
            "/api/v1/admin/grok/accounts/{id}/quota",
            get(compat::account_quota),
        )
        .route(
            "/api/v1/admin/{provider}/oauth/auth-url",
            post(compat::oauth_auth_url_provider),
        )
        .route(
            "/api/v1/admin/{provider}/oauth/exchange-code",
            post(compat::oauth_exchange_code_provider),
        )
        .route(
            "/api/v1/admin/proxies",
            get(compat::proxies).post(compat::create_proxy),
        )
        .route(
            "/api/v1/admin/proxies/{id}",
            put(compat::update_proxy).delete(compat::delete_proxy),
        )
        .route(
            "/api/v1/admin/scheduled-test-plans",
            get(compat::list_plans).post(compat::create_plan),
        )
        .route(
            "/api/v1/admin/scheduled-test-plans/{id}",
            put(compat::update_plan).delete(compat::delete_plan),
        )
        .route(
            "/api/v1/admin/scheduled-test-plans/{id}/results",
            get(compat::list_plan_results),
        )
        .route(
            "/api/v1/keys",
            get(compat::list_api_keys).post(compat::create_api_key),
        )
        .route(
            "/api/v1/keys/{id}",
            put(compat::update_api_key).delete(compat::delete_api_key),
        )
        .route("/v1/usage", get(data_usage))
        .route("/antigravity/v1/usage", get(antigravity_usage))
        .route("/v1/sub2api/billing", get(data_billing))
        .route("/v1/embeddings", post(data_embeddings))
        .route("/v1/images/generations/async", post(image_async_generate))
        .route("/v1/images/edits/async", post(image_async_edit))
        .route("/v1/images/tasks/{task_id}", get(image_task_show))
        .route(
            "/v1/images/batches",
            get(image_batches_list).post(image_batch_submit),
        )
        .route("/v1/images/batches/models", get(image_batch_models))
        .route(
            "/v1/images/batches/{id}",
            get(image_batch_show).delete(image_batch_remove),
        )
        .route("/v1/images/batches/{id}/items", get(image_batch_items))
        .route(
            "/v1/images/batches/{id}/items/{custom_id}/content",
            get(image_batch_item_content),
        )
        .route(
            "/v1/images/batches/{id}/download",
            get(image_batch_download),
        )
        .route("/v1/images/batches/{id}/cancel", post(image_batch_cancel))
        .route(
            "/v1/images/batches/{id}/outputs",
            delete(image_batch_outputs_clear),
        )
        .fallback(any(data_plane))
        .with_state(state)
}

async fn health(State(state): State<HostState>) -> Response {
    match compat::health_json(&state.control).await {
        Ok(value) if value["status"] == "healthy" => compat::success(value),
        Ok(_) => compat::failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "CR-LFC-0006",
            "Router stack is degraded",
        ),
        Err(_) => compat::failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "CR-LFC-0006",
            "Router health check failed",
        ),
    }
}
// ---------------------------------------------------------------------------
// Data plane
// ---------------------------------------------------------------------------

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn data_plane_authorized(state: &HostState, request: &Request) -> bool {
    let Some(token) = bearer_token(request.headers()) else {
        return false;
    };
    if token == state.local_key.as_str() {
        return true;
    }
    compat::data_key_valid(&state.control, token)
}

/// Map public paths onto CLIProxyAPI paths, preserving the query string.
fn map_path(uri: &str) -> String {
    let (path, query) = match uri.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (uri, None),
    };
    let mapped = if path == "/models" {
        "/v1/models".to_owned()
    } else if path == "/responses" {
        "/v1/responses".to_owned()
    } else if path == "/chat/completions" {
        "/v1/chat/completions".to_owned()
    } else if path == "/messages" {
        "/v1/messages".to_owned()
    } else if path == "/messages/count_tokens" {
        "/v1/messages/count_tokens".to_owned()
    } else if path == "/alpha/search" {
        "/v1/alpha/search".to_owned()
    } else if let Some(id) = path
        .strip_prefix("/v1/videos/")
        .and_then(|tail| tail.strip_suffix("/content"))
    {
        format!("/openai/v1/videos/{id}/content")
    } else {
        path.to_owned()
    };
    match query {
        Some(query) => format!("{mapped}?{query}"),
        None => mapped,
    }
}

/// Model segment of a Gemini `/v1beta/models/{model}:{action}` path.
fn extract_v1beta_model(mapped: &str) -> Option<&str> {
    let path = mapped.split('?').next().unwrap_or(mapped);
    let rest = path.strip_prefix("/v1beta/models/")?;
    let (model, action) = rest.split_once(':')?;
    if model.is_empty() || action.is_empty() {
        None
    } else {
        Some(model)
    }
}

/// Replace the model segment of a v1beta path with the internal
/// `{prefix}/{public_model}` form, preserving action and query string. The
/// CLI registers v1beta as a wildcard route and splits on `:`, so the slash
/// inside the internal model is safe upstream.
fn rewrite_v1beta_path_model(mapped: &str, internal_model: &str) -> String {
    let (path, query) = match mapped.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (mapped, None),
    };
    let Some(rest) = path.strip_prefix("/v1beta/models/") else {
        return mapped.to_owned();
    };
    let Some((_, action)) = rest.split_once(':') else {
        return mapped.to_owned();
    };
    let rewritten = format!("/v1beta/models/{internal_model}:{action}");
    match query {
        Some(query) => format!("{rewritten}?{query}"),
        None => rewritten,
    }
}

fn protocol_of(path: &str) -> &'static str {
    if path.contains("/responses") {
        "responses"
    } else if path.contains("/chat/completions") || path.contains("/completions") {
        "chat"
    } else if path.contains("/messages") {
        "anthropic"
    } else if path.starts_with("/v1beta") {
        "gemini"
    } else {
        "other"
    }
}

fn upstream_error_code(status: u16) -> &'static str {
    match status {
        400 => "CR-UP-0001",
        401 => "CR-UP-0002",
        403 => "CR-UP-0003",
        404 => "CR-UP-0004",
        408 => "CR-UP-0005",
        409 => "CR-UP-0006",
        413 => "CR-UP-0007",
        429 => "CR-UP-0008",
        500 => "CR-UP-0009",
        502 => "CR-UP-0010",
        503 => "CR-UP-0011",
        504 => "CR-UP-0012",
        _ => "CR-CLI-0004",
    }
}

fn extract_headers(request_headers: &axum::http::HeaderMap) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for name in [axum::http::header::ACCEPT, axum::http::header::CONTENT_TYPE] {
        if let Some(value) = request_headers.get(&name) {
            let _ = headers.insert(name, value.clone());
        }
    }
    for name in [
        "openai-beta",
        "anthropic-version",
        "anthropic-beta",
        "x-codex-client",
    ] {
        if let (Ok(header_name), Some(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            request_headers.get(name),
        ) {
            let _ = headers.insert(header_name, value.clone());
        }
    }
    headers
}

fn reqwest_to_axum_headers(headers: &reqwest::header::HeaderMap) -> axum::http::HeaderMap {
    let mut output = axum::http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if let Ok(axum_name) = HeaderName::from_bytes(name.as_str().as_bytes()) {
            if name != reqwest::header::HOST
                && name != reqwest::header::CONTENT_LENGTH
                && name != reqwest::header::TRANSFER_ENCODING
            {
                output.insert(axum_name, value.clone());
            }
        }
    }
    output
}

fn crate_request_id(request: &Request) -> String {
    request
        .headers()
        .get("x-request-id")
        .or_else(|| request.headers().get("x-client-request-id"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| structured_log::accepted_request_id(Some(value)).ok())
        .unwrap_or_else(structured_log::request_id)
}

fn error_response(status: StatusCode, code: &str, message: &str, request_id: &str) -> Response {
    let body = serde_json::json!({
        "error": {"message": message, "type": "codex_router_error", "param": null, "code": code},
        "request_id": request_id
    });
    let mut response = (status, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(code) {
        response
            .headers_mut()
            .insert("x-codex-router-error-code", value);
    }
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// Inject the Router error code into an upstream error envelope without
/// removing or renaming any legacy field.
const ANTIGRAVITY_VERIFY_ACCOUNT_MESSAGE: &str = "Google Antigravity requires account verification before this model can run. Open Antigravity or your Google Account, complete verification, then retry.";

fn is_antigravity_account_verification(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("validation_required") || lower.contains("verify your account")
}

async fn antigravity_blocked_verification_message(state: &HostState) -> Option<String> {
    let files = state
        .control
        .cli
        .get("/v0/management/auth-files")
        .await
        .ok()?;
    let items = files.get("files").cloned().unwrap_or(files);
    let items = items.as_array()?;
    for item in items {
        let provider = item.get("provider").and_then(Value::as_str).unwrap_or("");
        if !provider.eq_ignore_ascii_case("antigravity") {
            continue;
        }
        let message = item
            .get("status_message")
            .and_then(Value::as_str)
            .unwrap_or("");
        if is_antigravity_account_verification(message) {
            return Some(ANTIGRAVITY_VERIFY_ACCOUNT_MESSAGE.to_owned());
        }
    }
    None
}

fn annotate_error_body(body: &mut Value, code: &str, request_id: &str) {
    if let Some(error) = body.get_mut("error").and_then(Value::as_object_mut) {
        error
            .entry("code")
            .or_insert_with(|| Value::String(code.to_owned()));
    }
    if let Some(object) = body.as_object_mut() {
        object
            .entry("request_id")
            .or_insert_with(|| Value::String(request_id.to_owned()));
    }
}

/// Resolve the CLI-selected credential to a Router account id using the
/// `X-CPA-TRACE-ID` header the CLI stamps on every data-plane response.
/// Returns None (pool-level correlation) when the CLI did not attribute.
fn attribute_account(state: &HostState, headers: &reqwest::header::HeaderMap) -> Option<i64> {
    let trace = headers.get("x-cpa-trace-id")?.to_str().ok()?;
    let auth_index = config_compiler::parse_cpa_trace_auth_index(trace)?;
    state
        .control
        .cli_index_map
        .read()
        .ok()?
        .get(auth_index)
        .copied()
}

fn record_ledger(state: &HostState, input: &usage_ledger::LedgerInput<'_>) {
    let entry = usage_ledger::ledger_entry(input);
    if let Err(error) = usage_ledger::record_terminal(&state.control.store, &entry) {
        let description = error.to_string();
        // A second terminal write for the same request_id is expected after
        // retries / synthetic failed events. Do not spam the activity log.
        if description.contains("already exists") {
            return;
        }
        let _ = state.control.logger.write(serde_json::json!({
            "level": "WARN",
            "event": "ledger.record_failed",
            "request_id": input.request_id,
            "error_description": description,
        }));
    }
}

/// Public `/v1/models` answer: only Router-public models, in catalog order.
fn public_models_response(state: &HostState, request_id: &str, provider: Option<&str>) -> Response {
    let routes = state
        .control
        .routes
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let public: Vec<String> = match provider {
        Some(provider) => {
            let mut seen = std::collections::BTreeSet::new();
            routes
                .routes()
                .iter()
                .filter(|route| route.provider == provider)
                .map(|route| route.public_model.clone())
                .filter(|model| seen.insert(model.clone()))
                .collect()
        }
        None => routes.public_models(),
    };
    let models: Vec<Value> = public
        .iter()
        .map(|model| serde_json::json!({"id": model, "object": "model", "created": 0, "owned_by": "codex-router"}))
        .collect();
    let body = serde_json::json!({"object": "list", "data": models});
    let mut response = (StatusCode::OK, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

struct PlanResult {
    body: Vec<u8>,
    public_model: String,
    pool_id: String,
    pool_prefix: String,
    upstream_model: String,
    /// `{prefix}/{public_model}` as sent to the CLI; needed to rewrite
    /// path-carried models (Gemini v1beta) back into the URL.
    internal_model: String,
    /// Grok OAuth treats inbound `X-Request-Id` / `prompt_cache_key` as
    /// `X-Grok-Conv-Id`. A Codex thread id from another model is invalid.
    fresh_upstream_request_id: bool,
}

fn plan_request(
    state: &HostState,
    bytes: &[u8],
    session_header: Option<&str>,
    path_model: Option<&str>,
    provider_constraint: Option<&str>,
    request_path: &str,
    exclude: &HashSet<String>,
) -> std::result::Result<PlanResult, Value> {
    let mut parsed: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => {
            return Err(
                serde_json::json!({"status": 400, "code": "CR-REQ-0006", "message": "request body is not valid JSON"}),
            )
        }
    };
    let body_model = parsed
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(model) = body_model.clone().or_else(|| path_model.map(str::to_owned)) else {
        return Ok(PlanResult {
            body: bytes.to_vec(),
            public_model: String::new(),
            pool_id: String::new(),
            pool_prefix: String::new(),
            upstream_model: String::new(),
            internal_model: String::new(),
            fresh_upstream_request_id: false,
        });
    };
    let mut table = state
        .control
        .routes
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(provider) = provider_constraint {
        // Forced-pool surfaces (Antigravity) see only their provider's pools;
        // a missing route reports CR-RTE-0001 exactly like the public plane.
        table = table.filtered_by_provider(provider);
    }
    let continuation_key = table.continuation_key(
        parsed.get("conversation_id").and_then(Value::as_str),
        parsed.get("previous_response_id").and_then(Value::as_str),
        parsed.get("prompt_cache_key").and_then(Value::as_str),
        session_header,
    );
    let pools = table.pools(&model);
    if pools.is_empty() {
        return Err(
            serde_json::json!({"status": 404, "code": "CR-RTE-0001", "message": format!("no route for model {model}")}),
        );
    }
    let bindings = state
        .bindings
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let selected = match codex_router_lib::routing::select_pool(
        &table,
        &model,
        continuation_key.as_deref(),
        &bindings,
        exclude,
    ) {
        Ok(route) => route.clone(),
        Err(_) => {
            // Distinguish "continuation owner was deleted" (409, caller must
            // start a new session) from "route exists but every credential is
            // paused" (503, retry after recovery). Only treat the owner as
            // gone when it is missing from the entire table, not just this
            // public model.
            let owner_removed = continuation_key
                .as_deref()
                .and_then(|key| bindings.pool(key))
                .is_some_and(|pool_id| {
                    !table.routes().iter().any(|route| route.pool_id == pool_id)
                });
            if owner_removed {
                return Err(
                    serde_json::json!({"status": 409, "code": "CR-RTE-0006", "message": "continuation owner is no longer available"}),
                );
            }
            return Err(
                serde_json::json!({"status": 503, "code": "CR-RTE-0002", "message": "no schedulable credential in pool"}),
            );
        }
    };
    let switched_provider = codex_router_lib::routing::should_drop_previous_response(
        &table,
        &bindings,
        continuation_key.as_deref(),
        &selected,
    );
    if switched_provider {
        if let Some(object) = parsed.as_object_mut() {
            object.remove("previous_response_id");
            object.remove("conversation_id");
            object.remove("conversation");
            object.remove("prompt_cache_key");
            object.remove("client_metadata");
        }
    }
    if let Some(key) = continuation_key {
        state
            .bindings
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .bind(key.clone(), selected.pool_id.clone(), CONTINUATION_TTL);
        let _ = codex_router_lib::routing::persist_binding(
            &state.control.store,
            &key,
            &selected.pool_id,
            CONTINUATION_TTL,
        );
    }
    let internal_model = table.rewrite_request_model(&model, &selected);
    if body_model.is_some() {
        parsed["model"] = Value::String(internal_model.clone());
    }
    if !codex_router_lib::responses_compat::is_openai_family_model(&model) {
        let _ = codex_router_lib::responses_compat::sanitize_responses_request(
            request_path,
            &mut parsed,
        );
        if body_model.is_some() {
            parsed["model"] = Value::String(internal_model.clone());
        }
    }
    let body = serde_json::to_vec(&parsed).map_err(|_| {
        serde_json::json!({"status": 400, "code": "CR-REQ-0006", "message": "could not encode request"})
    })?;
    Ok(PlanResult {
        body,
        public_model: model,
        pool_id: selected.pool_id.clone(),
        pool_prefix: selected.prefix.clone(),
        upstream_model: selected.upstream_model.clone(),
        internal_model,
        fresh_upstream_request_id: switched_provider
            || codex_router_lib::responses_compat::is_xai_family_model(&selected.upstream_model)
            || codex_router_lib::responses_compat::is_xai_family_model(&selected.public_model),
    })
}

/// Stateful SSE line rewriter: rewrites model references inside `data:` JSON
/// payloads back to the public model and captures terminal usage frames.
pub struct SseRewriter {
    pending: Vec<u8>,
    internal_model: String,
    upstream_model: String,
    public_model: String,
    pub usage: Option<Value>,
    pub terminal_seen: Option<String>,
}

impl SseRewriter {
    pub fn new(pool_prefix: &str, public_model: &str, upstream_model: &str) -> Self {
        Self {
            pending: Vec::new(),
            internal_model: format!("{pool_prefix}/{public_model}"),
            upstream_model: upstream_model.to_owned(),
            public_model: public_model.to_owned(),
            usage: None,
            terminal_seen: None,
        }
    }

    fn rewrite_model_value(&self, value: &mut Value) {
        let internal = self.internal_model.clone();
        let upstream = self.upstream_model.clone();
        let public = self.public_model.clone();
        fn walk(value: &mut Value, internal: &str, upstream: &str, public: &str) {
            match value {
                Value::String(text) => {
                    if text == internal
                        || text == upstream
                        || text.starts_with(&format!("{internal}/"))
                    {
                        *text = public.to_owned();
                    }
                }
                Value::Array(items) => items
                    .iter_mut()
                    .for_each(|item| walk(item, internal, upstream, public)),
                Value::Object(object) => object
                    .values_mut()
                    .for_each(|item| walk(item, internal, upstream, public)),
                _ => {}
            }
        }
        walk(value, &internal, &upstream, &public);
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        while let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=position).collect();
            output.extend_from_slice(&self.process_line(line));
        }
        output
    }

    pub fn finish(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let line = std::mem::take(&mut self.pending);
        self.process_line(line)
    }

    fn process_line(&mut self, line: Vec<u8>) -> Vec<u8> {
        let text = String::from_utf8_lossy(&line);
        let Some(json_text) = text.strip_prefix("data: ") else {
            return line;
        };
        let json_text = json_text.trim_end();
        if json_text == "[DONE]" {
            self.terminal_seen = Some("done".to_owned());
            return line;
        }
        let Ok(mut payload) = serde_json::from_str::<Value>(json_text) else {
            return line;
        };
        if let Some(usage) = payload
            .get("usage")
            .cloned()
            .or_else(|| payload.pointer("/response/usage").cloned())
            .or_else(|| payload.get("usageMetadata").cloned())
        {
            self.usage = Some(usage);
        }
        if let Some(event_type) = payload.get("type").and_then(Value::as_str) {
            if event_type.ends_with(".completed")
                || event_type.ends_with(".failed")
                || event_type.ends_with(".cancelled")
                || event_type == "message_stop"
            {
                self.terminal_seen = Some(event_type.to_owned());
            }
            if event_type.ends_with(".failed") || event_type.ends_with(".cancelled") {
                if let Some(response) = payload.get_mut("response").and_then(Value::as_object_mut) {
                    let error = response
                        .entry("error")
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(error) = error.as_object_mut() {
                        error
                            .entry("code")
                            .or_insert_with(|| Value::String("CR-UP-0014".to_owned()));
                    }
                } else if let Some(error) = payload.get_mut("error").and_then(Value::as_object_mut)
                {
                    error
                        .entry("code")
                        .or_insert_with(|| Value::String("CR-UP-0014".to_owned()));
                }
            }
        }
        if payload
            .pointer("/candidates/0/finishReason")
            .is_some_and(|value| !value.is_null())
        {
            self.terminal_seen = Some("gemini.finished".to_owned());
        }
        self.rewrite_model_value(&mut payload);
        codex_router_lib::responses_compat::strip_think_tags_from_value(&mut payload);
        let mut rewritten = b"data: ".to_vec();
        rewritten.extend_from_slice(
            &serde_json::to_vec(&payload).unwrap_or_else(|_| json_text.as_bytes().to_vec()),
        );
        rewritten.push(b'\n');
        rewritten
    }
}

/// Detect a WebSocket upgrade request (RFC 6455 handshake).
fn is_websocket_upgrade(request: &Request) -> bool {
    let connection = request
        .headers()
        .get(axum::http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let upgrade = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    connection.split(',').any(|part| part.trim() == "upgrade") && upgrade.contains("websocket")
}

/// Resolve the CLIProxyAPI loopback socket address from the configured base URI.
fn cli_socket_addr(cli_base: &str) -> String {
    let stripped = cli_base.trim().trim_end_matches('/');
    stripped
        .strip_prefix("http://")
        .or_else(|| stripped.strip_prefix("https://"))
        .map(str::to_owned)
        .unwrap_or_else(|| stripped.to_owned())
}

/// Read an HTTP response head (through the blank line) from the CLI socket.
async fn read_response_head(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = tokio::io::AsyncReadExt::read(stream, &mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CLI closed before sending response headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buffer);
        }
        if buffer.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CLI response head is too large",
            ));
        }
    }
}

/// Build an axum response from a raw HTTP head returned by the CLI.
fn response_from_raw_head(head: &[u8], request_id: &str, body: Body) -> Response {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 400 Bad Request");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .map(StatusCode::from_u16)
        .and_then(Result::ok)
        .unwrap_or(StatusCode::BAD_REQUEST);
    let mut builder = axum::response::Response::builder().status(status);
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length"
                    | "host"
                    | "transfer-encoding"
                    | "proxy-authenticate"
                    | "proxy-authorization"
            ) {
                continue;
            }
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                builder = builder.header(header_name, header_value);
            }
        }
    }
    builder
        .header("x-request-id", request_id)
        .body(body)
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::BAD_GATEWAY,
                "CR-ADP-0008",
                "cannot build upstream response",
                request_id,
            )
        })
}

/// Bidirectionally relay bytes between the upgraded client stream and the CLI.
async fn relay_websocket(
    on_upgrade: hyper::upgrade::OnUpgrade,
    cli: tokio::net::TcpStream,
    leftover: Vec<u8>,
) -> anyhow::Result<()> {
    let upgraded = on_upgrade
        .await
        .context("WebSocket upgrade was cancelled")?;
    // Upgraded implements hyper::rt Read/Write; TokioIo bridges it into
    // tokio AsyncRead/Write so it can be copy_bidirectional'd with the CLI
    // TcpStream.
    let mut client = hyper_util::rt::TokioIo::new(upgraded);
    let mut upstream = cli;
    if !leftover.is_empty() {
        tokio::io::AsyncWriteExt::write_all(&mut client, &leftover).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Proxy a WebSocket upgrade to the CLI and tunnel frames bidirectionally.
async fn proxy_websocket(
    state: &HostState,
    request: Request,
    mapped: &str,
    request_id: &str,
) -> Response {
    let on_upgrade = request
        .extensions()
        .get::<hyper::upgrade::OnUpgrade>()
        .cloned();
    let Some(on_upgrade) = on_upgrade else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-STR-0008",
            "WebSocket upgrade context is missing",
            request_id,
        );
    };
    let (parts, _body) = request.into_parts();
    let mut handshake = format!("{} {mapped} HTTP/1.1\r\n", parts.method.as_str());
    // hyper consumes Connection/Upgrade while handling the upgrade, so they are
    // gone from the parsed headers; re-emit them so the CLI sees a valid
    // RFC 6455 handshake.
    handshake.push_str("connection: Upgrade\r\n");
    handshake.push_str("upgrade: websocket\r\n");
    for name in [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "accept",
        "openai-beta",
        "anthropic-version",
        "anthropic-beta",
        "x-codex-client",
    ] {
        if let Some(value) = parts.headers.get(name) {
            if let Ok(text) = value.to_str() {
                handshake.push_str(&format!("{name}: {text}\r\n"));
            }
        }
    }
    if let Some(host) = parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        handshake.push_str(&format!("host: {host}\r\n"));
    }
    handshake.push_str(&format!(
        "authorization: Bearer {}\r\n",
        state.local_key.as_str()
    ));
    handshake.push_str(&format!("x-request-id: {request_id}\r\n\r\n"));

    let cli_addr = cli_socket_addr(&state.cli_base);
    let mut cli = match tokio::net::TcpStream::connect(&cli_addr).await {
        Ok(stream) => stream,
        Err(_) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "CR-CLI-0004",
                "CLIProxyAPI failed while handling the request",
                request_id,
            );
        }
    };
    if tokio::io::AsyncWriteExt::write_all(&mut cli, handshake.as_bytes())
        .await
        .is_err()
    {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "CR-CLI-0004",
            "CLIProxyAPI failed while handling the request",
            request_id,
        );
    }
    let head = match read_response_head(&mut cli).await {
        Ok(head) => head,
        Err(_) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "CR-CLI-0004",
                "CLIProxyAPI failed while handling the request",
                request_id,
            );
        }
    };
    let head_text = String::from_utf8_lossy(&head);
    let status_line = head_text.lines().next().unwrap_or("");
    let upgraded_ok = status_line.contains(" 101")
        || status_line.starts_with("HTTP/1.1 101")
        || status_line.contains("101 Switching");
    if !upgraded_ok {
        // The CLI rejected the handshake; forward its response (including any
        // short body) to the client unchanged.
        let content_length = head_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body = if content_length > 0 && content_length <= 64 * 1024 {
            let mut body_bytes = Vec::with_capacity(content_length);
            let mut remaining = content_length;
            let mut chunk = [0u8; 1024];
            while remaining > 0 {
                let read = tokio::io::AsyncReadExt::read(&mut cli, &mut chunk)
                    .await
                    .unwrap_or(0);
                if read == 0 {
                    break;
                }
                let take = read.min(remaining);
                body_bytes.extend_from_slice(&chunk[..take]);
                remaining -= take;
            }
            Body::from(body_bytes)
        } else {
            Body::empty()
        };
        return response_from_raw_head(&head, request_id, body);
    }
    let separator = head
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(head.len());
    let leftover = head[separator..].to_vec();
    let head_only = &head[..separator];
    let response = response_from_raw_head(head_only, request_id, Body::empty());
    tokio::spawn(async move {
        let _ = relay_websocket(on_upgrade, cli, leftover).await;
    });
    response
}

async fn data_plane(State(state): State<HostState>, request: Request) -> Response {
    let started = Instant::now();
    let request_id = crate_request_id(&request);
    let terminal = TerminalSpanGuard::new(
        state.control.logger.clone(),
        request_id.clone(),
        format!("{} {}", request.method(), request.uri().path()),
    );
    if !data_plane_authorized(&state, &request) {
        let response = error_response(
            StatusCode::UNAUTHORIZED,
            "CR-AUT-0001",
            "missing valid Router API key",
            &request_id,
        );
        let _ = terminal.complete("unauthorized", Some(401), Some("CR-AUT-0001"), 1);
        return response;
    }
    let mapped = map_path(&request.uri().to_string());
    if is_websocket_upgrade(&request) {
        let response = proxy_websocket(&state, request, &mapped, &request_id).await;
        let _ = terminal.complete("ok", Some(101), None, 1);
        return response;
    }
    // Forced Antigravity pool: `/antigravity/v1*` shares the CLI data plane but
    // pool selection and the public catalog are constrained to provider
    // "antigravity" (manager doc 7.1).
    let (mapped, provider_constraint) = match mapped.strip_prefix("/antigravity") {
        Some(rest) if rest.starts_with("/v1") => (rest.to_owned(), Some("antigravity")),
        _ => (mapped, None),
    };
    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    if method == reqwest::Method::GET && mapped.split('?').next() == Some("/v1/models") {
        let has_routes = state
            .control
            .routes
            .read()
            .map(|table| !table.routes().is_empty())
            .unwrap_or(false);
        if has_routes {
            // A populated route table owns the public catalog; an empty one falls
            // through to the CLI native model list below.
            let _ = terminal.complete("ok", Some(200), None, 1);
            return public_models_response(&state, &request_id, provider_constraint);
        }
    }
    let session_header = request
        .headers()
        .get("x-codex-session")
        .or_else(|| request.headers().get("session_id"))
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let forward_headers = extract_headers(request.headers());
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "CR-REQ-0004",
                "request body is too large",
                &request_id,
            );
            let _ = terminal.complete("rejected", Some(413), Some("CR-REQ-0004"), 1);
            return response;
        }
    };
    let is_json = forward_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("json"));
    let mut failed_pools = HashSet::new();
    let request_path = mapped.clone();
    loop {
        let plan = if is_json
            && !bytes.is_empty()
            && matches!(method, reqwest::Method::POST | reqwest::Method::PUT)
        {
            match plan_request(
                &state,
                &bytes,
                session_header.as_deref(),
                extract_v1beta_model(&request_path),
                provider_constraint,
                &request_path,
                &failed_pools,
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    let status = StatusCode::from_u16(
                        error.get("status").and_then(Value::as_u64).unwrap_or(400) as u16,
                    )
                    .unwrap_or(StatusCode::BAD_REQUEST);
                    let code = error
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("CR-REQ-0006");
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("invalid request");
                    let response = error_response(status, code, message, &request_id);
                    let _ = terminal.complete("rejected", Some(status.as_u16()), Some(code), 1);
                    return response;
                }
            }
        } else {
            PlanResult {
                body: bytes.to_vec(),
                public_model: String::new(),
                pool_id: String::new(),
                pool_prefix: String::new(),
                upstream_model: String::new(),
                internal_model: String::new(),
                fresh_upstream_request_id: false,
            }
        };
        // Gemini v1beta carries the model in the URL path; rewrite it to the
        // internal `{prefix}/{public_model}` form after planning.
        let mapped =
            if !plan.internal_model.is_empty() && extract_v1beta_model(&request_path).is_some() {
                rewrite_v1beta_path_model(&request_path, &plan.internal_model)
            } else {
                request_path.clone()
            };
        let protocol = protocol_of(&mapped);
        if codex_router_lib::responses_compat::is_compact_path(&mapped)
            && !codex_router_lib::responses_compat::is_openai_family_model(&plan.public_model)
            && !codex_router_lib::responses_compat::is_xai_family_model(&plan.public_model)
        {
            if let Ok(json_body) = serde_json::from_slice::<Value>(&plan.body) {
                let output = json_body
                    .get("input")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let payload = codex_router_lib::responses_compat::synthetic_compact_response(
                    &plan.public_model,
                    &output,
                );
                record_ledger(
                    &state,
                    &usage_ledger::LedgerInput {
                        request_id: &request_id,
                        model: &plan.public_model,
                        pool_id: &plan.pool_id,
                        protocol: "responses",
                        status: "completed",
                        elapsed_ms: started.elapsed().as_millis() as i64,
                        ..Default::default()
                    },
                );
                let _ = terminal.complete("completed", Some(200), None, 1);
                let json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
                let res = axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .header("x-request-id", &request_id)
                    .body(axum::body::Body::from(json_bytes))
                    .unwrap_or_else(|_| (StatusCode::OK, "{}").into_response());
                return res;
            }
        }
        let url = format!("{}{}", state.cli_base, mapped);
        let upstream_request_id = if plan.fresh_upstream_request_id {
            structured_log::request_id()
        } else {
            request_id.clone()
        };
        let upstream_response = state
            .cli_data
            .request(method.clone(), &url)
            .headers(forward_headers.clone())
            .header(
                "authorization",
                format!("Bearer {}", state.local_key.as_str()),
            )
            .header("x-request-id", &upstream_request_id)
            .body(plan.body.clone())
            .send()
            .await;
        let upstream = match upstream_response {
            Ok(upstream) => upstream,
            Err(_) => {
                record_ledger(
                    &state,
                    &usage_ledger::LedgerInput {
                        request_id: &request_id,
                        model: &plan.public_model,
                        pool_id: &plan.pool_id,
                        protocol,
                        status: "failed",
                        elapsed_ms: started.elapsed().as_millis() as i64,
                        error_code: Some("CR-CLI-0004"),
                        ..Default::default()
                    },
                );
                let response = error_response(
                    StatusCode::BAD_GATEWAY,
                    "CR-CLI-0004",
                    "CLIProxyAPI failed while handling the request",
                    &request_id,
                );
                let _ = terminal.complete("upstream_error", Some(502), Some("CR-CLI-0004"), 1);
                return response;
            }
        };
        let upstream_status = upstream.status().as_u16();
        let shielded_auth = upstream_status == 401;
        if shielded_auth {
            let _ = state.control.logger.write(serde_json::json!({
            "level": "INFO",
            "event": "desktop.session.upstream_401_shielded",
            "error_code": codex_router_lib::control_plane::desktop_session::DSK_UPSTREAM_401_SHIELDED,
            "request_id": request_id,
            "public_model": plan.public_model,
            "upstream_status": 401,
            "forward_status": 503,
            "timestamp": structured_log::timestamp(),
        }));
        }
        let mut status_u16 = if shielded_auth { 503 } else { upstream_status };
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        let ledger_account = attribute_account(&state, upstream.headers());
        let mut response_headers = reqwest_to_axum_headers(upstream.headers());
        response_headers.remove("www-authenticate");
        response_headers.insert(
            "x-request-id",
            HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("invalid")),
        );
        let is_sse = upstream_status < 400
            && upstream
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("text/event-stream"));
        let elapsed = started.elapsed().as_millis() as i64;
        if is_sse {
            let rewriter =
                SseRewriter::new(&plan.pool_prefix, &plan.public_model, &plan.upstream_model);
            let context = SseContext {
                state: state.clone(),
                request_id: request_id.clone(),
                public_model: plan.public_model.clone(),
                pool_id: plan.pool_id.clone(),
                protocol: protocol.to_owned(),
                status_u16,
                account_id: ledger_account,
                terminal: Some(terminal),
            };
            let stream = wrap_sse_stream(upstream.bytes_stream(), rewriter, context, started);
            let mut builder = Response::builder().status(status);
            for (name, value) in response_headers.iter() {
                builder = builder.header(name, value);
            }
            return builder
                .body(Body::from_stream(stream))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
        } else {
            let body_bytes = match read_complete_response_body(upstream).await {
                Ok(body) => body,
                Err(_) => {
                    record_ledger(
                        &state,
                        &usage_ledger::LedgerInput {
                            request_id: &request_id,
                            model: &plan.public_model,
                            pool_id: &plan.pool_id,
                            account_id: ledger_account,
                            protocol,
                            status: "failed",
                            elapsed_ms: elapsed,
                            error_code: Some("CR-UP-0014"),
                            ..Default::default()
                        },
                    );
                    let _ = terminal.complete("upstream_error", Some(502), Some("CR-UP-0014"), 1);
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        "CR-UP-0014",
                        "upstream response body was interrupted",
                        &request_id,
                    );
                }
            };
            let failover_text = String::from_utf8_lossy(&body_bytes);
            // 503 `auth_unavailable: no auth available` means the CLIProxy
            // account pool behind this prefix has no usable credential. With
            // per-account prefixes (3.0.13+) a single dead OAuth account now
            // surfaces as this error, so it must fail over to the next pool
            // instead of ending the conversation -- but only when a fallback
            // pool actually exists (otherwise it is a real "no quota at all").
            let missing_auth =
                codex_router_lib::responses_compat::is_missing_provider_auth(&failover_text);
            let should_failover = !plan.public_model.is_empty()
                && (codex_router_lib::responses_compat::is_pool_failover_error(
                    upstream_status,
                    &failover_text,
                ) || missing_auth);
            if should_failover {
                failed_pools.insert(plan.pool_id.clone());
                let table = state
                    .control
                    .routes
                    .read()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
                if codex_router_lib::routing::has_fallback_pool(
                    &table,
                    &plan.public_model,
                    &failed_pools,
                ) {
                    let _ = state.control.logger.write(serde_json::json!({
                        "level": "INFO",
                        "event": "request.pool_failover",
                        "from_pool": plan.pool_id,
                        "public_model": plan.public_model,
                        "upstream_status": upstream_status,
                        "reason": if missing_auth { "auth_unavailable" } else { "pool_exhausted" },
                        "request_id": request_id,
                        "timestamp": structured_log::timestamp(),
                    }));
                    continue;
                }
                // Every pool for this model is unavailable right now. Surface
                // a WARN so the UI can tell the user the whole pool drained.
                if missing_auth {
                    let _ = state.control.logger.write(serde_json::json!({
                        "level": "WARN",
                        "event": "request.pool_unavailable",
                        "public_model": plan.public_model,
                        "upstream_status": upstream_status,
                        "reason": "auth_unavailable",
                        "request_id": request_id,
                        "timestamp": structured_log::timestamp(),
                    }));
                }
            }
            if upstream_status == 402 {
                status_u16 = 429;
            }
            let mut parsed: Option<Value> = serde_json::from_slice(&body_bytes).ok();
            if upstream_status == 402 {
                if let Some(body) = parsed.as_mut() {
                    if let Some(error) = body.get_mut("error").and_then(Value::as_object_mut) {
                        error.insert(
                            "message".to_owned(),
                            Value::String("usage limit reached".to_owned()),
                        );
                        error.insert("code".to_owned(), Value::String("usage_limit".to_owned()));
                    }
                }
            }
            if status_u16 == 503 {
                let missing_auth = parsed
                    .as_ref()
                    .and_then(|body| body.pointer("/error/message"))
                    .and_then(Value::as_str)
                    .is_some_and(codex_router_lib::responses_compat::is_missing_provider_auth);
                if missing_auth {
                    if let Some(hint) = antigravity_blocked_verification_message(&state).await {
                        if let Some(body) = parsed.as_mut() {
                            if let Some(error) =
                                body.get_mut("error").and_then(Value::as_object_mut)
                            {
                                error.insert("message".to_owned(), Value::String(hint));
                                error.insert(
                                    "code".to_owned(),
                                    Value::String("CR-UP-0003".to_owned()),
                                );
                            }
                        }
                        status_u16 = 403;
                    }
                }
            }
            let status = StatusCode::from_u16(status_u16).unwrap_or(status);
            if let Some(body) = parsed.as_mut() {
                if !plan.public_model.is_empty() {
                    let table = state
                        .control
                        .routes
                        .read()
                        .unwrap_or_else(|error| error.into_inner())
                        .clone();
                    if let Some(route) = table
                        .routes()
                        .iter()
                        .find(|route| route.prefix == plan.pool_prefix)
                    {
                        table.rewrite_response_model(body, route);
                    }
                }
                if !status.is_success() {
                    annotate_error_body(body, upstream_error_code(status_u16), &request_id);
                }
            }
            let mut output = parsed
                .as_ref()
                .map(|value| serde_json::to_vec(value).unwrap_or_else(|_| body_bytes.to_vec()))
                .unwrap_or_else(|| body_bytes.to_vec());
            if shielded_auth {
                output = serde_json::to_vec(&serde_json::json!({
                    "error": {
                        "message": "model temporarily unavailable",
                        "type": "codex_router_error",
                        "param": null,
                        "code": "CR-UP-0011"
                    },
                    "request_id": request_id
                }))
                .unwrap_or(output);
            }
            let ledger_status = if status.is_success() {
                "completed"
            } else {
                "failed"
            };
            let error_code = if status.is_success() {
                None
            } else {
                Some(upstream_error_code(status_u16))
            };
            record_ledger(
                &state,
                &usage_ledger::LedgerInput {
                    request_id: &request_id,
                    model: &plan.public_model,
                    pool_id: &plan.pool_id,
                    account_id: ledger_account,
                    protocol,
                    status: ledger_status,
                    body: parsed.as_ref(),
                    elapsed_ms: elapsed,
                    error_code,
                },
            );
            let _ = terminal.complete(
                if status.is_success() {
                    "ok"
                } else {
                    "upstream_error"
                },
                Some(status_u16),
                error_code,
                1,
            );
            let mut builder = Response::builder().status(status);
            for (name, value) in response_headers.iter() {
                builder = builder.header(name, value);
            }
            return builder
                .body(Body::from(output))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
        }
    }
}

async fn read_complete_response_body(
    response: reqwest::Response,
) -> std::result::Result<axum::body::Bytes, reqwest::Error> {
    response.bytes().await
}

struct SseContext {
    state: HostState,
    request_id: String,
    public_model: String,
    pool_id: String,
    protocol: String,
    status_u16: u16,
    account_id: Option<i64>,
    terminal: Option<TerminalSpanGuard>,
}

fn failed_sse_event(protocol: &str, request_id: &str, code: &str, message: &str) -> Vec<u8> {
    let payload = match protocol {
        "responses" => serde_json::json!({
            "type": "response.failed",
            "response": {
                "status": "failed",
                "error": {"code": code, "message": message},
            },
            "request_id": request_id,
        }),
        "anthropic" => serde_json::json!({
            "type": "error",
            "error": {"type": "api_error", "message": message, "code": code},
            "request_id": request_id,
        }),
        "gemini" => serde_json::json!({
            "error": {
                "code": 502,
                "status": "UNAVAILABLE",
                "message": message,
                "details": [{"error_code": code}],
            },
            "request_id": request_id,
        }),
        _ => serde_json::json!({
            "error": {
                "message": message,
                "type": "codex_router_error",
                "param": null,
                "code": code,
            },
            "request_id": request_id,
        }),
    };
    let event_name = match protocol {
        "responses" => "event: response.failed\n",
        "anthropic" => "event: error\n",
        _ => "",
    };
    format!(
        "{event_name}data: {}\n\n",
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_owned())
    )
    .into_bytes()
}

fn wrap_sse_stream<E>(
    upstream: impl futures_util::Stream<Item = std::result::Result<axum::body::Bytes, E>>
        + Send
        + Unpin
        + 'static,
    rewriter: SseRewriter,
    context: SseContext,
    started: Instant,
) -> impl futures_util::Stream<Item = std::result::Result<axum::body::Bytes, std::io::Error>>
       + Send
       + 'static
where
    E: Send + 'static,
{
    use futures_util::StreamExt;
    futures_util::stream::unfold(
        (upstream, rewriter, context, started, false),
        |(mut upstream, mut rewriter, mut context, started, terminated)| async move {
            if terminated {
                return None;
            }
            loop {
                match upstream.next().await {
                    Some(Ok(chunk)) => {
                        let out = rewriter.feed(&chunk);
                        if out.is_empty() {
                            continue;
                        }
                        return Some((
                            Ok(axum::body::Bytes::from(out)),
                            (upstream, rewriter, context, started, false),
                        ));
                    }
                    Some(Err(_)) => {
                        let mut out = rewriter.finish();
                        out.extend_from_slice(&failed_sse_event(
                            &context.protocol,
                            &context.request_id,
                            "CR-UP-0014",
                            "upstream stream failed before a terminal event",
                        ));
                        record_ledger(
                            &context.state,
                            &usage_ledger::LedgerInput {
                                request_id: &context.request_id,
                                model: &context.public_model,
                                pool_id: &context.pool_id,
                                protocol: &context.protocol,
                                status: "failed",
                                account_id: context.account_id,
                                elapsed_ms: started.elapsed().as_millis() as i64,
                                error_code: Some("CR-UP-0014"),
                                ..Default::default()
                            },
                        );
                        if let Some(terminal) = context.terminal.take() {
                            let _ = terminal.complete(
                                "upstream_error",
                                Some(context.status_u16),
                                Some("CR-UP-0014"),
                                1,
                            );
                        }
                        let state_tuple = (upstream, rewriter, context, started, true);
                        return Some((Ok(axum::body::Bytes::from(out)), state_tuple));
                    }
                    None => {
                        let mut out = rewriter.finish();
                        let terminal_seen = rewriter.terminal_seen.as_deref();
                        let usage_body = rewriter
                            .usage
                            .as_ref()
                            .map(|usage| serde_json::json!({"usage": usage}));
                        let http_ok = (200..300).contains(&context.status_u16);
                        let terminal_ok = terminal_seen.is_some_and(|terminal| {
                            terminal == "done"
                                || terminal == "message_stop"
                                || terminal == "gemini.finished"
                                || terminal.ends_with(".completed")
                        });
                        let ok = http_ok && terminal_ok;
                        let status = if ok { "completed" } else { "failed" };
                        let error_code = if ok {
                            None
                        } else if http_ok {
                            Some("CR-UP-0014")
                        } else {
                            Some(upstream_error_code(context.status_u16))
                        };
                        if terminal_seen.is_none() {
                            out.extend_from_slice(&failed_sse_event(
                                &context.protocol,
                                &context.request_id,
                                error_code.unwrap_or("CR-UP-0014"),
                                "upstream stream ended before a terminal event",
                            ));
                        }
                        record_ledger(
                            &context.state,
                            &usage_ledger::LedgerInput {
                                request_id: &context.request_id,
                                model: &context.public_model,
                                pool_id: &context.pool_id,
                                protocol: &context.protocol,
                                status,
                                account_id: context.account_id,
                                body: usage_body.as_ref(),
                                elapsed_ms: started.elapsed().as_millis() as i64,
                                error_code,
                            },
                        );
                        if let Some(terminal) = context.terminal.take() {
                            let _ = terminal.complete(
                                if ok { "ok" } else { "upstream_error" },
                                Some(context.status_u16),
                                error_code,
                                1,
                            );
                        }
                        if out.is_empty() {
                            return None;
                        }
                        return Some((
                            Ok(axum::body::Bytes::from(out)),
                            (upstream, rewriter, context, started, true),
                        ));
                    }
                }
            }
        },
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let root = router_root();
    codex_router_lib::credentials::set_scope_from_root(&root);
    let state_root = router_state_root();
    let data_root = state_root.join("data");
    let public_port = argument_value("--host-port=")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PUBLIC_PORT);
    let private_port = argument_value("--cli-port=")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PRIVATE_PORT);
    let desktop_auth_path = argument_value("--desktop-auth=")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".codex")
                .join("auth.json")
        });
    let no_cli = std::env::args().any(|argument| argument == "--no-cli");
    let logs = state_root.join("logs");
    std::fs::create_dir_all(&logs)?;
    let auth_dir = data_root.join("cli-proxy").join("auth");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::create_dir_all(
        root.join("app")
            .join("plugins")
            .join("windows")
            .join("amd64"),
    )?;
    let local_key = ensure_local_api_key()?;
    let management_secret = ensure_management_secret()?;
    let _admin_password = ensure_admin_password()?;
    let config_path = data_root.join("cli-proxy").join("config.yaml");
    if !config_path.is_file() {
        let runtime_config =
            default_runtime_config(&local_key, &management_secret, private_port, &auth_dir);
        write_runtime_config(&config_path, &runtime_config)?;
    } else {
        reconcile_runtime_config(
            &config_path,
            &local_key,
            &management_secret,
            private_port,
            &auth_dir,
        )?;
    }
    let store = StateStore::open(data_root.join("router-state.sqlite3"))?;
    let logger = Arc::new(StructuredLogger::open(logs.join("router-events.jsonl"))?);
    let cli = CliProxyManagementClient::new(
        format!("http://127.0.0.1:{private_port}"),
        management_secret.as_str(),
    )?;
    let control = ControlState {
        store: Arc::new(store),
        cli: cli.clone(),
        logger: logger.clone(),
        routes: Arc::new(RwLock::new(RouteTable::new(Vec::new())?)),
        cli_index_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
        backend: Some(Arc::new(compat::BackendPaths {
            config_path: config_path.clone(),
            auth_dir: auth_dir.clone(),
            downstream_key: local_key.to_string(),
            management_secret: management_secret.to_string(),
            cli_port: private_port,
            desktop_auth_path,
        })),
    };
    // Compile state-derived routing and configuration before traffic arrives.
    if let Err(error) = compat::sync_backend(&control).await {
        let _ = logger.write(serde_json::json!({"level":"ERROR","event":"backend.initial_sync_failed","error_description":error.to_string()}));
    }
    let mut child = None;
    if !no_cli {
        let spawned = start_cli(&root, &config_path).await?;
        child = Some(spawned);
        if let Err(error) = wait_cli_ready(&cli).await {
            let _ = logger.write(serde_json::json!({"level":"ERROR","event":"backend.cli_health_timeout","error_description":error.to_string()}));
            return Err(error);
        }
        // Re-sync after CLI is healthy so live file indexes and watcher registries attach immediately.
        let _ = compat::sync_backend(&control).await;
    }
    tokio::spawn(scheduler::run(control.clone()));
    let state = HostState {
        control,
        local_key: Arc::new(local_key),
        bindings: Arc::new(Mutex::new(ContinuationBindings::new())),
        cli_base: Arc::new(format!("http://127.0.0.1:{private_port}")),
        cli_child: Arc::new(Mutex::new(child)),
        cli_data: reqwest::Client::builder().no_proxy().build()?,
    };
    let app = public_router(state.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", public_port)).await?;
    println!("CodexRouter Host listening on http://127.0.0.1:{public_port}");
    let shutdown_child = state.cli_child.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            let child = shutdown_child
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            if let Some(mut child) = child {
                let _ = child.kill().await;
            }
        })
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy data adapters: usage, billing, embeddings, async images and batches
// ---------------------------------------------------------------------------

fn json_data_response(status: StatusCode, body: Value, request_id: &str) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn authorize_data_request(
    state: &HostState,
    request: &Request,
    request_id: &str,
) -> Option<Response> {
    if data_plane_authorized(state, request) {
        None
    } else {
        Some(error_response(
            StatusCode::UNAUTHORIZED,
            "CR-AUT-0001",
            "missing valid Router API key",
            request_id,
        ))
    }
}

async fn read_json_body(
    request: Request,
    request_id: &str,
) -> std::result::Result<Value, Box<Response>> {
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(Box::new(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "CR-REQ-0004",
                "request body is too large",
                request_id,
            )));
        }
    };
    serde_json::from_slice(&bytes).map_err(|_| {
        Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "CR-REQ-0006",
            "request body is not valid JSON",
            request_id,
        ))
    })
}

/// Pick an available pool for a public model. These legacy adapters carry no
/// conversation continuation, so selection is stateless; availability still
/// distinguishes "no route" (CR-RTE-0001) from "all credentials paused"
/// (CR-RTE-0002).
fn select_available_pool(
    state: &HostState,
    model: &str,
) -> std::result::Result<PoolRoute, (StatusCode, &'static str, String)> {
    let table = state
        .control
        .routes
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if table.pools(model).is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "CR-RTE-0001",
            format!("no route for model {model}"),
        ));
    }
    let bindings = state
        .bindings
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    codex_router_lib::routing::select_pool(&table, model, None, &bindings, &HashSet::new())
        .cloned()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CR-RTE-0002",
                "route exists but every credential is paused".to_owned(),
            )
        })
}

async fn data_usage(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    match data_ops::usage_by_model(&state.control.store) {
        Ok(body) => json_data_response(StatusCode::OK, body, &request_id),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "usage aggregation failed",
            &request_id,
        ),
    }
}

async fn data_billing(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    json_data_response(StatusCode::OK, data_ops::key_billing_info(), &request_id)
}
async fn data_embeddings(State(state): State<HostState>, request: Request) -> Response {
    let started = Instant::now();
    let request_id = crate_request_id(&request);
    let terminal = TerminalSpanGuard::new(
        state.control.logger.clone(),
        request_id.clone(),
        format!("{} {}", request.method(), request.uri().path()),
    );
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        let _ = terminal.complete("unauthorized", Some(401), Some("CR-AUT-0001"), 1);
        return denied;
    }
    let mut parsed = match read_json_body(request, &request_id).await {
        Ok(value) => value,
        Err(response) => {
            let _ = terminal.complete("rejected", Some(400), Some("CR-REQ-0006"), 1);
            return *response;
        }
    };
    let Some(model) = parsed
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0001"), 1);
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0001",
            "model is required",
            &request_id,
        );
    };
    let selected = match select_available_pool(&state, &model) {
        Ok(route) => route,
        Err((status, code, message)) => {
            let _ = terminal.complete("rejected", Some(status.as_u16()), Some(code), 1);
            return error_response(status, code, &message, &request_id);
        }
    };
    let channel =
        match data_ops::resolve_pool_direct_channel(&state.control.store, &selected.pool_id) {
            Ok(Some(channel)) => channel,
            _ => {
                let _ = terminal.complete("rejected", Some(422), Some("CR-VAL-0004"), 1);
                return error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "CR-VAL-0004",
                    "embeddings requires an API-key backed channel for this model",
                    &request_id,
                );
            }
        };
    parsed["model"] = Value::String(selected.upstream_model.clone());
    let url = format!("{}/embeddings", channel.base_url.trim_end_matches('/'));
    let upstream = state
        .cli_data
        .post(&url)
        .bearer_auth(channel.api_key.trim())
        .header("x-request-id", &request_id)
        .json(&parsed)
        .send()
        .await;
    let elapsed = started.elapsed().as_millis() as i64;
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(_) => {
            record_ledger(
                &state,
                &usage_ledger::LedgerInput {
                    request_id: &request_id,
                    model: &model,
                    pool_id: &selected.pool_id,
                    account_id: Some(channel.account_id),
                    protocol: "embeddings",
                    status: "failed",
                    elapsed_ms: elapsed,
                    error_code: Some("CR-UP-0010"),
                    ..Default::default()
                },
            );
            let _ = terminal.complete("upstream_error", Some(502), Some("CR-UP-0010"), 1);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "CR-UP-0010",
                "embedding upstream is unreachable",
                &request_id,
            );
        }
    };
    let status_u16 = upstream.status().as_u16();
    let body_bytes = upstream.bytes().await.unwrap_or_default();
    let mut body: Value = serde_json::from_slice(&body_bytes)
        .unwrap_or_else(|_| serde_json::json!({"raw": String::from_utf8_lossy(&body_bytes)}));
    let succeeded = (200..300).contains(&status_u16);
    if succeeded {
        body["model"] = Value::String(model.clone());
    }
    record_ledger(
        &state,
        &usage_ledger::LedgerInput {
            request_id: &request_id,
            model: &model,
            pool_id: &selected.pool_id,
            account_id: Some(channel.account_id),
            protocol: "embeddings",
            status: if succeeded { "completed" } else { "failed" },
            body: Some(&body),
            elapsed_ms: elapsed,
            error_code: if succeeded {
                None
            } else {
                Some(upstream_error_code(status_u16))
            },
        },
    );
    let _ = terminal.complete(
        if succeeded { "ok" } else { "upstream_error" },
        Some(status_u16),
        if succeeded {
            None
        } else {
            Some(upstream_error_code(status_u16))
        },
        1,
    );
    let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
    json_data_response(status, body, &request_id)
}
// ---------------------------------------------------------------------------
// Async image tasks
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ImageJobKind {
    Generation,
    Edit,
}

impl ImageJobKind {
    fn task_kind(self) -> &'static str {
        match self {
            Self::Generation => "generation",
            Self::Edit => "edit",
        }
    }

    fn cli_path(self) -> &'static str {
        match self {
            Self::Generation => "/v1/images/generations",
            Self::Edit => "/v1/images/edits",
        }
    }
}

async fn image_async_generate(State(state): State<HostState>, request: Request) -> Response {
    image_async_submit(state, request, ImageJobKind::Generation).await
}

async fn image_async_edit(State(state): State<HostState>, request: Request) -> Response {
    image_async_submit(state, request, ImageJobKind::Edit).await
}

async fn image_async_submit(state: HostState, request: Request, kind: ImageJobKind) -> Response {
    let request_id = crate_request_id(&request);
    let terminal = TerminalSpanGuard::new(
        state.control.logger.clone(),
        request_id.clone(),
        format!("{} {}", request.method(), request.uri().path()),
    );
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        let _ = terminal.complete("unauthorized", Some(401), Some("CR-AUT-0001"), 1);
        return denied;
    }
    let mut parsed = match read_json_body(request, &request_id).await {
        Ok(value) => value,
        Err(response) => {
            let _ = terminal.complete("rejected", Some(400), Some("CR-REQ-0006"), 1);
            return *response;
        }
    };
    let Some(model) = parsed
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0001"), 1);
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0001",
            "model is required",
            &request_id,
        );
    };
    let selected = match select_available_pool(&state, &model) {
        Ok(route) => route,
        Err((status, code, message)) => {
            let _ = terminal.complete("rejected", Some(status.as_u16()), Some(code), 1);
            return error_response(status, code, &message, &request_id);
        }
    };
    let rewritten = {
        let table = state
            .control
            .routes
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        table.rewrite_request_model(&model, &selected)
    };
    parsed["model"] = Value::String(rewritten);
    let body = match serde_json::to_vec(&parsed) {
        Ok(body) => body,
        Err(_) => {
            let _ = terminal.complete("rejected", Some(400), Some("CR-REQ-0006"), 1);
            return error_response(
                StatusCode::BAD_REQUEST,
                "CR-REQ-0006",
                "could not encode request",
                &request_id,
            );
        }
    };
    let task_id = match data_ops::image_task_create(&state.control.store, kind.task_kind(), &model)
    {
        Ok(task_id) => task_id,
        Err(_) => {
            let _ = terminal.complete("failed", Some(500), Some("CR-STO-0004"), 1);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0004",
                "could not create image task",
                &request_id,
            );
        }
    };
    let output_name = format!("{task_id}.json");
    let job = ImageJob {
        state: state.clone(),
        job_id: task_id.clone(),
        request_id: format!("task-{task_id}"),
        cli_path: kind.cli_path(),
        public_model: model.clone(),
        pool_id: selected.pool_id.clone(),
        pool_prefix: selected.prefix.clone(),
        upstream_model: selected.upstream_model.clone(),
    };
    tokio::spawn(async move {
        run_image_job(job, body, output_name).await;
    });
    let _ = terminal.complete("accepted", Some(202), None, 1);
    json_data_response(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "id": task_id,
            "object": "image_task",
            "kind": kind.task_kind(),
            "status": "queued",
            "model": model,
        }),
        &request_id,
    )
}
struct ImageJob {
    state: HostState,
    job_id: String,
    request_id: String,
    cli_path: &'static str,
    public_model: String,
    pool_id: String,
    pool_prefix: String,
    upstream_model: String,
}

impl ImageJob {
    fn ledger(
        &self,
        status: &'static str,
        body: Option<&Value>,
        error_code: Option<&'static str>,
        account_id: Option<i64>,
    ) {
        record_ledger(
            &self.state,
            &usage_ledger::LedgerInput {
                request_id: &self.request_id,
                model: &self.public_model,
                pool_id: &self.pool_id,
                account_id,
                protocol: "images",
                status,
                body,
                elapsed_ms: 0,
                error_code,
            },
        );
    }
}

/// Replace internal/upstream model strings inside an upstream payload with
/// the public model, mirroring the SSE rewriter semantics for JSON bodies.
fn rewrite_model_strings(
    value: &mut Value,
    pool_prefix: &str,
    public_model: &str,
    upstream_model: &str,
) {
    let internal = format!("{pool_prefix}/{public_model}");
    match value {
        Value::String(text) => {
            if *text == internal
                || *text == upstream_model
                || text.starts_with(&format!("{internal}/"))
            {
                *text = public_model.to_owned();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| {
            rewrite_model_strings(item, pool_prefix, public_model, upstream_model)
        }),
        Value::Object(object) => object.values_mut().for_each(|item| {
            rewrite_model_strings(item, pool_prefix, public_model, upstream_model)
        }),
        _ => {}
    }
}

/// Persist an upstream payload as the task output file under the task dir.
fn store_job_output(output_name: &str, parsed: &Value) -> std::result::Result<(), anyhow::Error> {
    let path = data_ops::task_output_path(&router_state_root(), output_name)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(parsed).unwrap_or_default())
        .with_context(|| format!("write {}", path.display()))
}

async fn run_image_job(job: ImageJob, body: Vec<u8>, output_name: String) {
    let store = &job.state.control.store;
    let _ = data_ops::image_task_status(store, &job.job_id, "running", None, None);
    let upstream = job
        .state
        .cli_data
        .post(format!("{}{}", job.state.cli_base, job.cli_path))
        .header(
            "authorization",
            format!("Bearer {}", job.state.local_key.as_str()),
        )
        .header("content-type", "application/json")
        .header("x-request-id", &job.request_id)
        .body(body)
        .send()
        .await;
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(_) => {
            let _ = data_ops::image_task_status(
                store,
                &job.job_id,
                "failed",
                None,
                Some("CR-CLI-0004"),
            );
            job.ledger("failed", None, Some("CR-CLI-0004"), None);
            return;
        }
    };
    let status = upstream.status().as_u16();
    let account = attribute_account(&job.state, upstream.headers());
    let bytes = upstream.bytes().await.unwrap_or_default();
    let mut parsed: Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));
    if !(200..300).contains(&status) {
        let code = upstream_error_code(status);
        let _ = data_ops::image_task_status(store, &job.job_id, "failed", None, Some(code));
        job.ledger("failed", Some(&parsed), Some(code), account);
        return;
    }
    rewrite_model_strings(
        &mut parsed,
        &job.pool_prefix,
        &job.public_model,
        &job.upstream_model,
    );
    let (final_status, output_ref, error_code) = match store_job_output(&output_name, &parsed) {
        Ok(()) => ("completed", Some(output_name.as_str()), None),
        Err(_) => ("failed", None, Some("CR-STO-0011")),
    };
    let _ = data_ops::image_task_status(store, &job.job_id, final_status, output_ref, error_code);
    job.ledger(final_status, Some(&parsed), error_code, account);
}

async fn image_task_show(
    State(state): State<HostState>,
    AxumPath(task_id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    if data_ops::safe_task_id(&task_id).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0006",
            "unsafe task id",
            &request_id,
        );
    }
    let mut task = match data_ops::image_task_get(&state.control.store, &task_id) {
        Ok(Some(task)) => task,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "CR-REQ-0009",
                "image task not found",
                &request_id,
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0003",
                "task lookup failed",
                &request_id,
            );
        }
    };
    if task["status"] == "completed" {
        if let Some(output_ref) = task["output_ref"].as_str() {
            if let Ok(path) = data_ops::task_output_path(&router_state_root(), output_ref) {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(result) = serde_json::from_slice::<Value>(&bytes) {
                        task["result"] = result;
                    }
                }
            }
        }
    }
    json_data_response(StatusCode::OK, task, &request_id)
}
// ---------------------------------------------------------------------------
// Image batches
// ---------------------------------------------------------------------------

async fn image_batches_list(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    match data_ops::image_batch_list(&state.control.store) {
        Ok(body) => json_data_response(StatusCode::OK, body, &request_id),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "batch list failed",
            &request_id,
        ),
    }
}

async fn image_batch_models(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    let table = state
        .control
        .routes
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let mut models = std::collections::BTreeSet::new();
    for route in table.routes() {
        if config_compiler::is_image_model(&route.upstream_model) {
            models.insert(route.public_model.clone());
        }
    }
    let data: Vec<Value> = models
        .into_iter()
        .map(|model| {
            serde_json::json!({"id": model, "object": "model", "created": 0, "owned_by": "codex-router"})
        })
        .collect();
    json_data_response(
        StatusCode::OK,
        serde_json::json!({"object": "list", "data": data}),
        &request_id,
    )
}

async fn image_batch_submit(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    let terminal = TerminalSpanGuard::new(
        state.control.logger.clone(),
        request_id.clone(),
        format!("{} {}", request.method(), request.uri().path()),
    );
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        let _ = terminal.complete("unauthorized", Some(401), Some("CR-AUT-0001"), 1);
        return denied;
    }
    let parsed = match read_json_body(request, &request_id).await {
        Ok(value) => value,
        Err(response) => {
            let _ = terminal.complete("rejected", Some(400), Some("CR-REQ-0006"), 1);
            return *response;
        }
    };
    let Some(model) = parsed
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0001"), 1);
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0001",
            "model is required",
            &request_id,
        );
    };
    let empty = Vec::new();
    let items = parsed
        .get("items")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    if items.is_empty() {
        let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0003"), 1);
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "items must be a non-empty array",
            &request_id,
        );
    }
    let selected = match select_available_pool(&state, &model) {
        Ok(route) => route,
        Err((status, code, message)) => {
            let _ = terminal.complete("rejected", Some(status.as_u16()), Some(code), 1);
            return error_response(status, code, &message, &request_id);
        }
    };
    let rewritten = {
        let table = state
            .control
            .routes
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        table.rewrite_request_model(&model, &selected)
    };
    let mut custom_ids = Vec::with_capacity(items.len());
    let mut jobs = Vec::with_capacity(items.len());
    for item in items {
        let Some(custom_id) = item.get("custom_id").and_then(Value::as_str) else {
            let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0003"), 1);
            return error_response(
                StatusCode::BAD_REQUEST,
                "CR-VAL-0003",
                "each item requires a string custom_id",
                &request_id,
            );
        };
        if data_ops::safe_task_id(custom_id).is_err() {
            let _ = terminal.complete("rejected", Some(400), Some("CR-VAL-0006"), 1);
            return error_response(
                StatusCode::BAD_REQUEST,
                "CR-VAL-0006",
                "unsafe custom_id",
                &request_id,
            );
        }
        let mut payload = item.clone();
        if let Some(object) = payload.as_object_mut() {
            object.remove("custom_id");
            object.insert("model".to_owned(), Value::String(rewritten.clone()));
        }
        let Ok(body) = serde_json::to_vec(&payload) else {
            let _ = terminal.complete("rejected", Some(400), Some("CR-REQ-0006"), 1);
            return error_response(
                StatusCode::BAD_REQUEST,
                "CR-REQ-0006",
                "could not encode batch item",
                &request_id,
            );
        };
        custom_ids.push(custom_id.to_owned());
        jobs.push((custom_id.to_owned(), body));
    }
    let batch_id = match data_ops::image_batch_create(&state.control.store, &model, &custom_ids) {
        Ok(batch_id) => batch_id,
        Err(_) => {
            let _ = terminal.complete("failed", Some(500), Some("CR-STO-0004"), 1);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0004",
                "could not create image batch",
                &request_id,
            );
        }
    };
    let job = ImageBatchJob {
        state: state.clone(),
        batch_id: batch_id.clone(),
        public_model: model.clone(),
        pool_id: selected.pool_id.clone(),
        pool_prefix: selected.prefix.clone(),
        upstream_model: selected.upstream_model.clone(),
    };
    tokio::spawn(async move {
        run_image_batch(job, jobs).await;
    });
    let _ = terminal.complete("accepted", Some(202), None, 1);
    json_data_response(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "id": batch_id,
            "object": "image_batch",
            "status": "queued",
            "model": model,
        }),
        &request_id,
    )
}

struct ImageBatchJob {
    state: HostState,
    batch_id: String,
    public_model: String,
    pool_id: String,
    pool_prefix: String,
    upstream_model: String,
}

fn batch_item_state(batch: &Value, custom_id: &str) -> Option<String> {
    batch["items"].as_array()?.iter().find_map(|row| {
        if row["custom_id"].as_str() == Some(custom_id) {
            row["status"].as_str().map(str::to_owned)
        } else {
            None
        }
    })
}
async fn run_image_batch(job: ImageBatchJob, items: Vec<(String, Vec<u8>)>) {
    let store = &job.state.control.store;
    let _ = data_ops::image_batch_start(store, &job.batch_id);
    for (custom_id, body) in &items {
        let still_queued = data_ops::image_batch_get(store, &job.batch_id)
            .ok()
            .flatten()
            .and_then(|batch| batch_item_state(&batch, custom_id))
            .is_some_and(|status| status == "queued");
        if !still_queued {
            // Cancelled (or deleted) while earlier items were running.
            continue;
        }
        let _ = data_ops::image_batch_item_update(
            store,
            &job.batch_id,
            custom_id,
            "running",
            None,
            None,
        );
        let request_id = format!("batch-{}-{custom_id}", job.batch_id);
        let upstream = job
            .state
            .cli_data
            .post(format!("{}/v1/images/generations", job.state.cli_base))
            .header(
                "authorization",
                format!("Bearer {}", job.state.local_key.as_str()),
            )
            .header("content-type", "application/json")
            .header("x-request-id", &request_id)
            .body(body.clone())
            .send()
            .await;
        let upstream = match upstream {
            Ok(upstream) => upstream,
            Err(_) => {
                let _ = data_ops::image_batch_item_update(
                    store,
                    &job.batch_id,
                    custom_id,
                    "failed",
                    None,
                    Some("CR-CLI-0004"),
                );
                record_ledger(
                    &job.state,
                    &usage_ledger::LedgerInput {
                        request_id: &request_id,
                        model: &job.public_model,
                        pool_id: &job.pool_id,
                        protocol: "images",
                        status: "failed",
                        error_code: Some("CR-CLI-0004"),
                        ..Default::default()
                    },
                );
                continue;
            }
        };
        let status = upstream.status().as_u16();
        let account = attribute_account(&job.state, upstream.headers());
        let bytes = upstream.bytes().await.unwrap_or_default();
        let mut parsed: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));
        if !(200..300).contains(&status) {
            let code = upstream_error_code(status);
            let _ = data_ops::image_batch_item_update(
                store,
                &job.batch_id,
                custom_id,
                "failed",
                None,
                Some(code),
            );
            record_ledger(
                &job.state,
                &usage_ledger::LedgerInput {
                    request_id: &request_id,
                    model: &job.public_model,
                    pool_id: &job.pool_id,
                    account_id: account,
                    protocol: "images",
                    status: "failed",
                    body: Some(&parsed),
                    error_code: Some(code),
                    ..Default::default()
                },
            );
            continue;
        }
        rewrite_model_strings(
            &mut parsed,
            &job.pool_prefix,
            &job.public_model,
            &job.upstream_model,
        );
        let output_name = format!("{}__{custom_id}.json", job.batch_id);
        let (final_status, output_ref, error_code) = match store_job_output(&output_name, &parsed) {
            Ok(()) => ("completed", Some(output_name.as_str()), None),
            Err(_) => ("failed", None, Some("CR-STO-0011")),
        };
        let _ = data_ops::image_batch_item_update(
            store,
            &job.batch_id,
            custom_id,
            final_status,
            output_ref,
            error_code,
        );
        record_ledger(
            &job.state,
            &usage_ledger::LedgerInput {
                request_id: &request_id,
                model: &job.public_model,
                pool_id: &job.pool_id,
                account_id: account,
                protocol: "images",
                status: final_status,
                body: Some(&parsed),
                error_code,
                ..Default::default()
            },
        );
    }
    let final_status = data_ops::image_batch_get(store, &job.batch_id)
        .ok()
        .flatten()
        .map(|batch| {
            let rows = batch["items"].as_array().cloned().unwrap_or_default();
            let total = rows.len();
            let cancelled = rows
                .iter()
                .filter(|row| row["status"] == "cancelled")
                .count();
            let failed = rows.iter().filter(|row| row["status"] == "failed").count();
            if total > 0 && cancelled == total {
                "cancelled"
            } else if total > 0 && failed == total {
                "failed"
            } else {
                "completed"
            }
        })
        .unwrap_or("completed");
    let _ = data_ops::image_batch_finish(store, &job.batch_id, final_status);
}

// The Err payload is an already-built axum response; boxing it through every
// batch call site adds noise without changing behavior, so allow the lint.
#[allow(clippy::result_large_err)]
fn load_batch(
    state: &HostState,
    id: &str,
    request_id: &str,
) -> std::result::Result<Value, Response> {
    if data_ops::safe_task_id(id).is_err() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0006",
            "unsafe batch id",
            request_id,
        ));
    }
    match data_ops::image_batch_get(&state.control.store, id) {
        Ok(Some(batch)) => Ok(batch),
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "CR-REQ-0009",
            "image batch not found",
            request_id,
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "batch lookup failed",
            request_id,
        )),
    }
}

async fn image_batch_show(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    match load_batch(&state, &id, &request_id) {
        Ok(batch) => json_data_response(StatusCode::OK, batch, &request_id),
        Err(response) => response,
    }
}

async fn image_batch_items(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    match load_batch(&state, &id, &request_id) {
        Ok(batch) => {
            let items = batch["items"].clone();
            json_data_response(
                StatusCode::OK,
                serde_json::json!({"object": "list", "data": items}),
                &request_id,
            )
        }
        Err(response) => response,
    }
}
async fn image_batch_item_content(
    State(state): State<HostState>,
    AxumPath((id, custom_id)): AxumPath<(String, String)>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    if data_ops::safe_task_id(&custom_id).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0006",
            "unsafe custom_id",
            &request_id,
        );
    }
    let batch = match load_batch(&state, &id, &request_id) {
        Ok(batch) => batch,
        Err(response) => return response,
    };
    let item = batch["items"].as_array().and_then(|rows| {
        rows.iter()
            .find(|row| row["custom_id"].as_str() == Some(custom_id.as_str()))
            .cloned()
    });
    let Some(item) = item else {
        return error_response(
            StatusCode::NOT_FOUND,
            "CR-REQ-0009",
            "batch item not found",
            &request_id,
        );
    };
    let Some(output_ref) = item["output_ref"].as_str() else {
        return error_response(
            StatusCode::NOT_FOUND,
            "CR-REQ-0009",
            "batch item has no stored output",
            &request_id,
        );
    };
    let Ok(path) = data_ops::task_output_path(&router_state_root(), output_ref) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0006",
            "unsafe output reference",
            &request_id,
        );
    };
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(body) => json_data_response(StatusCode::OK, body, &request_id),
            Err(_) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0011",
                "stored output is not valid JSON",
                &request_id,
            ),
        },
        Err(_) => error_response(
            StatusCode::NOT_FOUND,
            "CR-REQ-0009",
            "stored output file is missing",
            &request_id,
        ),
    }
}

/// Bound for one batch download archive; larger batches must be fetched
/// item-by-item through the content endpoint instead.
const MAX_BATCH_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Manager doc 7.1: the batch download endpoint streams a zip archive of every
/// completed item. The output files are stored JSON and are added as
/// `{custom_id}.json` entries; entry names are sanitized so a hostile custom_id
/// cannot plant a path-traversal entry inside the archive.
fn sanitize_zip_entry_name(custom_id: &str) -> String {
    let sanitized: String = custom_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches(|character| character == '.' || character == '_');
    if trimmed.is_empty() {
        "item".to_owned()
    } else {
        trimmed.to_owned()
    }
}

async fn image_batch_download(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    let batch = match load_batch(&state, &id, &request_id) {
        Ok(batch) => batch,
        Err(response) => return response,
    };
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut total_bytes = 0usize;
    if let Some(rows) = batch["items"].as_array() {
        for row in rows {
            if row["status"] != "completed" {
                continue;
            }
            let Some(output_ref) = row["output_ref"].as_str() else {
                continue;
            };
            let Ok(path) = data_ops::task_output_path(&router_state_root(), output_ref) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(output) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            let custom_id = row["custom_id"].as_str().unwrap_or("item");
            let entry_bytes = serde_json::to_vec(&output).unwrap_or_default();
            total_bytes = total_bytes.saturating_add(entry_bytes.len());
            if total_bytes > MAX_BATCH_DOWNLOAD_BYTES {
                return error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "CR-REQ-0004",
                    "batch download exceeds the 256 MiB size limit; fetch items individually",
                    &request_id,
                );
            }
            let _ = writer.start_file(
                format!("{}.json", sanitize_zip_entry_name(custom_id)),
                options,
            );
            let _ = writer.write_all(&entry_bytes);
        }
    }
    let body = match writer.finish() {
        Ok(cursor) => cursor.into_inner(),
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0011",
                "could not build the batch download archive",
                &request_id,
            );
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/zip")
        .header(
            "content-disposition",
            format!("attachment; filename=\"batch-{id}.zip\""),
        )
        .header("content-length", body.len().to_string())
        .header("x-request-id", &request_id)
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn image_batch_cancel(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    if let Err(response) = load_batch(&state, &id, &request_id) {
        return response;
    }
    let _ = data_ops::image_batch_cancel_pending(&state.control.store, &id);
    // When nothing is left running the worker will not finalize the batch, so
    // the cancel call itself settles the terminal state.
    if let Ok(batch) = load_batch(&state, &id, &request_id) {
        let rows = batch["items"].as_array().cloned().unwrap_or_default();
        let active = rows
            .iter()
            .any(|row| row["status"] == "queued" || row["status"] == "running");
        if !active {
            let any_completed = rows.iter().any(|row| row["status"] == "completed");
            let status = if any_completed {
                "completed"
            } else {
                "cancelled"
            };
            let _ = data_ops::image_batch_finish(&state.control.store, &id, status);
        }
    }
    match load_batch(&state, &id, &request_id) {
        Ok(batch) => json_data_response(StatusCode::OK, batch, &request_id),
        Err(response) => response,
    }
}

async fn image_batch_remove(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    if data_ops::safe_task_id(&id).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0006",
            "unsafe batch id",
            &request_id,
        );
    }
    if let Ok(Some(batch)) = data_ops::image_batch_get(&state.control.store, &id) {
        remove_batch_files(&batch);
    }
    match data_ops::image_batch_delete(&state.control.store, &id) {
        Ok(0) => error_response(
            StatusCode::NOT_FOUND,
            "CR-REQ-0009",
            "image batch not found",
            &request_id,
        ),
        Ok(_) => json_data_response(
            StatusCode::OK,
            serde_json::json!({"id": id, "deleted": true}),
            &request_id,
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "batch delete failed",
            &request_id,
        ),
    }
}

fn remove_batch_files(batch: &Value) {
    if let Some(rows) = batch["items"].as_array() {
        for row in rows {
            if let Some(output_ref) = row["output_ref"].as_str() {
                if let Ok(path) = data_ops::task_output_path(&router_state_root(), output_ref) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

async fn image_batch_outputs_clear(
    State(state): State<HostState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    let batch = match load_batch(&state, &id, &request_id) {
        Ok(batch) => batch,
        Err(response) => return response,
    };
    remove_batch_files(&batch);
    match data_ops::image_batch_clear_outputs(&state.control.store, &id) {
        Ok(cleared) => json_data_response(
            StatusCode::OK,
            serde_json::json!({"id": id, "cleared": cleared}),
            &request_id,
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "clearing batch outputs failed",
            &request_id,
        ),
    }
}

/// Antigravity-scoped usage: same ledger aggregation as `/v1/usage`, filtered
/// to public models that have at least one Antigravity pool.
async fn antigravity_usage(State(state): State<HostState>, request: Request) -> Response {
    let request_id = crate_request_id(&request);
    if let Some(denied) = authorize_data_request(&state, &request, &request_id) {
        return denied;
    }
    let models: std::collections::BTreeSet<String> = state
        .control
        .routes
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .routes()
        .iter()
        .filter(|route| route.provider == "antigravity")
        .map(|route| route.public_model.clone())
        .collect();
    match data_ops::usage_by_model(&state.control.store) {
        Ok(mut body) => {
            if let Some(rows) = body["data"].as_array_mut() {
                rows.retain(|row| {
                    row["model"]
                        .as_str()
                        .is_some_and(|model| models.contains(model))
                });
            }
            let mut total_requests = 0i64;
            let mut total_tokens = 0i64;
            if let Some(rows) = body["data"].as_array() {
                for row in rows {
                    total_requests += row["requests"].as_i64().unwrap_or(0);
                    total_tokens += row["total_tokens"].as_i64().unwrap_or(0);
                }
            }
            body["total_requests"] = Value::from(total_requests);
            body["total_tokens"] = Value::from(total_tokens);
            json_data_response(StatusCode::OK, body, &request_id)
        }
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "usage aggregation failed",
            &request_id,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body as AxumBody;
    use axum::http::Request as AxumRequest;
    use codex_router_lib::control_plane::http_compat::BackendPaths;
    use codex_router_lib::control_plane::ControlState as TestControlState;
    use codex_router_lib::state::StateStore as TestStateStore;
    use futures_util::TryStreamExt;
    use std::collections::HashMap as StdHashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    #[test]
    fn google_verification_errors_are_detected_without_leaking_account_fields() {
        assert!(is_antigravity_account_verification(
            r#"{"error":{"reason":"VALIDATION_REQUIRED","message":"Verify your account to continue."}}"#
        ));
        assert!(!is_antigravity_account_verification(
            "auth_unavailable: no auth available"
        ));
    }

    #[test]
    fn zip_entry_names_are_sanitized_against_path_traversal() {
        assert_eq!(sanitize_zip_entry_name("img-001"), "img-001");
        assert_eq!(sanitize_zip_entry_name("a/b"), "a_b");
        assert_eq!(sanitize_zip_entry_name("../etc"), "etc");
        assert_eq!(sanitize_zip_entry_name(r"..\..\win"), "win");
        assert_eq!(sanitize_zip_entry_name("  "), "item");
        assert_eq!(sanitize_zip_entry_name("..."), "item");
        assert_eq!(sanitize_zip_entry_name("a b:c"), "a_b_c");
    }

    async fn mock_response_with_length(body: &'static [u8], declared_length: usize) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });
        format!("http://{address}/v1/responses")
    }

    #[tokio::test]
    async fn interrupted_json_response_body_is_never_returned_as_success() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let complete = mock_response_with_length(br#"{"ok":true}"#, 11).await;
        let response = client.get(complete).send().await.unwrap();
        assert_eq!(
            read_complete_response_body(response).await.unwrap(),
            &b"{\"ok\":true}"[..]
        );

        let truncated = mock_response_with_length(br#"{"partial":true,"#, 100).await;
        let response = client.get(truncated).send().await.unwrap();
        assert!(read_complete_response_body(response).await.is_err());
    }

    fn test_host_state() -> HostState {
        let dir = std::env::temp_dir().join(format!(
            "codex-router-routetest-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = TestStateStore::open(dir.join("router-state.sqlite3")).unwrap();
        let logger = Arc::new(
            StructuredLogger::open(dir.join("router-events.jsonl")).expect("open test logger"),
        );
        let cli = CliProxyManagementClient::new("http://127.0.0.1:1", "test-secret").unwrap();
        let routes = Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap()));
        let backend = Some(Arc::new(BackendPaths {
            config_path: dir.join("config.yaml"),
            auth_dir: dir.join("auth"),
            downstream_key: "test-key".to_owned(),
            management_secret: "test-secret".to_owned(),
            cli_port: 1,
            desktop_auth_path: dir.join("desktop-auth.json"),
        }));
        let control = TestControlState {
            store: Arc::new(store),
            cli,
            logger,
            routes,
            backend,
            cli_index_map: Arc::new(RwLock::new(StdHashMap::new())),
        };
        HostState {
            control,
            local_key: Arc::new(Zeroizing::new("sk-test-local-key-1234567890".to_owned())),
            bindings: Arc::new(Mutex::new(ContinuationBindings::new())),
            cli_base: Arc::new("http://127.0.0.1:1".to_owned()),
            cli_child: Arc::new(Mutex::new(None)),
            cli_data: reqwest::Client::builder().no_proxy().build().unwrap(),
        }
    }

    fn grok_test_route() -> PoolRoute {
        PoolRoute {
            pool_id: "pool-grok".to_owned(),
            prefix: "cr_test_xai".to_owned(),
            public_model: "grok-4.6".to_owned(),
            upstream_model: "grok-4.6".to_owned(),
            provider: "xai".to_owned(),
            priority: 1,
            enabled: true,
            available: true,
        }
    }

    fn contains_grok_rejected_schema_keyword(value: &Value) -> bool {
        match value {
            Value::Object(object) => {
                object
                    .keys()
                    .any(|key| matches!(key.as_str(), "format" | "pattern"))
                    || object
                        .get("additionalProperties")
                        .is_some_and(|value| !value.is_boolean())
                    || object.values().any(contains_grok_rejected_schema_keyword)
            }
            Value::Array(items) => items.iter().any(contains_grok_rejected_schema_keyword),
            _ => false,
        }
    }

    async fn mock_grok_cli() -> (String, tokio::sync::oneshot::Receiver<Value>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<Value>();
        let captured_tx = Arc::new(Mutex::new(Some(captured_tx)));
        let app = Router::new().route(
            "/v1/responses",
            post({
                let captured_tx = captured_tx.clone();
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let captured_tx = captured_tx.clone();
                    async move {
                        let parsed: Value = serde_json::from_slice(&body).unwrap();
                        let request_id = headers
                            .get("x-request-id")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let session_forwarded = headers.contains_key("x-codex-session")
                            || headers.contains_key("session_id");
                        if let Some(sender) = captured_tx
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .take()
                        {
                            let _ = sender.send(serde_json::json!({
                                "body": parsed,
                                "request_id": request_id,
                                "session_forwarded": session_forwarded,
                            }));
                        }
                        if contains_grok_rejected_schema_keyword(&parsed) {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "type": "error",
                                    "code": "invalid-argument"
                                })),
                            )
                                .into_response();
                        }
                        (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
                    }
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), captured_rx)
    }

    #[tokio::test]
    async fn grok_full_chain_removes_schema_keywords_that_trigger_invalid_argument() {
        let (cli_base, captured_rx) = mock_grok_cli().await;
        let mut state = test_host_state();
        state.cli_base = Arc::new(cli_base);
        *state
            .control
            .routes
            .write()
            .unwrap_or_else(|error| error.into_inner()) =
            RouteTable::new(vec![grok_test_route()]).unwrap();
        let app = public_router(state);
        let client_request_id = "01a02879-c79e-7041-9782-cc41ab37384f";
        let request = AxumRequest::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("authorization", "Bearer sk-test-local-key-1234567890")
            .header("content-type", "application/json")
            .header("x-request-id", client_request_id)
            .header("x-codex-session", client_request_id)
            .body(AxumBody::from(
                serde_json::to_vec(&serde_json::json!({
                    "model": "grok-4.6",
                    "client_metadata": {"thread_id": client_request_id},
                    "prompt_cache_key": client_request_id,
                    "input": [{
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "继续"}]
                    }],
                    "tools": [{
                        "type": "namespace",
                        "name": "mcp__codex_app",
                        "tools": [{
                            "type": "function",
                            "name": "open_in_codex",
                            "strict": false,
                            "parameters": {
                                "type": "object",
                                "additionalProperties": {},
                                "properties": {
                                    "path": {"type": "string", "format": "uri"},
                                    "placement": {"type": "string", "pattern": "^(right|bottom)$"}
                                }
                            }
                        }]
                    }]
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let response_body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let response_json: Value = serde_json::from_slice(&response_body).unwrap();
        let captured = captured_rx.await.unwrap();

        assert_ne!(captured["request_id"], client_request_id);
        assert_eq!(captured["session_forwarded"], false);
        assert!(captured["body"].get("client_metadata").is_none());
        assert!(captured["body"].get("prompt_cache_key").is_none());
        assert_eq!(
            status,
            StatusCode::OK,
            "Grok rejected the sanitized full-chain payload: {response_json}"
        );
    }

    #[tokio::test]
    async fn sse_eof_without_terminal_emits_failed_event() {
        let state = test_host_state();
        let upstream =
            futures_util::stream::iter([Ok::<_, reqwest::Error>(axum::body::Bytes::from_static(
                b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
            ))]);
        let context = SseContext {
            terminal: Some(TerminalSpanGuard::new(
                state.control.logger.clone(),
                "req-missing-terminal",
                "POST /v1/responses",
            )),
            state,
            request_id: "req-missing-terminal".to_owned(),
            public_model: "public-model".to_owned(),
            pool_id: "pool-1".to_owned(),
            protocol: "responses".to_owned(),
            status_u16: 200,
            account_id: None,
        };
        let chunks: Vec<axum::body::Bytes> = wrap_sse_stream(
            upstream,
            SseRewriter::new("pool-prefix", "public-model", "upstream-model"),
            context,
            Instant::now(),
        )
        .try_collect()
        .await
        .unwrap();
        let output = chunks.concat();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("response.failed"));
        assert!(output.contains("CR-UP-0014"));
        assert!(output.contains("req-missing-terminal"));
    }

    #[tokio::test]
    async fn sse_read_error_emits_failed_event_and_closes_normally() {
        let state = test_host_state();
        let store = state.control.store.clone();
        let log_path = state.control.logger.path().to_path_buf();
        let upstream = futures_util::stream::iter([
            Ok(axum::body::Bytes::from_static(
                b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
            )),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "synthetic upstream reset",
            )),
        ]);
        let context = SseContext {
            terminal: Some(TerminalSpanGuard::new(
                state.control.logger.clone(),
                "req-stream-reset",
                "POST /v1/responses",
            )),
            state,
            request_id: "req-stream-reset".to_owned(),
            public_model: "public-model".to_owned(),
            pool_id: "pool-1".to_owned(),
            protocol: "responses".to_owned(),
            status_u16: 200,
            account_id: None,
        };
        let chunks: Vec<axum::body::Bytes> = wrap_sse_stream(
            upstream,
            SseRewriter::new("pool-prefix", "public-model", "upstream-model"),
            context,
            Instant::now(),
        )
        .try_collect()
        .await
        .unwrap();
        let output = String::from_utf8(chunks.concat()).unwrap();

        assert!(output.contains("response.failed"));
        assert!(output.contains("CR-UP-0014"));
        assert!(output.contains("req-stream-reset"));
        let ledger = store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,error_code FROM request_ledger WHERE request_id=?1",
                        rusqlite::params!["req-stream-reset"],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(ledger, ("failed".to_owned(), "CR-UP-0014".to_owned()));
        let terminal_events = std::fs::read_to_string(log_path)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| {
                event["request_id"] == "req-stream-reset" && event["event"] == "request.completed"
            })
            .collect::<Vec<_>>();
        assert_eq!(terminal_events.len(), 1);
        assert_eq!(terminal_events[0]["status"], "upstream_error");
        assert_eq!(terminal_events[0]["error_code"], "CR-UP-0014");
    }

    #[tokio::test]
    async fn upstream_failed_sse_terminal_exposes_router_error_code() {
        let state = test_host_state();
        let upstream = futures_util::stream::iter([Ok::<_, std::io::Error>(
            axum::body::Bytes::from_static(
                b"data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"message\":\"upstream failed\"}}}\n\n",
            ),
        )]);
        let context = SseContext {
            terminal: Some(TerminalSpanGuard::new(
                state.control.logger.clone(),
                "req-upstream-failed",
                "POST /v1/responses",
            )),
            state,
            request_id: "req-upstream-failed".to_owned(),
            public_model: "public-model".to_owned(),
            pool_id: "pool-1".to_owned(),
            protocol: "responses".to_owned(),
            status_u16: 200,
            account_id: None,
        };
        let chunks: Vec<axum::body::Bytes> = wrap_sse_stream(
            upstream,
            SseRewriter::new("pool-prefix", "public-model", "upstream-model"),
            context,
            Instant::now(),
        )
        .try_collect()
        .await
        .unwrap();
        let output = String::from_utf8(chunks.concat()).unwrap();
        let payload = output
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .and_then(|line| serde_json::from_str::<Value>(line).ok())
            .unwrap();

        assert_eq!(payload["type"], "response.failed");
        assert_eq!(payload["response"]["error"]["code"], "CR-UP-0014");
    }

    /// Manager doc 11.1 S03: every section-7 static interface must be
    /// registered on the compatibility host; a route is proven registered when
    /// the handler responds with anything other than 404 (auth/config state
    /// may legitimately yield 400/401/500 on a bare test state).
    #[tokio::test]
    async fn section7_static_interfaces_are_registered() {
        let app = public_router(test_host_state());
        let paths = [
            "/health",
            "/api/v1/auth/login",
            "/api/v1/admin/compliance",
            "/api/v1/admin/compliance/accept",
            "/api/v1/admin/users/1",
            "/api/v1/admin/settings",
            "/api/v1/admin/groups/all",
            "/api/v1/admin/groups",
            "/api/v1/admin/groups/1",
            "/api/v1/admin/groups/1/composite-routes",
            "/api/v1/admin/groups/1/composite-routes/reconcile",
            "/api/v1/admin/groups/1/composite-routes/2",
            "/api/v1/admin/accounts",
            "/api/v1/admin/accounts/1",
            "/api/v1/admin/accounts/generate-auth-url",
            "/api/v1/admin/accounts/exchange-code",
            "/api/v1/admin/accounts/1/scheduled-test-plans",
            "/api/v1/admin/accounts/1/models/sync-upstream",
            "/api/v1/admin/openai/generate-auth-url",
            "/api/v1/admin/openai/create-from-oauth",
            "/api/v1/admin/openai/accounts/1/quota",
            "/api/v1/admin/grok/sso-to-oauth",
            "/api/v1/admin/grok/accounts/1/quota",
            "/api/v1/admin/gemini/oauth/auth-url",
            "/api/v1/admin/gemini/oauth/exchange-code",
            "/api/v1/admin/proxies",
            "/api/v1/admin/proxies/1",
            "/api/v1/admin/scheduled-test-plans",
            "/api/v1/admin/scheduled-test-plans/1",
            "/api/v1/keys",
            "/api/v1/keys/1",
            "/v1/usage",
            "/antigravity/v1/usage",
            "/v1/sub2api/billing",
            "/v1/embeddings",
            "/v1/images/generations/async",
            "/v1/images/edits/async",
            "/v1/images/tasks/task-1",
            "/v1/images/batches",
            "/v1/images/batches/models",
            "/v1/images/batches/batch-1",
            "/v1/images/batches/batch-1/items",
            "/v1/images/batches/batch-1/items/custom-1/content",
            "/v1/images/batches/batch-1/download",
            "/v1/images/batches/batch-1/cancel",
            "/v1/images/batches/batch-1/outputs",
        ];
        for path in paths {
            let response = app
                .clone()
                .oneshot(
                    AxumRequest::builder()
                        .method("GET")
                        .uri(path)
                        .body(AxumBody::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "static interface is not registered: {path}"
            );
        }
        // The data plane is a catch-all; an unknown data path must reach the
        // data_plane handler (unauthorized 401 on the bare state) and never
        // be a host-level 404.
        let response = app
            .oneshot(
                AxumRequest::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "data plane fallback must cover /v1/responses"
        );
    }
}
