//! Old `/api/v1` compatibility control plane backed by SQLite and CLIProxyAPI.

use crate::backend::cli_proxy::CliProxyManagementClient;
use crate::backend::config_compiler::{self, RouteTarget};
use crate::control_plane::account_probe::{self, ProbeFailure};
use crate::control_plane::scheduler;
use crate::oauth_credentials::{self, OAuthProvider};
use crate::routing::{PoolRoute, RouteTable};
use crate::state::StateStore;
use crate::telemetry::ledger;
use crate::telemetry::structured_log::StructuredLogger;
use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Everything the control plane needs to recompile and republish the
/// CLIProxyAPI runtime configuration after a state mutation.
pub struct BackendPaths {
    pub config_path: PathBuf,
    pub auth_dir: PathBuf,
    pub downstream_key: String,
    pub management_secret: String,
    pub cli_port: u16,
    /// Codex Desktop's auth file. OpenAI OAuth refresh ownership stays there;
    /// CLIProxyAPI receives only the current access token.
    pub desktop_auth_path: PathBuf,
}

#[derive(Clone)]
pub struct ControlState {
    pub store: Arc<StateStore>,
    pub cli: CliProxyManagementClient,
    pub logger: Arc<StructuredLogger>,
    pub routes: Arc<RwLock<RouteTable>>,
    pub backend: Option<Arc<BackendPaths>>,
    /// CLI auth index (X-CPA-TRACE-ID middle segment) -> Router account id.
    /// Rebuilt by every `sync_backend`; used for account-level ledger
    /// attribution without ever logging the index itself.
    pub cli_index_map: Arc<RwLock<HashMap<String, i64>>>,
}

pub fn sha256_hex(value: &[u8]) -> String {
    use sha2::Digest;
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn success(data: impl Into<Value>) -> Response {
    let body = json!({"success": true, "data": data.into()});
    response_json(StatusCode::OK, &body, None)
}

pub fn failure(status: StatusCode, code: &str, message: &str) -> Response {
    let body = json!({
        "success": false,
        "message": message,
        "error_code": code,
    });
    response_json(status, &body, Some(code))
}

pub fn response_json(status: StatusCode, body: &Value, error_code: Option<&str>) -> Response {
    let mut response = (status, Json(body.clone())).into_response();
    if let Ok(value) = HeaderValue::from_str(&crate::telemetry::structured_log::request_id()) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Some(code) = error_code {
        if let Ok(value) = HeaderValue::from_str(code) {
            response
                .headers_mut()
                .insert("x-codex-router-error-code", value);
        }
    }
    response
}

pub fn data(body: &Value) -> Value {
    body.get("data").cloned().unwrap_or_else(|| body.clone())
}

pub fn stable_identity_hmac(platform: &str, identity: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(b"CodexRouter-stable-identity-v2").expect("stable HMAC key");
    mac.update(platform.as_bytes());
    mac.update(&[0]);
    mac.update(identity.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn deleted_account_tombstone(account_id: i64) -> String {
    stable_identity_hmac(
        "deleted",
        &format!("{account_id}:{}", uuid::Uuid::now_v7().simple()),
    )
}

pub fn sanitize_state_payload(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| {
                let key = key.to_ascii_lowercase();
                !matches!(
                    key.as_str(),
                    "api_key"
                        | "apikey"
                        | "access_token"
                        | "refresh_token"
                        | "id_token"
                        | "password"
                        | "authorization"
                        | "cookie"
                        | "sso_token"
                )
            });
            for child in object.values_mut() {
                sanitize_state_payload(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(sanitize_state_payload),
        _ => {}
    }
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn account_secret_name(id: i64) -> String {
    format!("AccountKey-{id}")
}

fn read_account_secret(id: i64) -> Option<String> {
    crate::credentials::read_text(&account_secret_name(id))
        .ok()
        .flatten()
        .map(|secret| secret.to_string())
        .filter(|secret| !secret.trim().is_empty())
}

fn sync_openai_access_token(document: &mut Value, desktop_auth_path: &std::path::Path) {
    // Never leave a ChatGPT refresh token in Router-managed files. Desktop is
    // the sole refresh owner; Router consumes the access token it last wrote.
    if let Some(object) = document.as_object_mut() {
        object.remove("refresh_token");
    }
    let Ok(text) = std::fs::read_to_string(desktop_auth_path) else {
        return;
    };
    let Ok(auth) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let Some(tokens) = auth.get("tokens").and_then(Value::as_object) else {
        return;
    };
    let Some(access_token) = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return;
    };
    let Some(object) = document.as_object_mut() else {
        return;
    };
    object.insert(
        "access_token".to_owned(),
        Value::String(access_token.to_owned()),
    );
    for key in ["id_token", "account_id", "email", "last_refresh", "expired"] {
        if let Some(value) = tokens.get(key) {
            object.insert(key.to_owned(), value.clone());
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplicaSyncStats {
    pub scanned: usize,
    pub written: usize,
    pub skipped: usize,
}

/// Re-stamp every OpenAI CLI replica with Desktop's current access token.
/// Codex Desktop rotates its token in place; without this timer the replicas
/// would age out after the next Desktop refresh until some later backend
/// sync rewrites them. Identical bytes are skipped inside write_auth_file, so
/// an unchanged token never wakes CLIProxyAPI's Windows file watcher.
pub fn sync_desktop_openai_replicas(state: &ControlState) -> anyhow::Result<ReplicaSyncStats> {
    let Some(backend) = state.backend.clone() else {
        return Ok(ReplicaSyncStats::default());
    };
    if !backend.desktop_auth_path.is_file() {
        return Ok(ReplicaSyncStats::default());
    }
    let entries = std::fs::read_dir(&backend.auth_dir)?;
    let mut stats = ReplicaSyncStats::default();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("cr-router-oauth-") || !name.ends_with("-codex.json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut document) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        sync_openai_access_token(&mut document, &backend.desktop_auth_path);
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        stats.scanned += 1;
        let before = std::fs::read(&path).ok();
        write_auth_file(&backend.auth_dir, stem, &document)?;
        let after = std::fs::read(&path).ok();
        let wrote = before.as_ref() != after.as_ref();
        if wrote {
            stats.written += 1;
            let _ = state.logger.write(json!({
                "level":"INFO",
                "event":"desktop.session.replica_written",
                "error_code": crate::control_plane::desktop_session::DSK_REPLICA_WRITTEN,
                "stem":stem,
                "timestamp": crate::telemetry::structured_log::timestamp(),
            }));
        } else {
            stats.skipped += 1;
        }
    }
    Ok(stats)
}

/// Deep-merge a partial update into a stored JSON payload. Objects merge
/// recursively; every other value (including explicit null) replaces.
fn merge_payload(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            for (key, value) in patch_map {
                merge_payload(base_map.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (base, patch) => *base = patch.clone(),
    }
}

#[derive(Clone, Copy)]
enum CliPublish {
    Skip,
    Push,
}

/// Rebuild the route table and recompile the CLIProxyAPI configuration from
/// SQLite state. Returns the number of compiled route targets. Best effort by
/// design: callers log the structured error instead of failing the API call.
pub async fn sync_backend(state: &ControlState) -> Result<usize> {
    sync_backend_ex(state, CliPublish::Push).await
}

async fn sync_backend_ex(state: &ControlState, publish: CliPublish) -> Result<usize> {
    let Some(backend) = state.backend.clone() else {
        return Ok(0);
    };
    let publish_cli = matches!(publish, CliPublish::Push);
    // Account create/update during Apply must not health-check or PUT the CLI
    // on every channel: waiting for `/v1/models` (and the watcher reload it
    // triggers) is what pinned the UI on Applying. Host memory still rebuilds;
    // the final composite-route reconcile publishes YAML once.
    let cli_ready = publish_cli && state.cli.health().await.is_ok();
    let live_model_ids = live_cli_model_ids(state, &backend).await;
    // The CLI is the authority for file-based auth indexes. Its synthesizer
    // may normalize paths or retain an existing index, so reproducing the
    // hash locally is only a startup fallback and is not sufficient for
    // account-level ledger attribution after a live auth reload.
    let cli_file_indexes: HashMap<String, String> = if !cli_ready {
        HashMap::new()
    } else {
        state
            .cli
            .get("/v0/management/auth-files")
            .await
            .ok()
            .and_then(|value| {
                let files = value.get("files").cloned().unwrap_or(value);
                files.as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(|item| {
                            let name = item
                                .get("name")
                                .or_else(|| item.get("filename"))
                                .and_then(Value::as_str)?;
                            let index = item.get("auth_index").and_then(Value::as_str)?;
                            Some((name.to_owned(), index.to_owned()))
                        })
                        .collect()
                })
            })
            .unwrap_or_default()
    };
    let rows = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
            "SELECT r.id, r.public_model, r.upstream_model, r.target_platform, r.priority,
                    a.id, a.platform, a.account_type, a.priority, a.weight, a.payload, a.auth_index,
                    a.auth_file, a.schedulable, a.status, p.normalized_url
             FROM composite_routes r
             JOIN account_groups ag ON ag.group_id = r.group_id
             JOIN accounts a ON a.id = ag.account_id
             LEFT JOIN proxies p ON p.id = CAST(json_extract(a.payload, '$.proxy_id') AS INTEGER)
                AND p.deleted_at IS NULL
             WHERE r.enabled = 1 AND r.deleted_at IS NULL
               AND a.deleted_at IS NULL
             ORDER BY r.id, a.id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, Option<String>>(15)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    })?;
    let mut targets = Vec::new();
    let mut pool_routes = Vec::new();
    let mut cli_index_map: HashMap<String, i64> = HashMap::new();
    let mut desired_oauth_replicas = std::collections::HashSet::new();
    let mut seen_pools = std::collections::HashSet::new();
    let mut pool_available: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    let mut oauth_routes = std::collections::HashSet::new();
    for (
        route_id,
        _public_model,
        upstream_model,
        target_platform,
        _route_priority,
        _account_id,
        account_platform,
        account_type,
        _account_priority,
        _weight,
        payload,
        _auth_index,
        _auth_file,
        _schedulable,
        _status,
        _joined_proxy_url,
    ) in &rows
    {
        if account_type != "oauth" {
            continue;
        }
        let payload: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
        if oauth_route_provider_matches(account_platform, target_platform)
            && oauth_route_model_matches(&payload, _public_model, upstream_model)
        {
            oauth_routes.insert(*route_id);
        }
    }
    for (
        route_id,
        public_model,
        upstream_model,
        target_platform,
        route_priority,
        account_id,
        account_platform,
        account_type,
        account_priority,
        weight,
        payload,
        _auth_index,
        auth_file,
        schedulable,
        status,
        joined_proxy_url,
    ) in rows
    {
        let route_has_oauth = oauth_routes.contains(&route_id);
        let is_fallback_pool = route_has_oauth && account_type != "oauth";
        let pool_route_id =
            pool_route_id_for_account(route_id, &account_type, route_has_oauth, account_id);
        let account_available = account_is_cli_eligible(schedulable, &status);
        if seen_pools.insert(pool_route_id.clone()) {
            pool_routes.push(PoolRoute {
                pool_id: config_compiler::pool_id(&pool_route_id, &target_platform),
                prefix: config_compiler::pool_prefix(&pool_route_id, &target_platform),
                public_model: public_model.clone(),
                upstream_model: upstream_model.clone(),
                provider: config_compiler::normalize_platform(&target_platform),
                priority: if is_fallback_pool {
                    fallback_pool_priority(route_priority)
                } else {
                    account_priority.max(1) as i32
                },
                enabled: true,
                available: false,
            });
        }
        if !account_available {
            // Disabled / error / unschedulable accounts never reach the CLI
            // candidate set; the Router availability gate reports CR-RTE-0002.
            continue;
        }
        let payload: Value = serde_json::from_str(&payload).unwrap_or_else(|_| json!({}));
        if account_type != "oauth"
            && !api_route_model_matches(&payload, &public_model, &upstream_model)
        {
            continue;
        }
        if account_type == "oauth" {
            // OAuth credentials are provider-specific. An OAuth account must
            // not be attached to a different provider's composite route just
            // because both accounts share one Router group.
            if !oauth_route_provider_matches(&account_platform, &target_platform) {
                continue;
            }
            if !oauth_route_model_matches(&payload, &public_model, &upstream_model) {
                continue;
            }
            let auth_file_name = std::path::PathBuf::from(&auth_file)
                .file_name()
                .map(|name| name.to_owned())
                .context("OAuth auth file name is missing")?;
            let source_file = backend.auth_dir.join(&auth_file_name);
            let is_openai = config_compiler::normalize_platform(&account_platform) == "openai";
            let mut document = if is_openai {
                // Desktop is the sole credential owner for ChatGPT accounts.
                // Build the replica from the live Desktop login even when the
                // historical physical auth file was quarantined or removed;
                // sync_openai_access_token strips any refresh token and only
                // ever copies the current access token.
                let mut base = std::fs::read_to_string(&source_file)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .unwrap_or_else(|| json!({}));
                if base
                    .get("type")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    base["type"] = Value::String("codex".to_owned());
                }
                sync_openai_access_token(&mut base, &backend.desktop_auth_path);
                if base
                    .get("access_token")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    // Desktop has no ChatGPT login right now; leave the pool
                    // empty instead of publishing an unusable credential.
                    continue;
                }
                base
            } else {
                if !source_file.is_file() {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&source_file) else {
                    continue;
                };
                let Ok(document) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                document
            };
            let auth_type = document
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if auth_type.is_empty() {
                continue;
            }
            if config_compiler::normalize_platform(&account_platform) == "gemini" {
                if let Some(project_id) = payload
                    .pointer("/credentials/project_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    document["project_id"] = Value::String(project_id.to_owned());
                }
            }
            let replica_stem = format!("cr-router-oauth-{account_id}-{route_id}-{auth_type}");
            let replica_name = format!("{replica_stem}.json");
            let replica_path = backend.auth_dir.join(&replica_name);
            desired_oauth_replicas.insert(replica_name.clone());
            document["router_replica"] = Value::Bool(true);
            let pool_prefix = config_compiler::pool_prefix(&pool_route_id, &target_platform);
            document["prefix"] = Value::String(pool_prefix.clone());
            document["priority"] = json!(config_compiler::cli_priority(account_priority as i32));
            document["weight"] = json!(weight.max(1));
            if !document.get("model_aliases").is_some_and(Value::is_array) {
                document["model_aliases"] = Value::Array(Vec::new());
            }
            let aliases = document
                .get_mut("model_aliases")
                .and_then(Value::as_array_mut)
                .expect("model_aliases was initialized as an array");
            let upstream = resolve_live_oauth_upstream(
                &account_platform,
                &auth_type,
                &mapped_upstream_model(&payload, &target_platform, &public_model, &upstream_model),
                &live_model_ids,
            );
            for alias in oauth_replica_aliases(&auth_type, &pool_prefix, &public_model) {
                push_oauth_replica_alias(aliases, &upstream, &alias);
            }
            if let Err(error) = write_auth_file(&backend.auth_dir, &replica_stem, &document) {
                let _ = state.logger.write(json!({
                    "level":"WARN",
                    "event":"backend.auth_file_replica_failed",
                    "error_description":error.to_string()
                }));
                continue;
            }
            if account_available {
                pool_available.insert(pool_route_id.clone(), true);
            }
            let cli_index = cli_file_indexes
                .get(&replica_name)
                .cloned()
                .unwrap_or_else(|| {
                    config_compiler::cli_file_auth_index(
                        &auth_type,
                        &replica_path.to_string_lossy(),
                    )
                });
            cli_index_map.insert(cli_index, account_id);
            continue;
        }
        let Some(secret) = read_account_secret(account_id) else {
            let _ = state.logger.write(json!({"level":"WARN","event":"backend.account_secret_missing","account_id":account_id}));
            continue;
        };
        let base_url = payload
            .pointer("/credentials/base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let proxy_url = joined_proxy_url.or_else(|| {
            payload
                .get("proxy_url")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let cli_index =
            config_compiler::cli_key_auth_index(&target_platform, base_url.as_deref(), &secret);
        cli_index_map.insert(cli_index, account_id);
        if account_available {
            pool_available.insert(pool_route_id.clone(), true);
        }
        let openai_capabilities = payload
            .pointer("/credentials/openai_capabilities")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        targets.push(RouteTarget {
            route_id: pool_route_id,
            public_model,
            upstream_model,
            platform: target_platform,
            base_url,
            credential_ref: secret,
            priority: config_compiler::display_priority(account_priority as i32),
            weight: weight as i32,
            proxy_url,
            openai_capabilities,
        });
    }
    if let Ok(entries) = std::fs::read_dir(&backend.auth_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with("cr-router-oauth-")
                && name.ends_with(".json")
                && !desired_oauth_replicas.contains(name)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    for route in &mut pool_routes {
        if let Some(id) = route
            .pool_id
            .strip_prefix("cr/")
            .and_then(|tail| tail.split('/').next())
        {
            route.available = pool_available.get(id).copied().unwrap_or(false);
        }
    }
    let table = RouteTable::new(pool_routes)?;
    let mut config = if targets.is_empty() {
        let mut config = config_compiler::CliProxyConfig {
            port: backend.cli_port,
            auth_dir: backend.auth_dir.to_string_lossy().to_string(),
            remote_management: config_compiler::RemoteManagement {
                secret_key: backend.management_secret.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        config.api_keys.push(backend.downstream_key.clone());
        config
    } else {
        let mut config = config_compiler::compile(
            &targets,
            &backend.downstream_key,
            &backend.management_secret,
            &backend.auth_dir.to_string_lossy(),
        )?;
        config.port = backend.cli_port;
        config
    };
    config.proxy_url = std::env::var("CODEX_ROUTER_PROXY_URL")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    config_compiler::apply_platform_runtime_policy(&mut config);
    let yaml = config_compiler::to_yaml(&config)?;
    if publish_cli {
        // Push through the management API: the CLI validates the document,
        // writes it in place and reloads clients through its own file watcher.
        // A local rename would replace the watched file and permanently kill
        // that watcher (fsnotify on Windows never re-attaches after an atomic
        // replace). Account create/update skips this path so Apply does not
        // PUT the same YAML once per channel.
        if !cli_ready {
            std::fs::write(&backend.config_path, &yaml)
                .with_context(|| format!("write {}", backend.config_path.display()))?;
        } else if let Err(error) = state.cli.put_config_yaml(&yaml).await {
            let _ = state.logger.write(json!({
                "level":"INFO",
                "event":"backend.config_reload_deferred",
                "error_description":error.to_string(),
            }));
            std::fs::write(&backend.config_path, &yaml)
                .with_context(|| format!("write {}", backend.config_path.display()))?;
        }
    }
    *state
        .routes
        .write()
        .unwrap_or_else(|error| error.into_inner()) = table;
    *state
        .cli_index_map
        .write()
        .unwrap_or_else(|error| error.into_inner()) = cli_index_map;
    quarantine_legacy_openai_auth_files(&backend.auth_dir, &state.logger);
    Ok(targets.len())
}

fn quarantine_legacy_openai_auth_files(auth_dir: &std::path::Path, logger: &StructuredLogger) {
    let Ok(entries) = std::fs::read_dir(auth_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("legacy-openai-") || !name.ends_with(".json") {
            continue;
        }
        let quarantined = path.with_file_name(format!("{name}.quarantined"));
        if std::fs::rename(&path, &quarantined).is_ok() {
            let _ = logger.write(json!({
                "level":"INFO",
                "event":"backend.legacy_openai_quarantined",
                "reason":"desktop_openai_auth_owner",
            }));
        }
    }
}

/// Patch the pool prefix of a CLI auth file in place, preserving all other fields.
pub fn patch_auth_file_prefix(path: &std::path::Path, prefix: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read auth file {}", path.display()))?;
    let mut value: Value = serde_json::from_str(&text).context("parse auth file JSON")?;
    value["prefix"] = Value::String(prefix.to_owned());
    // CLIProxyAPI watches the auth directory/file identity on Windows. An
    // atomic rename replaces the watched inode and the CLI keeps the old
    // in-memory prefix, producing `unknown provider for model cr_...`. Keep
    // the file identity and let the CLI watcher reload the changed contents.
    std::fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

/// Apply a Router pool prefix and public-to-upstream alias to an OAuth auth
/// file. CLIProxyAPI registers OAuth models from the native upstream IDs; the
/// alias makes the Router's internal `prefix/public_model` request resolvable
/// without changing the shared API-key model rewrite contract.
pub fn patch_auth_file_route(
    path: &std::path::Path,
    prefix: &str,
    upstream_model: &str,
    public_model: &str,
) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read auth file {}", path.display()))?;
    let mut value: Value = serde_json::from_str(&text).context("parse auth file JSON")?;
    value["prefix"] = Value::String(prefix.to_owned());
    if !value.get("model_aliases").is_some_and(Value::is_array) {
        value["model_aliases"] = Value::Array(Vec::new());
    }
    let aliases = value
        .get_mut("model_aliases")
        .and_then(Value::as_array_mut)
        .expect("model_aliases was initialized as an array");
    let exists = aliases.iter().any(|entry| {
        entry.get("name").and_then(Value::as_str) == Some(upstream_model)
            && entry.get("alias").and_then(Value::as_str) == Some(public_model)
    });
    if !exists {
        aliases.push(json!({
            "name": upstream_model,
            "alias": public_model,
            "force-mapping": true,
        }));
    }
    // Preserve the watched file identity on Windows; see patch_auth_file_prefix.
    std::fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

/// Build a CLI auth file document from old-shape OAuth credentials.
pub fn build_auth_file(provider: &str, credentials: &Value, prefix: Option<&str>) -> Result<Value> {
    oauth_credentials::build_auth_file(OAuthProvider::parse(provider)?, credentials, prefix)
}

pub fn auth_index_is_safe(auth_index: &str) -> bool {
    let trimmed = auth_index.trim();
    !trimmed.is_empty()
        && trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@' | '+')
        })
}

pub fn write_auth_file(
    auth_dir: &std::path::Path,
    auth_index: &str,
    document: &Value,
) -> Result<PathBuf> {
    if !auth_index_is_safe(auth_index) {
        anyhow::bail!("unsafe auth index {auth_index}");
    }
    let path = auth_dir.join(format!("{auth_index}.json"));
    let mut document = document.clone();
    let openai_owned = document
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "codex" | "openai" | "chatgpt"
            )
        });
    if openai_owned {
        if let Some(object) = document.as_object_mut() {
            object.remove("refresh_token");
        }
    }
    let bytes = serde_json::to_vec_pretty(&document)?;
    std::fs::create_dir_all(auth_dir)?;
    // Do not recreate an identical watched auth file: each replace wakes
    // CLIProxyAPI. Overwrite in place (no delete+rename) so the watcher sees
    // WRITE rather than REMOVE, which previously reprocessed ChatGPT replicas.
    if std::fs::read(&path).is_ok_and(|existing| existing == bytes) {
        return Ok(path);
    }
    std::fs::write(&path, &bytes)?;
    Ok(path)
}

pub async fn reconcile_composite_routes(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers) {
        return failure(
            StatusCode::UNAUTHORIZED,
            "CR-AUT-0002",
            "admin token required",
        );
    }
    let Some(routes) = body.get("routes").and_then(Value::as_array) else {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "routes array is required",
        );
    };
    let mut desired = Vec::with_capacity(routes.len());
    for route in routes {
        let mut route = route.clone();
        let public_model = json_string(&route, "public_model");
        let upstream_model = json_string(&route, "upstream_model");
        let target_platform = json_string(&route, "target_platform");
        if public_model.trim().is_empty()
            || upstream_model.trim().is_empty()
            || target_platform.trim().is_empty()
        {
            return failure(
                StatusCode::BAD_REQUEST,
                "CR-VAL-0003",
                "public_model, upstream_model and target_platform are required",
            );
        }
        sanitize_state_payload(&mut route);
        desired.push((public_model, target_platform, upstream_model, route));
    }
    let result = state.store.with_connection(|connection| {
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE composite_routes SET deleted_at=CURRENT_TIMESTAMP WHERE group_id=?1 AND deleted_at IS NULL",
            rusqlite::params![group_id],
        )?;
        for (public_model, target_platform, upstream_model, route) in &desired {
            let endpoint = json_string(route, "endpoint");
            let endpoint = if endpoint.trim().is_empty() { "any" } else { endpoint.as_str() };
            let priority = route.get("priority").and_then(Value::as_i64).unwrap_or(1).clamp(1, 999_999);
            let enabled = route.get("enabled").and_then(Value::as_bool).unwrap_or(true);
            transaction.execute(
                "INSERT INTO composite_routes(group_id,public_model,upstream_model,target_platform,endpoint,priority,enabled,payload)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(group_id,public_model,upstream_model,target_platform,endpoint)
                 DO UPDATE SET priority=excluded.priority,enabled=excluded.enabled,payload=excluded.payload,
                    deleted_at=NULL,updated_at=CURRENT_TIMESTAMP",
                rusqlite::params![group_id, public_model, upstream_model, target_platform, endpoint, priority, enabled, route.to_string()],
            )?;
        }
        transaction.commit()?;
        Ok::<(), anyhow::Error>(())
    });
    if result.is_err() {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "could not reconcile composite routes",
        );
    }
    match sync_backend(&state).await {
        Ok(_) => success(json!({"updated": desired.len()})),
        Err(_) => failure(
            StatusCode::BAD_GATEWAY,
            "CR-CFG-0005",
            "CLI runtime did not apply composite routes",
        ),
    }
}
// ---------------------------------------------------------------------------
// Auth and admin basics
// ---------------------------------------------------------------------------

pub async fn login(State(state): State<ControlState>, Json(body): Json<Value>) -> Response {
    let email = body
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let password = body
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected = crate::credentials::read_text("AdminPassword")
        .ok()
        .flatten();
    let Some(expected) = expected else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "CR-AUT-0003",
            "Admin password is not initialized",
        );
    };
    let valid = (email == "admin@admin.com" || email == "admin@sub2api.local")
        && password.len() == expected.len()
        && constant_time_eq(password.as_bytes(), expected.as_bytes());
    if !valid {
        return failure(
            StatusCode::UNAUTHORIZED,
            "CR-AUT-0004",
            "Invalid administrator credentials",
        );
    }
    let token = crate::telemetry::structured_log::request_id();
    let token_hmac = sha256_hex(token.as_bytes());
    let expires = (chrono::Utc::now() + chrono::Duration::hours(12)).to_rfc3339();
    if let Err(error) = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO admin_tokens(token_hmac,expires_at) VALUES(?1,?2)",
            rusqlite::params![token_hmac, expires],
        )?;
        Ok(())
    }) {
        let _ = state.logger.write(json!({"level":"ERROR","event":"oauth.admin_login_failed","error_description":error.to_string()}));
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "Could not create admin token",
        );
    }
    success(json!({"access_token": token, "token_type": "Bearer", "expires_in": 43200}))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn authorized(state: &ControlState, headers: &HeaderMap) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let token_hmac = sha256_hex(token.as_bytes());
    state
        .store
        .with_connection(|connection| {
            let expires: Option<String> = connection
                .query_row(
                    "SELECT expires_at FROM admin_tokens WHERE token_hmac=?1",
                    rusqlite::params![token_hmac],
                    |row| row.get(0),
                )
                .optional_error()?;
            Ok(expires)
        })
        .ok()
        .flatten()
        .is_some_and(|expires| expires > chrono::Utc::now().to_rfc3339())
}

macro_rules! guarded {
    ($state:expr, $headers:expr) => {
        if !authorized(&$state, &$headers) {
            return failure(
                StatusCode::UNAUTHORIZED,
                "CR-AUT-0002",
                "admin token required",
            );
        }
    };
}

pub async fn compliance(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let accepted = state
        .store
        .setting("compliance.accepted")
        .ok()
        .flatten()
        .is_some();
    success(json!({
        "required": !accepted,
        "ack_phrase_zh": "我确认仅限本机使用 Codex Router",
    }))
}

pub async fn accept_compliance(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    if body.get("phrase").and_then(Value::as_str) != Some("我确认仅限本机使用 Codex Router")
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "compliance phrase mismatch",
        );
    }
    let _ = state.store.set_setting(
        "compliance.accepted",
        &json!(chrono::Utc::now().to_rfc3339()),
    );
    success(json!({"accepted": true}))
}

pub async fn oauth_capabilities(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let providers = ["openai", "anthropic", "gemini", "antigravity", "grok"];
    if providers
        .iter()
        .any(|provider| cli_oauth_endpoint(provider).is_none())
    {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-OAU-0001",
            "OAuth provider mapping is incomplete",
        );
    }
    if state.cli.auth_files().await.is_err() {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-OAU-0003",
            "CLI OAuth management is not ready",
        );
    }
    success(json!({"ready": true, "providers": providers}))
}

pub async fn user_detail(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let stored = state
        .store
        .setting("admin.user")
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| json!({}));
    let mut user = json!({
        "id": 1, "email": "admin@admin.com", "username": "Codex Router Administrator",
        "role": "admin", "concurrency": 0, "rpm_limit": 0, "notes": "local"
    });
    if let (Some(target), Some(source)) = (user.as_object_mut(), stored.as_object()) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
    user["id"] = json!(1);
    success(user)
}

pub async fn update_user(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    if let Some(password) = body.get("password").and_then(Value::as_str) {
        if password.chars().count() < 8 {
            return failure(
                StatusCode::BAD_REQUEST,
                "CR-VAL-0003",
                "password must contain at least 8 characters",
            );
        }
        if let Err(error) = crate::credentials::write_text("AdminPassword", password) {
            let _ = state.logger.write(json!({"level":"ERROR","event":"admin.password_update_failed","error_description":error.to_string()}));
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-AUT-0003",
                "could not update administrator password",
            );
        }
    }
    let mut stored = body.clone();
    if let Some(object) = stored.as_object_mut() {
        object.remove("password");
    }
    let _ = state.store.set_setting("admin.user", &stored);
    success(stored)
}

pub async fn settings(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let stored = state
        .store
        .setting("admin.settings")
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| json!({}));
    success(stored)
}

pub async fn update_settings(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let _ = state.store.set_setting("admin.settings", &body);
    success(body)
}

// ---------------------------------------------------------------------------
// Groups and composite routes
// ---------------------------------------------------------------------------

fn group_payload(id: i64, name: &str, status: &str, models: &str, payload: &str) -> Value {
    let mut value: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
    value["id"] = id.into();
    value["name"] = name.into();
    value["status"] = status.into();
    value["models"] = serde_json::from_str(models).unwrap_or_else(|_| json!([]));
    value
}

pub async fn groups_all(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let groups = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
            "SELECT id,name,status,models,payload FROM groups WHERE deleted_at IS NULL ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    });
    match groups {
        Ok(groups) => success(Value::Array(
            groups
                .iter()
                .map(|(id, name, status, models, payload)| {
                    group_payload(*id, name, status, models, payload)
                })
                .collect(),
        )),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not read groups",
        ),
    }
}

pub async fn create_group(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if name.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "group name is required",
        );
    }
    sanitize_state_payload(&mut body);
    let models = body
        .pointer("/models_list_config/models")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO groups(name,status,models,payload) VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                name,
                body.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("active"),
                models.to_string(),
                body.to_string()
            ],
        )?;
        Ok::<i64, anyhow::Error>(connection.last_insert_rowid())
    });
    match result {
        Ok(id) => {
            let mut out = body;
            out["id"] = id.into();
            out["models"] = models;
            success(out)
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "could not create group",
        ),
    }
}

pub async fn update_group(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    sanitize_state_payload(&mut body);
    let models = body.pointer("/models_list_config/models").cloned();
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE groups SET name=COALESCE(?1,name),status=COALESCE(?2,status),models=COALESCE(?3,models),payload=?4,updated_at=CURRENT_TIMESTAMP WHERE id=?5 AND deleted_at IS NULL",
            rusqlite::params![body.get("name").and_then(Value::as_str), body.get("status").and_then(Value::as_str), models.map(|value| value.to_string()), body.to_string(), id],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        body["id"] = id.into();
        success(body)
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "group not found")
    }
}

fn route_payload(row: &(i64, i64, String, String, String, String, i64, i64, String)) -> Value {
    let (
        id,
        group_id,
        public_model,
        upstream_model,
        target_platform,
        endpoint,
        priority,
        enabled,
        payload,
    ) = row;
    let mut value: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
    value["id"] = (*id).into();
    value["group_id"] = (*group_id).into();
    value["public_model"] = public_model.clone().into();
    value["upstream_model"] = upstream_model.clone().into();
    value["target_platform"] = target_platform.clone().into();
    value["endpoint"] = endpoint.clone().into();
    value["priority"] = (*priority).into();
    value["enabled"] = (*enabled != 0).into();
    value
}

pub async fn list_composite_routes(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let rows = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
            "SELECT id,group_id,public_model,upstream_model,target_platform,endpoint,priority,enabled,payload FROM composite_routes WHERE group_id=?1 AND deleted_at IS NULL ORDER BY id",
        )?;
        let rows = statement.query_map(rusqlite::params![group_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, String>(8)?))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    });
    match rows {
        Ok(rows) => success(
            json!({"items": rows.iter().map(route_payload).collect::<Vec<_>>(), "total": rows.len()}),
        ),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not read composite routes",
        ),
    }
}

pub async fn create_composite_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let public_model = json_string(&body, "public_model");
    let upstream_model = json_string(&body, "upstream_model");
    let target_platform = json_string(&body, "target_platform");
    if public_model.trim().is_empty()
        || upstream_model.trim().is_empty()
        || target_platform.trim().is_empty()
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "public_model, upstream_model and target_platform are required",
        );
    }
    sanitize_state_payload(&mut body);
    let endpoint = json_string(&body, "endpoint");
    let endpoint = if endpoint.trim().is_empty() {
        "any".to_owned()
    } else {
        endpoint
    };
    let priority = body
        .get("priority")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 999_999);
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO composite_routes(group_id,public_model,upstream_model,target_platform,endpoint,priority,enabled,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![group_id, public_model, upstream_model, target_platform, endpoint, priority, enabled, body.to_string()],
        )?;
        Ok::<i64, anyhow::Error>(connection.last_insert_rowid())
    });
    match result {
        Ok(id) => {
            body["id"] = id.into();
            body["group_id"] = group_id.into();
            let _ = sync_backend(&state).await;
            success(body)
        }
        Err(error) if error.to_string().contains("UNIQUE") => failure(
            StatusCode::CONFLICT,
            "CR-STO-0008",
            "duplicate composite route",
        ),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "could not create composite route",
        ),
    }
}

pub async fn update_composite_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path((group_id, id)): Path<(i64, i64)>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    sanitize_state_payload(&mut body);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE composite_routes SET public_model=COALESCE(?3,public_model),upstream_model=COALESCE(?4,upstream_model),target_platform=COALESCE(?5,target_platform),priority=COALESCE(?6,priority),enabled=COALESCE(?7,enabled),payload=?8,updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND group_id=?2 AND deleted_at IS NULL",
            rusqlite::params![id, group_id, body.get("public_model").and_then(Value::as_str), body.get("upstream_model").and_then(Value::as_str), body.get("target_platform").and_then(Value::as_str), body.get("priority").and_then(Value::as_i64), body.get("enabled").and_then(Value::as_bool), body.to_string()],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        body["id"] = id.into();
        body["group_id"] = group_id.into();
        let _ = sync_backend(&state).await;
        success(body)
    } else {
        failure(
            StatusCode::NOT_FOUND,
            "CR-STO-0007",
            "composite route not found",
        )
    }
}

pub async fn delete_composite_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path((group_id, id)): Path<(i64, i64)>,
) -> Response {
    guarded!(state, headers);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE composite_routes SET deleted_at=CURRENT_TIMESTAMP WHERE id=?1 AND group_id=?2",
            rusqlite::params![id, group_id],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        let _ = sync_backend(&state).await;
        success(json!({"deleted": true}))
    } else {
        failure(
            StatusCode::NOT_FOUND,
            "CR-STO-0007",
            "composite route not found",
        )
    }
}
// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

fn account_payload(row: &(i64, String, String, String, i64, i64, i64, String)) -> Value {
    let (id, platform, account_type, status, schedulable, priority, weight, payload) = row;
    let mut value: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
    value["id"] = (*id).into();
    value["platform"] = platform.clone().into();
    value["type"] = account_type.clone().into();
    value["status"] = status.clone().into();
    value["schedulable"] = (*schedulable != 0).into();
    value["priority"] = (*priority).into();
    value["weight"] = (*weight).into();
    value
}

const ACCOUNT_SELECT: &str =
    "SELECT id,platform,account_type,status,schedulable,priority,weight,payload FROM accounts";

pub async fn accounts(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    guarded!(state, headers);
    // Auth files are the CLI's source of truth. Reconcile physical OAuth
    // files before listing accounts so a login completed just before a Router
    // restart is not silently invisible in the compatibility API.
    if let Err(error) = sync_existing_oauth_accounts(&state).await {
        let _ = state.logger.write(json!({
            "level": "WARN",
            "event": "control.oauth_auth_file_sync_failed",
            "error_description": error.to_string(),
        }));
    }
    let platform_filter = query.get("platform").cloned();
    let rows = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(&format!(
            "{ACCOUNT_SELECT} WHERE deleted_at IS NULL ORDER BY id"
        ))?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    });
    match rows {
        Ok(rows) => {
            let mut items: Vec<Value> = rows.iter().map(account_payload).collect();
            if let Some(platform) = platform_filter {
                items.retain(|item| {
                    item.get("platform").and_then(Value::as_str) == Some(platform.as_str())
                });
            }
            success(
                json!({"items": items, "total": items.len(), "page": 1, "page_size": items.len().max(1)}),
            )
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not list accounts",
        ),
    }
}

pub async fn account_detail(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let row = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(&format!(
            "{ACCOUNT_SELECT} WHERE id=?1 AND deleted_at IS NULL"
        ))?;
        statement
            .query_row(rusqlite::params![id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(Into::into)
    });
    match row {
        Ok(row) => success(account_payload(&row)),
        Err(_) => failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found"),
    }
}

fn sync_account_groups(
    connection: &rusqlite::Connection,
    account_id: i64,
    group_ids: &[i64],
) -> Result<()> {
    connection.execute(
        "DELETE FROM account_groups WHERE account_id=?1",
        rusqlite::params![account_id],
    )?;
    for group_id in group_ids {
        connection.execute(
            "INSERT OR IGNORE INTO account_groups(account_id,group_id) VALUES(?1,?2)",
            rusqlite::params![account_id, group_id],
        )?;
    }
    Ok(())
}

fn group_ids_from(body: &Value) -> Vec<i64> {
    body.get("group_ids")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default()
}

fn persist_api_credential(account_id: i64, body: &Value) -> Result<()> {
    if let Some(api_key) = body
        .pointer("/credentials/api_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        crate::credentials::write_text(&account_secret_name(account_id), api_key)?;
    }
    Ok(())
}

fn account_identity_source<'a>(account_type: &str, body: &'a Value) -> &'a str {
    if account_type == "apikey" {
        body.get("name")
    } else {
        body.pointer("/credentials/access_token")
            .or_else(|| body.pointer("/credentials/refresh_token"))
            .or_else(|| body.get("name"))
    }
    .and_then(Value::as_str)
    .unwrap_or_default()
}

pub async fn create_account(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let platform = json_string(&body, "platform");
    let account_type_raw = json_string(&body, "type");
    let account_type = match account_type_raw.as_str() {
        "api" | "apikey" => "apikey".to_owned(),
        "oauth" => "oauth".to_owned(),
        _ => {
            return failure(
                StatusCode::BAD_REQUEST,
                "CR-VAL-0003",
                "valid platform and account type are required",
            )
        }
    };
    if platform.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "valid platform and account type are required",
        );
    }
    // API keys are often shared by several models on the same gateway. The
    // managed channel name is stable and non-secret, while using the key here
    // incorrectly collapses every model/channel that shares one credential.
    let identity_source = account_identity_source(&account_type, &body);
    if identity_source.trim().is_empty() {
        return failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CR-VAL-0004",
            "account credential reference is required",
        );
    }
    let identity = stable_identity_hmac(&platform, identity_source);
    let auth_index = format!("cr-account-{}", &identity[..16.min(identity.len())]);
    let priority = body
        .get("priority")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 999_999);
    let weight = body
        .get("weight")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 1_000_000);
    let group_ids = group_ids_from(&body);
    let original = body.clone();
    sanitize_state_payload(&mut body);
    let store_result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO accounts(platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9)",
            rusqlite::params![platform, account_type, auth_index, format!("{auth_index}.json"), identity, body.get("status").and_then(Value::as_str).unwrap_or("active"), priority, weight, body.to_string()],
        )?;
        let id = connection.last_insert_rowid();
        sync_account_groups(connection, id, &group_ids)?;
        Ok::<i64, anyhow::Error>(id)
    });
    let id = match store_result {
        Ok(id) => id,
        Err(error) if error.to_string().contains("UNIQUE") => {
            return failure(
                StatusCode::CONFLICT,
                "CR-STO-0008",
                "duplicate account identity",
            );
        }
        Err(error) => {
            let _ = state.logger.write(json!({"level":"ERROR","event":"control.account_create_failed","error_description":error.to_string()}));
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0004",
                "could not create account",
            );
        }
    };
    if account_type == "apikey" {
        if let Err(error) = persist_api_credential(id, &original) {
            let _ = state.logger.write(json!({"level":"ERROR","event":"control.account_secret_failed","account_id":id,"error_description":error.to_string()}));
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-AUT-0008",
                "could not store account credential",
            );
        }
    }
    if account_type == "oauth" {
        if let Some(credentials) = original.get("credentials") {
            match build_auth_file(&platform, credentials, None) {
                Ok(document) => {
                    if let Some(backend) = &state.backend {
                        if let Err(error) =
                            write_auth_file(&backend.auth_dir, &auth_index, &document)
                        {
                            let _ = state.logger.write(json!({"level":"ERROR","event":"control.auth_file_write_failed","account_id":id,"error_description":error.to_string()}));
                        }
                    }
                }
                Err(error) => {
                    let _ = state.logger.write(json!({"level":"WARN","event":"control.auth_file_build_failed","account_id":id,"error_description":error.to_string()}));
                }
            }
        }
    }
    let mut out = account_payload(&(
        id,
        platform,
        account_type,
        "active".into(),
        1,
        priority,
        weight,
        body.to_string(),
    ));
    out["auth_index"] = auth_index.into();
    let _ = sync_backend_ex(&state, CliPublish::Skip).await;
    success(out)
}

pub async fn update_account(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let original = body.clone();
    sanitize_state_payload(&mut body);
    let group_ids = group_ids_from(&body);
    let result = state.store.with_connection(|connection| {
        let existing: String = connection.query_row(
            "SELECT payload FROM accounts WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id],
            |row| row.get::<_, String>(0),
        )?;
        let mut merged: Value = serde_json::from_str(&existing).unwrap_or_else(|_| json!({}));
        merge_payload(&mut merged, &body);
        let changed = connection.execute(
            "UPDATE accounts SET status=COALESCE(?2,status),schedulable=COALESCE(?3,schedulable),priority=COALESCE(?4,priority),weight=COALESCE(?5,weight),payload=?6,updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id, body.get("status").and_then(Value::as_str), body.get("schedulable").and_then(Value::as_bool), body.get("priority").and_then(Value::as_i64), body.get("weight").and_then(Value::as_i64), merged.to_string()],
        )?;
        if changed == 1 && !group_ids.is_empty() {
            sync_account_groups(connection, id, &group_ids)?;
        }
        Ok::<(usize, Value), anyhow::Error>((changed, merged))
    });
    match result {
        Ok((1, merged)) => {
            if let Err(error) = persist_api_credential(id, &original) {
                let _ = state.logger.write(json!({"level":"ERROR","event":"control.account_secret_failed","account_id":id,"error_description":error.to_string()}));
            }
            let mut out = merged;
            out["id"] = id.into();
            let _ = sync_backend_ex(&state, CliPublish::Skip).await;
            success(out)
        }
        _ => failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found"),
    }
}

pub async fn delete_account(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let auth_material = state
        .store
        .with_connection(|connection| {
            Ok::<(String, String), anyhow::Error>(connection.query_row(
                "SELECT auth_index,auth_file FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                rusqlite::params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?)
        })
        .ok();
    // Keep the numeric row as a tombstone so account IDs are never reused,
    // but release the provider identity for a later re-add of the same key.
    // `stable_identity_hmac` has a legacy table-level UNIQUE constraint in
    // addition to the live-row index; leaving the old HMAC in a soft-deleted
    // row would make every legitimate re-add fail with CR-STO-0008.
    let tombstone_identity = deleted_account_tombstone(id);
    let result = state.store.with_connection(|connection| {
        let changed = connection.execute(
            "UPDATE accounts SET deleted_at=CURRENT_TIMESTAMP,schedulable=0,stable_identity_hmac=?2 WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id, tombstone_identity],
        )?;
        if changed > 0 {
            connection.execute("DELETE FROM account_groups WHERE account_id=?1", rusqlite::params![id])?;
        }
        Ok::<usize, anyhow::Error>(changed)
    });
    match result {
        Ok(changed) if changed > 0 => {
            if let Err(error) = crate::credentials::delete_text(&account_secret_name(id)) {
                let _ = state.logger.write(json!({"level":"WARN","event":"control.account_secret_delete_failed","account_id":id,"error_description":error.to_string()}));
            }
            if let (Some(backend), Some((auth_index, auth_file_name))) =
                (state.backend.as_ref(), auth_material)
            {
                let safe_name = std::path::PathBuf::from(&auth_file_name)
                    .file_name()
                    .map(|name| name.to_owned())
                    .unwrap_or_else(|| std::ffi::OsString::from(format!("{auth_index}.json")));
                let auth_file = backend.auth_dir.join(safe_name);
                if auth_file.is_file() {
                    let _ = std::fs::remove_file(auth_file);
                }
            }
            let _ = sync_backend(&state).await;
            success(json!({"deleted": true}))
        }
        Ok(_) => failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found"),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0006",
            "could not delete account",
        ),
    }
}

async fn update_account_status(state: &ControlState, id: i64, status: &str) -> Response {
    let result = state.store.with_connection(|connection| {
        connection.execute("UPDATE accounts SET status=?1,updated_at=CURRENT_TIMESTAMP WHERE id=?2 AND deleted_at IS NULL", rusqlite::params![status, id])?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        let _ = sync_backend_ex(state, CliPublish::Skip).await;
        success(json!({"id": id, "status": status}))
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found")
    }
}

fn requested_probe_model(body: Option<&Json<Value>>) -> String {
    body.and_then(|value| {
        value
            .get("model_id")
            .or_else(|| value.get("model"))
            .and_then(Value::as_str)
    })
    .unwrap_or_default()
    .trim()
    .to_owned()
}

fn inferred_probe_model(state: &ControlState, id: i64) -> String {
    state
        .store
        .with_connection(|connection| {
            let route_model = connection
                .query_row(
                    "SELECT r.upstream_model
                     FROM composite_routes r
                     JOIN account_groups ag ON ag.group_id=r.group_id
                     WHERE ag.account_id=?1 AND r.enabled=1 AND r.deleted_at IS NULL
                     ORDER BY r.priority,r.id LIMIT 1",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(model) = route_model.filter(|model| !model.trim().is_empty()) {
                return Ok(model);
            }
            let payload = connection
                .query_row(
                    "SELECT payload FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let model = payload
                .and_then(|payload| serde_json::from_str::<Value>(&payload).ok())
                .and_then(|payload| {
                    payload
                        .pointer("/credentials/model_mapping")
                        .and_then(Value::as_object)
                        .and_then(|mapping| mapping.keys().next().cloned())
                })
                .unwrap_or_default();
            Ok::<String, anyhow::Error>(model)
        })
        .unwrap_or_default()
}

fn probe_failure_response(failure_detail: &ProbeFailure) -> Response {
    let status =
        StatusCode::from_u16(failure_detail.http_status).unwrap_or(StatusCode::BAD_GATEWAY);
    failure(status, failure_detail.error_code, failure_detail.message)
}

fn is_desktop_owned_openai(state: &ControlState, id: i64) -> bool {
    state
        .store
        .with_connection(|connection| {
            connection
                .query_row(
                    "SELECT platform,account_type FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                    rusqlite::params![id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(Into::into)
        })
        .ok()
        .flatten()
        .is_some_and(|(platform, account_type)| {
            account_type.eq_ignore_ascii_case("oauth")
                && config_compiler::normalize_platform(&platform) == "openai"
        })
}

async fn probe_account_for_state(
    state: &ControlState,
    id: i64,
    model: &str,
) -> std::result::Result<account_probe::ProbeSuccess, ProbeFailure> {
    account_probe::probe_account(&state.store, &state.cli, &state.cli_index_map, id, model).await
}

async fn recover_account_after_probe(state: &ControlState, id: i64, model: &str) -> Response {
    if is_desktop_owned_openai(state, id) {
        let recovery_state = state.store.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT status FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        });
        match recovery_state {
            Ok(Some(status)) if status == "disabled" => {
                return failure(
                    StatusCode::CONFLICT,
                    "CR-OAU-0008",
                    "disabled OAuth account must be re-authenticated before recovery",
                );
            }
            Ok(None) => return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found"),
            Err(_) => {
                return failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CR-STO-0003",
                    "could not read account recovery state",
                );
            }
            Ok(Some(_)) => {}
        }
        let updated = state.store.with_connection(|connection| {
            connection.execute(
                "UPDATE accounts
                 SET status='active',schedulable=1,updated_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND deleted_at IS NULL",
                rusqlite::params![id],
            )?;
            Ok::<u64, anyhow::Error>(connection.changes())
        });
        if !matches!(updated, Ok(1)) {
            return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found");
        }
        if let Err(error) = sync_backend(state).await {
            let _ = state.logger.write(json!({
                "level":"ERROR",
                "event":"control.account_recovery_sync_failed",
                "account_id":id,
                "error_description":error.to_string(),
            }));
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-CFG-0005",
                "account was recovered but CLI routing could not be rebuilt",
            );
        }
        let _ = state.logger.write(json!({
            "level":"INFO",
            "event":"control.account_recovery_local",
            "account_id":id,
            "reason":"desktop_openai_auth_owner",
        }));
        return success(json!({
            "id": id,
            "schedulable": true,
            "probed": false,
            "reason": "desktop_openai_auth_owner",
        }));
    }
    // Automated GUI recovery and manual recovery share this endpoint. Never
    // let either path puncture a 401 cooldown or an explicit operator disable;
    // a completed OAuth login clears the cooldown before recovery is needed.
    let recovery_state = state.store.with_connection(|connection| {
        connection
            .query_row(
                "SELECT status,schedulable FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                rusqlite::params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(Into::into)
    });
    let (previous_status, previous_schedulable) = match recovery_state {
        Ok(Some((status, _))) if status == "disabled" => {
            return failure(
                StatusCode::CONFLICT,
                "CR-OAU-0008",
                "disabled OAuth account must be re-authenticated before recovery",
            );
        }
        Ok(Some(state)) => state,
        Ok(None) => return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found"),
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0003",
                "could not read account recovery state",
            );
        }
    };
    match crate::router_usage::reauth_cooldown_active(&state.store, id) {
        Ok(true) => {
            return failure(
                StatusCode::CONFLICT,
                "CR-OAU-0008",
                "OAuth account is waiting for re-authentication",
            );
        }
        Ok(false) => {}
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0003",
                "could not read account recovery cooldown",
            );
        }
    }
    let result = probe_account_for_state(state, id, model).await;
    let probe = match result {
        Ok(probe) => probe,
        Err(failure_detail) => {
            if failure_detail.upstream_status == Some(401) {
                if let Err(error) = crate::router_usage::note_reauth_failure(&state.store, id) {
                    let _ = state.logger.write(json!({
                        "level":"ERROR",
                        "event":"control.reauth_cooldown_write_failed",
                        "account_id":id,
                        "error_description":error.to_string(),
                    }));
                }
            }
            let _ = state.logger.write(json!({
                "level":"INFO",
                "event":"control.account_recovery_probe_failed",
                "account_id":id,
                "error_code":failure_detail.error_code,
                "upstream_status":failure_detail.upstream_status,
                "latency_ms":failure_detail.latency_ms,
            }));
            return probe_failure_response(&failure_detail);
        }
    };
    if let Err(error) = crate::router_usage::clear_reauth_cooldown(&state.store, id) {
        let _ = state.logger.write(json!({
            "level":"ERROR",
            "event":"control.reauth_cooldown_clear_failed",
            "account_id":id,
            "error_description":error.to_string(),
        }));
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0006",
            "account probe succeeded but re-auth cooldown could not be cleared",
        );
    }
    let updated = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE accounts
             SET status='active',schedulable=1,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if !matches!(updated, Ok(1)) {
        return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found");
    }
    if let Err(error) = sync_backend(state).await {
        let _ = state.store.with_connection(|connection| {
            connection.execute(
                "UPDATE accounts SET status=?2,schedulable=?3,updated_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND deleted_at IS NULL",
                rusqlite::params![id, previous_status, previous_schedulable],
            )?;
            Ok(())
        });
        let _ = state.logger.write(json!({
            "level":"ERROR",
            "event":"control.account_recovery_sync_failed",
            "account_id":id,
            "error_description":error.to_string(),
        }));
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-CFG-0005",
            "account recovered but backend sync failed",
        );
    }
    success(json!({
        "id":id,
        "status":"active",
        "schedulable":true,
        "probe":{
            "success":true,
            "model":probe.model,
            "latency_ms":probe.latency_ms,
            "upstream_status":probe.upstream_status,
        }
    }))
}

async fn account_usage_for_state(state: &ControlState, id: i64) -> Response {
    let desktop_auth = state
        .backend
        .as_ref()
        .map(|backend| backend.desktop_auth_path.as_path());
    match crate::router_usage::query_account_usage(
        &state.store,
        &state.cli,
        &state.logger,
        desktop_auth,
        id,
    )
    .await
    {
        Ok(crate::router_usage::AccountUsage::Found(value)) => success(value),
        Ok(crate::router_usage::AccountUsage::LiveUnavailable(value)) => {
            let body = json!({
                "success": false,
                "message": "provider live quota is unavailable",
                "error_code": "CR-USE-0003",
                "data": value,
            });
            response_json(StatusCode::BAD_GATEWAY, &body, Some("CR-USE-0003"))
        }
        Ok(crate::router_usage::AccountUsage::NotFound) => {
            failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found")
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not read account usage",
        ),
    }
}

pub async fn account_action(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path((id, action)): Path<(i64, String)>,
    body: Option<Json<Value>>,
) -> Response {
    guarded!(state, headers);
    match action.as_str() {
        "clear-error" => update_account_status(&state, id, "active").await,
        "recover-state" => {
            let requested = requested_probe_model(body.as_ref());
            let model = if requested.is_empty() {
                inferred_probe_model(&state, id)
            } else {
                requested
            };
            recover_account_after_probe(&state, id, &model).await
        }
        "schedulable" => {
            let schedulable = body
                .as_ref()
                .and_then(|value| value.get("schedulable"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let result = state.store.with_connection(|connection| {
                connection.execute("UPDATE accounts SET schedulable=?1,updated_at=CURRENT_TIMESTAMP WHERE id=?2 AND deleted_at IS NULL", rusqlite::params![schedulable, id])?;
                Ok::<u64, anyhow::Error>(connection.changes())
            });
            if matches!(result, Ok(1)) {
                let _ = sync_backend_ex(&state, CliPublish::Skip).await;
                success(json!({"id": id, "schedulable": schedulable}))
            } else {
                failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found")
            }
        }
        "models" => account_models_for_state(&state, id).await,
        "sync-upstream" => account_models_sync_upstream_for_state(&state, id).await,
        "test" => {
            if is_desktop_owned_openai(&state, id) {
                let _ = state.logger.write(json!({
                    "level":"INFO",
                    "event":"control.account_test_skipped",
                    "account_id":id,
                    "reason":"desktop_openai_auth_owner",
                }));
                return success(json!({
                    "success":true,
                    "account_id":id,
                    "skipped":true,
                    "reason":"desktop_openai_auth_owner",
                }));
            }
            let model = requested_probe_model(body.as_ref());
            match probe_account_for_state(&state, id, &model).await {
                Ok(probe) => success(json!({
                    "success":true,
                    "account_id":id,
                    "latency_ms":probe.latency_ms,
                    "model":probe.model,
                    "upstream_status":probe.upstream_status,
                })),
                Err(failure_detail) => probe_failure_response(&failure_detail),
            }
        }
        "stats" => match ledger::account_totals(&state.store, id) {
            Ok(totals) => success(totals),
            Err(_) => failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CR-STO-0003",
                "could not read account stats",
            ),
        },
        "usage" => account_usage_for_state(&state, id).await,
        _ => failure(
            StatusCode::NOT_FOUND,
            "CR-REQ-0002",
            "unknown account action",
        ),
    }
}

fn account_auth_material(
    state: &ControlState,
    id: i64,
) -> Result<(String, String, String, bool, Value)> {
    state.store.with_connection(|connection| {
        let row = connection.query_row(
            "SELECT account_type,auth_file,status,schedulable,payload
             FROM accounts WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, String>(4)?,
                ))
            },
        )?;
        let payload = serde_json::from_str(&row.4).unwrap_or_else(|_| json!({}));
        Ok((row.0, row.1, row.2, row.3, payload))
    })
}

fn cli_auth_file_models_path(auth_file: &str) -> String {
    let name: String = url::form_urlencoded::byte_serialize(auth_file.as_bytes()).collect();
    format!("/v0/management/auth-files/models?name={name}")
}

#[cfg(not(test))]
const MODEL_SYNC_POLL_ATTEMPTS: usize = 20;
#[cfg(test)]
const MODEL_SYNC_POLL_ATTEMPTS: usize = 3;

async fn account_models_for_state(state: &ControlState, id: i64) -> Response {
    let Ok((account_type, auth_file, status, schedulable, payload)) =
        account_auth_material(state, id)
    else {
        return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found");
    };
    if account_type == "oauth" {
        if status != "active"
            || !schedulable
            || !matches!(
                crate::router_usage::reauth_cooldown_active(&state.store, id),
                Ok(false)
            )
        {
            return failure(
                StatusCode::CONFLICT,
                "CR-OAU-0008",
                "OAuth account is not available for a live model query",
            );
        }
        let auth_file = std::path::Path::new(&auth_file)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if auth_file.trim().is_empty() {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0008",
                "OAuth account has no auth file",
            );
        }
        if state
            .backend
            .as_ref()
            .is_none_or(|backend| !backend.auth_dir.join(auth_file).is_file())
        {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-CLI-0007",
                "OAuth auth file is missing",
            );
        }
        return match state.cli.get(&cli_auth_file_models_path(auth_file)).await {
            Ok(value) => success(json!({
                "items": value.get("models").cloned().unwrap_or_else(|| json!([])),
            })),
            Err(_) => failure(StatusCode::BAD_GATEWAY, "CR-CLI-0006", "model query failed"),
        };
    }
    let items = payload
        .pointer("/credentials/model_mapping")
        .and_then(Value::as_object)
        .map(|mapping| {
            mapping
                .keys()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    success(json!({"items": items}))
}

fn account_platform(state: &ControlState, id: i64) -> Option<String> {
    state
        .store
        .with_connection(|connection| {
            connection
                .query_row(
                    "SELECT platform FROM accounts WHERE id=?1 AND deleted_at IS NULL",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        })
        .ok()
        .flatten()
}

async fn account_models_sync_upstream_for_state(state: &ControlState, id: i64) -> Response {
    let Ok((account_type, auth_file, status, schedulable, _payload)) =
        account_auth_material(state, id)
    else {
        return failure(StatusCode::NOT_FOUND, "CR-STO-0007", "account not found");
    };
    if account_type != "oauth" {
        return account_models_for_state(state, id).await;
    }
    let platform = account_platform(state, id).unwrap_or_default();
    if config_compiler::normalize_platform(&platform) == "openai" {
        // Desktop is the sole refresh owner. Touching the replica to wake
        // CLIProxyAPI's watcher was a remaining login-loop trigger: the CLI
        // reprocessed the ChatGPT file on every 3-minute GUI self-check.
        let _ = state.logger.write(json!({
            "level":"INFO",
            "event":"control.openai_sync_upstream_skipped",
            "account_id":id,
            "reason":"desktop_openai_auth_owner",
        }));
        return account_models_for_state(state, id).await;
    }
    if status != "active"
        || !schedulable
        || !matches!(
            crate::router_usage::reauth_cooldown_active(&state.store, id),
            Ok(false)
        )
    {
        return failure(
            StatusCode::CONFLICT,
            "CR-OAU-0008",
            "OAuth account is not available for an upstream model sync",
        );
    }
    let auth_file = std::path::Path::new(&auth_file)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if auth_file.trim().is_empty() {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-OAU-0008",
            "OAuth account has no auth file",
        );
    }
    let Some(backend) = state.backend.as_ref() else {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-CLI-0007",
            "auth registry reload is unavailable",
        );
    };
    let physical_auth_file = backend.auth_dir.join(auth_file);
    let auth_bytes = match std::fs::read(&physical_auth_file) {
        Ok(bytes) => bytes,
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-CLI-0007",
                "OAuth auth file is missing",
            )
        }
    };
    // Preserve the watched file identity and its exact credential bytes while
    // emitting a write event that makes CLIProxyAPI rebuild its auth registry.
    if std::fs::write(&physical_auth_file, auth_bytes).is_err() {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-CLI-0007",
            "could not reload OAuth auth file",
        );
    }
    let models_path = cli_auth_file_models_path(auth_file);
    for attempt in 0..MODEL_SYNC_POLL_ATTEMPTS {
        if let Ok(value) = state.cli.get(&models_path).await {
            let models = value.get("models").cloned().unwrap_or_else(|| json!([]));
            if models.as_array().is_some_and(|items| !items.is_empty()) {
                return success(json!({"items": models}));
            }
        }
        if attempt + 1 < MODEL_SYNC_POLL_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
    failure(
        StatusCode::BAD_GATEWAY,
        "CR-CLI-0007",
        "auth registry reload returned no models",
    )
}

pub async fn account_models(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    account_models_for_state(&state, id).await
}

pub async fn account_models_sync_upstream(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    account_models_sync_upstream_for_state(&state, id).await
}

// ---------------------------------------------------------------------------
// Proxies
// ---------------------------------------------------------------------------

pub async fn proxies(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let rows = state
        .store
        .with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT id,payload FROM proxies WHERE deleted_at IS NULL ORDER BY id")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .unwrap_or_default();
    let items: Vec<Value> = rows
        .iter()
        .filter_map(|(id, row)| {
            serde_json::from_str::<Value>(row).ok().map(|mut value| {
                value["id"] = (*id).into();
                value
            })
        })
        .collect();
    success(json!({"items": items, "total": items.len()}))
}

pub async fn create_proxy(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let host = json_string(&body, "host");
    let port = body.get("port").and_then(Value::as_i64).unwrap_or_default();
    if host.trim().is_empty() || !(1..=65535).contains(&port) {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-PRX-0001",
            "proxy host and port are invalid",
        );
    }
    sanitize_state_payload(&mut body);
    let protocol = json_string(&body, "protocol");
    let protocol = if protocol.trim().is_empty() {
        "http".to_owned()
    } else {
        protocol
    };
    let normalized = format!("{protocol}://{host}:{port}");
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO proxies(protocol,host,port,normalized_url,payload) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![protocol, host, port, normalized, body.to_string()],
        )?;
        Ok::<i64, anyhow::Error>(connection.last_insert_rowid())
    });
    match result {
        Ok(id) => {
            body["id"] = id.into();
            success(body)
        }
        Err(_) => failure(StatusCode::CONFLICT, "CR-PRX-0001", "duplicate proxy"),
    }
}

pub async fn update_proxy(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    sanitize_state_payload(&mut body);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE proxies SET payload=?2 WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id, body.to_string()],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        body["id"] = id.into();
        success(body)
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "proxy not found")
    }
}

pub async fn delete_proxy(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let references = state
        .store
        .with_connection(|connection| {
            Ok::<i64, anyhow::Error>(connection.query_row(
                "SELECT COUNT(*) FROM accounts WHERE deleted_at IS NULL AND json_extract(payload, '$.proxy_id')=?1",
                rusqlite::params![id],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .unwrap_or(0);
    if references > 0 {
        return failure(
            StatusCode::CONFLICT,
            "CR-STO-0008",
            "proxy is still referenced by accounts",
        );
    }
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE proxies SET deleted_at=CURRENT_TIMESTAMP WHERE id=?1 AND deleted_at IS NULL",
            rusqlite::params![id],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        success(json!({"deleted": true}))
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "proxy not found")
    }
}
// ---------------------------------------------------------------------------
// Local API keys
// ---------------------------------------------------------------------------

pub async fn list_api_keys(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    guarded!(state, headers);
    let rows = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
            "SELECT id,name,key_suffix,group_id,status,payload FROM api_keys ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    });
    match rows {
        Ok(rows) => {
            let items: Vec<Value> = rows
                .iter()
                .map(|(id, name, suffix, group_id, status, payload)| {
                    let mut value: Value =
                        serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
                    value["id"] = (*id).into();
                    value["name"] = name.clone().into();
                    value["key"] = format!("…{suffix}").into();
                    value["group_id"] = group_id.map(Value::from).unwrap_or(Value::Null);
                    value["status"] = status.clone().into();
                    value
                })
                .collect();
            success(json!({"items": items, "total": items.len()}))
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not list API keys",
        ),
    }
}

pub async fn create_api_key(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let name = json_string(&body, "name");
    let custom_key = json_string(&body, "custom_key");
    let key_value = if custom_key.trim().is_empty() {
        format!("sk-local-{}", uuid::Uuid::now_v7().simple())
    } else {
        custom_key
    };
    let group_id = body.get("group_id").and_then(Value::as_i64);
    let key_hmac = sha256_hex(key_value.as_bytes());
    let key_suffix = key_value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    sanitize_state_payload(&mut body);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO api_keys(name,key_hmac,key_suffix,group_id,status,payload) VALUES(?1,?2,?3,?4,'active',?5)",
            rusqlite::params![name, key_hmac, key_suffix, group_id, body.to_string()],
        )?;
        Ok::<i64, anyhow::Error>(connection.last_insert_rowid())
    });
    match result {
        Ok(id) => success(
            json!({"id": id, "name": name, "key": key_value, "group_id": group_id, "status": "active"}),
        ),
        Err(error) if error.to_string().contains("UNIQUE") => {
            failure(StatusCode::CONFLICT, "CR-STO-0008", "duplicate API key")
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "could not create API key",
        ),
    }
}

pub async fn update_api_key(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    sanitize_state_payload(&mut body);
    let status = json_string(&body, "status");
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE api_keys SET status=COALESCE(?2,status),payload=?3 WHERE id=?1",
            rusqlite::params![
                id,
                if status.is_empty() {
                    None
                } else {
                    Some(status)
                },
                body.to_string()
            ],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        body["id"] = id.into();
        success(body)
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "API key not found")
    }
}

pub async fn delete_api_key(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let result = state.store.with_connection(|connection| {
        connection.execute("DELETE FROM api_keys WHERE id=?1", rusqlite::params![id])?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        success(json!({"deleted": true}))
    } else {
        failure(StatusCode::NOT_FOUND, "CR-STO-0007", "API key not found")
    }
}

/// Data-plane key check: the bootstrap local key plus every active stored key.
pub fn data_key_valid(state: &ControlState, presented: &str) -> bool {
    let presented_hmac = sha256_hex(presented.as_bytes());
    state
        .store
        .with_connection(|connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM api_keys WHERE key_hmac=?1 AND status='active'",
                rusqlite::params![presented_hmac],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Scheduled test plans
// ---------------------------------------------------------------------------

type PlanRow = (
    i64,
    i64,
    String,
    String,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    String,
);

fn plan_payload(row: &PlanRow) -> Value {
    let (
        id,
        account_id,
        model,
        cron,
        enabled,
        auto_recover,
        max_results,
        last_run,
        next_run,
        payload,
    ) = row;
    let mut value: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
    value["id"] = (*id).into();
    value["account_id"] = (*account_id).into();
    value["model"] = model.clone().into();
    value["model_id"] = model.clone().into();
    value["cron"] = cron.clone().into();
    value["cron_expression"] = cron.clone().into();
    value["enabled"] = (*enabled != 0).into();
    value["auto_recover"] = (*auto_recover != 0).into();
    value["max_results"] = (*max_results).into();
    value["last_run"] = last_run.clone().map(Value::from).unwrap_or(Value::Null);
    value["next_run"] = next_run.clone().map(Value::from).unwrap_or(Value::Null);
    value
}

const PLAN_SELECT: &str = "SELECT id,account_id,model,cron,enabled,auto_recover,max_results,last_run,next_run,payload FROM scheduled_test_plans";

pub async fn list_plans(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    guarded!(state, headers);
    let account_filter = query
        .get("account_id")
        .and_then(|value| value.parse::<i64>().ok());
    let rows = state.store.with_connection(|connection| {
        let (sql, account) = if let Some(account_id) = account_filter {
            (
                format!("{PLAN_SELECT} WHERE account_id=?1 ORDER BY id"),
                Some(account_id),
            )
        } else {
            (format!("{PLAN_SELECT} ORDER BY id"), None)
        };
        let mut statement = connection.prepare(&sql)?;
        let mapper = |row: &rusqlite::Row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
            ))
        };
        let collected: Vec<_> = if let Some(account) = account {
            statement
                .query_map(rusqlite::params![account], mapper)?
                .collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            statement
                .query_map([], mapper)?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        Ok(collected)
    });
    match rows {
        Ok(rows) => success(
            json!({"items": rows.iter().map(plan_payload).collect::<Vec<_>>(), "total": rows.len()}),
        ),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not list scheduled test plans",
        ),
    }
}

pub async fn list_account_plans(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(account_id): Path<i64>,
) -> Response {
    list_plans(
        State(state),
        headers,
        Query(HashMap::from([(
            "account_id".to_owned(),
            account_id.to_string(),
        )])),
    )
    .await
}

pub async fn create_plan(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let account_id = body
        .get("account_id")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let model = {
        let value = json_string(&body, "model");
        if value.trim().is_empty() {
            json_string(&body, "model_id")
        } else {
            value
        }
    };
    let cron = json_string(&body, "cron");
    let cron = if cron.trim().is_empty() {
        let schedule = json_string(&body, "schedule");
        if schedule.trim().is_empty() {
            json_string(&body, "cron_expression")
        } else {
            schedule
        }
    } else {
        cron
    };
    if account_id <= 0 || cron.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "account_id, model and cron are required",
        );
    }
    if model.trim().is_empty() {
        return failure(StatusCode::BAD_REQUEST, "CR-VAL-0001", "model is required");
    }
    if scheduler::validate_cron(&cron).is_err() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "cron expression is invalid",
        );
    }
    sanitize_state_payload(&mut body);
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let auto_recover = body
        .get("auto_recover")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_results = body
        .get("max_results")
        .and_then(Value::as_i64)
        .unwrap_or(20)
        .clamp(1, 1000);
    let next_run = if enabled {
        scheduler::next_run_text(&cron, chrono::Utc::now()).ok()
    } else {
        None
    };
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "INSERT INTO scheduled_test_plans(account_id,model,cron,enabled,auto_recover,max_results,next_run,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![account_id, model, cron, enabled, auto_recover, max_results, next_run, body.to_string()],
        )?;
        Ok::<i64, anyhow::Error>(connection.last_insert_rowid())
    });
    match result {
        Ok(id) => {
            body["id"] = id.into();
            body["account_id"] = account_id.into();
            body["model"] = model.clone().into();
            body["model_id"] = model.into();
            body["cron"] = cron.clone().into();
            body["cron_expression"] = cron.into();
            body["enabled"] = enabled.into();
            body["auto_recover"] = auto_recover.into();
            body["max_results"] = max_results.into();
            body["next_run"] = next_run.map(Value::String).unwrap_or(Value::Null);
            success(body)
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0004",
            "could not create scheduled test plan",
        ),
    }
}

pub async fn update_plan(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(mut body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    sanitize_state_payload(&mut body);
    let current = state.store.with_connection(|connection| {
        connection
            .query_row(
                "SELECT account_id,model,cron,enabled,auto_recover,max_results,payload
                 FROM scheduled_test_plans WHERE id=?1",
                rusqlite::params![id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    });
    let Ok(Some((
        account_id,
        current_model,
        current_cron,
        current_enabled,
        current_auto_recover,
        current_max_results,
        current_payload,
    ))) = current
    else {
        return failure(
            StatusCode::NOT_FOUND,
            "CR-STO-0007",
            "scheduled test plan not found",
        );
    };
    let model = body
        .get("model")
        .or_else(|| body.get("model_id"))
        .and_then(Value::as_str)
        .unwrap_or(&current_model)
        .trim()
        .to_owned();
    let cron = body
        .get("cron")
        .or_else(|| body.get("schedule"))
        .or_else(|| body.get("cron_expression"))
        .and_then(Value::as_str)
        .unwrap_or(&current_cron)
        .trim()
        .to_owned();
    if model.is_empty() {
        return failure(StatusCode::BAD_REQUEST, "CR-VAL-0001", "model is required");
    }
    if scheduler::validate_cron(&cron).is_err() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "cron expression is invalid",
        );
    }
    let enabled = body
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(current_enabled != 0);
    let auto_recover = body
        .get("auto_recover")
        .and_then(Value::as_bool)
        .unwrap_or(current_auto_recover != 0);
    let max_results = body
        .get("max_results")
        .and_then(Value::as_i64)
        .unwrap_or(current_max_results)
        .clamp(1, 1000);
    let next_run = if enabled {
        scheduler::next_run_text(&cron, chrono::Utc::now()).ok()
    } else {
        None
    };
    let mut merged_payload: Value =
        serde_json::from_str(&current_payload).unwrap_or_else(|_| json!({}));
    merge_payload(&mut merged_payload, &body);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "UPDATE scheduled_test_plans
             SET model=?2,cron=?3,enabled=?4,auto_recover=?5,max_results=?6,next_run=?7,payload=?8
             WHERE id=?1",
            rusqlite::params![
                id,
                model,
                cron,
                enabled,
                auto_recover,
                max_results,
                next_run,
                merged_payload.to_string()
            ],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        body["id"] = id.into();
        body["account_id"] = account_id.into();
        body["model"] = model.clone().into();
        body["model_id"] = model.into();
        body["cron"] = cron.clone().into();
        body["cron_expression"] = cron.into();
        body["enabled"] = enabled.into();
        body["auto_recover"] = auto_recover.into();
        body["max_results"] = max_results.into();
        body["next_run"] = next_run.map(Value::String).unwrap_or(Value::Null);
        success(body)
    } else {
        failure(
            StatusCode::NOT_FOUND,
            "CR-STO-0007",
            "scheduled test plan not found",
        )
    }
}

pub async fn list_plan_results(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let rows = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
            "SELECT id,status,error_code,details,created_at
             FROM scheduled_test_results WHERE plan_id=?1 ORDER BY id DESC",
        )?;
        let rows = statement.query_map(rusqlite::params![id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    });
    match rows {
        Ok(rows) => {
            let items = rows
                .iter()
                .map(|(result_id, status, error_code, details, created_at)| {
                    let mut value: Value =
                        serde_json::from_str(details).unwrap_or_else(|_| json!({}));
                    value["id"] = (*result_id).into();
                    value["plan_id"] = id.into();
                    value["status"] = status.clone().into();
                    value["error_code"] =
                        error_code.clone().map(Value::String).unwrap_or(Value::Null);
                    value["created_at"] = created_at.clone().into();
                    value
                })
                .collect::<Vec<_>>();
            success(json!({"items":items,"total":items.len()}))
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-STO-0003",
            "could not list scheduled test results",
        ),
    }
}

pub async fn delete_plan(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    let result = state.store.with_connection(|connection| {
        connection.execute(
            "DELETE FROM scheduled_test_plans WHERE id=?1",
            rusqlite::params![id],
        )?;
        Ok::<u64, anyhow::Error>(connection.changes())
    });
    if matches!(result, Ok(1)) {
        success(json!({"deleted": true}))
    } else {
        failure(
            StatusCode::NOT_FOUND,
            "CR-STO-0007",
            "scheduled test plan not found",
        )
    }
}
// ---------------------------------------------------------------------------
// OAuth adapters: old Sub2API contract over CLIProxyAPI management OAuth
// ---------------------------------------------------------------------------

fn cli_oauth_endpoint(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("/v0/management/codex-auth-url"),
        "anthropic" => Some("/v0/management/anthropic-auth-url"),
        "antigravity" => Some("/v0/management/antigravity-auth-url"),
        "kimi" => Some("/v0/management/kimi-auth-url"),
        "grok" => Some("/v0/management/xai-auth-url"),
        "gemini" => Some("/v0/management/gemini-cli-auth-url"),
        _ => None,
    }
}

fn cli_oauth_provider_name(provider: &str) -> String {
    match provider {
        "openai" => "codex".to_owned(),
        "gemini" => "gemini-cli".to_owned(),
        "grok" => "xai".to_owned(),
        other => other.to_owned(),
    }
}

fn cli_oauth_auth_url_path(provider: &str) -> Option<String> {
    let endpoint = cli_oauth_endpoint(provider)?;
    if matches!(provider, "openai" | "anthropic") {
        Some(format!("{endpoint}?is_webui=true"))
    } else {
        Some(endpoint.to_owned())
    }
}

#[derive(Clone, Debug)]
struct GeminiOauthOptions {
    oauth_type: String,
    tier_id: String,
    project_id: String,
}

fn validate_gemini_oauth_options(body: &Value) -> Result<GeminiOauthOptions> {
    let oauth_type = match json_string(body, "oauth_type").trim() {
        "" => "google_one".to_owned(),
        value => value.to_owned(),
    };
    let expected_tier = match oauth_type.as_str() {
        "google_one" => "google_one_free",
        "code_assist" => "gcp_standard",
        _ => anyhow::bail!("unsupported Gemini oauth_type"),
    };
    let tier_id = match json_string(body, "tier_id").trim() {
        "" => expected_tier.to_owned(),
        value => value.to_owned(),
    };
    let project_id = json_string(body, "project_id").trim().to_owned();
    if tier_id != expected_tier
        || project_id.len() > 256
        || project_id.chars().any(char::is_control)
    {
        anyhow::bail!("invalid Gemini OAuth options");
    }
    Ok(GeminiOauthOptions {
        oauth_type,
        tier_id,
        project_id,
    })
}

fn oauth_session_metadata(state: &ControlState, session_state: &str) -> Result<Option<Value>> {
    let state_hmac = sha256_hex(session_state.as_bytes());
    state.store.with_connection(|connection| {
        let metadata: Option<String> = connection
            .query_row(
                "SELECT metadata FROM oauth_sessions WHERE state_hmac=?1",
                rusqlite::params![state_hmac],
                |row| row.get(0),
            )
            .optional()?;
        Ok::<Option<Value>, anyhow::Error>(
            metadata.and_then(|value| serde_json::from_str::<Value>(&value).ok()),
        )
    })
}

async fn oauth_auth_url(state: &ControlState, provider: &str, body: Option<&Value>) -> Response {
    if provider == "grok" {
        return grok_auth_url(state).await;
    }
    let Some(endpoint) = cli_oauth_auth_url_path(provider) else {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-OAU-0001",
            "unsupported OAuth provider",
        );
    };
    let gemini_options = if provider == "gemini" {
        match validate_gemini_oauth_options(body.unwrap_or(&Value::Null)) {
            Ok(options) => Some(options),
            Err(error) => {
                return failure(StatusCode::BAD_REQUEST, "CR-VAL-0003", &error.to_string())
            }
        }
    } else {
        None
    };
    match state.cli.get(&endpoint).await {
        Ok(value) => {
            let url = value.get("url").and_then(Value::as_str).unwrap_or_default();
            let session_state = value
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if url.is_empty() || session_state.is_empty() {
                return failure(
                    StatusCode::BAD_GATEWAY,
                    "CR-OAU-0003",
                    "CLI returned an incomplete OAuth URL response",
                );
            }
            let state_hmac = sha256_hex(session_state.as_bytes());
            let started_at = chrono::Utc::now().to_rfc3339();
            let expires = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
            let mut metadata = json!({"started_at": started_at});
            if let Some(options) = gemini_options {
                metadata["oauth_type"] = Value::String(options.oauth_type);
                metadata["tier_id"] = Value::String(options.tier_id);
                if !options.project_id.is_empty() {
                    metadata["project_id"] = Value::String(options.project_id);
                }
            }
            let _ = state.store.with_connection(|connection| {
                connection.execute(
                    "INSERT INTO oauth_sessions(state_hmac,provider,status,expires_at,metadata) VALUES(?1,?2,'pending',?3,?4)
                     ON CONFLICT(state_hmac) DO UPDATE SET status='pending',expires_at=excluded.expires_at,metadata=excluded.metadata",
                    rusqlite::params![state_hmac, provider, expires, metadata.to_string()],
                )?;
                Ok(())
            });
            success(json!({
                "auth_url": url,
                "url": url,
                "session_id": session_state,
                "state": session_state,
                "expires_in": 1800,
            }))
        }
        Err(_) => failure(
            StatusCode::BAD_GATEWAY,
            "CR-OAU-0003",
            "could not generate OAuth URL",
        ),
    }
}

pub async fn oauth_auth_url_openai(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    guarded!(state, headers);
    oauth_auth_url(&state, "openai", body.as_ref().map(|value| &value.0)).await
}

pub async fn oauth_auth_url_anthropic(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    guarded!(state, headers);
    oauth_auth_url(&state, "anthropic", body.as_ref().map(|value| &value.0)).await
}

pub async fn oauth_auth_url_provider(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    guarded!(state, headers);
    oauth_auth_url(&state, &provider, body.as_ref().map(|value| &value.0)).await
}

/// Poll CLI auth status until the flow completes, then load the newly saved
/// auth file and return legacy token fields.
async fn finish_oauth_session(
    state: &ControlState,
    provider: &str,
    session_state: &str,
) -> Result<Value> {
    let cli_name = cli_oauth_provider_name(provider);
    let session_hmac = sha256_hex(session_state.as_bytes());
    let started_at = state
        .store
        .with_connection(|connection| {
            let metadata: Option<String> = connection
                .query_row(
                    "SELECT metadata FROM oauth_sessions WHERE state_hmac=?1",
                    rusqlite::params![session_hmac],
                    |row| row.get(0),
                )
                .optional()?;
            Ok::<Option<String>, anyhow::Error>(metadata.and_then(|value| {
                serde_json::from_str::<Value>(&value).ok().and_then(|json| {
                    json.get("started_at")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            }))
        })
        .ok()
        .flatten();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut completed_file = None;
    loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("oauth session timed out");
        }
        let status = state
            .cli
            .get(&format!(
                "/v0/management/get-auth-status?state={session_state}"
            ))
            .await?;
        match status
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("wait")
        {
            "ok" => break,
            "error" => {
                let message = status
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("oauth failed");
                // Browser callbacks can consume and remove the one-time state
                // before Router Host polls it. Accept that race only when this
                // flow produced a fresh physical auth file for the provider.
                let files = state.cli.get("/v0/management/auth-files").await?;
                let items = files.get("files").cloned().unwrap_or(files);
                let items = items.as_array().cloned().unwrap_or_default();
                completed_file =
                    oauth_file_candidate(&items, &cli_name, provider, started_at.as_deref());
                if completed_file.is_some() {
                    break;
                }
                anyhow::bail!(
                    "oauth session failed: {message}. If the browser already showed success, Google userinfo likely timed out after the code was consumed."
                );
            }
            _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
        }
    }
    // CLIProxyAPI can report `status=ok` before its watcher has finished
    // publishing the auth-file registry. It can also expose one physical
    // Gemini auth file as several project-specific runtime-only entries.
    // Poll briefly, select a physical entry, and use modtime first because a
    // re-login updates an existing file without changing created_at.
    let candidate_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let candidate = if completed_file.is_some() {
        completed_file
    } else {
        loop {
            let files = state.cli.get("/v0/management/auth-files").await?;
            let items = files.get("files").cloned().unwrap_or_else(|| files.clone());
            let items = items.as_array().cloned().unwrap_or_default();
            if let Some(candidate) =
                oauth_file_candidate(&items, &cli_name, provider, started_at.as_deref())
            {
                break Some(candidate);
            }
            if std::time::Instant::now() >= candidate_deadline {
                break None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    };
    let Some(file) = candidate else {
        anyhow::bail!("oauth completed but no auth file appeared");
    };
    let name = oauth_file_name(&file).unwrap_or_default();
    let auth_index = file
        .get("auth_index")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(json!({
        "auth_file": name,
        "auth_index": auth_index,
        "email": file.get("email").and_then(Value::as_str).unwrap_or_default(),
        "account_id": file.get("account_id").and_then(Value::as_str).unwrap_or_default(),
        "project_id": file.get("project_id").and_then(Value::as_str).unwrap_or_default(),
    }))
}

fn oauth_file_name(item: &Value) -> Option<String> {
    ["path", "name", "filename"]
        .iter()
        .filter_map(|key| item.get(*key).and_then(Value::as_str))
        .find_map(|value| {
            std::path::Path::new(value)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.trim().is_empty())
                .map(str::to_owned)
        })
}

fn oauth_file_timestamp(item: &Value) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    ["modtime", "updated_at", "created_at"]
        .iter()
        .filter_map(|key| item.get(*key).and_then(Value::as_str))
        .find_map(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
}

fn oauth_file_candidate(
    items: &[Value],
    cli_provider: &str,
    provider: &str,
    started_at: Option<&str>,
) -> Option<Value> {
    let started_at = started_at.and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
    items
        .iter()
        .filter(|item| {
            !item
                .get("runtime_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter(|item| {
            let provider_field = item
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or_default();
            provider_field == cli_provider || provider_field == provider
        })
        .filter(|item| {
            let Some(started_at) = started_at else {
                return true;
            };
            oauth_file_timestamp(item).is_some_and(|timestamp| timestamp >= started_at)
        })
        .filter_map(|item| {
            let timestamp = oauth_file_timestamp(item)?;
            Some((timestamp, item))
        })
        .max_by_key(|(timestamp, _)| *timestamp)
        .map(|(_, item)| item.clone())
}

/// Turn a CLI-created OAuth auth file into the local account row used by the
/// Router. The CLI remains the only component that owns token material; this
/// mapping stores only non-secret identity metadata and the actual auth file
/// name so routing and account-level attribution can use the same file.
fn materialize_oauth_account(
    state: &ControlState,
    provider: &str,
    body: &Value,
    materialized: &Value,
) -> Result<Value> {
    let platform = provider.trim().to_ascii_lowercase();
    let raw_auth_file = ["auth_file", "name", "filename"]
        .iter()
        .map(|key| json_string(materialized, key))
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default();
    let auth_file = std::path::Path::new(&raw_auth_file)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("oauth produced no usable auth file"))?;
    let auth_index = {
        let candidate = json_string(materialized, "auth_index");
        if candidate.trim().is_empty() {
            auth_file.trim_end_matches(".json").to_owned()
        } else {
            candidate
        }
    };
    if !auth_index_is_safe(&auth_index) {
        anyhow::bail!("oauth returned an unsafe auth index");
    }

    let email = json_string(materialized, "email");
    let external_account_id = json_string(materialized, "account_id");
    let materialized_project_id = json_string(materialized, "project_id");
    let (identity_kind, identity_value) = if !external_account_id.trim().is_empty() {
        ("account", external_account_id.trim().to_owned())
    } else if !email.trim().is_empty() {
        ("email", email.trim().to_owned())
    } else {
        ("auth_index", auth_index.clone())
    };
    let identity = stable_identity_hmac(&platform, &format!("{identity_kind}:{identity_value}"));
    let existing_account = state.store.with_connection(|connection| {
        let mut statement = connection.prepare(
                "SELECT id,COALESCE(json_extract(payload,'$.credentials.project_id'),''),auth_file,
                    CASE WHEN stable_identity_hmac=?2 THEN 0 WHEN auth_file=?3 THEN 1 ELSE 2 END AS rank
                 FROM accounts
                 WHERE deleted_at IS NULL AND platform=?1
                   AND (stable_identity_hmac=?2
                       OR (?4<>'' AND COALESCE(json_extract(payload,'$.credentials.account_id'),
                           json_extract(payload,'$.credentials.chatgpt_account_id'),'')=?4)
                       OR (?4='' AND ?5<>'' AND json_extract(payload,'$.credentials.email')=?5)
                       OR (?4='' AND ?5='' AND auth_file=?3))
                  ORDER BY rank,id"
        )?;
        let matches = statement
            .query_map(
                rusqlite::params![platform, identity, auth_file, external_account_id, email],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let Some(best) = matches.first() else {
            return Ok::<_, anyhow::Error>(None);
        };
        if matches.get(1).is_some_and(|next| next.3 == best.3) {
            anyhow::bail!("OAuth identity matches multiple existing accounts");
        }
        Ok(Some((best.0, best.1.clone(), best.2.clone())))
    })?;
    let requested_project_id = json_string(body, "project_id").trim().to_owned();
    let project_id = if platform == "gemini" {
        if let Some((_, stored_project_id, _)) = existing_account.as_ref() {
            if materialized_project_id.trim().is_empty() {
                stored_project_id.trim().to_owned()
            } else {
                materialized_project_id.trim().to_owned()
            }
        } else if !requested_project_id.is_empty() {
            requested_project_id
        } else {
            materialized_project_id.trim().to_owned()
        }
    } else {
        materialized_project_id.trim().to_owned()
    };
    let gemini_options = if platform == "gemini"
        && (body.get("oauth_type").is_some() || body.get("tier_id").is_some())
    {
        Some(validate_gemini_oauth_options(body)?)
    } else {
        None
    };

    let requested_name = json_string(body, "name");
    let name = if !requested_name.trim().is_empty() {
        requested_name
    } else if !email.trim().is_empty() {
        format!("{} ({})", oauth_display_name(&platform), email.trim())
    } else {
        oauth_display_name(&platform).to_owned()
    };
    let priority = body
        .get("priority")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 999_999);
    let group_ids = group_ids_from(body);

    let mut credentials = serde_json::Map::new();
    if !email.trim().is_empty() {
        credentials.insert("email".to_owned(), Value::String(email));
    }
    if !external_account_id.trim().is_empty() {
        credentials.insert("account_id".to_owned(), Value::String(external_account_id));
    }
    if !project_id.trim().is_empty() {
        credentials.insert("project_id".to_owned(), Value::String(project_id));
    }
    let mut extra = json!({
        "auth_file": auth_file,
        "auth_index": auth_index,
    });
    if let Some(options) = gemini_options {
        extra["oauth_type"] = Value::String(options.oauth_type);
        extra["tier_id"] = Value::String(options.tier_id);
    }
    let payload = json!({
        "name": name,
        "notes": "Created by Codex-Router OAuth exchange.",
        "credentials": credentials,
        "extra": extra,
    });
    let payload_text = payload.to_string();

    let (id, reused) = state.store.with_connection(|connection| {
        let existing = existing_account.as_ref().map(|(id, _, _)| *id);
        if let Some(id) = existing {
            connection.execute(
                "UPDATE accounts SET auth_index=?2,auth_file=?3,stable_identity_hmac=?4,
                    status='active',schedulable=1,priority=?5,payload=?6 WHERE id=?1",
                rusqlite::params![id, auth_index, auth_file, identity, priority, payload_text],
            )?;
            sync_account_groups(connection, id, &group_ids)?;
            Ok::<(i64, bool), anyhow::Error>((id, true))
        } else {
            connection.execute(
                "INSERT INTO accounts(platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(?1,'oauth',?2,?3,?4,'active',1,?5,1,?6)",
                rusqlite::params![platform, auth_index, auth_file, identity, priority, payload_text],
            )?;
            let id = connection.last_insert_rowid();
            sync_account_groups(connection, id, &group_ids)?;
            Ok::<(i64, bool), anyhow::Error>((id, false))
        }
    })?;
    if let (Some(backend), Some((_, _, old_auth_file))) =
        (state.backend.as_ref(), existing_account.as_ref())
    {
        if !old_auth_file.eq_ignore_ascii_case(&auth_file) {
            let shared = state.store.with_connection(|connection| {
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM accounts WHERE id<>?1 AND deleted_at IS NULL
                        AND auth_file=?2 COLLATE NOCASE",
                    rusqlite::params![id, old_auth_file],
                    |row| row.get(0),
                )?;
                Ok::<bool, anyhow::Error>(count > 0)
            })?;
            if !shared {
                let old_name = std::path::Path::new(old_auth_file)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("existing OAuth auth file has no safe name")?;
                let old_path = backend.auth_dir.join(old_name);
                if old_path.is_file() {
                    if let Err(error) = std::fs::remove_file(&old_path) {
                        let _ = state.store.with_connection(|connection| {
                            connection.execute(
                                "UPDATE accounts SET status='error',schedulable=0,
                                    updated_at=CURRENT_TIMESTAMP WHERE id=?1",
                                rusqlite::params![id],
                            )?;
                            Ok(())
                        });
                        let _ = crate::router_usage::note_reauth_failure(&state.store, id);
                        return Err(error).with_context(|| {
                            format!("remove replaced OAuth auth file {old_name}")
                        });
                    }
                }
            }
        }
    }
    // Reaching this point means CLI completed a fresh OAuth exchange and the
    // resulting auth file was materialized. This is stronger evidence than a
    // generic account edit that the rejected credential was replaced.
    crate::router_usage::clear_reauth_cooldown(&state.store, id)?;

    let row = (
        id,
        platform,
        "oauth".to_owned(),
        "active".to_owned(),
        1_i64,
        priority,
        1_i64,
        payload_text,
    );
    let mut output = account_payload(&row);
    output["auth_index"] = Value::String(auth_index);
    output["auth_file"] = Value::String(auth_file);
    if reused {
        output["reused"] = Value::Bool(true);
    }
    Ok(output)
}

fn oauth_display_name(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "Claude OAuth",
        "gemini" => "Gemini OAuth",
        "antigravity" => "Antigravity OAuth",
        "grok" => "Grok OAuth",
        _ => "OAuth",
    }
}

fn effective_oauth_exchange_body(
    state: &ControlState,
    provider: &str,
    session_state: &str,
    body: &Value,
) -> Result<Value> {
    let mut effective = body.clone();
    if provider != "gemini" {
        return Ok(effective);
    }
    if let Some(metadata) = oauth_session_metadata(state, session_state)? {
        let object = effective
            .as_object_mut()
            .context("OAuth exchange body must be an object")?;
        for field in ["oauth_type", "tier_id", "project_id"] {
            let missing = object
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty());
            if missing {
                if let Some(value) = metadata
                    .get(field)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    object.insert(field.to_owned(), Value::String(value.to_owned()));
                }
            }
        }
    }
    let options = validate_gemini_oauth_options(&effective)?;
    let object = effective
        .as_object_mut()
        .context("OAuth exchange body must be an object")?;
    object.insert("oauth_type".to_owned(), Value::String(options.oauth_type));
    object.insert("tier_id".to_owned(), Value::String(options.tier_id));
    if !options.project_id.is_empty() {
        object.insert("project_id".to_owned(), Value::String(options.project_id));
    }
    Ok(effective)
}

async fn oauth_exchange_code(state: &ControlState, provider: &str, body: &Value) -> Response {
    let session_state = json_string(body, "state");
    let session_state = if session_state.trim().is_empty() {
        json_string(body, "session_id")
    } else {
        session_state
    };
    let code = json_string(body, "code");
    if session_state.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-OAU-0006",
            "oauth state/session_id is required",
        );
    }
    let effective_body = match effective_oauth_exchange_body(state, provider, &session_state, body)
    {
        Ok(body) => body,
        Err(error) => return failure(StatusCode::BAD_REQUEST, "CR-VAL-0003", &error.to_string()),
    };
    if provider == "antigravity" && !code.trim().is_empty() {
        return complete_antigravity_oauth(state, &effective_body, &code).await;
    }
    if provider == "grok" && !code.trim().is_empty() {
        return complete_grok_oauth(state, &effective_body, &session_state, &code).await;
    }
    // Manual-code providers forward the pasted code into the CLI callback.
    if !code.trim().is_empty() {
        let callback = json!({
            "provider": cli_oauth_provider_name(provider),
            "code": code,
            "state": session_state,
        });
        if state
            .cli
            .post("/v0/management/oauth-callback", callback)
            .await
            .is_err()
        {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0007",
                "CLI rejected the OAuth code",
            );
        }
    }
    match finish_oauth_session(state, provider, &session_state).await {
        Ok(materialized) => {
            if materialized
                .get("auth_file")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            {
                match materialize_oauth_account(state, provider, &effective_body, &materialized) {
                    Ok(account) => {
                        let _ = sync_backend(state).await;
                        success(account)
                    }
                    Err(error) => {
                        failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string())
                    }
                }
            } else {
                // Keep the legacy token response for CLI implementations that
                // complete OAuth without exposing an auth-file record yet.
                success(materialized)
            }
        }
        Err(error) => failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string()),
    }
}

fn cli_runtime_proxy_url(state: &ControlState) -> Option<String> {
    let path = state.backend.as_ref()?.config_path.clone();
    let text = std::fs::read_to_string(path).ok()?;
    config_compiler::from_yaml(&text)
        .ok()?
        .proxy_url
        .filter(|value| !value.trim().is_empty())
}

async fn grok_auth_url(state: &ControlState) -> Response {
    let session = super::grok_oauth::new_pkce_session();
    let url = super::grok_oauth::authorization_url(&session);
    let started_at = chrono::Utc::now().to_rfc3339();
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
    let state_hmac = sha256_hex(session.state.as_bytes());
    let metadata = json!({
        "started_at": started_at,
        "code_verifier": session.code_verifier,
        "nonce": session.nonce,
        "redirect_uri": super::grok_oauth::REDIRECT_URI,
    });
    if state
        .store
        .with_connection(|connection| {
            connection.execute(
                "INSERT INTO oauth_sessions(state_hmac,provider,status,expires_at,metadata) VALUES(?1,'grok','pending',?2,?3)
                 ON CONFLICT(state_hmac) DO UPDATE SET status='pending',expires_at=excluded.expires_at,metadata=excluded.metadata",
                rusqlite::params![state_hmac, expires, metadata.to_string()],
            )?;
            Ok(())
        })
        .is_err()
    {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-OAU-0003",
            "could not store Grok OAuth session",
        );
    }
    success(json!({
        "auth_url": url,
        "url": url,
        "session_id": session.state,
        "state": session.state,
        "expires_in": 1800,
    }))
}

async fn complete_grok_oauth(
    state: &ControlState,
    body: &Value,
    session_state: &str,
    code: &str,
) -> Response {
    let verifier = match oauth_session_metadata(state, session_state) {
        Ok(Some(metadata)) => metadata
            .get("code_verifier")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        Ok(None) => String::new(),
        Err(error) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0006",
                &format!("Grok OAuth session is unreadable: {error}"),
            );
        }
    };
    if verifier.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-OAU-0006",
            "Grok OAuth session is missing the PKCE verifier; start login again",
        );
    }
    let proxy_url = cli_runtime_proxy_url(state);
    let code = code.to_owned();
    let exchanged = match tokio::task::spawn_blocking(move || {
        super::grok_oauth::exchange_authorization_code(&code, &verifier, proxy_url.as_deref())
    })
    .await
    {
        Ok(Ok(tokens)) => tokens,
        Ok(Err(error)) => {
            let _ = state.logger.write(json!({
                "level":"ERROR",
                "event":"control.grok_oauth_exchange_failed",
                "error_code":"CR-OAU-0007",
                "error_description":error.to_string(),
            }));
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0007",
                &format!("Grok token exchange failed: {error}"),
            );
        }
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0008",
                "Grok token exchange task failed",
            );
        }
    };
    let Some(backend) = state.backend.as_ref() else {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-CLI-0007",
            "auth directory is unavailable",
        );
    };
    let stem = super::grok_oauth::auth_file_stem(&exchanged.email);
    let document = super::grok_oauth::auth_document(&exchanged);
    if let Err(error) = write_auth_file(&backend.auth_dir, &stem, &document) {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-OAU-0011",
            &format!("could not write Grok auth file: {error}"),
        );
    }
    let _ = state.logger.write(json!({
        "level":"INFO",
        "event":"control.grok_oauth_completed",
        "has_email":!exchanged.email.trim().is_empty(),
    }));
    let materialized = json!({
        "auth_file": format!("{stem}.json"),
        "auth_index": stem,
        "email": exchanged.email,
        "account_id": exchanged.sub,
    });
    match materialize_oauth_account(state, "grok", body, &materialized) {
        Ok(account) => {
            let _ = sync_backend(state).await;
            success(account)
        }
        Err(error) => failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string()),
    }
}

async fn complete_antigravity_oauth(state: &ControlState, body: &Value, code: &str) -> Response {
    let proxy_url = cli_runtime_proxy_url(state);
    let code = code.to_owned();
    let exchanged = match tokio::task::spawn_blocking(move || {
        super::antigravity_oauth::exchange_authorization_code(&code, proxy_url.as_deref())
    })
    .await
    {
        Ok(Ok(tokens)) => tokens,
        Ok(Err(error)) => {
            let _ = state.logger.write(json!({
                "level":"ERROR",
                "event":"control.antigravity_oauth_exchange_failed",
                "error_code":"CR-OAU-0007",
                "error_description":error.to_string(),
            }));
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0007",
                &format!("Antigravity token exchange failed: {error}"),
            );
        }
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0008",
                "Antigravity token exchange task failed",
            );
        }
    };
    let Some(backend) = state.backend.as_ref() else {
        return failure(
            StatusCode::BAD_GATEWAY,
            "CR-CLI-0007",
            "auth directory is unavailable",
        );
    };
    let stem = super::antigravity_oauth::auth_file_stem(&exchanged.email);
    let document = super::antigravity_oauth::auth_document(&exchanged);
    if let Err(error) = write_auth_file(&backend.auth_dir, &stem, &document) {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CR-OAU-0011",
            &format!("could not write Antigravity auth file: {error}"),
        );
    }
    let _ = state.logger.write(json!({
        "level":"INFO",
        "event":"control.antigravity_oauth_completed",
        "email_source":exchanged.email_source,
        "has_project":!exchanged.project_id.trim().is_empty(),
    }));
    let materialized = json!({
        "auth_file": format!("{stem}.json"),
        "auth_index": stem,
        "email": exchanged.email,
        "account_id": "",
        "project_id": exchanged.project_id,
    });
    match materialize_oauth_account(state, "antigravity", body, &materialized) {
        Ok(account) => {
            let _ = sync_backend(state).await;
            success(account)
        }
        Err(error) => failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string()),
    }
}

fn oauth_platform_from_cli_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "codex" | "openai" => Some("openai"),
        "claude" | "anthropic" => Some("anthropic"),
        "gemini-cli" => Some("gemini"),
        "antigravity" => Some("antigravity"),
        "xai" | "grok" => Some("grok"),
        _ => None,
    }
}

fn oauth_route_provider_matches(account_platform: &str, route_platform: &str) -> bool {
    let account = config_compiler::normalize_platform(account_platform);
    let route = config_compiler::normalize_platform(route_platform);
    account == route
}

fn model_slug(model: &str) -> String {
    model
        .trim()
        .trim_start_matches('~')
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase()
}

fn same_route_model(left: &str, right: &str) -> bool {
    let left = model_slug(left);
    let right = model_slug(right);
    !left.is_empty() && left == right
}

fn normalize_upstream_model_for_platform(platform: &str, model: &str) -> String {
    let p = config_compiler::normalize_platform(platform);
    if p == "antigravity" {
        if model == "claude-fable-5" || model.starts_with("claude-fable") {
            return "claude-sonnet-4-6".to_owned();
        }
        if model == "gemini-3.7-flash" || model == "gemini-3.7-flash-medium" {
            return "gemini-3.7-flash-high".to_owned();
        }
        if model == "gemini-3.8-flash"
            || model == "gemini-3.8-flash-medium"
            || model == "gemini-3.8-flash-high"
        {
            // CLIProxy 7.2.135 does not register Gemini 3.8 SKUs. Keep the
            // public 3.8 id and send a live 3.7 Flash SKU upstream.
            return "gemini-3.7-flash-high".to_owned();
        }
        if model == "gemini-3.1-pro-high" || model == "gemini-3.1-pro" {
            return "gemini-3.1-pro-low".to_owned();
        }
    }
    model.to_owned()
}

fn mapped_upstream_model(
    payload: &Value,
    platform: &str,
    public_model: &str,
    upstream_model: &str,
) -> String {
    let candidate = if let Some(mapping) = payload
        .pointer("/credentials/model_mapping")
        .and_then(Value::as_object)
    {
        let mut found = None;
        for key in [upstream_model, public_model] {
            if let Some(mapped) = mapping
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                found = Some(mapped.to_owned());
                break;
            }
        }
        found.unwrap_or_else(|| {
            mapping
                .iter()
                .find_map(|(from, to)| {
                    let to = to.as_str().unwrap_or("").trim();
                    if to.is_empty() {
                        return None;
                    }
                    if same_route_model(from, public_model)
                        || same_route_model(from, upstream_model)
                        || same_route_model(to, public_model)
                        || same_route_model(to, upstream_model)
                    {
                        Some(to.to_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| upstream_model.to_owned())
        })
    } else {
        upstream_model.to_owned()
    };
    normalize_upstream_model_for_platform(platform, &candidate)
}

fn api_route_model_matches(payload: &Value, public_model: &str, upstream_model: &str) -> bool {
    let Some(mapping) = payload
        .pointer("/credentials/model_mapping")
        .and_then(Value::as_object)
    else {
        return false;
    };
    mapping.iter().any(|(from, to)| {
        let to = to.as_str().unwrap_or("");
        same_route_model(from, public_model)
            || same_route_model(from, upstream_model)
            || same_route_model(to, public_model)
            || same_route_model(to, upstream_model)
    })
}

fn oauth_route_model_matches(payload: &Value, public_model: &str, upstream_model: &str) -> bool {
    let Some(mapping) = payload
        .pointer("/credentials/model_mapping")
        .and_then(Value::as_object)
    else {
        return true;
    };
    if mapping.is_empty() {
        return true;
    }
    api_route_model_matches(payload, public_model, upstream_model)
}

#[cfg(test)]
fn oauth_replica_alias(auth_type: &str, pool_prefix: &str, public_model: &str) -> String {
    let aliases = oauth_replica_aliases(auth_type, pool_prefix, public_model);
    aliases
        .iter()
        .find(|alias| alias.contains('/'))
        .cloned()
        .or_else(|| aliases.into_iter().next())
        .unwrap_or_else(|| public_model.to_owned())
}

fn oauth_replica_aliases(_auth_type: &str, pool_prefix: &str, public_model: &str) -> Vec<String> {
    let public = public_model.trim();
    if public.is_empty() {
        return Vec::new();
    }
    let prefixed = format!("{pool_prefix}/{public}");
    if prefixed == public {
        vec![public.to_owned()]
    } else {
        // Host always requests `{prefix}/{public_model}`. Some CLIProxy
        // executors auto-prefix a public alias; others only honor the exact
        // alias string. Register both so Antigravity/Gemini, xAI/Grok, Claude
        // and Codex keep resolving after a watcher reload.
        vec![public.to_owned(), prefixed]
    }
}

async fn live_cli_model_ids(state: &ControlState, backend: &BackendPaths) -> HashSet<String> {
    state
        .cli
        .model_registry(&backend.downstream_key)
        .await
        .ok()
        .and_then(|value| {
            value.get("data").and_then(Value::as_array).map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn live_has_model(live: &HashSet<String>, model: &str) -> bool {
    let model = model.trim();
    if model.is_empty() {
        return false;
    }
    live.contains(model)
        || live.iter().any(|id| {
            id.rsplit_once('/')
                .is_some_and(|(_, public)| public == model)
        })
}

fn resolve_live_oauth_upstream(
    platform: &str,
    auth_type: &str,
    desired: &str,
    live: &HashSet<String>,
) -> String {
    let desired = desired.trim();
    if desired.is_empty() || live_has_model(live, desired) {
        return desired.to_owned();
    }
    let antigravity = auth_type.eq_ignore_ascii_case("antigravity")
        || auth_type.eq_ignore_ascii_case("gemini-cli")
        || config_compiler::normalize_platform(platform) == "gemini";
    if antigravity && desired.to_ascii_lowercase().contains("gemini-3.8") {
        // CLIProxy 7.2.135 still lists 3.7 Flash as the newest Gemini SKU.
        // Keep the public 3.8 id, but point the alias at a live Flash SKU
        // so Host's `{prefix}/gemini-3.8-flash` request is not unknown.
        for fallback in [
            "gemini-3.7-flash-high",
            "gemini-3.7-flash",
            "gemini-3.6-flash-high",
            "gemini-3-flash",
        ] {
            if live.is_empty() || live_has_model(live, fallback) {
                return fallback.to_owned();
            }
        }
    }
    if antigravity && desired.to_ascii_lowercase().contains("gemini") {
        for fallback in [
            "gemini-3.8-flash-high",
            "gemini-3.7-flash-high",
            "gemini-3.6-flash-high",
            "gemini-3-flash",
        ] {
            if live_has_model(live, fallback) {
                return fallback.to_owned();
            }
        }
    }
    desired.to_owned()
}

fn push_oauth_replica_alias(aliases: &mut Vec<Value>, name: &str, alias: &str) {
    let exists = aliases.iter().any(|entry| {
        entry.get("name").and_then(Value::as_str) == Some(name)
            && entry.get("alias").and_then(Value::as_str) == Some(alias)
    });
    if !exists {
        aliases.push(json!({
            "name": name,
            "alias": alias,
            "force-mapping": true,
        }));
    }
}

fn account_is_cli_eligible(schedulable: i64, status: &str) -> bool {
    if schedulable == 0 {
        return false;
    }
    !matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "disabled" | "error"
    )
}

/// OAuth accounts get their own CLIProxy prefix. Google/xAI quota 429 cools
/// every credential in a prefix, so three Antigravity logins on one Gemini
/// card must not share `cr_r13_antigravity`. API-key fallback stays `r{id}f`.
fn pool_route_id_for_account(
    route_id: i64,
    account_type: &str,
    route_has_oauth: bool,
    account_id: i64,
) -> String {
    if account_type.eq_ignore_ascii_case("oauth") {
        format!("r{route_id}a{account_id}")
    } else if route_has_oauth {
        format!("r{route_id}f")
    } else {
        format!("r{route_id}")
    }
}

fn fallback_pool_priority(route_priority: i64) -> i32 {
    let base = route_priority.max(1) as i32;
    base.saturating_add(99).clamp(1, 999)
}

async fn sync_existing_oauth_accounts(state: &ControlState) -> Result<usize> {
    let files = state.cli.get("/v0/management/auth-files").await?;
    let items = files.get("files").cloned().unwrap_or(files);
    let Some(items) = items.as_array() else {
        return Ok(0);
    };
    let mut imported = 0;
    for item in items {
        if item
            .get("runtime_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(cli_provider) = item.get("provider").and_then(Value::as_str) else {
            continue;
        };
        let Some(platform) = oauth_platform_from_cli_provider(cli_provider) else {
            continue;
        };
        let Some(auth_file) = oauth_file_name(item) else {
            continue;
        };
        if auth_file.starts_with("cr-router-oauth-") {
            continue;
        }
        if let Some(backend) = state.backend.as_ref() {
            if !backend.auth_dir.join(&auth_file).is_file() {
                continue;
            }
        }
        let auth_index = json_string(item, "auth_index");
        let email = json_string(item, "email");
        let external_account_id = json_string(item, "account");
        let identity_value = if !external_account_id.trim().is_empty() {
            format!("account:{external_account_id}")
        } else if !email.trim().is_empty() {
            format!("email:{email}")
        } else {
            format!("auth_index:{auth_index}")
        };
        let identity = stable_identity_hmac(platform, &identity_value);
        let exists = state.store.with_connection(|connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM accounts WHERE deleted_at IS NULL AND platform=?1 AND (stable_identity_hmac=?2 OR auth_file=?3)",
                rusqlite::params![platform, identity, auth_file],
                |row| row.get(0),
            )?;
            Ok::<bool, anyhow::Error>(count > 0)
        })?;
        if exists {
            continue;
        }
        let mut materialized = item.clone();
        materialized["auth_file"] = Value::String(auth_file);
        materialized["auth_index"] = Value::String(auth_index);
        materialized["account_id"] = Value::String(external_account_id);
        materialized["email"] = Value::String(email);
        materialized["project_id"] = item.get("project_id").cloned().unwrap_or(Value::Null);
        materialize_oauth_account(state, platform, &json!({}), &materialized)?;
        imported += 1;
    }
    if imported > 0 {
        let _ = sync_backend(state).await;
    }
    Ok(imported)
}

pub async fn oauth_exchange_code_anthropic(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    oauth_exchange_code(&state, "anthropic", &body).await
}

pub async fn oauth_exchange_code_provider(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    oauth_exchange_code(&state, &provider, &body).await
}

/// Old OpenAI one-shot endpoint: exchange and create the account atomically.
pub async fn openai_create_from_oauth(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let session_state = json_string(&body, "state");
    let session_state = if session_state.trim().is_empty() {
        json_string(&body, "session_id")
    } else {
        session_state
    };
    let code = json_string(&body, "code");
    if session_state.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-OAU-0006",
            "oauth state is required",
        );
    }
    if !code.trim().is_empty() {
        let callback = json!({"provider": "codex", "code": code, "state": session_state});
        if state
            .cli
            .post("/v0/management/oauth-callback", callback)
            .await
            .is_err()
        {
            return failure(
                StatusCode::BAD_GATEWAY,
                "CR-OAU-0007",
                "CLI rejected the OAuth code",
            );
        }
    }
    let materialized = match finish_oauth_session(&state, "openai", &session_state).await {
        Ok(value) => value,
        Err(error) => return failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string()),
    };
    match materialize_oauth_account(&state, "openai", &body, &materialized) {
        Ok(account) => match sync_backend(&state).await {
            Ok(_) => success(account),
            Err(error) => {
                let _ = state.logger.write(json!({
                    "level":"ERROR",
                    "event":"control.oauth_relogin_sync_failed",
                    "account_id":account.get("id"),
                    "error_description":error.to_string(),
                }));
                failure(
                    StatusCode::BAD_GATEWAY,
                    "CR-CFG-0005",
                    "OAuth login succeeded but backend sync failed",
                )
            }
        },
        Err(error) => failure(StatusCode::BAD_GATEWAY, "CR-OAU-0008", &error.to_string()),
    }
}

/// Old Grok batch endpoint: convert SSO tokens into xAI OAuth auth files.
pub async fn grok_sso_to_oauth(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    guarded!(state, headers);
    let tokens: Vec<String> = body
        .get("sso_tokens")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if tokens.is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "CR-VAL-0003",
            "sso_tokens must be a non-empty array",
        );
    }
    let priority = body
        .get("priority")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 999_999);
    let group_ids = group_ids_from(&body);
    let base_name = json_string(&body, "name");
    let base_name = if base_name.trim().is_empty() {
        "Grok OAuth".to_owned()
    } else {
        base_name
    };
    let mut created = Vec::new();
    let mut failed = Vec::new();
    for token in tokens {
        let normalized = super::grok_sso::normalize_sso_token(&token);
        if normalized.is_empty() {
            failed.push(json!({"error": "empty sso token"}));
            continue;
        }
        let identity = stable_identity_hmac("grok", &normalized);
        let duplicate = state.store.with_connection(|connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM accounts WHERE stable_identity_hmac=?1 AND deleted_at IS NULL",
                rusqlite::params![identity],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        }).unwrap_or(false);
        if duplicate {
            failed.push(json!({"error": "duplicate account identity"}));
            continue;
        }
        let proxy_url = body
            .get("proxy_url")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let conversion = {
            let token = normalized.clone();
            let proxy = proxy_url.clone();
            tokio::task::spawn_blocking(move || {
                super::grok_sso::convert_sso_to_oauth(&token, proxy.as_deref())
            })
            .await
        };
        let tokens = match conversion {
            Ok(Ok(tokens)) => tokens,
            Ok(Err(error)) => {
                failed.push(json!({"error": error.to_string()}));
                continue;
            }
            Err(_) => {
                failed.push(json!({"error": "conversion task failed"}));
                continue;
            }
        };
        let credentials = super::grok_sso::tokens_to_credentials(&tokens);
        let auth_index = format!("cr-account-{}", &identity[..16]);
        let document = match build_auth_file("grok", &credentials, None) {
            Ok(document) => document,
            Err(error) => {
                failed.push(json!({"error": error.to_string()}));
                continue;
            }
        };
        if let Some(backend) = &state.backend {
            if let Err(error) = write_auth_file(&backend.auth_dir, &auth_index, &document) {
                failed.push(json!({"error": format!("could not write auth file: {error}")}));
                continue;
            }
        }
        let payload =
            json!({"name": base_name, "notes": "Imported by Codex-Router SSO conversion."});
        let result = state.store.with_connection(|connection| {
            connection.execute(
                "INSERT INTO accounts(platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES('grok','oauth',?1,?2,?3,'active',1,?4,1,?5)",
                rusqlite::params![auth_index, format!("{auth_index}.json"), identity, priority, payload.to_string()],
            )?;
            let id = connection.last_insert_rowid();
            sync_account_groups(connection, id, &group_ids)?;
            Ok::<i64, anyhow::Error>(id)
        });
        match result {
            Ok(id) => created
                .push(json!({"id": id, "platform": "grok", "type": "oauth", "name": base_name})),
            Err(error) => failed.push(json!({"error": error.to_string()})),
        }
    }
    let _ = sync_backend(&state).await;
    success(json!({"created": created, "failed": failed}))
}

// ---------------------------------------------------------------------------
// Provider quota proxies
// ---------------------------------------------------------------------------

pub async fn account_quota(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    guarded!(state, headers);
    account_usage_for_state(&state, id).await
}

// ---------------------------------------------------------------------------
// Aggregate health
// ---------------------------------------------------------------------------

pub async fn health_json(state: &ControlState) -> Result<Value> {
    let sqlite = state.store.integrity_check().unwrap_or(false);
    let cli_process = state.cli.health().await.is_ok();
    let cli_management = cli_process && state.cli.auth_files().await.is_ok();
    let cli_models = if let Some(backend) = state.backend.as_ref() {
        cli_process
            && state
                .cli
                .model_registry(&backend.downstream_key)
                .await
                .is_ok()
    } else {
        cli_process
    };
    let administrator = crate::credentials::read_text("AdminPassword")
        .ok()
        .flatten()
        .is_some_and(|secret| !secret.trim().is_empty());
    let healthy = sqlite && cli_process && cli_management && cli_models && administrator;
    Ok(json!({
        "status": if healthy { "healthy" } else { "degraded" },
        "components": [
            {"name":"Router Host","healthy":true},
            {"name":"SQLite","healthy":sqlite},
            {"name":"CLIProxyAPI","healthy":cli_process},
            {"name":"CLI management","healthy":cli_management},
            {"name":"CLI model registry","healthy":cli_models},
            {"name":"Administrator bootstrap","healthy":administrator},
        ]
    }))
}

trait OptionalConnectionResult {
    fn optional_error(self) -> Result<Option<String>>;
}

impl OptionalConnectionResult for rusqlite::Result<String> {
    fn optional_error(self) -> Result<Option<String>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[test]
    fn oauth_and_relay_get_separate_pool_ids() {
        assert_eq!(pool_route_id_for_account(1, "oauth", true, 52), "r1a52");
        assert_eq!(pool_route_id_for_account(13, "oauth", true, 53), "r13a53");
        assert_ne!(
            pool_route_id_for_account(13, "oauth", true, 52),
            pool_route_id_for_account(13, "oauth", true, 53)
        );
        assert_eq!(pool_route_id_for_account(1, "apikey", true, 9), "r1f");
        assert_eq!(pool_route_id_for_account(3, "apikey", false, 9), "r3");
        assert_eq!(fallback_pool_priority(1), 100);
        assert!(!account_is_cli_eligible(1, "disabled"));
        assert!(!account_is_cli_eligible(0, "active"));
        assert!(account_is_cli_eligible(1, "active"));
    }

    #[test]
    fn openai_router_replica_consumes_desktop_access_token_without_refresh_token() {
        let root = std::env::temp_dir().join(format!(
            "codex-router-openai-token-sync-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let desktop_auth = root.join("auth.json");
        std::fs::write(
            &desktop_auth,
            r#"{"tokens":{"access_token":"desktop-access","refresh_token":"desktop-refresh","account_id":"acct"}}"#,
        )
        .unwrap();
        let mut document = json!({
            "type":"codex",
            "access_token":"old-access",
            "refresh_token":"old-refresh"
        });
        sync_openai_access_token(&mut document, &desktop_auth);
        assert_eq!(document["access_token"], "desktop-access");
        assert!(document.get("refresh_token").is_none());
        let auth_dir = root.join("auth");
        write_auth_file(
            &auth_dir,
            "codex-source",
            &json!({"type":"codex","access_token":"a","refresh_token":"must-not-land"}),
        )
        .unwrap();
        let written: Value =
            serde_json::from_slice(&std::fs::read(auth_dir.join("codex-source.json")).unwrap())
                .unwrap();
        assert_eq!(written["access_token"], "a");
        assert!(written.get("refresh_token").is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn openai_sync_upstream_does_not_touch_the_replica_file() {
        let root =
            std::env::temp_dir().join(format!("router-openai-sync-skip-{}", uuid::Uuid::now_v7()));
        let auth_dir = root.join("auth");
        std::fs::create_dir_all(&auth_dir).unwrap();
        let replica = auth_dir.join("cr-router-oauth-1-1-codex.json");
        let original = br#"{"type":"codex","access_token":"desktop-access"}"#;
        std::fs::write(&replica, original).unwrap();
        let mtime = std::fs::metadata(&replica).unwrap().modified().unwrap();
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(1,'openai','oauth','codex','cr-router-oauth-1-1-codex.json','identity','active',1,1,1,'{}')",
                    [],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new("http://127.0.0.1:1", "test-management-secret")
                .unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: Some(Arc::new(BackendPaths {
                config_path: root.join("config.yaml"),
                auth_dir: auth_dir.clone(),
                downstream_key: "downstream".to_owned(),
                management_secret: "test-management-secret".to_owned(),
                cli_port: 1,
                desktop_auth_path: root.join("desktop-auth.json"),
            })),
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let _ = account_models_sync_upstream_for_state(&state, 1).await;
        assert_eq!(std::fs::read(&replica).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&replica).unwrap().modified().unwrap(),
            mtime,
            "openai sync-upstream must not rewrite the Desktop-owned replica"
        );
        let leftover = auth_dir.join("legacy-openai-1.json");
        std::fs::write(&leftover, br#"{"refresh_token":"dead"}"#).unwrap();
        quarantine_legacy_openai_auth_files(&auth_dir, &state.logger);
        assert!(!leftover.is_file());
        assert!(auth_dir.join("legacy-openai-1.json.quarantined").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn update_group_sql_binds_id_as_the_last_placeholder() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE groups (
                id INTEGER PRIMARY KEY,
                name TEXT,
                status TEXT,
                models TEXT,
                payload TEXT,
                deleted_at TEXT,
                updated_at TEXT
            );",
        )
        .unwrap();
        db.execute(
            "INSERT INTO groups(id,name,status,models,payload) VALUES(3,'Codex-Router','active','[]','{}')",
            [],
        )
        .unwrap();
        let changed = db
            .execute(
                "UPDATE groups SET name=COALESCE(?1,name),status=COALESCE(?2,status),models=COALESCE(?3,models),payload=?4,updated_at=CURRENT_TIMESTAMP WHERE id=?5 AND deleted_at IS NULL",
                rusqlite::params![
                    Some("Codex-Router"),
                    Some("active"),
                    Some(r#"["gpt-5.6-sol"]"#),
                    "{}",
                    3_i64
                ],
            )
            .unwrap();
        assert_eq!(changed, 1);
        let models: String = db
            .query_row("SELECT models FROM groups WHERE id=3", [], |row| row.get(0))
            .unwrap();
        assert!(models.contains("gpt-5.6-sol"));
    }

    type ModelSyncMockState = Arc<Mutex<(usize, Option<usize>)>>;

    #[derive(Clone)]
    struct AccountProbeMockState {
        requests: Arc<Mutex<Vec<Value>>>,
        upstream_status: u16,
    }

    async fn mock_probe_auth_files() -> Json<Value> {
        Json(json!({
            "files":[{
                "name":"probe.json",
                "auth_index":"authoritative-probe-index"
            }]
        }))
    }

    async fn mock_account_probe(
        State(state): State<AccountProbeMockState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        state
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(request);
        Json(json!({
            "status_code":state.upstream_status,
            "header":{},
            "body":if state.upstream_status == 200 { "{}" } else { "{\"secret\":\"must-not-escape\"}" }
        }))
    }

    async fn account_probe_test_state(
        root: &std::path::Path,
        upstream_status: u16,
        platform: &str,
    ) -> (
        ControlState,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mock_state = AccountProbeMockState {
            requests: requests.clone(),
            upstream_status,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = Router::new()
            .route("/v0/management/auth-files", get(mock_probe_auth_files))
            .route("/v0/management/api-call", post(mock_account_probe))
            .with_state(mock_state);
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload)
                     VALUES(1,?1,'oauth','stale-index','probe.json','probe-identity','error',0,1,1,?2)",
                    rusqlite::params![
                        platform,
                        json!({"credentials":{"base_url":"https://cli-chat-proxy.grok.com/v1"}}).to_string()
                    ],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new(
                format!("http://{address}"),
                "test-management-secret",
            )
            .unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        (state, requests, server)
    }

    async fn mock_antigravity_api_call(
        State(requests): State<Arc<Mutex<Vec<Value>>>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(request);
        let upstream = json!({
            "models": {
                "gemini-live": {
                    "displayName": "Gemini Live",
                    "quotaInfo": {
                        "remainingFraction": 0.75,
                        "resetTime": "2026-08-20T00:00:00Z"
                    }
                }
            }
        });
        Json(json!({
            "status_code": 200,
            "header": {},
            "body": upstream.to_string()
        }))
    }

    async fn mock_antigravity_unauthorized_api_call(
        State(requests): State<Arc<Mutex<Vec<Value>>>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(request);
        Json(json!({
            "status_code": 401,
            "header": {},
            "body": "{}"
        }))
    }

    async fn mock_models_after_reload(State(state): State<ModelSyncMockState>) -> Json<Value> {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.0 += 1;
        if state.1.is_some_and(|ready_after| state.0 >= ready_after) {
            Json(json!({"models": [{"id": "gemini-3.1-pro-high"}]}))
        } else {
            Json(json!({"models": []}))
        }
    }

    async fn antigravity_usage_test_state(
        root: &std::path::Path,
    ) -> (
        ControlState,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = Router::new()
            .route("/v0/management/api-call", post(mock_antigravity_api_call))
            .with_state(requests.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(1,'antigravity','oauth','ag-auth','ag.json','ag-identity','active',1,1,1,?1)",
                    rusqlite::params![json!({
                        "proxy_url":"http://127.0.0.1:9999",
                        "credentials":{"project_id":"ag-project"}
                    }).to_string()],
                )?;
                connection.execute(
                    "INSERT INTO admin_tokens(token_hmac,expires_at) VALUES(?1,?2)",
                    rusqlite::params![
                        sha256_hex(b"test-admin-token"),
                        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
                    ],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let logger = Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap());
        let cli =
            CliProxyManagementClient::new(format!("http://{address}"), "test-management-secret")
                .unwrap();
        let state = ControlState {
            store,
            cli,
            logger,
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        (state, requests, server)
    }

    #[tokio::test]
    async fn antigravity_usage_refreshes_live_model_quota_through_cli() {
        let root =
            std::env::temp_dir().join(format!("router-antigravity-usage-{}", uuid::Uuid::now_v7()));
        let (state, requests, server) = antigravity_usage_test_state(&root).await;
        let app = Router::new()
            .route("/api/v1/admin/accounts/{id}/{action}", get(account_action))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/accounts/1/usage?force=true")
                    .header(header::AUTHORIZATION, "Bearer test-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["data"]["stale"], false);
        assert_eq!(body["data"]["source"], "upstream");
        assert_eq!(
            body["data"]["antigravity_quota"]["gemini-live"]["utilization"],
            25.0
        );
        assert_eq!(
            body["data"]["antigravity_quota_details"]["gemini-live"]["display_name"],
            "Gemini Live"
        );

        let requests = requests.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["auth_index"], "ag-auth");
        assert_eq!(
            requests[0]["url"],
            "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels"
        );
        assert_eq!(requests[0]["data"], r#"{"project":"ag-project"}"#);
        assert_eq!(requests[0]["proxy_url"], "http://127.0.0.1:9999");
        drop(requests);
        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn recovery_activates_account_only_after_scoped_probe_succeeds() {
        let root = std::env::temp_dir().join(format!(
            "router-account-probe-success-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, requests, server) = account_probe_test_state(&root, 200, "grok").await;

        let response = recover_account_after_probe(&state, 1, "grok-test").await;

        assert_eq!(response.status(), StatusCode::OK);
        let status: (String, i64) = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(status, ("active".to_owned(), 1));
        assert!(!crate::router_usage::reauth_cooldown_active(&state.store, 1).unwrap());
        let requests = requests.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["auth_index"], "authoritative-probe-index");
        assert_eq!(
            requests[0]["url"],
            "https://cli-chat-proxy.grok.com/v1/responses"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn desktop_openai_recovery_reenables_locally_without_cli_probe() {
        let root = std::env::temp_dir().join(format!(
            "router-openai-recovery-skip-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, requests, server) = account_probe_test_state(&root, 200, "openai").await;
        let response = recover_account_after_probe(&state, 1, "gpt-test").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["data"]["probed"], false);
        assert_eq!(body["data"]["schedulable"], true);
        assert_eq!(body["data"]["reason"], "desktop_openai_auth_owner");
        assert_eq!(
            requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            0,
            "ChatGPT recovery must not send $TOKEN$ through CLIProxyAPI"
        );
        let status: (String, i64) = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(status, ("active".to_owned(), 1));
        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_recovery_probe_keeps_account_isolated_and_redacts_body() {
        let root = std::env::temp_dir().join(format!(
            "router-account-probe-failure-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, _requests, server) = account_probe_test_state(&root, 401, "grok").await;

        let response = recover_account_after_probe(&state, 1, "gpt-test").await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response
                .headers()
                .get("x-codex-router-error-code")
                .and_then(|value| value.to_str().ok()),
            Some("CR-UP-0002")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("must-not-escape"));
        let status: (String, i64) = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(status, ("error".to_owned(), 0));
        assert!(crate::router_usage::reauth_cooldown_active(&state.store, 1).unwrap());

        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn reauth_cooldown_blocks_recovery_without_touching_upstream() {
        let root = std::env::temp_dir().join(format!(
            "router-account-probe-cooldown-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, requests, server) = account_probe_test_state(&root, 200, "grok").await;
        crate::router_usage::note_reauth_failure(&state.store, 1).unwrap();

        let response = recover_account_after_probe(&state, 1, "grok-test").await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty());
        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn grok_generation_quota_failure_keeps_account_out_of_the_pool() {
        let root = std::env::temp_dir().join(format!(
            "router-grok-recovery-quota-failure-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, requests, server) = account_probe_test_state(&root, 429, "grok").await;

        let response = recover_account_after_probe(&state, 1, "grok-4.6").await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let status: (String, i64) = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(status, ("error".to_owned(), 0));
        let requests = requests.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]["url"],
            "https://cli-chat-proxy.grok.com/v1/responses"
        );
        assert_eq!(requests[0]["method"], "POST");
        let data: Value = serde_json::from_str(requests[0]["data"].as_str().unwrap()).unwrap();
        assert_eq!(data["model"], "grok-4.6");
        drop(requests);

        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn grok_successful_minimal_generation_restores_the_pool() {
        let root = std::env::temp_dir().join(format!(
            "router-grok-recovery-success-{}",
            uuid::Uuid::now_v7()
        ));
        let (state, requests, server) = account_probe_test_state(&root, 200, "grok").await;

        let response = recover_account_after_probe(&state, 1, "grok-4.6").await;

        assert_eq!(response.status(), StatusCode::OK);
        let status: (String, i64) = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(status, ("active".to_owned(), 1));
        let requests = requests.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "POST");
        assert_eq!(
            requests[0]["url"],
            "https://cli-chat-proxy.grok.com/v1/responses"
        );
        drop(requests);

        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn antigravity_usage_marks_cached_quota_stale_when_oauth_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "router-antigravity-usage-stale-{}",
            uuid::Uuid::now_v7()
        ));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = Router::new()
            .route(
                "/v0/management/api-call",
                post(mock_antigravity_unauthorized_api_call),
            )
            .with_state(requests.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(1,'antigravity','oauth','ag-auth','ag.json','ag-identity','active',1,1,1,'{}')",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO usage_windows(account_id,provider,window_kind,used,quota,reset_at,source,sampled_at) VALUES(1,'antigravity','gemini-live','40','100','2026-08-20T00:00:00Z','live','2026-08-19T00:00:00Z')",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO admin_tokens(token_hmac,expires_at) VALUES(?1,?2)",
                    rusqlite::params![
                        sha256_hex(b"test-admin-token"),
                        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
                    ],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new(
                format!("http://{address}"),
                "test-management-secret",
            )
            .unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let app = Router::new()
            .route("/api/v1/admin/accounts/{id}/{action}", get(account_action))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/accounts/1/usage?force=true")
                    .header(header::AUTHORIZATION, "Bearer test-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response
                .headers()
                .get("x-codex-router-error-code")
                .and_then(|value| value.to_str().ok()),
            Some("CR-USE-0003")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["success"], false);
        assert_eq!(body["error_code"], "CR-USE-0003");
        assert_eq!(body["data"]["stale"], true);
        assert_eq!(body["data"]["source"], "cache");
        assert_eq!(body["data"]["error_code"], "unauthenticated");
        assert_eq!(body["data"]["needs_reauth"], true);
        assert_eq!(
            body["data"]["antigravity_quota"]["gemini-live"]["utilization"],
            40.0
        );
        assert_eq!(
            requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );
        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn account_model_sync_reloads_auth_file_and_rejects_empty_registry() {
        let root = std::env::temp_dir().join(format!(
            "router-account-model-sync-{}",
            uuid::Uuid::now_v7()
        ));
        let auth_dir = root.join("auth");
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(
            auth_dir.join("gemini.json"),
            r#"{"type":"gemini-cli","refresh_token":"secret"}"#,
        )
        .unwrap();

        let calls = Arc::new(Mutex::new((0_usize, Some(2_usize))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = Router::new()
            .route(
                "/v0/management/auth-files/models",
                get(mock_models_after_reload),
            )
            .with_state(calls.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(1,'gemini','oauth','gemini','gemini.json','identity','active',1,1,1,'{}')",
                    [],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new(
                format!("http://{address}"),
                "test-management-secret",
            )
            .unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: Some(Arc::new(BackendPaths {
                config_path: root.join("config.yaml"),
                auth_dir: auth_dir.clone(),
                downstream_key: "downstream".to_owned(),
                management_secret: "test-management-secret".to_owned(),
                cli_port: address.port(),
                desktop_auth_path: root.join("desktop-auth.json"),
            })),
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };

        let original_auth_bytes = std::fs::read(auth_dir.join("gemini.json")).unwrap();
        let response = account_models_sync_upstream_for_state(&state, 1).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["data"]["items"][0]["id"], "gemini-3.1-pro-high");
        assert!(calls.lock().unwrap_or_else(|error| error.into_inner()).0 >= 2);
        assert_eq!(
            std::fs::read(auth_dir.join("gemini.json")).unwrap(),
            original_auth_bytes
        );

        *calls.lock().unwrap_or_else(|error| error.into_inner()) = (0, None);
        let empty_response = account_models_sync_upstream_for_state(&state, 1).await;
        assert_eq!(empty_response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            empty_response
                .headers()
                .get("x-codex-router-error-code")
                .and_then(|value| value.to_str().ok()),
            Some("CR-CLI-0007")
        );

        state
            .store
            .with_connection(|connection| {
                connection.execute(
                    "UPDATE accounts SET status='disabled',schedulable=0 WHERE id=1",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        *calls.lock().unwrap_or_else(|error| error.into_inner()) = (0, Some(0));
        let disabled_response = account_models_sync_upstream_for_state(&state, 1).await;
        assert_eq!(disabled_response.status(), StatusCode::CONFLICT);
        assert_eq!(
            calls.lock().unwrap_or_else(|error| error.into_inner()).0,
            0,
            "disabled OAuth model sync must not touch CLI"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stable_identity_is_provider_scoped_and_secret_free() {
        let first = stable_identity_hmac("openai", "identity");
        let second = stable_identity_hmac("anthropic", "identity");
        assert_ne!(first, second);
        assert!(!first.contains("identity"));
    }

    #[test]
    fn api_accounts_with_one_key_keep_distinct_channel_identities() {
        let first = json!({
            "name": "Codex-Router / model / relay-a",
            "credentials": {"api_key": "shared-secret"}
        });
        let second = json!({
            "name": "Codex-Router / model / relay-b",
            "credentials": {"api_key": "shared-secret"}
        });
        let first_identity =
            stable_identity_hmac("openai", account_identity_source("apikey", &first));
        let second_identity =
            stable_identity_hmac("openai", account_identity_source("apikey", &second));
        assert_ne!(first_identity, second_identity);
        assert!(!first_identity.contains("shared-secret"));
        assert!(!second_identity.contains("shared-secret"));
    }

    #[test]
    fn deleted_account_identity_can_be_readded_without_reusing_id() {
        let root =
            std::env::temp_dir().join(format!("router-account-readd-{}", uuid::Uuid::now_v7()));
        let store = StateStore::open(root.join("router-state.sqlite3")).unwrap();
        let identity = stable_identity_hmac("openai", "readd-key");
        store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(1,'openai','apikey','old','old.json',?1,'active',1,1,1,'{}')",
                    rusqlite::params![identity],
                )?;
                let tombstone = deleted_account_tombstone(1);
                connection.execute(
                    "UPDATE accounts SET deleted_at=CURRENT_TIMESTAMP,schedulable=0,stable_identity_hmac=?2 WHERE id=?1",
                    rusqlite::params![1_i64, tombstone],
                )?;
                connection.execute(
                    "INSERT INTO accounts(id,platform,account_type,auth_index,auth_file,stable_identity_hmac,status,schedulable,priority,weight,payload) VALUES(2,'openai','apikey','new','new.json',?1,'active',1,1,1,'{}')",
                    rusqlite::params![identity],
                )?;
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM accounts WHERE stable_identity_hmac=?1 AND deleted_at IS NULL",
                    rusqlite::params![identity],
                    |row| row.get(0),
                )?;
                assert_eq!(count, 1);
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn state_payload_is_sanitized_without_deleting_public_fields() {
        let mut value = json!({
            "name": "safe", "credentials": {"api_key":"sk", "note":"x"}
        });
        sanitize_state_payload(&mut value);
        assert_eq!(value["name"], "safe");
        assert!(value["credentials"].get("api_key").is_none());
        assert_eq!(value["credentials"]["note"], "x");
    }

    #[test]
    fn auth_file_builders_emit_provider_specific_shapes() {
        let credentials = json!({
            "access_token": "at", "refresh_token": "rt", "id_token": "it",
            "account_id": "acc-1", "email": "user@example.com", "expires_at": "2030-01-01T00:00:00Z",
        });
        let codex = build_auth_file("openai", &credentials, None).unwrap();
        assert_eq!(codex["type"], "codex");
        assert_eq!(codex["account_id"], "acc-1");
        let claude = build_auth_file("anthropic", &credentials, None).unwrap();
        assert_eq!(claude["type"], "claude");
        let xai = build_auth_file("grok", &credentials, Some("cr_r1_xai")).unwrap();
        assert_eq!(xai["type"], "xai");
        assert_eq!(xai["prefix"], "cr_r1_xai");
        assert!(build_auth_file("unknown-provider", &credentials, None).is_err());
    }

    #[test]
    fn auth_file_round_trip_and_prefix_patch_are_atomic() {
        let root = std::env::temp_dir().join(format!("router-auth-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let document = json!({"type": "codex", "access_token": "at"});
        let path = write_auth_file(&root, "cr-account-test", &document).unwrap();
        assert!(path.is_file());
        patch_auth_file_prefix(&path, "cr_r1_openai").unwrap();
        patch_auth_file_route(&path, "cr_r1_openai", "gpt-5.4", "public-gpt").unwrap();
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["prefix"], "cr_r1_openai");
        assert_eq!(written["access_token"], "at");
        assert_eq!(written["model_aliases"][0]["name"], "gpt-5.4");
        assert_eq!(written["model_aliases"][0]["alias"], "public-gpt");
        assert!(write_auth_file(&root, "../escape", &document).is_err());
    }

    #[test]
    fn gemini_oauth_options_round_trip_through_session_metadata() {
        let root =
            std::env::temp_dir().join(format!("router-oauth-session-{}", uuid::Uuid::now_v7()));
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new("http://127.0.0.1:1", "test-secret").unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let session_state = "gemini-session-state";
        state
            .store
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO oauth_sessions(state_hmac,provider,status,expires_at,metadata)
                     VALUES(?1,'gemini','pending',?2,?3)",
                    rusqlite::params![
                        sha256_hex(session_state.as_bytes()),
                        (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339(),
                        json!({
                            "started_at": chrono::Utc::now().to_rfc3339(),
                            "oauth_type": "code_assist",
                            "tier_id": "gcp_standard",
                            "project_id": "selected-project",
                        })
                        .to_string(),
                    ],
                )?;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();

        let effective = effective_oauth_exchange_body(
            &state,
            "gemini",
            session_state,
            &json!({"state": session_state}),
        )
        .unwrap();
        assert_eq!(effective["oauth_type"], "code_assist");
        assert_eq!(effective["tier_id"], "gcp_standard");
        assert_eq!(effective["project_id"], "selected-project");
        assert!(validate_gemini_oauth_options(&json!({
            "oauth_type": "code_assist",
            "tier_id": "google_one_free",
        }))
        .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn materialized_oauth_auth_file_creates_and_reuses_local_account() {
        let root = std::env::temp_dir().join(format!("router-oauth-map-{}", uuid::Uuid::now_v7()));
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        let logger = Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap());
        let cli = CliProxyManagementClient::new("http://127.0.0.1:1", "test-secret").unwrap();
        let state = ControlState {
            store,
            cli,
            logger,
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let materialized = json!({
            "auth_file": "google-account-gemini-cli.json",
            "auth_index": "cli-auth-1",
            "email": "user@example.com",
            "account_id": "google-account-1",
            "project_id": "project-1",
        });
        let body = json!({
            "group_ids": [],
            "priority": 4,
            "oauth_type": "code_assist",
            "tier_id": "gcp_standard",
            "project_id": "selected-project"
        });

        let first = materialize_oauth_account(&state, "gemini", &body, &materialized).unwrap();
        assert_eq!(first["id"], 1);
        assert_eq!(first["platform"], "gemini");
        assert_eq!(first["type"], "oauth");
        assert_eq!(first["auth_index"], "cli-auth-1");
        assert_eq!(first["credentials"]["email"], "user@example.com");
        assert_eq!(first["credentials"]["project_id"], "selected-project");
        assert_eq!(first["extra"]["oauth_type"], "code_assist");
        assert_eq!(first["extra"]["tier_id"], "gcp_standard");
        state
            .store
            .with_connection(|connection| {
                connection.execute(
                    "UPDATE accounts SET status='error',schedulable=0 WHERE id=1",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        crate::router_usage::note_reauth_failure(&state.store, 1).unwrap();

        let second_materialized = json!({
            "auth_file": "google-account-gemini-cli.json",
            "auth_index": "cli-auth-2",
            "email": "user@example.com",
            "account_id": "google-account-1",
            "project_id": "project-2",
        });
        let second =
            materialize_oauth_account(&state, "gemini", &body, &second_materialized).unwrap();
        assert_eq!(second["id"], 1);
        assert_eq!(second["reused"], true);
        assert_eq!(second["auth_index"], "cli-auth-2");
        assert_eq!(second["credentials"]["project_id"], "project-2");

        let stored = state
            .store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT auth_index,status,schedulable FROM accounts WHERE id=1",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(stored, ("cli-auth-2".to_owned(), "active".to_owned(), 1));
        assert!(!crate::router_usage::reauth_cooldown_active(&state.store, 1).unwrap());

        let count = state
            .store
            .with_connection(|connection| {
                Ok::<i64, anyhow::Error>(connection.query_row(
                    "SELECT COUNT(*) FROM accounts WHERE platform='gemini' AND deleted_at IS NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .unwrap();
        assert_eq!(count, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn oauth_file_candidate_uses_updated_physical_file_over_runtime_project_view() {
        let items = vec![
            json!({
                "provider": "gemini-cli",
                "name": "old-project.json",
                "path": "C:/auth/physical-gemini.json",
                "created_at": "2026-08-19T08:15:54+08:00",
                "modtime": "2026-08-19T10:19:55+08:00",
                "runtime_only": false,
            }),
            json!({
                "provider": "gemini-cli",
                "name": "virtual-project.json",
                "path": "C:/auth/physical-gemini.json",
                "created_at": "2026-08-19T08:15:54+08:00",
                "modtime": "2026-08-19T10:19:55+08:00",
                "runtime_only": true,
            }),
        ];
        let candidate = oauth_file_candidate(
            &items,
            "gemini-cli",
            "gemini",
            Some("2026-08-19T10:19:00+08:00"),
        )
        .unwrap();
        assert_eq!(
            oauth_file_name(&candidate).as_deref(),
            Some("physical-gemini.json")
        );
    }

    #[test]
    fn gemini_cli_replica_uses_full_internal_alias() {
        assert_eq!(
            oauth_replica_alias("gemini-cli", "cr_r6_gemini", "public-gemini"),
            "cr_r6_gemini/public-gemini"
        );
        assert_eq!(
            oauth_replica_alias("xai", "cr_r10a56_xai", "grok-4.6"),
            "cr_r10a56_xai/grok-4.6"
        );
        assert_eq!(
            oauth_replica_alias(
                "antigravity",
                "cr_r12991a54_antigravity",
                "gemini-3.8-flash"
            ),
            "cr_r12991a54_antigravity/gemini-3.8-flash"
        );
        assert_eq!(
            oauth_replica_aliases(
                "antigravity",
                "cr_r12991a54_antigravity",
                "gemini-3.8-flash"
            ),
            vec![
                "gemini-3.8-flash".to_owned(),
                "cr_r12991a54_antigravity/gemini-3.8-flash".to_owned()
            ]
        );
        assert_eq!(
            oauth_replica_aliases("codex", "cr_r1a61_openai", "gpt-5.6-sol"),
            vec![
                "gpt-5.6-sol".to_owned(),
                "cr_r1a61_openai/gpt-5.6-sol".to_owned()
            ]
        );
        assert_eq!(
            oauth_replica_alias("openai", "cr_r1_openai", "gpt-5.6-sol"),
            "cr_r1_openai/gpt-5.6-sol"
        );
    }

    #[test]
    fn antigravity_gemini_38_falls_back_to_live_flash() {
        let live = HashSet::from([
            "cr_r12991a54_antigravity/gemini-3.7-flash-high".to_owned(),
            "cr_r12991a54_antigravity/gemini-3.6-flash-high".to_owned(),
        ]);
        assert_eq!(
            resolve_live_oauth_upstream(
                "antigravity",
                "antigravity",
                "gemini-3.8-flash-high",
                &live
            ),
            "gemini-3.7-flash-high"
        );
        let live_38 = HashSet::from(["cr_r12991a54_antigravity/gemini-3.8-flash-high".to_owned()]);
        assert_eq!(
            resolve_live_oauth_upstream(
                "antigravity",
                "antigravity",
                "gemini-3.8-flash-high",
                &live_38
            ),
            "gemini-3.8-flash-high"
        );
        assert_eq!(
            resolve_live_oauth_upstream(
                "antigravity",
                "antigravity",
                "gemini-3.8-flash-high",
                &HashSet::new()
            ),
            "gemini-3.7-flash-high"
        );
    }

    #[test]
    fn oauth_routes_only_match_their_provider_pool() {
        assert!(oauth_route_provider_matches("gemini", "gemini"));
        assert!(oauth_route_provider_matches("grok", "xai"));
        assert!(!oauth_route_provider_matches("gemini", "grok"));
        assert!(!oauth_route_provider_matches("antigravity", "gemini"));
    }

    #[test]
    fn api_accounts_only_join_matching_model_routes() {
        let kimi = json!({"credentials":{"model_mapping":{"k3-256k":"k3-256k"}}});
        let empty = json!({"credentials":{}});
        assert!(api_route_model_matches(&kimi, "k3-256k", "k3-256k"));
        assert!(!api_route_model_matches(
            &kimi,
            "claude-fable-5",
            "claude-fable-5"
        ));
        assert!(!api_route_model_matches(&kimi, "grok-4.6", "grok-4.6"));
        assert!(!api_route_model_matches(&empty, "k3-256k", "k3-256k"));
    }

    #[test]
    fn oauth_accounts_only_join_mapped_model_routes() {
        let chatgpt = json!({"credentials":{"model_mapping":{
            "gpt-5.6-sol":"gpt-5.6-sol",
            "gpt-5.6-terra":"gpt-5.6-terra"
        }}});
        let empty = json!({"credentials":{}});
        assert!(oauth_route_model_matches(
            &chatgpt,
            "gpt-5.6-sol",
            "gpt-5.6-sol"
        ));
        assert!(!oauth_route_model_matches(
            &chatgpt,
            "kimi-for-coding",
            "kimi-for-coding"
        ));
        assert!(!oauth_route_model_matches(
            &chatgpt,
            "glm-latest",
            "glm-latest"
        ));
        assert!(oauth_route_model_matches(
            &empty,
            "kimi-for-coding",
            "kimi-for-coding"
        ));
    }

    #[test]
    fn oauth_replica_uses_mapped_upstream_model() {
        let payload = json!({
            "credentials": {
                "model_mapping": {
                    "gemini-3.7-flash": "gemini-3.7-flash-medium"
                }
            }
        });
        assert_eq!(
            mapped_upstream_model(
                &payload,
                "antigravity",
                "gemini-3.7-flash",
                "gemini-3.7-flash"
            ),
            "gemini-3.7-flash-high"
        );
        assert_eq!(
            mapped_upstream_model(
                &json!({"credentials":{"model_mapping":{"gemini-3.8-flash":"gemini-3.8-flash-medium"}}}),
                "antigravity",
                "gemini-3.8-flash",
                "gemini-3.8-flash"
            ),
            "gemini-3.7-flash-high"
        );
        assert_eq!(
            mapped_upstream_model(&payload, "antigravity", "claude-fable-5", "claude-fable-5"),
            "claude-sonnet-4-6"
        );
    }

    #[test]
    fn cli_provider_mapping_covers_all_five_oauth_providers() {
        assert_eq!(
            cli_oauth_endpoint("openai"),
            Some("/v0/management/codex-auth-url")
        );
        assert_eq!(
            cli_oauth_endpoint("gemini"),
            Some("/v0/management/gemini-cli-auth-url")
        );
        assert_eq!(
            cli_oauth_endpoint("grok"),
            Some("/v0/management/xai-auth-url")
        );
        assert_eq!(
            cli_oauth_endpoint("anthropic"),
            Some("/v0/management/anthropic-auth-url")
        );
        assert_eq!(
            cli_oauth_endpoint("antigravity"),
            Some("/v0/management/antigravity-auth-url")
        );
        assert_eq!(cli_oauth_endpoint("microsoft"), None);
        assert_eq!(
            cli_oauth_auth_url_path("openai").as_deref(),
            Some("/v0/management/codex-auth-url?is_webui=true")
        );
        assert_eq!(
            cli_oauth_auth_url_path("antigravity").as_deref(),
            Some("/v0/management/antigravity-auth-url")
        );
        assert!(auth_index_is_safe("antigravity-user@example.com"));
        assert!(!auth_index_is_safe("../secret"));
        assert_eq!(
            cli_oauth_auth_url_path("grok").as_deref(),
            Some("/v0/management/xai-auth-url")
        );
    }

    #[tokio::test]
    async fn grok_auth_url_is_host_owned_pkce_and_pins_loopback_callback() {
        let root = std::env::temp_dir().join(format!("router-grok-auth-{}", uuid::Uuid::now_v7()));
        let store = Arc::new(StateStore::open(root.join("router-state.sqlite3")).unwrap());
        let state = ControlState {
            store,
            cli: CliProxyManagementClient::new("http://127.0.0.1:1", "test-secret").unwrap(),
            logger: Arc::new(StructuredLogger::open(root.join("router-events.jsonl")).unwrap()),
            routes: Arc::new(RwLock::new(RouteTable::new(Vec::new()).unwrap())),
            backend: None,
            cli_index_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let response = grok_auth_url(&state).await;
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["success"], true);
        let data = &payload["data"];
        let url = data["auth_url"].as_str().unwrap();
        let session_id = data["session_id"].as_str().unwrap();
        assert!(url.contains("https://auth.x.ai/oauth2/authorize"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A56121%2Fcallback"));
        assert!(url.contains(&format!("state={session_id}")));
        assert!(!url.contains("localhost"));
        let metadata = oauth_session_metadata(&state, session_id)
            .unwrap()
            .expect("stored grok session");
        assert!(!metadata["code_verifier"]
            .as_str()
            .unwrap_or_default()
            .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
