use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod compose;
mod dns;
mod error;
mod names;
mod nginx_conf;
mod store;

use compose::ComposeManager;
use dns::CloudflareDns;
use error::ApiError;
use store::{Instance, InstanceStore};

const ADMIN_TOKEN_HEX_LEN: usize = 32;

#[derive(Clone)]
struct AppState {
    compose: Arc<ComposeManager>,
    store: Arc<RwLock<InstanceStore>>,
    config: AppConfig,
    dns: Option<Arc<CloudflareDns>>,
}

#[derive(Clone)]
struct AppConfig {
    admin_token: String,
    host_address: String,
    openclaw_domain: Option<String>,
    openclaw_image: String,
    compose_file: std::path::PathBuf,
    dstack_app_id: Option<String>,
    nginx_map_path: PathBuf,
    ingress_container_name: String,
}

/// Extractor that validates the admin token from the Authorization header
struct AdminAuth;

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization header format. Expected: Bearer <token>".into()))?
            .trim();

        let token_hex: String = token.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let expected_hex: String = state.config.admin_token.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if token_hex != expected_hex || token_hex.len() != 32 {
            return Err(ApiError::Unauthorized("Invalid admin token".into()));
        }

        Ok(AdminAuth)
    }
}

fn validate_admin_token(token: &str) -> anyhow::Result<()> {
    if token.len() != ADMIN_TOKEN_HEX_LEN {
        anyhow::bail!(
            "ADMIN_TOKEN must be exactly {} hex characters, got {} characters",
            ADMIN_TOKEN_HEX_LEN,
            token.len()
        );
    }
    if hex::decode(token).is_err() {
        anyhow::bail!("ADMIN_TOKEN must be a valid hex string");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let admin_token_raw = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set");
    let admin_token: String = admin_token_raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    validate_admin_token(&admin_token)?;

    let compose_file = std::env::var("COMPOSE_FILE")
        .unwrap_or_else(|_| "/app/docker-compose.worker.yml".to_string());

    let dstack_app_id = fetch_dstack_app_id().await;
    if let Some(ref app_id) = dstack_app_id {
        tracing::info!("dstack APP_ID: {}", app_id);
    }

    let config = AppConfig {
        admin_token,
        host_address: std::env::var("OPENCLAW_HOST_ADDRESS")
            .unwrap_or_else(|_| "localhost".to_string()),
        openclaw_domain: std::env::var("OPENCLAW_DOMAIN").ok(),
        openclaw_image: std::env::var("OPENCLAW_IMAGE")
            .unwrap_or_else(|_| "openclaw-nearai-worker:local".to_string()),
        compose_file: std::path::PathBuf::from(compose_file),
        dstack_app_id,
        nginx_map_path: PathBuf::from(
            std::env::var("NGINX_MAP_PATH").unwrap_or_else(|_| "/data/nginx/backends.map".to_string()),
        ),
        ingress_container_name: std::env::var("INGRESS_CONTAINER_NAME")
            .unwrap_or_else(|_| "dstack-ingress".to_string()),
    };

    let dns = match (
        std::env::var("CLOUDFLARE_API_TOKEN").ok(),
        std::env::var("CLOUDFLARE_ZONE_ID").ok(),
    ) {
        (Some(token), Some(zone_id)) => {
            tracing::info!("Cloudflare DNS client initialized");
            Some(Arc::new(CloudflareDns::new(&token, &zone_id)))
        }
        _ => {
            tracing::info!("Cloudflare DNS not configured (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID not set)");
            None
        }
    };

    let compose = Arc::new(ComposeManager::new(
        config.compose_file.clone(),
        std::path::PathBuf::from("data/envs"),
        config.openclaw_image.clone(),
    )?);

    let store = Arc::new(RwLock::new(InstanceStore::load_or_create("data/users.json")?));

    if let Some(ref domain) = config.openclaw_domain {
        tracing::info!("OPENCLAW_DOMAIN set: instance URLs will use https://{{name}}.{}", domain);
    }

    let state = AppState {
        compose,
        store,
        config,
        dns,
    };

    update_nginx_now(&state).await;

    // Ensure the "api" subdomain DNS record exists so the dstack gateway routes to us
    if let (Some(ref dns), Some(ref domain), Some(ref app_id)) =
        (&state.dns, &state.config.openclaw_domain, &state.config.dstack_app_id)
    {
        if let Err(e) = dns.ensure_txt_record("api", domain, app_id, 443).await {
            tracing::warn!("Failed to create DNS record for api.{}: {}", domain, e);
        }
    }

    if state.config.openclaw_domain.is_some() {
        let sync_state = state.clone();
        tokio::spawn(async move {
            background_sync_loop(sync_state).await;
        });
    }

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/version", get(version))
        .route("/instances", get(list_instances))
        .route("/instances", post(create_instance))
        .route("/instances/{name}", get(get_instance))
        .route("/instances/{name}", delete(delete_instance))
        .route("/instances/{name}/restart", post(restart_instance))
        .route("/instances/{name}/stop", post(stop_instance))
        .route("/instances/{name}/start", post(start_instance))
        .route("/instances/{name}/events", get(instance_events))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Management API listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn version() -> &'static str {
    "instance_v1"
}

// ── Request / Response types ─────────────────────────────────────────

#[derive(Deserialize)]
struct CreateInstanceRequest {
    nearai_api_key: String,
    #[serde(default)]
    ssh_pubkey: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Serialize)]
struct InstanceInfo {
    name: String,
    token: String,
    gateway_port: u16,
    ssh_port: u16,
    url: String,
    dashboard_url: String,
    ssh_command: String,
}

#[derive(Serialize)]
struct InstanceResponse {
    name: String,
    token: String,
    url: String,
    dashboard_url: String,
    gateway_port: u16,
    ssh_port: u16,
    ssh_command: String,
    status: String,
    created_at: String,
}

#[derive(Serialize)]
struct InstancesListResponse {
    instances: Vec<InstanceResponse>,
}

/// Generate URL and dashboard_url based on config
fn generate_urls(config: &AppConfig, name: &str, gateway_port: u16, token: &str) -> (String, String) {
    match &config.openclaw_domain {
        Some(domain) => {
            let base = format!("https://{}.{}", name, domain);
            (base.clone(), format!("{}/?token={}", base, token))
        }
        None => {
            let base = format!("http://{}:{}", config.host_address, gateway_port);
            (base.clone(), format!("{}/?token={}", base, token))
        }
    }
}

// ── SSE helpers ──────────────────────────────────────────────────────

/// Wrap an SSE stream with headers that disable proxy buffering (nginx, etc.)
fn unbuffered_sse(
    stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> impl IntoResponse {
    let headers = [
        ("X-Accel-Buffering", "no"),
        ("Cache-Control", "no-cache"),
    ];
    let sse = Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    );
    (headers, sse)
}

fn sse_stage(stage: &str, message: &str) -> Event {
    Event::default()
        .json_data(serde_json::json!({"stage": stage, "message": message}))
        .unwrap()
}

fn sse_error(message: &str) -> Event {
    Event::default()
        .json_data(serde_json::json!({"stage": "error", "message": message}))
        .unwrap()
}

fn sse_created(info: &InstanceInfo) -> Event {
    Event::default()
        .json_data(serde_json::json!({
            "stage": "created",
            "message": format!("Instance '{}' created, ports {}-{} allocated", info.name, info.gateway_port, info.ssh_port),
            "instance": info,
        }))
        .unwrap()
}

// ── Health polling loop (shared by create/start/restart SSE streams) ─

async fn poll_health_to_ready(
    state: &AppState,
    name: &str,
    tx: &tokio::sync::mpsc::Sender<Event>,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut last_stage = String::new();

    loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = tx.send(sse_error("timeout waiting for container to become ready")).await;
            return;
        }

        let health = state.compose.container_health(name);
        let (stage, msg, done) = match health {
            Ok(h) => match (h.state.as_str(), h.health.as_str()) {
                ("not_found", _) => ("container_starting", "Waiting for container to appear...", false),
                ("running", "starting") => ("healthcheck_starting", "Container running, waiting for health check...", false),
                ("running", "healthy") => ("healthy", "Health check passed", false),
                ("running", "none") | ("running", "") => ("container_running", "Container is running, health check not yet configured", false),
                ("exited", _) | ("dead", _) => ("error", "Container exited unexpectedly", true),
                (_, "unhealthy") => ("error", "Container health check failed", true),
                _ => ("container_starting", "Waiting for container...", false),
            },
            Err(e) => {
                let leaked: &str = e.to_string().leak();
                ("error", leaked, true)
            }
        };

        if stage != last_stage {
            last_stage = stage.to_string();
            if done {
                let _ = tx.send(sse_error(msg)).await;
                return;
            }

            let _ = tx.send(sse_stage(stage, msg)).await;

            if stage == "healthy" {
                let _ = tx.send(sse_stage("ready", &format!("Instance '{}' is ready", name))).await;
                return;
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

// ── Handlers ─────────────────────────────────────────────────────────

async fn create_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateInstanceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.nearai_api_key.is_empty() {
        return Err(ApiError::BadRequest("nearai_api_key is required".into()));
    }

    // Resolve instance name
    let name = if let Some(provided) = &req.name {
        let sanitized = provided.to_lowercase().replace(|c: char| !c.is_alphanumeric() && c != '-', "");
        if sanitized.is_empty() || sanitized.len() > 32 {
            return Err(ApiError::BadRequest("Invalid name: must be 1-32 alphanumeric/hyphen characters".into()));
        }
        const RESERVED: &[&str] = &["api", "www", "mail", "admin", "gateway"];
        if RESERVED.contains(&sanitized.as_str()) {
            return Err(ApiError::BadRequest(format!("'{}' is a reserved name", sanitized)));
        }
        let store = state.store.read().await;
        if store.exists(&sanitized) {
            return Err(ApiError::Conflict(format!("Instance '{}' already exists", sanitized)));
        }
        sanitized
    } else {
        let store = state.store.read().await;
        names::generate_name(|n| store.exists(n))
            .ok_or_else(|| ApiError::Internal("Failed to generate unique name".into()))?
    };

    let token = generate_token();
    let (gateway_port, ssh_port) = {
        let store = state.store.read().await;
        store.next_available_ports()
    };

    let (url, dashboard_url) = generate_urls(&state.config, &name, gateway_port, &token);
    let ssh_command = format!("ssh -p {} agent@{}", ssh_port, state.config.host_address);

    let info = InstanceInfo {
        name: name.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        url,
        dashboard_url,
        ssh_command,
    };

    let instance = Instance {
        name: name.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        created_at: chrono::Utc::now(),
        ssh_pubkey: req.ssh_pubkey.clone(),
        nearai_api_key: req.nearai_api_key.clone(),
        active: true,
    };

    // Save to store before streaming so it's persisted immediately
    {
        let mut store = state.store.write().await;
        store.add(instance)?;
    }

    let nearai_api_key = req.nearai_api_key.clone();
    let ssh_pubkey = req.ssh_pubkey.clone();

    let stream = async_stream::stream! {
        yield Ok(sse_created(&info));

        yield Ok(sse_stage("container_starting", "Pulling image and starting container..."));

        if let Err(e) = state.compose.up(
            &name,
            &nearai_api_key,
            &token,
            gateway_port,
            ssh_port,
            ssh_pubkey.as_deref(),
        ) {
            yield Ok(sse_error(&format!("Failed to start container: {}", e)));
            return;
        }

        yield Ok(sse_stage("configuring_routing", "Updating nginx routing table..."));
        update_nginx_now(&state).await;

        yield Ok(sse_stage("updating_dns", "Creating DNS record for subdomain..."));
        if let (Some(ref dns), Some(ref domain), Some(ref app_id)) =
            (&state.dns, &state.config.openclaw_domain, &state.config.dstack_app_id)
        {
            if let Err(e) = dns.ensure_txt_record(&name, domain, app_id, 443).await {
                tracing::warn!("Failed to create DNS record for {}: {}", name, e);
            }
        }

        tracing::info!("Created instance: {} (gateway:{}, ssh:{})", name, gateway_port, ssh_port);

        // Poll health until ready
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, &tx).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }
    };

    Ok(unbuffered_sse(stream))
}

async fn get_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let instance = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };

    match instance {
        Some(inst) => {
            let status = state.compose.status(&inst.name)?;
            let (url, dashboard_url) = generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
            let ssh_command = format!("ssh -p {} agent@{}", inst.ssh_port, state.config.host_address);
            Ok(Json(InstanceResponse {
                name: inst.name,
                token: inst.token,
                url,
                dashboard_url,
                gateway_port: inst.gateway_port,
                ssh_port: inst.ssh_port,
                ssh_command,
                status,
                created_at: inst.created_at.to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound(format!("Instance '{}' not found", name))),
    }
}

async fn list_instances(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let instances = {
        let store = state.store.read().await;
        store.list()
    };

    let mut responses = Vec::new();
    for inst in instances {
        let status = state.compose.status(&inst.name)
            .unwrap_or_else(|_| "unknown".to_string());
        let (url, dashboard_url) = generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
        let ssh_command = format!("ssh -p {} agent@{}", inst.ssh_port, state.config.host_address);
        responses.push(InstanceResponse {
            name: inst.name,
            token: inst.token,
            url,
            dashboard_url,
            gateway_port: inst.gateway_port,
            ssh_port: inst.ssh_port,
            ssh_command,
            status,
            created_at: inst.created_at.to_rfc3339(),
        });
    }

    Ok(Json(InstancesListResponse { instances: responses }))
}

async fn delete_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    state.compose.down(&name)?;

    if let (Some(ref dns), Some(ref domain)) =
        (&state.dns, &state.config.openclaw_domain)
    {
        if let Err(e) = dns.delete_txt_record(&name, domain).await {
            tracing::warn!("Failed to delete DNS record for {}: {}", name, e);
        }
    }

    {
        let mut store = state.store.write().await;
        store.remove(&name)?;
    }

    update_nginx_now(&state).await;

    tracing::info!("Deleted instance: {}", name);
    Ok(StatusCode::NO_CONTENT)
}

async fn restart_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let stream = async_stream::stream! {
        yield Ok(sse_stage("container_starting", "Restarting container..."));

        if let Err(e) = state.compose.restart(&name) {
            yield Ok(sse_error(&format!("Failed to restart container: {}", e)));
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, &tx).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }
    };

    Ok(unbuffered_sse(stream))
}

async fn stop_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let stream = async_stream::stream! {
        yield Ok(sse_stage("stopping", "Stopping container..."));

        if let Err(e) = state.compose.stop(&name) {
            yield Ok(sse_error(&format!("Failed to stop container: {}", e)));
            return;
        }

        {
            let mut store = state.store.write().await;
            if let Err(e) = store.set_active(&name, false) {
                tracing::warn!("Failed to mark instance inactive: {}", e);
            }
        }

        update_nginx_now(&state).await;
        tracing::info!("Stopped instance: {}", name);

        yield Ok(sse_stage("stopped", "Instance stopped, routing removed"));
    };

    Ok(unbuffered_sse(stream))
}

async fn start_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let stream = async_stream::stream! {
        yield Ok(sse_stage("container_starting", "Starting container..."));

        if let Err(e) = state.compose.start(&name) {
            yield Ok(sse_error(&format!("Failed to start container: {}", e)));
            return;
        }

        yield Ok(sse_stage("configuring_routing", "Restoring routing..."));

        {
            let mut store = state.store.write().await;
            if let Err(e) = store.set_active(&name, true) {
                tracing::warn!("Failed to mark instance active: {}", e);
            }
        }

        update_nginx_now(&state).await;
        tracing::info!("Started instance: {}", name);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, &tx).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }
    };

    Ok(unbuffered_sse(stream))
}

async fn instance_events(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let stream = async_stream::stream! {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, &tx).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }
    };

    Ok(unbuffered_sse(stream))
}

// ── Utilities ────────────────────────────────────────────────────────

async fn update_nginx_now(state: &AppState) {
    if let Some(ref domain) = state.config.openclaw_domain {
        let instances = {
            let store = state.store.read().await;
            store.list()
        };
        let changed = nginx_conf::write_backends_map(&instances, domain, &state.config.nginx_map_path);
        if changed {
            nginx_conf::reload_nginx(&state.config.ingress_container_name);
        }
    }
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

async fn fetch_dstack_app_id() -> Option<String> {
    let sock_path = "/var/run/dstack.sock";
    if !std::path::Path::new(sock_path).exists() {
        tracing::info!("dstack.sock not found, skipping APP_ID fetch");
        return None;
    }

    let output = std::process::Command::new("curl")
        .args(["--unix-socket", sock_path, "-s", "http://localhost/Info"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(app_id) = v.get("app_id").and_then(|v| v.as_str()) {
                    return Some(app_id.to_string());
                }
            }
            tracing::warn!("dstack /Info response missing app_id: {}", body);
            None
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            tracing::warn!("Failed to fetch dstack APP_ID: {}", stderr);
            None
        }
        Err(e) => {
            tracing::warn!("Failed to run curl for dstack APP_ID: {}", e);
            None
        }
    }
}

async fn background_sync_loop(state: AppState) {
    let domain = match &state.config.openclaw_domain {
        Some(d) => d.clone(),
        None => return,
    };

    let mut dns_tick: u32 = 0;
    const DNS_SYNC_INTERVAL: u32 = 12;

    tracing::info!("Background sync loop started (domain: {})", domain);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let instances = {
            let store = state.store.read().await;
            store.list()
        };

        let changed = nginx_conf::write_backends_map(
            &instances,
            &domain,
            &state.config.nginx_map_path,
        );
        if changed {
            nginx_conf::reload_nginx(&state.config.ingress_container_name);
        }

        dns_tick += 1;
        if dns_tick >= DNS_SYNC_INTERVAL {
            dns_tick = 0;
            if let (Some(ref dns), Some(ref app_id)) = (&state.dns, &state.config.dstack_app_id) {
                let names: Vec<String> = instances.iter().map(|i| i.name.clone()).collect();
                if let Err(e) = dns.sync_all_records(&names, &domain, app_id, 443).await {
                    tracing::warn!("DNS sync failed: {}", e);
                }
            }
        }
    }
}
