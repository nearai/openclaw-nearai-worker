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
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

mod backup;
mod compose;
mod dns;
mod error;
mod names;
mod nginx_conf;
mod store;

use backup::BackupManager;
use compose::ComposeManager;
use dns::CloudflareDns;
use error::ApiError;
use store::{Instance, InstanceStore};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OpenClaw Instance Management API",
        description = "Multi-tenant management API for OpenClaw NEAR AI worker instances.\n\nInstance management endpoints require a Bearer token via the `Authorization` header. Attestation endpoints are public.\n\nLifecycle operations (create, start, stop, restart) return Server-Sent Event (SSE) streams with real-time progress updates.",
        version = "1.0.0",
    ),
    paths(
        health_check,
        version,
        list_instances,
        create_instance,
        get_instance,
        delete_instance,
        restart_instance,
        stop_instance,
        start_instance,
        instance_attestation,
        tdx_attestation,
        create_backup_endpoint,
        list_backups_endpoint,
        download_backup_endpoint,
    ),
    components(schemas(
        VersionResponse,
        CreateInstanceRequest,
        RestartInstanceRequest,
        InstanceInfo,
        InstanceResponse,
        InstancesListResponse,
        AttestationResponse,
        TdxAttestationReport,
        BackupInfoResponse,
        BackupListResponse,
        BackupDownloadResponse,
        SseEvent,
        ErrorResponse,
    )),
    security(("bearer_auth" = [])),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
        }
    }
}

const ADMIN_TOKEN_HEX_LEN: usize = 32;

#[derive(Clone)]
struct AppState {
    compose: Arc<ComposeManager>,
    store: Arc<RwLock<InstanceStore>>,
    config: AppConfig,
    dns: Option<Arc<CloudflareDns>>,
    backup: Option<Arc<BackupManager>>,
}

#[derive(Clone)]
struct AppConfig {
    admin_token: String,
    host_address: String,
    openclaw_domain: Option<String>,
    openclaw_image: String,
    nearai_api_url: String,
    compose_file: std::path::PathBuf,
    dstack_app_id: Option<String>,
    dstack_gateway_base: Option<String>,
    nginx_map_path: PathBuf,
    ingress_container_name: String,
}

/// Extractor that validates the admin token from the Authorization header
struct AdminAuth;

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or_else(|| {
                ApiError::Unauthorized(
                    "Invalid Authorization header format. Expected: Bearer <token>".into(),
                )
            })?
            .trim();

        let token_hex: String = token.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let expected_hex: String = state
            .config
            .admin_token
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
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
    let admin_token: String = admin_token_raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    validate_admin_token(&admin_token)?;

    let compose_file = std::env::var("COMPOSE_FILE")
        .unwrap_or_else(|_| "/app/docker-compose.worker.yml".to_string());

    let dstack_app_id = fetch_dstack_app_id().await;
    if let Some(ref app_id) = dstack_app_id {
        tracing::info!("dstack APP_ID: {}", app_id);
    }

    let dstack_gateway_base = std::env::var("GATEWAY_DOMAIN")
        .ok()
        .and_then(|d| d.split_once('.').map(|(_, base)| base.to_string()));
    if let Some(ref base) = dstack_gateway_base {
        tracing::info!("dstack gateway base: {}", base);
    }

    let config = AppConfig {
        admin_token,
        host_address: std::env::var("OPENCLAW_HOST_ADDRESS")
            .unwrap_or_else(|_| "localhost".to_string()),
        openclaw_domain: std::env::var("OPENCLAW_DOMAIN").ok(),
        openclaw_image: std::env::var("OPENCLAW_IMAGE")
            .unwrap_or_else(|_| "openclaw-nearai-worker:local".to_string()),
        nearai_api_url: std::env::var("NEARAI_API_URL")
            .unwrap_or_else(|_| "https://cloud-api.near.ai/v1".to_string()),
        compose_file: std::path::PathBuf::from(compose_file),
        dstack_app_id,
        dstack_gateway_base,
        nginx_map_path: PathBuf::from(
            std::env::var("NGINX_MAP_PATH")
                .unwrap_or_else(|_| "/data/nginx/backends.map".to_string()),
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
            tracing::info!(
                "Cloudflare DNS not configured (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID not set)"
            );
            None
        }
    };

    let compose = Arc::new(ComposeManager::new(
        config.compose_file.clone(),
        std::path::PathBuf::from("data/envs"),
    )?);

    let mut instance_store = InstanceStore::new();
    match compose.discover_instances() {
        Ok(discovered) => {
            if !discovered.is_empty() {
                tracing::info!("discovered {} instances from Docker", discovered.len());
                for inst in &discovered {
                    if let Err(e) = compose.ensure_env_file(inst) {
                        tracing::warn!("failed to write env file for {}: {}", inst.name, e);
                    }
                }
                instance_store.populate(discovered);
            }
        }
        Err(e) => {
            tracing::warn!("failed to discover instances from Docker: {}", e);
        }
    }
    let store = Arc::new(RwLock::new(instance_store));

    let backup = match BackupManager::from_env().await {
        Some(bm) => Some(Arc::new(bm)),
        None => {
            tracing::info!("Backup not configured (BACKUP_S3_BUCKET not set)");
            None
        }
    };

    if let Some(ref domain) = config.openclaw_domain {
        tracing::info!(
            "OPENCLAW_DOMAIN set: instance URLs will use https://{{name}}.{}",
            domain
        );
    }

    let state = AppState {
        compose,
        store,
        config,
        dns,
        backup,
    };

    update_nginx_now(&state).await;

    // Ensure the "api" subdomain DNS record exists so the dstack gateway routes to us
    if let (Some(ref dns), Some(ref domain), Some(ref app_id)) = (
        &state.dns,
        &state.config.openclaw_domain,
        &state.config.dstack_app_id,
    ) {
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

    let mut app = Router::new()
        .route("/health", get(health_check))
        .route("/version", get(version))
        .route("/instances", get(list_instances))
        .route("/instances", post(create_instance))
        .route("/instances/{name}", get(get_instance))
        .route("/instances/{name}", delete(delete_instance))
        .route("/instances/{name}/restart", post(restart_instance))
        .route("/instances/{name}/stop", post(stop_instance))
        .route("/instances/{name}/start", post(start_instance))
        .route("/instances/{name}/attestation", get(instance_attestation))
        .route("/attestation/report", get(tdx_attestation));

    if state.backup.is_some() {
        app = app
            .route("/instances/{name}/backup", post(create_backup_endpoint))
            .route("/instances/{name}/backups", get(list_backups_endpoint))
            .route(
                "/instances/{name}/backups/{id}",
                get(download_backup_endpoint),
            );
    }

    let app = app
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .merge(Scalar::with_url("/docs", ApiDoc::openapi()));

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Management API listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

#[utoipa::path(get, path = "/health", tag = "System",
    security(),
    responses((status = 200, description = "Service is healthy", body = String))
)]
async fn health_check() -> &'static str {
    "OK"
}

#[derive(Serialize, utoipa::ToSchema)]
struct VersionResponse {
    version: &'static str,
    git_commit: &'static str,
    build_time: &'static str,
}

#[utoipa::path(get, path = "/version", tag = "System",
    security(),
    responses((status = 200, description = "API version info", body = VersionResponse))
)]
async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("GIT_COMMIT"),
        build_time: env!("BUILD_TIME"),
    })
}

// ── Request / Response types ─────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
struct CreateInstanceRequest {
    /// NEAR AI API key for the instance
    nearai_api_key: String,
    /// SSH public key for direct SSH access
    ssh_pubkey: String,
    /// Optional instance name (auto-generated if omitted, 1-32 alphanumeric/hyphen chars)
    #[serde(default)]
    name: Option<String>,
    /// Optional Docker image reference (defaults to server-configured image)
    #[serde(default)]
    image: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
struct RestartInstanceRequest {
    /// Optional Docker image to switch to on restart (triggers full recreate)
    #[serde(default)]
    image: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct InstanceInfo {
    name: String,
    token: String,
    gateway_port: u16,
    ssh_port: u16,
    url: String,
    dashboard_url: String,
    ssh_command: String,
    image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_digest: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct InstanceResponse {
    name: String,
    token: String,
    url: String,
    dashboard_url: String,
    gateway_port: u16,
    ssh_port: u16,
    ssh_command: String,
    image: String,
    image_digest: Option<String>,
    status: String,
    created_at: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct InstancesListResponse {
    instances: Vec<InstanceResponse>,
}

/// SSE event payload for lifecycle streaming responses
#[derive(Serialize, utoipa::ToSchema)]
struct SseEvent {
    /// Current stage (e.g. "created", "container_starting", "healthy", "ready", "error")
    stage: String,
    /// Human-readable description of the current stage
    message: String,
    /// Instance info (only present in "created" stage)
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<InstanceInfo>,
}

/// Public attestation info for an instance (no auth required)
#[derive(Serialize, utoipa::ToSchema)]
struct AttestationResponse {
    /// Instance name
    name: String,
    /// Docker image digest reference (e.g. docker.io/org/image@sha256:abc...)
    image_digest: Option<String>,
}

/// TDX attestation report with TLS certificate binding
#[derive(Serialize, utoipa::ToSchema)]
struct TdxAttestationReport {
    /// Base64-encoded TDX DCAP quote (~4KB)
    quote: String,
    /// TCG event log (JSON string)
    event_log: String,
    /// Hex-encoded 64-byte report_data embedded in the quote
    report_data: String,
    /// VM configuration (OS image hash, etc.)
    vm_config: String,
    /// PEM-encoded TLS leaf certificate
    tls_certificate: String,
    /// Hex SHA-256 fingerprint of the DER-encoded leaf certificate
    tls_certificate_fingerprint: String,
}

/// Error response body
#[derive(Serialize, utoipa::ToSchema)]
struct ErrorResponse {
    /// Error message
    error: String,
}

/// Single backup info
#[derive(Serialize, utoipa::ToSchema)]
struct BackupInfoResponse {
    id: String,
    timestamp: String,
    size_bytes: i64,
}

/// List of backups
#[derive(Serialize, utoipa::ToSchema)]
struct BackupListResponse {
    backups: Vec<BackupInfoResponse>,
}

/// Presigned download URL for a backup
#[derive(Serialize, utoipa::ToSchema)]
struct BackupDownloadResponse {
    url: String,
    expires_in_seconds: u64,
}

fn validate_image(image: &str) -> Result<(), ApiError> {
    let trimmed = image.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("image must not be empty".into()));
    }
    if trimmed.len() > 256 {
        return Err(ApiError::BadRequest(
            "image must not exceed 256 characters".into(),
        ));
    }
    if !trimmed.contains("@sha256:") {
        return Err(ApiError::BadRequest(
            "image must be a digest reference (e.g. docker.io/org/image@sha256:abc...), tags are not accepted".into(),
        ));
    }
    Ok(())
}

/// Generate URL and dashboard_url based on config
fn generate_urls(
    config: &AppConfig,
    name: &str,
    gateway_port: u16,
    token: &str,
) -> (String, String) {
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

/// Generate SSH command — uses TLS-tunneled proxy through dstack gateway when available,
/// otherwise falls back to direct SSH.
fn generate_ssh_command(config: &AppConfig, ssh_port: u16) -> String {
    match (&config.dstack_app_id, &config.dstack_gateway_base) {
        (Some(app_id), Some(base)) => format!(
            "ssh -o ProxyCommand=\"openssl s_client -quiet -connect %h:443 -servername %h\" agent@{}-{}.{}",
            app_id, ssh_port, base
        ),
        _ => format!("ssh -p {} agent@{}", ssh_port, config.host_address),
    }
}

// ── SSE helpers ──────────────────────────────────────────────────────

/// Wrap an SSE stream with headers that disable proxy buffering (nginx, etc.)
fn unbuffered_sse(
    stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> impl IntoResponse {
    let headers = [("X-Accel-Buffering", "no"), ("Cache-Control", "no-cache")];
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

async fn poll_health_to_ready(state: &AppState, name: &str, tx: &tokio::sync::mpsc::Sender<Event>) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut last_stage = String::new();

    loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = tx
                .send(sse_error("timeout waiting for container to become ready"))
                .await;
            return;
        }

        let health = state.compose.container_health(name);
        let (stage, msg, done) = match health {
            Ok(h) => match (h.state.as_str(), h.health.as_str()) {
                ("not_found", _) => (
                    "container_starting",
                    "Waiting for container to appear...",
                    false,
                ),
                ("running", "starting") => (
                    "healthcheck_starting",
                    "Container running, waiting for health check...",
                    false,
                ),
                ("running", "healthy") => ("healthy", "Health check passed", false),
                ("running", "none") | ("running", "") => (
                    "container_running",
                    "Container is running, health check not yet configured",
                    false,
                ),
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
                let _ = tx
                    .send(sse_stage("ready", &format!("Instance '{}' is ready", name)))
                    .await;
                return;
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

// ── Handlers ─────────────────────────────────────────────────────────

#[utoipa::path(post, path = "/instances", tag = "Instances",
    request_body = CreateInstanceRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SSE stream of lifecycle events", content_type = "text/event-stream", body = SseEvent),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 409, description = "Instance name already exists", body = ErrorResponse),
    )
)]
async fn create_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateInstanceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.nearai_api_key.is_empty() {
        return Err(ApiError::BadRequest("nearai_api_key is required".into()));
    }
    if req.ssh_pubkey.is_empty() {
        return Err(ApiError::BadRequest("ssh_pubkey is required".into()));
    }

    // Resolve image
    let image = match &req.image {
        Some(img) => {
            validate_image(img)?;
            img.trim().to_string()
        }
        None => state.config.openclaw_image.clone(),
    };

    // Resolve instance name
    let name = if let Some(provided) = &req.name {
        let sanitized = provided
            .to_lowercase()
            .replace(|c: char| !c.is_alphanumeric() && c != '-', "");
        if sanitized.is_empty() || sanitized.len() > 32 {
            return Err(ApiError::BadRequest(
                "Invalid name: must be 1-32 alphanumeric/hyphen characters".into(),
            ));
        }
        const RESERVED: &[&str] = &["api", "www", "mail", "admin", "gateway"];
        if RESERVED.contains(&sanitized.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "'{}' is a reserved name",
                sanitized
            )));
        }
        let store = state.store.read().await;
        if store.exists(&sanitized) {
            return Err(ApiError::Conflict(format!(
                "Instance '{}' already exists",
                sanitized
            )));
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
    let ssh_command = generate_ssh_command(&state.config, ssh_port);

    let info = InstanceInfo {
        name: name.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        url,
        dashboard_url,
        ssh_command,
        image: image.clone(),
        image_digest: None,
    };

    let instance = Instance {
        name: name.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        created_at: chrono::Utc::now(),
        ssh_pubkey: req.ssh_pubkey.clone(),
        nearai_api_key: req.nearai_api_key.clone(),
        nearai_api_url: Some(state.config.nearai_api_url.clone()),
        active: true,
        image: Some(image.clone()),
        image_digest: None,
    };

    // Save to store before streaming so it's persisted immediately
    {
        let mut store = state.store.write().await;
        store.add(instance);
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
            &ssh_pubkey,
            &image,
            &state.config.nearai_api_url,
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

        // Resolve the image digest now that the container is running
        let image_digest = state.compose.resolve_image_digest(&name);
        if let Some(ref digest) = image_digest {
            yield Ok(sse_stage("image_resolved", &format!("Image digest: {}", digest)));
        }
        {
            let mut store = state.store.write().await;
            let _ = store.set_image(&name, Some(image.clone()), image_digest);
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

#[utoipa::path(get, path = "/instances/{name}", tag = "Instances",
    params(("name" = String, Path, description = "Instance name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Instance details", body = InstanceResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
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
            let (url, dashboard_url) =
                generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
            let ssh_command = generate_ssh_command(&state.config, inst.ssh_port);
            let image = inst
                .image
                .clone()
                .unwrap_or_else(|| state.config.openclaw_image.clone());
            Ok(Json(InstanceResponse {
                name: inst.name,
                token: inst.token,
                url,
                dashboard_url,
                gateway_port: inst.gateway_port,
                ssh_port: inst.ssh_port,
                ssh_command,
                image,
                image_digest: inst.image_digest.clone(),
                status,
                created_at: inst.created_at.to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound(format!("Instance '{}' not found", name))),
    }
}

#[utoipa::path(get, path = "/instances", tag = "Instances",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of all instances", body = InstancesListResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    )
)]
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
        let status = state
            .compose
            .status(&inst.name)
            .unwrap_or_else(|_| "unknown".to_string());
        let (url, dashboard_url) =
            generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
        let ssh_command = generate_ssh_command(&state.config, inst.ssh_port);
        let image = inst
            .image
            .clone()
            .unwrap_or_else(|| state.config.openclaw_image.clone());
        responses.push(InstanceResponse {
            name: inst.name,
            token: inst.token,
            url,
            dashboard_url,
            gateway_port: inst.gateway_port,
            ssh_port: inst.ssh_port,
            ssh_command,
            image,
            image_digest: inst.image_digest.clone(),
            status,
            created_at: inst.created_at.to_rfc3339(),
        });
    }

    Ok(Json(InstancesListResponse {
        instances: responses,
    }))
}

#[utoipa::path(delete, path = "/instances/{name}", tag = "Instances",
    params(("name" = String, Path, description = "Instance name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Instance deleted"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
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

    if let (Some(ref dns), Some(ref domain)) = (&state.dns, &state.config.openclaw_domain) {
        if let Err(e) = dns.delete_txt_record(&name, domain).await {
            tracing::warn!("Failed to delete DNS record for {}: {}", name, e);
        }
    }

    {
        let mut store = state.store.write().await;
        store.remove(&name);
    }

    update_nginx_now(&state).await;

    tracing::info!("Deleted instance: {}", name);
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/instances/{name}/restart", tag = "Instances",
    params(("name" = String, Path, description = "Instance name")),
    request_body(content = inline(Option<RestartInstanceRequest>), description = "Optional: provide image to switch to a different image on restart"),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SSE stream of restart progress", content_type = "text/event-stream", body = SseEvent),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
async fn restart_instance(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Option<Json<RestartInstanceRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let new_image = match &body {
        Some(Json(req)) => match &req.image {
            Some(img) => {
                validate_image(img)?;
                Some(img.trim().to_string())
            }
            None => None,
        },
        None => None,
    };

    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    let stream = async_stream::stream! {
        if let Some(ref image) = new_image {
            // Full recreate with new image
            yield Ok(sse_stage("container_starting", &format!("Recreating container with image {}...", image)));

            if let Err(e) = state.compose.up(
                &name,
                &inst.nearai_api_key,
                &inst.token,
                inst.gateway_port,
                inst.ssh_port,
                &inst.ssh_pubkey,
                image,
                inst.nearai_api_url
                    .as_deref()
                    .unwrap_or(&state.config.nearai_api_url),
            ) {
                yield Ok(sse_error(&format!("Failed to recreate container: {}", e)));
                return;
            }

            // Resolve new digest
            let image_digest = state.compose.resolve_image_digest(&name);
            if let Some(ref digest) = image_digest {
                yield Ok(sse_stage("image_resolved", &format!("Image digest: {}", digest)));
            }
            {
                let mut store = state.store.write().await;
                let _ = store.set_image(&name, Some(image.clone()), image_digest);
            }
        } else {
            // Simple restart
            yield Ok(sse_stage("container_starting", "Restarting container..."));

            if let Err(e) = state.compose.restart(&name) {
                yield Ok(sse_error(&format!("Failed to restart container: {}", e)));
                return;
            }
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

#[utoipa::path(post, path = "/instances/{name}/stop", tag = "Instances",
    params(("name" = String, Path, description = "Instance name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SSE stream of stop progress", content_type = "text/event-stream", body = SseEvent),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
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

#[utoipa::path(post, path = "/instances/{name}/start", tag = "Instances",
    params(("name" = String, Path, description = "Instance name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SSE stream of start progress", content_type = "text/event-stream", body = SseEvent),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
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

#[utoipa::path(get, path = "/instances/{name}/attestation", tag = "Attestation",
    params(("name" = String, Path, description = "Instance name")),
    security(),
    responses(
        (status = 200, description = "Public attestation info for the instance", body = AttestationResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
    )
)]
async fn instance_attestation(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.store.read().await;
    let inst = store
        .get(&name)
        .ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;
    Ok(Json(AttestationResponse {
        name: inst.name.clone(),
        image_digest: inst.image_digest.clone(),
    }))
}

#[utoipa::path(get, path = "/attestation/report", tag = "Attestation",
    security(),
    responses(
        (status = 200, description = "TDX attestation report bound to the TLS certificate", body = TdxAttestationReport),
        (status = 503, description = "Attestation not available", body = ErrorResponse),
    )
)]
async fn tdx_attestation(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let domain = state
        .config
        .openclaw_domain
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("OPENCLAW_DOMAIN not configured".into()))?;

    // Read the TLS leaf certificate
    let (leaf_pem, leaf_der) = read_tls_certificate(domain)?;

    // Compute SHA-256 fingerprint of the DER-encoded leaf certificate
    use sha2::{Digest, Sha256};
    let fingerprint = Sha256::digest(&leaf_der);
    let fingerprint_hex = hex::encode(&fingerprint);

    // Build 64-byte report_data: sha256(cert) in first 32 bytes, zeros in last 32
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&fingerprint);

    // Get TDX quote from dstack guest-agent
    let quote_response = fetch_dstack_quote(&report_data).await?;

    let quote = quote_response
        .get("quote")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::ServiceUnavailable("dstack response missing 'quote'".into()))?
        .to_string();
    let event_log = quote_response
        .get("event_log")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::ServiceUnavailable("dstack response missing 'event_log'".into()))?
        .to_string();
    let returned_report_data = quote_response
        .get("report_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::ServiceUnavailable("dstack response missing 'report_data'".into())
        })?;
    let vm_config = quote_response
        .get("vm_config")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::ServiceUnavailable("dstack response missing 'vm_config'".into()))?
        .to_string();

    // Decode base64 report_data from dstack response to hex
    let report_data_hex = hex::encode(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            returned_report_data,
        )
        .map_err(|e| {
            ApiError::ServiceUnavailable(format!("failed to decode report_data from dstack: {}", e))
        })?,
    );

    Ok(Json(TdxAttestationReport {
        quote,
        event_log,
        report_data: report_data_hex,
        vm_config,
        tls_certificate: leaf_pem,
        tls_certificate_fingerprint: fingerprint_hex,
    }))
}

// ── Backup handlers ──────────────────────────────────────────────────

#[utoipa::path(post, path = "/instances/{name}/backup", tag = "Backups",
    params(("name" = String, Path, description = "Instance name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SSE stream of backup progress", content_type = "text/event-stream", body = SseEvent),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
        (status = 501, description = "Backups not configured", body = ErrorResponse),
    )
)]
async fn create_backup_endpoint(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_mgr = state
        .backup
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Backup not configured".into()))?
        .clone();

    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    let stream = async_stream::stream! {
        yield Ok(sse_stage("encrypting", "Exporting and encrypting workspace..."));

        let result = backup_mgr
            .create_backup(&name, &inst.ssh_pubkey, &state.compose)
            .await;

        match result {
            Ok(info) => {
                yield Ok(sse_stage("uploading", "Encrypted backup uploaded to S3"));
                yield Ok(Event::default()
                    .json_data(serde_json::json!({
                        "stage": "complete",
                        "message": format!("Backup complete: {}", info.id),
                        "backup": {
                            "id": info.id,
                            "timestamp": info.timestamp.to_rfc3339(),
                            "size_bytes": info.size_bytes,
                        }
                    }))
                    .unwrap());
            }
            Err(e) => {
                yield Ok(sse_error(&format!("Backup failed: {}", e)));
            }
        }
    };

    Ok(unbuffered_sse(stream))
}

#[utoipa::path(get, path = "/instances/{name}/backups", tag = "Backups",
    params(("name" = String, Path, description = "Instance name")),
    security(),
    responses(
        (status = 200, description = "List of available backups", body = BackupListResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
        (status = 501, description = "Backups not configured", body = ErrorResponse),
    )
)]
async fn list_backups_endpoint(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_mgr = state
        .backup
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Backup not configured".into()))?;

    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let backups = backup_mgr
        .list_backups(&name)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    let items: Vec<BackupInfoResponse> = backups
        .into_iter()
        .map(|b| BackupInfoResponse {
            id: b.id,
            timestamp: b.timestamp.to_rfc3339(),
            size_bytes: b.size_bytes,
        })
        .collect();

    Ok(Json(BackupListResponse { backups: items }))
}

#[utoipa::path(get, path = "/instances/{name}/backups/{id}", tag = "Backups",
    params(
        ("name" = String, Path, description = "Instance name"),
        ("id" = String, Path, description = "Backup ID (timestamp)"),
    ),
    security(),
    responses(
        (status = 200, description = "Presigned download URL", body = BackupDownloadResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
        (status = 501, description = "Backups not configured", body = ErrorResponse),
    )
)]
async fn download_backup_endpoint(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_mgr = state
        .backup
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Backup not configured".into()))?;

    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let url = backup_mgr
        .download_url(&name, &id)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok(Json(BackupDownloadResponse {
        url,
        expires_in_seconds: 3600,
    }))
}

// ── Utilities ────────────────────────────────────────────────────────

async fn update_nginx_now(state: &AppState) {
    if let Some(ref domain) = state.config.openclaw_domain {
        let instances = {
            let store = state.store.read().await;
            store.list()
        };
        let changed =
            nginx_conf::write_backends_map(&instances, domain, &state.config.nginx_map_path);
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

/// Read the TLS leaf certificate from the Let's Encrypt cert volume.
/// Returns (PEM string of leaf cert, DER bytes of leaf cert).
fn read_tls_certificate(domain: &str) -> Result<(String, Vec<u8>), ApiError> {
    let cert_base = std::env::var("CERT_DATA_PATH").unwrap_or_else(|_| "/etc/letsencrypt".into());
    let cert_path = format!("{}/live/{}/fullchain.pem", cert_base, domain);
    let pem_data = std::fs::read(&cert_path).map_err(|e| {
        ApiError::ServiceUnavailable(format!("TLS certificate not available: {}", e))
    })?;

    let certs = pem::parse_many(&pem_data)
        .map_err(|e| ApiError::ServiceUnavailable(format!("failed to parse PEM: {}", e)))?;

    let leaf_cert = certs
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::ServiceUnavailable("no certificate found in PEM file".into()))?;

    let leaf_pem = pem::encode(&leaf_cert);
    let der_bytes = leaf_cert.into_contents();

    Ok((leaf_pem, der_bytes))
}

/// Call dstack guest-agent GetQuote RPC via Unix socket.
async fn fetch_dstack_quote(report_data: &[u8; 64]) -> Result<serde_json::Value, ApiError> {
    let sock_path = "/var/run/dstack.sock";
    if !std::path::Path::new(sock_path).exists() {
        return Err(ApiError::ServiceUnavailable(
            "dstack.sock not found — not running in a TEE".into(),
        ));
    }

    let report_data_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, report_data);
    let body = serde_json::json!({ "report_data": report_data_b64 }).to_string();

    let output = tokio::process::Command::new("curl")
        .args([
            "--unix-socket",
            sock_path,
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            "http://localhost/GetQuote",
        ])
        .output()
        .await
        .map_err(|e| ApiError::ServiceUnavailable(format!("failed to call dstack: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::ServiceUnavailable(format!(
            "dstack GetQuote failed: {}",
            stderr
        )));
    }

    let response_body = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&response_body).map_err(|e| {
        ApiError::ServiceUnavailable(format!("failed to parse dstack response: {}", e))
    })
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

    // Scheduled backups every 6 hours (6 * 60 * 60 / 5 = 4320 ticks at 5s interval)
    let mut backup_tick: u32 = 0;
    const BACKUP_INTERVAL: u32 = 4320;

    tracing::info!("Background sync loop started (domain: {})", domain);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let instances = {
            let store = state.store.read().await;
            store.list()
        };

        let changed =
            nginx_conf::write_backends_map(&instances, &domain, &state.config.nginx_map_path);
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

        backup_tick += 1;
        if backup_tick >= BACKUP_INTERVAL {
            backup_tick = 0;
            if let Some(ref backup_mgr) = state.backup {
                for inst in &instances {
                    if !inst.active {
                        continue;
                    }
                    tracing::info!("Scheduled backup for instance: {}", inst.name);
                    match backup_mgr
                        .create_backup(&inst.name, &inst.ssh_pubkey, &state.compose)
                        .await
                    {
                        Ok(info) => {
                            tracing::info!(
                                "Scheduled backup complete for {}: {} ({} bytes)",
                                inst.name,
                                info.id,
                                info.size_bytes
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Scheduled backup failed for {}: {}", inst.name, e);
                        }
                    }
                }
            }
        }
    }
}
