use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
mod error;
mod names;
mod nginx_conf;
mod store;

use backup::BackupManager;
use compose::{ComposeManager, DEFAULT_NEARAI_API_URL};
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
        get_config,
        set_config,
        delete_config_key,
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
    config: Arc<AppConfig>,
    backup: Option<Arc<BackupManager>>,
}

struct AppConfig {
    admin_token: secrecy::SecretString,
    host_address: String,
    openclaw_domain: Option<String>,
    openclaw_image: String,
    ironclaw_image: String,
    compose_file: std::path::PathBuf,
    nginx_map_path: PathBuf,
    ingress_container_name: String,
    env_override_file: Option<PathBuf>,
    bastion_ssh_pubkey: Option<String>,
    bastion_ssh_port: Option<u16>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    async fn compose_up(
        &self,
        name: &str,
        nearai_api_key: &str,
        token: &str,
        gateway_port: u16,
        ssh_port: u16,
        ssh_pubkey: &str,
        image: &str,
        nearai_api_url: &str,
        service_type: &str,
        mem_limit: Option<String>,
        cpus: Option<String>,
        storage_size: Option<String>,
    ) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let nearai_api_key = nearai_api_key.to_string();
        let token = token.to_string();
        let ssh_pubkey = ssh_pubkey.to_string();
        let image = image.to_string();
        let nearai_api_url = nearai_api_url.to_string();
        let service_type = service_type.to_string();
        let bastion_ssh_pubkey = self.config.bastion_ssh_pubkey.clone();
        tokio::task::spawn_blocking(move || {
            compose.up(&compose::InstanceConfig {
                name: &name,
                nearai_api_key: &nearai_api_key,
                token: &token,
                gateway_port,
                ssh_port,
                ssh_pubkey: &ssh_pubkey,
                image: &image,
                nearai_api_url: &nearai_api_url,
                service_type: &service_type,
                bastion_ssh_pubkey: bastion_ssh_pubkey.as_deref(),
                mem_limit: mem_limit.as_deref(),
                cpus: cpus.as_deref(),
                storage_size: storage_size.as_deref(),
            })
        })
        .await
        .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_down(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.down(&name, service_type.as_deref()))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_stop(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.stop(&name, service_type.as_deref()))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_start(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.start(&name, service_type.as_deref()))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_restart(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.restart(&name, service_type.as_deref()))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_status(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<String, ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.status(&name, service_type.as_deref()))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_all_statuses(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, ApiError> {
        let compose = self.compose.clone();
        tokio::task::spawn_blocking(move || compose.all_statuses())
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_container_health(
        &self,
        name: &str,
    ) -> Result<compose::ContainerHealth, ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || compose.container_health(&name))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_resolve_image_digest(&self, name: &str) -> Option<String> {
        let compose = self.compose.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || compose.resolve_image_digest(&name))
            .await
            .ok()
            .flatten()
    }

    async fn compose_export_instance_data(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<Vec<u8>, ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            compose.export_instance_data(&name, service_type.as_deref())
        })
        .await
        .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }

    async fn compose_import_instance_data(
        &self,
        name: &str,
        tar_bytes: &[u8],
    ) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let tar_bytes = tar_bytes.to_vec();
        tokio::task::spawn_blocking(move || compose.import_instance_data(&name, &tar_bytes))
            .await
            .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
    }
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

        use secrecy::ExposeSecret;
        use subtle::ConstantTimeEq;

        if token.len() != ADMIN_TOKEN_HEX_LEN
            || !bool::from(
                token
                    .as_bytes()
                    .ct_eq(state.config.admin_token.expose_secret().as_bytes()),
            )
        {
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
    let admin_token = admin_token_raw.trim().to_string();
    validate_admin_token(&admin_token)?;

    let compose_file = std::env::var("COMPOSE_FILE")
        .unwrap_or_else(|_| "/app/docker-compose.worker.yml".to_string());
    let ironclaw_compose_file = std::env::var("IRONCLAW_COMPOSE_FILE")
        .unwrap_or_else(|_| "/app/docker-compose.ironclaw.yml".to_string());

    let bastion_ssh_pubkey = {
        let path = std::env::var("BASTION_SSH_PUBKEY_PATH")
            .unwrap_or_else(|_| "/app/data/bastion/id_ed25519.pub".to_string());
        match std::fs::read_to_string(&path) {
            Ok(key) => {
                let key = key.trim().to_string();
                tracing::info!("Loaded bastion SSH public key from {}", path);
                Some(key)
            }
            Err(_) => {
                tracing::info!(
                    "Bastion SSH public key not found at {} (bastion not deployed)",
                    path
                );
                None
            }
        }
    };
    let bastion_ssh_port: Option<u16> = Some(
        std::env::var("BASTION_SSH_EXTERNAL_PORT")
            .or_else(|_| std::env::var("BASTION_SSH_PORT"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15222),
    );

    let config = Arc::new(AppConfig {
        admin_token: secrecy::SecretString::from(admin_token),
        host_address: std::env::var("OPENCLAW_HOST_ADDRESS")
            .unwrap_or_else(|_| "localhost".to_string()),
        openclaw_domain: std::env::var("OPENCLAW_DOMAIN").ok(),
        openclaw_image: std::env::var("OPENCLAW_IMAGE")
            .unwrap_or_else(|_| "openclaw-nearai-worker:local".to_string()),
        ironclaw_image: std::env::var("IRONCLAW_IMAGE")
            .unwrap_or_else(|_| "ironclaw-nearai-worker:local".to_string()),
        compose_file: std::path::PathBuf::from(&compose_file),
        nginx_map_path: PathBuf::from(
            std::env::var("NGINX_MAP_PATH")
                .unwrap_or_else(|_| "/data/nginx/backends.map".to_string()),
        ),
        ingress_container_name: std::env::var("INGRESS_CONTAINER_NAME")
            .unwrap_or_else(|_| "nginx".to_string()),
        env_override_file: std::env::var("ENV_OVERRIDE_FILE").ok().map(PathBuf::from),
        bastion_ssh_pubkey,
        bastion_ssh_port,
    });

    let mut compose_files = std::collections::HashMap::new();
    compose_files.insert("openclaw".to_string(), config.compose_file.clone());
    let ironclaw_path = std::path::PathBuf::from(&ironclaw_compose_file);
    if ironclaw_path.exists() {
        compose_files.insert("ironclaw".to_string(), ironclaw_path);
        tracing::info!(
            "IronClaw compose template loaded: {}",
            ironclaw_compose_file
        );
    } else {
        tracing::info!(
            "IronClaw compose template not found at {}, ironclaw service type disabled",
            ironclaw_compose_file
        );
    }

    let compose = Arc::new(ComposeManager::new(
        compose_files,
        std::path::PathBuf::from("data/envs"),
        config.bastion_ssh_pubkey.clone(),
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
        backup,
    };

    update_nginx_now(&state).await;

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
        .route("/attestation/report", get(tdx_attestation))
        .route("/config", get(get_config))
        .route("/config", put(set_config))
        .route("/config/{key}", delete(delete_config_key));

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
        // Permissive CORS: required for embedded docs UI and external dashboards
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

#[derive(Serialize, Default, utoipa::ToSchema)]
struct ImageVersions {
    /// compose-api image reference (from COMPOSE_API_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    compose_api: Option<String>,
    /// openclaw worker image reference (from OPENCLAW_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    worker: Option<String>,
    /// ironclaw worker image reference (from IRONCLAW_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    ironclaw: Option<String>,
    /// nginx ingress image reference (from INGRESS_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<String>,
    /// ssh-bastion image reference (from BASTION_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    bastion: Option<String>,
    /// updater image reference (from UPDATER_IMAGE)
    #[serde(skip_serializing_if = "Option::is_none")]
    updater: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct VersionResponse {
    version: &'static str,
    git_commit: &'static str,
    build_time: &'static str,
    /// Currently deployed image references (from updater env overrides)
    images: ImageVersions,
}

#[utoipa::path(get, path = "/version", tag = "System",
    security(),
    responses((status = 200, description = "API version info", body = VersionResponse))
)]
async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    let images = state
        .config
        .env_override_file
        .as_deref()
        .and_then(|path| read_env_override_file(path).ok())
        .map(|vars| ImageVersions {
            compose_api: vars.get("COMPOSE_API_IMAGE").cloned(),
            worker: vars.get("OPENCLAW_IMAGE").cloned(),
            ironclaw: vars.get("IRONCLAW_IMAGE").cloned(),
            ingress: vars.get("INGRESS_IMAGE").cloned(),
            bastion: vars.get("BASTION_IMAGE").cloned(),
            updater: vars.get("UPDATER_IMAGE").cloned(),
        })
        .unwrap_or_default();

    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("GIT_COMMIT"),
        build_time: env!("BUILD_TIME"),
        images,
    })
}

// ── Request / Response types ─────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
struct CreateInstanceRequest {
    /// NEAR AI API key for the instance
    nearai_api_key: String,
    /// SSH public key for direct SSH access
    ssh_pubkey: String,
    /// Optional NEAR AI Cloud API URL (default: https://cloud-api.near.ai/v1)
    #[serde(default)]
    nearai_api_url: Option<String>,
    /// Optional instance name (auto-generated if omitted, 1-32 alphanumeric/hyphen chars)
    #[serde(default)]
    name: Option<String>,
    /// Optional Docker image reference (defaults to server-configured image)
    #[serde(default)]
    image: Option<String>,
    /// Service type: "openclaw" (default) or "ironclaw"
    #[serde(default)]
    service_type: Option<String>,
    /// Memory limit (e.g. "1g", "2g", "512m"). Default: "1g"
    #[serde(default)]
    mem_limit: Option<String>,
    /// CPU limit (e.g. "2", "4", "0.5"). Default: "2"
    #[serde(default)]
    cpus: Option<String>,
    /// Container storage limit (e.g. "10G", "20G"). Default: "10G"
    #[serde(default)]
    storage_size: Option<String>,
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
    ssh_pubkey: String,
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

/// Query parameters for the attestation report endpoint
#[derive(Deserialize, utoipa::IntoParams)]
struct AttestationQuery {
    /// 64-character hex string (32 bytes) to bind into the TDX quote as a nonce
    nonce: Option<String>,
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
    /// Hex nonce embedded in report_data bytes 32–63
    request_nonce: String,
    /// CVM/TCB info from dstack guest-agent
    info: serde_json::Value,
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

pub fn is_valid_instance_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn reject_newlines(field: &str, value: &str) -> Result<(), ApiError> {
    if value.contains('\n') || value.contains('\r') {
        return Err(ApiError::BadRequest(format!(
            "{field} must not contain newline characters"
        )));
    }
    Ok(())
}

/// Validate and sanitize nearai_api_url. Prevents injection into .env files: the value is
/// written by ComposeManager::write_env_file as KEY=value\n. An attacker could inject
/// newlines to add arbitrary env vars (e.g. OPENCLAW_IMAGE=malicious) or overwrite existing ones.
fn validate_nearai_api_url(url: &str) -> Result<String, ApiError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "nearai_api_url must not be empty".into(),
        ));
    }
    if trimmed.len() > 512 {
        return Err(ApiError::BadRequest(
            "nearai_api_url must not exceed 512 characters".into(),
        ));
    }
    // Reject newlines/carriage returns — prevents .env injection of arbitrary KEY=value lines
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(ApiError::BadRequest(
            "nearai_api_url must not contain newline characters".into(),
        ));
    }
    // Reject '=' — prevents injecting env-style assignments within the value
    if trimmed.contains('=') {
        return Err(ApiError::BadRequest(
            "nearai_api_url must not contain '='".into(),
        ));
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "nearai_api_url must be a valid HTTP or HTTPS URL".into(),
        ));
    }
    Ok(trimmed.to_string())
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

/// Returns the user-facing SSH port: bastion port when configured, otherwise the
/// per-instance direct port.
fn effective_ssh_port(config: &AppConfig, instance_ssh_port: u16) -> u16 {
    config.bastion_ssh_port.unwrap_or(instance_ssh_port)
}

fn generate_ssh_command(config: &AppConfig, name: &str, ssh_port: u16) -> String {
    let host = config
        .openclaw_domain
        .as_deref()
        .unwrap_or(&config.host_address);
    let port = effective_ssh_port(config, ssh_port);
    format!("ssh -p {} {}@{}", port, name, host)
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
        .expect("SSE JSON serialization")
}

fn sse_error(message: &str) -> Event {
    Event::default()
        .json_data(serde_json::json!({"stage": "error", "message": message}))
        .expect("SSE JSON serialization")
}

fn sse_created(info: &InstanceInfo) -> Event {
    Event::default()
        .json_data(serde_json::json!({
            "stage": "created",
            "message": format!("Instance '{}' created, ports {}-{} allocated", info.name, info.gateway_port, info.ssh_port),
            "instance": info,
        }))
        .expect("SSE JSON serialization")
}

// ── Health polling loop (shared by create/start/restart SSE streams) ─

const MAX_HEALTH_RETRIES: u32 = 2;

async fn poll_health_to_ready(
    state: &AppState,
    name: &str,
    service_type: Option<&str>,
    tx: &tokio::sync::mpsc::Sender<Event>,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut last_stage = String::new();
    let mut retries: u32 = 0;

    let success = loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = tx
                .send(sse_error("timeout waiting for container to become ready"))
                .await;
            break false;
        }

        let health = match state.compose_container_health(name).await {
            Ok(h) => h,
            Err(e) => {
                let _ = tx.send(sse_error(&e.to_string())).await;
                break false;
            }
        };
        let (stage, msg, done) = match (health.state.as_str(), health.health.as_str()) {
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
        };

        if stage != last_stage {
            last_stage = stage.to_string();

            if done {
                if retries < MAX_HEALTH_RETRIES {
                    retries += 1;
                    let _ = tx
                        .send(sse_stage(
                            "retrying",
                            &format!(
                                "{} — restarting (attempt {}/{})",
                                msg, retries, MAX_HEALTH_RETRIES
                            ),
                        ))
                        .await;
                    tracing::warn!(
                        "Instance '{}' failed ({}), restarting (attempt {}/{})",
                        name,
                        msg,
                        retries,
                        MAX_HEALTH_RETRIES
                    );
                    // Use `start` for exited/dead containers, `restart` for
                    // unhealthy ones that are still running.
                    let result = if health.state == "exited" || health.state == "dead" {
                        state.compose_start(name, service_type).await
                    } else {
                        state.compose_restart(name, service_type).await
                    };
                    if let Err(e) = result {
                        let _ = tx
                            .send(sse_error(&format!("Failed to restart container: {}", e)))
                            .await;
                        break false;
                    }
                    last_stage.clear();
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
                let _ = tx.send(sse_error(msg)).await;
                break false;
            }

            let _ = tx.send(sse_stage(stage, msg)).await;

            if stage == "healthy" {
                let _ = tx
                    .send(sse_stage("ready", &format!("Instance '{}' is ready", name)))
                    .await;
                break true;
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    };

    // On health check failure, deactivate the instance and remove from routing
    // so nginx stops sending traffic to a non-functional container.
    if !success {
        {
            let mut store = state.store.write().await;
            if let Err(e) = store.set_active(name, false) {
                tracing::warn!("Failed to deactivate instance on health failure: {}", e);
            }
        }
        update_nginx_now(state).await;
        tracing::warn!("Deactivated instance '{}' after health check failure", name);
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

    // Resolve service type
    let service_type = req
        .service_type
        .as_deref()
        .unwrap_or("openclaw")
        .to_string();
    if service_type != "openclaw" && service_type != "ironclaw" {
        return Err(ApiError::BadRequest(
            "service_type must be 'openclaw' or 'ironclaw'".into(),
        ));
    }

    // Resolve image based on service type
    let image = match &req.image {
        Some(img) => {
            validate_image(img)?;
            img.trim().to_string()
        }
        None => match service_type.as_str() {
            "ironclaw" => state.config.ironclaw_image.clone(),
            _ => state.config.openclaw_image.clone(),
        },
    };

    // Defense-in-depth: reject newlines at the API boundary
    reject_newlines("nearai_api_key", &req.nearai_api_key)?;
    reject_newlines("ssh_pubkey", &req.ssh_pubkey)?;
    reject_newlines("image", &image)?;

    // Validate nearai_api_url (prevents .env injection via newlines)
    let nearai_api_url = match req.nearai_api_url.as_deref().filter(|s| !s.is_empty()) {
        Some(url) => validate_nearai_api_url(url)?,
        None => DEFAULT_NEARAI_API_URL.to_string(),
    };

    // Resolve instance name
    let name = if let Some(provided) = &req.name {
        let sanitized = provided.to_lowercase();
        if !is_valid_instance_name(&sanitized) {
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
        store.next_available_ports()?
    };

    let (url, dashboard_url) = generate_urls(&state.config, &name, gateway_port, &token);
    let ssh_command = generate_ssh_command(&state.config, &name, ssh_port);

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
        nearai_api_url: Some(nearai_api_url.clone()),
        active: true,
        image: Some(image.clone()),
        image_digest: None,
        service_type: Some(service_type.clone()),
        mem_limit: req.mem_limit.clone(),
        cpus: req.cpus.clone(),
        storage_size: req.storage_size.clone(),
    };

    // Save to store before streaming so it's persisted immediately
    {
        let mut store = state.store.write().await;
        store.add(instance);
    }

    let nearai_api_key = req.nearai_api_key.clone();
    let ssh_pubkey = req.ssh_pubkey.clone();
    let mem_limit = req.mem_limit.clone();
    let cpus = req.cpus.clone();
    let storage_size = req.storage_size.clone();

    let stream = async_stream::stream! {
        yield Ok(sse_created(&info));

        yield Ok(sse_stage("container_starting", "Pulling image and starting container..."));

        if let Err(e) = state.compose_up(
            &name,
            &nearai_api_key,
            &token,
            gateway_port,
            ssh_port,
            &ssh_pubkey,
            &image,
            &nearai_api_url,
            &service_type,
            mem_limit,
            cpus,
            storage_size,
        ).await {
            // Remove from store — container never started, instance is not functional
            {
                let mut store = state.store.write().await;
                store.remove(&name);
            }
            yield Ok(sse_error(&format!("Failed to start container: {}", e)));
            return;
        }

        yield Ok(sse_stage("configuring_routing", "Updating nginx routing table..."));
        update_nginx_now(&state).await;

        // Resolve the image digest now that the container is running
        let image_digest = state.compose_resolve_image_digest(&name).await;
        if let Some(ref digest) = image_digest {
            yield Ok(sse_stage("image_resolved", &format!("Image digest: {}", digest)));
        }
        {
            let mut store = state.store.write().await;
            let _ = store.set_image(&name, Some(image.clone()), image_digest);
        }

        tracing::info!("Created instance: {} (gateway:{}, ssh:{})", name, gateway_port, ssh_port);

        // Poll health until ready (with auto-retry on failure)
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        let poll_service_type = service_type.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, Some(&poll_service_type), &tx).await;
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
            let status = state
                .compose_status(&inst.name, inst.service_type.as_deref())
                .await?;
            let (url, dashboard_url) =
                generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
            let ssh_command = generate_ssh_command(&state.config, &inst.name, inst.ssh_port);
            let image = inst
                .image
                .clone()
                .unwrap_or_else(|| state.config.openclaw_image.clone());
            Ok(Json(InstanceResponse {
                name: inst.name.clone(),
                token: inst.token,
                url,
                dashboard_url,
                gateway_port: inst.gateway_port,
                ssh_port: inst.ssh_port,
                ssh_command,
                ssh_pubkey: inst.ssh_pubkey,
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

    if instances.is_empty() {
        return Ok(Json(InstancesListResponse {
            instances: Vec::new(),
        }));
    }

    let status_map = state.compose_all_statuses().await?;

    let responses: Vec<_> = instances
        .into_iter()
        .map(|inst| {
            let status = status_map
                .get(&inst.name)
                .cloned()
                .unwrap_or_else(|| "not found".to_string());
            let (url, dashboard_url) =
                generate_urls(&state.config, &inst.name, inst.gateway_port, &inst.token);
            let ssh_command = generate_ssh_command(&state.config, &inst.name, inst.ssh_port);
            let image = inst
                .image
                .unwrap_or_else(|| state.config.openclaw_image.clone());
            InstanceResponse {
                name: inst.name,
                token: inst.token,
                url,
                dashboard_url,
                gateway_port: inst.gateway_port,
                ssh_port: inst.ssh_port,
                ssh_command,
                ssh_pubkey: inst.ssh_pubkey,
                image,
                image_digest: inst.image_digest,
                status,
                created_at: inst.created_at.to_rfc3339(),
            }
        })
        .collect();

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
    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    state
        .compose_down(&name, inst.service_type.as_deref())
        .await?;

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
            // Full upgrade: export workspace → down -v → up with new image → restore workspace
            let stype = match inst.service_type.as_deref() {
                Some(st) => st,
                None => {
                    yield Ok(sse_error(&format!(
                        "Instance '{}' has no service_type set; refusing to upgrade \
                         (would use wrong compose file and lose data)",
                        name
                    )));
                    return;
                }
            };

            yield Ok(sse_stage("exporting", "Exporting workspace and config..."));

            let tar_bytes = match state.compose_export_instance_data(&name, Some(stype)).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    yield Ok(sse_error(&format!("Failed to export workspace: {}", e)));
                    return;
                }
            };

            yield Ok(sse_stage("stopping", "Stopping and removing old container..."));

            if let Err(e) = state.compose_down(&name, Some(stype)).await {
                yield Ok(sse_error(&format!("Failed to stop old container: {}", e)));
                return;
            }

            yield Ok(sse_stage("container_starting", &format!("Starting new container with image {}...", image)));

            if let Err(e) = state.compose_up(
                &name,
                &inst.nearai_api_key,
                &inst.token,
                inst.gateway_port,
                inst.ssh_port,
                &inst.ssh_pubkey,
                image,
                inst.nearai_api_url.as_deref().unwrap_or(DEFAULT_NEARAI_API_URL),
                stype,
                inst.mem_limit.clone(),
                inst.cpus.clone(),
                inst.storage_size.clone(),
            ).await {
                {
                    let mut store = state.store.write().await;
                    let _ = store.set_active(&name, false);
                }
                update_nginx_now(&state).await;
                yield Ok(sse_error(&format!("Failed to start new container: {}", e)));
                return;
            }

            // Update image metadata immediately after new container starts, so it's correct
            // even if workspace restore fails later
            let image_digest = state.compose_resolve_image_digest(&name).await;
            {
                let mut store = state.store.write().await;
                let _ = store.set_image(&name, Some(image.clone()), image_digest.clone());
            }
            if let Some(ref digest) = image_digest {
                yield Ok(sse_stage("image_resolved", &format!("Image digest: {}", digest)));
            }

            yield Ok(sse_stage("restoring", "Restoring workspace and config..."));

            if let Err(e) = state.compose_import_instance_data(&name, &tar_bytes).await {
                yield Ok(sse_error(&format!("Failed to restore workspace: {}", e)));
                return;
            }
        } else {
            // Simple restart
            yield Ok(sse_stage("container_starting", "Restarting container..."));

            if let Err(e) = state.compose_restart(&name, inst.service_type.as_deref()).await {
                yield Ok(sse_error(&format!("Failed to restart container: {}", e)));
                return;
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let poll_state = state.clone();
        let poll_name = name.clone();
        let poll_service_type = inst.service_type.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, poll_service_type.as_deref(), &tx).await;
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
    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    let stream = async_stream::stream! {
        yield Ok(sse_stage("stopping", "Stopping container..."));

        if let Err(e) = state.compose_stop(&name, inst.service_type.as_deref()).await {
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
    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    let stream = async_stream::stream! {
        yield Ok(sse_stage("container_starting", "Starting container..."));

        if let Err(e) = state.compose_start(&name, inst.service_type.as_deref()).await {
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
        let poll_service_type = inst.service_type.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, poll_service_type.as_deref(), &tx).await;
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
    params(AttestationQuery),
    responses(
        (status = 200, description = "TDX attestation report bound to the TLS certificate", body = TdxAttestationReport),
        (status = 400, description = "Invalid nonce format", body = ErrorResponse),
        (status = 503, description = "Attestation not available", body = ErrorResponse),
    )
)]
async fn tdx_attestation(
    State(state): State<AppState>,
    Query(params): Query<AttestationQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate and resolve nonce (caller-provided or random)
    let nonce_hex = if let Some(ref n) = params.nonce {
        // Validate: must be exactly 64 hex characters (32 bytes)
        if n.len() != 64 {
            return Err(ApiError::BadRequest(
                "nonce must be exactly 64 hex characters (32 bytes)".into(),
            ));
        }
        hex::decode(n)
            .map_err(|_| ApiError::BadRequest("nonce must be a valid hex string".into()))?;
        n.clone()
    } else {
        // Generate a random 32-byte nonce
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        hex::encode(bytes)
    };

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
    let fingerprint_hex = hex::encode(fingerprint);

    // Build 64-byte report_data: sha256(cert) in first 32 bytes, nonce in last 32
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&fingerprint);
    let nonce_bytes = hex::decode(&nonce_hex).expect("nonce already validated");
    report_data[32..].copy_from_slice(&nonce_bytes);

    // Get TDX quote and CVM info from dstack guest-agent
    let (quote_response, info) =
        tokio::try_join!(fetch_dstack_quote(&report_data), fetch_dstack_info())?;

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

    // dstack returns report_data as a hex string — validate and use directly
    let report_data_hex = returned_report_data.to_string();
    hex::decode(&report_data_hex).map_err(|e| {
        ApiError::ServiceUnavailable(format!("dstack returned invalid hex report_data: {}", e))
    })?;

    Ok(Json(TdxAttestationReport {
        quote,
        event_log,
        report_data: report_data_hex,
        vm_config,
        tls_certificate: leaf_pem,
        tls_certificate_fingerprint: fingerprint_hex,
        request_nonce: nonce_hex,
        info,
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
        .ok_or_else(|| ApiError::NotImplemented("Backup not configured".into()))?
        .clone();

    let inst = {
        let store = state.store.read().await;
        store.get(&name).cloned()
    };
    let inst = inst.ok_or_else(|| ApiError::NotFound(format!("Instance '{}' not found", name)))?;

    let stream = async_stream::stream! {
        yield Ok(sse_stage("encrypting", "Exporting and encrypting workspace..."));

        let tar_bytes = match state.compose_export_instance_data(&name, inst.service_type.as_deref()).await {
            Ok(bytes) => bytes,
            Err(e) => {
                yield Ok(sse_error(&format!("Backup failed: {}", e)));
                return;
            }
        };

        let result = backup_mgr
            .create_backup(&name, &inst.ssh_pubkey, tar_bytes)
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
                    .expect("SSE JSON serialization"));
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
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of available backups", body = BackupListResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
        (status = 501, description = "Backups not configured", body = ErrorResponse),
    )
)]
async fn list_backups_endpoint(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_mgr = state
        .backup
        .as_ref()
        .ok_or_else(|| ApiError::NotImplemented("Backup not configured".into()))?;

    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let backups = backup_mgr.list_backups(&name).await?;

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
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Presigned download URL", body = BackupDownloadResponse),
        (status = 404, description = "Instance not found", body = ErrorResponse),
        (status = 501, description = "Backups not configured", body = ErrorResponse),
    )
)]
async fn download_backup_endpoint(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_mgr = state
        .backup
        .as_ref()
        .ok_or_else(|| ApiError::NotImplemented("Backup not configured".into()))?;

    {
        let store = state.store.read().await;
        if store.get(&name).is_none() {
            return Err(ApiError::NotFound(format!("Instance '{}' not found", name)));
        }
    }

    let url = backup_mgr.download_url(&name, &id).await?;

    Ok(Json(BackupDownloadResponse {
        url,
        expires_in_seconds: 3600,
    }))
}

// ── Config (env override) handlers ───────────────────────────────────

fn validate_env_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty() || key.len() > 128 {
        return Err(ApiError::BadRequest("Key must be 1-128 characters".into()));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(ApiError::BadRequest("Key must match [A-Z0-9_]+".into()));
    }
    Ok(())
}

fn validate_env_value(value: &str) -> Result<(), ApiError> {
    if value.contains('\n') || value.contains('\r') {
        return Err(ApiError::BadRequest(
            "Value must not contain newline characters".into(),
        ));
    }
    Ok(())
}

fn read_env_override_file(path: &std::path::Path) -> Result<BTreeMap<String, String>, ApiError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => {
            return Err(ApiError::Internal(format!(
                "Failed to read override file: {}",
                e
            )))
        }
    };

    let mut map = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    Ok(map)
}

fn write_env_override_file(
    path: &std::path::Path,
    vars: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ApiError::Internal(format!("Failed to create override file directory: {}", e))
        })?;
    }
    let content: String = vars
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(path, content)
        .map_err(|e| ApiError::Internal(format!("Failed to write override file: {}", e)))?;
    Ok(())
}

fn require_override_file(config: &AppConfig) -> Result<&std::path::Path, ApiError> {
    config
        .env_override_file
        .as_deref()
        .ok_or_else(|| ApiError::NotFound("ENV_OVERRIDE_FILE not configured".into()))
}

#[utoipa::path(get, path = "/config", tag = "Config",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current env var overrides", body = Object),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Override file not configured", body = ErrorResponse),
    )
)]
async fn get_config(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let path = require_override_file(&state.config)?;
    let vars = read_env_override_file(path)?;
    Ok(Json(vars))
}

#[utoipa::path(put, path = "/config", tag = "Config",
    request_body = Object,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Updated env var overrides", body = Object),
        (status = 400, description = "Invalid key or value", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Override file not configured", body = ErrorResponse),
    )
)]
async fn set_config(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<BTreeMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let path = require_override_file(&state.config)?;

    for (key, value) in &body {
        validate_env_key(key)?;
        validate_env_value(value)?;
    }

    let mut vars = read_env_override_file(path)?;
    for (key, value) in body {
        vars.insert(key, value);
    }
    write_env_override_file(path, &vars)?;

    tracing::info!("Config updated: {} vars in override file", vars.len());
    Ok(Json(vars))
}

#[utoipa::path(delete, path = "/config/{key}", tag = "Config",
    params(("key" = String, Path, description = "Environment variable key to remove")),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Key removed"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Override file not configured or key not found", body = ErrorResponse),
    )
)]
async fn delete_config_key(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let path = require_override_file(&state.config)?;
    let mut vars = read_env_override_file(path)?;
    if vars.remove(&key).is_none() {
        return Err(ApiError::NotFound(format!("Key '{}' not found", key)));
    }
    write_env_override_file(path, &vars)?;
    tracing::info!("Config key '{}' removed from override file", key);
    Ok(StatusCode::NO_CONTENT)
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

    let report_data_hex = hex::encode(report_data);
    let body = serde_json::json!({ "report_data": report_data_hex }).to_string();

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

/// Call dstack guest-agent Info RPC via Unix socket to get CVM/TCB metadata.
async fn fetch_dstack_info() -> Result<serde_json::Value, ApiError> {
    let sock_path = "/var/run/dstack.sock";
    if !std::path::Path::new(sock_path).exists() {
        return Err(ApiError::ServiceUnavailable(
            "dstack.sock not found — not running in a TEE".into(),
        ));
    }

    let output = tokio::process::Command::new("curl")
        .args(["--unix-socket", sock_path, "-s", "http://localhost/Info"])
        .output()
        .await
        .map_err(|e| ApiError::ServiceUnavailable(format!("failed to call dstack: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::ServiceUnavailable(format!(
            "dstack Info failed: {}",
            stderr
        )));
    }

    let response_body = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&response_body).map_err(|e| {
        ApiError::ServiceUnavailable(format!("failed to parse dstack Info response: {}", e))
    })
}

// Expose AppConfig fields for generate_urls/generate_ssh_command tests
#[cfg(test)]
impl AppConfig {
    fn test_default() -> Self {
        Self {
            admin_token: secrecy::SecretString::from("a".repeat(32)),
            host_address: "localhost".to_string(),
            openclaw_domain: None,
            openclaw_image: "test:local".to_string(),
            ironclaw_image: "ironclaw-test:local".to_string(),
            compose_file: std::path::PathBuf::from("/dev/null"),
            nginx_map_path: PathBuf::from("/tmp/test.map"),
            ingress_container_name: "test-ingress".to_string(),
            env_override_file: None,
            bastion_ssh_pubkey: None,
            bastion_ssh_port: Some(15222),
        }
    }
}

async fn background_sync_loop(state: AppState) {
    let domain = match &state.config.openclaw_domain {
        Some(d) => d.clone(),
        None => return,
    };

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

        backup_tick += 1;
        if backup_tick >= BACKUP_INTERVAL {
            backup_tick = 0;
            if let Some(ref backup_mgr) = state.backup {
                for inst in &instances {
                    if !inst.active {
                        continue;
                    }
                    tracing::info!("Scheduled backup for instance: {}", inst.name);
                    let tar_bytes = match state
                        .compose_export_instance_data(&inst.name, inst.service_type.as_deref())
                        .await
                    {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::warn!(
                                "Scheduled backup export failed for {}: {}",
                                inst.name,
                                e
                            );
                            continue;
                        }
                    };
                    match backup_mgr
                        .create_backup(&inst.name, &inst.ssh_pubkey, tar_bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_admin_token ─────────────────────────────────────────

    #[test]
    fn test_validate_admin_token_valid() {
        assert!(validate_admin_token("abcdef0123456789abcdef0123456789").is_ok());
    }

    #[test]
    fn test_validate_admin_token_wrong_length() {
        assert!(validate_admin_token("abcdef").is_err());
    }

    #[test]
    fn test_validate_admin_token_non_hex() {
        assert!(validate_admin_token("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    // ── validate_image ───────────────────────────────────────────────

    #[test]
    fn test_validate_image_valid_digest() {
        assert!(validate_image("docker.io/org/img@sha256:abc123").is_ok());
    }

    #[test]
    fn test_validate_image_empty() {
        assert!(validate_image("").is_err());
    }

    #[test]
    fn test_validate_image_no_digest() {
        assert!(validate_image("docker.io/org/img:latest").is_err());
    }

    #[test]
    fn test_validate_image_too_long() {
        let long_image = format!("docker.io/org/img@sha256:{}", "a".repeat(300));
        assert!(validate_image(&long_image).is_err());
    }

    // ── generate_urls ────────────────────────────────────────────────

    #[test]
    fn test_generate_urls_with_domain() {
        let mut config = AppConfig::test_default();
        config.openclaw_domain = Some("example.com".to_string());
        let (url, dashboard) = generate_urls(&config, "test", 19001, "tok");
        assert_eq!(url, "https://test.example.com");
        assert_eq!(dashboard, "https://test.example.com/?token=tok");
    }

    #[test]
    fn test_generate_urls_without_domain() {
        let config = AppConfig::test_default();
        let (url, dashboard) = generate_urls(&config, "test", 19001, "tok");
        assert_eq!(url, "http://localhost:19001");
        assert_eq!(dashboard, "http://localhost:19001/?token=tok");
    }

    // ── generate_ssh_command ─────────────────────────────────────────

    #[test]
    fn test_generate_ssh_command() {
        let config = AppConfig::test_default();
        let cmd = generate_ssh_command(&config, "brave-tiger", 19002);
        assert_eq!(cmd, "ssh -p 15222 brave-tiger@localhost");
    }

    #[test]
    fn test_generate_ssh_command_with_bastion() {
        let mut config = AppConfig::test_default();
        config.bastion_ssh_port = Some(2222);
        let cmd = generate_ssh_command(&config, "brave-tiger", 19002);
        assert_eq!(cmd, "ssh -p 2222 brave-tiger@localhost");
    }

    #[test]
    fn test_generate_ssh_command_with_domain() {
        let mut config = AppConfig::test_default();
        config.openclaw_domain = Some("agent0.near.ai".into());
        let cmd = generate_ssh_command(&config, "brave-tiger", 19002);
        assert_eq!(cmd, "ssh -p 15222 brave-tiger@agent0.near.ai");
    }

    // ── is_valid_instance_name ───────────────────────────────────────

    #[test]
    fn test_is_valid_instance_name_valid() {
        assert!(is_valid_instance_name("brave-tiger"));
        assert!(is_valid_instance_name("a"));
        assert!(is_valid_instance_name("test-123"));
    }

    #[test]
    fn test_is_valid_instance_name_empty() {
        assert!(!is_valid_instance_name(""));
    }

    #[test]
    fn test_is_valid_instance_name_too_long() {
        assert!(!is_valid_instance_name(&"a".repeat(33)));
    }

    #[test]
    fn test_is_valid_instance_name_special_chars() {
        assert!(!is_valid_instance_name("foo bar"));
        assert!(!is_valid_instance_name("foo_bar"));
        assert!(!is_valid_instance_name("foo.bar"));
        assert!(!is_valid_instance_name("../etc"));
    }

    #[test]
    fn test_is_valid_instance_name_hyphens_ok() {
        assert!(is_valid_instance_name("a-b-c"));
        assert!(!is_valid_instance_name("-leading"));
        assert!(!is_valid_instance_name("trailing-"));
    }
}
