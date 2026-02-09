use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod compose;
mod dns;
mod error;
mod nginx_conf;
mod store;

use compose::ComposeManager;
use dns::CloudflareDns;
use error::ApiError;
use store::{User, UserStore};

const ADMIN_TOKEN_HEX_LEN: usize = 32;

#[derive(Clone)]
struct AppState {
    compose: Arc<ComposeManager>,
    store: Arc<RwLock<UserStore>>,
    config: AppConfig,
    dns: Option<Arc<CloudflareDns>>,
}

#[derive(Clone)]
struct AppConfig {
    admin_token: String,
    host_address: String,
    openclaw_domain: Option<String>,  // Used for generating HTTPS URLs
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

        // Normalize to hex-only to ignore trailing newline/\r/null from env or header
        let token_hex: String = token.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let expected_hex: String = state.config.admin_token.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if token_hex != expected_hex || token_hex.len() != 32 {
            return Err(ApiError::Unauthorized("Invalid admin token".into()));
        }

        Ok(AdminAuth)
    }
}

fn validate_admin_token(token: &str) -> anyhow::Result<()> {
    // Token should be 32 hex characters (16 bytes)
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
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load and validate admin token; normalize to hex-only (ignores trailing newline/\r from env)
    let admin_token_raw = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set");
    let admin_token: String = admin_token_raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    validate_admin_token(&admin_token)?;
    
    // Load configuration from environment
    let compose_file = std::env::var("COMPOSE_FILE")
        .unwrap_or_else(|_| "/app/docker-compose.worker.yml".to_string());

    // Fetch APP_ID from dstack.sock if available
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

    // Initialize Cloudflare DNS client if configured
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

    // Initialize Compose manager (creates env dir, validates compose file)
    let compose = Arc::new(ComposeManager::new(
        config.compose_file.clone(),
        std::path::PathBuf::from("data/envs"),
        config.openclaw_image.clone(),
    )?);

    // Load or create user store
    let store = Arc::new(RwLock::new(UserStore::load_or_create("data/users.json")?));

    if let Some(ref domain) = config.openclaw_domain {
        tracing::info!("OPENCLAW_DOMAIN set: user URLs will use https://{{user}}.{}", domain);
    }

    let state = AppState {
        compose,
        store,
        config,
        dns,
    };

    // Write initial nginx map at startup so pre-existing users are routable immediately
    update_nginx_now(&state).await;

    // Spawn background sync loop for nginx map + DNS reconciliation
    if state.config.openclaw_domain.is_some() {
        let sync_state = state.clone();
        tokio::spawn(async move {
            background_sync_loop(sync_state).await;
        });
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/version", get(version))
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{user_id}", get(get_user))
        .route("/users/{user_id}", delete(delete_user))
        .route("/users/{user_id}/restart", post(restart_user))
        .route("/users/{user_id}/stop", post(stop_user))
        .route("/users/{user_id}/start", post(start_user))
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
    "hex_norm_v1"
}

#[derive(Deserialize)]
struct CreateUserRequest {
    user_id: String,
    nearai_api_key: String,
    #[serde(default)]
    ssh_pubkey: Option<String>,
}

#[derive(Serialize)]
struct CreateUserResponse {
    user_id: String,
    token: String,
    gateway_port: u16,
    ssh_port: u16,
    url: String,
    dashboard_url: String,
    ssh_command: String,
    status: String,
}

/// Generate URL and dashboard_url based on config
fn generate_urls(config: &AppConfig, user_id: &str, gateway_port: u16, token: &str) -> (String, String) {
    match &config.openclaw_domain {
        Some(domain) => {
            let base = format!("https://{}.{}", user_id, domain);
            (base.clone(), format!("{}/?token={}", base, token))
        }
        None => {
            let base = format!("http://{}:{}", config.host_address, gateway_port);
            (base.clone(), format!("{}/?token={}", base, token))
        }
    }
}

async fn create_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = req.user_id.to_lowercase().replace(|c: char| !c.is_alphanumeric() && c != '-', "");
    
    if user_id.is_empty() || user_id.len() > 32 {
        return Err(ApiError::BadRequest("Invalid user_id: must be 1-32 alphanumeric characters".into()));
    }

    if req.nearai_api_key.is_empty() {
        return Err(ApiError::BadRequest("nearai_api_key is required".into()));
    }

    // Check if user already exists
    {
        let store = state.store.read().await;
        if store.get(&user_id).is_some() {
            return Err(ApiError::Conflict(format!("User {} already exists", user_id)));
        }
    }

    // Generate unique token
    let token = generate_token();
    
    // Allocate ports (gateway + SSH)
    let (gateway_port, ssh_port) = {
        let store = state.store.read().await;
        store.next_available_ports()
    };

    // Spin up the worker compose project
    state.compose.up(
        &user_id,
        &req.nearai_api_key,
        &token,
        gateway_port,
        ssh_port,
        req.ssh_pubkey.as_deref(),
    )?;

    // Store user info
    let user = User {
        user_id: user_id.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        created_at: chrono::Utc::now(),
        ssh_pubkey: req.ssh_pubkey.clone(),
        nearai_api_key: req.nearai_api_key.clone(),
        active: true,
    };

    {
        let mut store = state.store.write().await;
        store.add(user)?;
    }

    // Update nginx map immediately so the instance is routable right away
    update_nginx_now(&state).await;

    // Create DNS TXT record immediately so routing works right away
    if let (Some(ref dns), Some(ref domain), Some(ref app_id)) =
        (&state.dns, &state.config.openclaw_domain, &state.config.dstack_app_id)
    {
        if let Err(e) = dns.ensure_txt_record(&user_id, domain, app_id, 443).await {
            tracing::warn!("Failed to create DNS record for {}: {}", user_id, e);
        }
    }

    tracing::info!("Created user container: {} (gateway:{}, ssh:{})", user_id, gateway_port, ssh_port);

    let (url, dashboard_url) = generate_urls(&state.config, &user_id, gateway_port, &token);
    let ssh_command = format!("ssh -p {} agent@{}", ssh_port, state.config.host_address);
    
    Ok((
        StatusCode::CREATED,
        Json(CreateUserResponse {
            user_id,
            token,
            gateway_port,
            ssh_port,
            url,
            dashboard_url,
            ssh_command,
            status: "running".to_string(),
        }),
    ))
}

#[derive(Serialize)]
struct UserResponse {
    user_id: String,
    token: String,
    url: String,
    dashboard_url: String,
    gateway_port: u16,
    ssh_port: u16,
    ssh_command: String,
    status: String,
    created_at: String,
}

async fn get_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = {
        let store = state.store.read().await;
        store.get(&user_id).cloned()
    };

    match user {
        Some(user) => {
            let status = state.compose.status(&user.user_id)?;
            let (url, dashboard_url) = generate_urls(&state.config, &user.user_id, user.gateway_port, &user.token);
            let ssh_command = format!("ssh -p {} agent@{}", user.ssh_port, state.config.host_address);
            Ok(Json(UserResponse {
                user_id: user.user_id,
                token: user.token,
                url,
                dashboard_url,
                gateway_port: user.gateway_port,
                ssh_port: user.ssh_port,
                ssh_command,
                status,
                created_at: user.created_at.to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

#[derive(Serialize)]
struct UsersListResponse {
    users: Vec<UserResponse>,
}

async fn list_users(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let users = {
        let store = state.store.read().await;
        store.list().to_vec()
    };

    let mut responses = Vec::new();
    for user in users {
        let status = state.compose.status(&user.user_id)
            .unwrap_or_else(|_| "unknown".to_string());
        let (url, dashboard_url) = generate_urls(&state.config, &user.user_id, user.gateway_port, &user.token);
        let ssh_command = format!("ssh -p {} agent@{}", user.ssh_port, state.config.host_address);
        responses.push(UserResponse {
            user_id: user.user_id.clone(),
            token: user.token.clone(),
            url,
            dashboard_url,
            gateway_port: user.gateway_port,
            ssh_port: user.ssh_port,
            ssh_command,
            status,
            created_at: user.created_at.to_rfc3339(),
        });
    }

    Ok(Json(UsersListResponse { users: responses }))
}

async fn delete_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = {
        let store = state.store.read().await;
        store.get(&user_id).cloned()
    };

    match user {
        Some(_user) => {
            // Tear down the compose project (removes containers + volumes)
            state.compose.down(&user_id)?;

            // Delete DNS TXT record immediately
            if let (Some(ref dns), Some(ref domain)) =
                (&state.dns, &state.config.openclaw_domain)
            {
                if let Err(e) = dns.delete_txt_record(&user_id, domain).await {
                    tracing::warn!("Failed to delete DNS record for {}: {}", user_id, e);
                }
            }

            // Remove from store
            {
                let mut store = state.store.write().await;
                store.remove(&user_id)?;
            }

            // Update nginx map immediately to stop routing to deleted instance
            update_nginx_now(&state).await;

            tracing::info!("Deleted user container: {}", user_id);
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

async fn restart_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = {
        let store = state.store.read().await;
        store.get(&user_id).cloned()
    };

    match user {
        Some(_user) => {
            state.compose.restart(&user_id)?;
            tracing::info!("Restarted user container: {}", user_id);
            Ok(Json(serde_json::json!({"status": "restarted"})))
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

async fn stop_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = {
        let store = state.store.read().await;
        store.get(&user_id).cloned()
    };

    match user {
        Some(_user) => {
            state.compose.stop(&user_id)?;
            {
                let mut store = state.store.write().await;
                store.set_active(&user_id, false)?;
            }
            update_nginx_now(&state).await;
            tracing::info!("Stopped user container: {}", user_id);
            Ok(Json(serde_json::json!({"status": "stopped"})))
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

async fn start_user(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = {
        let store = state.store.read().await;
        store.get(&user_id).cloned()
    };

    match user {
        Some(_user) => {
            state.compose.start(&user_id)?;
            {
                let mut store = state.store.write().await;
                store.set_active(&user_id, true)?;
            }
            update_nginx_now(&state).await;
            tracing::info!("Started user container: {}", user_id);
            Ok(Json(serde_json::json!({"status": "started"})))
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

/// Immediately write the nginx backends map and reload if changed.
async fn update_nginx_now(state: &AppState) {
    if let Some(ref domain) = state.config.openclaw_domain {
        let users = {
            let store = state.store.read().await;
            store.list()
        };
        let changed = nginx_conf::write_backends_map(&users, domain, &state.config.nginx_map_path);
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

/// Fetches the APP_ID from dstack.sock (GET http://localhost/Info via unix socket).
/// Returns None if dstack.sock is not available.
async fn fetch_dstack_app_id() -> Option<String> {
    let sock_path = "/var/run/dstack.sock";
    if !std::path::Path::new(sock_path).exists() {
        tracing::info!("dstack.sock not found, skipping APP_ID fetch");
        return None;
    }

    // Shell out to curl for simplicity — avoids pulling in hyper unix socket deps
    let output = std::process::Command::new("curl")
        .args(["--unix-socket", sock_path, "-s", "http://localhost/Info"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            // Parse JSON and extract app_id
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

/// Background loop that syncs the nginx backends map and DNS TXT records.
async fn background_sync_loop(state: AppState) {
    let domain = match &state.config.openclaw_domain {
        Some(d) => d.clone(),
        None => return,
    };

    let mut dns_tick: u32 = 0;
    const DNS_SYNC_INTERVAL: u32 = 12; // Every 12 * 5s = 60s

    tracing::info!("Background sync loop started (domain: {})", domain);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Read current users
        let users = {
            let store = state.store.read().await;
            store.list()
        };

        // Update nginx backends map
        let changed = nginx_conf::write_backends_map(
            &users,
            &domain,
            &state.config.nginx_map_path,
        );
        if changed {
            nginx_conf::reload_nginx(&state.config.ingress_container_name);
        }

        // Periodically sync DNS records
        dns_tick += 1;
        if dns_tick >= DNS_SYNC_INTERVAL {
            dns_tick = 0;
            if let (Some(ref dns), Some(ref app_id)) = (&state.dns, &state.config.dstack_app_id) {
                let user_ids: Vec<String> = users.iter().map(|u| u.user_id.clone()).collect();
                if let Err(e) = dns.sync_all_records(&user_ids, &domain, app_id, 443).await {
                    tracing::warn!("DNS sync failed: {}", e);
                }
            }
        }
    }
}
