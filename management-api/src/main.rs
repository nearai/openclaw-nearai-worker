use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod docker;
mod error;
mod store;

use docker::DockerManager;
use error::ApiError;
use store::{User, UserStore};

const ADMIN_TOKEN_HEX_LEN: usize = 32;

#[derive(Clone)]
struct AppState {
    docker: Arc<DockerManager>,
    store: Arc<RwLock<UserStore>>,
    config: AppConfig,
}

#[derive(Clone)]
struct AppConfig {
    admin_token: String,
    host_address: String,
    openclaw_domain: Option<String>,  // Used for generating HTTPS URLs
    openclaw_image: String,
    network_name: String,
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
            .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization header format. Expected: Bearer <token>".into()))?;

        if token != state.config.admin_token {
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

    // Load and validate admin token
    let admin_token = std::env::var("ADMIN_TOKEN")
        .expect("ADMIN_TOKEN must be set");
    validate_admin_token(&admin_token)?;
    
    // Load configuration from environment
    let config = AppConfig {
        admin_token,
        host_address: std::env::var("OPENCLAW_HOST_ADDRESS")
            .unwrap_or_else(|_| "localhost".to_string()),
        openclaw_domain: std::env::var("OPENCLAW_DOMAIN").ok(),
        openclaw_image: std::env::var("OPENCLAW_IMAGE")
            .unwrap_or_else(|_| "openclaw-nearai-worker:local".to_string()),
        network_name: std::env::var("OPENCLAW_NETWORK")
            .unwrap_or_else(|_| "openclaw-network".to_string()),
    };

    // Initialize Docker manager
    let docker = Arc::new(DockerManager::new().await?);
    
    // Ensure network exists
    docker.ensure_network(&config.network_name).await?;

    // Load or create user store
    let store = Arc::new(RwLock::new(UserStore::load_or_create("data/users.json")?));

    if let Some(ref domain) = config.openclaw_domain {
        tracing::info!("OPENCLAW_DOMAIN set: user URLs will use https://{{user}}.{}", domain);
    }

    let state = AppState {
        docker,
        store,
        config,
    };

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
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

    // Create the container
    let container_name = format!("openclaw-{}", user_id);
    
    state.docker.create_openclaw_container(
        &container_name,
        &state.config.openclaw_image,
        &req.nearai_api_key,
        &token,
        gateway_port,
        ssh_port,
        req.ssh_pubkey.as_deref(),
        &state.config.network_name,
    ).await?;

    // Start the container
    state.docker.start_container(&container_name).await?;

    // Store user info (note: API key stored for potential container recreation)
    let user = User {
        user_id: user_id.clone(),
        token: token.clone(),
        gateway_port,
        ssh_port,
        container_name: container_name.clone(),
        created_at: chrono::Utc::now(),
        ssh_pubkey: req.ssh_pubkey.clone(),
        nearai_api_key: req.nearai_api_key.clone(),
    };

    {
        let mut store = state.store.write().await;
        store.add(user)?;
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
            let status = state.docker.get_container_status(&user.container_name).await?;
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
        let status = state.docker.get_container_status(&user.container_name).await
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
        Some(user) => {
            // Stop and remove container
            state.docker.stop_container(&user.container_name).await.ok();
            state.docker.remove_container(&user.container_name).await?;

            // Remove from store
            {
                let mut store = state.store.write().await;
                store.remove(&user_id)?;
            }

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
        Some(user) => {
            state.docker.restart_container(&user.container_name).await?;
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
        Some(user) => {
            state.docker.stop_container(&user.container_name).await?;
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
        Some(user) => {
            state.docker.start_container(&user.container_name).await?;
            tracing::info!("Started user container: {}", user_id);
            Ok(Json(serde_json::json!({"status": "started"})))
        }
        None => Err(ApiError::NotFound(format!("User {} not found", user_id))),
    }
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}
