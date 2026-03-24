use axum::{
    extract::{Form, FromRequestParts, Path, Query, RawForm, RawQuery, State},
    http::{request::Parts, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Redirect,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE;
#[cfg(test)]
use std::collections::HashMap;

mod backup;
mod compose;
mod error;
mod names;
mod nginx_conf;
mod store;

use backup::BackupManager;
use compose::{ComposeManager, DEFAULT_NEARAI_API_URL};
use error::ApiError;
use store::{Instance, InstanceStore, PortRange};

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
        restart_management_service,
        get_services_status,
        oauth_callback_router,
        oauth_exchange,
        oauth_refresh,
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
        RestartServiceResponse,
        ServiceStatus,
        ServicesStatusResponse,
        OAuthExchangeRequest,
        OAuthRefreshRequest,
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

/// Max workspace export size (512 MB). Protects against OOM during upgrades.
const MAX_EXPORT_BYTES: usize = 512 * 1024 * 1024;
const HOSTED_STATE_CHECKSUM_BYTES: usize = 12;

#[derive(Clone)]
struct AppState {
    compose: Arc<ComposeManager>,
    store: Arc<RwLock<InstanceStore>>,
    config: Arc<AppConfig>,
    backup: Option<Arc<BackupManager>>,
    /// Per-instance lock to prevent concurrent upgrades.
    upgrading: Arc<Mutex<HashSet<String>>>,
    /// URL exposed to ironclaw containers for them to proxy OAuth token exchanges through this service
    /// (e.g. "http://host.docker.internal:8080"). Always set when the service is running — generic
    /// OAuth providers send their own credentials, so this is not gated on Google creds.
    oauth_exchange_url: Option<String>,
    /// Shared HTTP client for outgoing requests (OAuth token exchange).
    http_client: reqwest::Client,
    #[cfg(test)]
    /// Test-only escape hatch for local mock token endpoints.
    allow_private_oauth_token_endpoints: bool,
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
    /// Google OAuth client ID (public). Passed to ironclaw containers for auth URL construction.
    google_oauth_client_id: Option<String>,
    /// Google OAuth client secret (confidential). Used by the exchange proxy, never enters containers.
    google_oauth_client_secret: Option<secrecy::SecretString>,
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
        extra_env: Option<std::collections::HashMap<String, String>>,
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
        let openclaw_domain = self.config.openclaw_domain.clone();
        let google_oauth_client_id = self.config.google_oauth_client_id.clone();
        let oauth_exchange_url = self.oauth_exchange_url.clone();
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
                openclaw_domain: openclaw_domain.as_deref(),
                google_oauth_client_id: google_oauth_client_id.as_deref(),
                oauth_exchange_url: oauth_exchange_url.as_deref(),
                extra_env: extra_env.as_ref(),
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

    async fn compose_start(&self, name: &str, force_recreate: bool, service_type: Option<&str>) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
        let service_type = service_type.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || compose.start(&name, force_recreate, service_type.as_deref()))
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

    async fn compose_all_health_statuses(
        &self,
    ) -> Result<std::collections::HashMap<String, compose::ContainerHealth>, ApiError> {
        let compose = self.compose.clone();
        tokio::task::spawn_blocking(move || compose.all_health_statuses())
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
        tar_bytes: Vec<u8>,
    ) -> Result<(), ApiError> {
        let compose = self.compose.clone();
        let name = name.to_string();
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

/// Constant-time token comparison that does not leak length via timing.
///
/// Hand-rolled XOR rather than `subtle::ConstantTimeEq` because `ct_eq` requires
/// equal-length slices, forcing a branch on length that leaks timing information.
/// This version iterates `max(len_a, len_b)` and pads with zeros, so the work done
/// is independent of which input is shorter.
fn constant_time_token_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = ab.len().max(bb.len());
    let mut diff: u8 = 0;
    for i in 0..max_len {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0 && ab.len() == bb.len()
}

/// Extractor that validates an instance gateway token from the Authorization header.
/// Returns the instance name if the token matches any known instance.
struct InstanceAuth {
    instance_name: String,
}

impl FromRequestParts<AppState> for InstanceAuth {
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

        // Scan all instances without early exit to avoid timing side-channels.
        // Always call constant_time_token_eq to keep per-iteration time constant.
        let store = state.store.read().await;
        let mut matched_name: Option<String> = None;
        for inst in store.all() {
            let is_match = constant_time_token_eq(token, &inst.token);
            if is_match && matched_name.is_none() {
                matched_name = Some(inst.name.clone());
            }
        }

        match matched_name {
            Some(name) => Ok(InstanceAuth {
                instance_name: name,
            }),
            None => Err(ApiError::Unauthorized("Invalid instance token".into())),
        }
    }
}

// ── OAuth token exchange proxy ───────────────────────────────────────

/// Google's token endpoint URL (used as fallback when no token_url is provided).
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

fn default_provider_google() -> String {
    "google".into()
}

fn normalize_optional_oauth_field(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
struct HostedOAuthStatePayload {
    #[serde(default)]
    instance_name: Option<String>,
}

#[derive(Deserialize)]
struct HostedOAuthStateWrapper {
    #[serde(default)]
    state: Option<String>,
}

fn hosted_state_checksum(payload_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(payload_bytes);
    URL_SAFE_NO_PAD.encode(&digest[..HOSTED_STATE_CHECKSUM_BYTES])
}

fn decode_urlsafe_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

type ParamsList = Vec<(String, String)>;

fn parse_urlencoded_pairs(input: &[u8]) -> Result<ParamsList, ApiError> {
    serde_urlencoded::from_bytes(input)
        .map_err(|_| ApiError::BadRequest("Invalid form or query encoding".into()))
}

fn extract_required_param(params: &mut ParamsList, key: &str) -> Result<String, ApiError> {
    extract_optional_param(params, key)?
        .ok_or_else(|| ApiError::BadRequest(format!("Missing required field: {}", key)))
}

fn extract_optional_param(params: &mut ParamsList, key: &str) -> Result<Option<String>, ApiError> {
    let matches = params
        .iter()
        .enumerate()
        .filter_map(|(index, (param_key, _))| (param_key == key).then_some(index))
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(params.remove(*index).1)),
        _ => Err(ApiError::BadRequest(format!(
            "Duplicate '{}' parameters are not allowed",
            key
        ))),
    }
}

/// Extract the instance name from an OAuth state parameter.
///
/// Supports two formats:
/// - **New (ic2):** `ic2.{base64_payload}.{checksum}` where payload is JSON containing `instance_name`
/// - **Legacy:** `instance:nonce` where instance is a DNS label before the first colon
fn extract_instance_from_state(state: &str) -> Result<String, ApiError> {
    // Try new ic2 format: ic2.{base64_payload}.{checksum}
    if let Some(rest) = state.strip_prefix("ic2.") {
        if let Some((payload_b64, checksum)) = rest.rsplit_once('.') {
            if let Ok(payload_bytes) = decode_urlsafe_base64(payload_b64) {
                let expected_checksum = hosted_state_checksum(&payload_bytes);
                if checksum != expected_checksum {
                    return Err(ApiError::BadRequest(
                        "Hosted OAuth state checksum mismatch".into(),
                    ));
                }
                if let Ok(payload) =
                    serde_json::from_slice::<HostedOAuthStatePayload>(&payload_bytes)
                {
                    if let Some(instance) = payload.instance_name.filter(|s| !s.is_empty()) {
                        return Ok(instance);
                    }
                }
            }
        }
    }

    // MCP install flows may wrap the actual hosted state in a base64url-encoded
    // JSON object that contains a nested `state` field. Unwrap and recurse.
    if let Ok(wrapper_bytes) = decode_urlsafe_base64(state) {
        if let Ok(wrapper) = serde_json::from_slice::<HostedOAuthStateWrapper>(&wrapper_bytes) {
            if let Some(nested_state) = wrapper.state.filter(|nested| !nested.is_empty()) {
                if nested_state != state {
                    return extract_instance_from_state(&nested_state);
                }
            }
        }
    }

    // Legacy: instance:nonce
    if let Some((instance, nonce)) = state.split_once(':') {
        if !instance.is_empty() && !nonce.is_empty() {
            return Ok(instance.to_string());
        }
    }

    Err(ApiError::BadRequest(
        "Could not extract instance name from state parameter".into(),
    ))
}

/// Route OAuth callbacks to the correct IronClaw instance.
///
/// OAuth providers redirect to `https://auth.DOMAIN/oauth/callback?code=...&state=...`.
/// This handler decodes the state parameter to extract the instance name, then
/// issues a 307 Temporary Redirect to
/// `https://{instance}.DOMAIN/oauth/callback?...` preserving all query parameters.
#[utoipa::path(
    get,
    path = "/oauth/callback",
    tag = "OAuth",
    security(),
    params(
        ("state" = String, Query, description = "OAuth state parameter containing instance routing info"),
        ("code" = Option<String>, Query, description = "Authorization code from the OAuth provider"),
    ),
    responses(
        (status = 307, description = "Temporary Redirect to the correct instance"),
        (status = 400, description = "Missing or invalid state parameter"),
        (status = 500, description = "Platform domain not configured"),
    )
)]
async fn oauth_callback_router(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> Result<impl IntoResponse, ApiError> {
    let raw_query = raw_query.unwrap_or_default();
    let mut query_pairs = parse_urlencoded_pairs(raw_query.as_bytes())?;
    let state_param = extract_required_param(&mut query_pairs, "state")?;
    if state_param.is_empty() {
        return Err(ApiError::BadRequest(
            "OAuth callback missing state parameter".into(),
        ));
    }

    let instance_name = extract_instance_from_state(&state_param)?;

    // Validate instance name using the same rules as instance creation
    // (alphanumeric + hyphens, no leading/trailing hyphens, max 32 chars).
    if !is_valid_instance_name(&instance_name) {
        return Err(ApiError::BadRequest(
            "Invalid instance name extracted from state parameter".into(),
        ));
    }

    let domain = state.config.openclaw_domain.as_deref().ok_or_else(|| {
        ApiError::Internal(
            "OPENCLAW_DOMAIN not configured; OAuth callback routing unavailable".into(),
        )
    })?;

    // Forward the raw query string as-is to preserve original encoding.
    // Omit the `?` when there is no query string to keep redirects canonical.
    let redirect_url = match (!raw_query.is_empty()).then_some(raw_query) {
        Some(qs) => format!("https://{}.{}/oauth/callback?{}", instance_name, domain, qs),
        None => format!("https://{}.{}/oauth/callback", instance_name, domain),
    };

    tracing::info!(
        instance = %instance_name,
        "OAuth callback routing to instance"
    );

    Ok(Redirect::temporary(&redirect_url))
}

/// Schema-only struct for OpenAPI documentation.
/// The actual handler uses `RawForm` so repeated provider-specific params
/// (e.g., RFC 8707 `resource`) are preserved and forwarded to the token endpoint.
#[derive(Deserialize, utoipa::ToSchema)]
#[allow(dead_code)]
struct OAuthExchangeRequest {
    /// Provider hint (e.g., "google"). Defaults to "google" for backward compatibility.
    #[serde(default = "default_provider_google")]
    provider: String,
    /// Authorization code from the OAuth provider.
    code: String,
    /// The redirect_uri used in the authorization request.
    redirect_uri: String,
    /// PKCE code verifier (optional).
    #[serde(default)]
    code_verifier: Option<String>,
    /// Provider's token endpoint URL. If not provided, falls back to built-in
    /// endpoint for known providers (currently only Google).
    #[serde(default)]
    token_url: Option<String>,
    /// OAuth client ID. If not provided, uses platform credentials for the provider.
    #[serde(default)]
    client_id: Option<String>,
    /// OAuth client secret. If not provided, uses platform credentials for the provider.
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
struct OAuthRefreshRequest {
    /// Provider hint (e.g., "google"). Defaults to "google" for backward compatibility.
    #[serde(default = "default_provider_google")]
    provider: String,
    /// The refresh token to exchange for a new access token.
    refresh_token: String,
    /// Provider's token endpoint URL. If not provided, falls back to built-in endpoint.
    #[serde(default)]
    token_url: Option<String>,
    /// OAuth client ID. If not provided, uses platform credentials for the provider.
    #[serde(default)]
    client_id: Option<String>,
    /// OAuth client secret. If not provided, uses platform credentials for the provider.
    #[serde(default)]
    client_secret: Option<String>,
}

/// Resolve the token endpoint URL from the request or built-in defaults.
fn resolve_token_endpoint(token_url: &Option<String>, provider: &str) -> Result<String, ApiError> {
    if let Some(url) = token_url {
        if !url.is_empty() {
            return Ok(url.clone());
        }
    }
    if provider == "google" {
        return Ok(GOOGLE_TOKEN_ENDPOINT.to_string());
    }
    Err(ApiError::BadRequest(format!(
        "No token_url provided and provider '{}' has no built-in endpoint",
        provider
    )))
}

fn oauth_exchange_allows_private_token_endpoints(state: &AppState) -> bool {
    #[cfg(test)]
    {
        state.allow_private_oauth_token_endpoints
    }
    #[cfg(not(test))]
    {
        let _ = state;
        false
    }
}

#[derive(Debug, Clone)]
struct ValidatedTokenEndpoint {
    url: String,
    resolved_addrs: Vec<SocketAddr>,
}

fn is_shared_ipv4_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_ipv6_site_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfec0
}

fn is_disallowed_oauth_endpoint_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || is_shared_ipv4_cgnat(ip)
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            // Catch IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) which the
            // kernel treats as their IPv4 equivalent but bypass the IPv6 checks above.
            if let Some(mapped_v4) = ip.to_ipv4_mapped() {
                return is_disallowed_oauth_endpoint_ip(IpAddr::V4(mapped_v4));
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || is_ipv6_site_local(ip)
                || ip.is_multicast()
        }
    }
}

async fn validate_token_endpoint_url(
    token_url: &str,
    allow_private: bool,
) -> Result<ValidatedTokenEndpoint, ApiError> {
    let parsed = reqwest::Url::parse(token_url)
        .map_err(|_| ApiError::BadRequest("token_url must be a valid URL".into()))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => {
            return Err(ApiError::BadRequest("token_url must use https".into()));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::BadRequest(
            "token_url must not include embedded credentials".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(ApiError::BadRequest(
            "token_url must not include a fragment".into(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("token_url must include a host".into()))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ApiError::BadRequest("token_url must include a known port".into()))?;

    if allow_private {
        return Ok(ValidatedTokenEndpoint {
            url: parsed.to_string(),
            resolved_addrs: Vec::new(),
        });
    }

    let mut resolved_any = false;
    let mut resolved_addrs = Vec::new();
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ApiError::BadRequest("token_url host could not be resolved".into()))?;
    for addr in resolved {
        resolved_any = true;
        resolved_addrs.push(addr);
        if is_disallowed_oauth_endpoint_ip(addr.ip()) {
            return Err(ApiError::BadRequest(
                "token_url must not resolve to non-public addresses".into(),
            ));
        }
    }
    if !resolved_any {
        return Err(ApiError::BadRequest(
            "token_url host did not resolve to any address".into(),
        ));
    }

    Ok(ValidatedTokenEndpoint {
        url: parsed.to_string(),
        resolved_addrs,
    })
}

fn build_token_http_client(
    state: &AppState,
    endpoint: &ValidatedTokenEndpoint,
) -> Result<reqwest::Client, ApiError> {
    if endpoint.resolved_addrs.is_empty() {
        return Ok(state.http_client.clone());
    }

    let host = reqwest::Url::parse(&endpoint.url)
        .map_err(|_| ApiError::Internal("Validated token endpoint URL became invalid".into()))?
        .host_str()
        .ok_or_else(|| ApiError::Internal("Validated token endpoint URL is missing a host".into()))?
        .to_string();

    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &endpoint.resolved_addrs)
        .build()
        .map_err(|e| ApiError::Internal(format!("Failed to build pinned HTTP client: {}", e)))
}

/// Resolve OAuth client credentials from the request or platform config.
///
/// When a `client_id` is provided without a `client_secret`, and it matches
/// the platform's Google OAuth client_id, the platform secret is injected.
/// This handles the case where IronClaw containers receive the web-app
/// `GOOGLE_OAUTH_CLIENT_ID` via env but deliberately omit the secret (which
/// stays on compose-api).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthCredentialSource {
    Request,
    Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedClientCredentials {
    client_id: String,
    client_secret: Option<String>,
    source: OAuthCredentialSource,
}

impl ResolvedClientCredentials {
    fn uses_platform_credentials(&self) -> bool {
        self.source == OAuthCredentialSource::Platform
    }
}

fn resolve_client_credentials(
    req_client_id: &Option<String>,
    req_client_secret: &Option<String>,
    config: &AppConfig,
) -> Result<ResolvedClientCredentials, ApiError> {
    match (req_client_id, req_client_secret) {
        // Request provides both client_id and client_secret — use them directly
        (Some(id), Some(secret)) if !id.is_empty() => Ok(ResolvedClientCredentials {
            client_id: id.clone(),
            client_secret: Some(secret.clone()),
            source: OAuthCredentialSource::Request,
        }),
        // Request provides client_id but no secret — check if it matches the
        // platform's Google client_id and inject the platform secret if so.
        (Some(id), None) if !id.is_empty() => {
            if config
                .google_oauth_client_id
                .as_deref()
                .is_some_and(|platform_id| platform_id == id)
            {
                use secrecy::ExposeSecret;
                let platform_secret = config
                    .google_oauth_client_secret
                    .as_ref()
                    .map(|s| s.expose_secret().to_string())
                    .ok_or_else(|| {
                        ApiError::BadRequest(
                            "Platform Google client_id selected but GOOGLE_OAUTH_CLIENT_SECRET is not configured"
                                .into(),
                        )
                    })?;

                Ok(ResolvedClientCredentials {
                    client_id: id.clone(),
                    client_secret: Some(platform_secret),
                    source: OAuthCredentialSource::Platform,
                })
            } else {
                Ok(ResolvedClientCredentials {
                    client_id: id.clone(),
                    client_secret: None,
                    source: OAuthCredentialSource::Request,
                })
            }
        }
        // No client creds in request — fall back to platform Google creds
        _ => {
            let id = config
                .google_oauth_client_id
                .as_deref()
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "No client_id provided and no platform credentials configured".into(),
                    )
                })?
                .to_string();
            use secrecy::ExposeSecret;
            let secret = config
                .google_oauth_client_secret
                .as_ref()
                .map(|s| s.expose_secret().to_string());
            Ok(ResolvedClientCredentials {
                client_id: id,
                client_secret: secret,
                source: OAuthCredentialSource::Platform,
            })
        }
    }
}

fn resolve_token_endpoint_for_credentials(
    token_url: &Option<String>,
    provider: &str,
    credentials: &ResolvedClientCredentials,
) -> Result<String, ApiError> {
    if credentials.uses_platform_credentials()
        && token_url
            .as_deref()
            .is_some_and(|token_url| token_url != GOOGLE_TOKEN_ENDPOINT)
    {
        return Err(ApiError::BadRequest(
            "token_url override is not allowed when using platform credentials".into(),
        ));
    }

    resolve_token_endpoint(token_url, provider)
}

/// Exchange an authorization code for tokens via the provider's token endpoint.
///
/// Supports two modes:
/// - **Platform credentials:** Container sends only `code` + `redirect_uri`; compose-api
///   adds Google client credentials from env vars. Used for Google OAuth extensions.
/// - **Request credentials:** Container sends `token_url`, `client_id`, and optionally
///   `client_secret`. Used for MCP OAuth and other generic providers.
#[utoipa::path(
    post,
    path = "/oauth/exchange",
    tag = "OAuth",
    security(("bearer_auth" = [])),
    request_body(content = OAuthExchangeRequest),
    responses(
        (status = 200, description = "Token exchange successful"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 502, description = "Provider error"),
    )
)]
async fn oauth_exchange(
    auth: InstanceAuth,
    State(state): State<AppState>,
    RawForm(form): RawForm,
) -> Result<impl IntoResponse, ApiError> {
    let mut form = parse_urlencoded_pairs(&form)?;

    // Extract known fields from the form data.
    // Any remaining fields (e.g., RFC 8707 `resource`) are forwarded to the token endpoint.
    let provider =
        extract_optional_param(&mut form, "provider")?.unwrap_or_else(default_provider_google);
    let code = extract_required_param(&mut form, "code")?;
    let redirect_uri = extract_required_param(&mut form, "redirect_uri")?;
    let code_verifier =
        normalize_optional_oauth_field(extract_optional_param(&mut form, "code_verifier")?);
    let token_url = normalize_optional_oauth_field(extract_optional_param(&mut form, "token_url")?);
    let req_client_id =
        normalize_optional_oauth_field(extract_optional_param(&mut form, "client_id")?);
    let req_client_secret =
        normalize_optional_oauth_field(extract_optional_param(&mut form, "client_secret")?);

    // Remove fields that are only meaningful to compose-api, not the token endpoint.
    let _ = extract_optional_param(&mut form, "access_token_field")?;

    let resolved_credentials =
        resolve_client_credentials(&req_client_id, &req_client_secret, &state.config)?;
    let token_endpoint =
        resolve_token_endpoint_for_credentials(&token_url, &provider, &resolved_credentials)?;
    let token_endpoint = validate_token_endpoint_url(
        &token_endpoint,
        oauth_exchange_allows_private_token_endpoints(&state),
    )
    .await?;
    let http_client = build_token_http_client(&state, &token_endpoint)?;

    // When using platform credentials, validate redirect_uri belongs to the platform domain.
    // This prevents a compromised container from exchanging codes destined for other instances.
    // When the container provides its own credentials (MCP/generic), skip this check —
    // the provider validates redirect_uri independently.
    if resolved_credentials.uses_platform_credentials() {
        match &state.config.openclaw_domain {
            Some(domain) => {
                let expected_prefix = format!("https://auth.{}/", domain);
                if !redirect_uri.starts_with(&expected_prefix) {
                    tracing::warn!(
                        instance = %auth.instance_name,
                        redirect_uri = %redirect_uri,
                        "OAuth exchange rejected: redirect_uri does not match platform domain"
                    );
                    return Err(ApiError::BadRequest(format!(
                        "redirect_uri must start with https://auth.{}/",
                        domain
                    )));
                }
            }
            None => {
                return Err(ApiError::Internal(
                    "OPENCLAW_DOMAIN not configured; OAuth exchange with platform credentials is unavailable".into(),
                ));
            }
        }
    }

    let mut params: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code),
        ("redirect_uri".into(), redirect_uri),
        ("client_id".into(), resolved_credentials.client_id),
    ];
    if let Some(secret) = resolved_credentials.client_secret {
        params.push(("client_secret".into(), secret));
    }
    if let Some(cv) = code_verifier {
        params.push(("code_verifier".into(), cv));
    }
    // Forward any remaining form fields (e.g., RFC 8707 `resource`) to the token endpoint.
    // Strip reserved OAuth keys that we set internally to prevent a malicious container
    // from overriding them (e.g., injecting a different `grant_type`).
    const RESERVED_OAUTH_KEYS: &[&str] = &[
        "grant_type",
        "code",
        "redirect_uri",
        "client_id",
        "client_secret",
        "code_verifier",
    ];
    for (key, value) in &form {
        if !RESERVED_OAUTH_KEYS.contains(&key.as_str()) {
            params.push((key.clone(), value.clone()));
        }
    }

    let response = http_client
        .post(&token_endpoint.url)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "Failed to contact token endpoint {}: {}",
                token_endpoint.url, e
            ))
        })?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to parse token response: {}", e)))?;

    if !status.is_success() {
        tracing::warn!(
            provider = %provider,
            status = %status,
            error = %body.get("error").and_then(|v| v.as_str()).unwrap_or("unknown"),
            description = %body.get("error_description").and_then(|v| v.as_str()).unwrap_or(""),
            "OAuth token exchange failed"
        );
        return Err(ApiError::BadGateway(format!(
            "Token exchange failed: {}",
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
        )));
    }

    Ok(Json(body))
}

/// Refresh an access token using a refresh token.
///
/// Supports the same two modes as `/oauth/exchange`:
/// - Platform credentials (Google) when no `token_url`/`client_id` provided
/// - Request credentials (generic/MCP) when `token_url` and `client_id` are in the request
#[utoipa::path(
    post,
    path = "/oauth/refresh",
    tag = "OAuth",
    security(("bearer_auth" = [])),
    request_body(content = OAuthRefreshRequest),
    responses(
        (status = 200, description = "Token refresh successful"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 502, description = "Provider error"),
    )
)]
async fn oauth_refresh(
    _auth: InstanceAuth,
    State(state): State<AppState>,
    Form(req): Form<OAuthRefreshRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token_url = normalize_optional_oauth_field(req.token_url.clone());
    let client_id = normalize_optional_oauth_field(req.client_id.clone());
    let client_secret = normalize_optional_oauth_field(req.client_secret.clone());
    let resolved_credentials =
        resolve_client_credentials(&client_id, &client_secret, &state.config)?;
    let token_endpoint =
        resolve_token_endpoint_for_credentials(&token_url, &req.provider, &resolved_credentials)?;
    let token_endpoint = validate_token_endpoint_url(
        &token_endpoint,
        oauth_exchange_allows_private_token_endpoints(&state),
    )
    .await?;
    let http_client = build_token_http_client(&state, &token_endpoint)?;

    let mut params: Vec<(&str, String)> = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", req.refresh_token.clone()),
        ("client_id", resolved_credentials.client_id),
    ];
    if let Some(ref secret) = resolved_credentials.client_secret {
        params.push(("client_secret", secret.clone()));
    }

    let response = http_client
        .post(&token_endpoint.url)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "Failed to contact token endpoint {}: {}",
                token_endpoint.url, e
            ))
        })?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to parse token response: {}", e)))?;

    if !status.is_success() {
        tracing::warn!(
            provider = %req.provider,
            status = %status,
            error = %body.get("error").and_then(|v| v.as_str()).unwrap_or("unknown"),
            description = %body.get("error_description").and_then(|v| v.as_str()).unwrap_or(""),
            "OAuth token refresh failed"
        );
        return Err(ApiError::BadGateway(format!(
            "Token refresh failed: {}",
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
        )));
    }

    Ok(Json(body))
}

/// Set up iptables DOCKER-USER chain rules to block container egress to RFC1918.
///
/// Uses source matching (-s 172.16.0.0/12) so only container-originated traffic
/// is blocked. Host-to-container DNAT traffic (source 127.0.0.1) is unaffected.
///
/// Controlled by CONTAINER_FIREWALL env var (default: "true").
/// Idempotent: checks existing rules before inserting.
/// Never panics or fails startup — logs warnings on errors.
fn setup_container_firewall() {
    let enabled = std::env::var("CONTAINER_FIREWALL").unwrap_or_else(|_| "true".to_string());

    if enabled.to_lowercase() != "true" {
        tracing::info!(
            "Container firewall disabled (CONTAINER_FIREWALL={})",
            enabled
        );
        return;
    }

    tracing::info!("Setting up container egress firewall (DOCKER-USER chain)");

    // Detect working iptables binary. Docker uses iptables-legacy for its chains,
    // but the default `iptables` in Debian bookworm is the nft variant which fails
    // inside containers with "Could not fetch rule set generation id: Invalid argument".
    let iptables = detect_iptables_binary();
    let Some(iptables) = iptables else {
        tracing::warn!(
            "Firewall: no working iptables binary found. Container egress is unrestricted."
        );
        return;
    };
    tracing::info!("Firewall: using {}", iptables);

    // Source = Docker bridge subnet (container-originated traffic only).
    // This preserves host-to-container DNAT traffic (nginx, bastion) which has src=127.0.0.1.
    let source = "172.16.0.0/12";

    // Block container access to non-Docker RFC1918 ranges.
    // We intentionally do NOT block 172.16.0.0/12 as destination because
    // containers need to reach each other on the Docker bridge.
    let dest_cidrs = ["10.0.0.0/8", "192.168.0.0/16"];

    for dest in &dest_cidrs {
        // Check if REJECT rule already exists (idempotent)
        let reject_exists = std::process::Command::new(iptables)
            .args([
                "-C",
                "DOCKER-USER",
                "-s",
                source,
                "-d",
                dest,
                "-j",
                "REJECT",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if reject_exists {
            tracing::info!(
                "Firewall: REJECT rule for {} -> {} already exists, skipping",
                source,
                dest
            );
            continue;
        }

        // Check if DROP rule already exists (from a previous fallback)
        let drop_exists = std::process::Command::new(iptables)
            .args(["-C", "DOCKER-USER", "-s", source, "-d", dest, "-j", "DROP"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if drop_exists {
            tracing::info!(
                "Firewall: DROP rule for {} -> {} already exists, skipping",
                source,
                dest
            );
            continue;
        }

        // Try REJECT first (preferred: causes immediate socket close via ICMP unreachable).
        // Fall back to DROP if REJECT not supported.
        let result = std::process::Command::new(iptables)
            .args([
                "-I",
                "DOCKER-USER",
                "1",
                "-s",
                source,
                "-d",
                dest,
                "-j",
                "REJECT",
            ])
            .output();

        match result {
            Ok(o) if o.status.success() => {
                tracing::info!("Firewall: added REJECT rule for {} -> {}", source, dest);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                tracing::warn!(
                    "Firewall: REJECT failed for {} -> {} ({}), trying DROP",
                    source,
                    dest,
                    stderr.trim()
                );
                let drop_result = std::process::Command::new(iptables)
                    .args([
                        "-I",
                        "DOCKER-USER",
                        "1",
                        "-s",
                        source,
                        "-d",
                        dest,
                        "-j",
                        "DROP",
                    ])
                    .output();
                match drop_result {
                    Ok(o2) if o2.status.success() => {
                        tracing::info!(
                            "Firewall: added DROP rule for {} -> {} (fallback)",
                            source,
                            dest
                        );
                    }
                    Ok(o2) => {
                        tracing::warn!(
                            "Firewall: DROP also failed for {} -> {}: {}",
                            source,
                            dest,
                            String::from_utf8_lossy(&o2.stderr).trim()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Firewall: iptables exec failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Firewall: {} not available ({}). Container egress is unrestricted.",
                    iptables,
                    e
                );
                return;
            }
        }
    }

    // Log final state for Datadog visibility
    if let Ok(o) = std::process::Command::new(iptables)
        .args(["-L", "DOCKER-USER", "-n", "-v"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&o.stdout);
        tracing::info!("Firewall: DOCKER-USER chain:\n{}", stdout);
    }
}

/// Detect a working iptables binary by trying to list the DOCKER-USER chain.
/// Prefers iptables-legacy (what Docker uses) over iptables (nft variant).
fn detect_iptables_binary() -> Option<&'static str> {
    for bin in &["iptables-legacy", "iptables"] {
        if let Ok(o) = std::process::Command::new(bin)
            .args(["-L", "DOCKER-USER", "-n"])
            .output()
        {
            if o.status.success() {
                return Some(bin);
            }
            tracing::debug!(
                "Firewall: {} failed: {}",
                bin,
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }
    None
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

    setup_container_firewall();

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
        google_oauth_client_id: std::env::var("GOOGLE_OAUTH_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty()),
        google_oauth_client_secret: std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(secrecy::SecretString::from),
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

    // Compute the internal OAuth exchange proxy URL for containers.
    // Containers call this URL instead of providers directly, keeping client_secrets on the platform.
    // Uses host.docker.internal because ironclaw containers run on a Docker bridge network
    // and can't reach the host's 127.0.0.1. The compose template adds extra_hosts for this.
    // Always available — generic OAuth providers send their own credentials in the exchange request.
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listen_port = match listen_addr.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr.port().to_string(),
        Err(_) => listen_addr
            .split(':')
            .next_back()
            .unwrap_or("8080")
            .to_string(),
    };
    let oauth_exchange_url: Option<String> =
        Some(format!("http://host.docker.internal:{}", listen_port));

    let port_range = PortRange::from_env();
    let mut instance_store = InstanceStore::new(port_range);
    match compose.discover_instances() {
        Ok(discovered) => {
            if !discovered.is_empty() {
                tracing::info!("discovered {} instances from Docker", discovered.len());
                for inst in &discovered {
                    if let Err(e) = compose.ensure_env_file(
                        inst,
                        config.openclaw_domain.as_deref(),
                        config.google_oauth_client_id.as_deref(),
                        oauth_exchange_url.as_deref(),
                    ) {
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
        upgrading: Arc::new(Mutex::new(HashSet::new())),
        oauth_exchange_url: oauth_exchange_url.clone(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            // Disable redirect following to prevent SSRF: a malicious token_url
            // could pass IP validation but 30x-redirect to a private/loopback
            // address. Token endpoints should not redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client"),
        #[cfg(test)]
        allow_private_oauth_token_endpoints: false,
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
        .route("/config/{key}", delete(delete_config_key))
        .route(
            "/admin/restart-service/{service}",
            post(restart_management_service),
        )
        .route("/admin/services", get(get_services_status))
        .route("/admin/debug/health", get(debug_health))
        .route("/admin/debug/active", get(debug_active))
        .route("/admin/debug/backends", get(debug_backends))
        .route("/admin/debug/reactivate", post(debug_reactivate));

    // OAuth routes: callback router is public (no auth), exchange/refresh require instance auth.
    // Always registered — generic providers send their own credentials in the request.
    app = app
        .route("/oauth/callback", get(oauth_callback_router))
        .route("/oauth/exchange", post(oauth_exchange))
        .route("/oauth/refresh", post(oauth_refresh));

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
    /// Additional environment variables to inject into the container.
    #[serde(default)]
    extra_env: Option<std::collections::HashMap<String, String>>,
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
    health_ok: Option<Arc<AtomicBool>>,
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
                        state.compose_start(name, false, service_type).await
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
                if let Some(ref flag) = health_ok {
                    flag.store(true, Ordering::Release);
                }
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
        extra_env: req.extra_env.clone(),
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
    let extra_env = req.extra_env.clone();

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
            extra_env,
        ).await {
            // Remove from store — container never started, instance is not functional
            {
                let mut store = state.store.write().await;
                store.remove(&name);
            }
            yield Ok(sse_error(&format!("Failed to start container: {}", e)));
            return;
        }

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
        let health_ok = Arc::new(AtomicBool::new(false));
        let poll_state = state.clone();
        let poll_name = name.clone();
        let poll_service_type = service_type.clone();
        let poll_health_ok = health_ok.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, Some(&poll_service_type), &tx, Some(poll_health_ok)).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }

        // Only add to nginx routing after health check passes — avoids 502s
        // during the startup window before the gateway is ready.
        if health_ok.load(Ordering::Acquire) {
            yield Ok(sse_stage("configuring_routing", "Updating nginx routing table..."));
            update_nginx_now(&state).await;
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

    // Reject delete while an upgrade is in progress.
    {
        let upgrading = state.upgrading.lock().await;
        if upgrading.contains(&name) {
            return Err(ApiError::Conflict(format!(
                "Instance '{}' is currently being upgraded",
                name
            )));
        }
    }

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

    // Reject concurrent upgrades on the same instance.
    if new_image.is_some() {
        let mut upgrading = state.upgrading.lock().await;
        if !upgrading.insert(name.clone()) {
            return Err(ApiError::Conflict(format!(
                "Instance '{}' is already being upgraded",
                name
            )));
        }
    }

    // Run the entire upgrade/restart flow in a background task so it completes
    // even if the SSE client disconnects mid-flight (e.g. after compose_down).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);

    {
        let state = state.clone();
        let name = name.clone();
        let inst = inst.clone();
        let new_image = new_image.clone();

        tokio::spawn(async move {
            if let Some(ref image) = new_image {
                // Full upgrade: export workspace → down -v → up with new image → restore workspace

                // Infer service types from the existing container image (if any) and from the
                // requested new image. This gives us a source-of-truth independent of the
                // stored Instance.service_type field, which may be stale.
                let inferred_old = inst
                    .image
                    .as_deref()
                    .map(|img| state.compose.infer_service_type_from_image(Some(img)));
                let inferred_new = state
                    .compose
                    .infer_service_type_from_image(Some(image.as_str()));

                // Safety check: if we can infer a type from the existing image and it disagrees
                // with the type inferred from the new image, abort the upgrade rather than
                // risk migrating an openclaw workspace into an ironclaw template (or vice versa).
                if let Some(old_ty) = inferred_old {
                    if old_ty != inferred_new {
                        let _ = tx
                            .send(sse_error(&format!(
                                "Instance '{}' image types do not match: old '{}' vs new '{}'; refusing to upgrade.",
                                name, old_ty, inferred_new
                            )))
                            .await;
                        state.upgrading.lock().await.remove(&name);
                        return;
                    }
                }

                let inferred = inferred_new;

                // Reconcile the stored service_type with what we infer from images:
                // - If they agree, use the stored value.
                // - If they disagree, prefer the image-based inference but log a warning, since
                //   the stored value is likely stale.
                // - If service_type is entirely missing, keep the legacy behavior and refuse to
                //   upgrade, because we can't be confident which compose file is correct.
                let stype = match inst.service_type.as_deref() {
                    Some(st) if st == inferred => st,
                    Some(st) => {
                        tracing::warn!(
                            "Instance '{}': stored service_type '{}' differs from inferred '{}'; using inferred value",
                            name,
                            st,
                            inferred
                        );
                        inferred
                    }
                    None => {
                        let _ = tx
                            .send(sse_error(&format!(
                                "Instance '{}' has no service_type set; refusing to upgrade \
                             (would use wrong compose file and lose data)",
                                name
                            )))
                            .await;
                        state.upgrading.lock().await.remove(&name);
                        return;
                    }
                };

                let _ = tx
                    .send(sse_stage("exporting", "Exporting workspace and config..."))
                    .await;

                let tar_bytes = match state.compose_export_instance_data(&name, Some(stype)).await {
                    Ok(bytes) => {
                        if bytes.len() > MAX_EXPORT_BYTES {
                            let _ = tx
                                .send(sse_error(&format!(
                                    "Workspace export too large ({} MB, limit {} MB). \
                                 Clean up large files before upgrading.",
                                    bytes.len() / (1024 * 1024),
                                    MAX_EXPORT_BYTES / (1024 * 1024),
                                )))
                                .await;
                            state.upgrading.lock().await.remove(&name);
                            return;
                        }
                        bytes
                    }
                    Err(e) => {
                        let _ = tx
                            .send(sse_error(&format!("Failed to export workspace: {}", e)))
                            .await;
                        state.upgrading.lock().await.remove(&name);
                        return;
                    }
                };

                let _ = tx
                    .send(sse_stage(
                        "stopping",
                        "Stopping and removing old container...",
                    ))
                    .await;

                if let Err(e) = state.compose_down(&name, Some(stype)).await {
                    let _ = tx
                        .send(sse_error(&format!("Failed to stop old container: {}", e)))
                        .await;
                    state.upgrading.lock().await.remove(&name);
                    return;
                }

                let _ = tx
                    .send(sse_stage(
                        "container_starting",
                        &format!("Starting new container with image {}...", image),
                    ))
                    .await;

                let old_image = inst.image.as_deref().unwrap_or(image);
                if let Err(e) = state
                    .compose_up(
                        &name,
                        &inst.nearai_api_key,
                        &inst.token,
                        inst.gateway_port,
                        inst.ssh_port,
                        &inst.ssh_pubkey,
                        image,
                        inst.nearai_api_url
                            .as_deref()
                            .unwrap_or(DEFAULT_NEARAI_API_URL),
                        stype,
                        inst.mem_limit.clone(),
                        inst.cpus.clone(),
                        inst.storage_size.clone(),
                        inst.extra_env.clone(),
                    )
                    .await
                {
                    // Attempt rollback with the original image
                    let _ = tx
                        .send(sse_stage(
                            "rolling_back",
                            &format!(
                                "Failed to start with new image ({}), rolling back to {}...",
                                e, old_image
                            ),
                        ))
                        .await;
                    if let Err(rb_err) = state
                        .compose_up(
                            &name,
                            &inst.nearai_api_key,
                            &inst.token,
                            inst.gateway_port,
                            inst.ssh_port,
                            &inst.ssh_pubkey,
                            old_image,
                            inst.nearai_api_url
                                .as_deref()
                                .unwrap_or(DEFAULT_NEARAI_API_URL),
                            stype,
                            inst.mem_limit.clone(),
                            inst.cpus.clone(),
                            inst.storage_size.clone(),
                            inst.extra_env.clone(),
                        )
                        .await
                    {
                        let mut store = state.store.write().await;
                        let _ = store.set_active(&name, false);
                        drop(store);
                        update_nginx_now(&state).await;
                        let _ = tx
                            .send(sse_error(&format!(
                                "Rollback also failed ({}). Instance needs manual recreation.",
                                rb_err
                            )))
                            .await;
                        state.upgrading.lock().await.remove(&name);
                        return;
                    }
                    // Rollback succeeded — restore workspace into the old container
                    if !tar_bytes.is_empty() {
                        let _ = state.compose_import_instance_data(&name, tar_bytes).await;
                    }
                    let _ = tx
                        .send(sse_error(&format!(
                            "Upgrade failed, rolled back to previous image: {}",
                            e
                        )))
                        .await;
                    state.upgrading.lock().await.remove(&name);
                    // Still run health polling for the rolled-back container
                    poll_health_to_ready(&state, &name, Some(stype), &tx, None).await;
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
                    let _ = tx
                        .send(sse_stage(
                            "image_resolved",
                            &format!("Image digest: {}", digest),
                        ))
                        .await;
                }

                if !tar_bytes.is_empty() {
                    let _ = tx
                        .send(sse_stage("restoring", "Restoring workspace and config..."))
                        .await;

                    if let Err(e) = state.compose_import_instance_data(&name, tar_bytes).await {
                        let _ = tx.send(sse_error(&format!(
                            "Failed to restore workspace, the instance may be missing user data: {}", e
                        ))).await;
                    }
                }

                state.upgrading.lock().await.remove(&name);
            } else {
                // Simple restart
                let _ = tx
                    .send(sse_stage("container_starting", "Restarting container..."))
                    .await;

                if let Err(e) = state
                    .compose_restart(&name, inst.service_type.as_deref())
                    .await
                {
                    let _ = tx
                        .send(sse_error(&format!("Failed to restart container: {}", e)))
                        .await;
                    return;
                }

                // Mark active and update nginx routing (instance may have been
                // discovered as inactive on startup or previously stopped).
                {
                    let mut store = state.store.write().await;
                    if let Err(e) = store.set_active(&name, true) {
                        tracing::warn!("Failed to mark instance active after restart: {}", e);
                    }
                }
                update_nginx_now(&state).await;
            }

            // Health polling always runs, even after a partial restore failure
            poll_health_to_ready(&state, &name, inst.service_type.as_deref(), &tx, None).await;
        });
    }

    let stream = async_stream::stream! {
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

        if let Err(e) = state.compose_start(&name, false, inst.service_type.as_deref()).await {
            yield Ok(sse_error(&format!("Failed to start container: {}", e)));
            return;
        }

        tracing::info!("Started instance: {}", name);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(16);
        let health_ok = Arc::new(AtomicBool::new(false));
        let poll_state = state.clone();
        let poll_name = name.clone();
        let poll_service_type = inst.service_type.clone();
        let poll_health_ok = health_ok.clone();
        tokio::spawn(async move {
            poll_health_to_ready(&poll_state, &poll_name, poll_service_type.as_deref(), &tx, Some(poll_health_ok)).await;
        });

        while let Some(event) = rx.recv().await {
            yield Ok(event);
        }

        // Only restore routing after health check passes
        if health_ok.load(Ordering::Acquire) {
            {
                let mut store = state.store.write().await;
                if let Err(e) = store.set_active(&name, true) {
                    tracing::warn!("Failed to mark instance active: {}", e);
                }
            }
            yield Ok(sse_stage("configuring_routing", "Restoring routing..."));
            update_nginx_now(&state).await;
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

// ── Admin: management service restart ────────────────────────────────

/// Management service names (Docker Compose service labels) used by both the
/// admin restart endpoint and the background service monitor.
const MANAGEMENT_SERVICES: &[&str] = &["openclaw-updater", "nginx", "ssh-bastion", "datadog-agent"];

#[derive(Serialize, utoipa::ToSchema)]
struct RestartServiceResponse {
    /// Service that was restarted
    service: String,
    /// Container ID that was restarted
    container_id: String,
    /// Result status
    status: String,
}

#[utoipa::path(post, path = "/admin/restart-service/{service}", tag = "Admin",
    params(("service" = String, Path, description = "Management service name to restart or start (openclaw-updater, nginx, ssh-bastion, datadog-agent). Restarts running containers; starts stopped/exited containers.")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Service restarted or started successfully", body = RestartServiceResponse),
        (status = 400, description = "Service name not in allowlist", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Container not found for service", body = ErrorResponse),
        (status = 500, description = "Docker restart/start failed", body = ErrorResponse),
    )
)]
async fn restart_management_service(
    _auth: AdminAuth,
    Path(service): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if !MANAGEMENT_SERVICES.contains(&service.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Service '{}' not in allowlist. Allowed: {}",
            service,
            MANAGEMENT_SERVICES.join(", ")
        )));
    }

    let service_clone = service.clone();
    let (container_id, action) = tokio::task::spawn_blocking(move || {
        let filter = format!("label=com.docker.compose.service={}", service_clone);

        // First, look for a running container
        let find_running = std::process::Command::new("docker")
            .args(["ps", "-q", "--filter", &filter])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker ps: {}", e)))?;

        let running_id = String::from_utf8_lossy(&find_running.stdout)
            .trim()
            .to_string();

        if !running_id.is_empty() {
            // Running container found — validate single match, then restart
            let mut lines = running_id.lines();
            let container_id = lines.next().unwrap().to_string();
            if lines.next().is_some() {
                return Err(ApiError::BadRequest(format!(
                    "Multiple containers found for service '{}'. Restarting multi-replica services is not supported.",
                    service_clone
                )));
            }

            let restart = std::process::Command::new("docker")
                .args(["restart", &container_id])
                .output()
                .map_err(|e| {
                    ApiError::Internal(format!("Failed to run docker restart: {}", e))
                })?;

            if !restart.status.success() {
                let stderr = String::from_utf8_lossy(&restart.stderr);
                return Err(ApiError::Internal(format!(
                    "docker restart failed: {}",
                    stderr
                )));
            }

            return Ok((container_id, "restarted"));
        }

        // No running container — look for stopped/exited containers
        let find_all = std::process::Command::new("docker")
            .args(["ps", "-a", "-q", "--filter", &filter])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker ps -a: {}", e)))?;

        let all_id = String::from_utf8_lossy(&find_all.stdout)
            .trim()
            .to_string();

        if all_id.is_empty() {
            return Err(ApiError::NotFound(format!(
                "No container found for service '{}'",
                service_clone
            )));
        }

        // Validate single match
        let mut lines = all_id.lines();
        let container_id = lines.next().unwrap().to_string();
        if lines.next().is_some() {
            return Err(ApiError::BadRequest(format!(
                "Multiple containers found for service '{}'. Starting multi-replica services is not supported.",
                service_clone
            )));
        }

        let start = std::process::Command::new("docker")
            .args(["start", &container_id])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker start: {}", e)))?;

        if !start.status.success() {
            let stderr = String::from_utf8_lossy(&start.stderr);
            return Err(ApiError::Internal(format!(
                "docker start failed: {}",
                stderr
            )));
        }

        Ok((container_id, "started"))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task join: {e}")))
    .and_then(|r| r)?;

    tracing::info!(
        "Management service '{}' {} (container={})",
        service,
        action,
        container_id
    );

    Ok(Json(RestartServiceResponse {
        service,
        container_id,
        status: action.to_string(),
    }))
}

// ── Admin: management services status ───────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct ServiceStatus {
    /// Service name
    service: String,
    /// Docker container ID (empty if not found)
    container_id: Option<String>,
    /// Container state: "running", "exited", "restarting", "paused", "not_found", etc.
    state: String,
    /// Docker's full status string, e.g. "Up 2 days" or "Exited (1) 3 hours ago"
    status: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct ServicesStatusResponse {
    services: Vec<ServiceStatus>,
}

#[utoipa::path(get, path = "/admin/services", tag = "Admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Status of all management services", body = ServicesStatusResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Docker command failed", body = ErrorResponse),
    )
)]
async fn get_services_status(_auth: AdminAuth) -> Result<impl IntoResponse, ApiError> {
    let services = tokio::task::spawn_blocking(|| {
        let mut results = Vec::with_capacity(MANAGEMENT_SERVICES.len());

        for &svc in MANAGEMENT_SERVICES {
            let output = std::process::Command::new("docker")
                .args([
                    "ps",
                    "-a",
                    "--format",
                    "{{.ID}} {{.State}} {{.Status}}",
                    "--filter",
                    &format!("label=com.docker.compose.service={}", svc),
                ])
                .output()
                .map_err(|e| ApiError::Internal(format!("Failed to run docker ps: {}", e)))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let line = stdout.trim();

            if line.is_empty() {
                results.push(ServiceStatus {
                    service: svc.to_string(),
                    container_id: None,
                    state: "not_found".to_string(),
                    status: String::new(),
                });
            } else {
                // Format: "<ID> <State> <Status...>"
                // Status may contain spaces, so split into at most 3 parts.
                // If multiple containers match, take only the first line.
                let first_line = line.lines().next().unwrap_or("");
                let mut parts = first_line.splitn(3, ' ');
                let id_str = parts.next().unwrap_or("").to_string();
                let state = parts.next().unwrap_or("unknown").to_string();
                let status = parts.next().unwrap_or("").to_string();

                results.push(ServiceStatus {
                    service: svc.to_string(),
                    container_id: if id_str.is_empty() {
                        None
                    } else {
                        Some(id_str)
                    },
                    state,
                    status,
                });
            }
        }

        Ok::<_, ApiError>(results)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task join: {e}")))??;

    Ok(Json(ServicesStatusResponse { services }))
}

// ── Debug endpoints ──────────────────────────────────────────────────

/// Docker health status for all managed containers (what background sync sees).
async fn debug_health(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let health_map = state.compose_all_health_statuses().await?;
    // Count by (state, health) combination
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for h in health_map.values() {
        let key = format!("{}:{}", h.state, h.health);
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut entries: Vec<serde_json::Value> = health_map
        .iter()
        .map(|(name, h)| {
            serde_json::json!({
                "name": name,
                "state": h.state,
                "health": h.health,
            })
        })
        .collect();
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(serde_json::json!({
        "total": health_map.len(),
        "counts": counts,
        "instances": entries,
    })))
}

/// Internal active state for all instances (active = routed via nginx).
async fn debug_active(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let instances = {
        let store = state.store.read().await;
        store.list()
    };
    let active_count = instances.iter().filter(|i| i.active).count();
    let inactive_count = instances.len() - active_count;
    let mut entries: Vec<serde_json::Value> = instances
        .iter()
        .map(|i| {
            serde_json::json!({
                "name": i.name,
                "active": i.active,
            })
        })
        .collect();
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(serde_json::json!({
        "total": instances.len(),
        "active": active_count,
        "inactive": inactive_count,
        "instances": entries,
    })))
}

/// Current nginx backends.map content.
async fn debug_backends(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let path = state.config.nginx_map_path.clone();
    let (content, entries, error) = match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let count = content.lines().filter(|l| !l.trim().is_empty()).count();
            (content, count, None::<String>)
        }
        Err(e) => (String::new(), 0, Some(e.to_string())),
    };
    Ok(Json(serde_json::json!({
        "path": path,
        "entries": entries,
        "content": content,
        "error": error,
    })))
}

/// Force re-evaluate all instances: run background sync logic immediately.
async fn debug_reactivate(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let health_map = state.compose_all_health_statuses().await?;
    let mut activated = Vec::new();
    let mut deactivated = Vec::new();
    {
        let mut store = state.store.write().await;
        for inst in store.list() {
            let should_be_active = health_map
                .get(&inst.name)
                .map(|h| h.state == "running" && h.health == "healthy")
                .unwrap_or(false);
            if inst.active != should_be_active {
                if let Err(e) = store.set_active(&inst.name, should_be_active) {
                    tracing::warn!(
                        "debug_reactivate: failed to set active for '{}': {}",
                        inst.name, e
                    );
                }
                if should_be_active {
                    activated.push(inst.name.clone());
                } else {
                    deactivated.push(inst.name.clone());
                }
            }
        }
    }
    // Update nginx
    update_nginx_now(&state).await;
    Ok(Json(serde_json::json!({
        "activated": activated.len(),
        "deactivated": deactivated.len(),
        "activated_names": activated,
        "deactivated_names": deactivated,
    })))
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
            google_oauth_client_id: None,
            google_oauth_client_secret: None,
        }
    }
}

/// Check management services and start any that are not running.
/// Uses `docker ps -a` with service label filter to find containers in any state,
/// then `docker start` for non-running ones (preserving the original container).
fn check_and_restart_services() {
    for &service in MANAGEMENT_SERVICES {
        // Find container by compose service label (including stopped containers with -a)
        let find = match std::process::Command::new("docker")
            .args([
                "ps",
                "-a",
                "--format",
                "{{.ID}} {{.State}}",
                "--filter",
                &format!("label=com.docker.compose.service={}", service),
            ])
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                tracing::warn!(
                    "service_monitor: failed to run docker ps for {}: {}",
                    service,
                    e
                );
                continue;
            }
        };

        if !find.status.success() {
            let stderr = String::from_utf8_lossy(&find.stderr);
            tracing::warn!(
                "service_monitor: docker ps failed for '{}': {}",
                service,
                stderr.trim()
            );
            continue;
        }

        let stdout = String::from_utf8_lossy(&find.stdout);
        let trimmed = stdout.trim();

        if trimmed.is_empty() {
            continue;
        }

        let mut lines = trimmed.lines();
        let first_line = match lines.next() {
            Some(l) => l,
            None => continue,
        };

        if lines.next().is_some() {
            tracing::error!(
                "service_monitor: multiple containers found for service '{}', skipping",
                service
            );
            continue;
        }

        let mut parts = first_line.split_whitespace();
        let container_id = match parts.next() {
            Some(id) => id,
            None => continue,
        };
        let container_state = parts.next().unwrap_or("");

        if container_state == "running" {
            continue;
        }

        tracing::warn!(
            "service_monitor: service '{}' is {} (container={}), attempting docker start",
            service,
            container_state,
            container_id
        );

        match std::process::Command::new("docker")
            .args(["start", container_id])
            .output()
        {
            Ok(result) if result.status.success() => {
                tracing::info!(
                    "service_monitor: successfully started '{}' (container={})",
                    service,
                    container_id
                );
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                tracing::error!(
                    "service_monitor: docker start failed for '{}' (container={}): {}",
                    service,
                    container_id,
                    stderr.trim()
                );
            }
            Err(e) => {
                tracing::error!(
                    "service_monitor: failed to run docker start for '{}': {}",
                    service,
                    e
                );
            }
        }
    }
}

/// Check disk space on key mount points and log warnings/errors.
fn check_disk_space() {
    const MOUNTS_TO_CHECK: &[&str] = &["/", "/var/lib/docker"];
    const CRITICAL_THRESHOLD_PCT: u32 = 95;
    const WARNING_THRESHOLD_PCT: u32 = 85;

    for mount in MOUNTS_TO_CHECK {
        let output = match std::process::Command::new("df")
            .args(["-P", mount])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!("disk_monitor: failed to run df for {}: {}", mount, e);
                continue;
            }
        };
        if !output.status.success() {
            // /var/lib/docker may not be a separate mount — silently skip
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        // df -P output: header line, then one data line per filesystem
        // Fields: Filesystem, 1024-blocks, Used, Available, Capacity, Mounted-on
        // Capacity field looks like "42%"
        if let Some(line) = stdout.lines().nth(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                let pct_str = fields[4].trim_end_matches('%');
                if let Ok(pct) = pct_str.parse::<u32>() {
                    if pct > CRITICAL_THRESHOLD_PCT {
                        tracing::error!(
                            "disk_monitor: {} is {}% full — critically low disk space",
                            mount,
                            pct
                        );
                    } else if pct > WARNING_THRESHOLD_PCT {
                        tracing::warn!(
                            "disk_monitor: {} is {}% full — disk space running low",
                            mount,
                            pct
                        );
                    }
                }
            }
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

    // Service monitor every 30s (30 / 5 = 6 ticks at 5s interval)
    let mut service_monitor_tick: u32 = 0;
    const SERVICE_MONITOR_INTERVAL: u32 = 6;

    // Disk space monitoring every 5 minutes (5 * 60 / 5 = 60 ticks at 5s interval)
    let mut disk_monitor_tick: u32 = 0;
    const DISK_MONITOR_INTERVAL: u32 = 60;

    tracing::info!("Background sync loop started (domain: {})", domain);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Reconcile in-memory `active` flags with actual Docker container state.
        // This catches containers that recovered (e.g. after CVM reboot) or died
        // without the API being notified — ensuring nginx routes stay in sync.
        // Only mark an instance active if the container is running AND healthy —
        // a "running" container with a crashed gateway process would cause 502s.
        if let Ok(docker_statuses) = state.compose_all_health_statuses().await {
            let mut store = state.store.write().await;
            for inst in store.list() {
                let should_be_active = docker_statuses
                    .get(&inst.name)
                    .map(|h| h.state == "running" && h.health == "healthy")
                    .unwrap_or(false);
                if inst.active != should_be_active {
                    let health_info = docker_statuses
                        .get(&inst.name)
                        .map(|h| format!("state={}, health={}", h.state, h.health))
                        .unwrap_or_else(|| "not found".to_string());
                    tracing::info!(
                        "background_sync: reconciling instance {} active {} -> {} ({})",
                        inst.name,
                        inst.active,
                        should_be_active,
                        health_info,
                    );
                    if let Err(e) = store.set_active(&inst.name, should_be_active) {
                        tracing::warn!(
                            "background_sync: Failed to set active state for instance {}: {}",
                            inst.name,
                            e
                        );
                    }
                }
            }
        }

        let instances = {
            let store = state.store.read().await;
            store.list()
        };

        let changed =
            nginx_conf::write_backends_map(&instances, &domain, &state.config.nginx_map_path);
        if changed {
            nginx_conf::reload_nginx(&state.config.ingress_container_name);
        }

        // Monitor management services and auto-restart if not running.
        service_monitor_tick += 1;
        if service_monitor_tick >= SERVICE_MONITOR_INTERVAL {
            service_monitor_tick = 0;
            if let Err(e) = tokio::task::spawn_blocking(check_and_restart_services).await {
                tracing::warn!("service_monitor: task panicked: {}", e);
            }
        }

        // Monitor disk space.
        disk_monitor_tick += 1;
        if disk_monitor_tick >= DISK_MONITOR_INTERVAL {
            disk_monitor_tick = 0;
            if let Err(e) = tokio::task::spawn_blocking(check_disk_space).await {
                tracing::warn!("disk_monitor: task panicked: {}", e);
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

    // ── constant_time_token_eq ──────────────────────────────────────

    #[test]
    fn test_ct_eq_matching() {
        assert!(constant_time_token_eq("abc123", "abc123"));
    }

    #[test]
    fn test_ct_eq_different_content() {
        assert!(!constant_time_token_eq("abc123", "xyz789"));
    }

    #[test]
    fn test_ct_eq_different_length() {
        assert!(!constant_time_token_eq("short", "muchlongertoken"));
    }

    #[test]
    fn test_ct_eq_empty_strings() {
        assert!(constant_time_token_eq("", ""));
    }

    #[test]
    fn test_ct_eq_one_empty() {
        assert!(!constant_time_token_eq("", "notempty"));
        assert!(!constant_time_token_eq("notempty", ""));
    }

    // ── extract_instance_from_state ─────────────────────────────────

    /// Build a valid ic2 state string for testing.
    fn build_ic2_state(flow_id: &str, instance_name: Option<&str>) -> String {
        let payload = serde_json::json!({
            "flow_id": flow_id,
            "instance_name": instance_name,
            "issued_at": 1710000000u64,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
        // Checksum: first 12 bytes of SHA256, base64url-encoded (matches IronClaw's format)
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&payload_bytes);
        let checksum = URL_SAFE_NO_PAD.encode(&digest[..12]);
        format!("ic2.{}.{}", payload_b64, checksum)
    }

    fn build_wrapped_mcp_state(inner_state: &str) -> String {
        let payload = serde_json::json!({
            "responseType": "code",
            "clientId": "test-client",
            "redirectUri": "https://auth.example.com/oauth/callback",
            "scope": [],
            "state": inner_state,
            "mcp_state_key": "mcp_test_state",
            "mcp_state_val": "123e4567-e89b-12d3-a456-426614174000",
            "mcp_time": 1710000000123u64,
        });
        URL_SAFE.encode(serde_json::to_vec(&payload).unwrap())
    }

    #[test]
    fn test_extract_instance_ic2_format() {
        let state = build_ic2_state("test-flow-id", Some("alice"));
        let result = extract_instance_from_state(&state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_instance_ic2_no_instance_name_falls_through() {
        let state = build_ic2_state("test-flow-id", None);
        let result = extract_instance_from_state(&state);
        // No instance_name in payload, no legacy colon format → error
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_ic2_empty_instance_name() {
        let state = build_ic2_state("test-flow-id", Some(""));
        let result = extract_instance_from_state(&state);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_legacy_format() {
        let result = extract_instance_from_state("alice:some-random-nonce");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_instance_legacy_with_hyphens() {
        let result = extract_instance_from_state("brave-tiger:abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "brave-tiger");
    }

    #[test]
    fn test_extract_instance_mcp_wrapped_ic2_format() {
        let state = build_wrapped_mcp_state(&build_ic2_state("test-flow-id", Some("alice")));
        let result = extract_instance_from_state(&state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_instance_mcp_wrapped_legacy_format() {
        let state = build_wrapped_mcp_state("brave-tiger:abc123");
        let result = extract_instance_from_state(&state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "brave-tiger");
    }

    #[test]
    fn test_extract_instance_legacy_empty_instance() {
        let result = extract_instance_from_state(":some-nonce");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_legacy_empty_nonce() {
        let result = extract_instance_from_state("alice:");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_no_colon_no_ic2() {
        let result = extract_instance_from_state("justarandomnonce");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_empty_string() {
        let result = extract_instance_from_state("");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_ic2_invalid_base64() {
        let result = extract_instance_from_state("ic2.!!!invalid!!!.checksum");
        // Invalid base64 falls through to legacy check, no colon → error
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_ic2_invalid_json() {
        let garbage = URL_SAFE_NO_PAD.encode(b"not json at all");
        let result = extract_instance_from_state(&format!("ic2.{}.fakechecksum", garbage));
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_instance_ic2_bad_checksum_rejected() {
        let state = build_ic2_state("test-flow-id", Some("alice"));
        let tampered = format!("{state}broken");
        let result = extract_instance_from_state(&tampered);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("checksum"));
    }

    // ── resolve_token_endpoint ──────────────────────────────────────

    #[test]
    fn test_resolve_token_endpoint_explicit_url() {
        let url = Some("https://notion.so/oauth/token".to_string());
        let result = resolve_token_endpoint(&url, "notion");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://notion.so/oauth/token");
    }

    #[test]
    fn test_resolve_token_endpoint_google_fallback() {
        let result = resolve_token_endpoint(&None, "google");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), GOOGLE_TOKEN_ENDPOINT);
    }

    #[test]
    fn test_resolve_token_endpoint_unknown_provider_no_url() {
        let result = resolve_token_endpoint(&None, "notion");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_token_endpoint_empty_url_falls_back() {
        let result = resolve_token_endpoint(&Some("".to_string()), "google");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), GOOGLE_TOKEN_ENDPOINT);
    }

    #[test]
    fn test_resolve_token_endpoint_empty_url_unknown_provider() {
        let result = resolve_token_endpoint(&Some("".to_string()), "notion");
        assert!(result.is_err());
    }

    // ── validate_token_endpoint_url ─────────────────────────────────

    #[tokio::test]
    async fn test_validate_token_endpoint_url_rejects_http_in_production_mode() {
        let result = validate_token_endpoint_url("http://127.0.0.1:8080/token", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_endpoint_url_rejects_loopback_https_in_production_mode() {
        let result = validate_token_endpoint_url("https://127.0.0.1/token", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_endpoint_url_rejects_embedded_credentials() {
        let result =
            validate_token_endpoint_url("https://user:pass@example.com/token", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_endpoint_url_allows_test_loopback_override() {
        let result = validate_token_endpoint_url("http://127.0.0.1:8080/token", true).await;
        assert!(result.is_ok());
    }

    // ── is_disallowed_oauth_endpoint_ip ─────────────────────────────

    #[test]
    fn test_disallowed_ip_ipv4_mapped_loopback() {
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_disallowed_oauth_endpoint_ip(ip),
            "::ffff:127.0.0.1 must be blocked (IPv4-mapped loopback)"
        );
    }

    #[test]
    fn test_disallowed_ip_ipv4_mapped_private() {
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(
            is_disallowed_oauth_endpoint_ip(ip),
            "::ffff:10.0.0.1 must be blocked (IPv4-mapped private)"
        );
    }

    #[test]
    fn test_disallowed_ip_ipv4_mapped_link_local() {
        let ip: IpAddr = "::ffff:169.254.1.1".parse().unwrap();
        assert!(
            is_disallowed_oauth_endpoint_ip(ip),
            "::ffff:169.254.1.1 must be blocked (IPv4-mapped link-local)"
        );
    }

    #[test]
    fn test_allowed_ip_ipv4_mapped_public() {
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(
            !is_disallowed_oauth_endpoint_ip(ip),
            "::ffff:8.8.8.8 must be allowed (IPv4-mapped public)"
        );
    }

    #[test]
    fn test_disallowed_ip_ipv4_cgnat_range() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(
            is_disallowed_oauth_endpoint_ip(ip),
            "100.64.0.1 must be blocked (shared CGNAT range)"
        );
    }

    #[test]
    fn test_disallowed_ip_ipv6_site_local() {
        let ip: IpAddr = "fec0::1".parse().unwrap();
        assert!(
            is_disallowed_oauth_endpoint_ip(ip),
            "fec0::1 must be blocked (IPv6 site-local range)"
        );
    }

    // ── resolve_client_credentials ──────────────────────────────────

    #[test]
    fn test_resolve_creds_from_request() {
        let config = AppConfig::test_default();
        let result = resolve_client_credentials(
            &Some("my-client-id".into()),
            &Some("my-secret".into()),
            &config,
        );
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "my-client-id");
        assert_eq!(resolved.client_secret, Some("my-secret".to_string()));
        assert_eq!(resolved.source, OAuthCredentialSource::Request);
    }

    #[test]
    fn test_resolve_creds_from_request_id_only_non_platform() {
        let config = AppConfig::test_default();
        let result = resolve_client_credentials(&Some("my-client-id".into()), &None, &config);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "my-client-id");
        // Non-platform client_id with no secret → no secret injected
        assert_eq!(resolved.client_secret, None);
        assert_eq!(resolved.source, OAuthCredentialSource::Request);
    }

    #[test]
    fn test_resolve_creds_injects_platform_secret_when_client_id_matches() {
        let mut config = AppConfig::test_default();
        config.google_oauth_client_id = Some("web-app-id-123".to_string());
        config.google_oauth_client_secret = Some(secrecy::SecretString::from(
            "web-app-secret-xyz".to_string(),
        ));

        // client_id matches platform Google client_id, no secret provided
        // → compose-api should inject the platform secret
        let result = resolve_client_credentials(&Some("web-app-id-123".into()), &None, &config);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "web-app-id-123");
        assert_eq!(
            resolved.client_secret,
            Some("web-app-secret-xyz".to_string()),
            "platform secret must be injected when client_id matches"
        );
        assert_eq!(resolved.source, OAuthCredentialSource::Platform);
    }

    #[test]
    fn test_resolve_creds_does_not_inject_secret_for_non_matching_id() {
        let mut config = AppConfig::test_default();
        config.google_oauth_client_id = Some("web-app-id-123".to_string());
        config.google_oauth_client_secret = Some(secrecy::SecretString::from(
            "web-app-secret-xyz".to_string(),
        ));

        // client_id does NOT match platform → no secret injected
        let result = resolve_client_credentials(&Some("notion-dcr-abc".into()), &None, &config);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "notion-dcr-abc");
        assert_eq!(
            resolved.client_secret, None,
            "must NOT inject platform secret for non-matching client_id"
        );
        assert_eq!(resolved.source, OAuthCredentialSource::Request);
    }

    #[test]
    fn test_resolve_creds_fallback_to_google_platform() {
        let mut config = AppConfig::test_default();
        config.google_oauth_client_id = Some("google-id".to_string());
        config.google_oauth_client_secret =
            Some(secrecy::SecretString::from("google-secret".to_string()));
        let result = resolve_client_credentials(&None, &None, &config);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "google-id");
        assert_eq!(resolved.client_secret, Some("google-secret".to_string()));
        assert_eq!(resolved.source, OAuthCredentialSource::Platform);
    }

    #[test]
    fn test_resolve_creds_no_request_no_platform() {
        let config = AppConfig::test_default();
        let result = resolve_client_credentials(&None, &None, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_creds_empty_client_id_falls_back() {
        let mut config = AppConfig::test_default();
        config.google_oauth_client_id = Some("google-id".to_string());
        config.google_oauth_client_secret =
            Some(secrecy::SecretString::from("google-secret".to_string()));
        let result = resolve_client_credentials(&Some("".to_string()), &None, &config);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.client_id, "google-id");
        assert_eq!(resolved.source, OAuthCredentialSource::Platform);
    }

    #[test]
    fn test_resolve_creds_matching_platform_id_requires_secret() {
        let mut config = AppConfig::test_default();
        config.google_oauth_client_id = Some("google-id".to_string());
        let result = resolve_client_credentials(&Some("google-id".to_string()), &None, &config);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err())
            .contains("GOOGLE_OAUTH_CLIENT_SECRET is not configured"));
    }

    // ── oauth_callback_router integration ───────────────────────────

    /// Build a minimal Router with just the callback route for testing.
    fn test_oauth_app(domain: Option<&str>) -> Router {
        let mut config = AppConfig::test_default();
        config.openclaw_domain = domain.map(String::from);

        let mut compose_files = std::collections::HashMap::new();
        // ComposeManager requires an "openclaw" key in the compose files map.
        compose_files.insert("openclaw".to_string(), config.compose_file.clone());
        let compose = Arc::new(
            ComposeManager::new(
                compose_files,
                std::path::PathBuf::from("/tmp/test-envs"),
                None,
            )
            .unwrap(),
        );
        let state = AppState {
            compose,
            store: Arc::new(RwLock::new(
                store::InstanceStore::new(PortRange::from_env()),
            )),
            config: Arc::new(config),
            backup: None,
            upgrading: Arc::new(Mutex::new(HashSet::new())),
            oauth_exchange_url: None,
            http_client: reqwest::Client::new(),
            allow_private_oauth_token_endpoints: false,
        };
        Router::new()
            .route("/oauth/callback", get(oauth_callback_router))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_callback_routes_ic2_state() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = build_ic2_state("flow123", Some("alice"));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!("/oauth/callback?code=AUTHCODE&state={}", state))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://alice.example.com/oauth/callback?"));
        assert!(location.contains("code=AUTHCODE"));
    }

    #[tokio::test]
    async fn test_callback_routes_legacy_state() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri("/oauth/callback?code=AUTHCODE&state=bob:nonce123")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://bob.example.com/oauth/callback?"));
    }

    #[tokio::test]
    async fn test_callback_routes_mcp_wrapped_ic2_state() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = build_wrapped_mcp_state(&build_ic2_state("flow123", Some("kind-fly")));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!("/oauth/callback?code=AUTHCODE&state={}", state))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://kind-fly.example.com/oauth/callback?"));
        assert!(location.contains("code=AUTHCODE"));
    }

    #[tokio::test]
    async fn test_callback_missing_state() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri("/oauth/callback?code=AUTHCODE")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_rejects_duplicate_state_params() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = build_ic2_state("flow123", Some("alice"));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!(
                "/oauth/callback?code=AUTHCODE&state={}&state=bob:nonce",
                state
            ))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_no_domain_configured() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = test_oauth_app(None);
        let request = axum::http::Request::builder()
            .uri("/oauth/callback?code=AUTHCODE&state=alice:nonce")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_callback_unparseable_state() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri("/oauth/callback?code=AUTHCODE&state=justarandomnonce")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_preserves_all_query_params() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = build_ic2_state("flow-xyz", Some("alice"));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!(
                "/oauth/callback?code=AUTHCODE&state={}&extra=hello&scope=read",
                state
            ))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://alice.example.com/oauth/callback?"));
        assert!(location.contains("code=AUTHCODE"));
        assert!(location.contains("extra=hello"));
        assert!(location.contains("scope=read"));
        assert!(location.contains(&format!("state={}", state)));
    }

    #[tokio::test]
    async fn test_callback_rejects_invalid_instance_name_chars() {
        use axum::body::Body;
        use tower::ServiceExt;

        // Build a state with an instance name containing unsafe chars
        let state = build_ic2_state("flow-xyz", Some("alice/../etc"));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!("/oauth/callback?code=X&state={}", state))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_empty_state_param() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri("/oauth/callback?code=X&state=")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_rejects_ic2_checksum_mismatch() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = format!("{}broken", build_ic2_state("flow-xyz", Some("alice")));
        let app = test_oauth_app(Some("example.com"));
        let request = axum::http::Request::builder()
            .uri(format!("/oauth/callback?code=X&state={}", state))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── oauth_exchange E2E tests ────────────────────────────────────

    /// Start a mock token endpoint that captures the received form params
    /// and returns a configurable JSON response.
    async fn start_mock_token_server(
        response_json: serde_json::Value,
    ) -> (
        String,
        tokio::sync::oneshot::Sender<()>,
        Arc<Mutex<Option<HashMap<String, String>>>>,
    ) {
        let captured_params: Arc<Mutex<Option<HashMap<String, String>>>> =
            Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured_params);
        let response_clone = response_json.clone();

        let mock_app = Router::new().route(
            "/token",
            post(move |Form(params): Form<HashMap<String, String>>| {
                let captured = Arc::clone(&captured_clone);
                let resp = response_clone.clone();
                async move {
                    *captured.lock().await = Some(params);
                    Json(resp)
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, mock_app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .ok();
        });

        (
            format!("http://127.0.0.1:{}", addr.port()),
            shutdown_tx,
            captured_params,
        )
    }

    /// Start a mock token endpoint that captures the received form params with
    /// duplicates preserved.
    type CapturedFormPairs = Arc<Mutex<Option<Vec<(String, String)>>>>;

    async fn start_mock_token_server_pairs(
        response_json: serde_json::Value,
    ) -> (String, tokio::sync::oneshot::Sender<()>, CapturedFormPairs) {
        let captured_params: CapturedFormPairs = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured_params);
        let response_clone = response_json.clone();

        let mock_app = Router::new().route(
            "/token",
            post(move |RawForm(body): RawForm| {
                let captured = Arc::clone(&captured_clone);
                let resp = response_clone.clone();
                async move {
                    *captured.lock().await =
                        Some(parse_urlencoded_pairs(&body).expect("parse mock form body"));
                    Json(resp)
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, mock_app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .ok();
        });

        (
            format!("http://127.0.0.1:{}", addr.port()),
            shutdown_tx,
            captured_params,
        )
    }

    /// Build a full app with oauth exchange routes and an authenticated instance.
    fn test_exchange_app_with_private_token_urls(
        domain: Option<&str>,
        google_client_id: Option<&str>,
        google_client_secret: Option<&str>,
        allow_private_oauth_token_endpoints: bool,
    ) -> (Router, String) {
        let mut config = AppConfig::test_default();
        config.openclaw_domain = domain.map(String::from);
        config.google_oauth_client_id = google_client_id.map(String::from);
        config.google_oauth_client_secret =
            google_client_secret.map(|s| secrecy::SecretString::from(s.to_string()));

        let instance_token = "test-instance-token-1234";
        let instance = Instance {
            name: "alice".to_string(),
            token: instance_token.to_string(),
            gateway_port: 19001,
            ssh_port: 19002,
            created_at: chrono::Utc::now(),
            ssh_pubkey: "ssh-ed25519 AAAA".to_string(),
            nearai_api_key: "sk-test".to_string(),
            nearai_api_url: None,
            active: true,
            image: None,
            image_digest: None,
            service_type: Some("openclaw".to_string()),
            mem_limit: None,
            cpus: None,
            storage_size: None,
            extra_env: None,
        };

        let mut compose_files = std::collections::HashMap::new();
        compose_files.insert("openclaw".to_string(), config.compose_file.clone());
        let compose = Arc::new(
            ComposeManager::new(
                compose_files,
                std::path::PathBuf::from("/tmp/test-envs"),
                None,
            )
            .unwrap(),
        );

        let mut instance_store = store::InstanceStore::new(PortRange::from_env());
        instance_store.populate(vec![instance]);

        let state = AppState {
            compose,
            store: Arc::new(RwLock::new(instance_store)),
            config: Arc::new(config),
            backup: None,
            upgrading: Arc::new(Mutex::new(HashSet::new())),
            oauth_exchange_url: None,
            http_client: reqwest::Client::new(),
            allow_private_oauth_token_endpoints,
        };

        let app = Router::new()
            .route("/oauth/callback", get(oauth_callback_router))
            .route("/oauth/exchange", post(oauth_exchange))
            .route("/oauth/refresh", post(oauth_refresh))
            .with_state(state);

        (app, instance_token.to_string())
    }

    fn test_exchange_app(
        domain: Option<&str>,
        google_client_id: Option<&str>,
        google_client_secret: Option<&str>,
    ) -> (Router, String) {
        test_exchange_app_with_private_token_urls(
            domain,
            google_client_id,
            google_client_secret,
            true,
        )
    }

    #[tokio::test]
    async fn test_exchange_forwards_resource_param_to_token_endpoint() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, captured) = start_mock_token_server(serde_json::json!({
            "access_token": "notion-token-xyz",
            "token_type": "bearer",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        // Simulate IronClaw's exchange_via_proxy request for MCP Notion
        let body = serde_urlencoded::to_string([
            ("code", "AUTH_CODE_FROM_NOTION"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "dcr-client-id-123"),
            ("code_verifier", "pkce-verifier-abc"),
            ("access_token_field", "access_token"),
            ("resource", "https://mcp.notion.com/mcp"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify the mock token endpoint received the resource param
        let params = captured.lock().await;
        let params = params.as_ref().expect("mock should have captured params");
        assert_eq!(params.get("grant_type").unwrap(), "authorization_code");
        assert_eq!(params.get("code").unwrap(), "AUTH_CODE_FROM_NOTION");
        assert_eq!(params.get("client_id").unwrap(), "dcr-client-id-123");
        assert_eq!(params.get("code_verifier").unwrap(), "pkce-verifier-abc");
        assert_eq!(
            params.get("resource").unwrap(),
            "https://mcp.notion.com/mcp",
            "RFC 8707 resource param must be forwarded to token endpoint"
        );
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "https://auth.example.com/oauth/callback"
        );
        // compose-api should NOT forward these internal fields
        assert!(
            params.get("token_url").is_none(),
            "token_url is for compose-api routing, not the token endpoint"
        );
        assert!(
            params.get("access_token_field").is_none(),
            "access_token_field is for compose-api, not the token endpoint"
        );
        assert!(
            params.get("provider").is_none() || params.get("provider").unwrap() != "google",
            "provider hint should not be forwarded"
        );
    }

    #[tokio::test]
    async fn test_exchange_rejects_custom_token_url_for_platform_creds() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, _captured) = start_mock_token_server(serde_json::json!({
            "access_token": "google-token",
            "refresh_token": "google-refresh",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(
            Some("example.com"),
            Some("google-platform-id"),
            Some("google-platform-secret"),
        );

        let body = serde_urlencoded::to_string([
            ("code", "GOOGLE_AUTH_CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_rejects_redirect_uri_mismatch_for_platform_creds() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, instance_token) = test_exchange_app(
            Some("example.com"),
            Some("google-id"),
            Some("google-secret"),
        );

        // No client_id → platform creds → redirect_uri must match auth.example.com
        let body = serde_urlencoded::to_string([
            ("code", "CODE"),
            ("redirect_uri", "https://evil.com/callback"),
            ("token_url", GOOGLE_TOKEN_ENDPOINT),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_skips_redirect_uri_check_for_mcp_creds() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, _captured) = start_mock_token_server(serde_json::json!({
            "access_token": "mcp-token",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        // MCP: provides client_id → redirect_uri validation is skipped
        let body = serde_urlencoded::to_string([
            ("code", "MCP_CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "mcp-dcr-id"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_exchange_missing_code_returns_400() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        let body = serde_urlencoded::to_string([
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", "https://api.notion.com/v1/oauth/token"),
            ("client_id", "some-id"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_no_auth_returns_401() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, _token) = test_exchange_app(Some("example.com"), None, None);

        let body =
            serde_urlencoded::to_string([("code", "CODE"), ("redirect_uri", "https://x.com/cb")])
                .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_exchange_no_token_url_no_platform_creds_returns_400() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        // No token_url + no platform creds + provider defaults to "google" but
        // we'd hit the Google endpoint (which would fail), but since no client_id
        // is provided and no platform creds exist, should fail before reaching endpoint
        let body = serde_urlencoded::to_string([
            ("code", "CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should fail because no client_id provided and no platform creds configured
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_unknown_provider_without_token_url_returns_400() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        let body = serde_urlencoded::to_string([
            ("provider", "notion"),
            ("code", "CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("client_id", "some-id"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_token_endpoint_error_returns_502() {
        use axum::body::Body;
        use tower::ServiceExt;

        // Start a mock that returns an error
        let error_app = Router::new().route(
            "/token",
            post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "The authorization code has expired"
                    })),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, error_app).await.ok();
        });

        let token_url = format!("http://127.0.0.1:{}/token", addr.port());
        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        let body = serde_urlencoded::to_string([
            ("code", "EXPIRED_CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "test-id"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_exchange_rejects_custom_token_url_when_platform_secret_would_be_injected() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, _captured) = start_mock_token_server(serde_json::json!({
            "access_token": "google-web-token",
            "refresh_token": "google-web-refresh",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(
            Some("example.com"),
            Some("web-app-id-123"),
            Some("web-app-secret-xyz"),
        );

        let body = serde_urlencoded::to_string([
            ("code", "GOOGLE_CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "web-app-id-123"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exchange_mcp_dcr_no_secret_injected() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, captured) = start_mock_token_server(serde_json::json!({
            "access_token": "notion-token",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        // Platform has Google creds, but MCP uses a different client_id
        let (app, instance_token) = test_exchange_app(
            Some("example.com"),
            Some("web-app-id-123"),
            Some("web-app-secret-xyz"),
        );

        // MCP DCR: client_id is from Notion DCR, doesn't match platform Google
        let body = serde_urlencoded::to_string([
            ("code", "NOTION_CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "notion-dcr-abc123"),
            ("code_verifier", "pkce-verifier"),
            ("resource", "https://mcp.notion.com/mcp"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let params = captured.lock().await;
        let params = params.as_ref().unwrap();
        assert_eq!(params.get("client_id").unwrap(), "notion-dcr-abc123");
        assert!(
            params.get("client_secret").is_none(),
            "must NOT inject platform secret for non-matching MCP client_id"
        );
        assert_eq!(
            params.get("resource").unwrap(),
            "https://mcp.notion.com/mcp"
        );
    }

    #[tokio::test]
    async fn test_exchange_multiple_extra_params_forwarded() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, captured) = start_mock_token_server(serde_json::json!({
            "access_token": "tok",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);

        let body = serde_urlencoded::to_string([
            ("code", "CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", &token_url),
            ("client_id", "id"),
            ("resource", "https://mcp.example.com/v1"),
            ("audience", "https://api.example.com"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let params = captured.lock().await;
        let params = params.as_ref().unwrap();
        assert_eq!(
            params.get("resource").unwrap(),
            "https://mcp.example.com/v1"
        );
        assert_eq!(params.get("audience").unwrap(), "https://api.example.com");
    }

    #[tokio::test]
    async fn test_exchange_preserves_repeated_resource_params() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, captured) = start_mock_token_server_pairs(serde_json::json!({
            "access_token": "tok",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(Some("example.com"), None, None);
        let body = serde_urlencoded::to_string(vec![
            ("code", "CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", token_url.as_str()),
            ("client_id", "id"),
            ("resource", "https://mcp.example.com/v1"),
            ("resource", "https://mcp.example.com/v2"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let params = captured.lock().await;
        let params = params.as_ref().unwrap();
        let resources = params
            .iter()
            .filter_map(|(key, value)| (key == "resource").then_some(value.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            resources,
            vec!["https://mcp.example.com/v1", "https://mcp.example.com/v2"]
        );
    }

    #[tokio::test]
    async fn test_exchange_rejects_private_token_url_by_default() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (app, instance_token) =
            test_exchange_app_with_private_token_urls(Some("example.com"), None, None, false);

        let body = serde_urlencoded::to_string([
            ("code", "CODE"),
            ("redirect_uri", "https://auth.example.com/oauth/callback"),
            ("token_url", "http://127.0.0.1:8080/token"),
            ("client_id", "mcp-dcr-id"),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_refresh_rejects_custom_token_url_for_platform_creds() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mock_url, _shutdown, _captured) = start_mock_token_server(serde_json::json!({
            "access_token": "refreshed-token",
            "expires_in": 3600
        }))
        .await;

        let token_url = format!("{}/token", mock_url);
        let (app, instance_token) = test_exchange_app(
            Some("example.com"),
            Some("google-platform-id"),
            Some("google-platform-secret"),
        );

        let body = serde_urlencoded::to_string([
            ("provider", "google"),
            ("refresh_token", "REFRESH_TOKEN"),
            ("token_url", &token_url),
        ])
        .unwrap();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth/refresh")
            .header("Authorization", format!("Bearer {}", instance_token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
