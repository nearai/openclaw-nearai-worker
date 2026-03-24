use axum::{
    extract::{Form, FromRequestParts, Path, RawForm, RawQuery, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod error;
mod registry;

use crate::error::ApiError;
use crate::registry::{authenticate_gateway_token, constant_time_token_eq, InstanceTokenRegistry};

const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const HOSTED_STATE_CHECKSUM_BYTES: usize = 12;

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    registry: Arc<InstanceTokenRegistry>,
    http_client: reqwest::Client,
    #[cfg(test)]
    allow_private_oauth_token_endpoints: bool,
}

struct AppConfig {
    openclaw_domain: Option<String>,
    google_oauth_client_id: Option<String>,
    google_oauth_client_secret: Option<secrecy::SecretString>,
    sync_token: secrecy::SecretString,
}

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

#[derive(Debug, Clone)]
struct ValidatedTokenEndpoint {
    url: String,
    resolved_addrs: Vec<SocketAddr>,
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

#[derive(Deserialize)]
struct OAuthRefreshRequest {
    #[serde(default = "default_provider_google")]
    provider: String,
    refresh_token: String,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Deserialize)]
struct SyncInstanceRequest {
    gateway_token: String,
}

#[derive(Deserialize)]
struct ReconcileInstancesRequest {
    instances: Vec<ReconcileInstance>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ReconcileInstance {
    instance_name: String,
    gateway_token: String,
}

type ParamsList = Vec<(String, String)>;

struct InstanceAuth {
    instance_name: String,
}

impl FromRequestParts<AppState> for InstanceAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let gateway_token = bearer_token_from_headers(parts)?;
        let instance_name = authenticate_gateway_token(&state.registry, gateway_token)
            .await
            .ok_or_else(|| ApiError::Unauthorized("Invalid instance token".into()))?;

        Ok(Self { instance_name })
    }
}

struct SyncAuth;

impl FromRequestParts<AppState> for SyncAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token_from_headers(parts)?;
        if !constant_time_token_eq(token, state.config.sync_token.expose_secret()) {
            return Err(ApiError::Unauthorized("Invalid OAuth sync token".into()));
        }
        Ok(Self)
    }
}

fn bearer_token_from_headers(parts: &Parts) -> Result<&str, ApiError> {
    let auth_header = parts
        .headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".into()))?;

    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .map(str::trim)
        .ok_or_else(|| {
            ApiError::Unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token>".into(),
            )
        })
}

fn default_provider_google() -> String {
    "google".into()
}

fn normalize_optional_oauth_field(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn hosted_state_checksum(payload_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(payload_bytes);
    URL_SAFE_NO_PAD.encode(&digest[..HOSTED_STATE_CHECKSUM_BYTES])
}

fn decode_urlsafe_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

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

fn extract_instance_from_state(state: &str) -> Result<String, ApiError> {
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

    if let Ok(wrapper_bytes) = decode_urlsafe_base64(state) {
        if let Ok(wrapper) = serde_json::from_slice::<HostedOAuthStateWrapper>(&wrapper_bytes) {
            if let Some(nested_state) = wrapper.state.filter(|nested| !nested.is_empty()) {
                if nested_state != state {
                    return extract_instance_from_state(&nested_state);
                }
            }
        }
    }

    if let Some((instance, nonce)) = state.split_once(':') {
        if !instance.is_empty() && !nonce.is_empty() {
            return Ok(instance.to_string());
        }
    }

    Err(ApiError::BadRequest(
        "Could not extract instance name from state parameter".into(),
    ))
}

fn is_valid_instance_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

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

fn resolve_client_credentials(
    req_client_id: &Option<String>,
    req_client_secret: &Option<String>,
    config: &AppConfig,
) -> Result<ResolvedClientCredentials, ApiError> {
    match (req_client_id, req_client_secret) {
        (Some(id), Some(secret)) if !id.is_empty() => Ok(ResolvedClientCredentials {
            client_id: id.clone(),
            client_secret: Some(secret.clone()),
            source: OAuthCredentialSource::Request,
        }),
        (Some(id), None) if !id.is_empty() => {
            if config
                .google_oauth_client_id
                .as_deref()
                .is_some_and(|platform_id| platform_id == id)
            {
                let platform_secret = config
                    .google_oauth_client_secret
                    .as_ref()
                    .map(|secret| secret.expose_secret().to_string())
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
        _ => {
            let client_id = config
                .google_oauth_client_id
                .as_deref()
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "No client_id provided and no platform credentials configured".into(),
                    )
                })?
                .to_string();

            Ok(ResolvedClientCredentials {
                client_id,
                client_secret: config
                    .google_oauth_client_secret
                    .as_ref()
                    .map(|secret| secret.expose_secret().to_string()),
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
        .map_err(|err| ApiError::Internal(format!("Failed to build pinned HTTP client: {}", err)))
}

async fn health_check() -> &'static str {
    "OK"
}

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

    let redirect_url = match (!raw_query.is_empty()).then_some(raw_query) {
        Some(qs) => format!("https://{}.{}/oauth/callback?{}", instance_name, domain, qs),
        None => format!("https://{}.{}/oauth/callback", instance_name, domain),
    };

    tracing::info!(instance = %instance_name, "OAuth callback routing to instance");

    Ok(Redirect::temporary(&redirect_url))
}

async fn oauth_exchange(
    auth: InstanceAuth,
    State(state): State<AppState>,
    RawForm(form): RawForm,
) -> Result<impl IntoResponse, ApiError> {
    let mut form = parse_urlencoded_pairs(&form)?;

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
    if let Some(code_verifier) = code_verifier {
        params.push(("code_verifier".into(), code_verifier));
    }

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
        .map_err(|err| {
            ApiError::Internal(format!(
                "Failed to contact token endpoint {}: {}",
                token_endpoint.url, err
            ))
        })?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|err| ApiError::Internal(format!("Failed to parse token response: {}", err)))?;

    if !status.is_success() {
        tracing::warn!(
            provider = %provider,
            status = %status,
            error = %body.get("error").and_then(|value| value.as_str()).unwrap_or("unknown"),
            description = %body
                .get("error_description")
                .and_then(|value| value.as_str())
                .unwrap_or(""),
            "OAuth token exchange failed"
        );
        return Err(ApiError::BadGateway(format!(
            "Token exchange failed: {}",
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(|value| value.as_str())
                .unwrap_or("unknown error")
        )));
    }

    Ok(Json(body))
}

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
    if let Some(secret) = resolved_credentials.client_secret {
        params.push(("client_secret", secret));
    }

    let response = http_client
        .post(&token_endpoint.url)
        .form(&params)
        .send()
        .await
        .map_err(|err| {
            ApiError::Internal(format!(
                "Failed to contact token endpoint {}: {}",
                token_endpoint.url, err
            ))
        })?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|err| ApiError::Internal(format!("Failed to parse token response: {}", err)))?;

    if !status.is_success() {
        tracing::warn!(
            provider = %req.provider,
            status = %status,
            error = %body.get("error").and_then(|value| value.as_str()).unwrap_or("unknown"),
            description = %body
                .get("error_description")
                .and_then(|value| value.as_str())
                .unwrap_or(""),
            "OAuth token refresh failed"
        );
        return Err(ApiError::BadGateway(format!(
            "Token refresh failed: {}",
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(|value| value.as_str())
                .unwrap_or("unknown error")
        )));
    }

    Ok(Json(body))
}

async fn upsert_instance_auth(
    _auth: SyncAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<SyncInstanceRequest>,
) -> Result<StatusCode, ApiError> {
    state.registry.upsert(&name, &req.gateway_token).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_instance_auth(
    _auth: SyncAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.registry.remove(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reconcile_instance_auth(
    _auth: SyncAuth,
    State(state): State<AppState>,
    Json(req): Json<ReconcileInstancesRequest>,
) -> Result<StatusCode, ApiError> {
    let desired = req
        .instances
        .into_iter()
        .map(|instance| (instance.instance_name, instance.gateway_token));
    state.registry.replace_all(desired).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/oauth/callback", get(oauth_callback_router))
        .route("/oauth/exchange", post(oauth_exchange))
        .route("/oauth/refresh", post(oauth_refresh))
        .route(
            "/internal/instances/{name}/oauth",
            put(upsert_instance_auth).delete(delete_instance_auth),
        )
        .route(
            "/internal/instances/oauth/reconcile",
            put(reconcile_instance_auth),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sync_token = std::env::var("OAUTH_SERVICE_SYNC_TOKEN")
        .map_err(|_| anyhow::anyhow!("OAUTH_SERVICE_SYNC_TOKEN must be set"))?;
    if sync_token.trim().is_empty() {
        anyhow::bail!("OAUTH_SERVICE_SYNC_TOKEN must not be empty");
    }

    let registry_path = std::env::var("OAUTH_INSTANCE_REGISTRY_PATH")
        .unwrap_or_else(|_| "/app/data/oauth-instance-auth.json".to_string());
    let registry = Arc::new(InstanceTokenRegistry::load(registry_path).await?);

    let config = Arc::new(AppConfig {
        openclaw_domain: std::env::var("OPENCLAW_DOMAIN")
            .ok()
            .filter(|value| !value.is_empty()),
        google_oauth_client_id: std::env::var("GOOGLE_OAUTH_CLIENT_ID")
            .ok()
            .filter(|value| !value.is_empty()),
        google_oauth_client_secret: std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")
            .ok()
            .filter(|value| !value.is_empty())
            .map(secrecy::SecretString::from),
        sync_token: secrecy::SecretString::from(sync_token),
    });

    let state = AppState {
        config,
        registry,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client"),
        #[cfg(test)]
        allow_private_oauth_token_endpoints: false,
    };

    let app = build_app(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:47393".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("OAuth service listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    async fn test_state() -> AppState {
        let tempdir = tempdir().unwrap();
        AppState {
            config: Arc::new(AppConfig {
                openclaw_domain: Some("example.com".into()),
                google_oauth_client_id: Some("platform-id".into()),
                google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
                sync_token: secrecy::SecretString::from("sync-token"),
            }),
            registry: Arc::new(
                InstanceTokenRegistry::load(tempdir.path().join("oauth.json"))
                    .await
                    .unwrap(),
            ),
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            allow_private_oauth_token_endpoints: true,
        }
    }

    #[test]
    fn extract_instance_from_new_and_legacy_state() {
        let payload = serde_json::json!({
            "instance_name": "pale-crab",
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let state = format!(
            "ic2.{}.{}",
            URL_SAFE_NO_PAD.encode(payload_bytes.as_slice()),
            hosted_state_checksum(&payload_bytes)
        );

        assert_eq!(extract_instance_from_state(&state).unwrap(), "pale-crab");
        assert_eq!(
            extract_instance_from_state("pale-crab:nonce-123").unwrap(),
            "pale-crab"
        );
    }

    #[test]
    fn platform_credentials_reject_token_override() {
        let config = AppConfig {
            openclaw_domain: Some("example.com".into()),
            google_oauth_client_id: Some("platform-id".into()),
            google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
            sync_token: secrecy::SecretString::from("sync-token"),
        };

        let credentials =
            resolve_client_credentials(&Some("platform-id".into()), &None, &config).unwrap();
        let err = resolve_token_endpoint_for_credentials(
            &Some("https://example.com/token".into()),
            "google",
            &credentials,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("token_url override is not allowed"));
    }

    #[tokio::test]
    async fn internal_sync_upserts_and_deletes_registry() {
        let state = test_state().await;
        let registry = state.registry.clone();
        let app = build_app(state);

        let upsert = Request::builder()
            .method("PUT")
            .uri("/internal/instances/pale-crab/oauth")
            .header("Authorization", "Bearer sync-token")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"gateway_token":"gateway-secret"}"#))
            .unwrap();
        let response = app.clone().oneshot(upsert).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            authenticate_gateway_token(registry.as_ref(), "gateway-secret")
                .await
                .as_deref(),
            Some("pale-crab")
        );

        let delete = Request::builder()
            .method("DELETE")
            .uri("/internal/instances/pale-crab/oauth")
            .header("Authorization", "Bearer sync-token")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(delete).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            authenticate_gateway_token(registry.as_ref(), "gateway-secret").await,
            None
        );
    }
}
