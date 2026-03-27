use axum::{
    body::Body,
    extract::{Form, FromRequestParts, RawForm, State},
    http::{header::CONTENT_TYPE, request::Parts, HeaderValue, Response},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod error;

use crate::error::ApiError;

const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const MAX_UPSTREAM_BODY_SIZE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    http_client: reqwest::Client,
    pinned_http_clients: Arc<Mutex<HashMap<PinnedClientCacheKey, reqwest::Client>>>,
    allow_private_oauth_token_endpoints: bool,
}

struct AppConfig {
    google_oauth_client_id: Option<String>,
    google_oauth_client_secret: Option<secrecy::SecretString>,
    proxy_auth_token: secrecy::SecretString,
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
    host: String,
    resolved_addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PinnedClientCacheKey {
    host: String,
    resolved_addrs: Vec<SocketAddr>,
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

type ParamsList = Vec<(String, String)>;

struct ProxyAuth;

impl FromRequestParts<AppState> for ProxyAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token_from_headers(parts)?;
        if !constant_time_eq(token, state.config.proxy_auth_token.expose_secret()) {
            return Err(ApiError::Unauthorized(
                "Invalid OAuth proxy auth token".into(),
            ));
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
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            ApiError::Unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token>".into(),
            )
        })
}

fn constant_time_eq(a: &str, b: &str) -> bool {
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

fn trim_nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn normalize_optional_oauth_field(value: Option<String>) -> Option<String> {
    value.as_deref().and_then(trim_nonempty)
}

fn resolve_proxy_auth_token(
    proxy_auth_token: Option<&str>,
    gateway_auth_token: Option<&str>,
) -> Option<String> {
    proxy_auth_token
        .and_then(trim_nonempty)
        .or_else(|| gateway_auth_token.and_then(trim_nonempty))
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .as_deref()
        .and_then(trim_nonempty)
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn default_provider_google() -> String {
    "google".into()
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

fn resolve_token_endpoint(token_url: &Option<String>, provider: &str) -> Result<String, ApiError> {
    if let Some(url) = token_url {
        return Ok(url.clone());
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
        (Some(id), Some(secret)) => Ok(ResolvedClientCredentials {
            client_id: id.clone(),
            client_secret: Some(secret.clone()),
            source: OAuthCredentialSource::Request,
        }),
        (Some(id), None) => {
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
        (None, Some(_)) => Err(ApiError::BadRequest(
            "client_secret requires client_id".into(),
        )),
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
    state.allow_private_oauth_token_endpoints
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
            host: host.to_string(),
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
        host: host.to_string(),
        resolved_addrs,
    })
}

fn build_base_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

fn build_token_http_client(
    state: &AppState,
    endpoint: &ValidatedTokenEndpoint,
) -> Result<reqwest::Client, ApiError> {
    if endpoint.resolved_addrs.is_empty() {
        return Ok(state.http_client.clone());
    }

    let cache_key = PinnedClientCacheKey {
        host: endpoint.host.clone(),
        resolved_addrs: endpoint.resolved_addrs.clone(),
    };

    {
        let pinned_http_clients = state
            .pinned_http_clients
            .lock()
            .map_err(|_| ApiError::Internal("Pinned HTTP client cache lock was poisoned".into()))?;
        if let Some(client) = pinned_http_clients.get(&cache_key).cloned() {
            return Ok(client);
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&endpoint.host, &endpoint.resolved_addrs)
        .build()
        .map_err(|err| {
            ApiError::Internal(format!("Failed to build pinned HTTP client: {}", err))
        })?;

    let mut pinned_http_clients = state
        .pinned_http_clients
        .lock()
        .map_err(|_| ApiError::Internal("Pinned HTTP client cache lock was poisoned".into()))?;
    if let Some(existing_client) = pinned_http_clients.get(&cache_key).cloned() {
        return Ok(existing_client);
    }
    pinned_http_clients.insert(cache_key, client.clone());
    Ok(client)
}

async fn health_check() -> &'static str {
    "OK"
}

fn response_with_body(
    status: reqwest::StatusCode,
    content_type: Option<&HeaderValue>,
    body: bytes::Bytes,
) -> Result<Response<Body>, ApiError> {
    let mut response = Response::builder().status(status);
    if let Some(content_type) = content_type {
        response = response.header(CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(body))
        .map_err(|err| ApiError::Internal(format!("Failed to build HTTP response: {}", err)))
}

async fn forward_provider_response(
    mut response: reqwest::Response,
    context: &str,
) -> Result<Response<Body>, ApiError> {
    let status = response.status();
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let mut body = bytes::BytesMut::new();

    while let Some(chunk) = response.chunk().await.map_err(|err| {
        ApiError::Internal(format!("Failed to read {} response body: {}", context, err))
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_UPSTREAM_BODY_SIZE_BYTES {
            return Err(ApiError::Internal(format!(
                "{} response body exceeded maximum size of {} bytes",
                context, MAX_UPSTREAM_BODY_SIZE_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let body = body.freeze();

    if !status.is_success() {
        tracing::warn!(status = %status, "{} failed", context);
    }

    response_with_body(status, content_type.as_ref(), body)
}

async fn oauth_exchange(
    _auth: ProxyAuth,
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

    forward_provider_response(response, "OAuth token exchange").await
}

async fn oauth_refresh(
    _auth: ProxyAuth,
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

    forward_provider_response(response, "OAuth token refresh").await
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/oauth/exchange", post(oauth_exchange))
        .route("/oauth/refresh", post(oauth_refresh))
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

    let proxy_auth_token = resolve_proxy_auth_token(
        std::env::var("IRONCLAW_OAUTH_PROXY_AUTH_TOKEN")
            .ok()
            .as_deref(),
        std::env::var("GATEWAY_AUTH_TOKEN").ok().as_deref(),
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "IRONCLAW_OAUTH_PROXY_AUTH_TOKEN or GATEWAY_AUTH_TOKEN must be set to a non-empty value"
        )
    })?;

    let config = Arc::new(AppConfig {
        google_oauth_client_id: std::env::var("GOOGLE_OAUTH_CLIENT_ID")
            .ok()
            .and_then(|value| trim_nonempty(&value)),
        google_oauth_client_secret: std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")
            .ok()
            .and_then(|value| trim_nonempty(&value))
            .map(secrecy::SecretString::from),
        proxy_auth_token: secrecy::SecretString::from(proxy_auth_token),
    });

    let state = AppState {
        config,
        http_client: build_base_http_client().expect("failed to build HTTP client"),
        pinned_http_clients: Arc::new(Mutex::new(HashMap::new())),
        allow_private_oauth_token_endpoints: env_flag("OAUTH_ALLOW_PRIVATE_TOKEN_URLS"),
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

    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
        routing::post,
    };
    use std::sync::Mutex;
    use tower::util::ServiceExt;

    async fn test_state() -> AppState {
        AppState {
            config: Arc::new(AppConfig {
                google_oauth_client_id: Some("platform-id".into()),
                google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
                proxy_auth_token: secrecy::SecretString::from("shared-secret"),
            }),
            http_client: build_base_http_client().unwrap(),
            pinned_http_clients: Arc::new(Mutex::new(HashMap::new())),
            allow_private_oauth_token_endpoints: true,
        }
    }

    async fn spawn_token_server(
        status: StatusCode,
        body: &'static str,
        captured_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        let app = Router::new().route(
            "/token",
            post({
                let captured_body = captured_body.clone();
                move |request_body: String| {
                    let captured_body = captured_body.clone();
                    async move {
                        *captured_body.lock().unwrap() = Some(request_body);
                        (
                            status,
                            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                            body,
                        )
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}/token", addr)
    }

    async fn spawn_dynamic_token_server(
        status: StatusCode,
        body: String,
        captured_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        let body = Arc::new(body);
        let app = Router::new().route(
            "/token",
            post({
                let captured_body = captured_body.clone();
                let body = body.clone();
                move |request_body: String| {
                    let captured_body = captured_body.clone();
                    let body = body.clone();
                    async move {
                        *captured_body.lock().unwrap() = Some(request_body);
                        (
                            status,
                            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                            (*body).clone(),
                        )
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}/token", addr)
    }

    #[test]
    fn proxy_auth_token_falls_back_to_gateway_token() {
        assert_eq!(
            resolve_proxy_auth_token(Some("   "), Some(" gateway-secret ")).as_deref(),
            Some("gateway-secret")
        );
        assert_eq!(
            resolve_proxy_auth_token(Some(" proxy-secret "), Some("gateway-secret")).as_deref(),
            Some("proxy-secret")
        );
        assert_eq!(resolve_proxy_auth_token(None, Some("   ")), None);
    }

    #[test]
    fn platform_credentials_reject_token_override() {
        let config = AppConfig {
            google_oauth_client_id: Some("platform-id".into()),
            google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
            proxy_auth_token: secrecy::SecretString::from("shared-secret"),
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

    #[test]
    fn platform_credentials_inject_google_secret() {
        let config = AppConfig {
            google_oauth_client_id: Some("platform-id".into()),
            google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
            proxy_auth_token: secrecy::SecretString::from("shared-secret"),
        };

        let credentials =
            resolve_client_credentials(&Some("platform-id".into()), &None, &config).unwrap();

        assert_eq!(credentials.client_id, "platform-id");
        assert_eq!(
            credentials.client_secret.as_deref(),
            Some("platform-secret")
        );
        assert!(credentials.uses_platform_credentials());
    }

    #[test]
    fn client_secret_without_client_id_is_rejected() {
        let config = AppConfig {
            google_oauth_client_id: Some("platform-id".into()),
            google_oauth_client_secret: Some(secrecy::SecretString::from("platform-secret")),
            proxy_auth_token: secrecy::SecretString::from("shared-secret"),
        };

        let err =
            resolve_client_credentials(&None, &Some("secret-only".into()), &config).unwrap_err();

        assert!(err.to_string().contains("client_secret requires client_id"));
    }

    #[tokio::test]
    async fn pinned_http_clients_are_cached_by_host_and_resolved_addrs() {
        let state = test_state().await;
        let endpoint = ValidatedTokenEndpoint {
            url: "https://example.com/token".into(),
            host: "example.com".into(),
            resolved_addrs: vec!["203.0.113.10:443".parse().unwrap()],
        };

        build_token_http_client(&state, &endpoint).unwrap();
        build_token_http_client(&state, &endpoint).unwrap();

        let cache = state.pinned_http_clients.lock().unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&PinnedClientCacheKey {
            host: "example.com".into(),
            resolved_addrs: vec!["203.0.113.10:443".parse().unwrap()],
        }));
    }

    #[tokio::test]
    async fn exchange_accepts_direct_callback_url_and_passthrough_params() {
        let captured_body = Arc::new(Mutex::new(None));
        let token_url = spawn_token_server(
            StatusCode::OK,
            r#"{"access_token":"token","refresh_token":"refresh","expires_in":3600}"#,
            captured_body.clone(),
        )
        .await;

        let app = build_app(test_state().await);
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", "Bearer shared-secret")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "code=abc&redirect_uri=https%3A%2F%2Finstance.example.com%2Foauth%2Fcallback&token_url={}&client_id=test-client&client_secret=test-secret&access_token_field=access_token&resource=test-resource",
                urlencoding::encode(&token_url)
            )))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"access_token":"token","refresh_token":"refresh","expires_in":3600}"#
        );

        let upstream_body = captured_body.lock().unwrap().clone().unwrap();
        assert!(upstream_body.contains("grant_type=authorization_code"));
        assert!(upstream_body.contains("code=abc"));
        assert!(upstream_body
            .contains("redirect_uri=https%3A%2F%2Finstance.example.com%2Foauth%2Fcallback"));
        assert!(upstream_body.contains("client_id=test-client"));
        assert!(upstream_body.contains("client_secret=test-secret"));
        assert!(upstream_body.contains("resource=test-resource"));
    }

    #[tokio::test]
    async fn exchange_forwards_provider_error_body_and_status() {
        let captured_body = Arc::new(Mutex::new(None));
        let token_url = spawn_token_server(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant","error_description":"bad code"}"#,
            captured_body,
        )
        .await;

        let app = build_app(test_state().await);
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", "Bearer shared-secret")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "code=abc&redirect_uri=https%3A%2F%2Finstance.example.com%2Foauth%2Fcallback&token_url={}&client_id=test-client&access_token_field=access_token",
                urlencoding::encode(&token_url)
            )))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"error":"invalid_grant","error_description":"bad code"}"#
        );
    }

    #[tokio::test]
    async fn exchange_rejects_oversized_provider_response_body() {
        let captured_body = Arc::new(Mutex::new(None));
        let token_url = spawn_dynamic_token_server(
            StatusCode::OK,
            "a".repeat(MAX_UPSTREAM_BODY_SIZE_BYTES + 1),
            captured_body,
        )
        .await;

        let app = build_app(test_state().await);
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/exchange")
            .header("Authorization", "Bearer shared-secret")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "code=abc&redirect_uri=https%3A%2F%2Finstance.example.com%2Foauth%2Fcallback&token_url={}&client_id=test-client&client_secret=test-secret&access_token_field=access_token",
                urlencoding::encode(&token_url)
            )))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn refresh_requires_valid_shared_bearer_token() {
        let app = build_app(test_state().await);
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/refresh")
            .header("Authorization", "Bearer wrong-secret")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "refresh_token=abc&token_url=http%3A%2F%2F127.0.0.1%2Ftoken&client_id=test-client",
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
