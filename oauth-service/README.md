# OAuth Service

Standalone hosted OAuth exchange service for IronClaw instances.

This service matches the direct-callback hosted flow:

1. IronClaw sends the browser to the provider.
2. The provider redirects directly back to the hosted IronClaw instance.
3. IronClaw finishes `/oauth/callback` locally.
4. IronClaw calls this service for token exchange or refresh.
5. IronClaw stores the returned access and refresh tokens locally.

The service is stateless with respect to user OAuth tokens.

## What It Owns

- `POST /oauth/exchange`
  - Shared bearer token auth
  - Accepts IronClaw's form payload
  - Calls the provider token endpoint with redirects disabled
  - Returns the provider response body directly
- `POST /oauth/refresh`
  - Shared bearer token auth
  - Accepts IronClaw's refresh form payload
  - Calls the provider token endpoint with redirects disabled
  - Returns the provider response body directly
- `GET /health`
  - Simple health endpoint

No `/oauth/callback` route is required in this direct-callback model.

## Runtime Env Vars

- `LISTEN_ADDR`
  - Bind address for the service
  - Default: `0.0.0.0:47393`
- `OAUTH_ALLOW_PRIVATE_TOKEN_URLS`
  - Optional dev-only override for local testing
  - When set to `1`, `true`, or `yes`, allows private and loopback `token_url` values
- `IRONCLAW_OAUTH_PROXY_AUTH_TOKEN`
  - Shared bearer token expected from hosted IronClaw instances
  - Whitespace-only values are treated as unset
  - Falls back to `GATEWAY_AUTH_TOKEN`
- `GATEWAY_AUTH_TOKEN`
  - Fallback shared bearer token for existing hosted infra
- `GOOGLE_OAUTH_CLIENT_ID`
  - Public platform Google client id
- `GOOGLE_OAUTH_CLIENT_SECRET`
  - Platform Google client secret injected server-side for hosted Google flows

## IronClaw Contract

This service is compatible with the current hosted IronClaw contract:

- `IRONCLAW_OAUTH_CALLBACK_URL`
  - Set on IronClaw to the direct instance callback URL or base URL
- `IRONCLAW_OAUTH_EXCHANGE_URL`
  - Set on IronClaw to this service's base URL
- `IRONCLAW_OAUTH_PROXY_AUTH_TOKEN`
  - Sent by IronClaw as `Authorization: Bearer ...`
- `GOOGLE_OAUTH_CLIENT_ID`
  - Still set on IronClaw for hosted Google auth URL construction

## Security Behavior

- Rejects non-HTTPS token URLs in production
- Rejects token URLs that resolve to loopback or private addresses in production
- Disables redirect following for outbound provider requests
- `OAUTH_ALLOW_PRIVATE_TOKEN_URLS` relaxes the token URL checks only for explicit local testing
- For hosted Google platform flows:
  - injects the platform `client_secret` server-side
  - rejects arbitrary `token_url` overrides

## Local Build

```bash
cargo test
docker build -t openclaw-oauth-service:local .
```

## Publish Image

This repo's GitHub Actions build workflow publishes `oauth-service` to Docker Hub
as `docker.io/<DOCKER_REGISTRY_USER>/openclaw-oauth-service:<tag>`.

Tag behavior matches the other repo images:

- `main` branch builds publish `:dev`
- `v*` tags publish the version number without the leading `v`
- manual workflow runs can override the tag with the `tag` input

Example pull:

```bash
docker pull docker.io/<your-dockerhub-user>/openclaw-oauth-service:dev
```
