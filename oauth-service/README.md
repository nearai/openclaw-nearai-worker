# OAuth Service

Standalone hosted OAuth service for IronClaw instances.

This service is intentionally separate from `compose-api`. Existing hosted environments can
continue using the current compose-api OAuth endpoints unchanged, while new infra can point
IronClaw at this service instead.

## What It Owns

- `GET /oauth/callback`
  - Shared callback entrypoint for hosted OAuth flows
  - Decodes hosted `state` and `307` redirects to `https://{instance}.{domain}/oauth/callback`
- `POST /oauth/exchange`
  - Instance-authenticated token exchange proxy
  - Preserves the current IronClaw form contract
- `POST /oauth/refresh`
  - Instance-authenticated refresh proxy
  - Preserves the current IronClaw form contract
- `PUT /internal/instances/{name}/oauth`
- `DELETE /internal/instances/{name}/oauth`
- `PUT /internal/instances/oauth/reconcile`
  - Internal registry sync endpoints for provisioning valid instance gateway tokens

The service does not persist user access tokens or refresh tokens. Those remain stored on each
IronClaw instance.

## Env Vars

- `LISTEN_ADDR`
  - Bind address for the service
  - Default: `0.0.0.0:47393`
- `OPENCLAW_DOMAIN`
  - Required when `/oauth/callback` is used for shared callback routing
- `GOOGLE_OAUTH_CLIENT_ID`
  - Public platform Google client id
- `GOOGLE_OAUTH_CLIENT_SECRET`
  - Platform Google client secret
  - Only needed for platform-credential Google flows
- `OAUTH_SERVICE_SYNC_TOKEN`
  - Bearer token used by the provisioning/control plane to sync instance gateway tokens
  - Required
- `OAUTH_INSTANCE_REGISTRY_PATH`
  - Path to the persisted hashed instance-token registry
  - Default: `/app/data/oauth-instance-auth.json`

## IronClaw Contract

This service is compatible with the current IronClaw hosted OAuth contract:

- `IRONCLAW_OAUTH_EXCHANGE_URL`
  - Point this to the service base URL
- `GATEWAY_AUTH_TOKEN`
  - Sent by IronClaw as `Authorization: Bearer ...` on `/oauth/exchange` and `/oauth/refresh`
- `GOOGLE_OAUTH_CLIENT_ID`
  - Still set on the IronClaw instance for hosted Google auth URL construction

## Cloudflare Worker Note

If you want a Cloudflare Worker in front of this, the safest split is:

- Cloudflare Worker or other edge service for `GET /oauth/callback`
- This Rust service for `/oauth/exchange` and `/oauth/refresh`

That keeps token-endpoint validation and pinned-address outbound requests in the Rust service,
which is a better fit for the current SSRF protections than a pure Worker-only implementation.

## Local Build

```bash
cargo test
docker build -t openclaw-oauth-service:local .
```
