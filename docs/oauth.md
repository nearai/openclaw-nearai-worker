# OAuth Flow — Hosted Mode (E2E)

A single OAuth redirect URI (`https://auth.DOMAIN/oauth/callback`) serves all instances.
Compose-api routes callbacks to the correct instance by decoding the state parameter.
The platform holds provider secrets and proxies token exchanges so containers never see them.
Generic providers (MCP, etc.) can send their own credentials in the exchange request.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OAUTH FLOW — HOSTED MODE (E2E)                              │
│                                                                                │
│  Actors:  Browser │ Web UI (JS) │ Gateway │ ExtMgr │ compose-api │ Provider   │
└─────────────────────────────────────────────────────────────────────────────────┘

 Browser/Web UI                    IronClaw Container              Platform / External
 ─────────────                     ──────────────────              ────────────────────
      │                                   │                                │
      │  1. Click "Configure" on ext      │                                │
      │──────────────────────────────────► │                                │
      │  POST /api/extensions/{name}/setup│                                │
      │  {client_id, client_secret}       │                                │
      │                                    │                                │
      │  2. Click "Activate"               │                                │
      │──────────────────────────────────► │                                │
      │  POST /api/extensions/{name}/activate                              │
      │                                    │                                │
      │                          ┌─────────┴─────────┐                      │
      │                          │  ExtensionManager  │                      │
      │                          │  start_wasm_oauth()│                      │
      │                          │                    │                      │
      │                          │  callback_url()    │                      │
      │                          │  = "https://auth   │                      │
      │                          │    .DOMAIN"        │                      │
      │                          │                    │                      │
      │                          │  redirect_uri =    │                      │
      │                          │  callback_url()    │                      │
      │                          │+ "/oauth/callback" │                      │
      │                          │                    │                      │
      │                          │  state =           │                      │
      │                          │  "ic2.{base64      │                      │
      │                          │   payload}.{cksum}"│                      │
      │                          │  (contains         │                      │
      │                          │   instance_name    │                      │
      │                          │   + flow_id)       │                      │
      │                          │                    │                      │
      │                          │  Store pending     │                      │
      │                          │  flow keyed by     │                      │
      │                          │  flow_id           │                      │
      │                          └─────────┬─────────┘                      │
      │                                    │                                │
      │  3. Returns {auth_url, callback_type: "gateway"}                    │
      │◄──────────────────────────────────-│                                │
      │                                    │                                │
      │  4. Open popup window                                               │
      │─────────────────────────────────────────────────────────────────────►│
      │  https://provider.example.com/oauth/authorize                       │
      │    ?client_id=...                                                   │
      │    &redirect_uri=https://auth.DOMAIN/oauth/callback                 │
      │    &state=ic2.eyJ...                                                │
      │    &scope=...                                                       │
      │                                                             Provider│
      │                                                              OAuth  │
      │  5. User consents                                            Server │
      │                                                                │    │
      │  6. Provider redirects browser                                 │    │
      │◄───────────────────────────────────────────────────────────────┘    │
      │  Redirect → https://auth.DOMAIN/oauth/callback                     │
      │         ?code=AUTH_CODE_ABC                                         │
      │         &state=ic2.eyJ...                                          │
      │                                                                     │
      │                                                                     │
      │         ┌──────────────────────────┐                                │
      │         │  compose-api             │                                │
      │         │  /oauth/callback         │                                │
      │────────►│                          │                                │
      │         │  decode state:           │                                │
      │         │  ic2.{payload}.{cksum}   │                                │
      │         │   → instance = "alice"   │                                │
      │         │                          │                                │
      │  7.     │  307 redirect to:        │                                │
      │◄────────│  https://alice.DOMAIN/   │                                │
      │         │  oauth/callback          │                                │
      │         │  ?code=AUTH_CODE_ABC     │                                │
      │         │  &state=ic2.eyJ...      │                                │
      │         └──────────────────────────┘                                │
      │                                                                     │
      │  8. Browser follows redirect                                        │
      │──────────────────────────────────►│                                 │
      │  GET /oauth/callback              │                                 │
      │   ?code=AUTH_CODE_ABC             │                                 │
      │   &state=ic2.eyJ...              │                                 │
      │                                   │                                 │
      │                          ┌────────┴────────┐                        │
      │                          │ oauth_callback_  │                        │
      │                          │ handler()        │                        │
      │                          │                  │                        │
      │                          │ Decode state,    │                        │
      │                          │ lookup pending   │                        │
      │                          │ flow by flow_id  │                        │
      │                          │ (atomic remove)  │                        │
      │                          │                  │        compose-api     │
      │                          │ 9. Exchange code │        (platform)      │
      │                          │──────────────────────────►┌──────────┐   │
      │                          │ POST http://host.docker   │ /oauth/  │   │
      │                          │  .internal:<port>/oauth/  │ exchange │   │
      │                          │  exchange                 │          │   │
      │                          │  Auth: Bearer <gw_token>  │          │   │
      │                          │  {code, redirect_uri,     │ Resolves │   │
      │                          │   token_url (optional),   │ creds &  │───►
      │                          │   client_id (optional),   │ endpoint │   │
      │                          │   code_verifier: ...}     │          │   │
      │                          │                           │ POST to  │   │
      │                          │                           │ provider │   │
      │                          │                           │ token    │   │
      │                          │ 10. Receive tokens        │ endpoint │   │
      │                          │◄──────────────────────────┤          │◄──│
      │                          │  {access_token,           └──────────┘   │
      │                          │   refresh_token,                         │
      │                          │   expires_in}                            │
      │                          │                  │                       │
      │                          │ 11. Validate     │                       │
      │                          │ (optional: call  │                       │
      │                          │  validation      │                       │
      │                          │  endpoint)       │                       │
      │                          │                  │                       │
      │                          │ 12. Store tokens ├──►┌─────────┐        │
      │                          │  encrypted       │   │ Secrets │        │
      │                          │                  │   │  Store  │        │
      │                          │                  │   │(AES-256)│        │
      │                          │                  │   └─────────┘        │
      │                          │ 13. Broadcast    │                       │
      │                          │  SSE event       │                       │
      │                          └────────┬────────┘                       │
      │                                   │                                │
      │  14. Return success HTML          │                                │
      │◄──────────────────────────────────│                                │
      │  (popup shows "Connected")        │                                │
      │                                   │                                │
      │  15. SSE: AuthCompleted           │                                │
      │◄──────────────────────────────────│                                │
      │  {extension: "...",               │                                │
      │   success: true}                  │                                │
      │                                   │                                │
      │  16. Web UI refreshes             │                                │
      │  extension list, shows            │                                │
      │  extension as "active"            │                                │


┌─────────────────────────────────────────────────────────────────────────────────┐
│  ENV VARS IN THE WORKER CONTAINER                                              │
│                                                                                │
│  Set by ironclaw-worker/entrypoint.sh:                                         │
│  IRONCLAW_OAUTH_CALLBACK_URL = https://auth.DOMAIN                             │
│  IRONCLAW_INSTANCE_NAME      = alice          (from OPENCLAW_INSTANCE_NAME)    │
│  GATEWAY_AUTH_TOKEN          = <random hex>   (for exchange proxy auth)        │
│                                                                                │
│  Injected by compose-api when available:                                       │
│  GOOGLE_OAUTH_CLIENT_ID      = 637554...      (public, for auth URL)           │
│  IRONCLAW_OAUTH_EXCHANGE_URL = http://host.docker.internal:<compose-api-port>  │
│                                                                                │
│  NOT in container:                                                             │
│  GOOGLE_OAUTH_CLIENT_SECRET  — stays on compose-api only                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PROVIDER CONSOLE — Authorized redirect URIs:                                  │
│                                                                                │
│  https://auth.DOMAIN/oauth/callback                                            │
│  (single URI covers ALL instances — compose-api routes by state param)         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  DNS:  auth.DOMAIN       → same server IP                                      │
│        *.DOMAIN           → same server IP                                     │
│        DOMAIN             → same server IP                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│  KEY DESIGN DECISIONS                                                          │
│                                                                                │
│  • Single redirect URI for all instances (no per-instance registration)        │
│  • Instance routing via state param (compose-api decodes ic2 format + legacy)  │
│  • Token exchange via platform proxy (platform Google secret stays off containers) │
│  • Generic providers (MCP, etc.) send token_url + client_id in exchange req    │
│  • Flow registry keyed by flow_id (atomic remove prevents replay)              │
│  • 5-minute expiry on pending flows                                            │
│  • Falls back to direct exchange + TCP listener in local/desktop mode          │
├─────────────────────────────────────────────────────────────────────────────────┤
│  STATE PARAMETER FORMATS                                                       │
│                                                                                │
│  New (ic2): ic2.{base64url_json}.{sha256_checksum}                             │
│    Payload JSON: {"flow_id":"...","instance_name":"alice","issued_at":...}      │
│    Checksum: first 12 bytes of SHA256(payload), base64url-encoded              │
│                                                                                │
│  Legacy:    instance:nonce (e.g., "alice:abc123")                              │
│    Instance name is the text before the first colon                            │
│                                                                                │
│  compose-api's /oauth/callback handler verifies ic2 checksums and decodes both formats. │
├─────────────────────────────────────────────────────────────────────────────────┤
│  EXCHANGE PROXY PROTOCOL                                                       │
│                                                                                │
│  IronClaw appends /oauth/exchange to IRONCLAW_OAUTH_EXCHANGE_URL.             │
│  compose-api injects the actual listen port here (47392 in the default deploy).│
│  Request: POST, form-encoded.                                                  │
│  Auth: Bearer <gateway_token>.                                                 │
│                                                                                │
│  Mode 1 — Platform credentials (Google):                                       │
│    IronClaw may send code, redirect_uri, code_verifier, token_url, client_id,  │
│    and access_token_field. compose-api treats missing / empty client creds,     │
│    or a client_id matching the platform Google app, as platform-credential      │
│    mode. In that mode it injects the platform client_secret server-side and     │
│    only allows the built-in Google token endpoint.                              │
│                                                                                │
│  Mode 2 — Request credentials (generic/MCP):                                   │
│    Fields: code, redirect_uri, token_url, client_id, client_secret (optional)  │
│    plus provider-specific extras such as resource. compose-api forwards these   │
│    to the provided token_url after URL validation, and never injects platform   │
│    secrets for non-platform credentials.                                        │
│                                                                                │
│  Response: JSON {access_token, refresh_token, expires_in, ...}.                │
└─────────────────────────────────────────────────────────────────────────────────┘
```
