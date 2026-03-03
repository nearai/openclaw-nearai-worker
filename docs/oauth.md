# OAuth Flow — Hosted Mode (E2E)

A single OAuth redirect URI (`https://auth.DOMAIN/oauth/callback`) serves all instances.
Nginx routes callbacks to the correct instance by parsing the instance name from the `state` query parameter.
The platform's compose-api holds the Google client secret and proxies token exchanges so containers never see it.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OAUTH FLOW — HOSTED MODE (E2E)                              │
│                                                                                │
│  Actors:  Browser │ Web UI (JS) │ Gateway │ ExtMgr │ Nginx │ Google │ Secrets  │
└─────────────────────────────────────────────────────────────────────────────────┘

 Browser/Web UI                    IronClaw Container              Platform / External
 ─────────────                     ──────────────────              ────────────────────
      │                                   │                                │
      │  1. Click "Configure" on Gmail     │                                │
      │──────────────────────────────────► │                                │
      │  POST /api/extensions/gmail/setup  │                                │
      │  {client_id, client_secret}        │                                │
      │                                    │                                │
      │  2. Click "Activate"               │                                │
      │──────────────────────────────────► │                                │
      │  POST /api/extensions/gmail/activate                                │
      │                                    │                                │
      │                          ┌─────────┴─────────┐                      │
      │                          │  ExtensionManager  │                      │
      │                          │  start_wasm_oauth()│                      │
      │                          │                    │                      │
      │                          │  callback_url()    │                      │
      │                          │  = "https://auth   │                      │
      │                          │    .DOMAIN/oauth"  │                      │
      │                          │                    │                      │
      │                          │  redirect_uri =    │                      │
      │                          │  callback_url()    │                      │
      │                          │  + "/callback"     │                      │
      │                          │  = "https://auth.  │                      │
      │                          │  DOMAIN/oauth/     │                      │
      │                          │  callback"         │                      │
      │                          │                    │                      │
      │                          │  state =           │                      │
      │                          │  "alice:rand_nonce"│                      │
      │                          │  (instance prefix  │                      │
      │                          │   from env var)    │                      │
      │                          │                    │                      │
      │                          │  Store pending     │                      │
      │                          │  flow keyed by     │                      │
      │                          │  full state string │                      │
      │                          └─────────┬─────────┘                      │
      │                                    │                                │
      │  3. Returns {auth_url, callback_type: "gateway"}                    │
      │◄──────────────────────────────────-│                                │
      │                                    │                                │
      │  4. Open popup window                                               │
      │─────────────────────────────────────────────────────────────────────►│
      │  https://accounts.google.com/o/oauth2/v2/auth                       │
      │    ?client_id=637554...                                             │
      │    &redirect_uri=https://auth.DOMAIN/oauth/callback                 │
      │    &state=alice:rand_nonce                                          │
      │    &scope=gmail.modify+gmail.compose                                │
      │    &access_type=offline                                             │
      │    &prompt=consent                                          Google   │
      │                                                              OAuth   │
      │  5. User consents                                            Server  │
      │                                                                │     │
      │  6. Google redirects browser                                   │     │
      │◄───────────────────────────────────────────────────────────────┘     │
      │  302 → https://auth.DOMAIN/oauth/callback                           │
      │         ?code=AUTH_CODE_ABC                                          │
      │         &state=alice:rand_nonce                                      │
      │                                                                      │
      │                                                                      │
      │         ┌──────────────────────────┐                                 │
      │         │  Nginx (auth.DOMAIN)     │                                 │
      │────────►│                          │                                 │
      │         │  map $arg_state:         │                                 │
      │         │  "alice:rand_nonce"      │                                 │
      │         │   → instance = "alice"   │                                 │
      │         │                          │                                 │
      │  7.     │  302 redirect to:        │                                 │
      │◄────────│  https://alice.DOMAIN/   │                                 │
      │         │  oauth/callback          │                                 │
      │         │  ?code=AUTH_CODE_ABC     │                                 │
      │         │  &state=alice:rand_nonce │                                 │
      │         └──────────────────────────┘                                 │
      │                                                                      │
      │  8. Browser follows redirect                                         │
      │──────────────────────────────────►│                                  │
      │  GET /oauth/callback              │                                  │
      │   ?code=AUTH_CODE_ABC             │                                  │
      │   &state=alice:rand_nonce         │                                  │
      │                                   │                                  │
      │                          ┌────────┴────────┐                         │
      │                          │ oauth_callback_  │                         │
      │                          │ handler()        │                         │
      │                          │                  │                         │
      │                          │ Lookup pending   │                         │
      │                          │ flow by full     │                         │
      │                          │ state string     │                         │
      │                          │ (atomic remove)  │                         │
      │                          │                  │        compose-api      │
      │                          │ 9. Exchange code │        (platform)       │
      │                          │──────────────────────────►┌──────────┐    │
      │                          │ POST http://host.docker   │ /oauth/  │    │
      │                          │  .internal:8080/oauth/    │ exchange │    │
      │                          │  exchange                 │          │    │
      │                          │  Auth: Bearer <gw_token>  │          │    │
      │                          │  {provider: "google",     │ Adds     │    │
      │                          │   code: AUTH_CODE_ABC,    │ client_  │    │
      │                          │   redirect_uri: ...,     │ secret   │───►│
      │                          │   code_verifier: ...}    │          │    │
      │                          │                          │ POST to  │    │
      │                          │                          │ Google   │    │
      │                          │                          │ token    │    │
      │                          │ 10. Receive tokens       │ endpoint │    │
      │                          │◄─────────────────────────┤          │◄───│
      │                          │  {access_token,          └──────────┘    │
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
      │  (popup shows "Google Connected") │                                │
      │                                   │                                │
      │  15. SSE: AuthCompleted           │                                │
      │◄──────────────────────────────────│                                │
      │  {extension: "gmail",             │                                │
      │   success: true}                  │                                │
      │                                   │                                │
      │  16. Web UI refreshes             │                                │
      │  extension list, shows            │                                │
      │  Gmail as "active"                │                                │


┌─────────────────────────────────────────────────────────────────────────────────┐
│  ENV VARS (set by ironclaw-worker/entrypoint.sh)                               │
│                                                                                │
│  IRONCLAW_OAUTH_CALLBACK_URL = https://auth.DOMAIN/oauth                       │
│  IRONCLAW_INSTANCE_NAME      = alice          (from OPENCLAW_INSTANCE_NAME)    │
│  GOOGLE_OAUTH_CLIENT_ID      = 637554...      (public, for auth URL)           │
│  IRONCLAW_OAUTH_EXCHANGE_URL = http://host.docker.internal:8080/oauth          │
│  GATEWAY_AUTH_TOKEN           = <random hex>   (for exchange proxy auth)        │
│                                                                                │
│  NOT in container:                                                             │
│  GOOGLE_OAUTH_CLIENT_SECRET  — stays on compose-api only                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│  GOOGLE CONSOLE — Authorized redirect URIs:                                    │
│                                                                                │
│  https://auth.DOMAIN/oauth/callback                                            │
│  (single URI covers ALL instances — nginx routes by state param)               │
├─────────────────────────────────────────────────────────────────────────────────┤
│  DNS:  auth.DOMAIN       → same server IP                                      │
│        *.DOMAIN           → same server IP                                     │
│        DOMAIN             → same server IP                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│  KEY DESIGN DECISIONS                                                          │
│                                                                                │
│  • Single redirect URI for all instances (no per-instance registration)        │
│  • Instance routing via state param prefix ("alice:nonce"), not subdomain       │
│  • Token exchange via platform proxy (client_secret never enters containers)   │
│  • Flow registry keyed by full state string (including instance prefix)        │
│  • Atomic remove from registry prevents replay attacks                         │
│  • 5-minute expiry on pending flows                                            │
│  • Falls back to direct exchange + TCP listener in local/desktop mode          │
└─────────────────────────────────────────────────────────────────────────────────┘
```
