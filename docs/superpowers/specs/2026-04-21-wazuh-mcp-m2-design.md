# Wazuh MCP M2 — Multi-tenant + OAuth Design Spec

**Date:** 2026-04-21
**Status:** Brainstorming output, pending plan
**Milestone:** M2 of v1 (see `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md` §9)
**Predecessor:** M1 walking skeleton, tag `v0.1.0-m1`, retro at `docs/superpowers/retros/2026-04-20-m1-retro.md`.

## 1. Purpose & Scope

M2 takes M1's working-but-local MCP server and makes it a real multi-tenant remote service. It adds Streamable HTTP transport, OAuth 2.1 authentication against a single configured IdP, API-key fallback, per-tenant connection pooling, and the RFC 9728 metadata endpoint.

M2 remains **read-only** — `search_alerts` stays the only tool. Additional tools, real secret backends (AWS SM / Vault / sqlite_age), rate limits, OTel, metrics, and write-tool scaffolding are explicitly deferred to M3-M4.

## 2. M2 Brainstorming Decisions

| # | Decision | Choice |
|---|---|---|
| Q1 | OAuth target | Generic OIDC/OAuth 2.1 contract. Integration-tested against Keycloak in docker-compose. API-key fallback stays. |
| Q2 | Token → `tenant_id` mapping | Hybrid — prefer custom `tenant_id` claim; fall back to `iss` → registry lookup. |
| Q3 | stdio lifecycle | Both stdio and Streamable HTTP ship. Chosen by CLI flag / `server.yaml`. |
| Q4 | `SecretStore` driver in M2 | YAML only. Production backends defer to M4. |
| Q5 | `IndexerClient` lifecycle | Per-tenant pool shared across sessions. Server-lifetime, no TTL eviction in M2. |
| Q6 | TLS termination | Reverse proxy (Caddy reference config). Server runs plain HTTP. |
| Q7 | IdP multiplicity | One deployment = one IdP. Diverse-IdP customers get separate deployments. |
| Arch | Module integration | Approach 3 — `SessionFactory` protocol, M1 wiring becomes `ConfigSessionFactory`, M2 adds `OAuthSessionFactory` and `ApiKeySessionFactory` behind a `ChainSessionFactory`. |

## 3. Architecture

M2 adds a remote transport, OAuth, API-key fallback, and per-tenant connection pooling — all slotted behind a `SessionFactory` protocol so M1's stdio path stays intact.

```
                         stdio client
                              │
                              ▼  (single-operator local)
           ┌─────────────────────────────────────────┐
           │  ConfigSessionFactory                   │
           │  (builds Session from server.yaml)      │
           └─────────────────────────────────────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │      FastMCP app       │
                 │  (M1's search_alerts,  │
                 │   registered as-is)    │
                 └────────────────────────┘
                              ▲
                              │  same tool handler
                              │
           ┌─────────────────────────────────────────┐
           │  OAuthSessionFactory  ──or──  ApiKey…   │
           │  (token → tenant_id, rbac_role)         │
           └─────────────────────────────────────────┘
                              ▲
                              │  per-request
                              │
           ┌─────────────────────────────────────────┐
           │  Streamable HTTP ASGI                   │
           │  (uvicorn, /mcp endpoint,               │
           │   session middleware)                   │
           └─────────────────────────────────────────┘
                              ▲
                              │  HTTPS (reverse proxy)
                              │
                         HTTP client

   IndexerClientPool   (shared across sessions, per-tenant)
   TenantRegistry      (extended: oauth_issuer, aud, rbac_claim)
   AuditEmitter        (unchanged — stderr default still protects stdio)
```

**Invariants:**
- `SessionFactory` is the sole constructor of `Session`. Tool handlers never touch auth machinery — they pull `Session` from a per-request contextvar.
- Transport stays dumb. stdio reads JSON-RPC frames; Streamable HTTP serves `/mcp` + `/.well-known/oauth-protected-resource`. Neither knows about auth specifics.
- One IdP per deployment. OAuth validator caches the single issuer's JWKS (10-min TTL, refresh on unknown kid).
- Tenant resolution is still session-pinned — `tenant_id` derived from token once at auth, stored in `Session`, no tool argument can override.
- `IndexerClientPool` keyed by `tenant_id`, lazy-initialized, server-lifetime, no TTL in M2.
- No new tools, no new transports, no real secret backends — all deferred.

## 4. Components

### `auth/` (extended from M1)
- `session.py` — **unchanged.** `Session` dataclass stays.
- `factory.py` — **new.** `SessionFactory(Protocol)` with `async build(ctx: RequestContext) -> Session`.
- `config_factory.py` — **new.** `ConfigSessionFactory` wraps M1's config-load + Session-build into the factory protocol. Pure refactor.
- `oauth.py` — **new.** `OAuthSessionFactory`. Verifies JWT against cached JWKS using `authlib.jose`, extracts `tenant_id` (custom claim → iss fallback), extracts `rbac_role` (from `wazuh_mcp_role` → `groups` → `roles`, first present wins).
- `api_key.py` — **new.** `ApiKeySessionFactory`. Parses `Authorization: Bearer wzk_<tenant>_<random>`, verifies argon2id hash in `ApiKeyStore`.
- `api_key_store.py` — **new.** `ApiKeyStore(Protocol)` + `YamlApiKeyStore` driver. Entries carry `key_id`, argon2id `hash`, `tenant_id`, `user_id`, `rbac_role`, `revoked`, optional `expires_at`.
- `chain_factory.py` — **new.** `ChainSessionFactory` dispatches by token shape: `wzk_` prefix → API-key factory; three dot-separated JWT segments → OAuth factory; else 401. No blind probing of both.
- `errors.py` — **new.** Auth-layer types: `InvalidToken`, `ExpiredToken`, `UnknownIssuer`, `MissingClaim`, `ApiKeyRevoked`. Scrubbed at the transport boundary.

### `tenancy/` (extended from M1)
- `config.py` — `TenantConfig` grows optional `oauth_issuer: HttpUrl | None`, `oauth_audience: str | None`. `extra='forbid'` stays.
- `registry.py` — `TenantRegistry` unchanged; YAML accepts the new fields.
- `issuer_index.py` — **new.** Reverse index `iss → tenant_id` from the registry at startup. Used by `OAuthSessionFactory`'s iss-fallback path. Rejects duplicate issuers.

### `transport/` (new module)
- `__init__.py` — re-exports `run_stdio` (M1's entry) and `build_asgi_app` (M2).
- `http.py` — `build_asgi_app(app, factory) -> ASGIApplication`. FastMCP's Streamable HTTP mount + session middleware (builds `Session` via factory, stores in contextvar). Also exposes `/.well-known/oauth-protected-resource`, `/healthz`, `/readyz`.
- `session_ctx.py` — **new.** `current_session() -> Session` for tool handlers to pull from the per-request contextvar. Replaces the singleton `cfg.session` indirection.

### `wazuh/` (extended from M1)
- `indexer.py` — `IndexerClient` **unchanged.**
- `indexer_pool.py` — **new.** `IndexerClientPool.acquire(tenant_id) -> IndexerClient`: lazy-init per tenant, returns long-lived shared client. `aclose_all()` on shutdown. Fetches creds from `SecretStore` once per tenant.

### `tools/alerts.py` — minimal change
- `search_alerts` signature unchanged. Its HTTP-mode wrapper uses `pool.acquire(session.tenant_id)` and does NOT close (pool-owned). stdio-mode wrapper preserved from M1.

### `server.py` — refactored
- Reads config → builds registry, secrets, pool → constructs the chosen `SessionFactory` (config vs oauth_chain) → hands factory + app to the chosen transport (stdio vs http).

### `observability/` — **unchanged** from M1.

### `config/` — extended
New fields in `server.yaml`:
```yaml
transport: stdio|http                 # default: stdio
auth: config|oauth_chain              # default: config
http:                                 # only if transport=http
  bind: "0.0.0.0:8000"
  public_url: "https://mcp.example.com"
oauth:                                # only if auth=oauth_chain
  issuer: "https://idp.example.com/realms/msp"
  audience: "wazuh-mcp-api"
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256, ES256]
  clock_skew_seconds: 30
api_keys_file: "./config/api_keys.yaml"   # only if auth=oauth_chain
```

## 5. Data Flow (authenticated HTTP call)

*Analyst in Claude client, authenticated via OAuth, asks "show critical alerts in last hour" against tenant Acme.*

```
1. Client initiates
   Claude client has already run OAuth (discovery → PKCE code flow → bearer token).

   POST /mcp   Authorization: Bearer eyJhbGci...

2. HTTP transport middleware (transport/http.py)
   a. Extract Authorization header.
   b. Call ChainSessionFactory.build(ctx):
      → detects JWT shape → routes to OAuthSessionFactory.
   c. OAuthSessionFactory:
      → fetches/validates JWKS (cached, 10-min TTL)
      → verifies signature, iss, aud, exp, nbf, iat, allowlisted alg
      → tenant_id:
          - first: "tenant_id" custom claim if present
          - fallback: IssuerIndex[token.iss] → tenant_id
      → rbac_role: first present of [wazuh_mcp_role, groups, roles]
      → returns Session(user_id=sub, tenant_id=X, rbac_role=Y, auth_method="oauth")
   d. Store Session in session_ctx ContextVar.
   e. Forward to FastMCP app.

3. Tool dispatch
   Claude selects search_alerts(time_range="1h", min_level=12)
   → Pydantic strict validation (M1)
   → Wrapper calls:
       session = current_session()
       indexer = await pool.acquire(session.tenant_id)
   → Pool is lazy:
       if not cached: fetch creds via SecretStore, build IndexerClient, cache.
       return cached client.
   → Delegates to M1's search_alerts(args, session, indexer, audit).
   → M1 logic unchanged end-to-end.

4. Response
   MCP response flows back through ASGI. Indexer NOT closed — pool-owned.
   Audit event to stderr: user_id, tenant_id, tool, arg_hash, duration, outcome.

5. Shutdown
   On SIGTERM: await pool.aclose_all() before process exit.
```

### Error paths

| Scenario | HTTP status | Body | Audit? |
|---|---|---|---|
| No Authorization | 401 | `{"error":"unauthorized"}` | no |
| Malformed bearer | 401 | `{"error":"unauthorized"}` | no |
| Unknown issuer | 401 | `{"error":"unauthorized"}` | no |
| Invalid signature | 401 | `{"error":"unauthorized"}` | no |
| Expired | 401 | `{"error":"token_expired"}` + `WWW-Authenticate: Bearer error="invalid_token"` | no |
| No tenant resolution | 403 | `{"error":"forbidden"}` | no |
| API key `wzk_` prefix, no match | 401 | `{"error":"unauthorized"}` | no |
| Authenticated, WazuhError | 200, MCP error payload | safe code | yes, outcome=error |
| Authenticated, 429 upstream | 200, MCP error payload | `rate_limited` | yes |

**Invariants preserved from M1:**
- Tenant resolved from session only; no tool arg.
- Secrets never cross the tool-return boundary; `SecretValue` only inside the pool.
- Error bodies never echo upstream parse details.
- Audit on every authenticated exit path.

**New invariants in M2:**
- Pre-auth 401s never audit — single-line log only (prevents audit-log flood attacks).
- `contextvars.ContextVar` isolates sessions per asyncio task.
- JWKS refresh-on-unknown-kid runs exactly once per failing request.

## 6. Security Model

M1 primitives are inherited unchanged (strict Pydantic, `SecretValue`, error scrubbing, path-traversal guard, audit-to-stderr). This section covers M2's new surface only.

### OAuth validation
Every JWT is rejected unless ALL of:
1. `alg` in config allowlist (default `RS256,RS384,RS512,ES256,ES384,ES512` — never `none`, never symmetric).
2. Signature valid against a key from the cached JWKS (fetched from the issuer's `/.well-known/openid-configuration`).
3. `iss` matches `oauth.issuer` in `server.yaml` **exactly**.
4. `aud` contains `oauth.audience`.
5. `exp > now - clock_skew` (default 30s).
6. `nbf <= now + clock_skew` if present.
7. `iat` not more than `clock_skew` in the future.

Any failure → 401, reason never in body. `WWW-Authenticate: Bearer error="invalid_token"` header per RFC 6750.

### JWKS cache hygiene
- TTL: 10 minutes. Refresh-on-miss only (no background refresh in M2).
- On `kid not found`, force one refresh and retry verification. Still unknown → 401.
- JWKS fetch uses dedicated `httpx.AsyncClient`, 5s timeout, TLS verified against system trust. Custom CA support deferred to M4.
- Issuer's JWKS URL is derived from `/.well-known/openid-configuration` at startup — not operator-configured directly. Startup fails loudly if discovery fails.

### API-key path
- Format: `wzk_<tenant_id>_<base64url-32-bytes>`. Prefix lets `ChainSessionFactory` route without false positives against JWTs.
- Hashing: argon2id with OWASP 2024 parameters (`memory_cost=19456, time_cost=2, parallelism=1`).
- Store: `YamlApiKeyStore`. Each entry:
  ```yaml
  - key_id: wzk_acme_01
    hash: "$argon2id$v=19$m=19456,t=2,p=1$..."
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
  ```
- Revocation + expiry checked per call (in-memory store, O(1)).
- Key prefix `tenant_id` is a **routing hint only** — the store entry's `tenant_id` is authoritative. Crafted keys can't claim a tenant.

### Token / tenant consistency
- If JWT carries both a `tenant_id` claim AND the `iss` maps to a different tenant → 401 (mismatch). If the claim is present but no iss mapping exists → claim wins. If neither yields a tenant → 403.
- `aud` is NEVER used for tenant routing — cryptographic audience check only.

### Per-request isolation
- `contextvars.ContextVar[Session]` set by middleware, read by handlers. Python asyncio guarantees per-task isolation.
- Middleware `finally:` block resets the contextvar — defense against exceptions leaving stale state.
- `IndexerClientPool` entries are tenant-scoped, not session-scoped. Correct: credentials are tenant-level.

### Audit hygiene
- `user_id`, `tenant_id`, `auth_method` logged per call.
- Token / key value never logged.
- JWT `sub` logged (user identity). `jti` logged if present (useful for revocation audits).
- Control characters stripped from user-controlled claims before logging (prevents log injection).

### Explicit M2 non-goals
- No mTLS (reverse proxy's job if needed).
- No refresh-token handling server-side — client handles refresh; we only validate access tokens.
- No RFC 7662 token introspection — short-lived tokens are the story.
- No dynamic client registration endpoint on our side — the IdP handles it.
- No per-user MFA / step-up — the IdP does it.
- No rate limits — M4.

## 7. Testing Strategy

### Unit (pytest, no network)
New test files:
- `test_oauth_factory.py` — JWT verification table (bad alg / iss / aud / expired / nbf-future / tampered sig / `none` / HS256-with-RSA-pub / unknown kid forces refresh).
- `test_api_key_factory.py` — format parsing, argon2id verify, revocation, expiry, prefix-vs-store mismatch.
- `test_api_key_store.py` — YAML loader, duplicate key_ids rejected, malformed hash rejected.
- `test_chain_factory.py` — token-shape routing: `wzk_` → ApiKey, JWT → OAuth, garbage → 401.
- `test_issuer_index.py` — registry reverse-index correctness, duplicate issuers rejected.
- `test_indexer_pool.py` — lazy init, same-tenant share, different-tenant distinct, idempotent close-all, no credential leak.
- `test_session_ctx.py` — contextvar isolation across simulated concurrent tasks.
- `test_oauth_http_mw.py` — ASGI middleware: bearer extraction, factory dispatch, contextvar set/clear, `WWW-Authenticate` header on pre-auth 401, no audit emit.
- `test_protected_resource_metadata.py` — RFC 9728 body shape; single authorization_server.
- `test_healthz_readyz.py` — liveness always 200; readiness 503 until JWKS discovery succeeds + tenant registered, then 200.

Updated:
- `test_server_wiring.py` — adds HTTP-mode wiring test; stdio-mode tests unchanged.

Fixtures (new in `tests/conftest.py` or dedicated `tests/fixtures/`):
- `jwt_factory` — builds signed JWTs with arbitrary claims against an in-memory RSA keypair; paired with a matching JWKS dict.
- `fake_session_factory` — returns a canned `Session` for tool tests that shouldn't re-test auth.

### Integration (`@integration`)
Extended `docker/integration-compose.yml` adds Keycloak 26 alongside Wazuh indexer. Shared bootstrap seeds a realm `wazuh-mcp`, a confidential client, two users, and audience `wazuh-mcp-api`.

New integration tests (`tests/integration/test_oauth_e2e.py`):
- `test_search_alerts_with_valid_oauth_token` — full happy path.
- `test_search_alerts_rejects_expired_token` — short-lived test token.
- `test_wrong_audience_rejected`.
- `test_api_key_happy_path`.
- `test_concurrent_different_tenants_isolated` — assert pool + session isolation end-to-end.

Existing M1 integration tests run unchanged in stdio mode.

### Security negatives (`tests/security/test_m2_negatives.py`)
No Keycloak needed — uses `jwt_factory` + fake JWKS endpoint.
- `test_alg_none_rejected`.
- `test_hs256_with_public_key_rejected`.
- `test_kid_unknown_refreshes_once`.
- `test_token_reuse_allowed` (no introspection in M2, documented).
- `test_pre_auth_does_not_audit`.
- `test_log_poisoning_in_user_id_claim` — `sub` with `\n` / ANSI → single-line stripped audit.

### Out of scope for M2 testing (conscious)
- Load test.
- Chaos test on JWKS (IdP downtime) — M4.
- Fuzz test on metadata endpoint — static JSON.
- MCP-level behavioral evals — M5.

### CI
- Default CI job runs unit + security-negatives. Integration suite (needs Keycloak + Wazuh pull, multi-GB) stays local / dedicated runner. Document `make integration-tests`.

## 8. Scale & Deployment

### Shape
- Distroless non-root image; adds `uvicorn[standard]` + `authlib`. ~15 MB growth.
- Single uvicorn worker default. Multi-worker safe but needs shared JWKS cache — YAGNI; one worker handles hundreds of concurrent sessions.
- Reverse proxy: reference `Caddyfile` in `docker/reverse-proxy/`. TLS termination + ACME renewal. Forwards to `mcp:8000`. uvicorn runs with `--proxy-headers`.
- Entry points:
  - `wazuh-mcp` (stdio, unchanged from M1)
  - `wazuh-mcp --transport http` or `transport: http` in `server.yaml`
- CLI precedence: flag > env var > `server.yaml`.

### Posture
- Per-tenant `IndexerClient`, each with httpx default pool (100 keepalive conns). Ample up to ~50 tenants per process.
- JWKS cache: one entry (one issuer), 10-min TTL, ~1 KB memory.
- API-key store: loaded once, in-memory argon2id verify O(1). ~5 MB for 10k keys.
- Session contextvar: per-asyncio-task, no accumulation.
- Audit: synchronous stderr write. Sufficient for M2 scale; M4 adds async sink + ring buffer.

### Observability (M2 minimum)
- Structured JSON logs to stdout (stdio mode writes to stderr; audit contract from M1 unchanged).
- `/healthz` — liveness (process up, event loop live). 200 always.
- `/readyz` — liveness + readiness (JWKS discovery OK + ≥1 tenant registered). 503 until ready, then 200.
- **No metrics / no tracing** — M4.

### Deploy docs (new in M2)
- `docs/deploy/m2-http.md` — docker-compose with Caddy + MCP + Wazuh, env vars, OAuth wiring.
- `docs/deploy/oauth-setup/keycloak.md`.
- `docs/deploy/oauth-setup/okta.md`.
- `docs/deploy/oauth-setup/entra.md`.
- `docs/deploy/oauth-setup/auth0.md`.
- `docs/deploy/api-keys.md` — generate, hash, add, rotate, revoke.

### M2 ship-blockers (DoD)
- All M1 tests green.
- ~40 new unit tests green.
- ~8 security-negative tests green.
- ~5 Keycloak integration tests green.
- Manual end-to-end: Claude Desktop → remote MCP URL (behind Caddy) → Keycloak OAuth → `search_alerts` returns seeded data.
- Deploy docs merged.
- M2 retro written before M3 starts.

## 9. Roadmap after M2

Unchanged from the original v1 design spec §9:
- **M3** — Full tool surface (~14 tools: `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*`), resources, prompts, toolsets. Server API client (port 55000, JWT lifecycle) lands here.
- **M4** — Production hardening: real `SecretStore` backends (AWS SM, Vault, sqlite_age), RBAC-aware `list_tools`, per-tenant rate limits, OTel, back-to-Wazuh audit sink, v2 write scaffolding disabled.
- **M5** — Ship-gate: eval harness ≥90%, Wazuh LTS matrix in CI, cross-tenant leak suite, full docs.

## 10. References

- M1 design spec: `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md`.
- M1 retro: `docs/superpowers/retros/2026-04-20-m1-retro.md`.
- MCP spec 2025-06-18 (OAuth 2.1, RFC 9728 protected-resource metadata, Streamable HTTP transport).
- RFC 6750 (bearer tokens), RFC 7591 (DCR — IdP's problem), RFC 9728 (OAuth 2.0 protected-resource metadata).
- `authlib.jose` — JWT/JWS/JWKS verification.
- Keycloak 26 docs (integration fixture reference IdP).
