# Wazuh MCP Server — Design Spec

**Date:** 2026-04-20
**Status:** Brainstorming output, pending plan
**Audience:** Implementer of v1; reviewer validating scope before implementation planning.

## 1. Purpose & Scope

Build a production-grade Model Context Protocol (MCP) server fronting Wazuh (SIEM/XDR) deployments so SOC analysts can triage, investigate, and hunt via Claude.

**Primary deployment model:** MSSP (Managed Security Service Provider). One MCP service, many customer tenants, mixed infrastructure per tenant.

**v1 posture:** read-only. Writes (active response, rule changes, agent lifecycle) are scaffolded but disabled; enabled per-tenant in v2.

## 2. Product Decisions (from brainstorming)

| # | Decision | Choice |
|---|---|---|
| Q1 | User / runtime | MSSP / multi-tenant, shared hosted service |
| Q2 | Tenant-to-Wazuh mapping | Hybrid: dedicated Wazuh stack for large tenants; shared cluster with RBAC for smaller |
| Q3 | Action scope | Phased — read-only v1, write tools behind per-tenant allowlist in v2 |
| Q4 | End-user auth | OAuth 2.1 primary, API-key fallback |
| Q5 | Stack | Python + official `mcp` SDK (FastMCP-style) |
| Q6 | Per-tenant Wazuh credentials | Pluggable `SecretStore` (AWS Secrets Manager, Vault, encrypted SQLite) |
| Q7 | v1 tool surface | Triage + hunt (~14-16 tools) |

## 3. Architecture

Single Python process exposing MCP over **Streamable HTTP** (primary, team deployments) with an optional **stdio** entry point (local analyst use in Claude Desktop; dev/debug).

```
Analyst (Claude client)
   │  OAuth 2.1 (PKCE)  ──or──  API key
   ▼
┌─────────────────────────────────────────────┐
│        Wazuh MCP Server (Python)            │
│                                             │
│  Auth layer ──▶ Session(user, tenant, role) │
│                              │              │
│                              ▼              │
│                       Tool layer            │
│                    (triage + hunt)          │
│                              │              │
│                              ▼              │
│   Wazuh client factory (per-session)        │
│   fetches creds from SecretStore,           │
│   applies run_as auth-context,              │
│   manages JWT refresh                       │
│          │                      │           │
│          ▼                      ▼           │
│   ServerAPI (55000)     IndexerAPI (9200)   │
│   per tenant            per tenant          │
└─────────────────────────────────────────────┘

SecretStore (pluggable: AWS SM / Vault / enc-SQLite)
TenantRegistry (tenant_id → endpoints, auth mode, RBAC)
AuditLog (structured JSON, shippable back to customer Wazuh)
```

**Invariants:**

- **Stateless tool handlers.** Every call resolves tenant + creds from the session; no in-memory tenant state on handlers.
- **Session-pinned tenant.** A session talks to exactly one tenant, set at auth time (OAuth claim or API-key binding). No tool accepts `tenant_id` as an argument. Prevents cross-tenant leaks by construction.
- **Toolsets** per MCP spec 2025-06-18: `alerts.*`, `agents.*`, `vulnerabilities.*`, `hunt.*`, `mitre.*`, `fim.*`. Clients can enable subsets; RBAC further restricts which tools appear at `list_tools` time.

## 4. Components

Module-by-module. Each has a single purpose, clear interface, and is independently testable.

### `auth/`
- `oauth.py` — OAuth 2.1 resource-server flow per MCP spec (PKCE, dynamic client reg, RFC 9728 metadata endpoint). Validates bearer tokens against configured IdP JWKS.
- `api_key.py` — fallback: 256-bit random, stored as argon2id hash. Format `wzk_<tenant>_<random>` so leaks are triageable. Rotation without downtime; revocation list checked each call.
- `session.py` — `Session(user_id, tenant_id, rbac_role, auth_method)` built at connect, attached to every tool invocation.

### `tenancy/`
- `registry.py` — `TenantRegistry` interface returning `TenantConfig(endpoints, auth_mode, tls_ca, default_rbac_role, write_allowlist)`. YAML-backed and DB-backed drivers ship in v1.
- `router.py` — session → (stack, run_as role) resolution.

### `secrets/`
- `store.py` — `SecretStore` protocol: `get(tenant_id, key) -> SecretValue`. Drivers: `aws_sm.py`, `vault.py`, `sqlite_age.py`. TTL-bound cache. Secrets never cross the tool-result boundary.

### `wazuh/`
- `server_api.py` — async `httpx` client for port 55000. JWT lifecycle: fetch, track expiry, proactive refresh at 80% lifetime, retry-once on 401. `run_as` auth-context support.
- `indexer.py` — async client for port 9200. OpenSearch DSL builder helpers; `_search` with `search_after` cursor pagination; server-enforced `size` cap (100), `terminate_after` (10k), 30s timeout; clamped time range (max 30-day lookback v1); strips `_source` noise by default.
- `models.py` — strict Pydantic: `Alert`, `Agent`, `Vulnerability`, `FimEvent`, `MitreTechnique`. Version-aware field mapping (handles 4.8+ vuln index rename).
- `errors.py` — maps upstream errors to safe, scrubbed MCP errors (no schema/trace leakage). Safe codes only: `auth_expired`, `rate_limited`, `invalid_query`, `forbidden`, `upstream_error`.

### `tools/` (v1: ~14-16 tools)
- `alerts.py` — `search_alerts`, `get_alert`, `alerts_by_agent`, `alerts_by_mitre`.
- `agents.py` — `list_agents`, `get_agent`, `agent_processes`, `agent_packages`, `agent_ports`.
- `vulns.py` — `list_vulnerabilities_by_agent`, `search_vulnerabilities` (by CVE, severity, CVSS).
- `mitre.py` — `get_mitre_technique`, `search_mitre`.
- `hunt.py` — `hunt_query` (structured `{field, op, value}` clauses from an allowlist; DSL is built server-side, never accepted raw), `pivot_by_ioc` (hash/IP/user/domain).
- `fim.py` — `fim_history_for_path`, `fim_changes_by_agent`.

### `resources/` (stable reference data)
- `wazuh://rules/{id}`, `wazuh://mitre/technique/{id}`, `wazuh://agents/{id}/config` — cacheable reads Claude can attach without burning a tool call.

### `prompts/` (user-invokable IR playbooks)
- `/wazuh:investigate-alert {alert_id}`, `/wazuh:triage-last-hour`, `/wazuh:agent-posture {agent_id}`.

### `observability/`
- `audit.py` — one structured JSON event per tool call: `{timestamp, session_id, user, tenant, tool, arg_hash, result_count, duration, outcome}`. Args are sha256-hashed (IOCs can themselves be sensitive). Pluggable sinks: stdout, file, HTTP, back-to-customer-Wazuh. Async non-blocking with bounded disk ring-buffer if sink is down.
- `otel.py` — OpenTelemetry spans per MCP spec attributes.

### `server.py`
Entry point. Dependency-injects the above; selects transport (stdio vs Streamable HTTP) from config.

## 5. Data Flow (representative call)

*Analyst asks: "show me critical alerts in the last hour on the Acme tenant."*

```
1. Client connects
   POST /mcp   Authorization: Bearer <OAuth token>
   → auth.oauth.validate() → Session(user=alice, tenant=acme, role=soc_analyst)
   → initialize handshake; tool list filtered to Acme's enabled toolsets + role

2. Claude selects a tool
   call: search_alerts(time_range="1h", min_level=12, size=25)
   → Pydantic strict-validates input (extra='forbid')
   → Audit: {tool: search_alerts, tenant: acme, user: alice, arg_hash: sha256(...)}

3. Tenant resolution
   tenancy.router.resolve(session.tenant_id)
   → TenantConfig{stack: shared_cluster_east, indexer: https://..., run_as_role: acme_analyst}

4. Credential fetch
   secrets.store.get(tenant_id=acme, key=indexer_basic_auth)
   → SecretValue (in-memory, TTL bound); never logged

5. Wazuh call
   wazuh.indexer.search(
     index="wazuh-alerts-*",
     query=build_bool({"range": {"timestamp": "now-1h"}, "range": {"rule.level": {"gte": 12}}}),
     size=25, sort=[{"timestamp":"desc"}],
     _source=DEFAULT_ALERT_FIELDS
   )
   → 200 with hits + opaque search_after cursor

6. Shape response
   models.Alert.from_hit(...) → strict Pydantic
   MCP response:
     structuredContent: {alerts: [...], total, next_cursor, truncated}
     text: concise human summary: "24 critical alerts; top rules: ssh_brute_force (8), ..."

7. Audit closes out
   {outcome: ok, result_count: 24, duration_ms: 142}
```

**Invariants reinforced by the flow:**
- Tenant resolved from session, never from tool args. Prevents confused-deputy.
- Credentials live only on the call stack; never in a tool return, never in an error.
- Every response carries both `structuredContent` (chaining) and a short `text` summary (Claude's reasoning) per MCP 2025-06-18.
- Pagination is cursor-based; `size` is server-capped.
- Time range always clamped; no unbounded scans over `wazuh-alerts-*`.

**Error paths:**
- 401 (JWT expired) → transparent refresh + retry once; if still 401, surface `auth_expired`.
- 403 (RBAC partial denial) → partial result with `forbidden_count: N`; do not fail tool.
- 429 → surface `rate_limited` with `retry_after_s`.
- OpenSearch parse error → `invalid_query` with offending field name only, never raw exception.

## 6. Security Model

### Authentication
- OAuth 2.1 primary: RFC 9728 `/.well-known/oauth-protected-resource`; JWKS-validated bearer; PKCE mandatory; RFC 7591 dynamic client reg.
- API-key fallback: 256-bit random, argon2id-hashed, `wzk_<tenant>_<random>` format, rotatable, per-call revocation-list check.
- mTLS optional at reverse proxy for customers that want it.

### Tenant isolation
- Session bound to exactly one tenant at auth time. No tool accepts a tenant argument.
- No shared Wazuh clients across tenants. Clients are session-scoped and disposed at session close.
- `SecretStore` lookups are scoped by tenant_id at the interface.

### Credential hygiene
- Wazuh JWT and basic-auth creds stay inside `wazuh/`. `SecretValue.__repr__` and `__str__` return `<redacted>`. Explicit test: no model carrying a secret field can be JSON-serialized.
- Error paths scrub; only safe error codes sent over MCP.
- Logs redact by pattern (`Authorization`, `token=`, `password=`, basic-auth headers) before emit.

### Input validation
- Every tool input: strict Pydantic, tight enums, regex for IDs.
- Agent IDs, CVE IDs, tenant IDs validated before any Wazuh call.
- `hunt_query` accepts structured clauses only. Allowlisted ops and fields. Server builds DSL. `script`, `runtime_mappings`, `script_score`, painless — unreachable.
- `size` ≤ 100 hard cap; `terminate_after: 10_000`; time range required and clamped to 30-day lookback.

### Authorization / least privilege
- Wazuh `run_as` auth-context carries end-user identity to Wazuh's audit log where supported.
- Per-tenant `write_allowlist` gates v2 write tools; empty in v1. Write tools scaffolded but not registered when allowlist is empty.
- RBAC-aware `list_tools`: disallowed tools don't appear; Claude won't try what it can't see.

### Rate limiting
- Per-session token bucket (60 req/min, burst 20).
- Per-tenant token bucket upstream of Wazuh (tighter — protects Wazuh's 300/min cap).
- Indexer: 30s timeout + `terminate_after` cap per query.

### Auditing
- One structured JSON event per tool call. Args sha256-hashed.
- Auth events (login, refresh, revocation) emitted separately.
- Events shippable back to customer's Wazuh — customers see MCP activity in their SIEM.

### Supply chain / deploy
- Distroless non-root container, read-only rootfs.
- Pinned lockfile, `pip-audit` + `safety` in CI, dependabot on.
- Egress restricted to configured Wazuh endpoints + IdP JWKS + SecretStore.

### v1 non-goals (explicit, to prevent scope creep)
- No raw OpenSearch DSL passthrough.
- No write/mutation tools.
- No cross-tenant joins or "all my tenants" tools.
- No prompt-injection defense beyond input validation (indirect prompt injection via ingested alert content is called out as user-education concern, not solved at MCP layer).

## 7. Testing Strategy

### Unit (pytest, no network)
- Pydantic strict-mode boundaries, version-aware vuln field mapping.
- Query builder: structured input → DSL snapshot tests. Confirms no forbidden clauses producible.
- Secret redaction: `hypothesis` property test — secrets never appear in `repr`, `str`, `json.dumps`, log formatter output.
- Error mapper fixtures: no internal info leaks.
- JWT lifecycle: 200 / 401-expired / 401-still-expired / 429 / 403-partial paths.
- Rate limiter math under burst.
- Tenant router resolution across dedicated + shared-cluster configs.
- RBAC-aware `list_tools`: role → visible tool set.

### Integration (pytest + docker-compose, `@integration`)
- Real Wazuh single-node stack (manager + indexer), synthetic seed data (alerts, agents, vulns, FIM).
- Every tool end-to-end. Assert `structuredContent` shape and `next_cursor` presence.
- JWT expiry end-to-end (short `auth_token_exp_timeout`).
- Partial RBAC denial: restricted user; confirm `forbidden_count > 0` without exception.
- Pagination cursor correctness under concurrent index writes.
- Self-signed cert handling: valid CA bundle + invalid; never silent `verify=False`.
- CI matrix: Wazuh current LTS + latest.

### MCP-level evals (mcp-evals-style harness)
- ~40 `(NL prompt, expected tool call)` pairs covering triage + hunt.
- Selection accuracy, arg correctness, pagination behavior.
- Nightly (slow, model-dependent); PR-gate a smaller smoke subset.
- Ship-block: ≥ 90% selection accuracy.

### Security tests
- Per-tool negative: oversized inputs, control chars, regex-bypass, injected JSON, oversized `size`, time-range overflow, path traversal in resource URIs.
- Cross-tenant isolation: session bound to tenant A runs every tool; confirm no tenant B data leakable, including via errors.
- `pip-audit` / `safety` in CI.
- Secret-leak scanner on integration log corpus (basic-auth, JWT, `password=` patterns).

### Not tested in v1
- Chaos/fault injection (v2 when remote HTTP hardens).
- Load testing (defer until a real customer deploys).
- Prompt injection via ingested alert content (out of scope for MCP layer).

## 8. Scale & Deployment

### Shape
- Single async Python process (`uvicorn` ASGI). Horizontally scalable behind a sticky-session LB.
- Distroless non-root container, read-only rootfs, env + mounted-file config, no shell.
- stdio entry point `uvx wazuh-mcp` for local/Claude-Desktop use; same codebase, different transport.
- `/healthz` (liveness) and `/readyz` (reach SecretStore + at least one Wazuh) separate from `/mcp`.

### Posture
- Per-session JWT cache; proactive refresh at 80% lifetime.
- Per-tenant `httpx.AsyncClient` pools sized from `TenantConfig`.
- Indexer queries: `size ≤ 100`, `terminate_after: 10_000`, 30s timeout. Never scan; always filter + cap + aggregate.
- Per-tenant rate buckets upstream of Wazuh's 300/min cap.
- Audit sink async non-blocking; bounded disk ring-buffer if sink is down.

### Observability
- OTel traces: Claude → MCP → Wazuh, correlated by `mcp.session.id`. OTLP exporter default.
- Structured JSON logs to stdout.
- Prometheus metrics: `mcp_tool_calls_total{tenant,tool,outcome}`, `mcp_tool_duration_seconds`, `wazuh_upstream_errors_total`, `jwt_refresh_total`, `rate_limited_total`, `secret_fetch_duration_seconds`.
- Built-in `wazuh-mcp eval --corpus ./evals/` for CI regression gate.

## 9. Roadmap

### v2 (write tools, plumbing already scaffolded in v1)
Enabled per-tenant via `write_allowlist`. Each v2 tool requires:
1. Tenant listed in `write_allowlist` for that tool.
2. `confirm: true` arg in the tool schema.
3. Double-audit: pre-write intent + post-write outcome.
4. Role check: only `write_roles` see the tool at `list_tools` time.

Priority order:
- `isolate_agent` (active-response firewall-drop, agent-scoped).
- `add_agent_to_group` / `remove_agent_from_group`.
- `restart_agent`.
- `create_rule` / `update_rule` (file edit + manager restart).
- `run_active_response` (generic AR with allowlisted commands).

### v3+
- Cross-tenant analytics (MSSP-wide views; separate aggregation tier).
- Streaming alert subscriptions (MCP subscription/notification surface).
- LLM-assisted rule tuning.
- Compliance toolset expansion (SCA, PCI/HIPAA/NIST views).
- Full admin surface (decoders CRUD, cluster management).

## 10. Ship-blockers for v1

- Full tool-corpus eval ≥ 90% selection accuracy against Claude.
- Integration suite green against current Wazuh LTS.
- Cross-tenant leak suite green.
- `pip-audit` clean.
- Secret-leak scanner green on integration log corpus.
- Docs complete: README, per-tool reference, deploy guide (docker-compose + k8s Helm), OAuth setup guide for Okta / Entra / Keycloak.

## 11. Wazuh-Specific Gotchas to Keep in Mind During Implementation

From research — these bit existing Wazuh MCP projects and must be handled:

- **JWT 15-min default expiry** — proactive refresh; retry-once on 401.
- **Self-signed certs** in default deployments — explicit CA bundle config per tenant; never silent `verify=False`.
- **Alert volume (up to 100k/s at scale)** — always push filters server-side; cap `size`; prefer aggregations over hits; use `search_after`, not deep `from`. Respect `index.max_result_window` (10_000).
- **Daily index rollover** — always query the `wazuh-alerts-*` pattern, not a specific date; clamp time range.
- **Cluster vs single-node** — some Server API endpoints are master-only (return code 3013 on workers). Use `?nodes_list=` where relevant.
- **RBAC partial denials** — common and expected; surface as structured partial result, not error.
- **`run_as` vs service-account auth** — use `run_as` auth-context so Wazuh's own audit attributes actions to end-users, not to the MCP service account.
- **Active-response is fire-and-forget** (v2) — Server API returns 200 once queued; confirm via later alert with `rule.groups: active_response`.
- **Field-name churn across Wazuh versions** — 4.8 moved vulnerability state from Server API to indexer and renamed fields. Version-gate mappings in `wazuh/models.py`.
- **`wazuh-archives-*` disabled by default** — don't assume it exists.
- **Server API rate limit 300/min IP-based** — batch via indexer where possible; per-tenant bucket upstream to avoid starving.
- **`limit=100000` cap theoretical**; practical cap ~500 — always paginate with cursors.

## 12. References

- MCP spec 2025-06-18 (current stable), 2025-11 draft.
- Wazuh documentation: Server API reference, RBAC reference, Indexer.
- Reference implementations: GitHub `github-mcp-server` (toolsets, OAuth); Cloudflare MCP servers (Workers + OAuth 2.1); Sentry `sentry-mcp` (per-user scoping, structured output); `modelcontextprotocol/servers` baseline.
- Existing Wazuh MCP projects surveyed for gaps: lack of cursor pagination, no JWT lifetime tracking, silent TLS bypass, no RBAC-aware tool gating, no multi-cluster support.
