# wazuh-mcp M4a — Production hardening (observability, access control, secrets)

Status: Design approved 2026-04-23. Supersedes the M4 section of `2026-04-20-wazuh-mcp-design.md` §9 for the hardening half of M4. Write-tools and formal toolset SDK support are deferred to M4b.

## 0. Scope split

M4 in the v1 design spec packed two different risk profiles into one milestone. This session decomposed it into:

- **M4a (this spec)** — additive hardening: real `SecretStore` drivers, RBAC-aware `list_tools`, per-tenant + per-session rate limits, OpenTelemetry + Prometheus, pluggable audit sinks, amd64 CI runner for integration tests, production `streamable_http_client` migration.
- **M4b (separate spec)** — write-tool surface (`isolate_agent`, `add/remove_agent_from_group`, `restart_agent`, `create/update_rule`, `run_active_response`), formal MCP toolset SDK support. Each write tool gated by `TenantConfig.write_allowlist` + `confirm:true` + double-audit + RBAC at `list_tools` time.

Each milestone ships its own plan, tag, and retro. M4a's tag is `v0.4.0-m4a`.

## 1. Goals and non-goals

**Goals.**

1. Replace the placeholder `SecretStore` surface with three production drivers (AWS Secrets Manager, HashiCorp Vault, age-encrypted local SQLite) against the existing M1 protocol.
2. Enforce per-tenant and per-session rate limits in front of every tool call; protect Wazuh's 300/min Server API cap; fail closed with `rate_limited`.
3. Filter `list_tools` by `Session.rbac_role` and guard `call_tool` with the same policy; default role set covers the common deploy shapes.
4. Emit OpenTelemetry spans + Prometheus metrics per MCP 2025-06-18 attribute conventions; bridge both via the OTel SDK's Prom exporter (single emission layer).
5. Swap `AuditEmitter` (stderr only) for a pluggable, fan-out `MultiSinkAuditEmitter` with stdout / file / HTTP / back-to-Wazuh sinks, bounded async queues, best-effort retry with loss observability.
6. Run the M3 integration suite on an amd64 GitHub Actions runner on a nightly + manual-dispatch schedule; keep the existing arm64+darwin local skip marker for developer ergonomics.
7. Migrate the remaining production `streamablehttp_client` callsites to `streamable_http_client`.

**Non-goals.**

- Write tools of any kind (M4b).
- Horizontal scale / multi-replica state sharing (Redis-backed rate limiter, shared RBAC cache). The `RateLimiter` and `SecretStore` surfaces are protocol-shaped so a future swap is a driver change, not a callsite change.
- On-disk ring-buffer for audit events. The durability story is "operators configure the back-to-Wazuh sink and rely on Wazuh's own indexer for persistence," or "operators configure the `FileSink` and rely on the OS for persistence." No custom durable-write path in the MCP container.
- Real-Vault integration tests. Vault is unit-tested with `hvac` mocks in M4a; revisit if a deploy surfaces a bug that unit tests couldn't catch.
- A dockerized Vault in the integration fixture.
- OTLP endpoint defaults. Operators configure via standard OTel env vars; the server just wires the SDK.

## 2. Locked design decisions

### 2.1 `SecretStore` drivers

- **Libraries**: `aioboto3` for AWS (async-native); `hvac` + `asyncio.to_thread` for Vault (no mature async client; `aiohvac` is a community fork we avoid); `pyrage` + `aiosqlite` for the age-encrypted SQLite driver.
- **Secret-path convention**: `AWSSecretsManagerStore` and `VaultSecretStore` default to `wazuh-mcp/{tenant_id}/{key}` and `secret/data/wazuh-mcp/{tenant_id}/{key}` respectively, with an operator-configurable prefix via a new `TenantConfig.secret_prefix: str | None` field (customers with existing hierarchies plug in here). `secret_prefix` is only consumed by the AWS and Vault drivers; `SqliteAgeSecretStore` ignores it — schema is `(tenant_id TEXT, key TEXT, ciphertext BLOB, PRIMARY KEY(tenant_id, key))`.
- **Auth / config**: AWS defaults to ambient IAM via boto3's credential chain; explicit `aws_access_key_id` / `aws_secret_access_key` / `aws_region` via env for dev. Vault defaults to `VAULT_ADDR` + `VAULT_TOKEN`; AppRole (`role_id` / `secret_id`) supported as an explicit config option. `SqliteAgeSecretStore` reads a DB path and an age identity file path from env or config.
- **Caching**: a separate `CachingSecretStore(inner, ttl_seconds=300)` wrapper in `secrets/caching.py`, opt-in by wiring it in `build_app` / `build_http_app`. Invalidation: TTL expiry plus an explicit `.invalidate(tenant_id, key)` hook. Keeps the three drivers pure.
- **Error mapping**: secret missing → `not_found`; auth failure (expired IAM creds, revoked Vault token, wrong age key) → `auth_expired`; backend down / timeout → `upstream_error` / `upstream_timeout`. No new entries in `SAFE_CODES`.
- **Testing**: AWS driver end-to-end through `aioboto3` against `moto` (dev-dep). Vault driver unit tests mock `hvac.Client` at the call boundary. SQLite+age driver runs a real `pyrage` round-trip against a tempdir SQLite + ephemeral age keypair. Caching wrapper tested against an in-memory fake inner store (TTL, invalidation, concurrent gets are single-flight).

### 2.2 Rate limits

- **Protocol**: new `RateLimiter` protocol in `rate_limit/limiter.py`: `async acquire(tenant_id, session_id) -> None` (raises `WazuhError(code="rate_limited")` on denial). One in-process implementation, `InProcessRateLimiter`, backed by a `TokenBucket` primitive.
- **State**: in-process dict `{tenant_id: TokenBucket}` and `{(tenant_id, session_id): TokenBucket}`, guarded by `asyncio.Lock`. Single-process deploy today; swapping to Redis is a new driver implementing the protocol.
- **Defaults**: tenant bucket capacity 250, refill 4.17 tokens/sec (≈250/60s, leaves 50/min headroom under Wazuh's 300/min cap). Session bucket capacity 60, refill 1.0 tokens/sec (≈1 req/sec sustained, reasonable for interactive analyst workflow).
- **Scope**: global per session — every tool call consumes exactly 1 token from both buckets. No per-tool weighting; revisit if a specific tool proves disproportionately expensive.
- **Failure**: fail closed → `WazuhError(code="rate_limited")` (already in `SAFE_CODES`). Records a `rate_limited_total{tenant,scope}` counter (scope is `tenant` or `session`).
- **Location**: applied by the `@instrumented_tool` decorator in `observability/decorators.py`, wrapped around every tool at registration time in `_register_everything`. One chokepoint, works identically for stdio and HTTP transports, uses the existing `CURRENT_SESSION` contextvar for tenant/session.
- **Config shape**: new `RateLimitConfig` Pydantic model:
  ```python
  class BucketConfig(BaseModel):
      capacity: int
      refill_per_sec: float
  class RateLimitConfig(BaseModel):
      tenant: BucketConfig = BucketConfig(capacity=250, refill_per_sec=4.17)
      session: BucketConfig = BucketConfig(capacity=60, refill_per_sec=1.0)
  ```
  Attached to `TenantConfig.rate_limit: RateLimitConfig`. Defaults apply if omitted.

### 2.3 RBAC-aware `list_tools`

- **Default role set** (global, operator-overridable per tenant):
  - `admin` → `*` (every registered tool; reserves write-tools for M4b without a code change).
  - `analyst` → `alerts.*`, `agents.*`, `vulnerabilities.*`, `mitre.*`, `hunt.*`, `fim.*`.
  - `readonly` → `alerts.*`, `agents.get_agent`, `agents.list_agents`, `vulnerabilities.*`, `mitre.*`, `fim.*`. No `hunt.*` (hunt can be expensive; reserve for analysts).
- **Override shape**: `TenantConfig.role_tool_allowlist: dict[str, list[str]] | None`. If present, entries fully replace the global default for that role within that tenant. If absent, the global default applies.
- **Pattern language**: prefix patterns (`alerts.*`) and exact names (`hunt.hunt_query`). Matching is literal prefix-with-dot for the wildcard case. No regex.
- **Unknown role**: deny all. Session with an unmapped `rbac_role` gets an empty `list_tools` response and every `call_tool` returns `forbidden`.
- **Enforcement — both points mandatory**:
  - **List-time filter**: responds to MCP `tools/list` with the filtered set. Pure UX — hides tools the client cannot call.
  - **Call-time guard**: the `@instrumented_tool` decorator checks policy before dispatch. Even a client that bypasses the list is rejected with `forbidden`. This is the security contract.
- **FastMCP probe**: an explicit task in the plan probes whether the installed FastMCP version exposes a list_tools filter hook (M3 Task 22 precedent for SDK discovery). Implement via the native hook if present; otherwise wrap the handler in `_register_everything`. Deliverable is the same either way.
- **Policy merge**: `rbac/policy.py` owns the defaults and the per-tenant override merge. `rbac/filter.py` implements the prefix+exact matcher and exposes `is_allowed(session: Session, tool_name: str) -> bool` for the guard.

### 2.4 Audit sinks

- **Emitter**: `observability/audit.py` refactors `AuditEmitter` into `MultiSinkAuditEmitter`. The existing stderr-as-default behaviour is preserved: when `audit_sinks` is empty, `[StderrSink()]` is installed. **Stderr default is load-bearing for stdio mode** — the server's stdout carries JSON-RPC frames, and any interleaved bytes corrupt the wire. A `StdoutSink` exists for HTTP-only deployments or operators with stdout-collecting log pipelines, but it is opt-in and unsafe to use under stdio transport.
- **Delivery**: fan-out. Each event enqueues to every configured sink's bounded `asyncio.Queue` without awaiting. Tool latency unaffected by sink latency.
- **Buffer**: per-sink `asyncio.Queue(maxsize=10_000)`; overflow drops oldest and emits `audit_dropped_total{sink,reason="overflow"}`.
- **Retry**: each sink's drain task wraps I/O in exponential backoff (base 100ms, 5 attempts); on final failure drops + emits `audit_dropped_total{sink,reason="delivery_failed"}`. Never propagates to the hot path.
- **Lifecycle**: drain tasks spawn in the FastMCP lifespan `startup` and cancel+drain in `shutdown`. Bootstrap wiring lives in `build_app` / `build_http_app`.
- **Sink implementations**:
  - `StderrSink` — JSON lines to stderr (safe default for stdio transport).
  - `StdoutSink` — JSON lines to stdout. **Unsafe under stdio MCP transport** (corrupts the JSON-RPC wire); opt-in and only sensible for HTTP-mode deploys or operators with stdout-collecting log pipelines.
  - `FileSink` — JSON lines to a path, with a simple size-based rotation (e.g. 100 MiB, keep last 5). Reuses the OS's filesystem persistence.
  - `HttpSink` — `POST` batches to an operator-configured webhook URL. Batch size and flush interval configurable.
  - `WazuhIndexerSink` — bulk writes to `{prefix}-YYYY.MM.DD` index (default prefix `wazuh-mcp-audit`). Uses the existing `IndexerClientPool` — no new credentials. Installs a hardcoded index template on first write (no dynamic mapping inference).
- **Config shape** (discriminated union on `kind`):
  ```yaml
  audit_sinks:
    - { kind: stderr }
    - { kind: file, path: /var/log/wazuh-mcp/audit.log, rotate_size_mb: 100, keep: 5 }
    - { kind: http, url: https://siem.example.com/ingest, batch: 50, flush_ms: 500 }
    - { kind: wazuh_indexer, index_prefix: "wazuh-mcp-audit" }
  ```
  Attached to `TenantConfig.audit_sinks: list[AuditSinkConfig]`. Empty list falls back to a single `StderrSink` for backward compat with the M3 default (stderr is the safe default under stdio transport).

### 2.5 OpenTelemetry + Prometheus

- **Emission**: OTel SDK is the single emission layer. Prometheus metrics are produced via `opentelemetry-exporter-prometheus`. No duplicate `prometheus_client` layer.
- **Spans**:
  - `mcp.tool.call` span per tool invocation, owned by `@instrumented_tool`. Attributes: `mcp.tool.name`, `mcp.session.id`, `mcp.tenant.id`, `mcp.user.id`, `mcp.outcome` (`ok` | `error` | `rate_limited` | `forbidden` | `auth_expired` | `not_found` | `upstream_error` | `upstream_timeout` | `invalid_query`). Duration captured via span timing.
  - `opentelemetry-instrumentation-httpx` auto-instruments outbound `IndexerClient` + `ServerApiClient` calls.
  - `opentelemetry-instrumentation-starlette` auto-instruments inbound HTTP requests. `SessionMiddleware` runs first so the request span gets tenant/session attributes enriched after auth.
- **Metrics** (via Prom exporter):
  - `mcp_tool_calls_total{tenant,tool,outcome}` — counter.
  - `mcp_tool_duration_seconds{tenant,tool}` — histogram (buckets 5 ms, 10, 25, 50, 100, 250, 500, 1 s, 2.5, 5, 10; covers fast-indexer and slow-server-api tails).
  - `wazuh_upstream_errors_total{tenant,upstream,code}` — counter; `upstream ∈ {indexer, server_api}`.
  - `jwt_refresh_total{tenant,result}` — counter; `result ∈ {ok, failed, preemptive}` (preemptive = 80%-lifetime refresh, failed = mint/refresh threw).
  - `rate_limited_total{tenant,scope}` — counter; `scope ∈ {tenant, session}`.
  - `audit_dropped_total{sink,reason}` — counter; `reason ∈ {overflow, delivery_failed}`.
- **Resource attributes**: `service.name=wazuh-mcp`, `service.version={__version__}`, `service.namespace=wazuh`.
- **Export**: OTLP endpoint configured exclusively via standard OTel env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_PROTOCOL`, etc). Server has no bespoke export config.
- **`/metrics` endpoint**:
  - HTTP mode: mounted at `/metrics` on the existing ASGI app. No auth — operators put this behind a private network. Returns Prometheus text format from the OTel→Prom exporter.
  - stdio mode: off by default. Opt in via env var `WAZUH_MCP_METRICS_ADDR=host:port` (e.g. `0.0.0.0:9464`) — spins up a separate tiny HTTP server inside the stdio process. Useful for local dev and Claude Desktop sessions.

### 2.6 QEMU / amd64 CI runner

- New workflow `.github/workflows/integration.yml`:
  - `runs-on: ubuntu-latest` (amd64).
  - Triggers: `schedule: cron "0 6 * * *"` (daily 06:00 UTC) + `workflow_dispatch` (manual).
  - Steps: checkout, install uv, install deps, run `bash docker/bootstrap.sh`, wait for health, run `uv run pytest -m integration`.
  - Publishes JUnit XML on failure for inspection.
- Existing `lint-and-unit` workflow unchanged on every PR (required status check).
- Local arm64+darwin path: a pytest collection hook registers `@pytest.mark.requires_manager` and auto-skips those tests when `platform.system() == "Darwin" and platform.machine() == "arm64"`. The `wazuh/wazuh-manager:4.9.0` image segfaults under QEMU on Apple Silicon; indexer-only integration tests (`alerts.*`, `hunt.*`, `fim.*`, `vulnerabilities.*`, `triage-last-hour`, oauth e2e) stay runnable locally.
- All integration tests that call `ServerApiClient` (`agents.*`, `mitre.*`, resources, `investigate-alert` / `agent-posture` prompts) get the `requires_manager` marker.

### 2.7 `streamable_http_client` migration

- Grep production code (`src/wazuh_mcp/**`) for the legacy `streamablehttp_client` symbol; update callsites to `streamable_http_client`. Expected footprint is 1-2 files based on M3 context. One commit.

### 2.8 Version discipline

- The first M4a commit bumps `pyproject.toml` from `0.3.0` to `0.4.0-dev` (explicit "-dev" suffix so a mid-milestone ambient build isn't mistaken for a release). Ship-time commit bumps to `0.4.0` and tags `v0.4.0-m4a`. The plan's first task is the version bump, not an afterthought at ship.

## 3. Module layout

```
src/wazuh_mcp/
  secrets/
    store.py                 # (existing) SecretStore protocol + SecretValue
    value.py                 # (existing)
    yaml_driver.py           # (existing) YAML-file dev driver
    aws_sm.py                # NEW — AWSSecretsManagerStore (aioboto3)
    vault.py                 # NEW — VaultSecretStore (hvac + to_thread)
    sqlite_age.py            # NEW — SqliteAgeSecretStore (pyrage + aiosqlite)
    caching.py               # NEW — CachingSecretStore(inner, ttl=300)
  rbac/                      # NEW package
    __init__.py
    policy.py                # ROLE_TOOL_ALLOWLIST defaults + per-tenant merge
    filter.py                # prefix+exact matcher, is_allowed(session, tool_name)
  rate_limit/                # NEW package
    __init__.py
    token_bucket.py          # TokenBucket primitive
    limiter.py               # RateLimiter protocol + InProcessRateLimiter
  observability/
    audit.py                 # REFACTOR — AuditEmitter → MultiSinkAuditEmitter
    sinks/                   # NEW subpackage
      __init__.py
      base.py                # AuditSink protocol + shared drain task helpers
      stdout.py
      file.py
      http.py
      wazuh_indexer.py
    otel.py                  # NEW — SDK bootstrap (TracerProvider, MeterProvider, exporters)
    instrumentation.py       # NEW — httpx + starlette auto-instrumentation wiring
    metrics.py               # NEW — Prom exporter + /metrics route factory
    decorators.py            # NEW — @instrumented_tool (rate_limit + RBAC + span + audit)
  server.py                  # EDIT — _register_everything wraps every tool in @instrumented_tool,
                             #        mounts /metrics, bootstraps OTel, swaps audit emitter.
  tenancy/
    config.py                # EDIT — TenantConfig gains secret_prefix, role_tool_allowlist,
                             #        rate_limit, audit_sinks.
  transport/
    http.py                  # EDIT — /metrics route, starlette instrumentation hook.
```

## 4. Request flow (tool call, HTTP mode)

```
incoming MCP tools/call
  → SessionMiddleware populates CURRENT_SESSION contextvar
  → starlette auto-instrumentation opens request span
  → FastMCP dispatches to @instrumented_tool-wrapped handler
      1. RBAC guard — rbac.filter.is_allowed(session, tool_name). Deny → WazuhError(forbidden).
      2. RateLimiter.acquire(tenant_id, session_id). Deny → WazuhError(rate_limited).
      3. tracer.start_span("mcp.tool.call") with tool/session/tenant/user attrs.
      4. original handler runs. Outbound IndexerClient / ServerApiClient calls auto-instrumented.
      5. MultiSinkAuditEmitter.emit(event) — non-blocking fan-out to every sink's queue.
      6. span.set_attribute("mcp.outcome", outcome). Meter records counter + histogram.
  → FastMCP returns Pydantic result → FastMCP promotes to MCP content.
  → response flows out through starlette span; OTel exports via OTLP; Prom scrapes /metrics.
```

Stdio mode is identical minus the starlette span (stdio has no HTTP request layer). Tool-level instrumentation still fires because the decorator is applied at registration inside `_register_everything`, which both transports share.

## 5. Config shape (TenantConfig additions)

```yaml
tenants:
  default:
    # ... existing M3 fields (wazuh_user_claim, etc) ...
    secret_prefix: "wazuh-mcp/"
    role_tool_allowlist:
      custom_role: ["alerts.*", "hunt.hunt_query"]
    rate_limit:
      tenant:  { capacity: 250, refill_per_sec: 4.17 }
      session: { capacity: 60,  refill_per_sec: 1.0  }
    audit_sinks:
      - { kind: stderr }
      - { kind: file, path: /var/log/wazuh-mcp/audit.log, rotate_size_mb: 100, keep: 5 }
      - { kind: wazuh_indexer, index_prefix: "wazuh-mcp-audit" }
```

All four new fields are optional. Omission preserves current M3 behaviour: no prefix, global-default RBAC, default bucket sizes, single stderr sink (stdio-safe).

## 6. Error mapping

No new codes; `SAFE_CODES` stays `{auth_expired, forbidden, rate_limited, invalid_query, upstream_error, not_found, upstream_timeout}`.

| Condition | Code |
|---|---|
| Secret missing from backend | `not_found` |
| Expired IAM creds, revoked Vault token, wrong age key | `auth_expired` |
| Backend down / network | `upstream_error` |
| Backend slow past deadline | `upstream_timeout` |
| RBAC deny at list-time | (tool not listed) |
| RBAC deny at call-time | `forbidden` |
| Rate-limit bucket empty | `rate_limited` |
| Audit sink delivery failure | (silent; `audit_dropped_total` only) |

## 7. Testing strategy

### 7.1 Unit tests

- **SecretStore drivers**: AWS end-to-end through `aioboto3` against `moto`; Vault mocks `hvac.Client` at the call boundary; SQLite+age is a real `pyrage` round-trip against a tempdir DB + ephemeral keypair. Caching wrapper covers TTL expiry, explicit invalidation, and single-flight behaviour (concurrent gets for the same key issue exactly one call to the inner store; other callers await the shared result).
- **Rate limits**: `TokenBucket` invariants (monotone refill, capacity clamp, concurrent `acquire` fairness under `asyncio.Lock`). `InProcessRateLimiter.acquire` with synthetic time.
- **RBAC**: `policy.py` merge logic (global default vs. per-tenant override). `filter.py` matcher — prefix, exact, unknown role, empty allowlist. **Hypothesis fuzz** over role names + pattern lists to verify no bypass via overlapping prefixes or case shenanigans (reuse M3's hunt_query fuzz template).
- **Audit sinks**: fan-out delivery to multiple mock sinks, bounded-queue overflow drops oldest, exponential backoff retry on `HttpSink` and `WazuhIndexerSink` failures, clean shutdown via lifespan teardown.
- **OTel / Prom**: in-memory span exporter asserts span names and attributes on each tool path. In-memory metric reader asserts counter increments and histogram observations. Prometheus text output format asserted against a regex per metric family.
- **Decorator composition**: tool dispatch exercises the full decorator stack against mock session/limiter/policy/audit/tracer — verifies order (RBAC first, then rate-limit, then span, then handler, then audit), and that each layer's failure mode short-circuits correctly.

### 7.2 Integration tests

Runs on amd64 via the new `integration.yml` workflow nightly + manual-dispatch.

- Existing M3 integration suite (all 17 tools + 3 resources + 3 prompts against the real stack) continues to pass.
- New M4a additions:
  - `/metrics` endpoint returns valid Prometheus text-format output that includes all six metric families after a handful of tool calls.
  - A tool call with a rate-limit exhausted tenant returns `rate_limited` and increments `rate_limited_total{scope="tenant"}`.
  - A tool call from a session with a role that doesn't allow the tool returns `forbidden` and is absent from that session's `tools/list` response.
  - The `WazuhIndexerSink` posts audit events to `wazuh-mcp-audit-YYYY.MM.DD`; a follow-up indexer query finds them.
  - Claim-allowlist integration: unchanged behaviour from M3 since OAuth flows aren't touched.

### 7.3 Out of scope

- Real Vault integration (unit-only for M4a; revisit if a deploy surfaces a bug mocks miss).
- Load tests against the rate limiter under high concurrency — unit fuzz covers correctness; production-shaped load testing is M5 scope.
- Claude Desktop tool-selection ergonomics against M4a — still an M5 eval concern.

## 8. Dependencies

New pins in `pyproject.toml`:

- Runtime: `aioboto3`, `hvac`, `pyrage`, `aiosqlite`, `opentelemetry-api`, `opentelemetry-sdk`, `opentelemetry-exporter-prometheus`, `opentelemetry-instrumentation-httpx`, `opentelemetry-instrumentation-starlette`.
- Dev-only: `moto[secretsmanager]`.

All pinned; `uv.lock` regenerated in the same commit as the `pyproject.toml` edit that introduces them.

## 9. Risk tiers

Per the M3 methodology (tier A = full dual-review, tier B = implementer-only + controller spot-check, batched adjacent tier-B tasks share one implementer dispatch).

**Tier A (security-critical, full review):**

1. RBAC filter + call-time guard (`rbac/policy.py` + `rbac/filter.py` + decorator wiring) — security contract. Incorrect matching or a merge bug leaks tools across roles.
2. Rate-limit decorator composition (`observability/decorators.py`) — mis-composition could drop the RBAC check, the audit emit, or the metric. Also the `@instrumented_tool` wrapper is the single point that converts to `WazuhError`; hot-path correctness matters.
3. Audit-sink queue semantics (`observability/audit.py` + `observability/sinks/base.py`) — drop/retry correctness affects write-tool auditability in M4b. If events are silently lost without the metric bump, the operator loses the loss signal.

**Tier B (batched, lighter review):**

- Each `SecretStore` driver (aws_sm, vault, sqlite_age, caching wrapper) — protocol-shaped, independent, tested against moto / hvac mocks / real pyrage respectively. Three drivers + wrapper in one or two implementer dispatches.
- OTel + Prom bootstrap + metric definitions (mechanical SDK wiring).
- `TenantConfig` field additions + loader updates.
- `integration.yml` workflow.
- `streamable_http_client` migration.
- Version bump to `0.4.0-dev`.
- Dependency adds + `uv.lock` regeneration.

## 10. Deliverables

- All unit tests green: `uv run pytest -q -m "not integration"`.
- All lint green: `uv run ruff check .` + `uv run ruff format --check .` + `uv run ty check .`.
- Integration suite green on amd64 CI (nightly run passes at least once during the milestone; manual-dispatch run passes on the ship commit).
- `pyproject.toml` at `0.4.0`, tagged `v0.4.0-m4a`, pushed with `git push origin main --tags`.
- Retro committed to `docs/superpowers/retros/2026-04-XX-m4a-retro.md` before M4b work starts.
- Optional but encouraged: operator docs updated — `docs/deploy/m4a-secrets.md` (per-driver setup), `docs/deploy/m4a-observability.md` (OTel env + Prom scrape config), `docs/deploy/m4a-audit.md` (sink configuration + Wazuh Dashboards index-pattern install for the back-to-Wazuh sink). These can ship in the same milestone or land as a follow-on batched dispatch.

## 11. Deferred to M4b (separate spec)

- Write tools: `isolate_agent`, `add_agent_to_group`, `remove_agent_from_group`, `restart_agent`, `create_rule`, `update_rule`, `run_active_response`.
- `confirm:true` flow; double-audit on write paths; per-write-tool RBAC tightening (write tools appear only for roles explicitly granted).
- `TenantConfig.write_allowlist` wiring (currently unused; M4b activates it).
- Formal MCP toolset SDK support (`meta={"toolset": "..."}` drives client-enabled subsets) — depends on the Python SDK catching up.

M4a leaves the seams in place: the RBAC default for `admin` is `*`, so M4b write tools are automatically gated to `admin` + any explicitly-granted role; the audit emitter is already pluggable, so M4b's double-audit is a one-line emit; the rate limiter already covers every tool at the decorator, so write tools inherit it without change.
