# Observability — OpenTelemetry, Prometheus, audit

wazuh-mcp emits OpenTelemetry traces and Prometheus metrics for every tool call, plus a structured audit event per call on every exit path. Configuration is entirely through environment variables (OTel) and `TenantConfig` (sinks). The hot path never blocks on sink latency.

## OpenTelemetry traces

The OTel SDK is initialised once per process via `init_otel(service_version=...)`. The `TracerProvider` is installed with a fixed resource:

- `service.name=wazuh-mcp`
- `service.version=<package version>`
- `service.namespace=wazuh`

These are hard-coded — operators must not try to override them. Dashboards and alert rules downstream expect exactly these values.

### Configure OTLP

Standard OTel env vars in the MCP process environment:

```
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.com:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <token>
```

If `OTEL_EXPORTER_OTLP_ENDPOINT` is unset the SDK silently drops spans — there is no default endpoint. Set a collector address in every environment where you want traces, including dev.

Supported protocols: `grpc` (4317) and `http/protobuf` (4318). Pick whichever your collector terminates.

See `src/wazuh_mcp/observability/otel.py`.

### Span semantics

Every tool call opens one span named `mcp.tool.call` with these attributes:

- `mcp.tool.name` — dotted tool name, e.g. `alerts.search_alerts`.
- `mcp.session.id` — OAuth `sub` or API-key identity.
- `mcp.tenant.id` — tenant the call is scoped to.
- `mcp.user.id` — currently the same as `mcp.session.id`; retained as a separate attribute for future divergence.
- `mcp.outcome` — set on exit to the same vocabulary as the `outcome` label on `mcp_tool_calls_total`.

`httpx` is auto-instrumented, so upstream calls to the Wazuh indexer and Server API appear as child `HTTP` spans on the same trace. In Jaeger or Tempo, filtering by `service.name=wazuh-mcp` and `mcp.tool.name=<tool>` gives a clean view of one tenant's tool calls plus their upstream fan-out. Starlette is instrumented on HTTP transport for inbound-request spans.

See `src/wazuh_mcp/observability/decorators.py` and `src/wazuh_mcp/observability/instrumentation.py`.

## Prometheus metrics

In HTTP mode the ASGI app mounts a `/metrics` route on the same bind as `/mcp`. Point Prometheus at it:

```yaml
scrape_configs:
  - job_name: wazuh-mcp
    metrics_path: /metrics
    scheme: https
    scrape_interval: 30s
    static_configs:
      - targets:
          - mcp.example.com:443
```

`/metrics` is **not** behind the OAuth chain or the API-key guard. That is intentional — metrics endpoints are expected to be network-scoped, not application-scoped. Put `/metrics` on a private address, bind Prometheus to the same network, and block external access at the reverse proxy:

```
mcp.example.com {
    @metrics path /metrics
    handle @metrics {
        @allowed remote_ip 10.0.0.0/8
        handle @allowed {
            reverse_proxy mcp:8000
        }
        respond 403
    }
    handle {
        reverse_proxy mcp:8000
    }
}
```

See `src/wazuh_mcp/observability/metrics.py`.

### Stdio-mode metrics endpoint

In stdio mode there is no ASGI app. To scrape a stdio-transport deployment set `WAZUH_MCP_METRICS_ADDR`:

```
WAZUH_MCP_METRICS_ADDR=127.0.0.1:9464
```

The address is `host:port`. Host defaults to `0.0.0.0` if you pass just `:9464`. Keep it on loopback or a private network — the side-car has no auth.

systemd drop-in:

```ini
# /etc/systemd/system/wazuh-mcp.service.d/metrics.conf
[Service]
Environment=WAZUH_MCP_METRICS_ADDR=127.0.0.1:9464
```

Docker Compose:

```yaml
services:
  wazuh-mcp:
    image: wazuh-mcp:1.0.0
    environment:
      WAZUH_MCP_METRICS_ADDR: "0.0.0.0:9464"
    ports:
      - "127.0.0.1:9464:9464"
```

### Metric families

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mcp_tool_calls_total` | counter | `tenant`, `tool`, `outcome` | One increment per tool invocation. `outcome` ∈ {`ok`, `error`, `forbidden`, `rate_limited`, `auth_expired`, `not_found`, `upstream_error`, `upstream_timeout`, `invalid_query`, `parse_error`, `cancelled`, `internal`}. |
| `mcp_tool_duration_seconds` | histogram | `tenant`, `tool` | End-to-end handler latency including RBAC, rate-limit acquire, audit submit. Buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s. |
| `wazuh_upstream_errors_total` | counter | `tenant`, `upstream`, `code` | Bumped when an upstream Wazuh call returns a mapped `WazuhError`. `upstream` ∈ {`indexer`, `server_api`}; `code` mirrors the error code. |
| `jwt_refresh_total` | counter | `tenant`, `result` | Server API JWT refresh attempts. `result` ∈ {`ok`, `error`}. A spike in `error` usually means the Server API service-account password is stale. |
| `mcp_rate_limit_drops_total` | counter | `tenant`, `scope` | Rate-limit denials. `scope` ∈ {`rate_limit:tenant`, `rate_limit:session`} — read directly from `WazuhError.scope` (M5b T-G1 — see "WazuhError.scope" below). |
| `mcp_audit_drops_total` | counter | `sink`, `tenant`, `reason` | Audit events that did not make it to their sink. `tenant` carries `<global>` / `<unknown>` / `<tenant_id>`. `reason` ∈ {`overflow`, `delivery_failed`}. |

Suggested alerts (operator-authored; not shipped):

```
sum(rate(mcp_tool_calls_total{outcome="auth_expired"}[5m])) by (tenant) > 0
sum(rate(mcp_rate_limit_drops_total[5m])) by (tenant) > 0.1
sum(rate(mcp_audit_drops_total[5m])) > 0
```

All counters and the histogram are defined in `m4_counters()`. Every label set is bounded — tenant and tool are closed sets per deploy, outcome is a small vocabulary.

## WazuhError.scope (v1.0.0)

Rate-limit and allowlist-deny errors carry a structured `scope` field on `WazuhError`. The metric label `mcp_rate_limit_drops_total{tenant, scope}` reads `err.scope` directly — no brittle substring-match against the error message.

Defined scope values:

| Scope | Source |
|---|---|
| `rate_limit:tenant` | `InProcessRateLimiter` denies on the per-tenant bucket |
| `rate_limit:session` | `InProcessRateLimiter` denies on the per-session bucket |
| `write_allowlist` | `_check_write_allowed` denies (server.py) |
| `ar_allowlist` | `run_active_response` denies — command not in `active_response_allowlist` |
| `ar_group_allowlist` | `run_active_response_on_group` denies — group not in `agent_group_allowlist`, OR `ar_group_allowlist_policy` is `None` |

Backwards-compat: positional 3-arg `WazuhError(code, message, status_code)` callers are unchanged. `scope` is keyword-only and defaults to `None`. Audit events surface `scope` as a top-level field on `outcome=error` events when populated:

```json
{
  "tool": "write.run_active_response",
  "tenant": "acme",
  "outcome": "error",
  "error_code": "forbidden",
  "scope": "ar_allowlist",
  "duration_ms": 0
}
```

## Audit emitter

Every tool call produces exactly one audit event on every exit path — `ok`, mapped `WazuhError`, validation error, internal exception, or cancellation. Events are structured JSON with a fixed schema. The emitter fans each event out to one or more sinks; the hot path never blocks on sink latency.

### Schema

| Field | Type | Notes |
|---|---|---|
| `timestamp` | ISO-8601 UTC | |
| `tool` | string | Dotted tool name (`alerts.search_alerts`, `write.isolate_agent`, `<rbac.resolve>` for resolver-miss). |
| `user` | string | OAuth `sub` or API-key identity. |
| `tenant` | string | Tenant id. |
| `rbac_role` | string | Effective role at call time. |
| `arg_hash` | string | sha256 over the sorted-key JSON of tool args. Stable across replays; does not leak argument values. |
| `outcome` | string | `ok` / `error` / `write.requested` (write tools only, pre-call). |
| `result_count` | int | 0 on errors and on scalar result models. |
| `duration_ms` | int | Milliseconds. 0 for `write.requested` and resolver-miss. |
| `error_code` | string? | Set only when `outcome=error`. One of `SAFE_CODES`. |
| `error_reason` | string? | Optional structured reason (e.g., `tenant_not_registered` for `<rbac.resolve>`). |
| `scope` | string? | Set only when the underlying `WazuhError` carried a scope (rate-limit + allowlist denials). |
| `event_id` | string | (v1.2+) Per-emit UUIDv4. Used as the OpenSearch `_id` on the bulk-index action so retries from `QueuedSink` upsert idempotently — no duplicate documents on partial-success bulk retry. |
| `request_id` | string? | (v1.2+) JSON-RPC id of the originating MCP request, populated from MCP SDK's `request_ctx`. Null for stdio transport (until plumbed) and for any emit outside an active MCP request scope (e.g. RBAC resolver-miss). |

### `MultiSinkAuditEmitter`

Dual-track:

- `global_sinks` — always-on. Defaults to `[StderrSink()]` — the operator safety net.
- `per_tenant_sinks: dict[tenant_id, list[AuditSink]]` — overlay. Empty list for unknown tenants.

`emit(session)` writes to globals + `per_tenant_sinks.get(session.tenant_id, [])`. Unknown tenants route to globals only — preserves visibility for the resolver-miss path.

See `multi-tenant.md` for the per-tenant fan-out details and `src/wazuh_mcp/observability/audit.py` for the implementation.

### Audit dedup (v1.2+)

Two fields work together to make retry-induced duplicates a non-issue:

- **`event_id`** is set as the OpenSearch `_id` on the bulk-index action. `op_type=index` (the default) upserts on `_id` collision — retries from `QueuedSink` post the same event with the same `event_id` and silently overwrite the existing doc instead of inserting a duplicate. End-effect: at-least-once delivery becomes effectively exactly-once at the index layer.
- **`request_id`** is queryable. If cross-replica observation overlap ever materializes (rare in practice — JSON-RPC clients use unique `id`s per request), operators dedup at query time:

```bash
curl -sku admin:admin "https://wazuh-indexer:9200/local-audit-*/_search" \
  -H 'Content-Type: application/json' -d '{
    "query": { "term": { "request_id": "rpc-77" } }
  }'
```

#### Index template + manual rollover

The Wazuh-indexer sink installs an index template declaring `event_id` and `request_id` as `keyword`. The template applies to **future** daily indices automatically. Existing indices written under v1.1 (which had `dynamic: false` and the older mapping) accept the new fields on writes but **won't field-index them until they roll**.

If you want the current day's index to reflect the new mapping immediately:

```bash
curl -sku admin:admin -X POST "https://wazuh-indexer:9200/local-audit-*/_rollover" \
  -H 'Content-Type: application/json' -d '{}'
```

This is **not required for correctness** — every operator query that doesn't filter on `event_id` or `request_id` keeps working without rollover. Skipping the rollover means new fields aren't queryable on the current day's docs but are queryable from tomorrow onward.

## Audit sinks

Configured per-tenant via `TenantConfig.audit_sinks`. If empty, the server installs a single `StderrSink` by default (via `global_sinks`).

| Sink | Transport safe under | Use for |
|---|---|---|
| `stderr` | stdio + HTTP | Default. Safe because stdio uses stdout for JSON-RPC frames; stderr is free. |
| `stdout` | **HTTP only** | Opt-in. Writing audit JSON to stdout under stdio corrupts the MCP wire. |
| `file` | stdio + HTTP | Self-hosted simple operators. Size-based rotation, bounded archive retention. |
| `http` | stdio + HTTP | Shipping to an external SIEM webhook (Splunk HEC, Sumo HTTP source, Datadog logs intake, generic webhook). Batched, retried with backoff. |
| `wazuh_indexer` | **HTTP only** | MSPs and in-house SOC teams who want MCP audit events visible inside Wazuh Dashboards alongside the rest of their Wazuh data. Requires the HTTP-mode indexer pool. |

Multiple sinks can coexist — a common production shape is `stderr` (journald capture) + `wazuh_indexer` (Wazuh Dashboards) + `http` (ship to the central SIEM). Each sink has its own bounded queue, so one slow sink does not stall the others or the tool handlers.

### Configuration

`audit_sinks` is a list of discriminated-union entries. The `kind` field picks the variant.

```yaml
tenants:
  - tenant_id: acme
    audit_sinks:
      - kind: stderr
      - kind: file
        path: /var/log/wazuh-mcp/acme.log
        rotate_size_mb: 100
        keep: 5
      - kind: http
        url: https://splunk.acme.internal:8088/services/collector/raw
        batch: 50
        flush_ms: 500
        max_attempts: 5
      - kind: wazuh_indexer
        index_prefix: acme-audit
        batch: 100
        flush_ms: 1000
        max_attempts: 5
```

Field reference per variant:

- `stderr` — no fields.
- `stdout` — no fields.
- `file` — `path` (required, `Path`), `rotate_size_mb` (default 100, 1..10000), `keep` (default 5, 0..100).
- `http` — `url` (required, `HttpUrl`), `batch` (default 50), `flush_ms` (default 500), `max_attempts` (default 5). The sink POSTs a JSON array; upstream must accept an array body.
- `wazuh_indexer` — `index_prefix` (default `wazuh-mcp-audit`), `batch` (default 100), `flush_ms` (default 1000), `max_attempts` (default 5). Writes via `_bulk` through the tenant's existing indexer client pool; no extra credentials.

See `src/wazuh_mcp/tenancy/m4_config.py` for authoritative field definitions and `src/wazuh_mcp/observability/sinks/` for implementations.

## QueuedSink wrapper

`http` and `wazuh_indexer` sinks wrap a `QueuedSink` for the bounded-queue + drain-task pattern. Two loss modes, both surfaced via `mcp_audit_drops_total`:

- **`reason="overflow"`** — the per-sink queue hit `maxsize` (default 10 000) before the drain task could deliver. The emitter evicts the oldest event to make room. Causes: sustained burst exceeding sink throughput, or an intermittently-slow sink. Remediation:
  - Raise `maxsize` (more headroom at the cost of memory).
  - Speed up the sink. For `http`, lower `batch` or point at a closer endpoint. For `wazuh_indexer`, check cluster health.
  - Split high-volume tenants into their own MCP deploy.
- **`reason="delivery_failed"`** — the sink tried `max_attempts` times (default 5) with exponential backoff and the upstream stayed unavailable. Event is dropped at that point. Causes: SIEM collector down, Wazuh indexer cluster unreachable, TLS trust drift. Remediation:
  - Check sink health.
  - Raise `max_attempts` only if upstream recovery time is predictable; otherwise fix upstream.
  - Keep a secondary sink (e.g. `stderr` or `file`) so transient SIEM outages don't lose the audit trail irrecoverably.

`mcp_audit_drops_total > 0` is the only operator-visible signal of audit loss. Alert on it.

## Wazuh Dashboards setup (`wazuh_indexer` sink)

`WazuhIndexerSink` writes one event per tool call to a daily index `{index_prefix}-YYYY.MM.DD` using the tenant's existing indexer credentials (no new service account). On first use it installs an index template that pins the mapping — `timestamp` is a date, everything else is a keyword — so dashboards and saved searches can filter and aggregate without dynamic-mapping drift.

**M5b T-G5b note.** The index template's pattern now matches `index_prefix` exactly (tenant-specific patterns like `acme-audit-*` are picked up correctly). Earlier versions hard-coded `wazuh-mcp-audit-*`; deployments using non-default `index_prefix` should re-roll the index template by deleting the existing template (`DELETE _index_template/wazuh-mcp-audit-template`) and letting the sink reinstall it with the correct pattern on the next event.

In Wazuh Dashboards:

1. **Management → Stack Management → Index Patterns**.
2. **Create index pattern**.
3. Enter `<index_prefix>-*` (e.g. `acme-audit-*`).
4. Pick `timestamp` as the primary time field.
5. Save.

Useful saved searches:

- **Denied tool calls** — `outcome:error AND error_code:forbidden`.
- **Rate-limited tenants** — `outcome:error AND error_code:rate_limited` (group by `scope`).
- **Expired upstream auth** — `outcome:error AND error_code:auth_expired`.
- **Slow tool calls** — `duration_ms:>2000`.
- **Per-analyst activity** — `user:"<oauth-sub>"` sorted by `timestamp` descending.
- **Resolver-miss path** — `tool:"<rbac.resolve>" AND error_reason:tenant_not_registered`.
- **Write requests** — `tool:write.* AND outcome:"write.requested"`.

See `src/wazuh_mcp/observability/sinks/wazuh_indexer.py`.

## Concurrency model

`AuditEmitter.emit` is synchronous and non-blocking:

1. Build the event dict in the calling task.
2. For each sink, call `sink.submit(event)`.
3. `submit` enqueues on the sink's bounded `asyncio.Queue` with drop-oldest overflow handling. No awaits, no I/O.

Each sink owns a background drain task started in `start()`. The drain task pulls from the queue and calls `_deliver` (file write, HTTP POST, indexer `_bulk`, stream write) with exponential backoff and bounded attempts. On shutdown the drain task gets a chance to flush within `shutdown_timeout_s` (default 5 s), then is cancelled.

Operator consequences:

- Tool latency is unaffected by sink latency. A stuck SIEM webhook does not slow a single `alerts.search_alerts` call.
- Audit delivery is eventually-consistent within the queue depth and the drain task's throughput. Do not expect synchronous delivery semantics.
- Process crashes lose whatever is still queued. If strict durability matters, add a `file` sink as a local spool alongside the network sink.

See `src/wazuh_mcp/observability/audit.py` and `src/wazuh_mcp/observability/sinks/base.py`.
