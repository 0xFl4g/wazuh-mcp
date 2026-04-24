# M4a — Audit sinks

## Overview

Every tool call produces exactly one audit event on every exit path — `ok`, mapped `WazuhError`, validation error, internal exception, or cancellation. Events are structured JSON with a fixed schema (`timestamp`, `tool`, `user`, `tenant`, `rbac_role`, `arg_hash`, `outcome`, `result_count`, `duration_ms`, optional `error_code`). The emitter fans each event out to one or more sinks; the hot path never blocks on sink latency.

## Pick sinks per deploy shape

One or more sinks per tenant, configured via `TenantConfig.audit_sinks`. If the list is empty, the server installs a single `StderrSink` by default.

| Sink | Transport safe under | Use for |
|---|---|---|
| `stderr` | stdio and HTTP | Default. Safe because stdio uses stdout for JSON-RPC frames; stderr is free. |
| `stdout` | **HTTP only** | Opt-in. Writing audit JSON to stdout under stdio corrupts the MCP wire. Only pick this when you run in HTTP mode and collect logs from stdout. |
| `file` | stdio and HTTP | Self-hosted simple operators. Size-based rotation, bounded archive retention. |
| `http` | stdio and HTTP | Shipping to an external SIEM webhook — Splunk HEC, Sumo HTTP source, Datadog logs intake, generic webhook. Batched, retried with backoff. |
| `wazuh_indexer` | **HTTP only** | MSPs and in-house SOC teams who want MCP audit events visible inside Wazuh Dashboards alongside the rest of their Wazuh data. Requires the HTTP-mode indexer pool. |

Multiple sinks can coexist — a common production shape is `stderr` (journald capture) + `wazuh_indexer` (Wazuh Dashboards) + `http` (ship to the central SIEM). Each sink has its own bounded queue, so one slow sink does not stall the others or the tool handlers.

## Configure `audit_sinks`

`audit_sinks` is a list of discriminated-union entries in `TenantConfig`. The `kind` field picks the variant.

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: soc_analyst
    audit_sinks:
      - kind: stderr
      - kind: file
        path: /var/log/wazuh-mcp/audit.log
        rotate_size_mb: 100
        keep: 5
      - kind: http
        url: https://splunk.acme.internal:8088/services/collector/raw
        batch: 50
        flush_ms: 500
        max_attempts: 5
      - kind: wazuh_indexer
        index_prefix: wazuh-mcp-audit
        batch: 100
        flush_ms: 1000
        max_attempts: 5
```

One `kind: stdout` example, for HTTP-mode only:

```yaml
audit_sinks:
  - kind: stdout
```

Field reference per variant:

- `stderr` — no fields.
- `stdout` — no fields.
- `file` — `path` (required, `Path`), `rotate_size_mb` (default 100, 1..10000), `keep` (default 5, 0..100). When `path` exceeds `rotate_size_mb`, the file shifts to `.1`, older archives shift up to `.keep`, anything beyond is deleted.
- `http` — `url` (required, `HttpUrl`), `batch` (default 50), `flush_ms` (default 500), `max_attempts` (default 5). The sink POSTs a JSON array; upstream must accept an array body.
- `wazuh_indexer` — `index_prefix` (default `wazuh-mcp-audit`), `batch` (default 100), `flush_ms` (default 1000), `max_attempts` (default 5). Writes via `_bulk` through the tenant's existing indexer client pool; no extra credentials.

See `src/wazuh_mcp/tenancy/m4_config.py` for the authoritative field definitions and `src/wazuh_mcp/observability/sinks/` for the implementations.

## Set up `wazuh_indexer` in Wazuh Dashboards

`WazuhIndexerSink` writes one event per tool call to a daily index `{index_prefix}-YYYY.MM.DD` using the tenant's existing indexer credentials (no new service account). On first use it installs an index template that pins the mapping — `timestamp` is a date, everything else is a keyword — so dashboards and saved searches can filter and aggregate without dynamic-mapping drift.

Stored fields (mirror the emitter schema exactly):

- `timestamp` — ISO-8601 UTC.
- `tool` — dotted tool name, e.g. `alerts.search_alerts`.
- `user` — session user id (OAuth `sub` or API-key identity).
- `tenant` — tenant id.
- `rbac_role` — effective role at call time.
- `arg_hash` — sha256 over the sorted-key JSON of tool args. Stable across replays; does not leak argument values.
- `outcome` — `ok` or `error`.
- `result_count` — integer; 0 on errors and on scalar result models.
- `duration_ms` — integer milliseconds.
- `error_code` — set only when `outcome=error`; one of the codes listed in `m4a-observability.md` under `mcp_tool_calls_total.outcome`.

In Wazuh Dashboards:

1. Navigate to **Management → Stack Management → Index Patterns**.
2. Click **Create index pattern**.
3. Enter `wazuh-mcp-audit-*` as the pattern.
4. Pick `timestamp` as the primary time field.
5. Save.

Useful saved searches to seed the team:

- **Denied tool calls** — `outcome:error AND error_code:forbidden` — RBAC mistakes and role drift.
- **Rate-limited tenants** — `outcome:error AND error_code:rate_limited` — tenants that need a bigger bucket.
- **Expired upstream auth** — `outcome:error AND error_code:auth_expired` — service-account passwords close to rotation.
- **Slow tool calls** — `duration_ms:>2000` — index hotspots or Server API backpressure.
- **Per-analyst activity** — `user:"<oauth-sub>"` sorted by `timestamp` descending.

See `src/wazuh_mcp/observability/sinks/wazuh_indexer.py`.

## Watch for loss

Every `QueuedSink` has two loss modes, both surfaced via `audit_dropped_total{sink, reason}` (see `m4a-observability.md`):

- `reason="overflow"` — the per-sink queue hit `maxsize` (default 10 000) before the drain task could deliver. The emitter evicts the oldest event to make room. Causes: a sustained burst exceeding sink throughput, or a sink that is intermittently slow. Remediation:
  - Raise `maxsize` (buy more headroom at the cost of memory).
  - Speed up the sink. For `http`, lower `batch` or point at a closer endpoint. For `wazuh_indexer`, check cluster health and per-node shard load.
  - Split high-volume tenants into their own MCP deploy.
- `reason="delivery_failed"` — the sink tried `max_attempts` times (default 5) with exponential backoff and the upstream stayed unavailable. Event is dropped at that point. Causes: SIEM collector down, Wazuh indexer cluster unreachable, TLS trust drift. Remediation:
  - Check sink health with the same probe your SRE dashboards use.
  - Raise `max_attempts` only if the upstream recovery time is predictable; otherwise fix the upstream.
  - Keep a secondary sink (e.g. `stderr` or `file`) so transient SIEM outages don't lose the audit trail irrecoverably.

`audit_dropped_total > 0` is the only operator-visible signal of audit loss. Alert on it.

## Concurrency model

`AuditEmitter.emit` is synchronous and non-blocking:

1. Build the event dict in the calling task.
2. For each sink, call `sink.submit(event)`.
3. `submit` enqueues on the sink's bounded `asyncio.Queue` with drop-oldest overflow handling. No awaits, no I/O.

Each sink owns a background drain task started in `start()`. The drain task pulls from the queue and calls `_deliver` (file write, HTTP POST, indexer `_bulk`, stream write) with exponential backoff and bounded attempts. On shutdown the drain task gets a chance to flush within `shutdown_timeout_s` (default 5 s), then is cancelled.

The consequences for operators:

- Tool latency is unaffected by sink latency. A stuck SIEM webhook does not slow a single `alerts.search_alerts` call.
- Audit delivery is eventually-consistent within the queue depth and the drain task's throughput. Do not expect synchronous delivery semantics.
- Process crashes lose whatever is still queued. If strict durability matters, add a `file` sink as a local spool alongside the network sink.

See `src/wazuh_mcp/observability/audit.py` and `src/wazuh_mcp/observability/sinks/base.py`.
