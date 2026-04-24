# M4a — Observability

## Overview

wazuh-mcp emits OpenTelemetry traces and Prometheus metrics for every tool call, plus a small set of ambient counters (JWT refreshes, rate-limit denials, audit drops). Traces go out via OTLP; metrics are scraped from the process over HTTP. Configuration is entirely through environment variables — the service resource attributes are fixed and operators never touch them.

## Configure OTLP for traces

The OTel SDK is initialised once per process via `init_otel(service_version=...)`. The `TracerProvider` is installed with a fixed resource:

- `service.name=wazuh-mcp`
- `service.version=<package version>`
- `service.namespace=wazuh`

These are hard-coded. Operators must not try to override them — the dashboards and alert rules downstream expect exactly these values.

The span exporter is wired by the SDK based on the standard OTel env vars. Set them in the MCP process environment:

```
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.com:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <token>
```

If `OTEL_EXPORTER_OTLP_ENDPOINT` is unset the SDK silently drops spans — there is no default endpoint. Set a collector address in every environment where you want traces, including dev.

Supported protocols: `grpc` (4317) and `http/protobuf` (4318). Pick whichever your collector terminates.

See `src/wazuh_mcp/observability/otel.py`.

## Scrape Prometheus metrics

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
# Caddyfile fragment
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

## Expose metrics under stdio

In stdio mode there is no ASGI app, so `/metrics` does not exist by default. To scrape a stdio-transport deployment set `WAZUH_MCP_METRICS_ADDR` and the server starts a side-car HTTP server on a background thread (prometheus_client's `start_http_server`):

```
WAZUH_MCP_METRICS_ADDR=127.0.0.1:9464
```

The address is parsed as `host:port`. Host defaults to `0.0.0.0` if you pass just `:9464`. Keep it on loopback or a private network — the side-car has no auth.

systemd drop-in example:

```ini
# /etc/systemd/system/wazuh-mcp.service.d/metrics.conf
[Service]
Environment=WAZUH_MCP_METRICS_ADDR=127.0.0.1:9464
```

Docker Compose example:

```yaml
services:
  wazuh-mcp:
    image: wazuh-mcp:0.3.0
    environment:
      WAZUH_MCP_METRICS_ADDR: "0.0.0.0:9464"
    ports:
      - "127.0.0.1:9464:9464"
```

Prometheus scrape target in stdio mode becomes `127.0.0.1:9464` (or whatever you bound).

## Metric families

All counters and the one histogram are defined in `m4_counters()`. Every label set is bounded — tenant and tool are closed sets per deploy, outcome is a small vocabulary. No high-cardinality free-text labels.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mcp_tool_calls_total` | counter | `tenant`, `tool`, `outcome` | One increment per tool invocation. `outcome` is one of `ok`, `error`, `forbidden`, `rate_limited`, `auth_expired`, `not_found`, `upstream_error`, `upstream_timeout`, `invalid_query`, `parse_error`, `cancelled`, `internal`. |
| `mcp_tool_duration_seconds` | histogram | `tenant`, `tool` | End-to-end handler latency including RBAC, rate-limit acquire, and audit submit. Buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s. |
| `wazuh_upstream_errors_total` | counter | `tenant`, `upstream`, `code` | Bumped when an upstream Wazuh call (indexer or Server API) returns a mapped `WazuhError`. `upstream` is `indexer` or `server_api`; `code` mirrors the error code. |
| `jwt_refresh_total` | counter | `tenant`, `result` | Server API JWT refresh attempts. `result` is `ok` or `error`. A spike in `error` usually means the Server API service account password is stale. |
| `rate_limited_total` | counter | `tenant`, `scope` | Rate-limit denials. `scope` is `tenant` (shared bucket) or `session` (per-user bucket). |
| `audit_dropped_total` | counter | `sink`, `reason` | Audit events that did not make it to their sink. `reason` is `overflow` (queue full) or `delivery_failed` (upstream unavailable past `max_attempts`). See `m4a-audit.md` for remediation. |

Suggested alerts (operator-authored; not shipped):
- `sum(rate(mcp_tool_calls_total{outcome="auth_expired"}[5m])) by (tenant) > 0` — tenant credentials expiring.
- `sum(rate(rate_limited_total[5m])) by (tenant) > 0.1` — tenant sustained over their budget.
- `sum(rate(audit_dropped_total[5m])) > 0` — audit trail lossy; something is wrong with a sink.

## Span semantics

Every tool call opens one span named `mcp.tool.call` with these attributes:

- `mcp.tool.name` — dotted tool name, e.g. `alerts.search_alerts`.
- `mcp.session.id` — OAuth `sub` or API-key identity.
- `mcp.tenant.id` — tenant the call is scoped to.
- `mcp.user.id` — currently the same as `mcp.session.id`; retained as a separate attribute for future divergence.
- `mcp.outcome` — set on exit to the same vocabulary as the `outcome` label on `mcp_tool_calls_total`.

`httpx` is auto-instrumented, so upstream calls to the Wazuh indexer and Server API appear as child `HTTP` spans on the same trace. In Jaeger or Tempo, filtering by `service.name=wazuh-mcp` and `mcp.tool.name=<tool>` gives a clean view of one tenant's tool calls plus their upstream fan-out. Starlette is instrumented on HTTP transport for inbound-request spans.

See `src/wazuh_mcp/observability/decorators.py` and `src/wazuh_mcp/observability/instrumentation.py`.
