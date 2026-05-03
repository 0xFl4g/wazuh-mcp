# Install + first-run

wazuh-mcp ships in three install paths: a `uv sync` dev install (stdio transport), a Docker container (HTTP transport), and a Helm chart (Kubernetes). All three share the same `config/` directory layout. This guide walks each path and the first-run smoke.

## Install paths

| Path | Transport | When to use |
|---|---|---|
| `uv sync` | stdio (default) or HTTP | Local dev, single-tenant, Claude Desktop integration. |
| Docker container | HTTP | Self-hosted multi-tenant, behind Caddy or another reverse proxy. |
| Helm chart | HTTP | Kubernetes — see `helm.md` for the full chart guide. |

Pick the path that matches your deployment shape; config files are interchangeable across them.

## Prerequisites

- Python 3.12+ (for the `uv sync` path).
- Docker + Docker Compose (for the container path; also for the integration test suite).
- A reachable Wazuh manager (port 55000) and Wazuh indexer (port 9200) — either local or remote.
- An OIDC issuer for OAuth-based MCP client auth (HTTP transport only). API keys are the alternative — see `api-keys.md`.

## Path 1: `uv sync`

```
uv sync
```

This creates a virtualenv with the package and its runtime deps. Run the server with:

```
WAZUH_MCP_CONFIG_DIR=./config uv run wazuh-mcp
```

The `wazuh-mcp` entry point speaks MCP over stdio by default. To run HTTP transport:

```
WAZUH_MCP_CONFIG_DIR=./config uv run wazuh-mcp serve
```

For Claude Desktop integration, add to the desktop config:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "uv",
      "args": ["run", "--project", "/abs/path/to/wazuh-mcp", "wazuh-mcp"],
      "env": { "WAZUH_MCP_CONFIG_DIR": "/abs/path/to/wazuh-mcp/config" }
    }
  }
}
```

For Claude Code, use `claude mcp add` with the equivalent shape:

```
claude mcp add wazuh-mcp \
    --command uv \
    --arg run --arg --project --arg /abs/path/to/wazuh-mcp --arg wazuh-mcp \
    --env WAZUH_MCP_CONFIG_DIR=/abs/path/to/wazuh-mcp/config
```

## Path 2: Docker container (HTTP)

A typical production-style topology runs uvicorn behind Caddy with OAuth in front of `/mcp`:

```
  Claude client
       │
       ▼  HTTPS (ACME cert via Caddy)
┌─────────────────┐
│   Caddy         │   terminates TLS, forwards to mcp:8000
└─────────────────┘
       │
       ▼
┌─────────────────┐
│   wazuh-mcp     │   uvicorn, ASGI, /mcp + /healthz + /readyz
│   + auth chain  │         + /.well-known/oauth-protected-resource
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Wazuh indexer   │   OAuth IdP (Keycloak / Okta / Entra / Auth0)
└─────────────────┘
```

`docker-compose.yml`:

```yaml
services:
  mcp:
    image: ghcr.io/0xFl4g/wazuh-mcp:1.0.0
    environment:
      - WAZUH_MCP_CONFIG_DIR=/etc/wazuh-mcp
    volumes:
      - ./wazuh-mcp:/etc/wazuh-mcp:ro
    restart: unless-stopped

  caddy:
    image: caddy:2-alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on: [mcp]
    restart: unless-stopped

volumes:
  caddy_data:
```

`Caddyfile`:

```
mcp.example.com {
    reverse_proxy mcp:8000
}
```

Caddy handles ACME automatically. For internal/staging setups, add `{ auto_https off }` and run behind an internal cert.

## Path 3: Helm chart

See `helm.md` for the full chart guide, including the bring-your-own-Secret pattern, opt-in NetworkPolicy / ServiceMonitor / Ingress, and the explicit single-replica HA caveat.

## Config directory layout

All three install paths read configuration from a config directory (`WAZUH_MCP_CONFIG_DIR` env var; defaults to `./config`):

```
config/
  server.yaml          # transport + auth + global oauth + api-keys path
  tenants.yaml         # per-tenant TenantConfig entries
  secrets.yaml         # YAML secret store (dev only) — replace with KMS in production
  api_keys.yaml        # API key registry, mode 0600 (optional)
```

For real secret backends (AWS Secrets Manager, HashiCorp Vault, SQLite + age), see `secrets.md`.

### `server.yaml`

Stdio (single-tenant local dev):

```yaml
active_tenant: local
user_id: alice
```

HTTP (multi-tenant, OAuth-fronted):

```yaml
transport: http
auth: oauth_chain
http:
  bind: "0.0.0.0:8000"
  public_url: "https://mcp.example.com"
oauth:
  issuer: "https://idp.example.com/realms/msp"
  audience: "wazuh-mcp-api"
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256, ES256]
  clock_skew_seconds: 30
api_keys_file: /etc/wazuh-mcp/api_keys.yaml
```

For the OAuth chain in detail (issuer routing, JWKS, IssuerIndex, `wazuh_user` claim), see `oauth.md`.

### `tenants.yaml`

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    verify_tls: true
    ca_bundle_path: /etc/wazuh-mcp/ca/acme.pem
    default_rbac_role: soc_analyst
    oauth_issuer: https://idp.example.com/realms/msp
    oauth_audience: wazuh-mcp-api
```

For the full `TenantConfig` schema (every field, validator, semantics), see `tenants.md`.

### `secrets.yaml` (dev only)

```yaml
acme:
  indexer_user: mcp-reader
  indexer_password: "pw-1"
```

`chmod 0600` and own as the MCP service user. Production deployments replace this with a KMS-backed driver — see `secrets.md`.

### `api_keys.yaml`

See `api-keys.md` for the format and generation.

## Stdio transport (single-tenant default)

Stdio is the default transport. The server reads JSON-RPC frames from stdin and writes responses to stdout — exactly the shape Claude Desktop / Claude Code consume natively. Stderr is reserved for logs and audit emission (the default `stderr` audit sink).

Key constraints under stdio:
- Single-tenant only. The `active_tenant` field in `server.yaml` selects which `TenantConfig` to use.
- No `/metrics` endpoint by default — set `WAZUH_MCP_METRICS_ADDR` to expose a side-car. See `observability.md`.
- No OAuth — the session is "the operator". `user_id` in `server.yaml` is the audited identity.

## HTTP transport (multi-tenant)

HTTP transport runs uvicorn on the address in `server.yaml`'s `http.bind` and exposes:

- `POST /mcp` — the Streamable HTTP transport endpoint. OAuth-fronted (or API-key fronted) per `auth_chain`.
- `GET /healthz` — `{"status":"ok", "rate_limiter": {...}}` once the process is up. The `rate_limiter` field reflects backend + breaker state — see `redis.md` for the field shape.
- `GET /readyz` — `{"status":"ok"}` once JWKS has been fetched for every configured issuer.
- `GET /.well-known/oauth-protected-resource` — the RFC 8707 protected-resource metadata document.
- `GET /metrics` — Prometheus scrape endpoint, NOT behind the auth chain. Network-scope it. See `observability.md`.

Multi-tenancy is implicit: each tenant in `tenants.yaml` gets its own indexer + Server API pool, its own RBAC + write/AR/AR-group allowlists, its own rate-limit bucket, and its own audit-sink fan-out. See `multi-tenant.md` for the structural guarantees.

## First-run smoke

Health probes:

```
curl https://mcp.example.com/healthz                                  # → {"status":"ok", "rate_limiter": {"backend": "in_process", "redis": "disabled"}}
curl https://mcp.example.com/readyz                                   # → {"status":"ok"} once JWKS fetched
curl https://mcp.example.com/.well-known/oauth-protected-resource     # → resource + authorization_servers
```

Authenticated MCP `initialize` call:

```
TOKEN=$(get-a-token-from-your-idp)
curl -X POST https://mcp.example.com/mcp \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"curl","version":"0.1"}}}'
```

A successful initialize returns the server's capability set + `serverInfo`. From there, `tools/list` enumerates every tool callable for the session's tenant + role.

## Sizing (HTTP transport)

- ~50 tenants / 100 concurrent sessions per uvicorn worker is comfortable.
- Add workers behind Caddy with `uvicorn --workers N` (shared JWKS cache is per-worker; acceptable at the cost of N× discovery fetches at startup).
- For > 500 tenants, consider per-IdP sharding (multiple deployments).

## Where to go next

- OAuth setup per IdP — `oauth.md` + `oauth-setup/{keycloak,okta,entra,auth0}.md`.
- API-key generation — `api-keys.md`.
- Tenant config reference — `tenants.md`.
- Read tools — `tools.md`.
- Write tools — `writes.md`.
- Multi-tenant guarantees — `multi-tenant.md`.
- Secrets — `secrets.md`.
- Observability — `observability.md`.
- Quality gates — `quality-gates.md`.
- Helm chart — `helm.md`.
- Full per-tool API — `../api-reference.md`.
