# M2 — Remote HTTP deployment

This guide walks through a production-style wazuh-mcp deployment: uvicorn behind Caddy, with OAuth 2.1 in front of the `/mcp` endpoint and an API-key fallback for clients without an IdP.

## Topology

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

## Files you'll create

- `/etc/wazuh-mcp/server.yaml` (see below)
- `/etc/wazuh-mcp/tenants.yaml`
- `/etc/wazuh-mcp/secrets.yaml`  (mode 0600)
- `/etc/wazuh-mcp/api_keys.yaml` (mode 0600)
- `/etc/caddy/Caddyfile`

## server.yaml

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

## tenants.yaml

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

(Add one entry per customer tenant. If tenants live behind different IdPs, one MCP deployment per IdP.)

## secrets.yaml

```yaml
acme:
  indexer_user: mcp-reader
  indexer_password: "pw-1"
```

Chmod 0600 and owned by the MCP service user. Production deployments should replace this with a KMS-backed driver in M4.

## api_keys.yaml

See `docs/deploy/api-keys.md` for how to generate entries.

## Caddyfile

```
mcp.example.com {
    reverse_proxy mcp:8000
}
```

Caddy handles ACME automatically. For internal/staging setups, add `{ auto_https off }` and run behind an internal cert.

## docker-compose deployment

```yaml
services:
  mcp:
    image: ghcr.io/0xFl4g/wazuh-mcp:0.2.0
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

## Verifying the deployment

```
curl https://mcp.example.com/healthz          # → {"status":"ok"}
curl https://mcp.example.com/readyz           # → {"status":"ok"} once JWKS fetched
curl https://mcp.example.com/.well-known/oauth-protected-resource
# {"resource":"https://mcp.example.com",
#  "authorization_servers":["https://idp.example.com/realms/msp"], ...}
```

Smoke-test an authenticated call:

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

## Sizing

- ~50 tenants / 100 concurrent sessions per uvicorn worker is comfortable.
- Add workers behind Caddy with `uvicorn --workers N` (shared JWKS cache is per-worker; acceptable at the cost of N× discovery fetches at startup).
- For > 500 tenants, consider per-IdP sharding (multiple deployments).

## Known gaps (v1 / M2)

- No rate limiting in-process. Let Caddy do coarse-grained DOS protection.
- No OTel / metrics; M4 adds both.
- No refresh-token handling server-side — clients handle token refresh.
- No mTLS on the MCP endpoint; use Caddy + client certs if you need it.

## Next steps

- OAuth setup per IdP: `docs/deploy/oauth-setup/{keycloak,okta,entra,auth0}.md`.
- API-key generation: `docs/deploy/api-keys.md`.
