# OAuth 2.1 authentication

wazuh-mcp authenticates MCP clients via OAuth 2.1 bearer tokens (with API keys as a fallback — see `api-keys.md`). This document covers the OIDC discovery + JWKS validation flow, the per-tenant config surface, the IssuerIndex semantics that govern tenant routing, and the `wazuh_user` claim mapping for `run_as` attribution.

For IdP-specific setup, see `oauth-setup/{keycloak,okta,entra,auth0}.md`.

## OIDC discovery + JWKS

At boot the OAuth chain fetches the OIDC discovery document for every distinct issuer in `tenants.yaml`:

```
GET <issuer>/.well-known/openid-configuration
```

From the discovery document the chain follows `jwks_uri` and caches the JWKS in-process. Each MCP worker holds its own JWKS cache (no shared cache across uvicorn workers). At `/readyz`, the chain reports `ok` only after the first JWKS fetch completes for every configured issuer.

Token validation per inbound request:
1. Parse the `Authorization: Bearer <token>` header.
2. Read the JWT header `kid`; look up the matching JWK in the cached JWKS for the token's `iss`.
3. Verify signature with one of the configured algorithms (default `RS256`, `ES256`).
4. Verify `aud` against the matched tenant's `oauth_audience`.
5. Verify `exp` / `nbf` with `clock_skew_seconds` slack (default 30 s).
6. Mint a `Session` from the verified claims.

The chain refreshes JWKS on a `kid` cache miss (handles IdP key rotation) and falls back to deny on signature/audience/expiry failure with `WazuhError("auth_expired", ...)`.

## Configure the chain

`server.yaml`:

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

Per-tenant overrides on `TenantConfig`:

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: soc_analyst
    oauth_issuer: https://idp.example.com/realms/msp
    oauth_audience: wazuh-mcp-api
    wazuh_user_claim: wazuh_user        # default; override if your IdP names the claim differently
```

`oauth_issuer` and `oauth_audience` are optional. If unset, the tenant inherits the global `oauth.issuer` / `oauth.audience` from `server.yaml`. Set them explicitly when one MCP deploy serves multiple IdPs (rare, but supported when each tenant lives in its own realm).

If tenants live behind genuinely different IdPs (separate vendor accounts), the cleaner pattern is one MCP deployment per IdP. The `IssuerIndex` (below) handles a single IdP serving multiple tenants out of the same realm just fine.

## IssuerIndex: single vs shared issuer

The `IssuerIndex` (`src/wazuh_mcp/tenancy/issuer_index.py`) is a reverse index from canonical issuer URL to `TenantConfig`. It is used by `OAuthSessionFactory` to resolve a verified token's `iss` claim back to a tenant.

Two cases:

**Unambiguous issuer (one tenant per issuer URL).** The lookup returns the matched `TenantConfig`. `Session.tenant_id` is set from the matched tenant.

**Shared issuer (multiple tenants behind one realm).** Multiple `TenantConfig` entries declare the same `oauth_issuer` URL. The index collapses to `None` for that issuer key:

```python
# src/wazuh_mcp/tenancy/issuer_index.py:44-49
if key in by_issuer:
    # Ambiguous: two or more tenants share this issuer.
    # Force claim-based resolution by collapsing to None.
    by_issuer[key] = None
else:
    by_issuer[key] = t
```

When `IssuerIndex.get(iss)` returns `None`, `OAuthSessionFactory` falls back to claim-only routing — the verified token MUST carry a `tenant_id` claim, and `Session.tenant_id` is taken from that claim. A token without a `tenant_id` claim hitting an ambiguous issuer fails closed with `MissingClaim` at the factory layer.

This is the M5a-shipped behavior. Specifically:
- A token from a single-issuer realm routes by issuer (no claim required).
- A token from a multi-tenant realm routes by `tenant_id` claim (claim required).
- A `tenant_id` claim that contradicts an unambiguous issuer match raises `MissingClaim` (sanity check — defense-in-depth).

**Independent tenant-id lookup.** `IssuerIndex.get_by_tenant_id(tenant_id)` exposes the secondary `tenant_id -> TenantConfig` map for callers that have already resolved a tenant_id via claim and need the tenant's `default_rbac_role` / `wazuh_user_claim` for fallback.

## RBAC claim mapping

`server.yaml`'s `oauth.rbac_claims` lists JWT claim names checked in order; the first present claim is used as the operator's role. The role string is matched against `role_tool_allowlist` (see `multi-tenant.md`):

```yaml
oauth:
  rbac_claims: [wazuh_mcp_role, groups, roles]
```

If none of the listed claims is present, the session falls back to the tenant's `default_rbac_role` (configured in `TenantConfig`).

## `wazuh_user` claim — `run_as` attribution

Every Server API call sets `?run_as=<wazuh_user>` when the verified bearer carries the configured `wazuh_user_claim`:

```yaml
tenants:
  - tenant_id: acme
    wazuh_user_claim: wazuh_user        # default
```

Configure the IdP to emit the operator's Wazuh username as a custom claim on the access token:

```
sub: alice@example.com
wazuh_user: alice
```

At session setup, `Session.wazuh_user` is set to `"alice"`. Every Server API call the tool issues sends `?run_as=alice` as a query parameter, and Wazuh's own audit log (typically `/var/ossec/logs/api.log`) records the effective user:

```
$ grep 'run_as=alice' /var/ossec/logs/api.log
```

If the OAuth claim is absent, `Session.wazuh_user` is `None` and Server API calls run as the tenant's service account with no per-operator attribution. There is no tool-arg override and no config-path derivation — the claim is the only path for `run_as`.

API-key sessions never carry `wazuh_user`. They always run as the tenant's service account.

Cross-check: if the MCP audit event shows `user=alice@example.com` but the Wazuh log shows `run_as=` absent, the OAuth claim is not making it through. Verify `wazuh_user_claim` matches the actual JWT claim name and that the IdP mapping is in place.

## Verify the deployment

After bringing the deploy up, smoke-test the OAuth chain:

```
curl https://mcp.example.com/healthz                                  # → {"status":"ok"}
curl https://mcp.example.com/readyz                                   # → {"status":"ok"} once JWKS fetched
curl https://mcp.example.com/.well-known/oauth-protected-resource     # → resource + authorization_servers
```

Authenticated call:

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

A 401 with `WWW-Authenticate: Bearer error="invalid_token"` indicates JWKS / signature failure; a 401 with `error="missing_claim"` indicates the token did not carry an expected claim (typically `tenant_id` against an ambiguous issuer). Inspect the token with `jwt.io` against the IdP's published JWKS to confirm.

## IdP-specific setup

- Keycloak — `oauth-setup/keycloak.md`
- Okta — `oauth-setup/okta.md`
- Entra ID (Azure AD) — `oauth-setup/entra.md`
- Auth0 — `oauth-setup/auth0.md`

Each guide walks the realm/tenant/app-registration setup, the `wazuh_user` claim mapper, and a worked example token.

## Known caveats

- JWKS cache is per-uvicorn-worker. N workers means N initial JWKS fetches at startup. Acceptable at typical worker counts; not worth a shared cache.
- No refresh-token handling server-side. Clients handle their own token refresh; MCP simply rejects expired bearers with `auth_expired`.
- `clock_skew_seconds` defaults to 30 s. Shorter is safer; longer accommodates clock drift on legacy IdPs.
