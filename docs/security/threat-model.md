# Wazuh MCP Threat Model (as of v0.2.0-m2)

Consolidates the deliberate security non-goals and known-limitations from the M1 and M2 specs, retros, and code reviews. Operators reading this before deploying, and M3+ planners scoping new features, should reference it so nothing surprising lands downstream.

## Out of scope by design (v1 / M1+M2)

| Area | Not implemented | Why / mitigation |
|---|---|---|
| Rate limiting | No per-session or per-tenant limits | Operator fronts with nginx/Caddy for coarse-grained DOS. Per-tenant limits are M4 scope. |
| Token revocation | No RFC 7662 introspection | Short-lived access tokens (default 5 min via Keycloak) are the revocation mechanism. If real-time revocation is needed, enable IdP back-channel logout in M4. |
| mTLS on MCP endpoint | Not implemented | Reverse proxy (Caddy) can do client-cert auth; MCP server trusts `X-Forwarded-*` via `--proxy-headers`. |
| In-process TLS | uvicorn runs plain HTTP | Reverse proxy terminates TLS with ACME. One less thing to misconfigure. |
| Real secret backends | YAML only in M2 | AWS Secrets Manager / Vault / encrypted-SQLite drivers land in M4. `SecretStore` protocol already locks the interface. |
| RBAC-aware `list_tools` | Disabled — Claude sees all tools for all roles | M4 filters the tool list by `Session.rbac_role`. |
| Write tools | Not registered in M2 | `write_allowlist` plumbing exists in the spec; enabled per-tenant in M4+. |
| OTel / metrics | No tracing, no Prometheus | Structured JSON logs on stderr only. M4 adds OTel + Prometheus. |
| Prompt injection defense | Out of MCP-layer scope | Cannot be solved at the transport. Documented in spec §6 as user-education concern. |
| Dynamic Client Registration endpoint (RFC 7591) | Not implemented on our side | The IdP handles DCR; we're a resource server, not an authorization server. |
| Cross-tenant analytics | No "all my tenants" tools | Explicit non-goal — prevents confused-deputy. Separate aggregation tier is v3+ scope. |

## Known observable behaviors worth calling out

### Timing oracle on unknown API keys
`YamlApiKeyStore.verify()` short-circuits on unknown `key_id` in ~microseconds, but pays the ~50ms argon2id cost on a known key. An attacker probing the store can distinguish "key exists" from "doesn't exist" via timing.

- **Not mitigated in M2.** Deemed acceptable for the fallback auth path at MSSP scale.
- **Mitigation if ever needed** (one-liner): always verify against a dummy argon2id hash on miss, so the wall-clock cost is constant.

### Stale JWKS on upstream IdP failure
`JwksCache` keeps its last-known keys when a refresh fetch returns non-200 — a legitimate tradeoff to avoid flapping during brief IdP blips. A long outage during key rotation would cause auth failures until the JWKS refresh succeeds.

- **Acceptable** for M2 scale (small deployments, rare rotations).
- **M4** may add background refresh + circuit breaker.

### Pre-auth 401s do not emit audit events
We intentionally skip the audit sink for requests that fail before a `Session` is built. Prevents an attacker from flooding the audit log with forged bearers. The pre-auth path writes a one-line log to stderr only.

- **Implication**: if you want to forensic-trace unauthenticated probing, run the MCP server behind a reverse proxy that logs raw request lines.

### `AuditEmitter` default goes to stderr
Because MCP stdio transport uses stdout as the JSON-RPC wire, any audit emit to stdout would corrupt the protocol. The default is stderr. A regression test locks this in.

- **Implication for HTTP mode**: stderr is also the default there. Redirect with a sink override if you want audit logs in a different location.

### Token `tenant_id` claim can override `iss` mapping
When both a `tenant_id` claim and an `iss`-mapped `TenantConfig` are present, they must match or the factory raises `InvalidToken`. If only the claim is present (no `iss` mapping configured), the claim wins. A malicious user would need a token signed by the configured IdP to forge a tenant — which pushes trust to the IdP's own user-tenant mapping.

- **Implication**: compromise of the IdP's tenant-claim population = compromise of tenant isolation. Auditors should review the IdP's claim mapper with the same scrutiny as MCP config.

## Attack surface summary

**Closed at v0.2.0-m2:**
- JWT `alg=none` attack (rejected at factory construction AND at joserfc algorithm allowlist AND at header pre-check).
- JWT HS256-with-public-key-as-secret attack (blocked by algorithm allowlist).
- JWT signature tampering (joserfc signature verify).
- JWT with unknown/forbidden `iss` or `aud` (strict comparison).
- JWT with expired `exp` / future `nbf` / future `iat` (clock-skew aware check).
- Claim/iss tenant mismatch → `InvalidToken`, not silent acceptance.
- API-key argon2i / argon2d downgrade (prefix check requires `$argon2id$`).
- API-key format spoofing (store entry's `tenant_id` is authoritative, not the prefix).
- API-key revocation + expiry (checked per call before the hash verify).
- `/mcp` path-traversal via middleware prefix match (`startswith(p + "/")` + exact match, not bare prefix).
- `IndexerClient.search(index="..")` path traversal (validator rejects `/` or `..`).
- RFC 6750 strict-client compatibility (`WWW-Authenticate: Bearer realm="mcp", error="insufficient_scope"` — spec-valid error codes only).
- Contextvar leak across async tasks (middleware `finally:` resets).
- Secret leakage through `repr` / `str` / `json.dumps` / serialisation / `copy.deepcopy` (`SecretValue` refuses serialisation round-trips, redacts every format path, is `@final`).

**Deferred to M4:**
- Per-tenant rate limits.
- Per-user session rate limits.
- RBAC-aware `list_tools` filtering.
- Cloud-KMS-backed `SecretStore` drivers.
- Audit sink pluggability (HTTP / back-to-Wazuh).
- Write-tool scaffolding (currently no write paths exist).

**Documented user-education concerns (not solvable at MCP layer):**
- Indirect prompt injection via ingested alert content.
- Tool-selection ambiguity if too many tools overlap (M3 concern as tool count grows).
- Operator misconfiguration (bad `algorithms` list, reused API keys, stale `tenants.yaml`).

## Operator-facing security checklist

Before deploying M2 to production:

- [ ] `oauth.algorithms` excludes `none` and any symmetric algorithm (`HS*`). Constructor guard already refuses `none` — but verify the list.
- [ ] `oauth.issuer` is an exact string match, not a prefix.
- [ ] `oauth.audience` is tenant-specific OR a well-known deployment identifier; not the IdP's default client ID.
- [ ] `api_keys.yaml` is mode 0600 and owned by the MCP service user.
- [ ] `tenants.yaml` `verify_tls` is `true` for every tenant in production. Private CAs use `ca_bundle_path`.
- [ ] Reverse proxy (Caddy / nginx) terminates TLS with automated cert rotation.
- [ ] `WAZUH_MCP_CONFIG_DIR` points at a path only the service user can read.
- [ ] Structured logs are shipped to a SIEM (ideally back to the same Wazuh the MCP server talks to).

## References

- M1 design spec: `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md` §6.
- M2 design spec: `docs/superpowers/specs/2026-04-21-wazuh-mcp-m2-design.md` §6.
- M1 retro: `docs/superpowers/retros/2026-04-20-m1-retro.md`.
- M2 retro: `docs/superpowers/retros/2026-04-21-m2-retro.md`.
- RFC 6750 (bearer tokens), RFC 7662 (introspection — deferred), RFC 9728 (protected-resource metadata).
