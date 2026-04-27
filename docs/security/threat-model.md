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

## M4d additions

- **Per-tenant rate-limit isolation.** `InProcessRateLimiter.per_tenant` populated from `registry.all_tenants()` at boot. Tenant_a's bucket exhaustion no longer affects tenant_b. Closes the "rogue session burns shared budget" cross-tenant DOS path that persisted through M4c.
- **Per-tenant audit-sink fan-out.** `MultiSinkAuditEmitter` dual-track refactor. `emit(session)` routes to `global_sinks` (always-on, defaults to `[StderrSink()]`) plus `per_tenant_sinks.get(session.tenant_id, [])`. Closes the "tenant_a's audit events leak to tenant_b's sink" forensic-isolation gap. Existing M4a sink lifecycle (rollback on start failure, exception-group-safe stop) preserved across the flat `_all_sinks` list.
- **Drop-metric `tenant` label.** `mcp_audit_drops_total{sink, tenant, reason}` series cardinality manageable for 50+ tenant deployments. `<global>` sentinel for global sinks; identity-keyed lookup so distinct tenant sink instances of the same class get distinct labels.
- **Boot-time fail-fast on per-tenant sink config.** `_build_per_tenant_sinks` wraps each tenant's `_build_sinks` call with a tenant-id-tagged `RuntimeError` (`audit sinks for tenant 'tenant_X' failed to build: ...`). Operator gets the offending tenant's name on misconfiguration instead of an opaque sink-construction trace.

## M4c additions

- **Per-tenant policy resolution.** `role_tool_allowlist`, `write_allowlist`, and `active_response_allowlist` now resolve at call time against `session.tenant_id` via three resolver factories in `src/wazuh_mcp/rbac/resolver.py`. Closes the multi-tenant policy-bleed: a session minted for tenant B no longer sees tenant A's allowlists. Single-tenant deployments (stdio + single-tenant HTTP) are behavior-equivalent because both modes route through the same factories with a one-entry registry.
- **Defense-in-depth fail-closed on unknown tenant_id.** When `registry.get(session.tenant_id)` raises `KeyError` (programming error or DB-driver lag in a future driver swap), each resolver returns its safe-default — `{}` for RBAC, `[]` for both write filters. Empty role table → every tool denies in `list_tools` and `call_tool`. Each KeyError emits an audit event with sentinel `tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"` (deduplication intentionally omitted; rare event).
- **Write-tool registration is uniform across tenants.** All 8 writes register unconditionally; per-tenant denial is purely call-time. The M4b "write_allowlist=[] hides tools from list_tools" surface-narrowing behavior is dropped in favor of multi-tenant integrity (uniform tool surface). Operator-visible delta documented in `docs/deploy/m4c-multi-tenant.md` §3.
- **`write.restart_manager` blast radius.** New tool restarts the Wazuh manager (`scope=node` → single node; `scope=cluster` → coordinator-driven full-cluster cycle). Two-layer M4b allowlist (`write_allowlist` + RBAC role) is the floor. Wazuh's API enforces cluster-admin role independently — an MCP-allowed call still fails at Wazuh if the API user lacks the role. Audit captures `scope` and `affected_nodes` from the pre-flight `cluster_status` read so post-incident review can reconstruct who restarted what.
- **Multi-agent active-response.** `agent_ids: list[str]` (1≤N≤50) replaces single-agent shape. Hypothesis-fuzzed URL-injection invariant pins that no agent_id can contain a comma — Wazuh agent IDs are numeric. Partial-failure semantics: `WriteResult.failed_agents` carries per-agent reasons; `ok=true` iff every agent succeeded; no exception is raised for partial failure (the LLM caller decides whether to retry). Catastrophic API errors still raise.

## M3 additions

- **Server API client JWT hygiene.** Tokens are signature-verified by Wazuh at use; the client only decodes `exp` to schedule refresh. Credentials never appear in repr/logs/errors. Mint stampedes prevented via `asyncio.Lock`.
- **`run_as` policy.** Only sourced from the OAuth bearer's configured claim. No tool argument, no config path, no derivation from `preferred_username`. Absent claim → service account (fail-closed).
- **`hunt_query` grammar.** Field + op allowlists enforced at the Pydantic layer. DSL construction only emits `term`, `terms`, `range`, `exists`, `prefix` — never `script`, `runtime_mappings`, `script_score`, `painless`, or nested `bool`. Clause count capped at 20; `in` list capped at 100; `prefix` ≥ 3 chars. Hypothesis property tests verify no bypass.
- **Resources.** New MCP surface. `resources/list` returns empty; `resources/templates/list` publishes three URI templates. All reads scoped to the session's tenant — URIs have no tenant segment, so no cross-tenant URI confusion.
- **Prompts.** Privilege-equivalent to tool calls under the session's identity. Handlers run nested tool calls; all inherit the session's `tenant_id` + `wazuh_user`. No elevation path.
- **New error codes.** `not_found` (agent/rule/technique missing — leaks only the ID the caller supplied) and `upstream_timeout` (504, leaks nothing). Both added to `SAFE_CODES`.

## References

- M1 design spec: `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md` §6.
- M2 design spec: `docs/superpowers/specs/2026-04-21-wazuh-mcp-m2-design.md` §6.
- M1 retro: `docs/superpowers/retros/2026-04-20-m1-retro.md`.
- M2 retro: `docs/superpowers/retros/2026-04-21-m2-retro.md`.
- RFC 6750 (bearer tokens), RFC 7662 (introspection — deferred), RFC 9728 (protected-resource metadata).
