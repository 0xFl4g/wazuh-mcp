# Multi-tenant deployments

wazuh-mcp's multi-tenant model is structural: every per-tenant policy resolves at call time against `session.tenant_id`. There is no path through RBAC, write allowlists, AR allowlists, rate limits, or audit-sink fan-out that captures the wrong tenant's config.

This document covers the per-tenant resolver model, per-tenant rate-limit budgets, per-tenant audit-sink routing, the cross-tenant isolation guarantees, and the multi-tenant + multi-manager test fixtures.

For the per-tool surface, see `tools.md` (reads) and `writes.md` (writes). For the OAuth / `tenant_id` claim flow that mints `session.tenant_id` in the first place, see `oauth.md`.

## Per-tenant resolver model

Four resolver factories live in `src/wazuh_mcp/rbac/resolver.py`:

- `make_rbac_policy(registry, audit_emitter) -> Callable[[Session], dict[str, list[str]]]`
- `make_write_allowlist(registry, audit_emitter) -> Callable[[Session], list[str] | None]`
- `make_ar_allowlist(registry, audit_emitter) -> Callable[[Session], list[str]]`
- `make_ar_group_allowlist(registry, audit_emitter) -> Callable[[Session], list[str]]`  *(M5b T-A1)*

Each takes a `TenantRegistry` and returns a session-keyed callable. The callable is wired once at server-build time; the per-tenant lookup happens on every call. Stdio mode uses a `SingleTenantRegistry({cfg.tenant})` adapter so both transports share the wiring.

When `registry.get(session.tenant_id)` raises `KeyError` (programming error, DB-driver lag, future driver swap), the resolver fails closed:
- RBAC returns `{}` (empty role table → every tool denies in both `list_tools` and `call_tool`).
- Write allowlist returns `[]` (every write denies at handler time).
- AR allowlist returns `[]` (every AR command denies at handler time).
- AR group allowlist returns `[]` (every group-target AR call denies at handler time).

Each KeyError emits one audit event with `tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"`. See "Resolver-miss audit shape" below.

## Configuration — no schema change

`TenantConfig` carries the per-tenant overrides:

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: analyst
    role_tool_allowlist:
      admin: ["*"]
      responder: ["alerts.*", "agents.*", "write.isolate_agent"]
    write_allowlist:
      - write.isolate_agent
      - write.restart_manager
    active_response_allowlist:
      - isolate
      - restart_service
    agent_group_allowlist:                  # M5b
      - linux-prod
      - dmz
    rate_limit:
      tenant: { capacity: 100, refill_per_sec: 10.0 }
      session: { capacity: 10, refill_per_sec: 1.0 }
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: acme-audit

  - tenant_id: contoso
    indexer_url: https://wazuh.contoso.example:9200
    default_rbac_role: readonly
    rate_limit:
      tenant: { capacity: 5, refill_per_sec: 0.5 }
      session: { capacity: 5, refill_per_sec: 0.5 }
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: contoso-audit
      - kind: file
        path: /var/log/wazuh-mcp/contoso.jsonl
```

Sessions for `acme` see acme's role/write/AR/AR-group allowlists; sessions for `contoso` see contoso's. Each tenant draws against its own rate-limit bucket; each tenant's audit events route to its own sinks (plus the global stderr safety net).

For the full `TenantConfig` schema, see `tenants.md`.

## `write_allowlist=[]` operator-visible delta (M4c)

`write_allowlist=[]` no longer hides write tools from `list_tools`. It registers all writes uniformly across tenants and denies disallowed calls at handler-body time:

| | M4b (v0.5.x) | M4c+ (v0.6.x+) |
|---|---|---|
| Tool registration | `write.*` not registered when `write_allowlist=[]` | All 9 writes registered unconditionally |
| `list_tools` output | Hides denied writes | Lists denied writes |
| `call_tool` denied write | `Unknown tool: ...` | `forbidden` (per-tenant `write_allowlist` denies in handler body) |

**Why.** Multi-tenant integrity over surface narrowing. With per-tenant registration, the FastMCP app served the union of all tenants' write_allowlists, leaking information about other tenants' configurations. Uniform registration + call-time denial gives every tenant the same `list_tools` surface; only the per-call resolution determines what's actually invocable.

**Recommended migration.** Keep `write_allowlist: []` config as-is. Calls still deny with `forbidden`; `list_tools` now shows the rejected tools but they cannot be invoked. The `forbidden` audit events on probe attempts are useful operational signal.

## Per-tenant rate-limit budgets (M4d)

The existing `tenant.rate_limit:` block in `tenants.yaml` actually applies per-tenant. At boot, `build_http_app` calls `registry.all_tenants()`, builds `{t.tenant_id: t.rate_limit for t in all_tenants}`, and passes it as `InProcessRateLimiter(default=..., per_tenant=...)`. The limiter's `_cfg(tenant_id)` lookup hits the per-tenant map first and falls through to the default for tenant_ids not in the map.

```yaml
tenants:
  - tenant_id: tenant_a
    rate_limit:
      tenant: { capacity: 100, refill_per_sec: 10.0 }
      session: { capacity: 10, refill_per_sec: 1.0 }
  - tenant_id: tenant_b
    rate_limit:
      tenant: { capacity: 5, refill_per_sec: 0.5 }
      session: { capacity: 5, refill_per_sec: 0.5 }
```

A session minted for `tenant_b` draws against `tenant_b`'s explicit 5-capacity bucket. Tenants no longer compete for shared budget. Rate-limit denials surface as `WazuhError("rate_limited", ..., scope="rate_limit:tenant" | "rate_limit:session")` and increment `mcp_rate_limit_drops_total{tenant, scope}` (see `observability.md`).

**Stdio mode** is single-tenant by construction. `build_app` populates `per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit}` — a single-entry map functionally equivalent to the default but defense-in-depth so any future code path that consults the explicit map hits a real entry.

**No-tenant fallback.** If `http_cfg.registry` is absent (legacy callers, defensive paths) the per-tenant dict is `{}` and every tenant draws against the default. Production callers always pass a registry.

## Per-tenant audit-sink fan-out (M4d)

`MultiSinkAuditEmitter` is dual-track: `global_sinks` (always-on, defaults to `[StderrSink()]`) plus `per_tenant_sinks: {tenant_id: [...]}` (overlay). `emit(session)` writes to:

1. Every sink in `global_sinks` (always — the safety net).
2. Every sink in `per_tenant_sinks.get(session.tenant_id, [])` (overlay — empty list for unknown tenants).

Unknown tenant_id (no entry in the dict) routes to globals only. This preserves audit visibility for the resolver-miss audit shape (`tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"`) and any future defense-in-depth paths that emit events for sessions whose tenant isn't registered.

At boot, `build_http_app` calls `_build_per_tenant_sinks(registry.all_tenants(), indexer_pool=...)`. Sink construction failure tags the offending tenant_id:

```
RuntimeError: audit sinks for tenant 'tenant_b' failed to build: <reason>
```

**Lifecycle.** `start()` iterates the flat `_all_sinks` list (globals + per-tenant in dict order) and rolls back on any failure — previously-started sinks get `stop()`'d in reverse order before the exception propagates. `stop()` is best-effort across all sinks; failures aggregate into a `BaseExceptionGroup`.

**Single-tenant deployments** see no behavioral change. `build_app` (stdio) calls `_build_per_tenant_sinks([cfg.tenant], indexer_pool=None)` — a one-entry dict equivalent to the old single-list semantics, plus the implicit `[StderrSink()]` global default.

### Drop-metric `tenant` label

`mcp_audit_drops_total` carries a `tenant` label for `QueuedSink`-wrapping sinks (Wazuh Indexer sink, future async sinks). Sentinel values:

- `tenant="<global>"` — sink belongs to `global_sinks` (operator-shared safety net).
- `tenant="<unknown>"` — sink instance not found in either map (defensive; should not occur in practice).
- `tenant="tenant_X"` — sink belongs to `per_tenant_sinks["tenant_X"]`.

Cardinality grows by N tenants in `QueuedSink`-wrapping deployments. With 50 tenants and 2 reasons per sink, the worst-case series count is `N_tenants × N_sinks × 2` — manageable for typical deployments.

Identity-keyed labels: the label resolution uses Python `id(sink)` lookup, so two distinct sink instances with identical configuration get distinct labels. Operators should pass distinct sink instances per tenant — sharing one physical instance across tenants is a configuration error.

## Cross-tenant isolation guarantees

After M4c + M4d + M5b, no production path routes one tenant's reads, writes, AR commands, rate-limit budget, or audit events to another tenant. The structural guarantees:

- **RBAC + write/AR/AR-group allowlists.** Resolved at call time via `registry.get(session.tenant_id)`. KeyError fails closed and emits `<rbac.resolve>` audit. No server-build-time capture of any other tenant's config.
- **Rate limit.** `InProcessRateLimiter` keys buckets by `session.tenant_id`. Per-tenant config lookup is O(1); fall-through to default. No shared bucket across tenants.
- **Audit fan-out.** `emit(session)` looks up `per_tenant_sinks[session.tenant_id]`; the lookup is O(1) and cannot return a different tenant's list. Globals are intentionally tenant-agnostic and operator-visible.
- **Tool registration.** Uniform across tenants since M4c — `list_tools` returns the same surface for every session. No surface-narrowing per tenant.
- **Indexer + Server API pools.** Per-tenant `acquire(tenant_id)` API. Pools are keyed by tenant_id; one tenant's pool is structurally inaccessible from another tenant's session.

The unit suite pins these invariants:
- `tests/unit/test_per_tenant_sink_fanout.py` — six audit routing tests.
- `tests/unit/test_audit_emitter_lifecycle_multi_tenant.py` — four start/stop/rollback tests.
- `tests/unit/test_per_tenant_rate_limiter.py` — five per-tenant rate-limit tests.

## Resolver-miss audit shape

When a session is minted with a `tenant_id` not in the registry, each of the four resolvers fires once and emits:

```json
{
  "timestamp": "2026-04-27T13:24:11.482Z",
  "tool": "<rbac.resolve>",
  "user": "alice@phantom-tenant",
  "tenant": "phantom",
  "rbac_role": "admin",
  "arg_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "outcome": "error",
  "result_count": 0,
  "duration_ms": 0,
  "error_code": "forbidden",
  "error_reason": "tenant_not_registered"
}
```

Up to 4× these events per inbound call (the four resolvers fire independently); deduplication is intentionally not applied — 4× audit on a vanishingly-rare event is preferable to module-level memoization state.

Followed by the actual tool deny:

```json
{
  "tool": "alerts.search_alerts",
  "tenant": "phantom",
  "outcome": "error",
  "error_code": "forbidden",
  "duration_ms": 0
}
```

**Wazuh Dashboards saved-search update.** If your existing dashboard filters on `tool` field with the regex `^[a-z_]+\.[a-z_]+$`, update to include the angle-bracket sentinel:

```
tool:/^[a-z_]+\.[a-z_]+$/ OR tool:"<rbac.resolve>"
```

Or filter on `outcome:error AND error_reason:tenant_not_registered` to surface just the unknown-tenant path.

## Multi-tenant integration fixture (M4d)

`tests/integration/conftest.py` declares two tenants in the inline `tenants.yaml` for the `mcp_http_server` fixture:

- `local` — baseline. `capacity=100`, generous; index `local-audit-*`.
- `tenant_b` — restrictive. `capacity=2`; index `tenant-b-audit-*`.

Per-tenant token mint: Keycloak protocol-mapper hardcodes `tenant_id` per service-account. Both tenants share the realm + audience; distinguished by claim. See `docker/config/keycloak-realm.json` for the two service-account clients.

`IssuerIndex` (`src/wazuh_mcp/tenancy/issuer_index.py`) returns `None` for issuers shared by multiple tenants. The OAuthSessionFactory then routes by the `tenant_id` claim alone; a token without a `tenant_id` claim hitting an ambiguous issuer fails closed with `MissingClaim`.

The cross-tenant leak suite at `tests/integration/test_m4d_multi_tenant.py` pins five invariants end-to-end:
1. Per-tenant rate-limit isolation.
2. Per-tenant audit routing.
3. Local session's tools do not query tenant_b's IndexerClient.
4. Unknown-tenant token routes to globals only.
5. tenant_b token cannot resolve to local — claim-precedence end-to-end.

See `quality-gates.md` for the full suite.

## Multi-manager fixture (M5b T-C1)

Federation-style deployments — multiple distinct Wazuh manager clusters behind one MCP server — are tested via a separate weekly workflow against two distinct manager containers. The fixture extends `tests/integration/conftest.py` with a `multi_manager` parametrization:

- Each tenant points its `indexer_url` at a different Wazuh stack.
- `TenantConfig.server_api_url` (added by M5b T-C1) explicitly overrides the derived port-55000 URL so each tenant can target its own manager cluster.
- Per-manager pools (indexer + server API) are independent — one manager going down does not block the other tenant's calls.

The weekly multi-manager workflow runs against both stacks and asserts cross-manager isolation: a tenant_a tool call must not reach tenant_b's manager cluster, and vice versa.

See `quality-gates.md` for the workflow definition.

## Migration

There is no operator-facing migration for the M4c → M4d → M5b multi-tenant evolution. Tenant configs that already declare per-tenant `role_tool_allowlist`, `write_allowlist`, `active_response_allowlist`, `rate_limit`, and `audit_sinks` see the intended per-tenant behavior take effect on upgrade. Single-tenant deployments see no behavioral change.

The new M5b additions (`agent_group_allowlist`, `server_api_url`) are purely opt-in: omit them and behavior matches v0.7.x.
