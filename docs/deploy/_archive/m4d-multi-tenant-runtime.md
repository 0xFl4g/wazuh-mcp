# M4d — Per-tenant rate-limit + audit-sink fan-out

## Overview

M4d closes the last two tenant_cfg-derived runtime concerns that were primary-tenant-captured at server-build time after M4c. There are no operator-config schema changes; the `rate_limit:` and `audit_sinks:` blocks per tenant in `tenants.yaml` now actually apply per-tenant. Two changes operators will notice when upgrading from `v0.6.x` to `v0.7.0-m4d`:

1. **Per-tenant rate-limit budgets enforce.** Previously, every session shared the *primary* tenant's `rate_limit:` budget — a rogue session on tenant B could exhaust tenant A's token bucket. M4d populates `InProcessRateLimiter.per_tenant` from `registry.all_tenants()` at boot, so each tenant_id gets an isolated token bucket sized from its own `tenant.rate_limit:` block.
2. **Per-tenant audit sinks route.** Previously, `MultiSinkAuditEmitter` captured the primary tenant's `audit_sinks:` and fanned every event there regardless of the calling session's tenant. M4d refactors the emitter to dual-track: `global_sinks` (always-on, defaults to `[StderrSink()]`) plus `per_tenant_sinks: {tenant_id: [...]}` (overlay). `emit(session)` routes to globals + `per_tenant_sinks.get(session.tenant_id, [])`. Cross-tenant audit leak is closed structurally.

One observability delta:

- `mcp_audit_drops_total` Prometheus counter gains a `tenant` label dimension. Cardinality grows by N tenants in deployments using `QueuedSink` wrappers (Wazuh Indexer sink and any future async sinks).

Spec: `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4d-design.md`. This doc walks the operator-facing pieces.

## 1. Per-tenant rate-limit

No schema change. The existing `tenant.rate_limit:` block in `tenants.yaml` now actually applies per-tenant:

```yaml
tenants:
  - tenant_id: tenant_a
    rate_limit:
      tenant: { capacity: 100, refill_per_sec: 10.0 }
      session: { capacity: 10, refill_per_sec: 1.0 }
    # ...
  - tenant_id: tenant_b
    rate_limit:
      tenant: { capacity: 5, refill_per_sec: 0.5 }
      session: { capacity: 5, refill_per_sec: 0.5 }
    # ...
```

At boot, `build_http_app` calls `registry.all_tenants()`, builds `{t.tenant_id: t.rate_limit for t in all_tenants}`, and passes it as `InProcessRateLimiter(default=..., per_tenant=...)`. The limiter's existing `_cfg(tenant_id)` lookup hits the per-tenant map first and falls through to the default config only for tenant_ids not in the map.

**Behavior delta from M4c:** previously, a session minted for `tenant_b` would draw against `tenant_a`'s 100-capacity bucket (the primary tenant's limit, not its own). Under M4d, that session draws against `tenant_b`'s explicit 5-capacity bucket. Tenants no longer compete for shared budget.

**Stdio mode** is single-tenant by construction. `build_app` populates `per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit}` — a single-entry map functionally equivalent to the default but defense-in-depth so any future code path that consults the explicit map hits a real entry.

**No-tenant fallback.** If `http_cfg.registry` is absent (legacy callers, defensive paths) the per-tenant dict is `{}` and every tenant draws against the default. Production callers always pass a registry.

## 2. Per-tenant audit-sink fan-out

No schema change. The existing `tenant.audit_sinks:` block now actually applies per-tenant. Sample two-tenant config:

```yaml
tenants:
  - tenant_id: tenant_a
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: tenant-a-audit
  - tenant_id: tenant_b
    audit_sinks:
      - kind: wazuh_indexer
        index_prefix: tenant-b-audit
      - kind: jsonl
        path: /var/log/wazuh-mcp/tenant-b.jsonl
```

At boot, `build_http_app` calls `_build_per_tenant_sinks(registry.all_tenants(), indexer_pool=...)` — a thin wrapper around the existing `_build_sinks(tenant, indexer_pool=...)` that builds a per-tenant dict and tags any construction failure with the offending `tenant_id`:

```
RuntimeError: audit sinks for tenant 'tenant_b' failed to build: <reason>
```

The dict is passed to `MultiSinkAuditEmitter(per_tenant_sinks=...)`. `global_sinks` is left as the default `[StderrSink()]` — the always-on operator safety net.

**Routing.** On every audited tool call, `emit(session)` writes the event to:

1. Every sink in `global_sinks` (always — the safety net).
2. Every sink in `per_tenant_sinks.get(session.tenant_id, [])` (overlay — empty list for unknown tenants).

Unknown tenant_id (no entry in the dict) routes to globals only. This preserves audit visibility for the M4c resolver-miss audit shape (`tool="<rbac.resolve>"`, `error_code="forbidden"`, `error_reason="tenant_not_registered"`) and any future defense-in-depth paths that emit events for sessions whose tenant isn't registered.

**Lifecycle.** `start()` iterates the flat `_all_sinks` list (globals + per-tenant in dict order) and rolls back on any failure: previously-started sinks get `stop()`'d in reverse order before the exception propagates. `stop()` is best-effort across all sinks; failures are aggregated into a `BaseExceptionGroup`. The M4a sink-lifecycle invariants are preserved verbatim across the dual-track refactor.

**Single-tenant deployments** see no behavioral change. `build_app` (stdio) calls `_build_per_tenant_sinks([cfg.tenant], indexer_pool=None)` — a one-entry dict equivalent to the old single-list semantics, plus the implicit `[StderrSink()]` global default that was always there.

## 3. `mcp_audit_drops_total` tenant label

The drop-metric counter (incremented when a `QueuedSink`'s bounded queue overflows or shutdown drains incomplete) gains a `tenant` label:

```
mcp_audit_drops_total{sink="wazuh_indexer", tenant="tenant_a", reason="overflow"}
mcp_audit_drops_total{sink="wazuh_indexer", tenant="<global>"  , reason="overflow"}
```

Sentinel values:
- `tenant="<global>"` — the dropping sink belongs to `global_sinks` (operator-shared safety net).
- `tenant="<unknown>"` — sink instance not found in either map (defensive; should not occur in practice).
- `tenant="tenant_X"` — sink belongs to `per_tenant_sinks["tenant_X"]`.

Cardinality grows by N tenants in `QueuedSink`-wrapping deployments. With 50 tenants and 2 reasons per sink, the worst-case series count is `N_tenants × N_sinks × 2` — manageable for typical deployments.

**Identity-keyed labels.** The label resolution uses Python `id(sink)` lookup, so two distinct sink instances with identical configuration (e.g. two `WazuhIndexerSink(index_prefix="…")` constructed from different tenant blocks) get distinct labels. Operators should pass distinct sink instances per tenant — the same physical instance shared across tenants would collapse to one label and is a configuration error.

## 4. Cross-tenant audit isolation

After M4d, no production path routes one tenant's events to another tenant's sinks. The structural guarantees:

- `emit(session)` reads `session.tenant_id` and looks up sinks in `per_tenant_sinks.get(session.tenant_id, [])`. The lookup is O(1) and cannot return a different tenant's list.
- `_build_per_tenant_sinks` builds the dict from `registry.all_tenants()` at boot — no inter-tenant aliasing.
- The `global_sinks` list is intentionally tenant-agnostic. Operators who want NO global cross-tenant log should set `global_sinks=[]` (empty list) explicitly when constructing a `MultiSinkAuditEmitter` directly. Note: stdio + HTTP boot paths always supply only `per_tenant_sinks=`, so the default `[StderrSink()]` global remains. Removing the stderr safety net is a code-level customization, not a YAML knob.

The unit suite pins the routing invariants in `tests/unit/test_per_tenant_sink_fanout.py` (six routing tests) and the lifecycle behavior in `tests/unit/test_audit_emitter_lifecycle_multi_tenant.py` (four start/stop/rollback tests). Per-tenant rate-limit isolation is pinned in `tests/unit/test_per_tenant_rate_limiter.py` (five tests).

## 5. Multi-tenant integration fixture

`tests/integration/conftest.py` now declares two tenants in the inline `tenants.yaml` for the `mcp_http_server` fixture:

- `local` — existing baseline. `capacity=100`, generous; index `local-audit-*`.
- `tenant_b` — new. `capacity=2`, restrictive; index `tenant-b-audit-*`.

This is the M5 cross-tenant leak suite prerequisite. The integration tests in `tests/integration/test_m4d_multi_tenant.py` skip with a clear rationale: per-tenant token mint requires either a second Keycloak realm or a `tenant_id` claim mapper in the existing realm, and both are deferred to M5. Per-tenant fan-out and rate-limit are fully covered at the unit level today; the integration validation is gated on the M5 fixture refactor.

## 6. Migration

There is no operator-facing migration. The kwarg rename `MultiSinkAuditEmitter(sinks=) → MultiSinkAuditEmitter(global_sinks=, per_tenant_sinks=)` is internal to the codebase — no downstream consumer of the `wazuh-mcp` package constructs `MultiSinkAuditEmitter` directly. Pre-1.0.0 internal kwarg renames are not semver-breaking by project convention.

Tenant configs that already declare `rate_limit:` and `audit_sinks:` per tenant will see the intended behavior take effect on upgrade — no YAML changes required. Operators running single-tenant deployments will see no behavioral change.
