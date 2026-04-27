# wazuh-mcp M4d — Per-tenant rate-limit + audit-sink fan-out

Status: Design approved 2026-04-27. Successor to `2026-04-27-wazuh-mcp-m4c-design.md`. Ship target `v0.7.0-m4d`.

## 0. Scope

M4d is the multi-tenant runtime-isolation completion milestone. M4c moved the three tenant_cfg-derived *policy* allowlists (`role_tool_allowlist`, `write_allowlist`, `active_response_allowlist`) to call-time per-tenant resolution. M4d does the same for the two remaining tenant_cfg-derived *runtime* concerns:

1. **Per-tenant rate-limit budgets.** Today's `InProcessRateLimiter` already supports per-tenant config via its `per_tenant: dict[str, RateLimitConfig]` kwarg, and per-tenant token-bucket isolation already works (`_tenant_buckets` keyed by tenant_id). The bug is purely wiring: `build_app` and `build_http_app` construct the limiter with `default=cfg.tenant.rate_limit` and never populate `per_tenant`. Fix is ~10 lines: build the dict from the registry at boot.
2. **Per-tenant audit-sink fan-out.** Today's `MultiSinkAuditEmitter` holds one flat sink list (the primary tenant's sinks) and `emit()` fans out to all of them regardless of `session.tenant_id`. M4d refactors to a dual-track structure (`global_sinks` + `per_tenant_sinks`) with `emit()` routing by tenant.

Both gaps land in M4d as a single milestone, internally phased: Phase 1 ships rate-limiter (mechanical), Phase 2 ships sink fan-out (real refactor), Phase 3 ships docs + retro + tag.

### 0.1 Items shipped

1. **`InProcessRateLimiter.per_tenant` populated at boot.** From `registry.all_tenants()` — `{t.tenant_id: t.rate_limit for t in all_tenants}`. Per-tenant capacity overrides take effect; tenant_a's bucket exhaustion no longer affects tenant_b.
2. **`MultiSinkAuditEmitter` dual-track refactor.** Signature changes from `sinks=` to `global_sinks=` + `per_tenant_sinks=`. `emit(session)` fans out to `global_sinks + per_tenant_sinks.get(session.tenant_id, [])`. Cross-tenant audit leak closed structurally.
3. **`TenantRegistry.all_tenants()` Protocol method.** Added to enable boot-time iteration over all configured tenants. Implemented on `YamlTenantRegistry` (returns `self._tenants.values()`-shaped list) and `SingleTenantRegistry` (returns `[self._tenant]`).
4. **`_build_per_tenant_sinks(all_tenants, *, indexer_pool)` helper.** New top-level helper in `server.py` that calls `_build_sinks` per registered tenant, wraps construction errors with tenant_id in message, returns the dict for `MultiSinkAuditEmitter`'s `per_tenant_sinks=` kwarg.
5. **Drop-metric `tenant` label.** `mcp_audit_drops_total` Prom counter gains `tenant` label dimension. Per-tenant sinks of same class (e.g., two `WazuhIndexerSink` instances for tenant_a and tenant_b) are now distinguishable in metrics. Global sinks tagged with `tenant="<global>"` sentinel.
6. **Multi-tenant integration fixture extension.** `tests/integration/conftest.py` extended to bring up a second Keycloak realm + tenant entry; new `test_m4d_multi_tenant.py` exercises per-tenant rate-limit isolation and per-tenant audit routing end-to-end.

### 0.2 Non-goals

- **No new operator-config surface.** `tenants.yaml` `audit_sinks:` and `rate_limit:` blocks keep their existing schemas. M4d is a wiring + routing change; no new YAML fields. The operator-visible delta is purely "the per-tenant config you've been writing now actually applies per-tenant."
- **No `global_audit_sinks` config field.** Global sinks default to `[StderrSink()]` implicitly (matches M4a default emitter behavior). Operators who want sophisticated global routing express it via per-tenant entries — same FileSink path on every tenant, etc.
- **No backwards-compat shim** on `MultiSinkAuditEmitter(sinks=...)`. The kwarg renames to `global_sinks=`; lockstep test migration. Pre-1.0.0; no known external pinned callers; M4c retro flagged shim debt.
- **No new emitter class.** Direct refactor of `MultiSinkAuditEmitter`. No `PerTenantAuditEmitter` sibling.
- **No external (Redis) rate-limiter.** Single-process `InProcessRateLimiter` only. The `RateLimiter` Protocol is the extension point if external coordination is ever needed; M4d doesn't add it.
- **No per-tenant Prom metric for rate-limit consumption.** Drop-metric label gains `tenant`, but the existing `mcp_tool_calls_total` counter doesn't grow a tenant dimension as part of M4d. (It already has tenant labeling per M4a; no change.)
- **No tenant-N skip-on-config-error path.** If a tenant's `_build_sinks` raises at boot, the whole app fails to boot. Operator must fix config before any tenant works. Matches M4a/M4b precedent.
- **No M5 scope creep.** Cross-tenant leak test suite (full coverage of every read+write tool from session_a asserting nothing touches tenant_b's data) remains M5. M4d's two integration tests (rate-limit isolation + audit routing) are *prerequisites* for the M5 suite, not the suite itself.

## 1. Goals and non-goals

### Goals

1. Move `InProcessRateLimiter` per-tenant cfg from "supported but never populated" to "populated at boot from the registry." Multi-tenant deployments enforce per-tenant capacities; single-tenant unchanged.
2. Refactor `MultiSinkAuditEmitter` to dual-track (`global_sinks` + `per_tenant_sinks`) so `emit(session)` routes audit events to the session's tenant sinks plus the global safety-net.
3. Extend `TenantRegistry` Protocol with `all_tenants()` so boot-time wiring can iterate the configured tenant set without poking at impl-internal `_tenants` attributes.
4. Preserve the M4c per-tenant resolver primitive's invariants — no churn on `rbac/resolver.py` or the M4c-introduced `<rbac.resolve>` audit shape.
5. Add the `tenant` label dimension to the audit drop metric so per-tenant sink overflows are distinguishable in Prom.
6. Land a multi-tenant integration fixture as Phase 2's last task — pre-requisite for the M5 cross-tenant leak suite.

### Non-goals

- Changing `RateLimitConfig` or `AuditSinkConfig` schemas — M4a structures preserved verbatim.
- Per-tenant FastMCP app instances. M4c registers tools uniformly across tenants; M4d preserves that. Per-tenant runtime isolation is purely at the rate-limit + audit-sink layers.
- Eval harness, Helm chart, `pip-audit` in CI, secret-leak scanner — all M5 scope.
- Per-tenant `Prom mcp_tool_calls_total` cardinality changes — already tenant-labeled per M4a.

## 2. Locked design decisions

### 2.1 Phase 1 — Rate-limiter wiring

`build_http_app` change (~5 lines):

```python
# Today (build_http_app, around line 415):
if http_cfg.limiter is not None:
    limiter = http_cfg.limiter
elif http_cfg.tenant is not None:
    limiter = InProcessRateLimiter(default=http_cfg.tenant.rate_limit)
else:
    from wazuh_mcp.tenancy.m4_config import RateLimitConfig
    limiter = InProcessRateLimiter(default=RateLimitConfig())

# M4d:
if http_cfg.limiter is not None:
    limiter = http_cfg.limiter
else:
    all_tenants = list(http_cfg.registry.all_tenants()) if http_cfg.registry else []
    default_cfg = (
        http_cfg.tenant.rate_limit if http_cfg.tenant is not None
        else RateLimitConfig()
    )
    per_tenant_cfg = {t.tenant_id: t.rate_limit for t in all_tenants}
    limiter = InProcessRateLimiter(default=default_cfg, per_tenant=per_tenant_cfg)
```

stdio's `build_app` mirrors:

```python
limiter = cfg.limiter or InProcessRateLimiter(
    default=cfg.tenant.rate_limit,
    per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
)
```

Single-tenant deployments: zero observable behavior change. The per_tenant entry is functionally equivalent to the default for the only tenant.

### 2.2 `TenantRegistry.all_tenants()` Protocol method

```python
class TenantRegistry(Protocol):
    def get(self, tenant_id: str) -> TenantConfig: ...
    def all_tenants(self) -> Iterable[TenantConfig]:
        """Return all configured tenants. Order is impl-defined but stable per call."""
        ...


class YamlTenantRegistry:
    ...
    def all_tenants(self) -> list[TenantConfig]:
        return list(self._tenants.values())


class SingleTenantRegistry:
    ...
    def all_tenants(self) -> list[TenantConfig]:
        return [self._tenant]
```

Returned type is `Iterable[TenantConfig]` in the Protocol (consumer-friendly), `list[TenantConfig]` in concrete impls (so callers can cache without consuming once-only generators).

### 2.3 Phase 2 — `MultiSinkAuditEmitter` dual-track

```python
class MultiSinkAuditEmitter:
    """Fan-out audit emitter with per-tenant routing.

    `emit(session=...)` fans out to:
      * every sink in `global_sinks` (always — operator's safety net)
      * every sink in `per_tenant_sinks.get(session.tenant_id, [])` (tenant overlay)

    Unknown tenant_id (no entry in per_tenant_sinks) routes to globals only —
    audit visibility preserved for the unknown-tenant defense-in-depth path.
    """

    def __init__(
        self,
        *,
        global_sinks: Sequence[AuditSink] | None = None,
        per_tenant_sinks: Mapping[str, Sequence[AuditSink]] | None = None,
        drop_metric: Any | None = None,
    ) -> None:
        self.global_sinks: list[AuditSink] = (
            list(global_sinks) if global_sinks is not None else [StderrSink()]
        )
        self.per_tenant_sinks: dict[str, list[AuditSink]] = {
            tid: list(sinks) for tid, sinks in (per_tenant_sinks or {}).items()
        }
        # Flatten for uniform start/stop iteration with rollback semantics.
        self._all_sinks: list[AuditSink] = (
            self.global_sinks
            + [s for sinks in self.per_tenant_sinks.values() for s in sinks]
        )
        if drop_metric is not None:
            self._wire_drop_metric(drop_metric)

    def _wire_drop_metric(self, drop_metric: Any) -> None:
        # For each sink, attach a recorder. Tenant label is "<global>" for
        # global sinks; tenant_id for per-tenant sinks.
        global_ids = {id(s) for s in self.global_sinks}
        per_tenant_owner: dict[int, str] = {}
        for tid, sinks in self.per_tenant_sinks.items():
            for s in sinks:
                per_tenant_owner[id(s)] = tid
        for s in self._all_sinks:
            if not isinstance(s, QueuedSink):
                continue
            tenant_label = (
                "<global>" if id(s) in global_ids
                else per_tenant_owner.get(id(s), "<unknown>")
            )
            sink_name = getattr(s, "name", s.__class__.__name__)

            def _recorder(
                event: dict[str, Any],
                reason: str,
                _name: str = sink_name,
                _tenant: str = tenant_label,
            ) -> None:
                drop_metric.add(
                    1, {"sink": _name, "tenant": _tenant, "reason": reason}
                )

            s._record_drop = _recorder  # ty: ignore[invalid-assignment]

    async def start(self) -> None:
        # Existing rollback logic, unchanged — iterates self._all_sinks.
        started: list[AuditSink] = []
        try:
            for s in self._all_sinks:
                await s.start()
                started.append(s)
        except BaseException:
            for s in reversed(started):
                with contextlib.suppress(Exception):
                    await s.stop()
            raise

    async def stop(self) -> None:
        # Existing exception-group-safe logic, unchanged — iterates self._all_sinks.
        errors: list[BaseException] = []
        for s in self._all_sinks:
            try:
                await s.stop()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("sink stop failures", errors)

    def emit(
        self,
        *,
        session: Session,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        result_count: int,
        duration_ms: int,
        error_code: str | None = None,
        error_reason: str | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": tool,
            "user": session.user_id,
            "tenant": session.tenant_id,
            "rbac_role": session.rbac_role,
            "arg_hash": _hash_args(args),
            "outcome": outcome,
            "result_count": result_count,
            "duration_ms": duration_ms,
        }
        if error_code is not None:
            event["error_code"] = error_code
        if error_reason is not None:
            event["error_reason"] = error_reason
        for sink in self.global_sinks:
            sink.submit(event)
        for sink in self.per_tenant_sinks.get(session.tenant_id, []):
            sink.submit(event)
```

`emit()` body shape preserved verbatim; only the fan-out section diverges. The `error_reason` kwarg from M4c is preserved.

### 2.4 `_build_per_tenant_sinks` helper

```python
def _build_per_tenant_sinks(
    all_tenants: Sequence[TenantConfig], *, indexer_pool: Any
) -> dict[str, list[AuditSink]]:
    out: dict[str, list[AuditSink]] = {}
    for t in all_tenants:
        try:
            out[t.tenant_id] = _build_sinks(t, indexer_pool=indexer_pool)
        except Exception as e:
            raise RuntimeError(
                f"audit sinks for tenant {t.tenant_id!r} failed to build: {e}"
            ) from e
    return out
```

Exception preserves underlying cause via `raise ... from e`. Error message includes tenant_id so operators know which tenant's `audit_sinks:` config has the issue.

### 2.5 `build_http_app` and stdio `build_app` wiring

```python
# build_http_app (around line 410-420):
all_tenants_list = list(http_cfg.registry.all_tenants()) if http_cfg.registry else []
per_tenant_sinks = _build_per_tenant_sinks(all_tenants_list, indexer_pool=http_cfg.pool)
audit_emitter = audit or http_cfg.audit or MultiSinkAuditEmitter(
    per_tenant_sinks=per_tenant_sinks,
    drop_metric=...,
)

# build_app stdio (around line 219-223):
per_tenant_sinks = _build_per_tenant_sinks([cfg.tenant], indexer_pool=None)
audit_emitter = audit or cfg.audit or MultiSinkAuditEmitter(
    per_tenant_sinks=per_tenant_sinks,
)
```

stdio passes `indexer_pool=None` — preserves M4a's "wazuh_indexer sink not allowed in stdio mode" guard inside `_build_sinks`.

### 2.6 Drop-metric `tenant` label

Existing: `mcp_audit_drops_total{sink, reason}` (cardinality: ~6 series for typical 3-sink deployment).

M4d: `mcp_audit_drops_total{sink, tenant, reason}` where `tenant ∈ {<global>, tenant_a, tenant_b, ...}`. Worst-case cardinality: `(N tenants + 1) × M sink types × R reasons`. 50-tenant deployment with 5 sink types and 3 reasons → 765 series — well under Prom's recommended 100k series per metric.

## 3. Architecture diagrams

### 3.1 Boot-time flow (HTTP, multi-tenant)

```
load_http_config(config_dir)
  ├─ YamlTenantRegistry(tenants.yaml)              ← already exists (M4c)
  └─ HttpAppConfig(... registry=registry, ...)

build_http_app(http_cfg)
  ├─ all_tenants = list(http_cfg.registry.all_tenants())   ← M4d Protocol method
  │
  ├─ # Phase 1: per-tenant rate-limit
  │  per_tenant_cfg = {t.tenant_id: t.rate_limit for t in all_tenants}
  │  default_cfg = http_cfg.tenant.rate_limit if http_cfg.tenant else RateLimitConfig()
  │  limiter = InProcessRateLimiter(default=default_cfg, per_tenant=per_tenant_cfg)
  │
  ├─ # Phase 2: per-tenant sink fan-out
  │  per_tenant_sinks = _build_per_tenant_sinks(all_tenants, indexer_pool=http_cfg.pool)
  │  audit_emitter = MultiSinkAuditEmitter(
  │      global_sinks=None,                        # → [StderrSink()] default
  │      per_tenant_sinks=per_tenant_sinks,
  │      drop_metric=...,
  │  )
  │
  ├─ # M4c resolvers (unchanged)
  │  rbac_policy = make_rbac_policy(http_cfg.registry, audit_emitter)
  │  ...
  └─ _register_everything(...) + _install_rbac_hooks(...)
```

### 3.2 Boot-time flow (stdio, single-tenant)

```
build_app(cfg)
  ├─ registry = SingleTenantRegistry(cfg.tenant)              ← M4c
  ├─ all_tenants = registry.all_tenants() → [cfg.tenant]      ← M4d Protocol method
  │
  ├─ limiter = InProcessRateLimiter(
  │      default=cfg.tenant.rate_limit,
  │      per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
  │  )
  │
  ├─ per_tenant_sinks = _build_per_tenant_sinks([cfg.tenant], indexer_pool=None)
  │  audit_emitter = MultiSinkAuditEmitter(per_tenant_sinks=per_tenant_sinks)
  │
  └─ ... (M4c resolver wiring identical)
```

Single-tenant: per_tenant dicts have one entry. Functionally equivalent to today's "default only" / "single sink list" — no observable behavior change.

### 3.3 Call-time flow (rate-limit, multi-tenant success path)

```
SessionMiddleware sets session.tenant_id="tenant_b"
@instrumented_tool wrapper:
  await limiter.acquire(session.tenant_id, session.user_id)
InProcessRateLimiter.acquire("tenant_b", "user-id-123"):
  cfg = self._cfg("tenant_b")
    → self._per_tenant.get("tenant_b") (hit) → tenant_b's RateLimitConfig
  tbucket = self._tenant_buckets.setdefault("tenant_b", _mk_bucket(cfg.tenant))
  if not tbucket.try_acquire(): raise WazuhError("rate_limited", "tenant rate limit exceeded", 429)
  # tenant_b's bucket is keyed independently from tenant_a's
  ...
```

Tenant_a's bucket exhaustion does NOT affect tenant_b's bucket. Per-tenant capacities applied.

### 3.4 Call-time flow (audit emit, multi-tenant)

```
session.tenant_id="tenant_b"
@instrumented_tool emits audit on completion:
  audit_emitter.emit(session=session, tool="alerts.search_alerts", outcome="ok", ...)
MultiSinkAuditEmitter.emit(session=session, ...):
  event = {... "tenant": "tenant_b", ...}
  for sink in self.global_sinks:                    # always: StderrSink
      sink.submit(event)                            # → stderr
  for sink in self.per_tenant_sinks.get("tenant_b", []):
      sink.submit(event)                            # → tenant_b's WazuhIndexerSink, FileSink, etc.
  # No fan-out to tenant_a's sinks. Cross-tenant audit leak closed.
```

### 3.5 Call-time flow (unknown tenant — defense-in-depth)

```
session.tenant_id="phantom" (programming error / DB-driver lag)
M4c resolver fires first:
  rbac_policy(session) → audit emit with sentinel <rbac.resolve> + return {} → call denied at _install_rbac_hooks
The resolver-miss audit lands on:
  - global_sinks (StderrSink)
  - per_tenant_sinks.get("phantom", []) → [] (empty)
Net: audit emitted to globals only. Phantom doesn't have a per-tenant entry.
No audit silence; forensic visibility preserved.
```

Subsequent rate-limit acquire is unreachable (call already denied). Even if it were reachable, `_cfg("phantom")` falls through to `self._default` — defense-in-depth.

## 4. Component file map

| Layer | File | Change |
|---|---|---|
| **Modified** | `src/wazuh_mcp/rate_limit/limiter.py` | No code change. Class already supports `per_tenant=`. |
| **Modified** | `src/wazuh_mcp/tenancy/registry.py` | Add `all_tenants() -> list[TenantConfig]` to `TenantRegistry` Protocol + impls on `YamlTenantRegistry` and `SingleTenantRegistry`. ~6 lines total. |
| **Modified** | `src/wazuh_mcp/observability/audit.py` | `MultiSinkAuditEmitter.__init__`: kwarg rename `sinks=` → `global_sinks=` + new `per_tenant_sinks=`. `emit()` adds tenant routing. `_wire_drop_metric` adds `tenant` label dimension. `_all_sinks` flat list for lifecycle. ~30-line net delta. |
| **Modified** | `src/wazuh_mcp/server.py` (top-level) | New helper `_build_per_tenant_sinks(all_tenants, *, indexer_pool)` ~12 lines. |
| **Modified** | `src/wazuh_mcp/server.py` (`build_http_app`) | Replace `_build_sinks(http_cfg.tenant, ...)` single-tenant call with `_build_per_tenant_sinks(all_tenants_list, ...)`. Limiter construction adds `per_tenant=` kwarg. ~10 lines net. |
| **Modified** | `src/wazuh_mcp/server.py` (`build_app` stdio) | Same shape: single-entry per_tenant_sinks dict; limiter `per_tenant=` kwarg. ~6 lines net. |
| **Tests new** | `tests/unit/test_per_tenant_rate_limiter.py` | Two-tenant fixture; tenant-bucket isolation; per-tenant capacity overrides; absent tenant_id falls through to default. |
| **Tests new** | `tests/unit/test_per_tenant_sink_fanout.py` | Dual-track routing; emit(session_a) → globals + tenant_a sinks (NOT tenant_b); emit(unknown) → globals only; no per_tenant_sinks → globals only; default global = `[StderrSink()]`; sink instances distinct per tenant. |
| **Tests new** | `tests/unit/test_audit_emitter_lifecycle_multi_tenant.py` | Multi-tenant `start()` rolls back across globals + per-tenant on mid-tenant failure; `stop()` exception-group-safe; event ordering per sink queue preserved. |
| **Tests new** | `tests/unit/test_server_wiring_m4d.py` | HTTP path: limiter constructed with `per_tenant` populated; audit_emitter constructed with `per_tenant_sinks` populated. stdio path: same shape with single-entry dicts. |
| **Tests new** | `tests/integration/test_m4d_multi_tenant.py` | Two-tenant integration: per-tenant rate-limit isolation; per-tenant audit routing (tenant_a's events land in tenant_a's index prefix, NOT tenant_b's). `@requires_manager`, amd64 nightly. |
| **Tests modified** | `tests/unit/test_audit_emitter.py`, `tests/unit/test_audit_drops.py` (if exists), `tests/unit/test_server_wiring_m4a.py`, `tests/unit/test_server_wiring_m4c.py`, `tests/integration/conftest.py`, others surfaced by grep | Migrate `MultiSinkAuditEmitter(sinks=[...])` → `MultiSinkAuditEmitter(global_sinks=[...])`. ~8-12 call sites estimated. |
| **Modified** | `tests/integration/conftest.py` (or `docker/`) | Add second Keycloak realm + second tenant entry to `tenants.yaml` + second issuer mapping. Multi-tenant integration fixture refactor. |
| **Doc new** | `docs/deploy/m4d-multi-tenant-runtime.md` | Operator guide: per-tenant rate-limit (point at unchanged `rate_limit:` schema, document now-actually-applied behavior); per-tenant sink fan-out (point at unchanged `audit_sinks:` schema); drop-metric `tenant` label addition; cross-tenant audit isolation note. |
| **Doc modified** | `docs/deploy/m4a-observability.md` | Add "M4d update" callout: per-tenant rate-limit + sink fan-out now wire correctly. Drop-metric label cardinality note. |
| **Doc modified** | `docs/security/threat-model.md` | M4d additions: per-tenant rate-limit (closes "tenant_a's rogue session burns tenant_b's quota"); per-tenant sink fan-out (closes "tenant_a's audit events leak to tenant_b's sink"). |
| **Doc modified** | `README.md` | Bump milestone table to include M4d. |
| **Spec/plan/retro** | `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4d-design.md` (this file), `docs/superpowers/plans/2026-04-XX-wazuh-mcp-m4d-plan.md`, `docs/superpowers/retros/2026-04-XX-m4d-retro.md` | Standard milestone artifacts. |

## 5. Error handling

### 5.1 Rate-limiter unknown-tenant

`InProcessRateLimiter._cfg(tenant_id)` returns `self._per_tenant.get(tenant_id, self._default)` — falls through to default for unknown tenants. Existing behavior, preserved. Unreachable in practice (M4c resolver denies first), but correct as defense-in-depth: a future code path bypassing RBAC wouldn't `KeyError` on the rate-limit dict.

No new error code; no audit emit from the limiter side. M4c resolver owns the unknown-tenant audit.

### 5.2 Sink-construction failure at boot

`_build_sinks(tenant, indexer_pool=...)` already raises (e.g., `RuntimeError("wazuh_indexer audit sink requires an indexer_pool")` for stdio + indexer-sink config). M4d preserves this.

`_build_per_tenant_sinks(all_tenants, ...)` wraps tenant-N's failure with the tenant_id in the message:

```
RuntimeError: audit sinks for tenant 'tenant_b' failed to build: wazuh_indexer audit sink requires an indexer_pool; only available in HTTP mode.
```

Whole boot fails. Operator must fix the offending tenant's config before any tenant works.

### 5.3 Sink-start failure mid-tenant

`MultiSinkAuditEmitter.start()` rolls back via the existing flat-list logic — iterates `self._all_sinks`, on failure unwinds previously-started sinks. Cross-tenant rollback works because globals + every tenant's sinks are in one ordered list.

Failure message reads `WazuhIndexerSink.start failed: ConnectionError`. No tenant tag in the bare exception, but the sink's `index_prefix` config (which the operator just edited) carries the tenant identity.

### 5.4 Sink-stop failure during shutdown

Existing `BaseExceptionGroup("sink stop failures", errors)` collects per-sink stop failures across the flat list. M4d unchanged.

### 5.5 `submit()` per-sink overflow

Existing async-queue overflow → drop_metric increment with new `tenant` label. `mcp_audit_drops_total{sink, tenant, reason}` series cardinality is `(N tenants + 1) × M sink types × R reasons`. Operator-doc-flagged for cardinality awareness in 50+ tenant deployments.

### 5.6 Empty `audit_sinks` on a tenant

Operator config with `audit_sinks: []` → `_build_sinks(tenant)` returns `[]` → `per_tenant_sinks[tid] = []`. Calls for that tenant fan-out to globals (StderrSink) only. Same as today's empty-config behavior, applied per-tenant.

### 5.7 Cross-tenant emit (defensive note)

A handler running for session_a that calls `audit_emitter.emit(session=session_b, ...)` would route to tenant_b's sinks. The decorator chokepoint always uses `current_session()` (contextvar-bound), so tools never get foreign Session objects. M4d doesn't add structural enforcement; the M4c resolver-pattern + decorator chokepoint is the structural floor.

## 6. Testing strategy

### 6.1 Unit-test coverage matrix

| Surface | Test file | Pinned invariants |
|---|---|---|
| `InProcessRateLimiter` per-tenant routing | `test_per_tenant_rate_limiter.py` | tenant_a's bucket exhaustion doesn't block tenant_b; per-tenant cfg overrides default; absent tenant_id falls through to default; session bucket key `(tenant_id, session_id)` so two sessions on same tenant have independent session buckets but shared tenant bucket |
| `MultiSinkAuditEmitter` dual-track routing | `test_per_tenant_sink_fanout.py` | `emit(session_a)` → globals + tenant_a (NOT tenant_b); unknown tenant → globals only; empty `per_tenant_sinks` → globals only; `global_sinks=None` defaults to `[StderrSink()]`; same `WazuhIndexerSinkConfig` for two tenants → two distinct sink instances |
| `MultiSinkAuditEmitter` lifecycle | `test_audit_emitter_lifecycle_multi_tenant.py` | `start()` iterates flat `_all_sinks`; failure mid-tenant rolls back globals + previously-started per-tenant; `stop()` exception-group-safe; event ordering per sink queue preserved |
| `_build_per_tenant_sinks` | `test_per_tenant_sink_fanout.py` (extends) | returns dict keyed by tenant_id; raises `RuntimeError("audit sinks for tenant 'X' failed to build: ...")` with tenant_id in message; preserves underlying exception via `raise ... from e` |
| `TenantRegistry.all_tenants()` | `test_tenant_registry.py` (existing — extends) | `YamlTenantRegistry.all_tenants()` returns all configs; `SingleTenantRegistry.all_tenants()` returns `[self._tenant]`; returned list is consumable (not generator-once) |
| Drop-metric label cardinality | `test_audit_drops.py` (existing — extends if exists, new otherwise) | per-tenant sink overflow → `mcp_audit_drops_total{sink, tenant=<tid>, reason}`; global sink overflow → `tenant="<global>"` |
| `build_http_app` / `build_app` wiring | `test_server_wiring_m4d.py` | HTTP: limiter constructed with `per_tenant` populated; audit_emitter with `per_tenant_sinks` populated; stdio: same shape with single-entry dicts |

### 6.2 Hypothesis fuzz

None planned. M4d is dict-keyed routing — no string-handling surface where Hypothesis-style invariant fuzzing pays off.

### 6.3 Integration tests

`tests/integration/test_m4d_multi_tenant.py` (new), `@requires_manager`:

- `test_per_tenant_rate_limit_isolation` — two tenants with distinct `rate_limit.tenant.capacity` (e.g., tenant_a=10, tenant_b=2). Burn tenant_b's bucket; assert tenant_a calls still succeed.
- `test_per_tenant_audit_routing` — two tenants each with a `WazuhIndexerSink` pointing at distinct index prefixes (`tenant-a-audit-*`, `tenant-b-audit-*`). Make a call as tenant_a; assert event lands in `tenant-a-audit-*`, NOT `tenant-b-audit-*`. (Index isolation is the real M4d invariant; existing M4a/M4b sinks share an indexer_pool, but `index_prefix` is per-tenant by design.)

### 6.4 Multi-tenant integration fixture refactor

The existing `tests/integration/conftest.py:38` defines one inline server. M4d adds a second tenant entry to `tenants.yaml`, plus a second Keycloak realm/issuer mapping so that OAuth tokens can be minted for either tenant. **This is a real fixture refactor**, not a one-line addition:

- Keycloak bootstrap script needs the second realm.
- OAuth `IssuerIndex` needs the second issuer in `tenants.yaml`.
- Test helpers need to mint tokens for both tenants (probably extend `keycloak_token` fixture or add `keycloak_token_for(tenant_id)`).

Estimate: 1-2 fixture-plumbing tasks before the integration test bodies.

### 6.5 Tier classification

| Phase | Tasks | Tier | Review |
|---|---|---|---|
| 1 | rate-limiter wiring + multi-tenant test | B | Implementer + spot-check |
| 1 | `TenantRegistry.all_tenants()` Protocol + impls | B | Implementer + spot-check |
| 2 | `MultiSinkAuditEmitter` dual-track refactor | A composition | Implementer + spot-check (composition over M4a-reviewed primitive) |
| 2 | `_build_per_tenant_sinks` helper + boot wiring | B | Implementer + spot-check |
| 2 | Drop-metric `tenant` label addition | B | Implementer + spot-check |
| 2 | Test migrations (kwarg rename) | B | Implementer + spot-check |
| 2 | Multi-tenant integration fixture | B | Implementer + spot-check |
| 3 | Operator doc, retro, ship | B | Controller |

**Zero full Tier-A reviews.** M4d composes already-reviewed M4a primitives (rate-limiter token-bucket isolation, sink lifecycle, audit emit chokepoint) and M4c primitives (registry threading, resolver factory pattern). No novel security primitive. Escalate to full review at any task if a spot-check surfaces something risky.

### 6.6 Regression-pinning tests carried forward

Must still pass:
- `test_indexer_client.py::test_bulk_posts_ndjson_to_bulk_endpoint`
- `test_instrumented_tool.py::test_args_model_surfaces_typed_fields_to_fastmcp_introspection`
- `test_m4c_per_tenant_policy.py::test_*_resolves_per_tenant_per_call`
- `test_m4c_per_tenant_policy.py::test_unknown_tenant_amid_known_tenants_emits_one_audit_per_resolver`

## 7. Internal phasing

Single tag `v0.7.0-m4d`. Phasing is plan-level; tests stay green commit-by-commit; main builds throughout.

### Phase 1 — Rate-limiter wiring (~2-3 tasks)

1. Add `TenantRegistry.all_tenants()` Protocol method + impls on `YamlTenantRegistry` and `SingleTenantRegistry`. Test pin.
2. `build_http_app` constructs `InProcessRateLimiter` with `per_tenant=` populated. Same shape for stdio.
3. Multi-tenant rate-limit unit test (`test_per_tenant_rate_limiter.py`).

Behavior delta-free for single-tenant deployments. Multi-tenant deployments now enforce per-tenant capacities. ~2-3 implementer dispatches.

### Phase 2 — Per-tenant sink fan-out (~6-8 tasks)

1. `MultiSinkAuditEmitter` dual-track refactor (kwarg rename + routing + lifecycle reuse + drop-metric label).
2. `_build_per_tenant_sinks` helper.
3. `build_http_app` + `build_app` wire `per_tenant_sinks=` from registry.
4. Migrate `MultiSinkAuditEmitter(sinks=[...])` call sites in tests (~8-12 sites).
5. New unit tests: dual-track routing, lifecycle multi-tenant, helper error path, drop-metric label.
6. `test_server_wiring_m4d.py` — HTTP + stdio wiring assertions.
7. Multi-tenant integration fixture extension: second Keycloak realm, second tenant in `tenants.yaml`, helper for second-tenant token mint.
8. `test_m4d_multi_tenant.py` integration tests (rate-limit isolation + audit routing).

Tier-A spot-check on dual-track refactor; Tier-B spot-checks elsewhere. ~6-8 implementer dispatches.

### Phase 3 — Operator doc + retro + ship (~2 commits)

1. `docs/deploy/m4d-multi-tenant-runtime.md`.
2. Update `m4a-observability.md`, `threat-model.md`, `README.md`.
3. Bump `pyproject.toml` to `0.7.0`. Optional ruff format alignment if drift. Retro to `docs/superpowers/retros/2026-04-XX-m4d-retro.md`. Tag, push.

0 implementer dispatches.

### Total milestone budget

| Phase | Implementers | Tier-A reviews | Fix-after-review | Total dispatches |
|---|---|---|---|---|
| 1 | 2-3 | 0 | 0 | 2-3 |
| 2 | 6-8 | 0 (spot-check) | 0-2 | 6-10 |
| 3 | 0 | 0 | 0 | 0 |
| **Total** | **8-11** | **0** | **0-2** | **8-13** |

Compares to M4c (15 dispatches, 17 tasks) and M4b (10 dispatches, 10 tasks). M4d sits between.

## 8. Threat model framing

### 8.1 Per-tenant rate-limit (closes M4d-1)

Today: tenant_a's rogue session can burn the rate-limit budget shared across all tenants — denying service to tenant_b. M4d: per-tenant token-bucket isolation enforced; tenant_a's bucket exhaustion does NOT affect tenant_b. Operator-configured per-tenant capacities take effect.

### 8.2 Per-tenant audit-sink fan-out (closes M4d-2)

Today: tenant_a's audit events land in tenant_b's sinks (e.g., tenant_b's WazuhIndexerSink with `index_prefix: tenant-b-audit`). Cross-tenant audit leak — operator running compliance review on tenant_b sees tenant_a's events. M4d: routing by `session.tenant_id` ensures tenant_a's events go ONLY to tenant_a's sinks (plus globals).

### 8.3 Defense-in-depth: unknown tenant_id

Per-tenant `_per_tenant.get(tenant_id, default)` returns default cfg — `KeyError` would be a programming error. Per-tenant `per_tenant_sinks.get(tenant_id, [])` returns empty list — audit goes to globals only. Both paths fail-open (the call's M4c policy decision and audit emit both still happen) rather than fail-silent.

### 8.4 What M4d does NOT close

- **Cross-tenant data access in tool handlers.** Tools that take `tenant_id`-style arguments must enforce session-tenant equality (M3 `wazuh_user_claim` + `run_as` machinery handles this for write tools). M4d doesn't change tool-level data-access enforcement; that's the M5 cross-tenant leak suite's domain.
- **External rate-limit coordination.** Single-process only. Multi-instance MCP deployments (e.g., behind a load balancer) don't share rate-limit state. The `RateLimiter` Protocol allows a future Redis-backed impl.
- **Per-tenant Prom counters for tool calls.** `mcp_tool_calls_total` already has tenant labeling per M4a; no change.
- **Multi-manager Wazuh integration fixture in CI.** Two distinct Wazuh clusters. Still M5 scope.

## 9. Migration guidance (operator-facing)

### 9.1 No `tenants.yaml` schema change

`rate_limit:` and `audit_sinks:` blocks keep their existing schemas. The operator-visible delta is that they now apply per-tenant.

### 9.2 `MultiSinkAuditEmitter` kwarg rename (test/code only)

Pre-1.0.0 breaking change. Callers constructing `MultiSinkAuditEmitter(sinks=[...])` migrate to `MultiSinkAuditEmitter(global_sinks=[...])`. Identical observable behavior. No external pinned callers known; lockstep test migration in Phase 2.

### 9.3 Drop-metric `tenant` label

The `mcp_audit_drops_total` Prom counter gains a `tenant` label dimension. **Aggregations that don't include `tenant` in the `by` clause are unchanged** — Prometheus sums across the new label automatically:

```promql
# Same query, same result pre/post M4d
sum by (sink, reason) (rate(mcp_audit_drops_total[5m]))
```

Operators wanting per-tenant drop visibility add `tenant` to the `by` clause:

```promql
sum by (sink, tenant, reason) (rate(mcp_audit_drops_total[5m]))
```

Series cardinality grows by a factor of `(N tenants + 1)` (the +1 is `tenant="<global>"` for global-sinks track). 50-tenant deployment: ~750 series — well under Prom's recommended 100k per metric.

Operators using label-equality matchers (`mcp_audit_drops_total{sink="WazuhIndexerSink"}`) get the same set of samples but with an extra `tenant` label per sample. Most clients (Grafana, alerting rules) handle this transparently; raw `metrics.json` consumers may need an aggregation step.

### 9.4 No new YAML fields, no new env vars, no new role permissions

M4d is purely runtime-routing. No operator config touchpoints beyond the existing `tenants.yaml`.

## 10. Out of scope (deferred to M4e / M5)

- **External (Redis) rate-limiter.** Multi-instance MCP deployment coordination. Protocol-extension when the use case lands.
- **Cross-tenant leak test suite.** Full coverage of every read+write tool from session_a asserting nothing touches tenant_b's data. M5 ship-gate item.
- **Multi-manager integration fixture.** Two distinct Wazuh clusters in CI. M5.
- **Eval harness, Helm chart, `pip-audit`/`safety` in CI, secret-leak scanner.** All M5.
- **Group-target `run_active_response`.** Deferred from M4c.
- **MCP elicitation activation of `confirm_required`.** Gated on SDK.
- **Formal toolset SDK wiring.** Gated on SDK.
- **`WazuhError.scope` field** (M4a nit), **`cancelled` outcome vocabulary** (M4a nit), **Vault integration tests** (M4a non-goal).
