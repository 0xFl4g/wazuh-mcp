# wazuh-mcp M4d Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `v0.7.0-m4d`: per-tenant `InProcessRateLimiter` budgets (mechanical wiring) and per-tenant `MultiSinkAuditEmitter` fan-out (real refactor). Closes the two remaining tenant_cfg-derived runtime concerns left primary-tenant-captured at server-build time after M4c.

**Architecture:** Phase 1 populates `InProcessRateLimiter.per_tenant` from `registry.all_tenants()` at boot — class already supports per-tenant; bug is purely wiring. Phase 2 refactors `MultiSinkAuditEmitter` to dual-track (`global_sinks` + `per_tenant_sinks`); `emit(session)` routes via `session.tenant_id` while preserving the always-on `[StderrSink()]` global default. Both halves apply M4c's per-tenant primitive pattern (factory-over-registry) without introducing new architectural surface.

**Tech Stack:** Python 3.12 • `uv` • `mcp` 1.27 • Pydantic v2 • `httpx 0.27` • `pytest` + `pytest-asyncio` + `pytest-httpx` • `ruff` + `ty`. Wazuh Manager 4.9 + Wazuh Indexer 4.9 + Keycloak 26 (integration only).

**Spec:** `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4d-design.md`

**Phases:**
- Phase 1 — Rate-limiter wiring (T1-T3). All Tier-B + spot-check.
- Phase 2 — Sink fan-out + multi-tenant fixture (T4-T10). T4 is Tier-A composition spot-check; rest Tier-B.
- Phase 3 — Operator doc + retro + ship (T11-T13). Controller-only inline.

**Total estimated dispatches:** 8-13 implementer + 0 full Tier-A reviewers.

**Branch convention:** Work on `main`. Atomic commit per task. First commit of T1 bumps `pyproject.toml` to `0.7.0-dev`. Last ship commit bumps to `0.7.0` and tags `v0.7.0-m4d`.

**Key signature baseline (verified pre-plan via grep):**
- `InProcessRateLimiter(*, default: RateLimitConfig, per_tenant: dict[str, RateLimitConfig] | None = None)` at `src/wazuh_mcp/rate_limit/limiter.py:33`. `per_tenant` already supported; `_cfg(tenant_id)` returns `self._per_tenant.get(tenant_id, self._default)`.
- `MultiSinkAuditEmitter(*, sinks: Sequence[AuditSink] | None = None, drop_metric: Any | None = None)` at `src/wazuh_mcp/observability/audit.py:35`. M4d renames `sinks=` → `global_sinks=` and adds `per_tenant_sinks=`.
- `_build_sinks(tenant: TenantConfig, *, indexer_pool: Any) -> list[AuditSink]` at `src/wazuh_mcp/server.py:87`. Reused unchanged.
- `TenantRegistry` Protocol at `src/wazuh_mcp/tenancy/registry.py:16` with single method `get(tenant_id) -> TenantConfig`. M4d adds `all_tenants() -> list[TenantConfig]`.
- `YamlTenantRegistry._tenants: dict[str, TenantConfig]` at `tenancy/registry.py:30`.
- `SingleTenantRegistry._tenant: TenantConfig` at `tenancy/registry.py` (added in M4c).
- Existing M4c-shipped `MultiSinkAuditEmitter.emit()` signature accepts `error_reason: str | None = None` (preserve in M4d refactor).

**Migration footprint:** `MultiSinkAuditEmitter(sinks=[...])` call sites verified by grep — ~25-30 sites across `tests/unit/`. Grouped:
- `tests/unit/test_rbac_resolver.py` — 12 sites
- `tests/unit/test_instrumented_tool.py` — ~10 sites
- `tests/unit/test_server_wiring_m4c.py` — 2 sites
- `tests/unit/test_audit_emitter.py` — 3 sites
- `tests/unit/test_m4c_per_tenant_policy.py` — 5 sites (CapturingSink fixture passed via sinks=)
- Probably 2-3 more in `test_audit_drops*.py`, `test_server_wiring_m4a.py`, etc.

T5 batches the migration into one dispatch.

---

## Phase 1 — Rate-limiter wiring (Tier-B)

### Task 1: Add `TenantRegistry.all_tenants()` Protocol method

**Files:**
- Modify: `src/wazuh_mcp/tenancy/registry.py` (add method to Protocol + both impls)
- Modify: `pyproject.toml` (version bump to `0.7.0-dev`)
- Test: `tests/unit/test_tenant_registry.py` (existing or new — search and use)

**Why:** `build_http_app` and `build_app` need to iterate the registered tenant set at boot to populate `InProcessRateLimiter.per_tenant` and `MultiSinkAuditEmitter.per_tenant_sinks`. Avoid duck-typed access to impl-internal `_tenants`/`_tenant`.

- [ ] **Step 1: Read current registry shape**

```bash
sed -n '1,50p' src/wazuh_mcp/tenancy/registry.py
```

Expected: `TenantRegistry` Protocol with `get(tenant_id)`. `YamlTenantRegistry` with `__init__(path)` reading YAML + `_tenants: dict[str, TenantConfig]`. `SingleTenantRegistry(tenant)` from M4c with `_tenant: TenantConfig`.

- [ ] **Step 2: Search for existing test file**

```bash
ls tests/unit/test_tenant_registry.py tests/unit/test_single_tenant_registry.py 2>/dev/null
```

`test_single_tenant_registry.py` was created in M4c T2. Add the new tests there. If no broader `test_tenant_registry.py` exists, the M4c file covers the M4d additions too.

- [ ] **Step 3: Write the failing test**

Append to `tests/unit/test_single_tenant_registry.py`:

```python
def test_single_tenant_registry_all_tenants_returns_one_entry() -> None:
    cfg = _cfg("tenant_a")
    registry = SingleTenantRegistry(cfg)
    result = list(registry.all_tenants())
    assert len(result) == 1
    assert result[0] is cfg


def test_yaml_tenant_registry_all_tenants_returns_all(tmp_path) -> None:
    from wazuh_mcp.tenancy.registry import YamlTenantRegistry

    yaml_path = tmp_path / "tenants.yaml"
    yaml_path.write_text(
        """
tenants:
  - tenant_id: tenant_a
    indexer_url: https://indexer.example.com:9200
    verify_tls: false
    default_rbac_role: readonly
    oauth_issuer: https://issuer-a.example.com
    oauth_audience: aud
  - tenant_id: tenant_b
    indexer_url: https://indexer.example.com:9200
    verify_tls: false
    default_rbac_role: analyst
    oauth_issuer: https://issuer-b.example.com
    oauth_audience: aud
""".strip()
    )
    registry = YamlTenantRegistry(yaml_path)
    result = list(registry.all_tenants())
    tenant_ids = {t.tenant_id for t in result}
    assert tenant_ids == {"tenant_a", "tenant_b"}
```

(`_cfg` helper already exists in this test file from M4c T2. `SingleTenantRegistry` import already present.)

- [ ] **Step 4: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_single_tenant_registry.py -v`

Expected: FAIL with `AttributeError: 'SingleTenantRegistry' object has no attribute 'all_tenants'`.

- [ ] **Step 5: Add `all_tenants()` to the Protocol and both impls**

Edit `src/wazuh_mcp/tenancy/registry.py`. Update the Protocol (around line 16) and add methods to both classes:

```python
class TenantRegistry(Protocol):
    def get(self, tenant_id: str) -> TenantConfig:
        """Return the config for tenant_id. Raises KeyError if unknown."""
        ...

    def all_tenants(self) -> list[TenantConfig]:
        """Return all configured tenants. Order is impl-defined but stable per call."""
        ...


class YamlTenantRegistry:
    # ... existing __init__ + get unchanged

    def all_tenants(self) -> list[TenantConfig]:
        return list(self._tenants.values())


class SingleTenantRegistry:
    # ... existing __init__ + get unchanged

    def all_tenants(self) -> list[TenantConfig]:
        return [self._tenant]
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_single_tenant_registry.py -v`

Expected: PASS (5 tests — 3 from M4c + 2 new).

- [ ] **Step 7: Run full unit suite for regressions**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 483 passed, 4 skipped (matches post-M4c baseline plus 2 new tests = 485).

- [ ] **Step 8: Bump version to `0.7.0-dev`**

Edit `pyproject.toml`:

```toml
version = "0.7.0-dev"
```

Run: `uv lock` to update `uv.lock`.

- [ ] **Step 9: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/tenancy/registry.py tests/unit/test_single_tenant_registry.py pyproject.toml uv.lock
git commit -m "tenancy: add all_tenants() to TenantRegistry Protocol

YamlTenantRegistry returns list of all configs; SingleTenantRegistry
returns [self._tenant]. Enables M4d boot-time iteration over the
registered tenant set in build_http_app and build_app without
duck-typed access to impl-internal _tenants attribute.

Bumps version to 0.7.0-dev (M4d milestone start)."
```

---

### Task 2: Pin `InProcessRateLimiter` per-tenant behavior

**Files:**
- Test: `tests/unit/test_per_tenant_rate_limiter.py` (new)

**Why:** The class already supports `per_tenant=`; M4c-era tests don't exercise this code path. Pin the behavior before T3 wires it through `build_app`/`build_http_app` so any regression in the limiter shows up immediately.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_per_tenant_rate_limiter.py`:

```python
"""Per-tenant rate-limiter behavior pinning (M4d T2).

Verifies InProcessRateLimiter.per_tenant works as advertised: tenant_a's
bucket exhaustion does not affect tenant_b; per-tenant cfg overrides
default; absent tenant_id falls through to default.
"""

from __future__ import annotations

import pytest

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter
from wazuh_mcp.tenancy.m4_config import BucketConfig, RateLimitConfig
from wazuh_mcp.wazuh.errors import WazuhError


def _cfg(tenant_capacity: int = 10, session_capacity: int = 10) -> RateLimitConfig:
    """Build a RateLimitConfig with refill so slow it's effectively a fixed cap."""
    return RateLimitConfig(
        tenant=BucketConfig(capacity=tenant_capacity, refill_per_sec=0.0),
        session=BucketConfig(capacity=session_capacity, refill_per_sec=0.0),
    )


@pytest.mark.asyncio
async def test_per_tenant_capacity_overrides_default() -> None:
    """tenant_a configured with capacity=2; default capacity=100. tenant_a
    hits its cap after 2 calls; default-only tenants do not."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=100, session_capacity=100),
        per_tenant={"tenant_a": _cfg(tenant_capacity=2, session_capacity=100)},
    )

    # tenant_a: 2 succeed, 3rd raises rate_limited.
    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError) as exc_info:
        await limiter.acquire("tenant_a", "alice")
    assert exc_info.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_tenant_a_exhaustion_does_not_block_tenant_b() -> None:
    """The headline M4d invariant: per-tenant token-bucket isolation."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=2, session_capacity=100),
        per_tenant={
            "tenant_a": _cfg(tenant_capacity=2, session_capacity=100),
            "tenant_b": _cfg(tenant_capacity=2, session_capacity=100),
        },
    )

    # Burn tenant_a's bucket entirely.
    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "alice")

    # tenant_b is unaffected.
    await limiter.acquire("tenant_b", "bob")
    await limiter.acquire("tenant_b", "bob")


@pytest.mark.asyncio
async def test_unknown_tenant_falls_through_to_default() -> None:
    """When per_tenant doesn't have an entry, default cfg applies."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=3, session_capacity=100),
        per_tenant={"tenant_a": _cfg(tenant_capacity=1, session_capacity=100)},
    )

    # tenant_unknown uses default (capacity=3): 3 succeed.
    await limiter.acquire("tenant_unknown", "alice")
    await limiter.acquire("tenant_unknown", "alice")
    await limiter.acquire("tenant_unknown", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_unknown", "alice")


@pytest.mark.asyncio
async def test_session_buckets_are_per_tenant_session_pair() -> None:
    """Two sessions on same tenant share tenant bucket but have independent
    session buckets. Two sessions across tenants share neither."""
    limiter = InProcessRateLimiter(
        default=_cfg(tenant_capacity=100, session_capacity=2),
    )

    # session_a on tenant_a: burn its session bucket.
    await limiter.acquire("tenant_a", "session_a")
    await limiter.acquire("tenant_a", "session_a")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "session_a")

    # session_b on tenant_a: independent session bucket; succeeds.
    await limiter.acquire("tenant_a", "session_b")
    await limiter.acquire("tenant_a", "session_b")


@pytest.mark.asyncio
async def test_no_per_tenant_arg_falls_through_to_default() -> None:
    """Backwards-compat: limiter constructed with only default kwarg works
    identically to today's behavior — every tenant gets default cfg."""
    limiter = InProcessRateLimiter(default=_cfg(tenant_capacity=2, session_capacity=100))

    await limiter.acquire("tenant_a", "alice")
    await limiter.acquire("tenant_a", "alice")
    with pytest.raises(WazuhError):
        await limiter.acquire("tenant_a", "alice")
```

- [ ] **Step 2: Run the test to verify it passes (no implementation needed — class already supports per_tenant=)**

Run: `uv run pytest tests/unit/test_per_tenant_rate_limiter.py -v`

Expected: PASS (5 tests).

- [ ] **Step 3: Run full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 488 passed, 4 skipped (485 + 5 new).

- [ ] **Step 4: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/unit/test_per_tenant_rate_limiter.py
git commit -m "tests: pin InProcessRateLimiter per-tenant behavior

Headline M4d Phase 1 invariant: tenant_a's bucket exhaustion does
not block tenant_b. Plus per-tenant cfg override, unknown-tenant
fallback, session-bucket independence within a tenant. Class
already supports per_tenant=; T3 wires the boot-time population."
```

---

### Task 3: Wire `per_tenant=` populated dict into `build_app` + `build_http_app`

**Files:**
- Modify: `src/wazuh_mcp/server.py` (`build_app` ~line 224, `build_http_app` ~line 415)
- Test: `tests/unit/test_server_wiring_m4d.py` (new)

**Why:** Connect `registry.all_tenants()` (T1) to `InProcessRateLimiter.per_tenant=` so multi-tenant deployments enforce per-tenant capacities.

- [ ] **Step 1: Read current limiter construction**

```bash
sed -n '215,230p' src/wazuh_mcp/server.py    # build_app
sed -n '410,425p' src/wazuh_mcp/server.py    # build_http_app
```

Expected: stdio constructs `InProcessRateLimiter(default=cfg.tenant.rate_limit)`; HTTP has a 3-branch fallback ending in `InProcessRateLimiter(default=...)`. Neither passes `per_tenant=`.

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_server_wiring_m4d.py`:

```python
"""M4d wiring assertions: rate-limiter per_tenant + audit_emitter
per_tenant_sinks populated at boot from registry."""

from __future__ import annotations

import inspect

from wazuh_mcp.rate_limit.limiter import InProcessRateLimiter


def test_build_http_app_constructs_limiter_with_per_tenant() -> None:
    """build_http_app passes per_tenant= to InProcessRateLimiter."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_http_app)
    # Limiter must be constructed with per_tenant kwarg.
    assert "per_tenant=" in src
    # And must reference all_tenants() to source the dict.
    assert "all_tenants" in src


def test_build_app_constructs_limiter_with_per_tenant() -> None:
    """Stdio build_app also passes per_tenant=."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_app)
    assert "per_tenant=" in src
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_wiring_m4d.py -v`

Expected: FAIL on `assert "per_tenant=" in src`.

- [ ] **Step 4: Modify `build_app` (stdio) limiter construction**

In `src/wazuh_mcp/server.py`, find the line:

```python
limiter = cfg.limiter or InProcessRateLimiter(default=cfg.tenant.rate_limit)
```

Replace with:

```python
limiter = cfg.limiter or InProcessRateLimiter(
    default=cfg.tenant.rate_limit,
    per_tenant={cfg.tenant.tenant_id: cfg.tenant.rate_limit},
)
```

(Single-tenant by construction. The per_tenant entry is functionally equivalent to the default for the only tenant — defense-in-depth so `_cfg(tenant_id)` hits the explicit map.)

- [ ] **Step 5: Modify `build_http_app` limiter construction**

Find the existing 3-branch fallback (around line 412-422). Replace with:

```python
    if http_cfg.limiter is not None:
        limiter = http_cfg.limiter
    else:
        from wazuh_mcp.tenancy.m4_config import RateLimitConfig

        all_tenants = (
            list(http_cfg.registry.all_tenants()) if http_cfg.registry else []
        )
        default_cfg = (
            http_cfg.tenant.rate_limit
            if http_cfg.tenant is not None
            else RateLimitConfig()
        )
        per_tenant_cfg = {t.tenant_id: t.rate_limit for t in all_tenants}
        limiter = InProcessRateLimiter(default=default_cfg, per_tenant=per_tenant_cfg)
```

The `RateLimitConfig` import is needed inline (lazy) because the existing fallback path imports it lazily — preserves the pattern.

- [ ] **Step 6: Run the new wiring test**

Run: `uv run pytest tests/unit/test_server_wiring_m4d.py -v`

Expected: PASS (2 tests).

- [ ] **Step 7: Run full unit suite + M4a/M4c wiring tests**

Run: `uv run pytest tests/unit/test_server_wiring_m4a.py tests/unit/test_server_wiring_m4c.py tests/unit/test_server_wiring_m4d.py -v`

Expected: all pass. Existing wiring tests don't assert on `per_tenant=` so they stay green.

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 490 passed, 4 skipped (488 + 2 new).

- [ ] **Step 8: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4d.py
git commit -m "server: wire per_tenant rate-limit dict at boot

build_http_app populates InProcessRateLimiter.per_tenant from
registry.all_tenants(). build_app (stdio) wires single-entry dict
for symmetry. Multi-tenant deployments now enforce per-tenant
capacities; tenant_a's bucket exhaustion no longer affects tenant_b.
End of M4d phase 1."
```

---

## Phase 2 — Sink fan-out (Tier-A spot-check on T4)

### Task 4: `MultiSinkAuditEmitter` dual-track refactor (Tier-A composition)

**Files:**
- Modify: `src/wazuh_mcp/observability/audit.py` (full `MultiSinkAuditEmitter` rewrite)

**Why:** The headline M4d primitive. Routes audit events by `session.tenant_id` to per-tenant sinks plus always-on global sinks. Closes cross-tenant audit leak.

**Tier-A spot-check note:** Composition over the M4a-reviewed sink-lifecycle primitive. Reviewer (controller spot-check) verifies (i) `emit(session)` fan-outs to globals + per-tenant only; (ii) lifecycle (`start`/`stop`) iterates flat `_all_sinks` for rollback semantics; (iii) drop-metric label dict gains `tenant` key with `<global>` sentinel for global sinks; (iv) `error_reason` kwarg from M4c preserved.

- [ ] **Step 1: Read current MultiSinkAuditEmitter**

```bash
sed -n '35,130p' src/wazuh_mcp/observability/audit.py
```

Expected: 95-line class with `__init__`, `start`, `stop`, `emit`. `_recorder` closure inside `__init__` for drop_metric wiring.

- [ ] **Step 2: Replace the class verbatim**

Replace lines 35-114 (the entire `MultiSinkAuditEmitter` class) of `src/wazuh_mcp/observability/audit.py` with:

```python
class MultiSinkAuditEmitter:
    """Dual-track fan-out audit emitter.

    `emit(session=...)` fans out to:
      * every sink in ``self.global_sinks`` (always — operator's safety net)
      * every sink in ``self.per_tenant_sinks.get(session.tenant_id, [])`` (overlay)

    Unknown tenant_id (no entry) routes to globals only — audit visibility
    preserved for the unknown-tenant defense-in-depth path (M4c resolver
    miss audit, M4d non-registered-tenant audit, etc.).
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
        # Public alias for backwards-compat readability — some external
        # introspection paths (and the M4a drop_metric wiring) reach for
        # `self.sinks`. Keep it as the flat list so existing iterations
        # continue to work.
        self.sinks: list[AuditSink] = self._all_sinks
        if drop_metric is not None:
            self._wire_drop_metric(drop_metric)

    def _wire_drop_metric(self, drop_metric: Any) -> None:
        # Tenant label is "<global>" for global sinks; tenant_id for per-tenant
        # sinks. Identity-keyed lookup so two same-config sinks (different
        # tenants) get distinct labels.
        global_ids = {id(s) for s in self.global_sinks}
        per_tenant_owner: dict[int, str] = {}
        for tid, sinks in self.per_tenant_sinks.items():
            for s in sinks:
                per_tenant_owner[id(s)] = tid
        for s in self._all_sinks:
            if not isinstance(s, QueuedSink):
                continue
            tenant_label = (
                "<global>"
                if id(s) in global_ids
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
        # Start sinks in flat order; roll back on failure.
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
        # Best-effort: each sink's stop() is independent; collect failures.
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

Add the `Mapping` import to the top of the file alongside the existing `Sequence` import:

```python
from collections.abc import Mapping, Sequence
```

(verify the existing import line; if `Mapping` isn't there, add it.)

- [ ] **Step 3: Verify the existing test_audit_emitter.py still imports cleanly (will fail until T5 migrates call sites)**

Run: `uv run pytest tests/unit/test_audit_emitter.py -v`

Expected: ALL FAIL with `TypeError: __init__() got an unexpected keyword argument 'sinks'`. This is expected — T5 migrates the call sites. **Do NOT proceed to T5 commit until you've staged this change separately.**

- [ ] **Step 4: Commit the refactor (with broken tests intentional)**

The refactor is breaking by design. T5 is the lockstep migration. Commit T4 alone first so the diff is clear.

Run: `uv run ruff check src/wazuh_mcp/observability/audit.py && uv run ruff format --check src/wazuh_mcp/observability/audit.py && uv run ty check src/wazuh_mcp/observability/audit.py`

Expected: green for the changed file. (Full repo will fail because tests reference the old kwarg.)

```bash
git add src/wazuh_mcp/observability/audit.py
git commit -m "audit: dual-track MultiSinkAuditEmitter (M4d Phase 2 primitive)

Kwarg rename: sinks= -> global_sinks=. New per_tenant_sinks=. emit()
fans out to global_sinks + per_tenant_sinks.get(session.tenant_id, []).
Unknown tenant routes to globals only — audit visibility preserved
for defense-in-depth paths (M4c resolver miss, M4d non-registered).

Lifecycle (start/stop) iterates flat _all_sinks for the existing
rollback semantics. Drop-metric label dict gains 'tenant' key with
'<global>' sentinel. error_reason kwarg from M4c preserved.

Breaks existing tests using sinks= kwarg — T5 migrates call sites
in lockstep. Pre-1.0.0 breaking change with no external pinned callers."
```

(The repo CI status will be red between T4 and T5 commits. T5 closes the gap.)

---

### Task 5: Migrate test call sites — `sinks=` → `global_sinks=`

**Files:**
- Modify: `tests/unit/test_rbac_resolver.py` (12 sites)
- Modify: `tests/unit/test_instrumented_tool.py` (~10 sites)
- Modify: `tests/unit/test_server_wiring_m4c.py` (2 sites)
- Modify: `tests/unit/test_audit_emitter.py` (3 sites)
- Modify: `tests/unit/test_m4c_per_tenant_policy.py` (5 sites — `_CapturingSink` passed via `sinks=[sink]`)
- Modify: any other call sites (search and update)

**Why:** Lockstep migration after T4's breaking refactor. Search and replace `sinks=` to `global_sinks=` in test code.

- [ ] **Step 1: Find all call sites**

```bash
grep -rn "MultiSinkAuditEmitter(sinks=" tests/unit/ tests/integration/ src/wazuh_mcp/ 2>/dev/null
```

Expected: 25-30 lines listing call sites in test files. (Production code in `server.py` is migrated separately in T8.)

- [ ] **Step 2: Migrate every test call site**

For each line returned in Step 1, replace `MultiSinkAuditEmitter(sinks=[X])` with `MultiSinkAuditEmitter(global_sinks=[X])`. The replacement is mechanical:

```bash
# Run for each affected test file. Verify each file with grep before/after.
```

For `tests/unit/test_rbac_resolver.py`:

```python
# Before: emitter = MultiSinkAuditEmitter(sinks=[sink])
# After:  emitter = MultiSinkAuditEmitter(global_sinks=[sink])
```

12 instances. Same shape across the file.

For `tests/unit/test_instrumented_tool.py`:

```python
# Multiple shapes:
# emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
# emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=io.StringIO())])
# Both → s/sinks=/global_sinks=/
```

For `tests/unit/test_server_wiring_m4c.py`:

```python
# audit = MultiSinkAuditEmitter(sinks=None)
# → audit = MultiSinkAuditEmitter(global_sinks=None)
# (None falls back to [StderrSink()] in the new shape, same as before.)
```

For `tests/unit/test_audit_emitter.py`:

```python
# emitter = MultiSinkAuditEmitter(sinks=[sink])
# → emitter = MultiSinkAuditEmitter(global_sinks=[sink])
```

For `tests/unit/test_m4c_per_tenant_policy.py`:

```python
# emitter = MultiSinkAuditEmitter(sinks=[sink])
# → emitter = MultiSinkAuditEmitter(global_sinks=[sink])
```

If grep surfaces additional files (e.g., `test_audit_drops.py`, `test_server_wiring_m4a.py`), apply the same migration.

- [ ] **Step 3: Verify no `sinks=` call sites remain in tests**

```bash
grep -rn "MultiSinkAuditEmitter(sinks=" tests/ 2>/dev/null
```

Expected: no output.

- [ ] **Step 4: Run full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 490 passed, 4 skipped (T3's 490 baseline; T5 changes 25-30 tests but each one keeps the same observable behavior because `global_sinks=[X]` plus `per_tenant_sinks={}` is equivalent to the old `sinks=[X]`).

If any test fails: investigate the assertion. Common pattern is a test that asserts on `emitter.sinks` directly — the new class exposes `self.sinks` as an alias for `self._all_sinks` (the flat list), so this should still work, but verify.

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/
git commit -m "tests: migrate MultiSinkAuditEmitter(sinks=) -> global_sinks=

Lockstep migration following T4's breaking kwarg rename. ~25-30
call sites across test_rbac_resolver, test_instrumented_tool,
test_audit_emitter, test_server_wiring_m4c, test_m4c_per_tenant_policy.
Identical observable behavior — global_sinks=[X] with empty
per_tenant_sinks fans out to X exactly as the old sinks=[X] did.

Repo back to all-green between T4 and T5; ship discipline preserved."
```

---

### Task 6: New unit tests — per-tenant sink fan-out

**Files:**
- Test: `tests/unit/test_per_tenant_sink_fanout.py` (new)

**Why:** Pin the M4d Phase 2 routing invariants. Headline test: `emit(session_a)` lands on globals + tenant_a sinks ONLY, NOT tenant_b's.

- [ ] **Step 1: Write the test file**

Create `tests/unit/test_per_tenant_sink_fanout.py`:

```python
"""Per-tenant sink fan-out routing (M4d T6).

Pins:
  * emit(session_a) fans out to globals + per_tenant_sinks[tenant_a]
  * NOT to per_tenant_sinks[tenant_b]
  * Unknown tenant routes to globals only
  * global_sinks=None defaults to [StderrSink()]
  * Same-config sinks for two tenants are distinct instances
"""

from __future__ import annotations

from typing import Any

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter


class _CapturingSink:
    """Minimal in-memory sink that records every event submitted."""

    def __init__(self, name: str = "capture") -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def _session(tenant_id: str, *, user_id: str = "alice") -> Session:
    return Session(
        user_id=user_id,
        tenant_id=tenant_id,
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=None,
    )


def test_emit_routes_to_globals_plus_session_tenant_sinks() -> None:
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")
    b = _CapturingSink("tenant_b")

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )

    emitter.emit(
        session=_session("tenant_a"),
        tool="alerts.search_alerts",
        args={},
        outcome="ok",
        result_count=10,
        duration_ms=42,
    )

    assert len(g.events) == 1
    assert len(a.events) == 1
    assert len(b.events) == 0
    assert g.events[0]["tenant"] == "tenant_a"


def test_emit_unknown_tenant_routes_to_globals_only() -> None:
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a]},
    )

    emitter.emit(
        session=_session("tenant_phantom"),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )

    assert len(g.events) == 1
    assert len(a.events) == 0
    assert g.events[0]["error_reason"] == "tenant_not_registered"


def test_global_sinks_none_defaults_to_stderr() -> None:
    """The empty constructor preserves the M4a default behavior."""
    from wazuh_mcp.observability.sinks.stream import StderrSink

    emitter = MultiSinkAuditEmitter()
    assert len(emitter.global_sinks) == 1
    assert isinstance(emitter.global_sinks[0], StderrSink)


def test_empty_per_tenant_sinks_means_globals_only() -> None:
    g = _CapturingSink("global")
    emitter = MultiSinkAuditEmitter(global_sinks=[g], per_tenant_sinks={})

    emitter.emit(
        session=_session("tenant_a"),
        tool="alerts.search_alerts",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=5,
    )
    assert len(g.events) == 1


def test_two_tenants_with_same_sink_config_get_distinct_instances() -> None:
    """The dict structure is identity-keyed; passing the SAME sink instance
    for two tenants would be wrong (both tenants share that sink). Operators
    should pass distinct instances. Verify by constructing two identical-
    looking sinks and confirming routing keeps them separate."""
    g = _CapturingSink("global")
    a = _CapturingSink("tenant_a")
    b = _CapturingSink("tenant_b")  # same class, different instance

    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )

    emitter.emit(
        session=_session("tenant_a"),
        tool="t1",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=1,
    )
    emitter.emit(
        session=_session("tenant_b"),
        tool="t2",
        args={},
        outcome="ok",
        result_count=1,
        duration_ms=1,
    )

    assert len(a.events) == 1
    assert len(b.events) == 1
    assert a.events[0]["tool"] == "t1"
    assert b.events[0]["tool"] == "t2"


def test_emit_preserves_error_reason_kwarg_from_m4c() -> None:
    """error_reason kwarg from M4c T1 must still flow through the new emit shape."""
    g = _CapturingSink("global")
    emitter = MultiSinkAuditEmitter(global_sinks=[g])

    emitter.emit(
        session=_session("tenant_a"),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )
    assert g.events[0]["error_reason"] == "tenant_not_registered"
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/unit/test_per_tenant_sink_fanout.py -v`

Expected: PASS (6 tests).

- [ ] **Step 3: Run full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 496 passed, 4 skipped.

- [ ] **Step 4: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/unit/test_per_tenant_sink_fanout.py
git commit -m "tests: pin per-tenant sink fan-out routing invariants

Headline M4d Phase 2 invariant: emit(session_a) lands on globals +
per_tenant_sinks[tenant_a] only, NOT tenant_b. Unknown tenant
routes to globals only. global_sinks=None defaults to [StderrSink()].
error_reason kwarg from M4c preserved through the new emit shape."
```

---

### Task 7: New unit tests — multi-tenant lifecycle

**Files:**
- Test: `tests/unit/test_audit_emitter_lifecycle_multi_tenant.py` (new)

**Why:** Pin start/stop rollback semantics across globals + per-tenant sinks.

- [ ] **Step 1: Write the test file**

Create `tests/unit/test_audit_emitter_lifecycle_multi_tenant.py`:

```python
"""Multi-tenant MultiSinkAuditEmitter lifecycle (M4d T7).

start() iterates the flat _all_sinks list (globals + per-tenant) and
rolls back on failure. stop() is exception-group-safe across all sinks.
"""

from __future__ import annotations

import pytest


class _RecordingSink:
    """Sink that records start/stop calls. Optionally raises on start."""

    def __init__(self, name: str, raise_on_start: bool = False) -> None:
        self.name = name
        self.raise_on_start = raise_on_start
        self.started = False
        self.stopped = False
        self.start_calls = 0
        self.stop_calls = 0

    async def start(self) -> None:
        self.start_calls += 1
        if self.raise_on_start:
            raise RuntimeError(f"sink {self.name} start failed")
        self.started = True

    async def stop(self) -> None:
        self.stop_calls += 1
        self.stopped = True

    def submit(self, event):  # type: ignore[no-untyped-def]
        pass


@pytest.mark.asyncio
async def test_start_iterates_globals_then_per_tenant_in_dict_order() -> None:
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g = _RecordingSink("global")
    a = _RecordingSink("a")
    b = _RecordingSink("b")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b]},
    )
    await emitter.start()
    assert g.started is True
    assert a.started is True
    assert b.started is True


@pytest.mark.asyncio
async def test_start_rollback_on_per_tenant_failure() -> None:
    """If tenant_b's sink fails, globals + tenant_a's sinks must be stopped."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g = _RecordingSink("global")
    a = _RecordingSink("a")
    b_bad = _RecordingSink("b", raise_on_start=True)
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a], "tenant_b": [b_bad]},
    )
    with pytest.raises(RuntimeError, match="sink b start failed"):
        await emitter.start()
    # Globals + tenant_a were started, then rolled back.
    assert g.stop_calls == 1
    assert a.stop_calls == 1
    # b never finished start, so its stop wasn't called by rollback.
    assert b_bad.stop_calls == 0


@pytest.mark.asyncio
async def test_stop_collects_failures_into_exception_group() -> None:
    """All sinks get stop() attempts even if some fail."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    class _FailingStopSink(_RecordingSink):
        async def stop(self) -> None:
            self.stop_calls += 1
            raise RuntimeError(f"sink {self.name} stop failed")

    g = _RecordingSink("global")
    a_bad = _FailingStopSink("a")
    b = _RecordingSink("b")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g],
        per_tenant_sinks={"tenant_a": [a_bad], "tenant_b": [b]},
    )
    await emitter.start()
    with pytest.raises(BaseExceptionGroup) as exc_info:
        await emitter.stop()
    # All three sinks attempted stop — best-effort.
    assert g.stop_calls == 1
    assert a_bad.stop_calls == 1
    assert b.stop_calls == 1
    # The failing tenant_a's stop is in the exception group.
    assert len(exc_info.value.exceptions) == 1


@pytest.mark.asyncio
async def test_start_failure_in_global_rolls_back_nothing_per_tenant() -> None:
    """If the FIRST global fails, no per-tenant sink ever started; rollback
    has nothing to do for per-tenant. Globals after the failed one also
    haven't started."""
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter

    g_bad = _RecordingSink("global_bad", raise_on_start=True)
    a = _RecordingSink("a")
    emitter = MultiSinkAuditEmitter(
        global_sinks=[g_bad],
        per_tenant_sinks={"tenant_a": [a]},
    )
    with pytest.raises(RuntimeError, match="sink global_bad start failed"):
        await emitter.start()
    assert a.start_calls == 0  # never reached
    assert a.stop_calls == 0
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/unit/test_audit_emitter_lifecycle_multi_tenant.py -v`

Expected: PASS (4 tests).

- [ ] **Step 3: Run full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 500 passed, 4 skipped.

- [ ] **Step 4: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/unit/test_audit_emitter_lifecycle_multi_tenant.py
git commit -m "tests: pin multi-tenant lifecycle rollback semantics

start() iterates globals then per-tenant in dict-order. Rollback on
mid-tenant failure unwinds globals + previously-started per-tenant.
stop() is exception-group-safe across the flat list."
```

---

### Task 8: `_build_per_tenant_sinks` helper + boot wiring

**Files:**
- Modify: `src/wazuh_mcp/server.py` (add helper, update `build_app` + `build_http_app` audit_emitter construction)

**Why:** Connect `registry.all_tenants()` to `MultiSinkAuditEmitter.per_tenant_sinks=`. Wraps `_build_sinks` per tenant with tenant_id-tagged error messages.

- [ ] **Step 1: Read current audit_emitter construction**

```bash
sed -n '215,225p' src/wazuh_mcp/server.py    # build_app stdio
sed -n '407,420p' src/wazuh_mcp/server.py    # build_http_app
```

Expected: stdio constructs `MultiSinkAuditEmitter(sinks=_build_sinks(cfg.tenant, indexer_pool=None))` (after T5 migration, `sinks=` → `global_sinks=`). HTTP similar.

WAIT — T5 migrated only TEST call sites. Production code still uses `sinks=`. Verify:

```bash
grep -n "MultiSinkAuditEmitter(sinks=\|MultiSinkAuditEmitter(global_sinks=" src/wazuh_mcp/server.py
```

If `sinks=` still appears, T8 migrates the production code too.

- [ ] **Step 2: Add the helper**

Append after the existing `_build_sinks` function in `src/wazuh_mcp/server.py` (around line 142):

```python
def _build_per_tenant_sinks(
    all_tenants: Sequence[TenantConfig], *, indexer_pool: Any
) -> dict[str, list[AuditSink]]:
    """Build per-tenant sink dict for MultiSinkAuditEmitter.

    Wraps each tenant's _build_sinks call with a tenant-id-tagged error so
    operators know which tenant's audit_sinks: config has the issue.
    """
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

`Sequence` import — verify it's already imported (it is, alongside other typing imports near the top of server.py).

- [ ] **Step 3: Update stdio `build_app` audit_emitter construction**

Find the line (around 219-223):

```python
audit_emitter = (
    audit
    or cfg.audit
    or MultiSinkAuditEmitter(sinks=_build_sinks(cfg.tenant, indexer_pool=None))
)
```

Replace with:

```python
audit_emitter = (
    audit
    or cfg.audit
    or MultiSinkAuditEmitter(
        per_tenant_sinks=_build_per_tenant_sinks([cfg.tenant], indexer_pool=None),
    )
)
```

(Single-tenant. `global_sinks` defaults to `[StderrSink()]` — preserves M4a's stderr-as-safety-net default.)

- [ ] **Step 4: Update `build_http_app` audit_emitter construction**

Find the lines (around 407-411):

```python
sinks: list[AuditSink] = []
if http_cfg.tenant is not None:
    sinks = _build_sinks(http_cfg.tenant, indexer_pool=http_cfg.pool)
audit_emitter = audit or http_cfg.audit or MultiSinkAuditEmitter(sinks=sinks or None)
```

Replace with:

```python
all_tenants_for_audit = (
    list(http_cfg.registry.all_tenants()) if http_cfg.registry else []
)
per_tenant_sinks = _build_per_tenant_sinks(
    all_tenants_for_audit, indexer_pool=http_cfg.pool
)
audit_emitter = audit or http_cfg.audit or MultiSinkAuditEmitter(
    per_tenant_sinks=per_tenant_sinks,
)
```

(`per_tenant_sinks` may be empty dict for legacy callers without `http_cfg.registry`. `MultiSinkAuditEmitter` handles empty dict — fans out to globals only, which is `[StderrSink()]` default. Preserves legacy behavior.)

- [ ] **Step 5: Extend `test_server_wiring_m4d.py`**

Add to `tests/unit/test_server_wiring_m4d.py`:

```python
def test_build_http_app_constructs_audit_with_per_tenant_sinks() -> None:
    """build_http_app passes per_tenant_sinks= to MultiSinkAuditEmitter."""
    import inspect

    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_http_app)
    assert "per_tenant_sinks=" in src
    assert "_build_per_tenant_sinks" in src


def test_build_app_constructs_audit_with_per_tenant_sinks() -> None:
    """Stdio build_app also passes per_tenant_sinks=."""
    import inspect

    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_app)
    assert "per_tenant_sinks=" in src
    assert "_build_per_tenant_sinks" in src
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/unit/test_server_wiring_m4d.py -v`

Expected: PASS (4 tests now — 2 from T3 + 2 new).

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 502 passed, 4 skipped.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4d.py
git commit -m "server: wire per_tenant_sinks at boot via _build_per_tenant_sinks

New helper iterates registered tenants, calls _build_sinks per tenant,
wraps construction errors with tenant_id in message. build_http_app
sources all_tenants from registry; build_app (stdio) passes single-
entry list. Behavior delta-free for single-tenant: per_tenant_sinks
with one entry equals the old single-list semantics, plus the implicit
[StderrSink()] global. Closes M4d cross-tenant audit leak."
```

---

### Task 9: New unit tests — `_build_per_tenant_sinks` error path

**Files:**
- Modify: `tests/unit/test_per_tenant_sink_fanout.py` (extend with helper tests)

**Why:** Pin the tenant-id-tagged error message format for forensic clarity.

- [ ] **Step 1: Append to `tests/unit/test_per_tenant_sink_fanout.py`**

```python
# ---------- _build_per_tenant_sinks helper ----------


def test_build_per_tenant_sinks_returns_dict_keyed_by_tenant_id(tmp_path) -> None:
    from wazuh_mcp.server import _build_per_tenant_sinks
    from wazuh_mcp.tenancy.config import TenantConfig
    from wazuh_mcp.tenancy.m4_config import StderrSinkConfig

    t_a = TenantConfig(
        tenant_id="tenant_a",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-a.example.com",
        oauth_audience="aud",
        audit_sinks=[StderrSinkConfig(type="stderr")],
    )
    t_b = TenantConfig(
        tenant_id="tenant_b",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-b.example.com",
        oauth_audience="aud",
        audit_sinks=[StderrSinkConfig(type="stderr")],
    )
    result = _build_per_tenant_sinks([t_a, t_b], indexer_pool=None)
    assert set(result.keys()) == {"tenant_a", "tenant_b"}
    assert len(result["tenant_a"]) == 1
    assert len(result["tenant_b"]) == 1


def test_build_per_tenant_sinks_raises_with_tenant_id_in_message() -> None:
    """If a tenant's _build_sinks fails, error message names the tenant."""
    from wazuh_mcp.server import _build_per_tenant_sinks
    from wazuh_mcp.tenancy.config import TenantConfig
    from wazuh_mcp.tenancy.m4_config import WazuhIndexerSinkConfig

    # wazuh_indexer sink in stdio mode (indexer_pool=None) raises.
    t_bad = TenantConfig(
        tenant_id="tenant_bad",
        indexer_url="https://indexer.example.com:9200",
        verify_tls=False,
        default_rbac_role="readonly",
        oauth_issuer="https://issuer-bad.example.com",
        oauth_audience="aud",
        audit_sinks=[
            WazuhIndexerSinkConfig(type="wazuh_indexer", index_prefix="bad-audit")
        ],
    )
    with pytest.raises(RuntimeError, match="tenant 'tenant_bad' failed to build"):
        _build_per_tenant_sinks([t_bad], indexer_pool=None)
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_per_tenant_sink_fanout.py -v`

Expected: PASS (8 tests now — 6 from T6 + 2 new).

- [ ] **Step 3: Run full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 504 passed, 4 skipped.

- [ ] **Step 4: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/unit/test_per_tenant_sink_fanout.py
git commit -m "tests: pin _build_per_tenant_sinks error path

Tenant-id-tagged RuntimeError when one tenant's _build_sinks fails.
Operator gets 'tenant 'tenant_bad' failed to build: ...' so the
right tenant.audit_sinks YAML config is identifiable."
```

---

### Task 10: Multi-tenant integration fixture + integration tests

**Files:**
- Modify: `tests/integration/conftest.py` (add second tenant + Keycloak realm support)
- Modify: `docker/bootstrap.sh` or related Keycloak setup (depending on what exists)
- Test: `tests/integration/test_m4d_multi_tenant.py` (new)

**Why:** End-to-end verification of per-tenant rate-limit isolation and per-tenant audit routing. Multi-tenant fixture is a prerequisite for the M5 cross-tenant leak suite.

**Important:** This task is the largest unknown in the plan. If Keycloak realm bootstrapping turns out painful, scope it down to "single Keycloak realm with two `tenants.yaml` entries that share the issuer" — semantically incomplete (both tenants trust the same OAuth issuer) but exercises the per-tenant rate-limit and sink fan-out at the MCP layer.

- [ ] **Step 1: Survey current Keycloak bootstrap**

```bash
ls docker/ && cat docker/bootstrap.sh 2>/dev/null | head -50
```

Read what's currently configured. The existing `KEYCLOAK_REALM = "wazuh-mcp"` realm has one client `wazuh-mcp-client` and emits tokens for `wazuh-mcp-api` audience. Adding a second realm typically means another `--realm wazuh-mcp-tenant-b` invocation.

- [ ] **Step 2: Decide approach (controller decision based on Step 1)**

If Keycloak realm bootstrap is straightforward → add second realm `wazuh-mcp-tenant-b` with its own client, then update conftest to bootstrap it.

If painful → fallback approach: keep single Keycloak realm; update `tenants.yaml` fixture to declare two tenants both trusting the same `oauth_issuer` (`http://localhost:8080/realms/wazuh-mcp`). Distinguish at the per-tenant level via `tenant_id` (handled by the `wazuh_mcp_tenant_id` claim or similar — verify how M4c's IssuerIndex resolves tenant from issuer).

This decision shapes the rest of the task.

- [ ] **Step 3: Modify `tests/integration/conftest.py` `mcp_http_server` fixture's tenants.yaml**

Update the inline `tenants.yaml` content (around line 49-60 of conftest.py) to include a second tenant entry. Pick one of the two paths from Step 2; here's the simpler shared-realm version:

```yaml
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    rate_limit:
      tenant:
        capacity: 100
        refill_per_sec: 10.0
      session:
        capacity: 10
        refill_per_sec: 1.0
    audit_sinks:
      - type: wazuh_indexer
        index_prefix: local-audit
  - tenant_id: tenant_b
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    rate_limit:
      tenant:
        capacity: 2
        refill_per_sec: 0.0
      session:
        capacity: 100
        refill_per_sec: 1.0
    audit_sinks:
      - type: wazuh_indexer
        index_prefix: tenant-b-audit
```

The deliberate distinction:
- `local` (existing single-tenant baseline): capacity=100, generous; index `local-audit-*`.
- `tenant_b` (new): capacity=2, restrictive; index `tenant-b-audit-*`.

This lets the integration tests assert "tenant_b's tight bucket exhausts after 2 calls but local's doesn't."

- [ ] **Step 4: Update `secrets.yaml` if needed**

The existing secrets.yaml has only `local:`. Add `tenant_b:`:

```yaml
local:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
tenant_b:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
```

- [ ] **Step 5: Decide tenant resolution from token**

If using shared Keycloak realm, the OAuth token has no per-tenant signal. Two options:
- Add a `tenant_id` claim mapper in Keycloak (operator-facing config; out of test fixture scope).
- Use the existing `wazuh_mcp_tenant_id` claim if present, falling back to a default mapping.

Verify how `OAuthSessionFactory` resolves tenant from token in current code:

```bash
grep -n "tenant_id\|claim" src/wazuh_mcp/auth/oauth.py | head -20
```

If token-driven tenant selection is impractical without a real second realm, this task scopes down to: write the `test_m4d_multi_tenant.py` tests as `pytest.skip("requires multi-realm Keycloak — fixture refactor pending M5")` and merge the partial fixture (two `tenants.yaml` entries) for the unit-level fan-out coverage. Document the gap explicitly.

- [ ] **Step 6: Write `tests/integration/test_m4d_multi_tenant.py`**

For the simpler scope (skip-everything path):

```python
"""M4d integration tests — per-tenant rate-limit + audit routing.

Marked @requires_manager — runs nightly on amd64 CI. Multi-tenant
fixture (two-tenant tenants.yaml) is in place; per-tenant token mint
requires either (a) a second Keycloak realm, or (b) a tenant_id claim
mapper in the existing realm. Both are deferred to M5 cross-tenant
leak suite scope.

For now: tests skip with a clear message pointing at the fixture
prerequisite. Per-tenant fan-out is fully covered at the unit level
in test_per_tenant_sink_fanout.py and test_per_tenant_rate_limiter.py.
"""

from __future__ import annotations

import pytest


pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@pytest.mark.asyncio
async def test_per_tenant_rate_limit_isolation() -> None:
    pytest.skip(
        "requires per-tenant token mint — multi-realm Keycloak or "
        "tenant_id claim mapper. Deferred to M5 cross-tenant leak suite. "
        "Unit coverage in test_per_tenant_rate_limiter.py."
    )


@pytest.mark.asyncio
async def test_per_tenant_audit_routing() -> None:
    pytest.skip(
        "requires per-tenant token mint — multi-realm Keycloak or "
        "tenant_id claim mapper. Deferred to M5. "
        "Unit coverage in test_per_tenant_sink_fanout.py."
    )
```

For the fuller scope (if multi-realm Keycloak bootstrap is straightforward), the body of each test follows the pattern from `tests/integration/test_m4b_writes.py` — mint a token for tenant_b, open `_mcp_session` against the shared MCP_URL, call tools, assert routing/limiting.

- [ ] **Step 7: Verify the integration tests collect cleanly**

Run: `uv run pytest tests/integration/test_m4d_multi_tenant.py --collect-only -q`

Expected: 2 tests collected.

- [ ] **Step 8: Run full unit suite to verify no regression**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: 504 passed, 4 skipped.

- [ ] **Step 9: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/integration/conftest.py tests/integration/test_m4d_multi_tenant.py
git commit -m "tests: multi-tenant integration fixture + M4d skip-stub tests

tests/integration/conftest.py mcp_http_server fixture now declares
two tenants in tenants.yaml: 'local' (existing baseline, capacity=100)
and 'tenant_b' (capacity=2, restrictive). Per-tenant token mint via
multi-realm Keycloak or claim mapper is deferred to M5 cross-tenant
leak suite scope; integration tests skip with rationale + pointer to
unit coverage. Multi-tenant fixture is the M5 prerequisite that does
land here."
```

---

## Phase 3 — Operator doc + retro + ship (controller inline)

### Task 11: Write `docs/deploy/m4d-multi-tenant-runtime.md`

**Files:**
- Create: `docs/deploy/m4d-multi-tenant-runtime.md`

**Why:** Operator-facing doc for per-tenant rate-limit and sink fan-out. Schemas unchanged; behavior change documented.

- [ ] **Step 1: Write the doc**

Create `docs/deploy/m4d-multi-tenant-runtime.md` with the structure outlined in spec §4 (refer to `2026-04-27-wazuh-mcp-m4d-design.md`). Sections:

1. Overview — what M4d changes for operators.
2. Per-tenant rate-limit (no schema change; existing `tenant.rate_limit:` block now actually applies per-tenant).
3. Per-tenant audit-sink fan-out (no schema change; existing `tenant.audit_sinks:` block now actually applies per-tenant).
4. `tenant` label on `mcp_audit_drops_total` Prom counter.
5. Cross-tenant audit isolation note.
6. Migration guidance (none operator-facing; pre-1.0.0 internal kwarg rename).

Use M4c's `m4c-multi-tenant.md` as structural template.

- [ ] **Step 2: Commit**

```bash
git add docs/deploy/m4d-multi-tenant-runtime.md
git commit -m "docs: add M4d operator guide for per-tenant rate-limit + sink fan-out"
```

---

### Task 12: Update existing operator docs

**Files:**
- Modify: `docs/deploy/m4a-observability.md` (M4d update callout)
- Modify: `docs/security/threat-model.md` (M4d additions)
- Modify: `README.md` (milestone table)

- [ ] **Step 1: Update `m4a-observability.md`**

Add a top-of-file callout matching the M4c pattern in `m4b-writes.md`:

```markdown
> **M4d update (v0.7.0-m4d, 2026-04-XX).** Per-tenant rate-limit and per-tenant audit-sink fan-out now wire correctly. Schemas unchanged (`rate_limit:` + `audit_sinks:` per tenant). `mcp_audit_drops_total` Prom counter gains a `tenant` label dimension (cardinality grows by N tenants). See `m4d-multi-tenant-runtime.md`.
```

- [ ] **Step 2: Update `threat-model.md`**

Add an M4d additions section before the existing `## M4c additions` section:

```markdown
## M4d additions

- **Per-tenant rate-limit isolation.** `InProcessRateLimiter.per_tenant` populated from registry at boot. Tenant_a's bucket exhaustion no longer affects tenant_b. Closes "rogue session burns shared budget" cross-tenant DOS path.
- **Per-tenant audit-sink fan-out.** `MultiSinkAuditEmitter` dual-track refactor. `emit(session)` routes to globals + `per_tenant_sinks[session.tenant_id]`. Closes "tenant_a's audit events leak to tenant_b's sink" forensic-isolation gap. Existing M4a sink lifecycle (rollback on start failure, exception-group-safe stop) preserved across the flat `_all_sinks` list.
- **Drop-metric `tenant` label.** `mcp_audit_drops_total{sink, tenant, reason}` series cardinality manageable for 50+ tenant deployments.
```

- [ ] **Step 3: Update `README.md`**

Append to the milestones table after the M4c entry:

```markdown
- **M4d (v0.7.0-m4d)** — multi-tenant runtime isolation completion: per-tenant rate-limit budgets (closes cross-tenant DOS), per-tenant audit-sink fan-out (closes cross-tenant audit leak). No new operator-config surface. See `docs/deploy/m4d-multi-tenant-runtime.md`.
```

- [ ] **Step 4: Commit**

```bash
git add docs/deploy/m4a-observability.md docs/security/threat-model.md README.md
git commit -m "docs: update m4a-observability, threat model, and README for M4d"
```

---

### Task 13: Bump version, retro, tag, push

**Files:**
- Modify: `pyproject.toml` (`0.7.0-dev` → `0.7.0`)
- Modify: `uv.lock` (regenerate)
- Create: `docs/superpowers/retros/2026-04-XX-m4d-retro.md`

- [ ] **Step 1: Run `ruff format .` for alignment commit**

Run: `uv run ruff format .` and check `git status`. If files changed, commit:

```bash
git add -u src/ tests/ docs/
git commit -m "chore: ruff format alignment for M4d"
```

If nothing changed, skip.

- [ ] **Step 2: Bump version to `0.7.0`**

Edit `pyproject.toml`: `version = "0.7.0-dev"` → `version = "0.7.0"`.

Run: `uv lock`.

- [ ] **Step 3: Write the retro**

Create `docs/superpowers/retros/2026-04-XX-m4d-retro.md` (replace `XX` with actual ship date). Sections (match M4c retro shape):

1. Headline — what shipped, dispatch count, ship date.
2. What went well — Phase 1 mechanical wiring; T4 dual-track refactor; fixture-grep-pre-plan paid off (zero plan-time fixture drifts because the M4d spec was authored after the M4c retro lesson).
3. What surprised us — fill in based on actual execution observations (fixture-refactor scope; LSP noise patterns; etc.).
4. Tier-A composition validated 3× running — zero full reviews; spot-checks caught nothing slipping.
5. Plan-detail investment outcome — fix-after-review cycles count.
6. Carry-forward to M5 — multi-tenant integration token mint (multi-realm Keycloak or claim mapper); cross-tenant leak suite; eval harness; Helm chart; multi-manager fixture.
7. Dispatch count vs prediction — actual vs the 8-13 estimate.

- [ ] **Step 4: Stage specific files (NOT `git add -A`)**

```bash
git add pyproject.toml uv.lock docs/superpowers/retros/2026-04-XX-m4d-retro.md
git status
```

Expected: only those three files staged.

- [ ] **Step 5: Commit + tag**

```bash
git commit -m "$(cat <<'EOF'
v0.7.0-m4d: per-tenant rate-limit + audit-sink fan-out

InProcessRateLimiter.per_tenant now populated from registry at boot;
tenant_a's bucket exhaustion no longer affects tenant_b. Multi-tenant
deployments enforce per-tenant capacities; single-tenant unchanged.

MultiSinkAuditEmitter refactored to dual-track: global_sinks (always-on
safety net, defaults to [StderrSink()]) + per_tenant_sinks (tenant
overlay). emit(session) routes via session.tenant_id. Cross-tenant
audit leak closed structurally. Drop-metric mcp_audit_drops_total
gains 'tenant' label dimension.

Breaking change (semver-pre-1.0):
  * MultiSinkAuditEmitter(sinks=) -> MultiSinkAuditEmitter(global_sinks=).
    Lockstep test migration; no external pinned callers known.

Architecture:
  * TenantRegistry.all_tenants() Protocol method added.
  * _build_per_tenant_sinks helper wraps tenant-N construction failure
    with tenant_id in error message.
  * Multi-tenant integration fixture in place (two tenants, distinct
    rate_limit + audit_sinks); per-tenant token mint deferred to M5.

Estimated 8-13 dispatches; zero full Tier-A reviews; spot-check throughout.
EOF
)"

git tag v0.7.0-m4d
```

- [ ] **Step 6: Push**

```bash
git push origin main --tags
```

- [ ] **Step 7: Verify**

```bash
git log --oneline -5 && git tag --list "v0.7.0*"
```

Expected: `v0.7.0-m4d` tag listed; HEAD is the ship commit.

---

## Self-review (controller-only — do not dispatch)

After all tasks complete:

- [ ] **Spec coverage:** Read each section of `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4d-design.md`. Point to a task. Any gaps?
- [ ] **Test count delta:** ~14 new tests across rate-limiter, sink fan-out, lifecycle, helper, wiring assertions. Expected total: ~504 unit + 2 skip-stubbed integration.
- [ ] **CI green check:** Verify nightly amd64 integration run picks up cleanly. The 2 skip-stubbed M4d integration tests will report SKIP; M4c's 3 tests should still pass.
- [ ] **Dependabot:** Re-rebase open PRs (#1, #2, #4, #5) post-tag.
- [ ] **Methodology refinements for retro:** track plan-time fixture drifts (expected to be near zero since M4c lesson was applied to M4d spec authoring); track DONE_WITH_CONCERNS reports; track any LSP-vs-CLI patterns.
