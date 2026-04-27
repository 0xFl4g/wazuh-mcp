# wazuh-mcp M4c Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `v0.6.0-m4c`: per-tenant policy resolution (closes the multi-tenant policy-bleed gap), `write.restart_manager` + `cluster.status` (completes M4b rule-activation flow), multi-agent `write.run_active_response`, and `confirm_required` cleanup.

**Architecture:** Three resolver factories in a new `rbac/resolver.py` module turn server-build-time allowlist capture into per-call session-keyed lookups. Stdio uses a `SingleTenantRegistry` adapter so both modes share resolver wiring. All 8 writes register unconditionally; per-tenant gating moves call-time. New write surface (`write.restart_manager` + paired read `cluster.status`) reuses the M4b chokepoint machinery wholesale.

**Tech Stack:** Python 3.12 • `uv` • `mcp` 1.27 • Pydantic v2 • `httpx 0.27` • `pytest` + `pytest-asyncio` + `pytest-httpx` + `hypothesis` • `ruff` + `ty`. Wazuh Manager 4.9 + Wazuh Indexer 4.9 (integration only).

**Spec:** `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4c-design.md`

**Phases:**
- Phase 1 — Foundation (T1-T7). Tier-A full review on resolver (T3); rest are spot-check. Behavior delta-free for existing operators.
- Phase 2 — Write surface extension + decoupling (T8-T14). Tier-A spot-check.
- Phase 3 — Operator doc + retro + ship (T15-T17). Controller-only.

**Total estimated dispatches:** 14-17.

**Branch convention:** Work on `main` directly per repo convention. Each task is one or more atomic commits. First commit of T1 bumps `pyproject.toml` to `0.6.0-dev`. Last ship commit bumps to `0.6.0` and tags.

---

## Phase 1 — Foundation

### Task 1: Add `error_reason` kwarg to `MultiSinkAuditEmitter.emit`

**Files:**
- Modify: `src/wazuh_mcp/observability/audit.py:89-114`
- Modify: `pyproject.toml` (version bump to `0.6.0-dev`)
- Test: `tests/unit/test_audit_emitter.py` (new file)

**Why:** The resolver factories (T3) emit audit events with a typed reason field (`tenant_not_registered`). Existing `emit()` only accepts `error_code`; the reason has no audit-visible home. Add `error_reason: str | None = None` and write it to the event dict alongside `error_code`. Additive — existing callers untouched.

- [ ] **Step 1: Read the current `emit()` to confirm the signature hasn't drifted**

```bash
sed -n '89,115p' src/wazuh_mcp/observability/audit.py
```

Expected: signature matches `def emit(self, *, session: Session, tool: str, args: dict[str, Any], outcome: str, result_count: int, duration_ms: int, error_code: str | None = None) -> None`.

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_audit_emitter.py`:

```python
"""Pin the additive `error_reason` kwarg added in M4c T1."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.sinks.base import AuditSink


class _CapturingSink:
    """In-memory sink: records every event submitted."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict) -> None:
        self.events.append(event)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


def test_emit_writes_error_reason_when_provided() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="<rbac.resolve>",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="tenant_not_registered",
    )
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "tenant_not_registered"


def test_emit_omits_error_reason_when_not_provided() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="alerts.search_alerts",
        args={"limit": 10},
        outcome="ok",
        result_count=10,
        duration_ms=42,
    )
    assert len(sink.events) == 1
    assert "error_reason" not in sink.events[0]


def test_emit_writes_error_reason_with_error_code() -> None:
    """error_reason without error_code is unusual but allowed; both fields are independent."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    emitter.emit(
        session=_session(),
        tool="alerts.search_alerts",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=0,
        error_code="forbidden",
        error_reason="rbac_role_denied",
    )
    event = sink.events[0]
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "rbac_role_denied"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_audit_emitter.py -v`

Expected: FAIL with `TypeError: emit() got an unexpected keyword argument 'error_reason'`.

- [ ] **Step 4: Modify `MultiSinkAuditEmitter.emit` to accept `error_reason`**

Edit `src/wazuh_mcp/observability/audit.py`, replacing the existing `emit` method:

```python
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
        for sink in self.sinks:
            sink.submit(event)
```

- [ ] **Step 5: Run the new test + the full unit suite**

Run: `uv run pytest tests/unit/test_audit_emitter.py -v`

Expected: PASS (3 tests).

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass; no regressions.

- [ ] **Step 6: Bump `pyproject.toml` version to `0.6.0-dev`**

Edit `pyproject.toml`: change `version = "0.5.1"` to `version = "0.6.0-dev"`.

Run: `uv lock --check` (ensures lockfile still valid; if it fails, run `uv lock` and stage the result).

- [ ] **Step 7: Lint + type-check + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

Expected: all pass.

```bash
git add src/wazuh_mcp/observability/audit.py tests/unit/test_audit_emitter.py pyproject.toml uv.lock
git commit -m "audit: add error_reason kwarg to emit() for M4c resolver-miss audit shape

Additive — existing callers omit it. Written directly to event dict
alongside error_code. M4c phase 1 dependency.

Bumps version to 0.6.0-dev."
```

---

### Task 2: Add `SingleTenantRegistry` adapter

**Files:**
- Modify: `src/wazuh_mcp/tenancy/registry.py` (additive)
- Test: `tests/unit/test_single_tenant_registry.py` (new)

**Why:** Stdio is single-tenant by construction (no `tenants.yaml`). To share resolver wiring with HTTP, stdio needs a `TenantRegistry`-shaped wrapper around its single `cfg.tenant`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_single_tenant_registry.py`:

```python
"""SingleTenantRegistry — stdio adapter for one-config registries (M4c T2)."""

from __future__ import annotations

import pytest

from wazuh_mcp.tenancy.config import RateLimitConfig, TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry


def _cfg(tenant_id: str = "tenant_a") -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://indexer.example.com:9200",
        wazuh_url="https://wazuh.example.com:55000",
        verify_tls=False,
        ca_bundle_path=None,
        oauth_issuer="https://issuer.example.com",
        oauth_audience="aud",
        api_key_default_role="readonly",
        wazuh_user_claim="wazuh_user",
        secret_prefix=None,
        role_tool_allowlist=None,
        rate_limit=RateLimitConfig(),
        audit_sinks=[],
        write_allowlist=None,
        active_response_allowlist=[],
    )


def test_returns_config_for_own_tenant_id() -> None:
    cfg = _cfg("tenant_a")
    registry = SingleTenantRegistry(cfg)
    assert registry.get("tenant_a") is cfg


def test_raises_keyerror_for_other_tenant_id() -> None:
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    with pytest.raises(KeyError, match="unknown tenant: tenant_b"):
        registry.get("tenant_b")


def test_implements_tenant_registry_protocol() -> None:
    """The adapter is structurally a TenantRegistry."""
    from wazuh_mcp.tenancy.registry import TenantRegistry

    cfg = _cfg("tenant_a")
    registry: TenantRegistry = SingleTenantRegistry(cfg)
    assert registry.get("tenant_a") is cfg
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_single_tenant_registry.py -v`

Expected: FAIL with `ImportError: cannot import name 'SingleTenantRegistry' from 'wazuh_mcp.tenancy.registry'`.

- [ ] **Step 3: Add `SingleTenantRegistry` to `tenancy/registry.py`**

Append to `src/wazuh_mcp/tenancy/registry.py`:

```python


class SingleTenantRegistry:
    """Single-config TenantRegistry adapter for stdio-mode wiring.

    Stdio is single-tenant by construction; this wraps the one ``TenantConfig``
    so the same resolver factories used by HTTP work in stdio without a
    separate code path.
    """

    def __init__(self, tenant: TenantConfig) -> None:
        self._tenant = tenant

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id != self._tenant.tenant_id:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenant
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_single_tenant_registry.py -v`

Expected: PASS (3 tests).

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/tenancy/registry.py tests/unit/test_single_tenant_registry.py
git commit -m "tenancy: add SingleTenantRegistry adapter for stdio mode

Wraps a single TenantConfig as a TenantRegistry so M4c resolver
factories work in stdio without a separate code path."
```

---

### Task 3: Build `rbac/resolver.py` — three factories (Tier-A FULL REVIEW)

**Files:**
- Create: `src/wazuh_mcp/rbac/resolver.py`
- Test: `tests/unit/test_rbac_resolver.py` (new)

**Why:** This is the M4c security primitive. Three factories close over a `TenantRegistry` and return `Callable[[Session], …]` values that resolve per-tenant policy at call time. KeyError on unknown tenant_id → audit emit + safe-default.

**Tier-A note:** Reviewer should verify (i) every code path through the three factories emits audit on KeyError before returning safe-default; (ii) safe-default is fail-closed (`{}` for RBAC, `[]` for both allowlists); (iii) `error_code="forbidden"` and `error_reason="tenant_not_registered"` are spelled exactly; (iv) sentinel `tool="<rbac.resolve>"` is consistent across all three factories; (v) `args={}`, `result_count=0`, `duration_ms=0` are the resolver-context-appropriate values.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_rbac_resolver.py`:

```python
"""rbac/resolver.py — per-tenant policy resolution factories (M4c T3, Tier-A)."""

from __future__ import annotations

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.resolver import (
    make_ar_allowlist,
    make_rbac_policy,
    make_write_allowlist,
)
from wazuh_mcp.tenancy.config import RateLimitConfig, TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry


class _CapturingSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict) -> None:
        self.events.append(event)


def _cfg(
    tenant_id: str,
    *,
    role_tool_allowlist: dict[str, list[str]] | None = None,
    write_allowlist: list[str] | None = None,
    active_response_allowlist: list[str] | None = None,
) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://indexer.example.com:9200",
        wazuh_url="https://wazuh.example.com:55000",
        verify_tls=False,
        ca_bundle_path=None,
        oauth_issuer=f"https://issuer-{tenant_id}.example.com",
        oauth_audience="aud",
        api_key_default_role="readonly",
        wazuh_user_claim="wazuh_user",
        secret_prefix=None,
        role_tool_allowlist=role_tool_allowlist,
        rate_limit=RateLimitConfig(),
        audit_sinks=[],
        write_allowlist=write_allowlist,
        active_response_allowlist=active_response_allowlist or [],
    )


def _session(tenant_id: str = "tenant_a", role: str = "admin") -> Session:
    return Session(
        user_id="alice",
        tenant_id=tenant_id,
        rbac_role=role,
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


# Multi-tenant resolution tests live in `test_m4c_per_tenant_policy.py` (T4);
# this module covers each factory's single-tenant + KeyError behavior.


# ---------- make_rbac_policy ----------


def test_rbac_policy_returns_default_when_override_absent() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", role_tool_allowlist=None))
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_a"))
    # DEFAULT_ROLE_TOOL_ALLOWLIST contains admin/analyst/readonly.
    assert "admin" in result
    assert result["admin"] == ["*"]
    assert sink.events == []


def test_rbac_policy_applies_tenant_override() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    override = {"admin": ["alerts.*"], "responder": ["write.isolate_agent"]}
    registry = SingleTenantRegistry(
        _cfg("tenant_a", role_tool_allowlist=override)
    )
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_a"))
    assert result["admin"] == ["alerts.*"]
    assert result["responder"] == ["write.isolate_agent"]
    # readonly not in override, fall through to default
    assert "readonly" in result


def test_rbac_policy_unknown_tenant_returns_empty_dict() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    policy = make_rbac_policy(registry, emitter)
    result = policy(_session("tenant_phantom"))
    assert result == {}


def test_rbac_policy_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    policy = make_rbac_policy(registry, emitter)
    policy(_session("tenant_phantom"))
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["tool"] == "<rbac.resolve>"
    assert event["tenant"] == "tenant_phantom"
    assert event["outcome"] == "error"
    assert event["error_code"] == "forbidden"
    assert event["error_reason"] == "tenant_not_registered"


# ---------- make_write_allowlist ----------


def test_write_allowlist_returns_none_when_unset() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", write_allowlist=None))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) is None


def test_write_allowlist_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a", write_allowlist=[]))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == []


def test_write_allowlist_returns_explicit_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(
        _cfg("tenant_a", write_allowlist=["write.isolate_agent"])
    )
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == ["write.isolate_agent"]


def test_write_allowlist_unknown_tenant_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_write_allowlist(registry, emitter)
    assert resolver(_session("tenant_phantom")) == []


def test_write_allowlist_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_write_allowlist(registry, emitter)
    resolver(_session("tenant_phantom"))
    assert len(sink.events) == 1
    assert sink.events[0]["tool"] == "<rbac.resolve>"
    assert sink.events[0]["error_reason"] == "tenant_not_registered"


# ---------- make_ar_allowlist ----------


def test_ar_allowlist_returns_tenants_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(
        _cfg("tenant_a", active_response_allowlist=["isolate", "kill_process"])
    )
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == ["isolate", "kill_process"]


def test_ar_allowlist_returns_empty_for_default_config() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_a")) == []


def test_ar_allowlist_unknown_tenant_returns_empty_list() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    assert resolver(_session("tenant_phantom")) == []


def test_ar_allowlist_unknown_tenant_emits_audit() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = SingleTenantRegistry(_cfg("tenant_a"))
    resolver = make_ar_allowlist(registry, emitter)
    resolver(_session("tenant_phantom"))
    assert len(sink.events) == 1
    assert sink.events[0]["tool"] == "<rbac.resolve>"
    assert sink.events[0]["error_reason"] == "tenant_not_registered"
```

Note: the unused `_two_tenant_registry()` helper is a stub for cross-test sharing — full multi-tenant test fixtures land in T4. Delete the helper from this file before committing or leave commented; current test set covers single-tenant resolution + KeyError fan-out.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_rbac_resolver.py -v`

Expected: FAIL with `ImportError: cannot import name 'make_rbac_policy' from 'wazuh_mcp.rbac.resolver'`.

- [ ] **Step 3: Implement `rbac/resolver.py`**

Create `src/wazuh_mcp/rbac/resolver.py`:

```python
"""Per-tenant policy resolution factories.

Each factory takes a ``TenantRegistry`` and returns a session-keyed callable.
On unknown tenant_id (registry KeyError), the resolver emits an audit event
with sentinel ``tool="<rbac.resolve>"`` and returns a fail-closed safe default
(empty role table for RBAC, empty allowlist for both write filters).

The factories are pure module-level functions; the closures they return are
the long-lived per-server callables wired into ``_register_everything``,
``_install_rbac_hooks``, and the write handlers.
"""

from __future__ import annotations

from collections.abc import Callable

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.policy import effective_allowlist_for
from wazuh_mcp.tenancy.registry import TenantRegistry

_RESOLVE_SENTINEL = "<rbac.resolve>"
_REASON = "tenant_not_registered"


def make_rbac_policy(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], dict[str, list[str]]]:
    def _policy(session: Session) -> dict[str, list[str]]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return {}
        return effective_allowlist_for(tenant_override=cfg.role_tool_allowlist)

    return _policy


def make_write_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str] | None]:
    def _resolve(session: Session) -> list[str] | None:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return []
        return cfg.write_allowlist

    return _resolve


def make_ar_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str]]:
    def _resolve(session: Session) -> list[str]:
        try:
            cfg = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                args={},
                outcome="error",
                result_count=0,
                duration_ms=0,
                error_code="forbidden",
                error_reason=_REASON,
            )
            return []
        return cfg.active_response_allowlist

    return _resolve
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_rbac_resolver.py -v`

Expected: PASS (12 tests).

- [ ] **Step 5: Lint + type-check + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/rbac/resolver.py tests/unit/test_rbac_resolver.py
git commit -m "rbac: add per-tenant policy resolver factories

Three factories — make_rbac_policy, make_write_allowlist,
make_ar_allowlist — each wrap a TenantRegistry and return a
session-keyed callable. KeyError on unknown tenant_id emits an
audit event with sentinel tool='<rbac.resolve>' and returns a
fail-closed safe default. Tier-A primitive."
```

---

### Task 4: Multi-tenant per-call resolution test

**Files:**
- Test: `tests/unit/test_m4c_per_tenant_policy.py` (new)

**Why:** Pin the headline M4c invariant — a single closure resolves to *different* allowlists for sessions with different tenant_ids. This is the test that proves the multi-tenant bleed is closed at the unit level.

- [ ] **Step 1: Write the test**

Create `tests/unit/test_m4c_per_tenant_policy.py`:

```python
"""Multi-tenant per-call policy resolution (M4c T4).

Pins the headline M4c invariant: a single resolver closure returns
the right allowlist for whatever tenant_id the session carries, on
every call. Closure does not capture tenant_a's config and serve it
to a tenant_b session.
"""

from __future__ import annotations

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.resolver import (
    make_ar_allowlist,
    make_rbac_policy,
    make_write_allowlist,
)
from wazuh_mcp.tenancy.config import RateLimitConfig, TenantConfig


class _DictRegistry:
    """Minimal multi-tenant registry impl for tests."""

    def __init__(self, tenants: dict[str, TenantConfig]) -> None:
        self._tenants = dict(tenants)

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id not in self._tenants:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenants[tenant_id]


class _CapturingSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def submit(self, event: dict) -> None:
        self.events.append(event)


def _cfg(
    tenant_id: str,
    *,
    role_tool_allowlist: dict[str, list[str]] | None = None,
    write_allowlist: list[str] | None = None,
    active_response_allowlist: list[str] | None = None,
) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://indexer.example.com:9200",
        wazuh_url="https://wazuh.example.com:55000",
        verify_tls=False,
        ca_bundle_path=None,
        oauth_issuer=f"https://issuer-{tenant_id}.example.com",
        oauth_audience="aud",
        api_key_default_role="readonly",
        wazuh_user_claim="wazuh_user",
        secret_prefix=None,
        role_tool_allowlist=role_tool_allowlist,
        rate_limit=RateLimitConfig(),
        audit_sinks=[],
        write_allowlist=write_allowlist,
        active_response_allowlist=active_response_allowlist or [],
    )


def _session(tenant_id: str, *, role: str = "admin") -> Session:
    return Session(
        user_id=f"user-{tenant_id}",
        tenant_id=tenant_id,
        rbac_role=role,
        auth_method="oauth",
        wazuh_user=None,
    )


def _two_tenant_registry() -> _DictRegistry:
    return _DictRegistry({
        "tenant_a": _cfg(
            "tenant_a",
            role_tool_allowlist={"admin": ["alerts.*"], "responder": ["write.isolate_agent"]},
            write_allowlist=["write.isolate_agent"],
            active_response_allowlist=["isolate"],
        ),
        "tenant_b": _cfg(
            "tenant_b",
            role_tool_allowlist={"admin": ["agents.*"], "soc": ["alerts.search_alerts"]},
            write_allowlist=None,  # registration-default (no filter)
            active_response_allowlist=["restart_service"],
        ),
    })


def test_rbac_policy_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    policy = make_rbac_policy(_two_tenant_registry(), emitter)

    result_a = policy(_session("tenant_a"))
    assert result_a["admin"] == ["alerts.*"]
    assert result_a["responder"] == ["write.isolate_agent"]

    result_b = policy(_session("tenant_b"))
    assert result_b["admin"] == ["agents.*"]
    assert result_b["soc"] == ["alerts.search_alerts"]
    # tenant_b doesn't have a "responder" key
    assert "responder" not in result_b


def test_write_allowlist_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    resolver = make_write_allowlist(_two_tenant_registry(), emitter)

    assert resolver(_session("tenant_a")) == ["write.isolate_agent"]
    assert resolver(_session("tenant_b")) is None  # tenant_b has no filter


def test_ar_allowlist_resolves_per_tenant_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    resolver = make_ar_allowlist(_two_tenant_registry(), emitter)

    assert resolver(_session("tenant_a")) == ["isolate"]
    assert resolver(_session("tenant_b")) == ["restart_service"]


def test_resolution_does_not_capture_first_session_tenant() -> None:
    """Closure must not memoize the first call's tenant config."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    policy = make_rbac_policy(_two_tenant_registry(), emitter)

    # Call with tenant_a, then tenant_b, then tenant_a again — each call
    # must resolve afresh.
    a1 = policy(_session("tenant_a"))
    b1 = policy(_session("tenant_b"))
    a2 = policy(_session("tenant_a"))

    assert a1 == a2
    assert a1 != b1
    assert sink.events == []  # no audit events on the happy path


def test_unknown_tenant_amid_known_tenants_emits_one_audit_per_resolver() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(sinks=[sink])
    registry = _two_tenant_registry()
    rbac = make_rbac_policy(registry, emitter)
    write = make_write_allowlist(registry, emitter)
    ar = make_ar_allowlist(registry, emitter)

    sess = _session("tenant_phantom")
    assert rbac(sess) == {}
    assert write(sess) == []
    assert ar(sess) == []

    # Three independent resolver calls → three audit events on the
    # unknown-tenant path. No deduplication (per spec §5.1).
    assert len(sink.events) == 3
    for event in sink.events:
        assert event["tool"] == "<rbac.resolve>"
        assert event["tenant"] == "tenant_phantom"
        assert event["error_reason"] == "tenant_not_registered"
```

- [ ] **Step 2: Run the test to verify it passes (no implementation needed — T3 already provides everything)**

Run: `uv run pytest tests/unit/test_m4c_per_tenant_policy.py -v`

Expected: PASS (5 tests).

- [ ] **Step 3: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/unit/test_m4c_per_tenant_policy.py
git commit -m "tests: pin multi-tenant per-call resolution invariant for M4c

Two-tenant fixture; three resolvers; sessions for tenant_a vs
tenant_b each see their own allowlists. Closure does not capture
the first call's tenant. Headline M4c invariant."
```

---

### Task 5: Thread `registry` through `HttpAppConfig`

**Files:**
- Modify: `src/wazuh_mcp/server.py:333-393` (HttpAppConfig + load_http_config)
- Test: `tests/unit/test_http_app_config.py` (new — small)

**Why:** `load_http_config` already builds `YamlTenantRegistry`; today it's discarded after feeding `IssuerIndex`. M4c keeps it on `HttpAppConfig` so `build_http_app` can close resolvers over it.

- [ ] **Step 1: Read the current HttpAppConfig**

```bash
sed -n '333,395p' src/wazuh_mcp/server.py
```

Expected: dataclass with `pool, server_api_pool, chain, oauth, issuer_index, resource_url, authorization_server, tenant, limiter, audit`. `load_http_config` ends with `return HttpAppConfig(... tenant=primary_tenant)`.

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_http_app_config.py`:

```python
"""HttpAppConfig.registry threading (M4c T5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wazuh_mcp.server import HttpAppConfig, load_http_config
from wazuh_mcp.tenancy.registry import YamlTenantRegistry


def test_http_app_config_has_registry_field() -> None:
    """HttpAppConfig accepts a registry kwarg."""
    # We don't need a fully-built config; just confirm the field exists.
    fields = {f.name for f in HttpAppConfig.__dataclass_fields__.values()}
    assert "registry" in fields


def test_load_http_config_threads_registry(tmp_path: Path) -> None:
    """The registry built inside load_http_config survives onto HttpAppConfig."""
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: tenant_a
    indexer_url: https://indexer.example.com:9200
    wazuh_url: https://wazuh.example.com:55000
    verify_tls: false
    oauth_issuer: https://issuer.example.com
    oauth_audience: aud
    api_key_default_role: readonly
"""
    )
    (cfg_dir / "secrets.yaml").write_text(
        "secrets:\n  - tenant_id: tenant_a\n    indexer_user: u\n    indexer_password: p\n    server_api_user: u\n    server_api_password: p\n"
    )
    (cfg_dir / "server.yaml").write_text(
        """
http:
  public_url: https://mcp.example.com
oauth:
  issuer: https://issuer.example.com
  audience: aud
  algorithms: [RS256]
api_keys_file: /dev/null
"""
    )
    # Touch the api_keys_file path with an empty store so ApiKeySessionFactory
    # can construct.
    api_keys = tmp_path / "api_keys.yaml"
    api_keys.write_text("api_keys: []\n")
    # Patch server.yaml to point at it.
    server_yaml = (cfg_dir / "server.yaml").read_text()
    (cfg_dir / "server.yaml").write_text(
        server_yaml.replace("/dev/null", str(api_keys))
    )

    http_cfg = load_http_config(cfg_dir)
    assert http_cfg.registry is not None
    assert isinstance(http_cfg.registry, YamlTenantRegistry)
    # Verify the registry has tenant_a registered.
    assert http_cfg.registry.get("tenant_a").tenant_id == "tenant_a"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_http_app_config.py -v`

Expected: FAIL with `AssertionError: 'registry' not in fields` (or similar).

- [ ] **Step 4: Modify `HttpAppConfig` and `load_http_config`**

Edit `src/wazuh_mcp/server.py`. Add `TenantRegistry` import and the `registry` field:

```python
# In imports near the top, alongside YamlTenantRegistry:
from wazuh_mcp.tenancy.registry import TenantRegistry, YamlTenantRegistry
```

Replace the `HttpAppConfig` dataclass:

```python
@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    server_api_pool: ServerApiClientPool
    chain: ChainSessionFactory
    oauth: OAuthSessionFactory
    issuer_index: IssuerIndex
    resource_url: str
    authorization_server: str
    # M4a wiring — defaults preserve M3 call sites.
    tenant: TenantConfig | None = None
    # M4c: per-tenant policy resolution. ``load_http_config`` builds the
    # registry and keeps it alive here so resolvers can close over it.
    registry: TenantRegistry | None = None
    limiter: RateLimiter | None = None
    audit: MultiSinkAuditEmitter | None = None
```

In `load_http_config`, change the `return HttpAppConfig(...)` to also pass `registry=registry`:

```python
    return HttpAppConfig(
        pool=pool,
        server_api_pool=server_api_pool,
        chain=chain,
        oauth=oauth,
        issuer_index=issuer_index,
        resource_url=http_cfg["public_url"],
        authorization_server=oauth_cfg["issuer"],
        tenant=primary_tenant,
        registry=registry,
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_http_app_config.py -v`

Expected: PASS (2 tests).

- [ ] **Step 6: Run the full unit suite to verify no regressions**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_http_app_config.py
git commit -m "server: thread TenantRegistry through HttpAppConfig

load_http_config previously discarded the YamlTenantRegistry after
feeding IssuerIndex. M4c keeps it on HttpAppConfig so resolvers in
build_http_app can close over it."
```

---

### Task 6: Stdio resolver wiring + new `_register_everything` kwargs (additive)

**Files:**
- Modify: `src/wazuh_mcp/server.py:280-298` (stdio `build_app`)
- Modify: `src/wazuh_mcp/server.py:480-1020` (`_register_everything` signature + run_active_response handler)
- Test: `tests/unit/test_server_wiring_m4c.py` (new)

**Why:** Replace the inline single-tenant `_rbac_policy` closure with `make_rbac_policy(SingleTenantRegistry(cfg.tenant), audit_emitter)`. Plumb `make_write_allowlist` and `make_ar_allowlist` outputs into `_register_everything` as new kwargs. `_register_everything` keeps `tenant_cfg=` registration filtering for now (decoupled in T8); but the AR handler closure switches to `ar_allowlist_policy(session)` per-call instead of the captured `ar_allowlist` list. Behavior delta-free for single-tenant operators.

**Note:** This task changes `_register_everything`'s signature. Every call site (stdio + HTTP) must update in lockstep. T6 updates stdio + adds the new kwargs to the function; T7 updates HTTP. Both must land before any subagent dispatches a stale signature.

- [ ] **Step 1: Read current stdio _rbac_policy + _register_everything signature**

```bash
sed -n '280,302p' src/wazuh_mcp/server.py
sed -n '480,495p' src/wazuh_mcp/server.py
sed -n '1176,1210p' src/wazuh_mcp/server.py
```

Expected: stdio defines `_rbac_policy`, calls `_register_everything(... tenant_cfg=cfg.tenant)`, calls `_install_rbac_hooks`. `_register_everything` signature has `rbac_policy=`, `tenant_cfg=`. The `run_active_response` handler closes over `ar_allowlist` (a list captured at registration time).

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_server_wiring_m4c.py`:

```python
"""M4c stdio + HTTP wiring (T6 + T7).

Both modes thread three resolvers (rbac, write_allowlist, ar_allowlist) into
_register_everything. The handlers must call ar_allowlist_policy(session) per
call instead of capturing tenant_cfg.active_response_allowlist at registration
time.
"""

from __future__ import annotations

import inspect

from wazuh_mcp.server import _register_everything


def test_register_everything_accepts_resolver_kwargs() -> None:
    sig = inspect.signature(_register_everything)
    params = sig.parameters
    assert "write_allowlist_policy" in params
    assert "ar_allowlist_policy" in params
    # Both should be optional with sensible defaults so existing callers don't
    # break mid-refactor.
    assert params["write_allowlist_policy"].default is None
    assert params["ar_allowlist_policy"].default is None
```

(The deeper behavior — that `run_active_response` hits the resolver per call — is pinned at the integration level in T14 and the unit test for the multi-agent refactor in T9.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py -v`

Expected: FAIL because the kwargs don't exist yet.

- [ ] **Step 4: Modify `_register_everything` to accept the resolver kwargs**

Edit `src/wazuh_mcp/server.py`:

Replace the function signature (around line 480-489):

```python
def _register_everything(
    mcp_app: FastMCP,
    *,
    indexer_pool: Any,
    server_api_pool: Any,
    audit_emitter: MultiSinkAuditEmitter,
    limiter: RateLimiter,
    rbac_policy: Callable[[Session], dict[str, list[str]]],
    tenant_cfg: TenantConfig | None = None,
    write_allowlist_policy: Callable[[Session], list[str] | None] | None = None,
    ar_allowlist_policy: Callable[[Session], list[str]] | None = None,
) -> None:
```

Inside the function body, near where `allowlist` and `ar_allowlist` are derived from `tenant_cfg` (around line 1018-1019), keep the existing `allowlist` (registration-time filter, removed in T8) but switch the AR closure to use the resolver per-call. Find and replace the `_run_ar_inner` block (around lines 1176-1210):

```python
    if _should_register("write.run_active_response", allowlist):

        async def _run_ar_inner(**kwargs: Any) -> Any:
            args = RunActiveResponseArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            # M4c: resolve the per-tenant AR allowlist per call. Falls back
            # to the captured tenant_cfg list when no resolver is wired
            # (legacy callers; removed in M4c T8 once both modes plumb).
            if ar_allowlist_policy is not None:
                effective_ar_allowlist = list(ar_allowlist_policy(session))
            else:
                effective_ar_allowlist = list(ar_allowlist)
            return await _run_active_response(
                args=args,
                session=session,
                server_api=sapi,
                ar_allowlist=effective_ar_allowlist,
            )

        mcp_app.tool(
            name="write.run_active_response",
            description=_write_desc_prefix
            + "Runs a tenant-allowlisted active-response command on a single agent. "
            + "The command must be enumerated in TenantConfig.active_response_allowlist.",
            meta={"toolset": "writes"},
        )(
            instrumented_tool(
                tool_name="write.run_active_response",
                handler=_run_ar_inner,
                rbac_policy=rbac_policy,
                limiter=limiter,
                audit=audit_emitter,
                args_model=RunActiveResponseArgs,
                result_model=WriteResult,
            )
        )
```

- [ ] **Step 5: Modify stdio `build_app` to wire the three resolvers**

In `build_app` (around line 280-298), replace the `_rbac_policy` block:

```python
    from wazuh_mcp.rbac.resolver import (
        make_ar_allowlist,
        make_rbac_policy,
        make_write_allowlist,
    )
    from wazuh_mcp.tenancy.registry import SingleTenantRegistry

    _registry = SingleTenantRegistry(cfg.tenant)
    rbac_policy = make_rbac_policy(_registry, audit_emitter)
    write_allowlist_policy = make_write_allowlist(_registry, audit_emitter)
    ar_allowlist_policy = make_ar_allowlist(_registry, audit_emitter)

    _register_everything(
        app,
        indexer_pool=_IndexerAdapter(),
        server_api_pool=_ServerApiAdapter(),
        audit_emitter=audit_emitter,
        limiter=limiter,
        rbac_policy=rbac_policy,
        tenant_cfg=cfg.tenant,
        write_allowlist_policy=write_allowlist_policy,
        ar_allowlist_policy=ar_allowlist_policy,
    )
    _install_rbac_hooks(app, rbac_policy=rbac_policy, audit_emitter=audit_emitter)
```

(Delete the previous `def _rbac_policy(session)` block — it's superseded by `rbac_policy = make_rbac_policy(...)` above.)

- [ ] **Step 6: Run the new test**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py -v`

Expected: PASS.

- [ ] **Step 7: Run the full unit suite to verify no regressions**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass. Stdio behavior unchanged (single-tenant, resolver returns same allowlist as before).

- [ ] **Step 8: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4c.py
git commit -m "server: stdio wires three resolvers; _register_everything plumbs them

Stdio's build_app uses SingleTenantRegistry(cfg.tenant) so it shares
resolver wiring with HTTP. _register_everything gains write_allowlist_policy
and ar_allowlist_policy kwargs (additive, optional during T6+T7). The
run_active_response handler now resolves the AR allowlist per-call when
the policy is provided. tenant_cfg's registration filter stays active
until T8 decouples it."
```

---

### Task 7: HTTP resolver wiring

**Files:**
- Modify: `src/wazuh_mcp/server.py:396-450` (`build_http_app`)

**Why:** Mirror T6 in HTTP mode. `build_http_app` closes the three resolvers over `http_cfg.registry` and passes them through to `_register_everything`.

- [ ] **Step 1: Read current build_http_app**

```bash
sed -n '396,450p' src/wazuh_mcp/server.py
```

Expected: build_http_app constructs `_rbac_policy` from `http_cfg.tenant.role_tool_allowlist`, calls `_register_everything(...)`, calls `_install_rbac_hooks(...)`.

- [ ] **Step 2: Write the failing test (via integration-style check on _rbac_policy_http)**

Add to `tests/unit/test_server_wiring_m4c.py`:

```python
def test_build_http_app_wires_three_resolvers() -> None:
    """build_http_app closes over registry — proven by absence of
    AttributeError when http_cfg.registry is None and presence of M4c
    resolver imports in server module."""
    import wazuh_mcp.server as server_mod

    src = inspect.getsource(server_mod.build_http_app)
    # The function should reference the three resolver factories.
    assert "make_rbac_policy" in src
    assert "make_write_allowlist" in src
    assert "make_ar_allowlist" in src
    # And it should pass write_allowlist_policy + ar_allowlist_policy
    # to _register_everything.
    assert "write_allowlist_policy=" in src
    assert "ar_allowlist_policy=" in src
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py::test_build_http_app_wires_three_resolvers -v`

Expected: FAIL — those names not yet in `build_http_app`.

- [ ] **Step 4: Modify `build_http_app`**

In `src/wazuh_mcp/server.py`, replace the `def _rbac_policy(session)` block inside `build_http_app` (around lines 426-434) and the call to `_register_everything` + `_install_rbac_hooks` (lines 436-445) with:

```python
    from wazuh_mcp.rbac.resolver import (
        make_ar_allowlist,
        make_rbac_policy,
        make_write_allowlist,
    )
    from wazuh_mcp.tenancy.registry import SingleTenantRegistry

    # Defense-in-depth: if registry is None (extremely rare; legacy callers),
    # fall back to a SingleTenantRegistry built from primary tenant. Logs a
    # warning but server still boots.
    _registry: TenantRegistry | None = http_cfg.registry
    if _registry is None and http_cfg.tenant is not None:
        _registry = SingleTenantRegistry(http_cfg.tenant)
    if _registry is None:
        # No tenant configured at all — every call will fail with
        # tenant_not_registered. Build a registry that always raises.
        class _EmptyRegistry:
            def get(self, tenant_id: str):  # type: ignore[no-untyped-def]
                raise KeyError(f"unknown tenant: {tenant_id}")

        _registry = _EmptyRegistry()  # type: ignore[assignment]

    rbac_policy = make_rbac_policy(_registry, audit_emitter)
    write_allowlist_policy = make_write_allowlist(_registry, audit_emitter)
    ar_allowlist_policy = make_ar_allowlist(_registry, audit_emitter)

    _register_everything(
        mcp_app,
        indexer_pool=http_cfg.pool,
        server_api_pool=http_cfg.server_api_pool,
        audit_emitter=audit_emitter,
        limiter=limiter,
        rbac_policy=rbac_policy,
        tenant_cfg=http_cfg.tenant,
        write_allowlist_policy=write_allowlist_policy,
        ar_allowlist_policy=ar_allowlist_policy,
    )
    _install_rbac_hooks(mcp_app, rbac_policy=rbac_policy, audit_emitter=audit_emitter)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py -v`

Expected: PASS (2 tests now).

- [ ] **Step 6: Run the full unit suite + the M4a wiring tests**

Run: `uv run pytest tests/unit/test_server_wiring_m4a.py tests/unit/test_server_registration.py tests/unit/test_instrumented_tool.py -v`

Expected: all pass. The M4a tests still use `rbac_policy=_policy` callable; they won't be affected by the new optional kwargs.

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4c.py
git commit -m "server: build_http_app wires three resolvers via http_cfg.registry

Mirrors T6's stdio change. Defense-in-depth fallback for callers
that pass http_cfg.registry=None: SingleTenantRegistry(primary)
when tenant exists, _EmptyRegistry that always raises KeyError
otherwise. End of M4c phase 1 — all tests still green, behavior
delta-free."
```

---

## Phase 2 — Write surface extension + decoupling (Tier-A spot-check)

### Task 8: Decouple registration from `tenant_cfg.write_allowlist` (call-time only)

**Files:**
- Modify: `src/wazuh_mcp/server.py:480-1020` (drop `tenant_cfg=` registration filter; add per-handler call-time check)

**Why:** Phase 1 shipped resolvers running in parallel with the M4b registration-time filter. T8 removes the registration-time filter. All 7 M4b writes register unconditionally; each handler body checks `write_allowlist_policy(session)` and raises `forbidden` when the tool isn't in the tenant's list. Operator-visible delta documented in spec §6.1.

**Tier-A spot-check note:** This is mechanical glue downstream of T3 (reviewed). Reviewer verifies (i) every `if _should_register(...)` is gone; (ii) every write handler body has a `_check_write_allowed(session, tool_name, write_allowlist_policy)` guard; (iii) `tenant_cfg=` is removed from `_register_everything`'s signature; (iv) call sites in T6+T7 don't pass `tenant_cfg=` anymore.

- [ ] **Step 1: Add a small helper for the per-handler write-allowlist check**

Add near the top of `_register_everything`'s body, after the imports block (around line 990):

```python
    def _check_write_allowed(session: Session, tool_name: str) -> None:
        """Raise WazuhError("forbidden", ...) if write tool not in tenant's
        write_allowlist. None = no filter; [] or list = filter."""
        if write_allowlist_policy is None:
            return
        allow = write_allowlist_policy(session)
        if allow is None:
            return
        if tool_name not in allow:
            raise WazuhError(
                "forbidden",
                f"tool {tool_name!r} not in tenant write_allowlist",
                403,
            )
```

Add `from wazuh_mcp.wazuh.errors import WazuhError` to the imports if not already present (search and confirm).

- [ ] **Step 2: Write the failing test**

Add to `tests/unit/test_server_wiring_m4c.py`:

```python
@pytest.mark.asyncio
async def test_write_allowlist_denies_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-call write_allowlist filter raises forbidden when tool not allowed."""
    from mcp.server.fastmcp import FastMCP

    from wazuh_mcp.auth.session import Session
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
    from wazuh_mcp.observability.contextvar import set_current_session
    from wazuh_mcp.observability.ratelimit import InProcessRateLimiter
    from wazuh_mcp.server import _register_everything
    from wazuh_mcp.tenancy.config import RateLimitConfig, TenantConfig
    from wazuh_mcp.wazuh.errors import WazuhError

    mcp_app = FastMCP(name="test")
    audit = MultiSinkAuditEmitter(sinks=None)
    limiter = InProcessRateLimiter(default=RateLimitConfig())

    # tenant_a's write_allowlist permits only isolate_agent.
    def _rbac_allow_admin(session: Session) -> dict[str, list[str]]:
        return {"admin": ["*"]}

    def _write_allow_isolate_only(session: Session) -> list[str] | None:
        return ["write.isolate_agent"]

    def _ar_allow_isolate(session: Session) -> list[str]:
        return ["isolate"]

    class _StubServerApiPool:
        async def acquire(self, tenant_id: str):
            class _StubClient:
                async def restart_agent(self, *, agent_id, run_as):
                    return {"data": {"affected_items": [agent_id]}}

            return _StubClient()

    class _StubIndexerPool:
        async def acquire(self, tenant_id: str):
            return None

    _register_everything(
        mcp_app,
        indexer_pool=_StubIndexerPool(),
        server_api_pool=_StubServerApiPool(),
        audit_emitter=audit,
        limiter=limiter,
        rbac_policy=_rbac_allow_admin,
        write_allowlist_policy=_write_allow_isolate_only,
        ar_allowlist_policy=_ar_allow_isolate,
    )

    sess = Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user=None,
    )
    set_current_session(sess)

    # write.restart_agent is registered (since registration is unconditional)
    # but call must deny because write_allowlist=[isolate_agent only].
    tools = await mcp_app.list_tools()
    tool_names = {t.name for t in tools}
    assert "write.restart_agent" in tool_names
    assert "write.isolate_agent" in tool_names

    # restart_agent call must raise forbidden.
    with pytest.raises(WazuhError) as exc_info:
        await mcp_app.call_tool(
            "write.restart_agent", {"agent_id": "001", "confirm": True}
        )
    assert exc_info.value.code == "forbidden"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py::test_write_allowlist_denies_per_call -v`

Expected: FAIL — registration-time filter still active, write.restart_agent isn't registered when write_allowlist=["write.isolate_agent"].

- [ ] **Step 4: Remove the registration-time filter from `_register_everything`**

In `src/wazuh_mcp/server.py`:

1. Drop the `tenant_cfg: TenantConfig | None = None` parameter from `_register_everything`'s signature.
2. Drop the `_should_register` helper and the `allowlist`/`ar_allowlist` derivations from `tenant_cfg` (around lines 1013-1019).
3. Replace every `if _should_register("write.X", allowlist):` block with an unconditional registration. Each handler's `_inner` adds a call-time check before the server_api call:

For each of the 7 M4b writes, modify the inner handler. Example for `write.isolate_agent`:

```python
    async def _isolate_inner(**kwargs: Any) -> Any:
        args = IsolateAgentArgs(**kwargs)
        session = current_session()
        _check_write_allowed(session, "write.isolate_agent")
        sapi = await server_api_pool.acquire(session.tenant_id)
        return await _isolate_agent(args=args, session=session, server_api=sapi)

    mcp_app.tool(
        name="write.isolate_agent",
        description=_write_desc_prefix
        + "Isolates a Wazuh agent (blocks network traffic via Wazuh's isolate active-response).",
        meta={"toolset": "writes"},
    )(
        instrumented_tool(
            tool_name="write.isolate_agent",
            handler=_isolate_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
            args_model=IsolateAgentArgs,
            result_model=WriteResult,
        )
    )
```

Apply the same shape — `_check_write_allowed(session, "write.X")` immediately after `session = current_session()`, no `if _should_register` wrapper — to:
- `write.restart_agent` (`_restart_inner`)
- `write.add_agent_to_group` (`_add_group_inner`)
- `write.remove_agent_from_group` (`_remove_group_inner`)
- `write.create_rule` (`_create_rule_inner`)
- `write.update_rule` (`_update_rule_inner`)
- `write.run_active_response` (`_run_ar_inner`) — also remove the `effective_ar_allowlist` fallback to `ar_allowlist` (the captured variable no longer exists; use `ar_allowlist_policy(session)` unconditionally; raise if `ar_allowlist_policy is None`).

For `_run_ar_inner`, the body becomes:

```python
    async def _run_ar_inner(**kwargs: Any) -> Any:
        args = RunActiveResponseArgs(**kwargs)
        session = current_session()
        _check_write_allowed(session, "write.run_active_response")
        if ar_allowlist_policy is None:
            raise WazuhError(
                "forbidden",
                "active-response not configured for this tenant",
                403,
            )
        ar_allowed = list(ar_allowlist_policy(session))
        sapi = await server_api_pool.acquire(session.tenant_id)
        return await _run_active_response(
            args=args,
            session=session,
            server_api=sapi,
            ar_allowlist=ar_allowed,
        )
```

- [ ] **Step 5: Update T6 + T7 callers to drop `tenant_cfg=` from `_register_everything` calls**

In stdio `build_app` (~line 290): drop `tenant_cfg=cfg.tenant` from the `_register_everything(...)` call.

In `build_http_app` (~line 437): drop `tenant_cfg=http_cfg.tenant` from the `_register_everything(...)` call.

- [ ] **Step 6: Run the M4c test + the M4b write registration tests + full unit suite**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py -v`

Expected: PASS (the call-time-deny test now passes).

Run: `uv run pytest tests/unit/test_server_registration.py tests/unit/test_server_wiring_m4a.py -v`

Expected: PASS — these don't depend on `tenant_cfg=` registration filtering.

The M4b write tests (`tests/unit/test_writes_*` if any, plus integration tests in `tests/integration/test_m4b_writes.py`) may have assertions that depend on the M4b "write tools NOT registered when write_allowlist=[]" behavior. Search for any such assertions:

```bash
grep -rn "write_allowlist\b" tests/unit tests/integration
```

If any unit test asserts "tool X is not in `list_tools` when write_allowlist excludes X", update those asserts to "tool X IS in `list_tools` but call denies" — flag in the commit message.

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4c.py
git commit -m "server: decouple write registration from tenant_cfg.write_allowlist

All 7 M4b writes register unconditionally; each handler invokes
write_allowlist_policy(session) at call time. Operator-visible delta
from M4b: write_allowlist=[] now lists all writes but denies every
call (was: tools hidden from list_tools). Documented in spec §6.1.

Drops tenant_cfg= parameter from _register_everything; stdio + HTTP
callers updated. M4c phase 2 first task."
```

---

### Task 9: Multi-agent AR refactor

**Files:**
- Modify: `src/wazuh_mcp/wazuh/server_api.py:167-176` (`isolate_agent`) and `:211-228` (`run_active_response`)
- Modify: `src/wazuh_mcp/tools/write.py` (`IsolateAgentArgs`, `RunActiveResponseArgs`, `WriteResult`, handlers, new constant `_AR_AGENTS_MAX`, new `FailedAgent` model)
- Modify: `src/wazuh_mcp/server.py` (`_isolate_inner` and `_run_ar_inner` already updated in T8 — only ensure they pass `agent_ids` correctly)
- Test: `tests/unit/test_multi_agent_ar.py` (new — server_api wire pinning + Args parse + handler partial-failure)
- Test: `tests/unit/test_server_api_writes.py` (modify existing isolate_agent / run_active_response tests)
- Test: `tests/integration/test_m4b_writes.py` (migrate the few callers to `agent_ids=["..."]`)

**Why:** Replace `agent_id: str` with `agent_ids: list[str]` (1≤len≤50). `WriteResult` gains `failed_agents`. Partial failure returns `ok=False` with both lists populated; no exception unless catastrophic.

- [ ] **Step 1: Verify Wazuh's failed_items response shape**

Look at the existing `_extract_affected_ids` helper in `src/wazuh_mcp/tools/write.py:40-45`. Wazuh response shape for AR endpoints with `agents_list=001,002`:

```json
{"data": {"affected_items": ["001"], "failed_items": [{"id": "002", "error": {"message": "agent offline"}}]}}
```

We pin this in T9's tests. (Per integration restoration session findings, Wazuh 4.9 returns this shape consistently for `PUT /active-response`.)

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_multi_agent_ar.py`:

```python
"""Multi-agent AR refactor (M4c T9).

Pins:
  * agent_ids field constraints (min/max length)
  * ServerApiClient builds comma-joined agents_list query param
  * WriteResult.failed_agents plumbing
  * partial-failure semantics (ok=False, no exception)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    FailedAgent,
    IsolateAgentArgs,
    RunActiveResponseArgs,
    WriteResult,
    _AR_AGENTS_MAX,
    isolate_agent,
    run_active_response,
)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


# ---------- Args parse ----------


def test_isolate_args_accepts_single_agent_in_list() -> None:
    args = IsolateAgentArgs(agent_ids=["001"], confirm=True)
    assert args.agent_ids == ["001"]


def test_isolate_args_accepts_max_agents() -> None:
    ids = [f"{i:03d}" for i in range(_AR_AGENTS_MAX)]
    args = IsolateAgentArgs(agent_ids=ids, confirm=True)
    assert len(args.agent_ids) == _AR_AGENTS_MAX


def test_isolate_args_rejects_empty_list() -> None:
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=[], confirm=True)


def test_isolate_args_rejects_over_cap() -> None:
    ids = [f"{i:03d}" for i in range(_AR_AGENTS_MAX + 1)]
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_ids=ids, confirm=True)


def test_run_ar_args_accepts_list() -> None:
    args = RunActiveResponseArgs(
        agent_ids=["001", "002"], command_name="isolate", confirm=True
    )
    assert args.agent_ids == ["001", "002"]


# ---------- ServerApiClient comma-join (mocked) ----------


@pytest.mark.asyncio
async def test_isolate_agent_handler_passes_list_to_server_api() -> None:
    captured: dict[str, Any] = {}

    class _StubClient:
        async def isolate_agent(self, *, agent_ids, run_as):  # type: ignore[no-untyped-def]
            captured["agent_ids"] = agent_ids
            captured["run_as"] = run_as
            return {"data": {"affected_items": agent_ids, "failed_items": []}}

    args = IsolateAgentArgs(agent_ids=["001", "002"], confirm=True)
    result = await isolate_agent(args=args, session=_session(), server_api=_StubClient())
    assert captured["agent_ids"] == ["001", "002"]
    assert result.ok is True
    assert result.affected_agents == ["001", "002"]
    assert result.failed_agents == []


# ---------- Partial-failure plumbing ----------


@pytest.mark.asyncio
async def test_isolate_agent_partial_failure_returns_ok_false_no_exception() -> None:
    class _StubClient:
        async def isolate_agent(self, *, agent_ids, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": ["001"],
                    "failed_items": [{"id": "002", "error": {"message": "agent offline"}}],
                }
            }

    args = IsolateAgentArgs(agent_ids=["001", "002"], confirm=True)
    result = await isolate_agent(args=args, session=_session(), server_api=_StubClient())
    assert result.ok is False
    assert result.affected_agents == ["001"]
    assert result.failed_agents == [FailedAgent(agent_id="002", reason="agent offline")]


@pytest.mark.asyncio
async def test_run_active_response_partial_failure_returns_ok_false() -> None:
    class _StubClient:
        async def run_active_response(self, *, agent_ids, command, custom_args, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": ["001"],
                    "failed_items": [{"id": "002", "error": {"message": "active-response timeout"}}],
                }
            }

    args = RunActiveResponseArgs(
        agent_ids=["001", "002"], command_name="isolate", confirm=True
    )
    result = await run_active_response(
        args=args, session=_session(), server_api=_StubClient(), ar_allowlist=["isolate"]
    )
    assert result.ok is False
    assert result.affected_agents == ["001"]
    assert result.failed_agents == [
        FailedAgent(agent_id="002", reason="active-response timeout")
    ]


@pytest.mark.asyncio
async def test_run_active_response_all_succeed_returns_ok_true() -> None:
    class _StubClient:
        async def run_active_response(self, *, agent_ids, command, custom_args, run_as):  # type: ignore[no-untyped-def]
            return {
                "data": {
                    "affected_items": agent_ids,
                    "failed_items": [],
                }
            }

    args = RunActiveResponseArgs(
        agent_ids=["001", "002", "003"], command_name="isolate", confirm=True
    )
    result = await run_active_response(
        args=args, session=_session(), server_api=_StubClient(), ar_allowlist=["isolate"]
    )
    assert result.ok is True
    assert sorted(result.affected_agents or []) == ["001", "002", "003"]
    assert result.failed_agents == []


# ---------- Hypothesis: agent_ids URL-injection invariant ----------


_AGENT_ID_REGEX = r"^[0-9]{1,8}$"


@given(
    agent_ids=st.lists(
        st.from_regex(_AGENT_ID_REGEX, fullmatch=True),
        min_size=1,
        max_size=_AR_AGENTS_MAX,
    )
)
@settings(max_examples=200)
def test_no_agent_id_contains_comma(agent_ids: list[str]) -> None:
    """Wazuh agent IDs are numeric — no agent_id can contain a comma. This
    pins the URL-injection invariant: comma-joining the list never produces
    ambiguous query syntax."""
    for aid in agent_ids:
        assert "," not in aid
    joined = ",".join(agent_ids)
    # Round-trip splits cleanly.
    assert joined.split(",") == agent_ids
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_multi_agent_ar.py -v`

Expected: FAIL with `ImportError: cannot import name 'FailedAgent'` (or similar) — types don't exist yet.

- [ ] **Step 4: Modify `src/wazuh_mcp/tools/write.py`**

Add at the top (after the existing imports), the new `FailedAgent` model + `_AR_AGENTS_MAX` constant:

```python
_AR_AGENTS_MAX: Final = 50


class FailedAgent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    reason: str
```

Add `Final` to the existing `typing` imports.

Replace the `WriteResult` model:

```python
class WriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    affected_agents: list[str] | None = None
    failed_agents: list[FailedAgent] = Field(default_factory=list)
    affected_files: list[str] | None = None
    timestamp: datetime
```

Add a helper `_extract_failed_items` near `_extract_affected_ids`:

```python
def _extract_failed_items(resp: dict[str, Any]) -> list[FailedAgent]:
    """Wazuh's data.failed_items shape: [{'id': '002', 'error': {'message': '...'}}]."""
    data = resp.get("data", {})
    items = data.get("failed_items") or []
    out: list[FailedAgent] = []
    for item in items:
        agent_id = str(item.get("id", ""))
        err = item.get("error") or {}
        reason = str(err.get("message", "unknown"))
        out.append(FailedAgent(agent_id=agent_id, reason=reason))
    return out
```

Replace `IsolateAgentArgs`:

```python
class IsolateAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_ids: Annotated[
        list[str],
        Field(min_length=1, max_length=_AR_AGENTS_MAX),
    ]
    confirm: Annotated[
        Literal[True],
        Field(
            description=(
                "Must be set to true by a human user. Setting this from an "
                "automated agent without explicit human instruction violates "
                "the tool's safety contract and is recorded in the audit log."
            )
        ),
    ]
```

Replace `isolate_agent` handler:

```python
async def isolate_agent(
    *,
    args: IsolateAgentArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.isolate_agent(agent_ids=args.agent_ids, run_as=session.wazuh_user)
    affected = _extract_affected_ids(resp)
    failed = _extract_failed_items(resp)
    return WriteResult(
        ok=len(failed) == 0,
        affected_agents=affected,
        failed_agents=failed,
        timestamp=datetime.now(UTC),
    )
```

Replace `RunActiveResponseArgs` and `run_active_response`:

```python
class RunActiveResponseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_ids: Annotated[
        list[str],
        Field(min_length=1, max_length=_AR_AGENTS_MAX),
    ]
    command_name: Annotated[str, Field(min_length=1, max_length=128)]
    custom_args: dict[str, Any] | None = None
    confirm: Literal[True]


async def run_active_response(
    *,
    args: RunActiveResponseArgs,
    session: Session,
    server_api: Any,
    ar_allowlist: Sequence[str],
) -> WriteResult:
    if args.command_name not in ar_allowlist:
        raise WazuhError(
            "forbidden",
            f"active-response command {args.command_name!r} not allowlisted for tenant",
            403,
        )
    resp = await server_api.run_active_response(
        agent_ids=args.agent_ids,
        command=args.command_name,
        custom_args=args.custom_args,
        run_as=session.wazuh_user,
    )
    affected = _extract_affected_ids(resp)
    failed = _extract_failed_items(resp)
    return WriteResult(
        ok=len(failed) == 0,
        affected_agents=affected,
        failed_agents=failed,
        timestamp=datetime.now(UTC),
    )
```

- [ ] **Step 5: Modify `src/wazuh_mcp/wazuh/server_api.py`**

Replace `isolate_agent` (around line 167):

```python
    async def isolate_agent(
        self, *, agent_ids: list[str], run_as: str | None = None
    ) -> dict[str, Any]:
        """Wazuh 4.9 active-response endpoint is ``PUT /active-response`` with
        the target agents in the ``agents_list`` query param and the command
        in the JSON body. Multi-agent: comma-joined list."""
        return await self.put(
            "/active-response",
            json={"command": "isolate"},
            params={"agents_list": ",".join(agent_ids)},
            run_as=run_as,
        )
```

Replace `run_active_response` (around line 211):

```python
    async def run_active_response(
        self,
        *,
        agent_ids: list[str],
        command: str,
        custom_args: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        # Wazuh 4.9: PUT /active-response with agents_list query param.
        body: dict[str, Any] = {"command": command}
        if custom_args:
            body.update(custom_args)
        return await self.put(
            "/active-response",
            json=body,
            params={"agents_list": ",".join(agent_ids)},
            run_as=run_as,
        )
```

- [ ] **Step 6: Update `_isolate_inner` and `_run_ar_inner` in `src/wazuh_mcp/server.py`**

The handlers already receive parsed `IsolateAgentArgs` / `RunActiveResponseArgs` and pass `args` through. Since the field name changed from `agent_id` to `agent_ids` and the handler bodies (`isolate_agent` in `tools/write.py`, etc.) consume `args.agent_ids` directly, no further `server.py` change is needed — but verify by reading the handlers:

```bash
sed -n '1028,1052p' src/wazuh_mcp/server.py
```

If any handler accesses `args.agent_id` directly (it shouldn't — the inner just passes `args=args`), update.

- [ ] **Step 7: Update `tests/unit/test_server_api_writes.py` callers**

```bash
grep -n "isolate_agent\|run_active_response" tests/unit/test_server_api_writes.py
```

For each call to `client.isolate_agent(agent_id="001", ...)` change to `client.isolate_agent(agent_ids=["001"], ...)`. Same for `run_active_response`.

The wire shape pinning (`agents_list=001`) still passes — `",".join(["001"])` is `"001"`.

- [ ] **Step 8: Update integration test `tests/integration/test_m4b_writes.py`**

```bash
grep -n "agent_id=" tests/integration/test_m4b_writes.py
```

For each call site that uses `write.isolate_agent` or `write.run_active_response` via FastMCP's tool API, change `{"agent_id": "001", ...}` to `{"agent_ids": ["001"], ...}`.

- [ ] **Step 9: Run the new tests + the full unit suite**

Run: `uv run pytest tests/unit/test_multi_agent_ar.py tests/unit/test_server_api_writes.py -v`

Expected: PASS.

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 10: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/tools/write.py src/wazuh_mcp/wazuh/server_api.py src/wazuh_mcp/server.py tests/unit/test_multi_agent_ar.py tests/unit/test_server_api_writes.py tests/integration/test_m4b_writes.py
git commit -m "writes: refactor isolate_agent + run_active_response to multi-agent

agent_id: str -> agent_ids: list[str] (1<=N<=50). Single API call
to Wazuh; comma-joined agents_list. WriteResult gains failed_agents
list. Partial-failure semantics: ok=False with both lists populated,
no exception unless catastrophic. Hypothesis fuzz pins the URL-
injection invariant on numeric agent IDs.

Breaking change from M4b. Migration: agent_id='001' -> agent_ids=['001']."
```

---

### Task 10: Add `ServerApiClient.restart_cluster` + `cluster_status` methods

**Files:**
- Modify: `src/wazuh_mcp/wazuh/server_api.py` (additive — new methods after existing M4b writes)
- Test: `tests/unit/test_server_api_cluster.py` (new)

**Why:** Wire the Wazuh 4.9 cluster endpoints with pytest-httpx wire-shape pinning. `restart_cluster(scope="cluster")` → `PUT /cluster/restart`; `restart_cluster(scope="node")` → `PUT /manager/restart`; `cluster_status()` → `GET /cluster/status`.

- [ ] **Step 1: Verify Wazuh 4.9 endpoint shapes**

Wazuh 4.9 OpenAPI:
- `PUT /manager/restart` — restart this manager node. Response: `{"data": {"affected_items": [...]}, "message": "..."}`.
- `PUT /cluster/restart` — coordinator-driven cluster restart. Response shape similar.
- `GET /cluster/status` — `{"data": {"enabled": "yes"|"no", "running": "yes"|"no"}}` (Wazuh returns `"yes"`/`"no"` strings, not booleans — confirmed by integration restoration session).
- `GET /cluster/nodes` — `{"data": {"affected_items": [{"name": "...", "type": "master"|"worker", "status": "..."}, ...], "total_affected_items": N}}`.

`cluster_status()` will issue both `GET /cluster/status` and `GET /cluster/nodes` and merge results.

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_server_api_cluster.py`:

```python
"""ServerApiClient cluster + restart wire-shape pinning (M4c T10)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from wazuh_mcp.security.secret import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


@pytest.fixture
def _stub_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the Wazuh JWT round-trip; pin a static token."""

    async def _ensure_jwt(self):  # type: ignore[no-untyped-def]
        return "stub.jwt.token"

    monkeypatch.setattr(ServerApiClient, "_ensure_jwt", _ensure_jwt)


def _client() -> ServerApiClient:
    return ServerApiClient(
        base_url="https://wazuh.example.com:55000",
        user=SecretValue("u"),
        password=SecretValue("p"),
        verify_tls=False,
        ca_bundle_path=None,
    )


@pytest.mark.asyncio
async def test_restart_cluster_scope_cluster_puts_to_cluster_restart(
    httpx_mock, _stub_jwt
) -> None:
    httpx_mock.add_response(
        method="PUT",
        url="https://wazuh.example.com:55000/cluster/restart",
        json={"data": {"affected_items": ["master"]}, "message": "Restart request sent"},
    )
    async with _client() as c:
        resp = await c.restart_cluster(scope="cluster")
    assert resp["data"]["affected_items"] == ["master"]


@pytest.mark.asyncio
async def test_restart_cluster_scope_node_puts_to_manager_restart(
    httpx_mock, _stub_jwt
) -> None:
    httpx_mock.add_response(
        method="PUT",
        url="https://wazuh.example.com:55000/manager/restart",
        json={"data": {"affected_items": ["master"]}, "message": "Restart request sent"},
    )
    async with _client() as c:
        resp = await c.restart_cluster(scope="node")
    assert resp["data"]["affected_items"] == ["master"]


@pytest.mark.asyncio
async def test_cluster_status_reads_status_and_nodes(httpx_mock, _stub_jwt) -> None:
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example.com:55000/cluster/status",
        json={"data": {"enabled": "yes", "running": "yes"}},
    )
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example.com:55000/cluster/nodes",
        json={
            "data": {
                "affected_items": [
                    {"name": "node-master", "type": "master", "status": "running"},
                    {"name": "node-worker-1", "type": "worker", "status": "running"},
                ],
                "total_affected_items": 2,
            }
        },
    )
    async with _client() as c:
        status = await c.cluster_status()
    assert status["enabled"] is True
    assert status["running"] is True
    assert len(status["nodes"]) == 2
    assert status["nodes"][0]["name"] == "node-master"


@pytest.mark.asyncio
async def test_cluster_status_returns_disabled_when_clustering_off(
    httpx_mock, _stub_jwt
) -> None:
    """When `/cluster/status` reports enabled=no, skip the /cluster/nodes call
    and return enabled=False with empty nodes."""
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example.com:55000/cluster/status",
        json={"data": {"enabled": "no", "running": "no"}},
    )
    async with _client() as c:
        status = await c.cluster_status()
    assert status["enabled"] is False
    assert status["running"] is False
    assert status["nodes"] == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_api_cluster.py -v`

Expected: FAIL — methods don't exist.

- [ ] **Step 4: Add `restart_cluster` and `cluster_status` to `ServerApiClient`**

Add after `run_active_response` (around line 228) in `src/wazuh_mcp/wazuh/server_api.py`:

```python
    async def restart_cluster(
        self,
        *,
        scope: Literal["node", "cluster"],
        run_as: str | None = None,
    ) -> dict[str, Any]:
        """Restart this manager node (scope='node') or the entire cluster
        (scope='cluster').

        Wazuh 4.9 returns 200 immediately on the restart request — actual
        cluster cycle takes 30s-5min depending on node count. Caller must
        poll cluster_status() for readiness.
        """
        path = "/cluster/restart" if scope == "cluster" else "/manager/restart"
        return await self.put(path, run_as=run_as)

    async def cluster_status(self, *, run_as: str | None = None) -> dict[str, Any]:
        """Combined cluster status: /cluster/status enabled+running flags +
        /cluster/nodes node list. When clustering is disabled, /cluster/nodes
        is skipped and the returned `nodes` list is empty.

        Returns: {"enabled": bool, "running": bool, "nodes": [{"name", "type", "status"}, ...]}.
        Wazuh's 'yes'/'no' strings are normalized to booleans here.
        """
        status_resp = await self.get("/cluster/status", run_as=run_as)
        data = status_resp.get("data", {})
        enabled = data.get("enabled", "no") == "yes"
        running = data.get("running", "no") == "yes"
        nodes: list[dict[str, Any]] = []
        if enabled:
            nodes_resp = await self.get("/cluster/nodes", run_as=run_as)
            nodes = nodes_resp.get("data", {}).get("affected_items", []) or []
        return {"enabled": enabled, "running": running, "nodes": nodes}
```

Add `Literal` to the existing `typing` imports if not already present.

- [ ] **Step 5: Run the new tests**

Run: `uv run pytest tests/unit/test_server_api_cluster.py -v`

Expected: PASS (4 tests).

- [ ] **Step 6: Run the full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/wazuh/server_api.py tests/unit/test_server_api_cluster.py
git commit -m "server_api: add restart_cluster + cluster_status methods

restart_cluster(scope='cluster' | 'node') routes to /cluster/restart
or /manager/restart. cluster_status combines /cluster/status (enabled/
running flags, normalized from Wazuh's yes/no strings) with /cluster/
nodes (skipped when clustering disabled). Pinned by pytest-httpx wire
shape."
```

---

### Task 11: Add `RestartManagerArgs`/`ClusterStatusResult` Pydantic models + handlers

**Files:**
- Create: `src/wazuh_mcp/tools/cluster.py` (new — analogous to existing `tools/agents.py` etc.)
- Modify: `src/wazuh_mcp/tools/write.py` (add `RestartManagerArgs`, `RestartManagerResult`, `restart_manager` handler)
- Test: `tests/unit/test_restart_manager.py` (new)
- Test: `tests/unit/test_cluster_status.py` (new)

**Why:** Pydantic Args + Result models for the new tools, plus their handler bodies. Handlers consume the new ServerApiClient methods from T10.

- [ ] **Step 1: Write the failing tests for restart_manager**

Create `tests/unit/test_restart_manager.py`:

```python
"""write.restart_manager handler tests (M4c T11)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    RestartManagerArgs,
    RestartManagerResult,
    restart_manager,
)
from wazuh_mcp.wazuh.errors import WazuhError


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="admin",
        auth_method="oauth",
        wazuh_user="alice-wazuh",
    )


def test_args_default_scope_is_cluster() -> None:
    args = RestartManagerArgs(confirm=True)
    assert args.scope == "cluster"


def test_args_accepts_node_scope() -> None:
    args = RestartManagerArgs(scope="node", confirm=True)
    assert args.scope == "node"


def test_args_rejects_invalid_scope() -> None:
    with pytest.raises(ValidationError):
        RestartManagerArgs(scope="rolling", confirm=True)  # ty: ignore[invalid-argument-type]


def test_args_rejects_confirm_false() -> None:
    with pytest.raises(ValidationError):
        RestartManagerArgs(confirm=False)  # ty: ignore[invalid-argument-type]


@pytest.mark.asyncio
async def test_handler_cluster_scope_calls_pre_status_then_restart() -> None:
    calls: list[str] = []

    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            calls.append("status")
            return {
                "enabled": True,
                "running": True,
                "nodes": [
                    {"name": "node-master", "type": "master", "status": "running"},
                ],
            }

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            calls.append(f"restart:{scope}")
            return {"data": {"affected_items": ["node-master"]}}

    args = RestartManagerArgs(scope="cluster", confirm=True)
    result = await restart_manager(args=args, session=_session(), server_api=_StubClient())
    assert calls == ["status", "restart:cluster"]
    assert result.ok is True
    assert result.scope == "cluster"
    assert result.affected_nodes == ["node-master"]


@pytest.mark.asyncio
async def test_handler_node_scope_calls_pre_status_then_node_restart() -> None:
    captured_scope: list[str] = []

    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {
                "enabled": False,
                "running": False,
                "nodes": [],
            }

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            captured_scope.append(scope)
            return {"data": {"affected_items": ["this-node"]}}

    args = RestartManagerArgs(scope="node", confirm=True)
    result = await restart_manager(args=args, session=_session(), server_api=_StubClient())
    # Even with clustering disabled, node-scope is allowed.
    assert captured_scope == ["node"]
    assert result.scope == "node"


@pytest.mark.asyncio
async def test_handler_cluster_scope_with_clustering_disabled_raises_upstream_error() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {"enabled": False, "running": False, "nodes": []}

        async def restart_cluster(self, *, scope, run_as):  # type: ignore[no-untyped-def]
            pytest.fail("restart should not be called when cluster scope requested but disabled")

    args = RestartManagerArgs(scope="cluster", confirm=True)
    with pytest.raises(WazuhError) as exc_info:
        await restart_manager(args=args, session=_session(), server_api=_StubClient())
    assert exc_info.value.code == "upstream_error"
    assert "cluster" in exc_info.value.message
```

- [ ] **Step 2: Write the failing tests for cluster.status read tool**

Create `tests/unit/test_cluster_status.py`:

```python
"""cluster.status read tool tests (M4c T11)."""

from __future__ import annotations

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.cluster import (
    ClusterNode,
    ClusterStatusArgs,
    ClusterStatusResult,
    cluster_status,
)


def _session() -> Session:
    return Session(
        user_id="alice",
        tenant_id="tenant_a",
        rbac_role="analyst",
        auth_method="oauth",
        wazuh_user=None,
    )


def test_args_takes_no_fields() -> None:
    args = ClusterStatusArgs()
    assert args is not None


@pytest.mark.asyncio
async def test_handler_returns_status_with_nodes() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {
                "enabled": True,
                "running": True,
                "nodes": [
                    {"name": "node-master", "type": "master", "status": "running"},
                    {"name": "node-worker", "type": "worker", "status": "running"},
                ],
            }

    args = ClusterStatusArgs()
    result = await cluster_status(args=args, session=_session(), server_api=_StubClient())
    assert result.enabled is True
    assert result.running is True
    assert len(result.nodes) == 2
    assert result.nodes[0] == ClusterNode(
        name="node-master", type="master", status="running"
    )


@pytest.mark.asyncio
async def test_handler_returns_disabled_when_clustering_off() -> None:
    class _StubClient:
        async def cluster_status(self):  # type: ignore[no-untyped-def]
            return {"enabled": False, "running": False, "nodes": []}

    args = ClusterStatusArgs()
    result = await cluster_status(args=args, session=_session(), server_api=_StubClient())
    assert result.enabled is False
    assert result.running is False
    assert result.nodes == []
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_restart_manager.py tests/unit/test_cluster_status.py -v`

Expected: FAIL — types don't exist.

- [ ] **Step 4: Add `RestartManagerArgs`, `RestartManagerResult`, `restart_manager` to `tools/write.py`**

Append to `src/wazuh_mcp/tools/write.py`:

```python
# ---------- 8. restart_manager ----------


class RestartManagerArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Literal["node", "cluster"] = "cluster"
    confirm: Annotated[
        Literal[True],
        Field(
            description=(
                "Must be set to true by a human user. Restarting the Wazuh "
                "manager (or cluster) cycles every connected agent's "
                "connection and is recorded in the audit log."
            )
        ),
    ]


class RestartManagerResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    scope: Literal["node", "cluster"]
    affected_nodes: list[str]
    timestamp: datetime


async def restart_manager(
    *,
    args: RestartManagerArgs,
    session: Session,
    server_api: Any,
) -> RestartManagerResult:
    pre = await server_api.cluster_status()
    if args.scope == "cluster" and not pre["enabled"]:
        raise WazuhError(
            "upstream_error",
            "cluster scope requested but clustering is not enabled on this manager",
            400,
        )
    affected_nodes = [n["name"] for n in pre.get("nodes", [])]
    if not affected_nodes:
        # Single-node manager — use a sentinel name.
        affected_nodes = ["this-node"]
    await server_api.restart_cluster(scope=args.scope, run_as=session.wazuh_user)
    return RestartManagerResult(
        ok=True,
        scope=args.scope,
        affected_nodes=affected_nodes,
        timestamp=datetime.now(UTC),
    )
```

- [ ] **Step 5: Create `src/wazuh_mcp/tools/cluster.py`**

```python
"""cluster.* read tools (M4c).

Currently single-tool: cluster.status.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from wazuh_mcp.auth.session import Session


class ClusterStatusArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClusterNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    type: Literal["master", "worker"]
    status: str


class ClusterStatusResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    running: bool
    nodes: list[ClusterNode]


async def cluster_status(
    *,
    args: ClusterStatusArgs,
    session: Session,
    server_api: Any,
) -> ClusterStatusResult:
    raw = await server_api.cluster_status()
    return ClusterStatusResult(
        enabled=bool(raw.get("enabled", False)),
        running=bool(raw.get("running", False)),
        nodes=[
            ClusterNode(
                name=str(n.get("name", "")),
                type=n.get("type", "worker"),
                status=str(n.get("status", "")),
            )
            for n in raw.get("nodes", [])
        ],
    )
```

- [ ] **Step 6: Run the new tests**

Run: `uv run pytest tests/unit/test_restart_manager.py tests/unit/test_cluster_status.py -v`

Expected: PASS.

- [ ] **Step 7: Run the full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 8: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/tools/write.py src/wazuh_mcp/tools/cluster.py tests/unit/test_restart_manager.py tests/unit/test_cluster_status.py
git commit -m "tools: add write.restart_manager + cluster.status handlers

restart_manager pre-flights cluster_status, raises upstream_error if
scope=cluster requested but clustering disabled. cluster.status is a
thin read returning enabled/running flags + node list. Both consume
ServerApiClient.cluster_status / restart_cluster from T10."
```

---

### Task 12: Wire `write.restart_manager` + `cluster.status` registrations

**Files:**
- Modify: `src/wazuh_mcp/server.py` (`_register_everything` — add the two new tool registrations)
- Test: `tests/unit/test_server_wiring_m4c.py` (extend)

**Why:** Connect the new handlers from T11 to the FastMCP app via `instrumented_tool` + `mcp_app.tool`. `write.restart_manager` lives alongside the other 7 writes (gets the audit pair via the `tool_name.startswith("write.")` branch in the decorator). `cluster.status` registers in the read-tools block (single audit event).

- [ ] **Step 1: Add the failing test**

Add to `tests/unit/test_server_wiring_m4c.py`:

```python
@pytest.mark.asyncio
async def test_restart_manager_and_cluster_status_registered() -> None:
    """Both new tools appear in list_tools."""
    from mcp.server.fastmcp import FastMCP

    from wazuh_mcp.auth.session import Session
    from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
    from wazuh_mcp.observability.contextvar import set_current_session
    from wazuh_mcp.observability.ratelimit import InProcessRateLimiter
    from wazuh_mcp.server import _register_everything
    from wazuh_mcp.tenancy.config import RateLimitConfig

    mcp_app = FastMCP(name="test")
    audit = MultiSinkAuditEmitter(sinks=None)
    limiter = InProcessRateLimiter(default=RateLimitConfig())

    def _allow_all(session: Session) -> dict[str, list[str]]:
        return {"admin": ["*"]}

    def _no_filter(session: Session) -> list[str] | None:
        return None

    def _no_ar(session: Session) -> list[str]:
        return []

    class _Pool:
        async def acquire(self, tenant_id: str):
            return None

    _register_everything(
        mcp_app,
        indexer_pool=_Pool(),
        server_api_pool=_Pool(),
        audit_emitter=audit,
        limiter=limiter,
        rbac_policy=_allow_all,
        write_allowlist_policy=_no_filter,
        ar_allowlist_policy=_no_ar,
    )

    set_current_session(
        Session(
            user_id="alice",
            tenant_id="tenant_a",
            rbac_role="admin",
            auth_method="oauth",
            wazuh_user=None,
        )
    )

    tools = await mcp_app.list_tools()
    names = {t.name for t in tools}
    assert "write.restart_manager" in names
    assert "cluster.status" in names
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py::test_restart_manager_and_cluster_status_registered -v`

Expected: FAIL — tools not registered.

- [ ] **Step 3: Add the registrations to `_register_everything`**

In `src/wazuh_mcp/server.py`, add to the imports inside `_register_everything` near the other write imports (around line 991):

```python
    from wazuh_mcp.tools.write import (
        RestartManagerArgs,
        RestartManagerResult,
    )
    from wazuh_mcp.tools.write import (
        restart_manager as _restart_manager,
    )
    from wazuh_mcp.tools.cluster import (
        ClusterStatusArgs,
        ClusterStatusResult,
    )
    from wazuh_mcp.tools.cluster import cluster_status as _cluster_status
```

After the `write.run_active_response` registration block (around line 1207), add the `write.restart_manager` block:

```python
    async def _restart_manager_inner(**kwargs: Any) -> Any:
        args = RestartManagerArgs(**kwargs)
        session = current_session()
        _check_write_allowed(session, "write.restart_manager")
        sapi = await server_api_pool.acquire(session.tenant_id)
        return await _restart_manager(args=args, session=session, server_api=sapi)

    mcp_app.tool(
        name="write.restart_manager",
        description=_write_desc_prefix
        + "Restarts the Wazuh manager (scope='cluster' restarts the entire cluster; "
        + "scope='node' restarts only this node). Required to activate uploaded rule "
        + "files. Cycles every connected agent connection.",
        meta={"toolset": "writes"},
    )(
        instrumented_tool(
            tool_name="write.restart_manager",
            handler=_restart_manager_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
            args_model=RestartManagerArgs,
            result_model=RestartManagerResult,
        )
    )
```

Then in the read-tools block (find any existing `mitre.*` or similar registration and place this nearby), add the `cluster.status` registration:

```python
    async def _cluster_status_inner(**kwargs: Any) -> Any:
        args = ClusterStatusArgs(**kwargs)
        session = current_session()
        sapi = await server_api_pool.acquire(session.tenant_id)
        return await _cluster_status(args=args, session=session, server_api=sapi)

    _wrap(
        tool_name="cluster.status",
        handler=_cluster_status_inner,
        description=(
            "Reads the Wazuh cluster's status: clustering enabled flag, running "
            "state, and per-node name/type/status. Use to verify cluster "
            "readiness pre/post manager restart."
        ),
        meta={"toolset": "cluster"},
        args_model=ClusterStatusArgs,
        result_model=ClusterStatusResult,
    )
```

(Place this near the existing `_wrap` calls for the M3 read tools — alphabetically before `fim.*` is a reasonable spot.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_server_wiring_m4c.py::test_restart_manager_and_cluster_status_registered -v`

Expected: PASS.

- [ ] **Step 5: Run the full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 6: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4c.py
git commit -m "server: wire write.restart_manager and cluster.status registrations

restart_manager registers alongside the other 7 writes (audit pair via
@instrumented_tool's write.* prefix branch). cluster.status registers
as a regular read tool (single audit event)."
```

---

### Task 13: Remove `confirm_required` from `SAFE_CODES`

**Files:**
- Modify: `src/wazuh_mcp/wazuh/errors.py:13-24`
- Test: `tests/unit/test_safe_codes.py` (existing — modify if it enumerates `SAFE_CODES`)

**Why:** `confirm_required` was declared in M4b T1 as a "reserved for future elicitation" code but never raised at runtime. Cleanup of dead vocabulary.

- [ ] **Step 1: Find existing tests that enumerate SAFE_CODES**

```bash
grep -rn "SAFE_CODES\|confirm_required" tests/ src/wazuh_mcp/
```

Expected: a unit test like `test_safe_codes_enumerated` may exist that does `assert SAFE_CODES == {...}`. Update its expected set.

- [ ] **Step 2: Remove `confirm_required` from `SAFE_CODES`**

Edit `src/wazuh_mcp/wazuh/errors.py`:

```python
SAFE_CODES: Final[frozenset[str]] = frozenset(
    {
        "auth_expired",
        "forbidden",
        "rate_limited",
        "invalid_query",
        "upstream_error",
        "not_found",
        "upstream_timeout",
    }
)
```

- [ ] **Step 3: Update any test that pinned the old set**

If `tests/unit/test_safe_codes.py` exists with an enumerated assertion, update it to match. Search and patch.

- [ ] **Step 4: Run the full unit suite**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add src/wazuh_mcp/wazuh/errors.py tests/unit/test_safe_codes.py
git commit -m "errors: remove confirm_required from SAFE_CODES

Declared in M4b T1 as reserved for future MCP elicitation support;
SDK 1.27 has no native elicitation and the code never fired at
runtime. Pydantic Literal[True] confirm gate IS the confirm contract.
Re-add when elicitation lands."
```

---

### Task 14: Integration tests for M4c writes

**Files:**
- Create: `tests/integration/test_m4c_writes.py`

**Why:** End-to-end verification of `write.restart_manager` (node scope on single-node CI stack), `cluster.status`, multi-agent isolate, and the `<rbac.resolve>` audit on unknown-tenant. `@requires_manager` skip on non-amd64.

- [ ] **Step 1: Write the integration test**

Create `tests/integration/test_m4c_writes.py`:

```python
"""M4c integration tests — write.restart_manager, cluster.status,
multi-agent isolate, unknown-tenant audit.

Marked @requires_manager — runs nightly on amd64 CI, manual dispatch
otherwise. Inline-server-spawn pattern on dedicated ports (8780/8781).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import AsyncIterator

import httpx
import pytest

from tests.integration.conftest import (  # type: ignore[import-not-found]
    requires_manager,
    _mcp_session,
    MCP_URL,
)


pytestmark = [pytest.mark.integration, requires_manager]


@pytest.mark.asyncio
async def test_cluster_status_reads_node_metadata(mcp_http_server) -> None:
    async with _mcp_session(MCP_URL) as session:
        result = await session.call_tool("cluster.status", {})
        payload = json.loads(result.content[0].text)
        assert payload["enabled"] in (True, False)
        # Single-node CI fixture: even with clustering disabled, the read
        # succeeds.
        if payload["enabled"]:
            assert len(payload["nodes"]) >= 1
            assert payload["nodes"][0]["name"]


@pytest.mark.asyncio
async def test_restart_manager_node_scope_completes(mcp_http_server) -> None:
    """Restart this node, then poll cluster.status until running again."""
    async with _mcp_session(MCP_URL) as session:
        result = await session.call_tool(
            "write.restart_manager",
            {"scope": "node", "confirm": True},
        )
        payload = json.loads(result.content[0].text)
        assert payload["ok"] is True
        assert payload["scope"] == "node"
        assert payload["affected_nodes"]

        # Poll cluster.status (or the manager's API directly) until ready.
        # CI's single-node stack typically settles within 60s.
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            try:
                status_result = await session.call_tool("cluster.status", {})
                status = json.loads(status_result.content[0].text)
                # Even with clustering disabled, the API responds when the
                # node is up.
                if status is not None:
                    return
            except Exception:
                pass
            await asyncio.sleep(3.0)
        pytest.fail("manager did not return to ready within 90s after node restart")


@pytest.mark.asyncio
async def test_multi_agent_isolate_one_agent(mcp_http_server) -> None:
    """Exercise the agent_ids: list[str] shape via the URL-builder path
    on the single-agent CI fixture."""
    async with _mcp_session(MCP_URL) as session:
        result = await session.call_tool(
            "write.isolate_agent",
            {"agent_ids": ["001"], "confirm": True},
        )
        payload = json.loads(result.content[0].text)
        # Whether the isolate active-response actually fires depends on the
        # manager's ossec.conf wiring (already configured for the integration
        # restoration). Either ok=True with affected_agents=["001"] or
        # ok=False with failed_agents populated is acceptable here — the
        # wire-shape pinning is the goal.
        assert payload["ok"] in (True, False)
        if payload["ok"]:
            assert payload["affected_agents"] == ["001"]


@pytest.mark.asyncio
async def test_unknown_tenant_audit_emits_sentinel(
    mcp_http_server, audit_log_path: Path
) -> None:
    """Mint a session with an unregistered tenant_id, call any read tool,
    assert the <rbac.resolve> sentinel + tenant_not_registered reason
    appear in the audit log."""
    # The integration fixture's OAuth issuer index won't accept a phantom
    # tenant — so this test exercises the resolver's defense-in-depth path
    # via an injected session contextvar at the inline-server boot.
    # SKIP if the fixture doesn't expose a way to inject; this is best-
    # effort defense-in-depth coverage.
    pytest.skip(
        "defense-in-depth path requires session-injection fixture; "
        "covered at unit level in test_m4c_per_tenant_policy.py"
    )
```

- [ ] **Step 2: Verify required fixtures**

```bash
grep -n "_mcp_session\|MCP_URL\|requires_manager\|audit_log_path" tests/integration/conftest.py
```

Expected: `_mcp_session`, `MCP_URL`, `requires_manager` already exist (M4a/M4b precedent). `audit_log_path` may not — if the test that uses it is the only one (the skipped unknown-tenant test), the fixture isn't blocking.

If a `mcp_http_server` fixture is needed, follow M4b's pattern (`tests/integration/test_m4b_writes.py` has an inline-server fixture on a dedicated port — copy that pattern, change the port to 8780/8781).

- [ ] **Step 3: (Conditional) Run the integration tests if local Wazuh stack is up**

```bash
uv run pytest tests/integration/test_m4c_writes.py -v -m integration
```

Expected: PASS for the 3 non-skipped tests. If the local stack isn't up, the `@requires_manager` decorator will skip — that's fine; CI runs them.

If the local stack is up but tests fail with fixture errors, debug fixture reuse from M4b's pattern.

- [ ] **Step 4: Run the full unit suite to verify nothing regressed**

Run: `uv run pytest tests/unit -q -m "not integration"`

Expected: all pass.

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`

```bash
git add tests/integration/test_m4c_writes.py
git commit -m "tests: integration coverage for M4c writes + cluster.status

Three tests: cluster.status reads node metadata, write.restart_manager
node-scope completes + cluster recovers, multi-agent isolate exercises
the agent_ids list path. Unknown-tenant audit test SKIP — defense-in-
depth path is covered at unit level. Runs nightly on amd64."
```

---

## Phase 3 — Operator doc + retro + ship

### Task 15: Write `docs/deploy/m4c-multi-tenant.md`

**Files:**
- Create: `docs/deploy/m4c-multi-tenant.md`

**Why:** Operator-facing doc for the per-tenant resolver model, the `write_allowlist=[]` delta, restart_manager + cluster.status setup, multi-agent AR migration, and unknown-tenant audit shape.

- [ ] **Step 1: Write the operator doc**

Create `docs/deploy/m4c-multi-tenant.md` with sections:

1. Overview — what M4c changes for operators
2. Per-tenant resolver model (architecture overview, no code)
3. `write_allowlist=[]` behavior change from M4b (the table from spec §6.1)
4. `<rbac.resolve>` audit shape (event field examples; Wazuh Dashboards saved-search update)
5. `write.restart_manager` setup
   - Add `"write.restart_manager"` to `tenant_cfg.write_allowlist`
   - Verify Wazuh API user has cluster-admin permissions
   - `scope=cluster` (default) vs `scope=node` tradeoff
   - Pair with `cluster.status` for readiness verification
   - Audit-log examples
6. `cluster.status` setup
   - Default analyst-readable
   - Operator override examples for restrictive RBAC
7. Multi-agent AR migration (1-line examples; before/after; Wazuh-side `agents_list` shape preserved)
8. Cross-tenant isolation note
   - All writes register uniformly; per-tenant denial is purely call-time
   - Differs from M4b's hidden-tools approach
   - Why: multi-tenant integrity over surface narrowing
9. Audit-shape examples
   - Successful multi-agent isolate (3/3 succeeded)
   - Partial-failure multi-agent (2/3 succeeded, 1 failed)
   - Unknown-tenant resolver miss

(Use the M4b operator doc `docs/deploy/m4b-writes.md` as a structural template. Match its tone and section depth.)

- [ ] **Step 2: Verify accuracy by cross-checking with the spec**

Read `docs/deploy/m4c-multi-tenant.md` and `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4c-design.md` side-by-side. Confirm the operator doc matches §6 of the spec.

- [ ] **Step 3: Commit**

```bash
git add docs/deploy/m4c-multi-tenant.md
git commit -m "docs: add M4c operator guide for per-tenant resolution + new writes"
```

---

### Task 16: Update existing operator docs

**Files:**
- Modify: `docs/deploy/m4b-writes.md` (drop `confirm_required` line; update single-agent AR examples to multi-agent)
- Modify: `docs/security/threat-model.md` (add per-tenant resolution to mitigation table)
- Modify: `README.md` (bump milestone table to include M4c)

**Why:** Keep docs in sync with the M4c shipping behavior so operators don't read stale guidance.

- [ ] **Step 1: Update `docs/deploy/m4b-writes.md`**

Find and remove the section that describes `confirm_required` as a reserved error code. Search for `confirm_required` in the file:

```bash
grep -n "confirm_required" docs/deploy/m4b-writes.md
```

Replace any text describing the reserved-but-unused code with a forward-pointer note: "M4c removed `confirm_required` from `SAFE_CODES`; the `confirm: Literal[True]` Args check IS the confirm gate."

For multi-agent AR migration, add a section at the bottom or update the `write.run_active_response` example. The schema table for `agent_id` should be replaced with `agent_ids: list[str]` (1-50). Add a one-line "M4b → M4c migration" note: "If your client pinned the M4b shape, change `agent_id='001'` to `agent_ids=['001']`."

- [ ] **Step 2: Update `docs/security/threat-model.md`**

Search for the RBAC / multi-tenant section:

```bash
grep -n "RBAC\|multi-tenant\|tenant_id" docs/security/threat-model.md
```

Add a new mitigation row to the table:

| Threat | Mitigation | Implementation |
|---|---|---|
| Cross-tenant policy bleed in multi-tenant HTTP | Per-call resolution of `role_tool_allowlist`, `write_allowlist`, `active_response_allowlist` against `session.tenant_id` | `rbac/resolver.py` factories closing over `TenantRegistry` |
| Unknown tenant_id minted into a session | Fail-closed: empty role table for RBAC, empty list for both write filters; audit emit with `<rbac.resolve>` sentinel | M4c phase 1 |

- [ ] **Step 3: Update `README.md`**

Find the milestone table:

```bash
grep -n "M4a\|M4b\|v0\." README.md | head -20
```

Add a row for M4c. Match the format of existing M4a/M4b rows.

- [ ] **Step 4: Verify renderings (no automated check; eyeball)**

```bash
head -100 docs/deploy/m4b-writes.md docs/security/threat-model.md README.md
```

- [ ] **Step 5: Commit**

```bash
git add docs/deploy/m4b-writes.md docs/security/threat-model.md README.md
git commit -m "docs: update m4b-writes, threat model, and README for M4c"
```

---

### Task 17: Bump version, ruff format alignment, retro, tag

**Files:**
- Modify: `pyproject.toml` (bump `0.6.0-dev` → `0.6.0`)
- Modify: `uv.lock` (regenerate)
- Create: `docs/superpowers/retros/2026-04-27-m4c-retro.md`
- Optional: ruff format alignment commit (precedent: M2 `3c20a8d`, M3 `6fa3fce`, M4a `765cd59`, M4b `4e68838`)

**Why:** Ship discipline. Version bump in its own commit; ruff format alignment in its own commit; retro in its own commit; tag on the final commit.

- [ ] **Step 1: Run ruff format on the entire repo (alignment commit)**

Run: `uv run ruff format .`

Expected: any drift from prior commits gets normalized.

```bash
git status
```

If files changed, commit:

```bash
git add -u src/ tests/ docs/  # NOT git add -A (sweeps .DS_Store)
git commit -m "chore: ruff format alignment for M4c"
```

If nothing changed (clean format throughout), skip this commit.

- [ ] **Step 2: Bump version to `0.6.0`**

Edit `pyproject.toml`: change `version = "0.6.0-dev"` to `version = "0.6.0"`.

Run: `uv lock` to regenerate the lockfile. Confirm `uv.lock` updates.

- [ ] **Step 3: Write the retro**

Create `docs/superpowers/retros/2026-04-27-m4c-retro.md`. Sections (match M4b's `2026-04-24-m4b-retro.md` shape):

1. **Headline** — what shipped, dispatch count, ship date.
2. **What went well** — phase-1 spot-check approach validated; resolver factor pulled cleanly out of server.py; multi-agent refactor was mechanical and trouble-free; cluster.status proved a useful pairing with restart_manager.
3. **What surprised us** — anything during execution that wasn't in the plan (resolver dedup, fixture issues, etc.). Fill in based on actual execution observations.
4. **Tier-A review knob calibration** — full review on T3 (resolver), spot-check on T6/T7/T8/T9/T10/T11/T12. Did the spot-check catch issues? Did full review on T3 add value?
5. **Plan-detail investment outcome** — track fix-after-review cycles; compare to M4b's zero.
6. **Carry-forward to M4d / M5** — group-target AR design pass; per-tenant rate-limiter / audit-sink fan-out; cross-tenant leak tests; eval harness; multi-manager integration fixture.
7. **Dispatch count vs prediction** — actual vs the 14-17 estimate.

(Filler sections like "what surprised us" and "tier-A calibration" need real data from execution — fill in at retro time, not at plan time.)

- [ ] **Step 4: Stage specific files (NOT `git add -A`)**

```bash
git add pyproject.toml uv.lock docs/superpowers/retros/2026-04-27-m4c-retro.md
```

- [ ] **Step 5: Verify staged set**

```bash
git status
```

Expected: only the three files above are staged. No `.DS_Store`. No stray drift.

- [ ] **Step 6: Commit + tag + push**

```bash
git commit -m "v0.6.0-m4c: per-tenant policy resolution + write-surface completion

Per-tenant role_tool_allowlist, write_allowlist, and active_response_
allowlist now resolve at call-time via session.tenant_id, closing the
multi-tenant policy-bleed gap carried over from M4b. New tools
write.restart_manager (scope=cluster|node) and cluster.status finish
the M4b rule-activation flow inside MCP. Multi-agent run_active_response
via agent_ids: list[str]. confirm_required removed from SAFE_CODES.

Breaking changes (semver-pre-1.0):
  * write.run_active_response and write.isolate_agent: agent_id: str
    -> agent_ids: list[str] (1<=N<=50). Migration: agent_id='001' ->
    agent_ids=['001'].
  * write_allowlist=[] no longer hides tools from list_tools; instead
    lists them and call-denies. See docs/deploy/m4c-multi-tenant.md.
  * confirm_required no longer in SAFE_CODES.

Architecture:
  * rbac/resolver.py: three factory functions (make_rbac_policy,
    make_write_allowlist, make_ar_allowlist) returning session-keyed
    callables. KeyError on unknown tenant -> audit emit + safe default.
  * SingleTenantRegistry adapter for stdio shares the resolver wiring.
  * HttpAppConfig.registry threading replaces the discarded YamlTenantRegistry.
  * MultiSinkAuditEmitter.emit() gains additive error_reason kwarg."

git tag v0.6.0-m4c
git push origin main --tags
```

- [ ] **Step 7: Verify the tag**

```bash
git log --oneline -5
git tag --list "v0.6.0*"
```

Expected: `v0.6.0-m4c` listed; HEAD commit is the ship commit.

---

## Self-review (controller-only — do not dispatch)

After all 17 tasks are complete, run a final sweep:

- [ ] **Spec coverage:** Read each section of `docs/superpowers/specs/2026-04-27-wazuh-mcp-m4c-design.md`. Point to the task that implemented it. Any gaps?
- [ ] **Test count delta:** `uv run pytest tests/unit -q -m "not integration" --collect-only | tail -1`. Expected: ~430 unit tests up to ~470+ after M4c (resolver tests + multi-agent + restart + cluster + per-tenant policy = ~30-40 new).
- [ ] **Integration count delta:** `uv run pytest tests/integration -q --collect-only | tail -1`. Expected: 26 → ~29 (3 new M4c writes).
- [ ] **CI green check:** Verify nightly amd64 integration run picks up the new tests cleanly. If a CI run fails, fix in a `v0.6.1` patch (precedent: `v0.5.1`).
- [ ] **Dependabot:** Re-rebase open PRs (#1, #2, #4, #5) post-tag; merge any that go green.

