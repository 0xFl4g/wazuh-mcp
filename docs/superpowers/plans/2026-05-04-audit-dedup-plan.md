# wazuh-mcp v1.2 — Audit-emitter Dedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the second half of the v1.0 HA caveat. Every audit event gets a per-emit UUID `event_id` (used as the OpenSearch `_id` for retry idempotency) plus a queryable `request_id` field for cross-replica query-time correlation.

**Architecture:** Five phases. T-A ships a tiny `audit_context.py` module that exposes a `get_request_id()` helper, falling through to MCP SDK's existing `mcp.server.lowlevel.server.request_ctx` contextvar — which means **no transport-layer hook is needed**. T-B updates `MultiSinkAuditEmitter.emit()` to populate the two new fields. T-C updates the Wazuh-indexer sink to set `_id` from `event_id` and add the keyword mappings to its index template. T-D adds real-Wazuh integration coverage. T-E ships docs + release notes + version bump + tag. T-A → T-B → T-C is sequential (each layer consumes the previous). T-D ⊥ T-E after T-C.

**Tech Stack:** Python 3.12 + uv + Pydantic v2 + pytest + pytest-asyncio + MCP SDK (`mcp.server.lowlevel`) + FastMCP (`mcp.server.fastmcp`) + OpenSearch / Wazuh-indexer + Docker Compose.

**Predecessor:** v1.1.0 at `c15cb5c` + spec `ea405c1` (`docs/superpowers/specs/2026-05-04-audit-dedup-design.md`).

**Successor:** v1.3+ open backlog — stdio `request_id` plumbing if demand surfaces, promote `request_id` into `_id` derivation if cross-replica overlap is observed in production.

**Total scope:** 7 task groups across 5 phases. ~6 dispatches expected (T-A1+T-A2 batched; T-E batches docs).

**Methodology in force** (from `feedback_methodology.md` + `feedback_subagent_patterns.md`):

- **No AI attribution in commits.** Never `Co-Authored-By: Claude` or "Generated with Claude" footer.
- **Tier-A spot-check** for all tasks. No novel primitives in this milestone — every change is composition over existing patterns. The "novel" piece (request_id fall-through to MCP's contextvar) is small enough to spot-check.
- **Plan-time signature greps** mandatory for tasks touching `audit.py:emit()` (verify all call sites still match the kwarg-only signature) and `wazuh_indexer.py:_build_bulk_body()` / `_ensure_template()`.
- **Cross-subsystem invariant grep:** at T-B plan-time, grep all callers of `audit_emitter.emit(...)` to confirm the existing kwargs are unchanged. The two new fields are populated *inside* `emit()`, not passed as kwargs by callers; the call-site signature stays stable.
- **Ruff selects:** E/F/I/UP/B/SIM/RUF/N/ASYNC. Line-length 100. Use `# ty: ignore` (NOT `# type: ignore`).

---

## File Structure (all phases)

### New files

```
src/wazuh_mcp/observability/
  audit_context.py                               # T-A1 (new — contextvar + helpers)

tests/unit/
  test_audit_context.py                          # T-A1 (new — contextvar tests)
  test_audit_dedup.py                            # T-B1 (new — emit() + indexer tests)

tests/integration/
  test_audit_dedup_real.py                       # T-D1 (new — real Wazuh container)
```

### Modified files

```
src/wazuh_mcp/observability/audit.py             # T-B1 (emit() populates event_id + request_id)
src/wazuh_mcp/observability/sinks/wazuh_indexer.py # T-C1 (bulk body sets _id; template adds mappings)

docs/deploy/helm.md                              # T-E1 (HA caveat collapses)
docs/deploy/observability.md                     # T-E1 (new section: dedup behavior)
README.md                                        # T-E1 (features matrix update)
pyproject.toml                                   # T-F1 (1.1.0 -> 1.2.0)
uv.lock                                          # T-F1 (regenerate)
```

---

## Phase 1: T-A — `audit_context` module

**Goal:** A 30-line module with `set_request_id()`, `reset_request_id()`, `get_request_id()`. The getter prefers a manually-set value (test fixtures, future stdio plumbing) and falls through to MCP SDK's existing `request_ctx` contextvar otherwise. No production code calls `set_request_id()` in v1.2 — it's there for tests and future use.

### Task T-A1: Implement `audit_context.py` + unit tests

**Files:**
- Create: `src/wazuh_mcp/observability/audit_context.py`
- Create: `tests/unit/test_audit_context.py`

- [ ] **Step 1: Verify MCP SDK exposes `request_ctx` at the expected path**

```bash
uv run python -c "from mcp.server.lowlevel.server import request_ctx; print(type(request_ctx).__name__, request_ctx.name)"
```

Expected output: `ContextVar request_ctx`. If this fails, the MCP SDK version may have moved the symbol; check `mcp.server.lowlevel` for the renamed export and adjust step 3's import.

- [ ] **Step 2: Verify `request_ctx.get(None)` returns `None` outside a request**

```bash
uv run python -c "from mcp.server.lowlevel.server import request_ctx; print(request_ctx.get(None))"
```

Expected: `None`. Confirms the contextvar is unset outside an active MCP request.

- [ ] **Step 3: Write `audit_context.py`**

Create `src/wazuh_mcp/observability/audit_context.py` with this exact content:

```python
"""Request-scoped audit correlation context.

Exposes a single ``ContextVar[str | None]`` plus helpers for setting,
resetting, and reading the current audit ``request_id``. The getter
falls through to MCP SDK's own ``request_ctx`` when our local contextvar
is unset — which is the common case in production, since no production
code calls ``set_request_id()``. Test fixtures and any future stdio
plumbing path can call ``set_request_id()`` to override.
"""

from __future__ import annotations

import contextvars

_audit_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "audit_request_id", default=None
)


def set_request_id(request_id: str | None) -> contextvars.Token[str | None]:
    """Set the audit request_id for the current context.

    Returns a token that callers MUST pass to ``reset_request_id`` on
    request exit. The standard pattern is::

        token = set_request_id(rid)
        try:
            ...
        finally:
            reset_request_id(token)
    """
    return _audit_request_id.set(request_id)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    """Reset the audit request_id contextvar using the token from ``set_request_id``."""
    _audit_request_id.reset(token)


def get_request_id() -> str | None:
    """Return the current audit request_id.

    Resolution order:
    1. The locally-set value (via ``set_request_id``), if any.
    2. The MCP SDK's ``request_ctx.get().request_id`` if a request is active.
    3. ``None`` (no request scope, no override).
    """
    rid = _audit_request_id.get()
    if rid is not None:
        return rid
    try:
        # Lazy import: keeps the module importable in environments that
        # don't have the MCP SDK installed (unlikely for this repo, but
        # defensive). LookupError is raised by ContextVar.get() with no
        # default; guard for both ImportError and LookupError.
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:
        return None
    ctx = request_ctx.get(None)
    if ctx is None:
        return None
    return str(ctx.request_id)
```

- [ ] **Step 4: Write the failing test scaffold**

Create `tests/unit/test_audit_context.py` with this exact content:

```python
"""audit_context.set/reset/get_request_id contextvar tests."""

from __future__ import annotations

import asyncio

import pytest

from wazuh_mcp.observability.audit_context import (
    get_request_id,
    reset_request_id,
    set_request_id,
)


def test_default_is_none() -> None:
    """No active request, no override → None."""
    assert get_request_id() is None


def test_set_then_get_returns_value() -> None:
    token = set_request_id("abc-123")
    try:
        assert get_request_id() == "abc-123"
    finally:
        reset_request_id(token)


def test_reset_returns_to_default() -> None:
    token = set_request_id("abc-123")
    reset_request_id(token)
    assert get_request_id() is None


def test_set_none_explicit() -> None:
    """Setting None explicitly is allowed and returns None."""
    token = set_request_id(None)
    try:
        assert get_request_id() is None
    finally:
        reset_request_id(token)


@pytest.mark.asyncio
async def test_concurrent_tasks_dont_leak_context() -> None:
    """Two concurrent tasks each set their own request_id; neither sees the other's."""
    seen: dict[str, str | None] = {}

    async def task(name: str, rid: str) -> None:
        token = set_request_id(rid)
        try:
            await asyncio.sleep(0)  # yield
            seen[name] = get_request_id()
        finally:
            reset_request_id(token)

    await asyncio.gather(
        task("a", "rid-A"),
        task("b", "rid-B"),
    )
    assert seen == {"a": "rid-A", "b": "rid-B"}


@pytest.mark.asyncio
async def test_create_task_inherits_parent_context() -> None:
    """A child task sees the parent's request_id at spawn time."""
    token = set_request_id("parent-rid")
    try:
        result_box: list[str | None] = []

        async def child() -> None:
            result_box.append(get_request_id())

        await asyncio.create_task(child())
        assert result_box == ["parent-rid"]
    finally:
        reset_request_id(token)


def test_falls_through_to_mcp_request_ctx_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """When local contextvar is unset, get_request_id() reads MCP SDK's request_ctx."""

    class FakeRequestCtx:
        request_id = "mcp-rid-456"

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    # Patch the import path used by audit_context.get_request_id().
    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)
    assert get_request_id() == "mcp-rid-456"


def test_local_override_wins_over_mcp_request_ctx(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit set_request_id wins over MCP's request_ctx."""

    class FakeRequestCtx:
        request_id = "mcp-rid-456"

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)

    token = set_request_id("local-override")
    try:
        assert get_request_id() == "local-override"
    finally:
        reset_request_id(token)


def test_handles_non_string_mcp_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON-RPC id can be int or null; we always return str."""

    class FakeRequestCtx:
        request_id = 42  # int — JSON-RPC permits this

    import contextvars

    fake_var: contextvars.ContextVar[FakeRequestCtx | None] = contextvars.ContextVar(
        "fake_request_ctx", default=None
    )
    fake_var.set(FakeRequestCtx())

    import mcp.server.lowlevel.server as mcp_server_mod

    monkeypatch.setattr(mcp_server_mod, "request_ctx", fake_var)
    assert get_request_id() == "42"
```

- [ ] **Step 5: Run the tests**

```bash
uv run pytest tests/unit/test_audit_context.py -v
```

Expected: **9 PASS**.

If `test_falls_through_to_mcp_request_ctx_when_unset` fails: confirm the monkeypatch target is correct. The `from ... import request_ctx` inside `get_request_id()` reads from `mcp.server.lowlevel.server` at import time — patching `mcp_server_mod.request_ctx` rebinds the module-level name BEFORE the lazy import executes, so the patch is seen.

If `test_concurrent_tasks_dont_leak_context` is slow: that's normal for the first run.

- [ ] **Step 6: Run linters**

```bash
uv run ruff check src/wazuh_mcp/observability/audit_context.py tests/unit/test_audit_context.py
uv run ruff format --check src/wazuh_mcp/observability/audit_context.py tests/unit/test_audit_context.py
uv run ty check src/wazuh_mcp/observability/audit_context.py
```

Expected: clean. If `ruff format --check` flags formatting, run `uv run ruff format <file>` and re-check.

- [ ] **Step 7: Run the full unit suite to confirm no regression**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -5
```

Expected: **600 PASS** (591 baseline + 9 new), 4 SKIPPED.

- [ ] **Step 8: Commit**

```bash
git add src/wazuh_mcp/observability/audit_context.py tests/unit/test_audit_context.py
git commit -m "feat(observability): audit_context module — request_id contextvar (v1.2 T-A1)

A 30-line module exposing set/reset/get_request_id helpers backed by a
ContextVar[str | None]. The getter resolves in this order:

  1. Locally-set value (via set_request_id) — for test fixtures and any
     future stdio plumbing path.
  2. MCP SDK's request_ctx.get().request_id if an MCP request is active.
  3. None.

This eliminates the v1.2 spec's transport-layer hook concern: MCP's
own SDK already populates request_ctx at the request lifecycle, so we
just READ it instead of plumbing a new hook through SessionMiddleware
or the @instrumented_tool decorator.

9 unit tests cover: default-None, set/reset round-trip, explicit-None
set, concurrent-task isolation, create_task context inheritance, MCP
request_ctx fall-through, local-override precedence, and non-string
JSON-RPC id coercion to str."
```

---

## Phase 2: T-B — `audit.py` `emit()` updates

**Goal:** `MultiSinkAuditEmitter.emit()` now populates `event_id` (per-emit UUIDv4) and `request_id` (from `audit_context.get_request_id()`) on every event. No call-site signature changes; the new fields are populated inside the method.

### Task T-B1: Update `emit()` + add unit tests

**Files:**
- Modify: `src/wazuh_mcp/observability/audit.py`
- Create: `tests/unit/test_audit_dedup.py`

- [ ] **Step 1: Plan-time grep — confirm `emit()` call-site signature stays stable**

```bash
grep -rn "audit_emitter\.emit\|audit\.emit(" src/wazuh_mcp/ --include="*.py" | head -15
```

Expected: ~10 sites, all calling `emit(session=..., tool=..., args=..., outcome=..., result_count=..., duration_ms=..., error_code=..., error_reason=...)`. No site passes `event_id` or `request_id` — those will be populated inside `emit()` and need no caller changes.

- [ ] **Step 2: Read the current `emit()` body for context**

```bash
sed -n '123,154p' src/wazuh_mcp/observability/audit.py
```

Expected: matches the existing event dict construction. The two new lines insert AFTER the existing dict-build, BEFORE the sink-fanout loop.

- [ ] **Step 3: Update `emit()`**

Edit `src/wazuh_mcp/observability/audit.py`. Add the import at the top of the file (after the existing `from wazuh_mcp.observability.sinks.stream import StderrSink` line):

```python
import uuid

from wazuh_mcp.observability.audit_context import get_request_id
```

Then in `emit()`, after the `event["duration_ms"] = duration_ms` assignment and before the `if error_code is not None` block, INSERT these two lines:

```python
        event["event_id"] = str(uuid.uuid4())
        event["request_id"] = get_request_id()
```

The exact diff context: locate the existing block:

```python
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
```

Change to:

```python
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
        event["event_id"] = str(uuid.uuid4())
        event["request_id"] = get_request_id()
        if error_code is not None:
            event["error_code"] = error_code
        if error_reason is not None:
            event["error_reason"] = error_reason
        for sink in self.global_sinks:
            sink.submit(event)
```

- [ ] **Step 4: Write `tests/unit/test_audit_dedup.py`**

Create with this exact content:

```python
"""MultiSinkAuditEmitter dedup-field population tests."""

from __future__ import annotations

import re

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.audit_context import reset_request_id, set_request_id


class _CapturingSink:
    """Minimal AuditSink-like double that captures every submitted event."""

    name = "capturing"

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def submit(self, event: dict[str, object]) -> None:
        self.events.append(event)


def _session(tenant: str = "default", user: str = "alice") -> Session:
    return Session(
        user_id=user,
        tenant_id=tenant,
        rbac_role="analyst",
        auth_method="config",
    )


_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _emit_one(emitter: MultiSinkAuditEmitter, *, tool: str = "alerts.search_alerts") -> None:
    emitter.emit(
        session=_session(),
        tool=tool,
        args={"q": "x"},
        outcome="ok",
        result_count=1,
        duration_ms=10,
    )


def test_emit_sets_event_id_uuid4() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    _emit_one(emitter)
    ev = sink.events[0]
    assert "event_id" in ev
    assert _UUID4_RE.match(ev["event_id"])  # ty: ignore


def test_emit_event_id_unique_per_call() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    for _ in range(1000):
        _emit_one(emitter)
    ids = {e["event_id"] for e in sink.events}
    assert len(ids) == 1000


def test_emit_request_id_none_outside_request_scope() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    _emit_one(emitter)
    assert sink.events[0]["request_id"] is None


def test_emit_request_id_populated_from_context() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    token = set_request_id("rpc-77")
    try:
        _emit_one(emitter)
    finally:
        reset_request_id(token)
    assert sink.events[0]["request_id"] == "rpc-77"


def test_emit_request_id_resets_after_scope_exits() -> None:
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    token = set_request_id("rpc-77")
    _emit_one(emitter)  # in scope
    reset_request_id(token)
    _emit_one(emitter)  # out of scope
    assert sink.events[0]["request_id"] == "rpc-77"
    assert sink.events[1]["request_id"] is None


def test_existing_fields_unchanged() -> None:
    """Regression: the v1.0 event shape (timestamp, tool, user, tenant, rbac_role,
    arg_hash, outcome, result_count, duration_ms) is preserved alongside the new
    fields."""
    sink = _CapturingSink()
    emitter = MultiSinkAuditEmitter(global_sinks=[sink])  # ty: ignore
    _emit_one(emitter, tool="cluster.status")
    ev = sink.events[0]
    for k in ("timestamp", "tool", "user", "tenant", "rbac_role", "arg_hash",
              "outcome", "result_count", "duration_ms"):
        assert k in ev, f"missing {k}"
    assert ev["tool"] == "cluster.status"
    assert ev["user"] == "alice"
    assert ev["tenant"] == "default"
```

- [ ] **Step 5: Run the new tests**

```bash
uv run pytest tests/unit/test_audit_dedup.py -v
```

Expected: **6 PASS**.

If `test_emit_event_id_uuid4` fails because the regex doesn't match: confirm `str(uuid.uuid4())` is the source. The UUID4 regex requires version-4 (`4` in position 13) and variant-`8`/`9`/`a`/`b` (in position 17) — Python's stdlib `uuid.uuid4()` always produces these, so a failure means we're emitting something other than a UUID4.

- [ ] **Step 6: Run linters**

```bash
uv run ruff check src/wazuh_mcp/observability/audit.py tests/unit/test_audit_dedup.py
uv run ruff format --check src/wazuh_mcp/observability/audit.py tests/unit/test_audit_dedup.py
uv run ty check src/wazuh_mcp/observability/audit.py
```

Expected: clean. The two `# ty: ignore` markers in the test (on the `_CapturingSink` instantiation) silence ty's complaint that the duck-typed sink doesn't implement the `AuditSink` Protocol — confirmed acceptable since the test exercises the duck-type contract. The `_UUID4_RE.match(...)` ty-ignore is for `re.match` returning `Match[str] | None` which mypy/ty narrows differently than pytest expects.

If ruff format flags differences, run `uv run ruff format <files>`.

- [ ] **Step 7: Full unit suite check**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -5
```

Expected: **606 PASS** (600 + 6 new), 4 SKIPPED. The existing audit-related tests (`test_audit.py`, `test_per_tenant_audit_routing.py`, etc.) keep passing — the two new fields are additive and don't break any contract.

- [ ] **Step 8: Commit**

```bash
git add src/wazuh_mcp/observability/audit.py tests/unit/test_audit_dedup.py
git commit -m "feat(observability): emit() populates event_id + request_id (v1.2 T-B1)

MultiSinkAuditEmitter.emit() now generates a per-call UUIDv4 as
event_id and reads request_id from audit_context (which falls through
to MCP SDK's request_ctx). Two new fields are populated inside emit();
caller signatures are unchanged.

event_id is the per-emit idempotency key — preserved across QueuedSink
retries since the event dict is queued whole. T-C1 wires it into the
OpenSearch _id on the bulk-index line, so retries upsert the same doc
instead of inserting a duplicate.

request_id is queryable correlation. v1.2 ships with operators
expected to query-dedup by it if cross-replica overlap materializes.

6 unit tests: event_id is UUID4, unique per call, request_id None
outside scope, populated from contextvar in scope, resets cleanly,
existing fields unchanged."
```

---

## Phase 3: T-C — Wazuh-indexer sink

**Goal:** The bulk-index action carries `_id: <event_id>`, and the index template's mapping declares `event_id` and `request_id` as `keyword`.

### Task T-C1: Update `wazuh_indexer.py` + tests

**Files:**
- Modify: `src/wazuh_mcp/observability/sinks/wazuh_indexer.py`
- Modify: `tests/unit/test_audit_dedup.py` (append more cases)

- [ ] **Step 1: Plan-time grep — confirm template name + bulk-body call site**

```bash
grep -n "_build_bulk_body\|_ensure_template\|put_index_template\|index_patterns" src/wazuh_mcp/observability/sinks/wazuh_indexer.py
```

Expected: `_build_bulk_body` is the only producer of bulk action lines; `_ensure_template` is the only template installer; template name is `f"{self._prefix}-template"`. No other code paths construct `{"index": {...}}` action lines.

- [ ] **Step 2: Update `_build_bulk_body()` to set `_id` from `event_id`**

Edit `src/wazuh_mcp/observability/sinks/wazuh_indexer.py`. Replace the existing `_build_bulk_body` body:

```python
    def _build_bulk_body(self, events: list[dict[str, Any]]) -> str:
        index = self._today_index()
        lines: list[str] = []
        for ev in events:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(ev))
        return "\n".join(lines) + "\n"
```

with:

```python
    def _build_bulk_body(self, events: list[dict[str, Any]]) -> str:
        index = self._today_index()
        lines: list[str] = []
        for ev in events:
            action: dict[str, Any] = {"index": {"_index": index}}
            event_id = ev.get("event_id")
            if event_id is not None:
                action["index"]["_id"] = event_id
            lines.append(json.dumps(action))
            lines.append(json.dumps(ev))
        return "\n".join(lines) + "\n"
```

The `if event_id is not None` guard preserves backwards compatibility: events emitted by code paths that bypass `MultiSinkAuditEmitter.emit()` (test fixtures injecting raw dicts, downstream consumers) fall back to the v1.1 auto-UUID behavior.

- [ ] **Step 3: Update `_ensure_template()` mappings to declare new fields**

In the same file, locate the `mappings.properties` dict inside `_ensure_template`:

```python
                "mappings": {
                    "dynamic": False,
                    "properties": {
                        "timestamp": {"type": "date"},
                        "tool": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "tenant": {"type": "keyword"},
                        "rbac_role": {"type": "keyword"},
                        "arg_hash": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "result_count": {"type": "long"},
                        "duration_ms": {"type": "long"},
                        "error_code": {"type": "keyword"},
                    },
                },
```

Change to:

```python
                "mappings": {
                    "dynamic": False,
                    "properties": {
                        "timestamp": {"type": "date"},
                        "tool": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "tenant": {"type": "keyword"},
                        "rbac_role": {"type": "keyword"},
                        "arg_hash": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "result_count": {"type": "long"},
                        "duration_ms": {"type": "long"},
                        "error_code": {"type": "keyword"},
                        "event_id": {"type": "keyword"},
                        "request_id": {"type": "keyword"},
                    },
                },
```

- [ ] **Step 4: Append unit tests to `test_audit_dedup.py`**

Append (do NOT replace existing content) at the end of `tests/unit/test_audit_dedup.py`:

```python


# ---------------------------------------------------------------------------
# WazuhIndexerSink — bulk body + template tests
# ---------------------------------------------------------------------------


class _FakeIndexerClient:
    """Captures put_index_template / bulk calls without going to the wire."""

    def __init__(self) -> None:
        self.template_body: dict[str, object] | None = None
        self.bulk_body: str | None = None

    async def put_index_template(self, *, name: str, body: dict[str, object]) -> None:
        self.template_body = body

    async def bulk(self, *, body: str) -> dict[str, object]:
        self.bulk_body = body
        return {"errors": False, "items": []}


class _FakePool:
    def __init__(self, client: _FakeIndexerClient) -> None:
        self._client = client

    async def acquire(self, tenant_id: str) -> _FakeIndexerClient:
        return self._client


@pytest.mark.asyncio
async def test_bulk_body_sets_id_from_event_id() -> None:
    from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink

    client = _FakeIndexerClient()
    sink = WazuhIndexerSink(pool=_FakePool(client), tenant_id="t1")
    events = [
        {"event_id": "id-A", "tool": "x", "user": "u", "tenant": "t1",
         "rbac_role": "analyst", "arg_hash": "h", "outcome": "ok",
         "result_count": 0, "duration_ms": 1, "timestamp": "2026-05-04T00:00:00+00:00",
         "request_id": "rpc-1"},
        {"event_id": "id-B", "tool": "y", "user": "u", "tenant": "t1",
         "rbac_role": "analyst", "arg_hash": "h", "outcome": "ok",
         "result_count": 0, "duration_ms": 1, "timestamp": "2026-05-04T00:00:00+00:00",
         "request_id": "rpc-2"},
    ]
    body = sink._build_bulk_body(events)  # noqa: SLF001 — deliberate test access
    # Two action lines, two doc lines, plus trailing newline.
    lines = body.rstrip("\n").split("\n")
    assert len(lines) == 4
    assert '"_id": "id-A"' in lines[0]
    assert '"_id": "id-B"' in lines[2]


@pytest.mark.asyncio
async def test_bulk_body_omits_id_when_event_id_missing() -> None:
    """Defensive: events injected without event_id (legacy / hand-crafted) fall back to auto-UUID."""
    from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink

    client = _FakeIndexerClient()
    sink = WazuhIndexerSink(pool=_FakePool(client), tenant_id="t1")
    events = [
        {"tool": "x", "user": "u", "tenant": "t1", "rbac_role": "analyst",
         "arg_hash": "h", "outcome": "ok", "result_count": 0,
         "duration_ms": 1, "timestamp": "2026-05-04T00:00:00+00:00"},
    ]
    body = sink._build_bulk_body(events)  # noqa: SLF001
    lines = body.rstrip("\n").split("\n")
    assert '"_id"' not in lines[0]


@pytest.mark.asyncio
async def test_template_declares_new_field_mappings() -> None:
    """The index template install carries event_id + request_id as keyword."""
    from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink

    client = _FakeIndexerClient()
    sink = WazuhIndexerSink(pool=_FakePool(client), tenant_id="t1")
    await sink._ensure_template()  # noqa: SLF001
    assert client.template_body is not None
    props = client.template_body["template"]["mappings"]["properties"]
    assert props["event_id"] == {"type": "keyword"}
    assert props["request_id"] == {"type": "keyword"}
```

- [ ] **Step 5: Run the new tests**

```bash
uv run pytest tests/unit/test_audit_dedup.py -v
```

Expected: **9 PASS** (6 from T-B1 + 3 new).

If the noqa SLF001 markers fire RUF100 (unused-noqa): drop them and replace with a plain `# deliberate test access` comment. Same caveat as the v1.1 milestone — `SLF001` is not in the project's ruff selects.

- [ ] **Step 6: Run linters**

```bash
uv run ruff check src/wazuh_mcp/observability/sinks/wazuh_indexer.py tests/unit/test_audit_dedup.py
uv run ruff format --check src/wazuh_mcp/observability/sinks/wazuh_indexer.py tests/unit/test_audit_dedup.py
uv run ty check src/wazuh_mcp/observability/sinks/wazuh_indexer.py
```

Expected: clean. If ruff RUF100 fires on the SLF001 noqa markers, run the auto-fix:

```bash
uv run ruff check --fix tests/unit/test_audit_dedup.py
```

- [ ] **Step 7: Full unit suite check**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -5
```

Expected: **609 PASS** (606 + 3 new), 4 SKIPPED.

- [ ] **Step 8: Commit**

```bash
git add src/wazuh_mcp/observability/sinks/wazuh_indexer.py tests/unit/test_audit_dedup.py
git commit -m "feat(observability): wazuh_indexer sink _id from event_id + template mapping (v1.2 T-C1)

WazuhIndexerSink._build_bulk_body() now extracts event['event_id'] and
sets it as the OpenSearch _id on the bulk-index action line. Retries
of the same event (preserved through the QueuedSink) hit OpenSearch
with the same _id and silently overwrite (op_type=index default).

The index template declares event_id and request_id as 'keyword' so
operators can query/aggregate by either. dynamic=False is preserved;
the mapping is now explicit for the new fields.

Defensive: bulk_body still works for events missing event_id (legacy
fixture injection / downstream consumers). Falls back to v1.1 auto-UUID.

3 new unit tests cover the _id extraction, the missing-event_id fall-
back, and the template body's new mappings."
```

---

## Phase 4: T-D — Real-Wazuh integration test

**Goal:** Prove dedup works end-to-end against a real Wazuh-indexer container. Multi-replica scenario simulated by emitting the same `event_id` twice from the same client.

### Task T-D1: Real-Wazuh integration coverage

**Files:**
- Create: `tests/integration/test_audit_dedup_real.py`

- [ ] **Step 1: Read the existing integration audit test for the conftest fixture pattern**

```bash
grep -n "mcp_http_server\|indexer_pool\|wazuh_indexer\|@pytest.fixture" tests/integration/test_m4a_audit_indexer_sink.py | head -10
sed -n '1,40p' tests/integration/test_m4a_audit_indexer_sink.py
```

Expected: the file imports `from tests.integration._helpers import ...` for the indexer-pool fixture. Use the same fixtures here.

- [ ] **Step 2: Write the integration test**

Create `tests/integration/test_audit_dedup_real.py`:

```python
"""Real-Wazuh integration test for v1.2 audit dedup.

Marked @pytest.mark.integration. Spun up via docker/bootstrap.sh which
starts wazuh-indexer; this test does not need the manager or keycloak.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator

import pytest

from wazuh_mcp.observability.sinks.wazuh_indexer import WazuhIndexerSink

pytestmark = pytest.mark.integration


@pytest.fixture
async def indexer_sink(indexer_pool) -> AsyncIterator[WazuhIndexerSink]:
    """Build a WazuhIndexerSink against the real wazuh-indexer fixture.

    Uses a unique index_prefix per test run so cross-test isolation is
    automatic. The fixture's indexer_pool is provided by the integration
    conftest.
    """
    prefix = f"wazuh-mcp-audit-dedup-{os.getpid()}"
    sink = WazuhIndexerSink(
        pool=indexer_pool,
        tenant_id="default",
        index_prefix=prefix,
        batch=10,
        flush_ms=200,
        max_attempts=2,
    )
    await sink.start()
    try:
        yield sink
    finally:
        await sink.stop()
        # Best-effort cleanup of created indices.
        client = await indexer_pool.acquire("default")
        try:
            await client.delete_index(f"{prefix}-*")
        except Exception:
            pass


def _event(event_id: str, *, tool: str = "alerts.search_alerts",
           request_id: str | None = None) -> dict[str, object]:
    return {
        "timestamp": "2026-05-04T12:00:00+00:00",
        "tool": tool,
        "user": "alice",
        "tenant": "default",
        "rbac_role": "analyst",
        "arg_hash": "h" * 64,
        "outcome": "ok",
        "result_count": 1,
        "duration_ms": 10,
        "event_id": event_id,
        "request_id": request_id,
    }


async def _refresh_and_count(indexer_pool, prefix: str) -> int:
    client = await indexer_pool.acquire("default")
    await client.refresh_index(f"{prefix}-*")
    resp = await client.count(index=f"{prefix}-*")
    return int(resp.get("count", 0))


@pytest.mark.asyncio
async def test_same_event_id_dedupes_to_one_doc(indexer_sink: WazuhIndexerSink, indexer_pool) -> None:
    """50 emits with the same event_id → exactly 1 document in the index."""
    for _ in range(50):
        indexer_sink.submit(_event("forced-id-A"))
    # Drain the queue.
    await asyncio.sleep(0.5)
    count = await _refresh_and_count(indexer_pool, indexer_sink._prefix)  # noqa: SLF001
    assert count == 1


@pytest.mark.asyncio
async def test_distinct_event_ids_produce_distinct_docs(indexer_sink: WazuhIndexerSink, indexer_pool) -> None:
    """50 emits with distinct event_ids → 50 docs."""
    import uuid

    for _ in range(50):
        indexer_sink.submit(_event(str(uuid.uuid4())))
    await asyncio.sleep(0.5)
    count = await _refresh_and_count(indexer_pool, indexer_sink._prefix)  # noqa: SLF001
    assert count == 50


@pytest.mark.asyncio
async def test_request_id_is_queryable(indexer_sink: WazuhIndexerSink, indexer_pool) -> None:
    """Events tagged with request_id can be retrieved via term query on that field."""
    import uuid

    indexer_sink.submit(_event(str(uuid.uuid4()), request_id="rpc-find-me"))
    indexer_sink.submit(_event(str(uuid.uuid4()), request_id="rpc-other"))
    await asyncio.sleep(0.5)

    client = await indexer_pool.acquire("default")
    await client.refresh_index(f"{indexer_sink._prefix}-*")  # noqa: SLF001
    resp = await client.search(
        index=f"{indexer_sink._prefix}-*",  # noqa: SLF001
        body={"query": {"term": {"request_id": "rpc-find-me"}}},
    )
    hits = resp.get("hits", {}).get("hits", [])
    assert len(hits) == 1
    assert hits[0]["_source"]["request_id"] == "rpc-find-me"


@pytest.mark.asyncio
async def test_dedup_survives_simulated_retry(indexer_sink: WazuhIndexerSink, indexer_pool) -> None:
    """Submitting the same event multiple times (sim retry) yields exactly 1 doc.

    Note: this is the same scenario as test_same_event_id_dedupes_to_one_doc,
    but framed as a retry rather than a duplicate emit. Kept as a separate
    test for readability and to document the retry-idempotency contract.
    """
    eid = "retry-target"
    for _ in range(5):
        indexer_sink.submit(_event(eid))
    await asyncio.sleep(0.5)
    count = await _refresh_and_count(indexer_pool, indexer_sink._prefix)  # noqa: SLF001
    assert count == 1
```

- [ ] **Step 3: Confirm pytest collects the new tests without execution**

```bash
uv run pytest tests/integration/test_audit_dedup_real.py --collect-only -q 2>&1 | tail -8
```

Expected: 4 tests listed. If a fixture (`indexer_pool`) isn't defined in `tests/integration/conftest.py`, the collection still succeeds (pytest only resolves fixtures at run time), but the tests would fail at runtime. Verify the fixture is defined:

```bash
grep -n "def indexer_pool\|@pytest.fixture" tests/integration/conftest.py | head -5
```

If `indexer_pool` is not a top-level fixture, look at how `test_m4a_audit_indexer_sink.py` resolves it and replicate the same setup (likely via the `mcp_http_server` fixture which exposes `indexer_pool`).

- [ ] **Step 4: Run linters**

```bash
uv run ruff check tests/integration/test_audit_dedup_real.py
uv run ruff format --check tests/integration/test_audit_dedup_real.py
uv run ty check tests/integration/test_audit_dedup_real.py
```

Expected: clean. If RUF100 fires on `# noqa: SLF001`, swap to plain comments.

- [ ] **Step 5: Run the integration suite (requires docker stack with wazuh-indexer up)**

```bash
docker compose -f docker/integration-compose.yml up -d wazuh-indexer
WAZUH_VERSION=4.9.0 \
COMPOSE_PROJECT_NAME=test \
uv run pytest tests/integration/test_audit_dedup_real.py -v -m integration
```

Expected: **4 PASS**. If the indexer fixture errors with "client not connected", the bootstrap script may need to run first:

```bash
COMPOSE_PROJECT_NAME=test WAZUH_VERSION=4.9.0 bash docker/bootstrap.sh
```

If `_refresh_and_count` returns 0 unexpectedly: the index name may differ from the per-test prefix. Add `print(client.cat_indices(...))` to debug (or use `gh run view --log` if running in CI).

- [ ] **Step 6: Confirm no unit-test regression**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -3
```

Expected: 609 PASS, 4 SKIPPED.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/test_audit_dedup_real.py
git commit -m "test(integration): real-Wazuh audit dedup coverage (v1.2 T-D1)

4 integration tests against a real wazuh-indexer:

- 50 emits with the same event_id -> 1 document (dedup confirmed
  end-to-end at the bulk-index layer)
- 50 emits with distinct event_ids -> 50 documents (no false dedup)
- request_id is queryable via term query
- 5 simulated retries with same event_id -> 1 document (retry
  idempotency contract documented as a separate test)

Tests use a unique index_prefix per pid so cross-test isolation is
automatic. Indices are best-effort cleaned up via teardown."
```

---

## Phase 5: T-E — Documentation

**Goal:** Update operator-facing docs to reflect that the v1.0 audit-dedup blocker is closed and document the manual `_rollover` step for operators who want today's index to reflect the new mapping immediately.

### Task T-E1: Docs + release notes

**Files:**
- Modify: `docs/deploy/helm.md` (collapse HA caveat)
- Modify: `docs/deploy/observability.md` (new dedup section)
- Modify: `README.md` (features matrix update)

- [ ] **Step 1: Update `docs/deploy/helm.md` HA caveat**

Read the current HA caveat section:

```bash
sed -n '125,160p' docs/deploy/helm.md
```

Replace the existing HA-caveat block (the section starting `## HA caveat` through the end of that section) with:

```markdown
## HA caveat

**v1.2 closes the last v1.0 HA blocker.** Multi-replica deployments are now fully supported when both `redis.enabled=true` AND `replicaCount: 2+` are set. The audit emitter's cross-replica deduplication is solved at the OpenSearch index layer: every event carries a per-emit `event_id` (used as the `_id`) so retries from any replica's `QueuedSink` upsert idempotently. A queryable `request_id` field exposes the originating JSON-RPC request id for cross-replica query-time correlation when needed.

The chart's default `replicaCount: 1` and `redis.enabled: false` reflect the conservative single-replica posture for operators who don't need HA. Bumping the default to multi-replica was rejected because it would force every existing operator to either provide a Redis Secret they may not have or explicitly pin `replicaCount: 1`. Operators who want HA opt in explicitly:

1. Stand up Redis (managed: ElastiCache, Memorystore, etc.; or self-hosted).
2. `kubectl create secret generic my-redis-creds --from-literal=redis-url=...`
3. Set `redis.enabled=true`, `redis.existingSecret=my-redis-creds`, AND `replicaCount: 2+` in Helm values.
4. Add a `rate_limiter:` block to your `.Values.server.yaml`. See [`docs/deploy/redis.md`](redis.md).

Operators upgrading from v1.1 to v1.2 see no behavior change unless they explicitly bump `replicaCount`. Existing daily audit indices accept the new event fields on writes but won't field-index them until rollover; see [`docs/deploy/observability.md`](observability.md) for the manual `_rollover` step if you want immediate field-indexed visibility on the current day.
```

- [ ] **Step 2: Read `docs/deploy/observability.md` to find the right insertion point**

```bash
grep -n "^## " docs/deploy/observability.md | head -10
```

Find a section like `## Audit emitter` or similar. Insert the new section AFTER the existing audit-emitter section (or at the end if there isn't one):

```markdown
## Audit dedup (v1.2+)

Every audit event carries two dedup-related fields:

| Field | Type | Purpose |
|---|---|---|
| `event_id` | UUIDv4 string | Per-emit idempotency key. Set as the OpenSearch `_id` on the bulk-index action. Retries from `QueuedSink` reuse the same `event_id`, so OpenSearch upserts the document instead of inserting a duplicate. |
| `request_id` | string \| null | The originating JSON-RPC request id (from MCP SDK's `request_ctx`). Null for stdio transport (until plumbed) and for any emit outside an active MCP request scope. |

### Querying by request_id

Useful when investigating a specific call across replicas:

```bash
curl -sku admin:admin "https://wazuh-indexer:9200/local-audit-*/_search" -H 'Content-Type: application/json' -d '{
  "query": { "term": { "request_id": "rpc-77" } }
}'
```

### Index template & manual rollover

The Wazuh-indexer sink installs an index template declaring `event_id` and `request_id` as `keyword`. The template applies to **future** daily indices automatically. Existing indices written under v1.1 (which had `dynamic: false` and the older mapping) accept the new fields on writes but **won't field-index them until they roll**.

If you want the current day's index to reflect the new mapping immediately:

```bash
curl -sku admin:admin -X POST "https://wazuh-indexer:9200/local-audit-*/_rollover" \
  -H 'Content-Type: application/json' -d '{}'
```

This is **not required for correctness** — every operator query that *doesn't* use `event_id` or `request_id` as a filter keeps working without rollover. Skipping the rollover means new fields aren't queryable on the current day's docs but are queryable from tomorrow onward.

### OpenSearch dedup semantics

`op_type=index` (the default) performs an upsert on `_id` collision. For our use case the second write has identical content (the QueuedSink retry posts the same `event` dict on every attempt), so upsert is safe. If you want strict reject-on-collision behavior for debugging dedup events, you can flip to `op_type=create` in a future release.
```

- [ ] **Step 3: Update `README.md` features matrix**

```bash
grep -n "Multi-replica HA" README.md
```

Find the existing v1.1 row that says "Multi-replica HA (Redis-backed rate limiter) | v1.1". Replace it with:

```markdown
| Multi-replica HA (Redis rate limiter + audit dedup) | v1.1+v1.2 | opt-in via `redis.enabled=true` + `replicaCount: 2+` |
```

Also find the "v1.1" milestone bullet (per-milestone list earlier in README) and add a v1.2 bullet right after it:

```markdown
- **v1.2** — multi-replica HA completion: audit-emitter cross-replica dedup via per-emit `event_id` (used as OpenSearch `_id`) + queryable `request_id` correlation. Closes the second half of the v1.0 HA caveat. See [`docs/deploy/observability.md`](docs/deploy/observability.md).
```

- [ ] **Step 4: Verify no remaining "deferred to v1.2" language anywhere in tracked docs**

```bash
grep -rn "deferred to v1.2\|v1.2 closes\|audit-dedup blocker\|audit dedup blocker" docs/ README.md 2>&1 | grep -v "docs/superpowers/"
```

Expected: matches inside `docs/deploy/helm.md` HA caveat (which now says "v1.2 closes" — that's fine), but NO remaining "deferred to v1.2" or "audit-dedup blocker remains" anywhere. The `docs/superpowers/` plans/specs are excluded — those are historical artifacts.

If you find a stale reference, edit it to reflect the closed state.

- [ ] **Step 5: Run linters on the touched files**

```bash
uv run ruff check . 2>&1 | tail -3
uv run ruff format --check . 2>&1 | tail -3
```

Expected: clean. Doc-only changes shouldn't affect Python lint.

- [ ] **Step 6: Commit**

```bash
git add docs/deploy/helm.md docs/deploy/observability.md README.md
git commit -m "docs(v1.2): audit dedup operator guide + HA caveat collapse (v1.2 T-E1)

- docs/deploy/helm.md: HA caveat collapses to 'v1.2 closes the last
  v1.0 HA blocker'. Documents the explicit two-flag opt-in
  (redis.enabled + replicaCount > 1) instead of bumping the default
  replicaCount.
- docs/deploy/observability.md: new 'Audit dedup' section describes
  event_id (OpenSearch primary key), request_id (correlation field),
  example query, manual _rollover step, op_type semantics.
- README.md: features matrix multi-replica HA row updated to credit
  v1.1+v1.2; new v1.2 milestone bullet added."
```

---

## Phase 6: T-F — Final verification + ship

**Goal:** Bump version 1.1.0 → 1.2.0, tag v1.2.0, push, verify GHCR release.

### Task T-F1: Version bump + tag + push

**Files:**
- Modify: `pyproject.toml` (version)
- Modify: `uv.lock` (regenerate)

- [ ] **Step 1: Run the full unit suite one last time**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -5
```

Expected: 609 PASS, 4 SKIPPED.

- [ ] **Step 2: Run full lint**

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests
```

Expected: all clean.

- [ ] **Step 3: Verify v1.1 backwards-compat**

```bash
uv run python -c "
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.observability.audit_context import get_request_id
from wazuh_mcp.auth.session import Session

# Capture an event without a request scope.
events = []
class S:
    name = 'test'
    async def start(self): pass
    async def stop(self): pass
    def submit(self, e): events.append(e)

emitter = MultiSinkAuditEmitter(global_sinks=[S()])
emitter.emit(
    session=Session(user_id='u', tenant_id='t', rbac_role='r', auth_method='config'),
    tool='x', args={}, outcome='ok', result_count=0, duration_ms=1
)

ev = events[0]
assert 'event_id' in ev and 'request_id' in ev
assert ev['request_id'] is None
print('v1.2 emit shape verified:', sorted(ev.keys()))
"
```

Expected: prints the field list including `event_id`, `request_id`.

- [ ] **Step 4: Bump version**

Edit `pyproject.toml`. Change `version = "1.1.0"` to `version = "1.2.0"`.

```bash
uv lock 2>&1 | tail -3
```

Expected: `Updated wazuh-mcp v1.1.0 -> v1.2.0`.

- [ ] **Step 5: Commit version bump**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: bump version 1.1.0 -> 1.2.0 for v1.2 ship"
```

- [ ] **Step 6: Tag v1.2.0**

```bash
git tag -a v1.2.0 -m "v1.2.0 — Audit-emitter cross-replica dedup

Closes the second half of the v1.0 HA caveat. Every audit event now
carries a per-emit UUID 'event_id' set as the OpenSearch _id, so
QueuedSink retries are idempotent (OpenSearch upserts on _id collision
instead of inserting duplicate docs). Every event also carries a
queryable 'request_id' field populated from MCP SDK's request_ctx;
operators query-dedup by request_id if cross-replica observation
overlap ever materializes.

Multi-replica HA is now fully supported with both redis.enabled=true
and replicaCount: 2+ set. The chart's defaults remain conservative
(replicaCount: 1, redis.enabled: false) — multi-replica is opt-in
because redis.enabled requires an operator-provided Secret that can't
be defaulted.

Backwards-compatible: v1.1 deployments upgrading to v1.2 see no
behavior change unless they explicitly bump replicaCount. Existing
audit consumers parsing local-audit-* keep working — event_id and
request_id are additive."
```

- [ ] **Step 7: Push main + tag**

```bash
git push origin main
git push origin v1.2.0
```

The release workflow at `.github/workflows/release.yml` builds + publishes the v1.2.0 GHCR image automatically.

- [ ] **Step 8: Watch the release workflow**

```bash
gh run list --workflow=release.yml --limit 1
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId') --exit-status
```

Expected: `release` workflow completes successfully (multi-arch GHCR image published as `ghcr.io/0xfl4g/wazuh-mcp:1.2.0` and `:latest`).

- [ ] **Step 9: Create GitHub Release page**

```bash
gh release create v1.2.0 \
  --title "v1.2.0 — Audit-emitter cross-replica dedup" \
  --notes "$(cat <<'EOF'
Closes the second half of the v1.0 HA caveat. Multi-replica deployments are now fully supported with both \`redis.enabled=true\` and \`replicaCount: 2+\` set.

## Highlights

- **Per-emit \`event_id\`** (UUIDv4) populated by \`MultiSinkAuditEmitter.emit()\` and used as the OpenSearch \`_id\` on the bulk-index action. \`QueuedSink\` retries reuse the same \`event_id\` → OpenSearch upserts on \`_id\` collision → no duplicate documents.
- **Queryable \`request_id\` field** populated from MCP SDK's \`request_ctx\` (no transport-layer plumbing required — the SDK already exposes the JSON-RPC id at the request lifecycle). Null for stdio transport (until plumbed) and for any emit outside an active MCP request scope.
- **Index template update** declares \`event_id\` and \`request_id\` as \`keyword\` for query/aggregation. Re-installed automatically on v1.2 startup; existing daily indices reflect the new mapping after the next rollover. Manual \`_rollover\` documented in [\`docs/deploy/observability.md\`](https://github.com/0xFl4g/wazuh-mcp/blob/v1.2.0/docs/deploy/observability.md) for operators who want immediate field-indexed visibility.

## Backwards compatibility

**Zero behavior change for v1.1 deployments.** No call-site signatures changed; the two new fields are populated inside \`emit()\`. Existing audit consumers parsing \`local-audit-*\` keep working. The \`_id\` semantic shifts from server-generated to client-generated UUIDv4 — same shape, no operator-visible change.

## Multi-replica HA — the full opt-in

After v1.2, both v1.0 HA blockers are closed:

1. ✅ Rate limiter (closed in v1.1 via Redis-backed limiter).
2. ✅ Audit emitter dedup (closed in v1.2 via \`event_id\` / \`request_id\`).

The chart's default \`replicaCount: 1\` and \`redis.enabled: false\` stay. Operators who want HA set both flags explicitly:

\`\`\`yaml
# values.yaml
redis:
  enabled: true
  existingSecret: my-redis-creds
replicaCount: 2
\`\`\`

See [\`docs/deploy/helm.md\`](https://github.com/0xFl4g/wazuh-mcp/blob/v1.2.0/docs/deploy/helm.md) for the full HA setup.

## Container image

\`ghcr.io/0xfl4g/wazuh-mcp:1.2.0\` + \`ghcr.io/0xfl4g/wazuh-mcp:latest\` (multi-arch amd64 + arm64).
EOF
)"
```

Expected: prints the URL of the new release page.

- [ ] **Step 10: Verify the release**

```bash
gh release view v1.2.0 --json name,publishedAt,assets 2>&1 | head -10
```

Expected: shows `v1.2.0` published with the formatted release notes.

---

## Self-review (plan author)

**Spec coverage check:** every spec section traced to a task.

- Goal / non-goals → plan header.
- Decisions 1-3 → T-A1 (UUID + contextvar fall-through), T-B1 (emit population), T-E1 (chart posture in docs).
- Architecture → T-A1, T-B1, T-C1 file structure.
- File layout → File Structure section.
- Component responsibilities → T-A1 (audit_context), T-B1 (audit.py), T-C1 (wazuh_indexer.py).
- Bulk body change → T-C1.
- Index template update → T-C1.
- Contextvars plumbing → T-A1.
- Why contextvars (justification) → plan-text in T-A1 commit message.
- Backwards compatibility → T-B1 self-review checklist + T-F1 step 3 smoke.
- Index template upgrade behavior → T-E1 documentation step.
- Helm chart edits (none) → T-E1 doc-only.
- Documentation → T-E1.
- Migration → T-E1 (release notes step in T-F1 step 9).
- Testing (3 layers) → T-A1 (contextvar tests), T-B1 (emit tests), T-C1 (sink tests), T-D1 (real-Wazuh integration).
- Acceptance criteria → matched against T-D1 + T-F1.
- Risk register → addressed: FastMCP integration risk eliminated by reading MCP request_ctx directly (no hook needed).

**Type-consistency check:** `event_id` and `request_id` field names consistent across audit.py, wazuh_indexer.py, audit_context.py, all tests, all docs. UUIDv4 string shape consistent. `request_id: str | None` consistent.

**Placeholder scan:** no "TBD" / "TODO" / "implement later". The "Open implementation choices (deferred to plan phase)" section in the spec resolved during plan exploration:
- FastMCP integration hook → MCP request_ctx fall-through (no hook needed).
- JSON-RPC id extraction → `str(ctx.request_id)` handles all id types (test in T-A1).
- `op_type=index` vs `op_type=create` → keep `op_type=index` (default) for v1.2.

**Scope check:** single-feature milestone (audit dedup only). Helm chart structural changes explicitly out-of-scope; only doc updates. ~7 task groups across 5 phases — proportionate to v1.1's 15 tasks given the simpler scope.
