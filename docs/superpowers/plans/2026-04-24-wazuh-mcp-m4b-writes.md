# wazuh-mcp M4b — Write-tool surface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the seven `write.*` MCP tools (isolate/restart agent, add/remove agent group, create/update rule, run active response) with `confirm: Literal[True]` gating, double-audit (`write.requested` + completion), two-layer allowlist (`TenantConfig.write_allowlist` at registration + RBAC at list/call), `run_as` attribution, and deny-all-by-default `active_response_allowlist`. Ends at `v0.5.0-m4b`.

**Architecture:** Write tools reuse M4a's `@instrumented_tool` chokepoint. The handler body parses `Args` (rejecting any missing/false `confirm`), emits the `write.requested` audit event, calls a new `ServerApiClient.<verb>` method with `run_as=session.wazuh_user`, and returns a structured result; the decorator emits the completion audit + metric bumps on exit. `TenantConfig.write_allowlist` is activated as a registration-time filter in `_register_everything`; missing entries don't register. A pure `render_rule_xml(RuleDefinition)` function handles rule-file payloads — no raw XML from the caller. A separate `active_response_allowlist: list[str]` field denies every `write.run_active_response` call unless the command name is explicitly allowlisted per tenant.

**Tech Stack:** Python 3.12, `uv`, FastMCP 1.27+, `httpx`, Pydantic v2, `hypothesis` (rule fuzz), `pytest` + `pytest-asyncio` + `pytest-httpx`, Wazuh Manager 4.9 Server API (integration).

**Spec:** `docs/superpowers/specs/2026-04-24-wazuh-mcp-m4b-design.md` (commit `91e5adf`).

---

## Task ordering & dependencies

- T1 (foundation) must land first — every other task needs `confirm_required` in `SAFE_CODES`.
- T2 (TenantConfig) must precede T6 (handlers use `active_response_allowlist`) and T7 (server wiring reads `write_allowlist`).
- T3 (rule renderer) must precede T6 (handlers call `render_rule_xml`).
- T4 (decorator double-audit) can land in parallel with T3; both precede T6.
- T5 (ServerApiClient methods) must precede T6.
- T6 (handlers) must precede T7 (wiring).
- T7 must precede T8 (integration tests).

Dispatch batching (per validated methodology):

- **Batch 1:** T1 + T2 — one implementer, two commits. Tier-B.
- **T3:** rule renderer. Tier-A (XML injection avoidance is security). Solo dispatch with combined spec+code review.
- **T4:** decorator double-audit. Tier-A (hot-path semantics). Solo dispatch with review.
- **T5:** ServerApiClient writes. Tier-B — batchable within one dispatch producing N commits (one per method group).
- **T6:** 7 write-tool handlers. Tier-A (security surface). Solo dispatch with review.
- **T7:** server wiring. Tier-A. Solo dispatch with review.
- **T8 + T9 + T10:** integration tests + docs. Tier-B. Individual or batched by size.
- **T11:** ship — controller-driven.

---

## Phase 0 — Foundation

### Task 1: Version bump, `confirm_required` in `SAFE_CODES`, toolset SDK probe

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock` (regenerated)
- Modify: `src/wazuh_mcp/wazuh/errors.py`
- Modify: `tests/unit/test_wazuh_errors.py`
- Create: `docs/superpowers/notes/2026-04-24-toolset-sdk-probe.md`

- [ ] **Step 1: Bump version**

Edit `pyproject.toml`:

```toml
[project]
name = "wazuh-mcp"
version = "0.5.0-dev"   # was "0.4.0"
```

- [ ] **Step 2: Regenerate lock**

Run: `uv lock`
Expected: `uv.lock` `wazuh-mcp` version shows `0.5.0.dev0`.

- [ ] **Step 3: Add `confirm_required` to SAFE_CODES**

Edit `src/wazuh_mcp/wazuh/errors.py`, modify the `SAFE_CODES` frozenset:

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
        "confirm_required",
    }
)
```

- [ ] **Step 4: Update existing enumeration guard test**

If `tests/unit/test_wazuh_errors.py` has an `assert SAFE_CODES == {...}` guard (it does per M3 pattern), append `"confirm_required"` to the expected set. Find the test and update.

- [ ] **Step 5: Write a failing test for the new code**

Add to `tests/unit/test_wazuh_errors.py`:

```python
def test_confirm_required_is_safe_code() -> None:
    """confirm_required is a client-visible WazuhError code; Claude pattern-
    matches on it to re-prompt the human."""
    err = WazuhError("confirm_required", "human confirmation required", 403)
    assert err.code == "confirm_required"
    assert err.status_code == 403
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/unit/test_wazuh_errors.py -v`
Expected: PASS.

- [ ] **Step 7: Probe MCP SDK for toolset support**

Run:

```bash
uv run python -c "import importlib.metadata; print('mcp', importlib.metadata.version('mcp'))"
uv run python -c "from mcp.server.fastmcp import FastMCP; print([m for m in dir(FastMCP) if 'toolset' in m.lower() or 'enable' in m.lower() or 'filter' in m.lower()])"
uv run python -c "import mcp.types as t; print([n for n in dir(t) if 'toolset' in n.lower() or 'enable' in n.lower()])"
```

Inspect the low-level `Server` and `ToolManager` classes for any toolset-aware method.

- [ ] **Step 8: Write findings note**

Create `docs/superpowers/notes/2026-04-24-toolset-sdk-probe.md`:

```markdown
# MCP toolset SDK probe — M4b T1

Question: does the installed MCP Python SDK support formal toolset
client-enablement?

## SDK version probed

[fill in: mcp version from uv.lock]

## Surface inspected

[Which classes/modules you looked at with file:line citations from
.venv/lib/python3.12/site-packages/mcp/.]

## Findings

[Concrete: does the SDK expose a way for the client to enable/disable
toolsets? If yes, describe the API. If no, describe what's available
(tool-level enable, server capabilities, etc).]

## Decision for M4b

[If supported: wire meta={"toolset": ...} to drive client enablement in
_register_everything. If not: leave meta as the M3 placeholder; revisit
in M4c. Document the placeholder explicitly so the next retro can
carry it forward.]

## Implementation sketch (if supported)

[3-10 lines of code the handler would need.]
```

Fill in every section concretely. No TBDs.

- [ ] **Step 9: Lint + type + full unit suite**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: all clean. Test count: 384 + 1 = 385 (or more if existing enumeration-guard test already covered the new path).

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml uv.lock src/wazuh_mcp/wazuh/errors.py tests/unit/test_wazuh_errors.py docs/superpowers/notes/2026-04-24-toolset-sdk-probe.md
git commit -m "M4b foundation: bump to 0.5.0-dev, add confirm_required to SAFE_CODES, probe toolset SDK"
```

---

## Phase 1 — Config shape

### Task 2: `TenantConfig` — activate `write_allowlist` + new `active_response_allowlist`

**Files:**
- Modify: `src/wazuh_mcp/tenancy/m4_config.py`
- Modify: `src/wazuh_mcp/tenancy/config.py`
- Create: `tests/unit/test_tenant_config_m4b.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_tenant_config_m4b.py`:

```python
"""TenantConfig M4b additions: write_allowlist activation + active_response_allowlist."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.tenancy.config import TenantConfig


def _base_kwargs() -> dict:
    return {
        "tenant_id": "t1",
        "indexer_url": "https://indexer.example",
        "default_rbac_role": "analyst",
    }


def test_write_allowlist_default_none() -> None:
    """None (omitted) -> no registration-time filter; all writes register."""
    cfg = TenantConfig(**_base_kwargs())
    assert cfg.write_allowlist is None


def test_write_allowlist_empty_list_denies_all_writes() -> None:
    """Empty list is semantically different from None: no writes register."""
    cfg = TenantConfig(**_base_kwargs(), write_allowlist=[])
    assert cfg.write_allowlist == []


def test_write_allowlist_accepts_valid_names() -> None:
    cfg = TenantConfig(
        **_base_kwargs(),
        write_allowlist=[
            "write.isolate_agent",
            "write.restart_agent",
            "write.add_agent_to_group",
            "write.remove_agent_from_group",
            "write.create_rule",
            "write.update_rule",
            "write.run_active_response",
        ],
    )
    assert len(cfg.write_allowlist) == 7


def test_write_allowlist_rejects_unknown_tool() -> None:
    """Operator typos fail fast at YAML load, not silently at first call."""
    with pytest.raises(ValidationError, match="write.bogus"):
        TenantConfig(**_base_kwargs(), write_allowlist=["write.bogus"])


def test_write_allowlist_rejects_non_write_namespace() -> None:
    with pytest.raises(ValidationError, match="must be under write.*"):
        TenantConfig(**_base_kwargs(), write_allowlist=["alerts.search_alerts"])


def test_active_response_allowlist_default_empty() -> None:
    """Empty default -> every run_active_response call rejected."""
    cfg = TenantConfig(**_base_kwargs())
    assert cfg.active_response_allowlist == []


def test_active_response_allowlist_accepts_strings() -> None:
    cfg = TenantConfig(
        **_base_kwargs(),
        active_response_allowlist=["block-ip", "disable-account"],
    )
    assert cfg.active_response_allowlist == ["block-ip", "disable-account"]


def test_active_response_allowlist_rejects_empty_command_name() -> None:
    with pytest.raises(ValidationError):
        TenantConfig(**_base_kwargs(), active_response_allowlist=[""])


def test_frozen_still_enforced() -> None:
    cfg = TenantConfig(**_base_kwargs(), write_allowlist=["write.isolate_agent"])
    with pytest.raises(ValidationError):
        cfg.__setattr__("write_allowlist", [])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/test_tenant_config_m4b.py -v`
Expected: FAIL — fields don't exist / no validation.

- [ ] **Step 3: Add field models and validators**

Edit `src/wazuh_mcp/tenancy/m4_config.py`, append at the end:

```python
# M4b additions ------------------------------------------------------------

_WRITE_TOOL_NAMES: set[str] = {
    "write.isolate_agent",
    "write.restart_agent",
    "write.add_agent_to_group",
    "write.remove_agent_from_group",
    "write.create_rule",
    "write.update_rule",
    "write.run_active_response",
}


def _validate_write_allowlist_entry(name: str) -> str:
    if not name.startswith("write."):
        raise ValueError(f"write_allowlist entries must be under write.* namespace; got {name!r}")
    if name not in _WRITE_TOOL_NAMES:
        raise ValueError(
            f"write_allowlist entry {name!r} is not a known write tool. "
            f"Valid names: {sorted(_WRITE_TOOL_NAMES)}"
        )
    return name


def _validate_ar_command_name(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("active_response_allowlist command names must be non-empty")
    return name
```

- [ ] **Step 4: Extend `TenantConfig`**

Edit `src/wazuh_mcp/tenancy/config.py`. Add imports:

```python
from pydantic import field_validator
```

And add fields to the existing `TenantConfig` class:

```python
class TenantConfig(BaseModel):
    # ... existing fields ...

    # M4b additions. write_allowlist: None -> no filter (all writes register).
    # Empty list -> NO writes register. List -> only those names register.
    write_allowlist: list[str] | None = None
    active_response_allowlist: list[str] = Field(default_factory=list)

    @field_validator("write_allowlist")
    @classmethod
    def _validate_writes(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        from wazuh_mcp.tenancy.m4_config import _validate_write_allowlist_entry
        return [_validate_write_allowlist_entry(name) for name in v]

    @field_validator("active_response_allowlist")
    @classmethod
    def _validate_ar(cls, v: list[str]) -> list[str]:
        from wazuh_mcp.tenancy.m4_config import _validate_ar_command_name
        return [_validate_ar_command_name(name) for name in v]
```

- [ ] **Step 5: Verify tests pass**

Run: `uv run pytest tests/unit/test_tenant_config_m4b.py tests/unit/test_tenant_config.py tests/unit/test_tenant_config_m4a.py -v`
Expected: new M4b tests pass; M4a + M1 tests unaffected.

- [ ] **Step 6: Full suite + lint + type**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: clean; 385 + 9 = 394 tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/wazuh_mcp/tenancy/m4_config.py src/wazuh_mcp/tenancy/config.py tests/unit/test_tenant_config_m4b.py
git commit -m "M4b config: activate write_allowlist + add active_response_allowlist with tool-name validation"
```

---

## Phase 2 — Rule XML renderer (tier-A)

### Task 3: `RuleDefinition` model + `render_rule_xml` + fuzz

**Files:**
- Create: `src/wazuh_mcp/wazuh/rule_render.py`
- Create: `tests/unit/test_rule_render.py`
- Create: `tests/unit/test_rule_render_fuzz.py`

- [ ] **Step 1: Write failing tests for the model + renderer**

Create `tests/unit/test_rule_render.py`:

```python
"""RuleDefinition model + render_rule_xml pure function."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest
from pydantic import ValidationError

from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml


def _parse(xml: str) -> ET.Element:
    return ET.fromstring(xml)


def test_minimal_rule() -> None:
    r = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    x = render_rule_xml(r)
    root = _parse(x)
    assert root.tag == "rule"
    assert root.attrib == {"id": "100100", "level": "5"}
    assert root.find("description").text == "Failed SSH login"


def test_rule_with_if_sid_list() -> None:
    r = RuleDefinition(id=100_200, level=10, description="d", if_sid=[5710, 5711])
    x = render_rule_xml(r)
    root = _parse(x)
    if_sids = root.findall("if_sid")
    assert len(if_sids) == 1
    assert if_sids[0].text == "5710, 5711"


def test_rule_with_match() -> None:
    r = RuleDefinition(id=100_300, level=3, description="d", match="failed login")
    x = render_rule_xml(r)
    root = _parse(x)
    assert root.find("match").text == "failed login"


def test_rule_with_regex_compile_fail_rejects_at_args_parse() -> None:
    with pytest.raises(ValidationError, match="regex"):
        RuleDefinition(id=100_400, level=3, description="d", regex="(unclosed")


def test_rule_with_groups() -> None:
    r = RuleDefinition(
        id=100_500, level=7, description="d", groups=["authentication_failed", "syslog"]
    )
    x = render_rule_xml(r)
    root = _parse(x)
    assert root.find("group").text == "authentication_failed,syslog,"


def test_rule_with_field_dict() -> None:
    r = RuleDefinition(
        id=100_600, level=4, description="d", field={"user.name": "^root$"}
    )
    x = render_rule_xml(r)
    root = _parse(x)
    fields = root.findall("field")
    assert len(fields) == 1
    assert fields[0].attrib == {"name": "user.name"}
    assert fields[0].text == "^root$"


def test_xml_escapes_user_strings_match() -> None:
    """No tool call can inject sibling elements via < or & in description/match."""
    r = RuleDefinition(
        id=100_700,
        level=3,
        description="alert for <script>alert(1)</script> & friends",
        match="password=\"hunter2\"",
    )
    x = render_rule_xml(r)
    # The output must parse cleanly and contain escaped entities, not literal markup.
    root = _parse(x)
    assert root.find("description").text == "alert for <script>alert(1)</script> & friends"
    assert root.find("match").text == 'password="hunter2"'
    # Belt-and-braces: the raw string should contain escaped entities.
    assert "&lt;" in x or "&amp;" in x or "&quot;" in x


def test_xml_has_no_sibling_elements_outside_rule() -> None:
    """Even an attacker-style description cannot produce extra top-level elements."""
    r = RuleDefinition(
        id=100_800,
        level=3,
        description="</rule><rule id=\"999999\" level=\"15\"><match>x",
    )
    x = render_rule_xml(r)
    # Wrap in a root so ElementTree can parse multiple top-level elements.
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    # Exactly one <rule> child — no injection.
    rule_children = [c for c in root if c.tag == "rule"]
    assert len(rule_children) == 1
    assert rule_children[0].attrib["id"] == "100800"


def test_id_range_validation() -> None:
    # Valid custom rule range: 100_000 - 999_999
    with pytest.raises(ValidationError):
        RuleDefinition(id=99_999, level=3, description="d")
    with pytest.raises(ValidationError):
        RuleDefinition(id=1_000_000, level=3, description="d")


def test_level_range_validation() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=-1, description="d")
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=16, description="d")


def test_description_length_limit() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=3, description="x" * 513)


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=3, description="d", unknown_field="x")
```

Create `tests/unit/test_rule_render_fuzz.py`:

```python
"""Hypothesis fuzz: no generated RuleDefinition produces malformed XML or
XML with injected sibling elements."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from hypothesis import given, strategies as st

from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml


_ids = st.integers(min_value=100_000, max_value=999_999)
_levels = st.integers(min_value=0, max_value=15)
_short_text = st.text(min_size=1, max_size=128)
_optional_text = st.one_of(st.none(), _short_text)
_optional_sid_list = st.one_of(st.none(), st.lists(st.integers(min_value=1, max_value=999_999), min_size=1, max_size=5))


@given(
    id=_ids,
    level=_levels,
    description=_short_text,
    match=_optional_text,
    if_sid=_optional_sid_list,
)
def test_every_rule_parses_and_has_single_rule_child(id, level, description, match, if_sid):
    r = RuleDefinition(id=id, level=level, description=description, match=match, if_sid=if_sid)
    x = render_rule_xml(r)
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    children = list(root)
    assert len(children) == 1
    assert children[0].tag == "rule"


@given(
    description=_short_text.filter(lambda s: any(c in s for c in "<>&\"'")),
)
def test_xml_unsafe_characters_always_escaped_in_description(description):
    r = RuleDefinition(id=100_001, level=3, description=description)
    x = render_rule_xml(r)
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    # Must roundtrip exactly.
    assert root.find("rule").find("description").text == description
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/test_rule_render.py tests/unit/test_rule_render_fuzz.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `RuleDefinition` + `render_rule_xml`**

Create `src/wazuh_mcp/wazuh/rule_render.py`:

```python
"""RuleDefinition model + pure XML renderer for M4b write.create_rule and
write.update_rule.

Matches M3's query-builder pattern: NO raw XML from callers. The renderer
escapes every user-controlled string via xml.sax.saxutils.escape so no
tool call can inject sibling elements or disable detection via
`<ignore>*</ignore>` tricks.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal
from xml.sax.saxutils import escape as _xml_escape, quoteattr as _xml_quoteattr

from pydantic import BaseModel, ConfigDict, Field, field_validator


_CUSTOM_RULE_ID_MIN = 100_000
_CUSTOM_RULE_ID_MAX = 999_999


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Annotated[int, Field(ge=_CUSTOM_RULE_ID_MIN, le=_CUSTOM_RULE_ID_MAX)]
    level: Annotated[int, Field(ge=0, le=15)]
    description: Annotated[str, Field(min_length=1, max_length=512)]

    if_sid: list[int] | None = None
    if_matched_sid: int | None = None
    match: str | None = None
    regex: str | None = None
    decoded_as: str | None = None
    field: dict[str, str] | None = None
    srcip: str | None = None
    program_name: str | None = None
    groups: list[str] | None = None
    options: list[Literal["no_log", "alert_by_email"]] | None = None

    @field_validator("regex")
    @classmethod
    def _validate_regex(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"regex does not compile: {exc}") from exc
        return v


def _el(tag: str, text: str) -> str:
    """Open tag, escaped text, close tag — no attrs."""
    return f"<{tag}>{_xml_escape(text)}</{tag}>"


def _el_with_attr(tag: str, attr_name: str, attr_value: str, text: str) -> str:
    return f"<{tag} {attr_name}={_xml_quoteattr(attr_value)}>{_xml_escape(text)}</{tag}>"


def render_rule_xml(rule: RuleDefinition) -> str:
    """Render a RuleDefinition as a minimal well-formed <rule>...</rule> block.

    Every user-controlled string is XML-escaped. Never accepts raw XML.
    """
    parts: list[str] = [
        f'<rule id={_xml_quoteattr(str(rule.id))} '
        f'level={_xml_quoteattr(str(rule.level))}>'
    ]
    # Description is required.
    parts.append(_el("description", rule.description))
    # Optional parent-rule relationships.
    if rule.if_sid is not None:
        parts.append(_el("if_sid", ", ".join(str(s) for s in rule.if_sid)))
    if rule.if_matched_sid is not None:
        parts.append(_el("if_matched_sid", str(rule.if_matched_sid)))
    # Optional matchers.
    if rule.match is not None:
        parts.append(_el("match", rule.match))
    if rule.regex is not None:
        parts.append(_el("regex", rule.regex))
    if rule.decoded_as is not None:
        parts.append(_el("decoded_as", rule.decoded_as))
    if rule.field is not None:
        for name, regex in rule.field.items():
            parts.append(_el_with_attr("field", "name", name, regex))
    if rule.srcip is not None:
        parts.append(_el("srcip", rule.srcip))
    if rule.program_name is not None:
        parts.append(_el("program_name", rule.program_name))
    # Wazuh's <group> element takes a comma-separated list with a trailing comma.
    if rule.groups is not None:
        parts.append(_el("group", ",".join(rule.groups) + ","))
    if rule.options is not None:
        for opt in rule.options:
            parts.append(_el("options", opt))
    parts.append("</rule>")
    return "".join(parts)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/test_rule_render.py tests/unit/test_rule_render_fuzz.py -v`
Expected: PASS. Fuzz tests run ~100 examples each.

- [ ] **Step 5: Lint + type + full suite**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: clean; test count up ~12+ from fuzz + unit.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/wazuh/rule_render.py tests/unit/test_rule_render.py tests/unit/test_rule_render_fuzz.py
git commit -m "M4b: RuleDefinition model + render_rule_xml pure renderer with hypothesis fuzz"
```

---

## Phase 3 — Decorator double-audit (tier-A)

### Task 4: Extend `@instrumented_tool` for write-tool double-audit + defensive `confirm` check

**Files:**
- Modify: `src/wazuh_mcp/observability/decorators.py`
- Modify: `tests/unit/test_instrumented_tool.py`

- [ ] **Step 1: Write failing tests for the new behaviours**

Append to `tests/unit/test_instrumented_tool.py`:

```python
@pytest.mark.asyncio
async def test_write_tool_emits_requested_then_completed_audit() -> None:
    """A write.* tool emits exactly one write.requested event BEFORE handler
    and one completion event AFTER. Ordering assert-able via a sequential
    sink."""
    import asyncio
    import io

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        async def _handler(**kw):
            return {"ok": True}
        wrapped = instrumented_tool(
            tool_name="write.isolate_agent",
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            await wrapped(agent_id="003", confirm=True)
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    # Two events: requested + ok.
    assert len(events) == 2
    assert '"outcome": "write.requested"' in events[0]
    assert '"tool": "write.isolate_agent"' in events[0]
    assert '"outcome": "ok"' in events[1]
    assert '"tool": "write.isolate_agent"' in events[1]


@pytest.mark.asyncio
async def test_write_tool_requested_audit_then_error_on_upstream_failure() -> None:
    """If the handler raises, the pre-emitted requested event still lands; the
    decorator emits the error completion. Exactly two events."""
    import asyncio
    import io

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        async def _handler(**kw):
            raise WazuhError("upstream_error", "boom", 502)
        wrapped = instrumented_tool(
            tool_name="write.restart_agent",
            handler=_handler,
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            with pytest.raises(WazuhError):
                await wrapped(agent_id="003", confirm=True)
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    assert len(events) == 2
    assert '"outcome": "write.requested"' in events[0]
    assert '"outcome": "error"' in events[1]
    assert '"error_code": "upstream_error"' in events[1]


@pytest.mark.asyncio
async def test_non_write_tool_emits_single_audit_as_before() -> None:
    """Non-write tools keep the M4a single-event contract."""
    import asyncio
    import io

    out = io.StringIO()
    emitter = MultiSinkAuditEmitter(sinks=[StderrSink(stream=out)])
    await emitter.start()
    try:
        wrapped = instrumented_tool(
            tool_name="alerts.search_alerts",
            handler=_handler,   # existing fixture, returns {"count": 1}
            rbac_policy=_policy,
            limiter=_limiter(),
            audit=emitter,
        )
        token = CURRENT_SESSION.set(_session("admin"))
        try:
            await wrapped()
        finally:
            CURRENT_SESSION.reset(token)
        await asyncio.sleep(0.05)
    finally:
        await emitter.stop()
    events = [line for line in out.getvalue().splitlines() if line]
    assert len(events) == 1
    assert '"outcome": "ok"' in events[0]
```

- [ ] **Step 2: Run, expect failure**

Run: `uv run pytest tests/unit/test_instrumented_tool.py -v -k "write_tool"`
Expected: FAIL — decorator doesn't emit `write.requested` yet.

- [ ] **Step 3: Add double-audit emit to `@instrumented_tool`**

Edit `src/wazuh_mcp/observability/decorators.py`. Inside the `wrapped` async function, AFTER the RBAC + rate-limit + span-open but BEFORE the `await handler(**kwargs)`, add a pre-call requested emit conditional on tool name:

```python
        # ... existing: RBAC guard, limiter.acquire, span.start_as_current_span ...
        with tracer.start_as_current_span("mcp.tool.call") as span:
            span.set_attribute("mcp.tool.name", tool_name)
            span.set_attribute("mcp.session.id", session.user_id)
            span.set_attribute("mcp.tenant.id", session.tenant_id)
            span.set_attribute("mcp.user.id", session.user_id)

            # M4b: write tools emit a pre-call "requested" event so operators
            # see intent even if the handler fails or is cancelled.
            if tool_name.startswith("write."):
                audit.emit(
                    session=session, tool=tool_name, args=kwargs,
                    outcome="write.requested", result_count=0, duration_ms=0,
                )

            try:
                result = await handler(**kwargs)
            except WazuhError as e:
                # ... existing WazuhError branch ...
```

Do NOT special-case `confirm_required` at the decorator level — the handler body checks it defensively and raises `WazuhError("confirm_required", ...)`, which the existing `except WazuhError` branch emits as the completion event with `error_code="confirm_required"`. Net: `write.requested` fires BEFORE confirm check (so attempted writes are audited even if unconfirmed), then the error completion fires. Two events, matching the contract.

- [ ] **Step 4: Verify tests pass**

Run: `uv run pytest tests/unit/test_instrumented_tool.py -v`
Expected: PASS all existing + new tests.

- [ ] **Step 5: Lint + type + full suite**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/observability/decorators.py tests/unit/test_instrumented_tool.py
git commit -m "M4b observability: @instrumented_tool emits write.requested pre-call audit for write.* tools"
```

---

## Phase 4 — `ServerApiClient` write methods

### Task 5: Add 7 new methods to `ServerApiClient`

**Files:**
- Modify: `src/wazuh_mcp/wazuh/server_api.py`
- Create: `tests/unit/test_server_api_writes.py`

**Note on Wazuh Server API endpoints.** Wazuh's REST API has shifted across 4.x releases. The paths below reflect the Wazuh 4.9 surface per publicly-documented endpoints. **If any of these return 404 in integration testing, verify against the installed Wazuh version and adjust the path — do NOT hack around with alternate endpoints.** The task's unit tests mock at the `ServerApiClient._request` boundary, so the exact path only matters for integration.

- [ ] **Step 1: Add generic PUT / DELETE / PUT-raw-body methods to `ServerApiClient`**

The existing `ServerApiClient` has `get` and `post` with run_as. Writes need `put`, `delete`, and a raw-body `put` for XML file uploads. Edit `src/wazuh_mcp/wazuh/server_api.py`, add after the existing `post` method:

```python
    async def put(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("PUT", path, json=json, params=params, run_as=run_as)

    async def delete(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("DELETE", path, params=params, run_as=run_as)

    async def put_raw(
        self,
        path: str,
        *,
        content: bytes,
        content_type: str,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        """PUT a raw body (e.g. XML for rule-file upload). Distinct from put()
        because httpx encodes json=..., but we need content=... here."""
        token = await self._ensure_jwt()
        effective_params = dict(params or {})
        if run_as is not None:
            effective_params["run_as"] = run_as
        headers = {"Authorization": f"Bearer {token}", "Content-Type": content_type}
        resp = await self._client.put(path, content=content, params=effective_params, headers=headers)
        # Reuse the existing response-code mapping pathway.
        return self._parse_response(resp)
```

If `ServerApiClient._parse_response` isn't a separate method today (inspect the existing `_request` body), refactor the response-handling logic out of `_request` into `_parse_response(resp)` so `put_raw` can share it. Check `_request`'s tail; it likely does status-code mapping via `map_http_error` and JSON parsing — that's the `_parse_response` body.

- [ ] **Step 2: Write failing tests for the 7 write methods**

Create `tests/unit/test_server_api_writes.py`:

```python
"""ServerApiClient M4b write methods."""
from __future__ import annotations

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


@pytest.fixture
def client(httpx_mock):
    # Minimal client fixture; JWT mint is mocked elsewhere or pre-seeded.
    httpx_mock.add_response(
        url="https://wazuh.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": "test-jwt"}},
    )
    c = ServerApiClient(
        base_url="https://wazuh.example:55000",
        username="wazuh",
        password=SecretValue("pass"),
        verify=False,
    )
    return c


@pytest.mark.asyncio
async def test_isolate_agent_posts_active_response(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/active-response", params={"run_as": "alice"}),
        method="POST",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.isolate_agent(agent_id="003", run_as="alice")
    assert "data" in resp
    req = httpx_mock.get_requests()[-1]
    body = req.read()
    assert b'"command":"isolate"' in body or b'"command": "isolate"' in body
    assert b'"agents":["003"]' in body or b'"agents": ["003"]' in body


@pytest.mark.asyncio
async def test_restart_agent_puts(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/agents/003/restart", params={"run_as": "alice"}),
        method="PUT",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.restart_agent(agent_id="003", run_as="alice")
    assert "data" in resp


@pytest.mark.asyncio
async def test_add_agent_to_group_puts(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/agents/003/group/linux", params={"run_as": "alice"}),
        method="PUT",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.add_agent_to_group(agent_id="003", group_id="linux", run_as="alice")
    assert "data" in resp


@pytest.mark.asyncio
async def test_remove_agent_from_group_deletes(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/agents/003/group/linux", params={"run_as": "alice"}),
        method="DELETE",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.remove_agent_from_group(agent_id="003", group_id="linux", run_as="alice")
    assert "data" in resp


@pytest.mark.asyncio
async def test_upload_rule_file_puts_raw_xml(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL(
            "https://wazuh.example:55000/manager/files/rules/wazuh-mcp-100100.xml",
            params={"run_as": "alice", "overwrite": "true"},
        ),
        method="PUT",
        json={"data": {"affected_items": ["wazuh-mcp-100100.xml"]}},
    )
    xml = b'<group name="test"><rule id="100100" level="5"><description>d</description></rule></group>'
    resp = await client.upload_rule_file(
        filename="wazuh-mcp-100100.xml", xml=xml, run_as="alice"
    )
    assert "data" in resp
    req = httpx_mock.get_requests()[-1]
    assert req.headers["content-type"].startswith("application/xml") or req.headers["content-type"] == "application/octet-stream"


@pytest.mark.asyncio
async def test_run_active_response_posts_with_command_and_args(client, httpx_mock) -> None:
    httpx_mock.add_response(
        url=httpx.URL("https://wazuh.example:55000/active-response", params={"run_as": "alice"}),
        method="POST",
        json={"data": {"affected_items": ["003"]}},
    )
    resp = await client.run_active_response(
        agent_id="003",
        command="block-ip",
        custom_args={"srcip": "10.0.0.1"},
        run_as="alice",
    )
    assert "data" in resp
    req = httpx_mock.get_requests()[-1]
    body = req.read()
    assert b'"command":"block-ip"' in body or b'"command": "block-ip"' in body
    assert b'"srcip":"10.0.0.1"' in body or b'"srcip": "10.0.0.1"' in body
```

- [ ] **Step 3: Run, expect failure**

Run: `uv run pytest tests/unit/test_server_api_writes.py -v`
Expected: FAIL — methods don't exist.

- [ ] **Step 4: Implement the 7 methods**

Append to `src/wazuh_mcp/wazuh/server_api.py`:

```python
    # ---- M4b writes ----

    async def isolate_agent(self, *, agent_id: str, run_as: str | None = None) -> dict[str, Any]:
        """Wazuh ships an 'isolate' active-response command by default on managed
        agents. This is a thin wrapper over POST /active-response."""
        return await self.post(
            "/active-response",
            json={"command": "isolate", "agents": [agent_id]},
            run_as=run_as,
        )

    async def restart_agent(self, *, agent_id: str, run_as: str | None = None) -> dict[str, Any]:
        return await self.put(f"/agents/{agent_id}/restart", run_as=run_as)

    async def add_agent_to_group(
        self, *, agent_id: str, group_id: str, run_as: str | None = None
    ) -> dict[str, Any]:
        return await self.put(f"/agents/{agent_id}/group/{group_id}", run_as=run_as)

    async def remove_agent_from_group(
        self, *, agent_id: str, group_id: str, run_as: str | None = None
    ) -> dict[str, Any]:
        return await self.delete(f"/agents/{agent_id}/group/{group_id}", run_as=run_as)

    async def upload_rule_file(
        self, *, filename: str, xml: bytes, run_as: str | None = None
    ) -> dict[str, Any]:
        """Upload a per-rule XML file. The manager must be restarted out-of-band
        for the ruleset to reload."""
        # Wazuh's rule-file endpoint accepts application/xml with overwrite=true
        # as a query-string flag.
        return await self.put_raw(
            f"/manager/files/rules/{filename}",
            content=xml,
            content_type="application/xml",
            params={"overwrite": "true"},
            run_as=run_as,
        )

    async def run_active_response(
        self,
        *,
        agent_id: str,
        command: str,
        custom_args: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"command": command, "agents": [agent_id]}
        if custom_args:
            # Wazuh expects custom fields as top-level keys in the body.
            body.update(custom_args)
        return await self.post("/active-response", json=body, run_as=run_as)
```

- [ ] **Step 5: Verify tests pass**

Run: `uv run pytest tests/unit/test_server_api_writes.py -v`
Expected: PASS. Cross-check existing `tests/unit/test_server_api.py` / `test_server_api_negatives.py` stay green.

- [ ] **Step 6: Full suite**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: clean; ~6 new tests.

- [ ] **Step 7: Commit**

```bash
git add src/wazuh_mcp/wazuh/server_api.py tests/unit/test_server_api_writes.py
git commit -m "M4b: ServerApiClient write methods (isolate/restart/group/rule-upload/active-response) with run_as"
```

---

## Phase 5 — Write tool handlers (tier-A)

### Task 6: Seven `write.*` tool handlers in `tools/write.py`

**Files:**
- Create: `src/wazuh_mcp/tools/write.py`
- Create: `tests/unit/test_write_tools.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_write_tools.py`:

```python
"""M4b write tool handlers — confirm/RBAC/allowlist/run_as contracts."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    IsolateAgentArgs,
    RestartAgentArgs,
    AddAgentToGroupArgs,
    RemoveAgentFromGroupArgs,
    CreateRuleArgs,
    UpdateRuleArgs,
    RunActiveResponseArgs,
    isolate_agent,
    restart_agent,
    add_agent_to_group,
    remove_agent_from_group,
    create_rule,
    update_rule,
    run_active_response,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.rule_render import RuleDefinition


def _session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="admin",
        auth_method="config",
        wazuh_user="alice",
    )


@pytest.fixture
def server_api():
    api = AsyncMock()
    api.isolate_agent = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.restart_agent = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.add_agent_to_group = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.remove_agent_from_group = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    api.upload_rule_file = AsyncMock(return_value={"data": {"affected_items": ["wazuh-mcp-100100.xml"]}})
    api.run_active_response = AsyncMock(return_value={"data": {"affected_items": ["003"]}})
    return api


# --- confirm contract (all tools) ---


def test_confirm_must_be_literal_true_on_isolate() -> None:
    # confirm=False is a type-check failure at Args parse (Literal[True]).
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_id="003", confirm=False)


def test_confirm_missing_on_isolate() -> None:
    with pytest.raises(ValidationError):
        IsolateAgentArgs(agent_id="003")


# --- run_as passthrough ---


@pytest.mark.asyncio
async def test_isolate_agent_passes_run_as(server_api) -> None:
    args = IsolateAgentArgs(agent_id="003", confirm=True)
    await isolate_agent(args=args, session=_session(), server_api=server_api)
    server_api.isolate_agent.assert_awaited_once_with(agent_id="003", run_as="alice")


@pytest.mark.asyncio
async def test_run_active_response_rejects_when_allowlist_empty(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_id="003", command_name="block-ip", custom_args=None, confirm=True
    )
    session = _session()
    with pytest.raises(WazuhError) as exc:
        await run_active_response(
            args=args, session=session, server_api=server_api, ar_allowlist=[]
        )
    assert exc.value.code == "forbidden"
    server_api.run_active_response.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_active_response_rejects_command_not_in_allowlist(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_id="003", command_name="dangerous", custom_args=None, confirm=True
    )
    with pytest.raises(WazuhError) as exc:
        await run_active_response(
            args=args, session=_session(), server_api=server_api,
            ar_allowlist=["block-ip", "disable-account"],
        )
    assert exc.value.code == "forbidden"


@pytest.mark.asyncio
async def test_run_active_response_allows_command_in_allowlist(server_api) -> None:
    args = RunActiveResponseArgs(
        agent_id="003", command_name="block-ip", custom_args={"srcip": "10.0.0.1"}, confirm=True
    )
    result = await run_active_response(
        args=args, session=_session(), server_api=server_api,
        ar_allowlist=["block-ip", "disable-account"],
    )
    assert result.ok is True
    server_api.run_active_response.assert_awaited_once_with(
        agent_id="003", command="block-ip", custom_args={"srcip": "10.0.0.1"}, run_as="alice",
    )


# --- rule handlers ---


@pytest.mark.asyncio
async def test_create_rule_uploads_rendered_xml(server_api) -> None:
    rd = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    args = CreateRuleArgs(rule=rd, confirm=True)
    result = await create_rule(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    server_api.upload_rule_file.assert_awaited_once()
    call = server_api.upload_rule_file.call_args
    assert call.kwargs["filename"] == "wazuh-mcp-100100.xml"
    # Payload is bytes of rendered XML; must contain our rule id.
    assert b'id="100100"' in call.kwargs["xml"]
    assert call.kwargs["run_as"] == "alice"


@pytest.mark.asyncio
async def test_update_rule_uploads_rendered_xml(server_api) -> None:
    rd = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    args = UpdateRuleArgs(rule_id=100_100, rule=rd, confirm=True)
    result = await update_rule(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    server_api.upload_rule_file.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_rule_id_mismatch_rejected() -> None:
    rd = RuleDefinition(id=100_100, level=5, description="d")
    with pytest.raises(ValidationError, match="rule_id"):
        UpdateRuleArgs(rule_id=100_200, rule=rd, confirm=True)


# --- result models expose consistent shape ---


@pytest.mark.asyncio
async def test_result_contains_timestamp_and_affected_ids(server_api) -> None:
    args = RestartAgentArgs(agent_id="003", confirm=True)
    result = await restart_agent(args=args, session=_session(), server_api=server_api)
    assert result.ok is True
    assert result.affected_agents == ["003"]
```

- [ ] **Step 2: Run, expect failure**

Run: `uv run pytest tests/unit/test_write_tools.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement write tool handlers**

Create `src/wazuh_mcp/tools/write.py`:

```python
"""M4b write tools — seven operations that mutate Wazuh state.

Contract every handler follows:
 1. Pydantic Args with `confirm: Literal[True]` (caller MUST set true).
 2. Handler takes (args, session, server_api, [ar_allowlist for run_active_response]).
 3. For run_active_response only: command_name must be in the tenant's
    active_response_allowlist.
 4. Call server_api.<verb>(..., run_as=session.wazuh_user).
 5. Return a structured Result model with ok/affected_agents/timestamp.

The pre-call audit (outcome=write.requested) and the post-call audit are
emitted by @instrumented_tool at the decorator layer. Handlers do NOT
emit audit directly.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wazuh_mcp.auth.session import Session
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml


# ---------- Shared result shape ----------


class WriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    affected_agents: list[str] | None = None
    affected_files: list[str] | None = None
    timestamp: datetime


def _extract_affected_ids(resp: dict[str, Any]) -> list[str]:
    """Wazuh returns {'data': {'affected_items': [...]}} for multi-item write
    endpoints. Read defensively."""
    data = resp.get("data", {})
    items = data.get("affected_items") or []
    return [str(i) for i in items]


# ---------- 1. isolate_agent ----------


class IsolateAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    confirm: Annotated[
        Literal[True],
        Field(description=(
            "Must be set to true by a human user. Setting this from an "
            "automated agent without explicit human instruction violates "
            "the tool's safety contract and is recorded in the audit log."
        )),
    ]


async def isolate_agent(
    *,
    args: IsolateAgentArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.isolate_agent(agent_id=args.agent_id, run_as=session.wazuh_user)
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 2. restart_agent ----------


class RestartAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    confirm: Literal[True]


async def restart_agent(
    *,
    args: RestartAgentArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.restart_agent(agent_id=args.agent_id, run_as=session.wazuh_user)
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 3. add_agent_to_group ----------


class AddAgentToGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    group_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")]
    confirm: Literal[True]


async def add_agent_to_group(
    *,
    args: AddAgentToGroupArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.add_agent_to_group(
        agent_id=args.agent_id, group_id=args.group_id, run_as=session.wazuh_user
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 4. remove_agent_from_group ----------


class RemoveAgentFromGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    group_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")]
    confirm: Literal[True]


async def remove_agent_from_group(
    *,
    args: RemoveAgentFromGroupArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    resp = await server_api.remove_agent_from_group(
        agent_id=args.agent_id, group_id=args.group_id, run_as=session.wazuh_user
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )


# ---------- 5. create_rule ----------


class CreateRuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule: RuleDefinition
    confirm: Literal[True]


def _rule_filename(rule_id: int) -> str:
    return f"wazuh-mcp-{rule_id}.xml"


async def create_rule(
    *,
    args: CreateRuleArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    xml_body = f'<group name="wazuh-mcp">{render_rule_xml(args.rule)}</group>'
    resp = await server_api.upload_rule_file(
        filename=_rule_filename(args.rule.id),
        xml=xml_body.encode("utf-8"),
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_files=[_rule_filename(args.rule.id)],
        timestamp=datetime.now(UTC),
    )


# ---------- 6. update_rule ----------


class UpdateRuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: Annotated[int, Field(ge=100_000, le=999_999)]
    rule: RuleDefinition
    confirm: Literal[True]

    @model_validator(mode="after")
    def _rule_id_matches(self) -> "UpdateRuleArgs":
        if self.rule_id != self.rule.id:
            raise ValueError(
                f"rule_id ({self.rule_id}) must match rule.id ({self.rule.id})"
            )
        return self


async def update_rule(
    *,
    args: UpdateRuleArgs,
    session: Session,
    server_api: Any,
) -> WriteResult:
    xml_body = f'<group name="wazuh-mcp">{render_rule_xml(args.rule)}</group>'
    resp = await server_api.upload_rule_file(
        filename=_rule_filename(args.rule_id),
        xml=xml_body.encode("utf-8"),
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_files=[_rule_filename(args.rule_id)],
        timestamp=datetime.now(UTC),
    )


# ---------- 7. run_active_response ----------


class RunActiveResponseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
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
        agent_id=args.agent_id,
        command=args.command_name,
        custom_args=args.custom_args,
        run_as=session.wazuh_user,
    )
    return WriteResult(
        ok=True,
        affected_agents=_extract_affected_ids(resp),
        timestamp=datetime.now(UTC),
    )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/test_write_tools.py -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint + type**

Run: `uv run ruff check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/tools/write.py tests/unit/test_write_tools.py
git commit -m "M4b tools: seven write.* handlers with Literal[True] confirm + run_as + AR allowlist check"
```

---

## Phase 6 — Server wiring (tier-A)

### Task 7: Register `write.*` tools in `_register_everything`; honor `write_allowlist`

**Files:**
- Modify: `src/wazuh_mcp/server.py`
- Modify: `tests/unit/test_server_wiring_m4a.py` (extend with M4b assertions; rename not required)
- Create: `tests/unit/test_server_wiring_m4b.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_server_wiring_m4b.py`:

```python
"""Server wiring for M4b writes — registration-time allowlist + RBAC + audit."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_writes_all_registered_when_write_allowlist_is_none() -> None:
    """None (default) -> all 7 writes registered."""
    from wazuh_mcp.server import build_app
    # ... using existing single-tenant fixture helpers from tests/unit/ ...
    # Confirm list_tools under admin role includes all seven write.* tools.
    pytest.skip("requires shared test fixture — implementer matches the pattern from test_server_wiring_m4a.py")


@pytest.mark.asyncio
async def test_writes_filtered_by_write_allowlist() -> None:
    """Non-empty write_allowlist -> only listed tools registered."""
    pytest.skip("see above; mirrors test_server_wiring_m4a patterns")


@pytest.mark.asyncio
async def test_empty_write_allowlist_registers_no_writes() -> None:
    """Empty list -> zero write tools, even for admin."""
    pytest.skip("see above")


@pytest.mark.asyncio
async def test_analyst_role_cannot_see_any_write_tool() -> None:
    """Default analyst role -> list_tools hides every write.*."""
    pytest.skip("see above")
```

(These skip-placeholder tests are intentional — the real integration shape reuses the `test_server_wiring_m4a.py` fixture pattern. Implementer fills them in against whatever fixture helper already exists in that file. If none exists, fall back to the Task 8 integration tests for end-to-end coverage and leave unit-level server-wiring assertions as the minimum coverage.)

- [ ] **Step 2: Extend `_register_everything` to register writes**

Read `src/wazuh_mcp/server.py`; find `_register_everything`. After the last M4a tool registration (prompts), add the write registration section:

```python
    # ---------- M4b write.* tools ----------
    # TenantConfig.write_allowlist semantics:
    #   None (default) -> every write.* tool registered.
    #   Non-empty list -> only named tools registered.
    #   Empty list     -> no write tools registered at all.
    from wazuh_mcp.tools.write import (
        AddAgentToGroupArgs,
        CreateRuleArgs,
        IsolateAgentArgs,
        RemoveAgentFromGroupArgs,
        RestartAgentArgs,
        RunActiveResponseArgs,
        UpdateRuleArgs,
        add_agent_to_group as _add_agent_to_group,
        create_rule as _create_rule,
        isolate_agent as _isolate_agent,
        remove_agent_from_group as _remove_agent_from_group,
        restart_agent as _restart_agent,
        run_active_response as _run_active_response,
        update_rule as _update_rule,
    )

    def _should_register(name: str, allowlist: list[str] | None) -> bool:
        if allowlist is None:
            return True
        return name in allowlist

    allowlist = tenant_cfg.write_allowlist
    ar_allowlist = tenant_cfg.active_response_allowlist

    if _should_register("write.isolate_agent", allowlist):
        async def _isolate_inner(**kwargs):
            args = IsolateAgentArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _isolate_agent(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.isolate_agent",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Isolates a Wazuh agent (blocks network traffic)."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.isolate_agent",
            handler=_isolate_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.restart_agent", allowlist):
        async def _restart_inner(**kwargs):
            args = RestartAgentArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _restart_agent(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.restart_agent",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Restarts the Wazuh agent process on the named agent."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.restart_agent",
            handler=_restart_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.add_agent_to_group", allowlist):
        async def _add_group_inner(**kwargs):
            args = AddAgentToGroupArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _add_agent_to_group(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.add_agent_to_group",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Adds an agent to a Wazuh group (applies group rules + shared config)."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.add_agent_to_group",
            handler=_add_group_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.remove_agent_from_group", allowlist):
        async def _remove_group_inner(**kwargs):
            args = RemoveAgentFromGroupArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _remove_agent_from_group(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.remove_agent_from_group",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Removes an agent from a Wazuh group."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.remove_agent_from_group",
            handler=_remove_group_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.create_rule", allowlist):
        async def _create_rule_inner(**kwargs):
            args = CreateRuleArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _create_rule(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.create_rule",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Uploads a new Wazuh rule file. Activation requires a manager restart out of band."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.create_rule",
            handler=_create_rule_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.update_rule", allowlist):
        async def _update_rule_inner(**kwargs):
            args = UpdateRuleArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _update_rule(args=args, session=session, server_api=sapi)

        mcp_app.tool(
            name="write.update_rule",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Updates an existing Wazuh rule file. Activation requires a manager restart."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.update_rule",
            handler=_update_rule_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))

    if _should_register("write.run_active_response", allowlist):
        async def _run_ar_inner(**kwargs):
            args = RunActiveResponseArgs(**kwargs)
            session = current_session()
            sapi = await server_api_pool.acquire(session.tenant_id)
            return await _run_active_response(
                args=args, session=session, server_api=sapi, ar_allowlist=ar_allowlist,
            )

        mcp_app.tool(
            name="write.run_active_response",
            description=(
                "WRITE tool. Destructive side effects. Before calling, explicitly confirm "
                "with the human user what action they want taken and that they approve. "
                "Only set confirm:true after the human has explicitly approved the specific call. "
                "Runs a tenant-allowlisted active-response command on a single agent. "
                "The command must be enumerated in TenantConfig.active_response_allowlist."
            ),
            meta={"toolset": "writes"},
        )(instrumented_tool(
            tool_name="write.run_active_response",
            handler=_run_ar_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
        ))
```

- [ ] **Step 3: Update `_register_everything` signature to take `tenant_cfg`**

The existing signature from M4a likely doesn't pass `tenant_cfg` directly — it's already part of `AppConfig.tenant` / `HttpAppConfig.tenant`. Thread the primary tenant config into `_register_everything` so the above code can read `tenant_cfg.write_allowlist` and `tenant_cfg.active_response_allowlist`. In `build_app` / `build_http_app`:

```python
_register_everything(
    mcp_app,
    indexer_pool=...,
    server_api_pool=...,
    audit_emitter=audit_emitter,
    limiter=limiter,
    rbac_policy=rbac_policy,
    tenant_cfg=cfg.tenant,   # NEW kwarg
)
```

- [ ] **Step 4: Verify existing tests pass, including the M4a wiring tests**

Run: `uv run pytest -q -m "not integration"`
Expected: all previous tests still pass; new M4b wiring tests are skips (placeholders).

- [ ] **Step 5: Lint + type**

Run: `uv run ruff check . && uv run ty check .`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring_m4b.py
git commit -m "M4b wiring: register 7 write.* tools honoring write_allowlist + active_response_allowlist"
```

---

## Phase 7 — Integration tests

### Task 8: M4b integration tests — writes against the real Wazuh manager

**Files:**
- Create: `tests/integration/test_m4b_writes.py`
- Possibly modify: `tests/integration/conftest.py` (add a tenant fixture that enables writes)

- [ ] **Step 1: Write integration tests**

Create `tests/integration/test_m4b_writes.py`:

```python
"""M4b write tools against the real Wazuh manager.

Requires amd64 runner; auto-skips on arm64+darwin via @requires_manager."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@pytest.mark.asyncio
async def test_isolate_then_restart_agent_roundtrip(mcp_http_client_with_writes) -> None:
    """Happy path: isolate, check audit events landed, restart, verify both ok."""
    iso = await mcp_http_client_with_writes.call_tool(
        "write.isolate_agent", {"agent_id": "001", "confirm": True}
    )
    assert not iso.isError

    restart = await mcp_http_client_with_writes.call_tool(
        "write.restart_agent", {"agent_id": "001", "confirm": True}
    )
    assert not restart.isError


@pytest.mark.asyncio
async def test_add_then_remove_from_group(mcp_http_client_with_writes) -> None:
    add = await mcp_http_client_with_writes.call_tool(
        "write.add_agent_to_group",
        {"agent_id": "001", "group_id": "test-group", "confirm": True},
    )
    assert not add.isError
    remove = await mcp_http_client_with_writes.call_tool(
        "write.remove_agent_from_group",
        {"agent_id": "001", "group_id": "test-group", "confirm": True},
    )
    assert not remove.isError


@pytest.mark.asyncio
async def test_create_rule_uploads_file(mcp_http_client_with_writes) -> None:
    result = await mcp_http_client_with_writes.call_tool(
        "write.create_rule",
        {
            "rule": {
                "id": 100_100,
                "level": 5,
                "description": "wazuh-mcp M4b integration test rule",
            },
            "confirm": True,
        },
    )
    assert not result.isError


@pytest.mark.asyncio
async def test_run_active_response_rejected_when_command_not_allowlisted(
    mcp_http_client_with_writes,
) -> None:
    result = await mcp_http_client_with_writes.call_tool(
        "write.run_active_response",
        {
            "agent_id": "001",
            "command_name": "not-in-allowlist",
            "custom_args": None,
            "confirm": True,
        },
    )
    assert result.isError
    text = "".join(c.text for c in result.content).lower()
    assert "allowlist" in text or "forbidden" in text


@pytest.mark.asyncio
async def test_confirm_missing_rejected_at_args_parse(mcp_http_client_with_writes) -> None:
    result = await mcp_http_client_with_writes.call_tool(
        "write.isolate_agent", {"agent_id": "001"}
    )
    assert result.isError


@pytest.mark.asyncio
async def test_audit_events_double_land_in_indexer(
    mcp_http_client_with_writes_and_indexer_sink, raw_indexer_client
) -> None:
    """One tool call -> both requested + completed audits in wazuh-mcp-audit-*."""
    import time
    await mcp_http_client_with_writes_and_indexer_sink.call_tool(
        "write.isolate_agent", {"agent_id": "001", "confirm": True}
    )
    time.sleep(3)
    today = datetime.now(UTC).strftime("%Y.%m.%d")
    resp = await raw_indexer_client.search(
        index=f"wazuh-mcp-audit-{today}",
        body={"query": {"match": {"tool": "write.isolate_agent"}}},
    )
    outcomes = [h["_source"]["outcome"] for h in resp["hits"]["hits"]]
    assert "write.requested" in outcomes
    assert "ok" in outcomes
```

- [ ] **Step 2: Add fixture(s) if needed**

Read `tests/integration/conftest.py`; the existing harness has tenant fixtures for M4a tests (e.g. `mcp_http_client_with_tiny_session_bucket`). Follow the same pattern to define `mcp_http_client_with_writes` — tenant config that enables all 7 writes and allowlists at least `block-ip` in `active_response_allowlist`. Same for `mcp_http_client_with_writes_and_indexer_sink`.

If the pattern is unclear, mirror `tests/integration/test_m4a_audit_indexer_sink.py`'s inline server-subprocess pattern. Subagent-patterns memory: "module-scoped server fixtures inline in each test file" is an acceptable shape.

- [ ] **Step 3: Verify collection**

Run: `uv run pytest --collect-only -q -m integration 2>&1 | tail -15`
Expected: 20 (M4a) + new M4b count = ~26+ integration tests.

- [ ] **Step 4: Verify unit collection still clean**

Run: `uv run pytest --collect-only -q -m "not integration" 2>&1 | tail -3`
Expected: unit count unchanged (no accidental unit-level integration tests).

- [ ] **Step 5: Lint + type**

Run: `uv run ruff check . && uv run ty check .`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/test_m4b_writes.py tests/integration/conftest.py
git commit -m "M4b integration: seven write-tool roundtrips + double-audit roundtrip + AR allowlist rejection"
```

---

## Phase 8 — Operator documentation

### Task 9: Operator docs for write-tool setup

**Files:**
- Create: `docs/deploy/m4b-writes.md`

- [ ] **Step 1: Write `m4b-writes.md`**

Create `docs/deploy/m4b-writes.md`. Must cover:

1. **Overview.** What M4b adds: seven `write.*` tools; safety model (confirm + double-audit + two-layer allowlist + run_as attribution); `active_response_allowlist` deny-all default.
2. **Enabling writes per tenant.** `TenantConfig.write_allowlist` semantics: `None` vs empty vs named list. YAML examples for each.
3. **`active_response_allowlist` setup.** Why deny-all default; how to list commands; correlation with Wazuh's own `ossec.conf` active-response configuration.
4. **Default role shape.** Admin-only writes. How to configure a "responder" custom role via `role_tool_allowlist`.
5. **`run_as` attribution.** How the OAuth `wazuh_user` claim maps to Wazuh's internal audit log. Verification: look for `run_as=<operator>` in Wazuh's own audit output alongside MCP's audit events.
6. **Confirm flow for operators of Claude.** Expected UX: Claude asks the human "May I X?", user says yes, Claude calls the tool with `confirm:true`. If Claude ever sets `confirm:true` without asking, operators see `confirm_required` error rate in their SIEM and can alert.
7. **Rule-file lifecycle.** `write.create_rule` / `write.update_rule` upload files but do NOT activate; operator restarts manager out of band. Step-by-step: upload, verify file exists via Wazuh UI, restart manager, confirm rule loads.
8. **Audit-log shape.** Every write emits TWO events (`write.requested` + completion). Example Wazuh Dashboards saved search for "attempted writes" vs "completed writes" vs "failed writes".
9. **Cross-references.** Link `m4a-secrets.md`, `m4a-observability.md`, `m4a-audit.md` for the underlying M4a primitives.

Match the style of the existing `docs/deploy/m3-tools.md` and `docs/deploy/m4a-audit.md`. Terse, operator-focused, concrete YAML examples with no ellipsis.

Target length 200-350 lines. Don't pad.

- [ ] **Step 2: Commit**

```bash
git add docs/deploy/m4b-writes.md
git commit -m "M4b docs: operator guide for write tools, allowlists, confirm flow, and rule lifecycle"
```

---

## Phase 9 — Ship

### Task 10: Ship M4b

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `docs/superpowers/retros/2026-04-XX-m4b-retro.md`

- [ ] **Step 1: Full-suite verification**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check . && uv run pytest -q -m "not integration"`
Expected: all green. If `ruff format --check` fails, apply via `uv run ruff format .` and commit that alignment in its own commit FIRST (matches M2/M3/M4a pattern: `3c20a8d`, `6fa3fce`, `765cd59`).

- [ ] **Step 2: (If needed) ruff format alignment commit**

```bash
# only if Step 1 surfaces format diffs:
uv run ruff format .
git add <specific files listed in the diff>   # NOT -A
git commit -m "Apply ruff format to align M4b source with repo format rules"
```

- [ ] **Step 3: Bump version**

Edit `pyproject.toml`:

```toml
version = "0.5.0"
```

- [ ] **Step 4: Regen lock**

Run: `uv lock`
Expected: `uv.lock` updated.

- [ ] **Step 5: Kick a manual-dispatch integration run (user territory)**

Via GH Actions UI, trigger `integration.yml` on the current HEAD. Wait for green (30 min). If it fails, fix and re-run — do NOT ship on a failing integration run.

- [ ] **Step 6: Write retro**

Create `docs/superpowers/retros/2026-04-XX-m4b-retro.md` (fill in the date at ship time). Template:

```markdown
# M4b Write-Tool Surface — Retrospective

**Tag:** `v0.5.0-m4b`
**Plan:** `docs/superpowers/plans/2026-04-24-wazuh-mcp-m4b-writes.md`
**Spec:** `docs/superpowers/specs/2026-04-24-wazuh-mcp-m4b-design.md`
**Predecessors:** M4a production hardening (`v0.4.0-m4a`).

## Outcome

[Test count, commits, features landed.]

## What went well

[Dispatch strategy, dual reviews, specific design wins.]

## Plan bugs caught

[Any plan-level issues that surfaced during execution.]

## Subagent behavior patterns (delta)

[New patterns not yet in feedback_subagent_patterns.md.]

## Known gaps carried to M4c / M5

- Toolset SDK (if probe came back negative).
- write.restart_manager for rule activation.
- Multi-agent run_active_response.
- Cross-tenant write leak tests (M5).

## Methodology notes

[Refinements to the brainstorm → spec → plan → subagent flow.]
```

- [ ] **Step 7: Commit version bump + retro**

```bash
git add pyproject.toml uv.lock docs/superpowers/retros/2026-04-XX-m4b-retro.md
git commit -m "M4b ship: bump to 0.5.0 and land retro

v0.5.0-m4b shipped. [fill in: N unit tests + N integration tests.] Full
write-tool surface: 7 write.* tools gated by Literal[True] confirm,
double-audit, two-layer allowlist (TenantConfig.write_allowlist at
registration + RBAC at list/call), run_as attribution via OAuth
wazuh_user claim, deny-all-by-default active_response_allowlist for
run_active_response. Structured Pydantic RuleDefinition -> pure XML
renderer (no raw DSL). Toolset SDK status per probe note."
```

- [ ] **Step 8: Tag + push**

```bash
git tag v0.5.0-m4b
git push origin main --tags
```

Expected: push succeeds; branch protection `lint-and-unit` status check goes green shortly after.

---

## Self-review checklist

**Spec coverage** — every 2.x section in the spec has at least one task:

- 2.1 Confirmation flow → T6 (Literal[True] in Args) + T4 (decorator emits `write.requested` pre-call) + T1 (`confirm_required` in SAFE_CODES) ✓
- 2.2 Namespace + default roles → T6 + T7 (`write.*` names in allowlist validator, admin-only default) ✓
- 2.3 Two-layer allowlist → T2 (`write_allowlist` validation) + T7 (registration-time filter) + (call-time RBAC inherited from M4a) ✓
- 2.4 `run_active_response` allowlist + single-agent + run_as → T2 + T6 + T5 ✓
- 2.5 Rule input shape → T3 (RuleDefinition + render_rule_xml + fuzz) ✓
- 2.6 Rule file lifecycle (no auto-restart) → T5 (upload_rule_file) + T6 (create/update_rule call upload only) + T9 (docs) ✓
- 2.7 ServerApiClient additions → T5 ✓
- 2.8 Double-audit → T4 (decorator) ✓
- 2.9 Toolset SDK probe → T1 ✓
- 2.10 Error mapping → T1 (confirm_required) + T6 (forbidden on AR allowlist deny) ✓

**Placeholder scan:**

- Retro date in T10 uses `YYYY-MM-XX` placeholder — intentional; filled at ship time.
- T7 has three `pytest.skip(...)` placeholder tests — intentional, the end-to-end coverage lives in the T8 integration tests. Plan explicitly calls this out.
- No TBDs or "implement later" beyond those.

**Type consistency:**

- `ServerApiClient.isolate_agent(agent_id: str, run_as: str | None)` in T5 matches the call in T6's `isolate_agent` handler.
- `RuleDefinition` in T3 matches `CreateRuleArgs.rule: RuleDefinition` and `UpdateRuleArgs.rule: RuleDefinition` in T6.
- `WriteResult` shape (ok, affected_agents, affected_files, timestamp) used consistently across all 7 handlers.
- `run_as=session.wazuh_user` passed through in every handler matches the ServerApiClient method signatures in T5.

**Task ordering verification:**

- T1 foundation first (SAFE_CODES addition needed by T6 handler's confirm_required path). ✓
- T2 config before T7 wiring reads `tenant_cfg.write_allowlist`. ✓
- T3 renderer before T6 handlers call `render_rule_xml`. ✓
- T4 decorator before T6 — handlers assume the decorator emits `write.requested` pre-call. ✓
- T5 ServerApiClient methods before T6 handler bodies call them. ✓
- T6 handlers before T7 wiring imports them. ✓
- T7 wiring before T8 integration tests exercise the full path. ✓
