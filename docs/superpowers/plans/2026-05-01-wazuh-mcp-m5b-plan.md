# wazuh-mcp M5b — v1.0.0 Ship-Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `v1.0.0` — the publicly-credible 1.0 release: matrix-tested compat across Wazuh-LTS + Wazuh-latest, production-baseline Helm chart, end-to-end Vault driver coverage, group-target active-response capability, topic-organized operator docs, and full closure of every M5a-deferred item.

**Architecture:** Six phases. Phase 1 lands the only novel security primitive (group-target AR with `agent_group_allowlist`). Phase 2 batches test-infrastructure additions (Wazuh matrix CI, multi-manager workflow, Vault container, audit-routing fix, phantom-token fixture, integration-log secret-scan). Phase 3 is the cross-cutting `WazuhError.scope` refactor. Phase 4 ships the Helm chart. Phase 5 restructures docs into topic files (controller-inline). Phase 6 runs T6 eval baseline + ship. Phases 2 ⊥ 3 ⊥ 4. Phase 5 must follow Phase 1. Phase 6 gated on all prior.

**Tech Stack:** Python 3.12 + uv + mcp 1.27 (FastMCP + streamable_http_client) + joserfc 1.6 + httpx 0.27 + Pydantic v2 + pytest + pytest-asyncio + Hypothesis + Helm 3 + Docker Compose + Kind + GitHub Actions + Wazuh 4.9 (LTS) + Wazuh 4.12.x (latest pin TBD at plan-execute) + Keycloak 26 + HashiCorp Vault 1.18 (community OSS dev mode) + gitleaks 8.x.

**Predecessor:** `v0.8.0-m5a` at `7c1f9c0` + 5 Dependabot merges + 7 post-ship patches. Spec at `docs/superpowers/specs/2026-05-01-wazuh-mcp-m5b-design.md` (commit `07f5876`). HEAD at plan-write time is `07f5876` on `main`.

**Successor:** v1.1 (External Secrets Operator integration, HA-grade Helm chart with PDB/HPA, external Redis rate-limiter, group-target AR enhancements).

**Total scope:** 31 tasks across 6 phases. ~16 dispatches expected (Phases 5+6 controller-inline absorb 12 tasks).

**Methodology in force** (from `feedback_methodology.md` + `feedback_subagent_patterns.md`):

- **No AI attribution in commits.** Never `Co-Authored-By: Claude` or "Generated with Claude" footer.
- **Tier-A spot-check default** for composition tasks; **full review** when introducing a novel primitive (T-A1, T-A2 only in M5b).
- **Plan-time signature grep** mandatory for tasks touching existing modules. Verified call sites embedded in each task body below.
- **Cross-subsystem invariant grep (M5a T7 lesson):** when a task changes one layer's invariant, grep ALL CALL SITES of the changed return value.
- **FastMCP wraps internal exceptions into ToolError.** Unit tests calling `mcp_app.call_tool(...)` must catch `ToolError` and assert `__cause__` is the underlying `WazuhError`.
- **Result-model contract:** typed-output tools return JSON in `result.structuredContent`, NOT `result.content[0].text`.
- **Code snippets must pass ruff:** no f-strings without placeholders (F541); use ASCII dashes (RUF001/RUF003); use `# ty: ignore` (not `# type: ignore` — ty syntax).
- **Don't stack spec→plan→execution in one session.** Plan ends at commit; execution happens in a fresh-context session.

---

## File Structure (all phases)

### New files

```
src/wazuh_mcp/                                   # Phase 1, 3
  # Phase 1: no new top-level src files; modifications only
  # Phase 3: no new top-level src files; modifications only

tests/unit/                                      # Phase 1, 3
  test_ar_group_allowlist.py                     # T-A1 (new)
  test_run_active_response_on_group.py           # T-A2 (new)
  test_wazuh_error_scope.py                      # T-G1 (new)

tests/integration/                               # Phase 1, 2
  test_m5b_group_ar.py                           # T-A3 (new)
  test_multi_manager.py                          # T-C1 (new)
  test_vault_secret_store.py                     # T-D1 (new)
  _vault_bootstrap.py                            # T-D1 (new helper)
  _keycloak_admin.py                             # T-G4a (new helper)

docker/                                          # Phase 2
  multi-manager-compose.yml                      # T-C1 (new)
  vault/                                         # T-D1
    README.md                                    # T-D1 (new)

charts/wazuh-mcp/                                # Phase 4
  Chart.yaml
  values.yaml
  values.schema.json
  README.md
  .helmignore
  templates/
    _helpers.tpl
    deployment.yaml
    service.yaml
    configmap-tenants.yaml
    secret.yaml
    serviceaccount.yaml
    role.yaml
    rolebinding.yaml
    networkpolicy.yaml
    servicemonitor.yaml
    ingress.yaml
    tests/
      test-connection.yaml

.github/workflows/                               # Phase 2, 4
  multi-manager-integration.yml                  # T-C2 (new)
  integration-log-scan.yml                       # T-G2b (new)
  helm-lint.yml                                  # T-E4 (new)

docs/deploy/                                     # Phase 5
  README.md                                      # T-F4 (new)
  install.md                                     # T-F4 (new)
  tenants.md                                     # T-F4 (new)
  secrets.md                                     # T-F1 (new)
  oauth.md                                       # T-F1 (new)
  tools.md                                       # T-F1 (new)
  writes.md                                      # T-F2 (new)
  observability.md                               # T-F3 (new)
  multi-tenant.md                                # T-F2 (new)
  quality-gates.md                               # T-F3 (new)
  helm.md                                        # T-E5 (new)
  _archive/
    README.md                                    # T-F4 (new)
    # m{2,3,4a,4b,4c,4d,5a}-*.md                 # T-F1-F4 (mv)

docs/                                            # Phase 5
  api-reference.md                               # T-F5 (new)

docs/eval-history/                               # Phase 6
  YYYY-MM-DD-claude-opus-4-7-results.json        # T-G3
  YYYY-MM-DD-claude-opus-4-7-raw.txt             # T-G3

docs/superpowers/retros/                         # Phase 6
  2026-05-XX-m5b-retro.md                        # ship-2 (new)
```

### Modified files

```
src/wazuh_mcp/wazuh/errors.py                    # T-G1: add scope kwarg + slot
src/wazuh_mcp/tenancy/config.py                  # T-A1: add agent_group_allowlist field
src/wazuh_mcp/tenancy/m4_config.py               # T-A1: add _validate_ar_group_name (if needed)
src/wazuh_mcp/rbac/resolver.py                   # T-A1: add make_ar_group_allowlist
src/wazuh_mcp/wazuh/server_api.py                # T-A2: add run_active_response_on_group
src/wazuh_mcp/tools/write.py                     # T-A2: add RunActiveResponseOnGroupArgs + handler
src/wazuh_mcp/server.py                          # T-A2: wire ar_group_allowlist_policy + new handler + registration
src/wazuh_mcp/rate_limit/limiter.py              # T-G1: add scope= to WazuhError raises
src/wazuh_mcp/observability/metrics.py           # T-G1: consume scope label, drop substring-match

tests/integration/conftest.py                    # T-G4a, T-D1: new fixtures
tests/integration/test_m4d_multi_tenant.py       # T-G4b: un-skip cross-tenant test 4 (test_unknown_tenant_token_routes_to_globals_only); T-G5b: un-skip test_per_tenant_audit_routing
tests/unit/test_*                                # T-G1: 5 raise-site test updates

docker/integration-compose.yml                   # T-B1: parameterize image tags; T-D1: add vault service
docker/bootstrap.sh                              # T-B1: pass WAZUH_VERSION through (already version-agnostic)

.github/workflows/integration.yml                # T-B1: matrix dim; T-G2a: always-upload artifacts; T-C2: filter update
.github/workflows/destructive-integration.yml    # T-B1: matrix dim
pyproject.toml                                   # T-C2, T-D1: register new markers; ship-1: version bump
README.md                                        # T-F5: top-level polish

docs/security/threat-model.md                    # T-A4 if WazuhError.scope or group-target adds threats
```

### Archived (moved into `_archive/` in Phase 5)

```
docs/deploy/m2-http.md                           # → _archive/ (T-F4)
docs/deploy/m3-tools.md                          # → _archive/ (T-F1)
docs/deploy/m4a-secrets.md                       # → _archive/ (T-F1)
docs/deploy/m4a-observability.md                 # → _archive/ (T-F3)
docs/deploy/m4a-audit.md                         # → _archive/ (T-F3)
docs/deploy/m4b-writes.md                        # → _archive/ (T-F2)
docs/deploy/m4c-multi-tenant.md                  # → _archive/ (T-F2)
docs/deploy/m4d-multi-tenant-runtime.md          # → _archive/ (T-F2)
docs/deploy/m5a-quality-gates.md                 # → _archive/ (T-F3)
```

---

## Phase 1 — Group-target `run_active_response` (3 tasks; T-A4 docs in Phase 5)

**Phase rationale:** The only novel security primitive in M5b. Lands first because Phase 5 docs need to describe the shipped surface, and downstream test fixtures (Phase 2 multi-manager, Phase 4 helm-test) may consume it for verification. Tier-A full review on T-A1 + T-A2 (one combined reviewer dispatch acceptable per M3 retro pattern).

### Task T-A1: `TenantConfig.agent_group_allowlist` + `make_ar_group_allowlist` resolver

**Tier:** A (full review).

**Files:**
- Modify: `src/wazuh_mcp/tenancy/config.py:22-63` (add field + validator)
- Modify: `src/wazuh_mcp/tenancy/m4_config.py` (add `_validate_ar_group_name` validator)
- Modify: `src/wazuh_mcp/rbac/resolver.py:74-96` (add `make_ar_group_allowlist` factory)
- Test: `tests/unit/test_ar_group_allowlist.py` (new)
- Test: `tests/unit/test_tenant_config.py` (extend existing if present, else add cases inline)

**Verified call sites (plan-time grep results, baseline at HEAD `07f5876`):**

```bash
# Run these at task start to confirm baseline hasn't drifted.
grep -n "active_response_allowlist\|class TenantConfig\|extra=\"forbid\"" src/wazuh_mcp/tenancy/config.py
grep -n "_validate_ar_command_name\|_validate_write_allowlist_entry\|_WRITE_TOOL_NAMES" src/wazuh_mcp/tenancy/m4_config.py
grep -n "make_ar_allowlist\|make_write_allowlist\|make_rbac_policy\|_RESOLVE_SENTINEL\|_REASON" src/wazuh_mcp/rbac/resolver.py
```

Expected at HEAD `07f5876`:
- `TenantConfig` at `tenancy/config.py:22`, `extra="forbid", frozen=True`. Existing `active_response_allowlist: list[str] = Field(default_factory=list)` at line 47 with `@field_validator("active_response_allowlist")` at line 58.
- `_validate_ar_command_name` at `tenancy/m4_config.py:95`. `_WRITE_TOOL_NAMES: set[str]` at line 73.
- `make_ar_allowlist` at `rbac/resolver.py:74`. `_RESOLVE_SENTINEL = "<rbac.resolve>"` at line 22; `_REASON = "tenant_not_registered"` at line 23.

**Cross-subsystem invariant grep (M5a T7 lesson):**

```bash
grep -rn "agent_group_allowlist\|ar_group_allowlist" src/ tests/
```

Expected: zero hits at HEAD `07f5876` (this is a new primitive). Re-run after T-A1 completion to confirm only the new sites added by this task are present.

**Steps:**

- [ ] **Step 1: Write failing test for `agent_group_allowlist` field default**

```python
# tests/unit/test_ar_group_allowlist.py
"""Per-tenant agent_group_allowlist resolver tests (M5b T-A1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import MultiSinkAuditEmitter
from wazuh_mcp.rbac.resolver import make_ar_group_allowlist
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import SingleTenantRegistry, YamlTenantRegistry


def _tenant(tenant_id: str = "t1", group_allow: list[str] | None = None) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        indexer_url="https://idx:9200",  # type: ignore[arg-type]
        default_rbac_role="admin",
        agent_group_allowlist=group_allow or [],
    )


def test_default_agent_group_allowlist_is_empty() -> None:
    t = _tenant()
    assert t.agent_group_allowlist == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/unit/test_ar_group_allowlist.py::test_default_agent_group_allowlist_is_empty -v
```

Expected: `FAILED` with `ValidationError: Extra inputs are not permitted [type=extra_forbidden, input_value=[], input_type=list]` (because `extra="forbid"` rejects unknown field).

- [ ] **Step 3: Add field to `TenantConfig`**

Edit `src/wazuh_mcp/tenancy/config.py`. After line 47 (existing `active_response_allowlist` declaration) add:

```python
    # M5b addition (T-A1). agent_group_allowlist: deny-all by default
    # (mirrors active_response_allowlist precedent). Group names are
    # used to fan out write.run_active_response_on_group calls; a session
    # may target a group only if its name appears here.
    agent_group_allowlist: list[str] = Field(default_factory=list)
```

After the existing `_validate_ar` `@field_validator("active_response_allowlist")` block (around line 58-63), add:

```python
    @field_validator("agent_group_allowlist")
    @classmethod
    def _validate_ar_groups(cls, v: list[str]) -> list[str]:
        from wazuh_mcp.tenancy.m4_config import _validate_ar_group_name

        return [_validate_ar_group_name(name) for name in v]
```

- [ ] **Step 4: Add validator to `m4_config.py`**

Edit `src/wazuh_mcp/tenancy/m4_config.py`. After the existing `_validate_ar_command_name` function (around line 95) add:

```python
_AGENT_GROUP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_AGENT_GROUP_MAX = 50


def _validate_ar_group_name(name: str) -> str:
    """Wazuh agent group names: alphanumeric + dot/dash/underscore, length 1-128.
    Reject empty strings and overflow at the field-validator layer to fail
    fast at YAML-load.
    """
    if not isinstance(name, str) or not _AGENT_GROUP_NAME_PATTERN.match(name):
        raise ValueError(
            f"invalid agent group name: {name!r}. "
            "Expected: alphanumeric + .-_ characters, length 1-128, "
            "must start with alphanumeric."
        )
    return name
```

Add `import re` at top if not already present (verify — it should already be present since `_AGENT_GROUP_NAME_PATTERN` uses it; if not, add it).

Also add a max-length validator at the field level for the list itself. Add a second validator after the per-element validator in `config.py`:

```python
    @field_validator("agent_group_allowlist")
    @classmethod
    def _validate_ar_groups_max(cls, v: list[str]) -> list[str]:
        from wazuh_mcp.tenancy.m4_config import _AGENT_GROUP_MAX

        if len(v) > _AGENT_GROUP_MAX:
            raise ValueError(
                f"agent_group_allowlist length {len(v)} exceeds max {_AGENT_GROUP_MAX}"
            )
        return v
```

Note: Pydantic v2 invokes multiple `@field_validator` for the same field in declaration order. Place the per-element validator first (it normalizes), then the length check second.

- [ ] **Step 5: Run test, verify it passes**

```bash
uv run pytest tests/unit/test_ar_group_allowlist.py::test_default_agent_group_allowlist_is_empty -v
```

Expected: `PASSED`.

- [ ] **Step 6: Add field validator tests**

Append to `tests/unit/test_ar_group_allowlist.py`:

```python
def test_valid_group_name_accepted() -> None:
    t = _tenant(group_allow=["test-group", "soc_responders.tier1"])
    assert t.agent_group_allowlist == ["test-group", "soc_responders.tier1"]


def test_invalid_group_name_with_special_char_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        _tenant(group_allow=["bad/name"])
    assert "invalid agent group name" in str(exc_info.value)


def test_empty_group_name_rejected() -> None:
    with pytest.raises(ValidationError):
        _tenant(group_allow=[""])


def test_group_allowlist_overflow_rejected() -> None:
    too_many = [f"g{i}" for i in range(51)]
    with pytest.raises(ValidationError) as exc_info:
        _tenant(group_allow=too_many)
    assert "exceeds max 50" in str(exc_info.value)
```

- [ ] **Step 7: Run validator tests**

```bash
uv run pytest tests/unit/test_ar_group_allowlist.py -v
```

Expected: 4 PASSED.

- [ ] **Step 8: Add resolver factory**

Edit `src/wazuh_mcp/rbac/resolver.py`. After the existing `make_ar_allowlist` function (line 74-95), add:

```python
def make_ar_group_allowlist(
    registry: TenantRegistry,
    audit_emitter: MultiSinkAuditEmitter,
) -> Callable[[Session], list[str]]:
    """M5b T-A1. Session-keyed agent_group_allowlist resolver.

    Fail-closed pattern matches make_ar_allowlist (line 74): unknown
    tenant_id → audit emit with sentinel tool='<rbac.resolve>' +
    error_reason='tenant_not_registered' + return [] (deny-all).
    """

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
        return list(cfg.agent_group_allowlist)

    return _resolve
```

- [ ] **Step 9: Add resolver tests**

Append to `tests/unit/test_ar_group_allowlist.py`:

```python
def test_resolver_returns_tenant_allowlist() -> None:
    t = _tenant(tenant_id="t1", group_allow=["soc-tier1", "soc-tier2"])
    registry = SingleTenantRegistry(t)
    audit_calls: list[dict] = []

    class _CapturingEmitter:
        def emit(self, **kwargs):
            audit_calls.append(kwargs)

    resolve = make_ar_group_allowlist(registry, _CapturingEmitter())  # type: ignore[arg-type]
    session = Session(
        user_id="u1", tenant_id="t1", rbac_role="admin",
        auth_method="oauth", wazuh_user="alice",
    )
    assert resolve(session) == ["soc-tier1", "soc-tier2"]
    assert audit_calls == []  # happy path: no audit


def test_resolver_unknown_tenant_emits_audit_and_returns_empty() -> None:
    t = _tenant(tenant_id="t1")
    registry = SingleTenantRegistry(t)
    audit_calls: list[dict] = []

    class _CapturingEmitter:
        def emit(self, **kwargs):
            audit_calls.append(kwargs)

    resolve = make_ar_group_allowlist(registry, _CapturingEmitter())  # type: ignore[arg-type]
    session = Session(
        user_id="u1", tenant_id="phantom-tenant", rbac_role="admin",
        auth_method="oauth", wazuh_user=None,
    )
    assert resolve(session) == []
    assert len(audit_calls) == 1
    assert audit_calls[0]["tool"] == "<rbac.resolve>"
    assert audit_calls[0]["error_code"] == "forbidden"
    assert audit_calls[0]["error_reason"] == "tenant_not_registered"
    assert audit_calls[0]["outcome"] == "error"
```

- [ ] **Step 10: Run all unit tests, verify pass**

```bash
uv run pytest tests/unit/test_ar_group_allowlist.py tests/unit/ -q -m "not integration" 2>&1 | tail -10
```

Expected: 6 new tests PASSED in `test_ar_group_allowlist.py`. Total unit count delta: +6 (519 → 525).

- [ ] **Step 11: Lint + type check**

```bash
uv run ruff check src/wazuh_mcp/tenancy/config.py src/wazuh_mcp/tenancy/m4_config.py src/wazuh_mcp/rbac/resolver.py tests/unit/test_ar_group_allowlist.py
uv run ruff format --check .
uv run ty check src/
```

Expected: all clean. The runtime LSP may flag `unresolved-attribute` on `TenantConfig.agent_group_allowlist` after edit (M4a-known false positive); CLI `ty check` is authoritative.

- [ ] **Step 12: Commit**

```bash
git add src/wazuh_mcp/tenancy/config.py src/wazuh_mcp/tenancy/m4_config.py src/wazuh_mcp/rbac/resolver.py tests/unit/test_ar_group_allowlist.py
git commit -m "M5b T-A1: per-tenant agent_group_allowlist field + resolver

Adds TenantConfig.agent_group_allowlist (deny-all default; max 50,
group-name validator) and make_ar_group_allowlist resolver that mirrors
make_ar_allowlist's fail-closed pattern (unknown tenant -> audit emit
+ empty list).

Wired into _register_everything by T-A2 (next task)."
```

---

### Task T-A2: `ServerApiClient.run_active_response_on_group` + Args + handler + registration

**Tier:** A (full review).

**Files:**
- Modify: `src/wazuh_mcp/wazuh/server_api.py:213-230` (add `run_active_response_on_group` method after existing `run_active_response`)
- Modify: `src/wazuh_mcp/tools/write.py:258-299` (add `RunActiveResponseOnGroupArgs` + `run_active_response_on_group` handler after existing AR section)
- Modify: `src/wazuh_mcp/tenancy/m4_config.py:73` (extend `_WRITE_TOOL_NAMES` set)
- Modify: `src/wazuh_mcp/server.py:537-547` (add `ar_group_allowlist_policy` kwarg to `_register_everything`); `:314-324` and `:490-500` (wire factories at both call sites); add new handler + registration block after existing `_run_ar_inner` block at `:1263-1298`
- Test: `tests/unit/test_run_active_response_on_group.py` (new)
- Test: `tests/unit/test_server_api_writes.py` (extend)

**Verified call sites (plan-time grep results, baseline at HEAD `07f5876`):**

```bash
# Re-run at task start.
grep -n "_AR_AGENTS_MAX\|class RunActiveResponseArgs\|async def run_active_response" src/wazuh_mcp/tools/write.py
grep -n "async def run_active_response\|/active-response\|agents_list" src/wazuh_mcp/wazuh/server_api.py
grep -n "_WRITE_TOOL_NAMES" src/wazuh_mcp/tenancy/m4_config.py
grep -n "def _register_everything\|ar_allowlist_policy\|_check_write_allowed" src/wazuh_mcp/server.py | head -10
grep -n "_run_ar_inner\|write.run_active_response" src/wazuh_mcp/server.py | head -10
```

Expected at HEAD `07f5876`:
- `_AR_AGENTS_MAX: Final = 50` at `tools/write.py:31`.
- `class RunActiveResponseArgs` at `tools/write.py:261`. `agent_ids: Annotated[list[str], Field(min_length=1, max_length=_AR_AGENTS_MAX)]` at `:264-267`.
- `async def run_active_response(*, args, session, server_api, ar_allowlist)` at `tools/write.py:273`.
- `async def run_active_response(self, *, agent_ids, command, custom_args, run_as)` on `ServerApiClient` at `server_api.py:213`. URL build: `params={"agents_list": ",".join(agent_ids)}`.
- `_WRITE_TOOL_NAMES: set[str] = { ... }` at `m4_config.py:73`.
- `_register_everything(...)` at `server.py:537`. `ar_allowlist_policy: Callable[[Session], list[str]] | None = None` at `:546`.
- `_check_write_allowed(session: Session, tool_name: str)` defined at `:581`. Called per write at `:1124`, `:1148`, `:1171`, `:1195`, `:1218`, `:1242`, `:1266`, `:1303`.
- `async def _run_ar_inner` at `server.py:1263`. Followed by `mcp_app.tool(name="write.run_active_response", description=..., meta={"toolset": "writes"})(instrumented_tool(...))` block at `:1282-1298`.

**Cross-subsystem invariant grep:**

```bash
grep -rn "make_ar_allowlist\|ar_allowlist_policy" src/ tests/
```

Expected: 6-8 hits in `src/wazuh_mcp/server.py` + a few in `tests/unit/`. Every site that constructs `ar_allowlist_policy` at boot (server.py:314, server.py:490) needs a parallel `ar_group_allowlist_policy` construction. Every test that builds a server-equivalent harness with an `ar_allowlist_policy` mock needs the parallel policy added.

**Steps:**

- [ ] **Step 1: Write failing test for new ServerApiClient method**

```python
# tests/unit/test_server_api_writes.py — extend existing module
# Add this test alongside existing run_active_response tests.
import pytest


@pytest.mark.asyncio
async def test_run_active_response_on_group_builds_group_agents_list(httpx_mock):
    """T-A2: PUT /active-response with agents_list=group:<name>.

    Wazuh 4.9 syntax for group-target AR. Distinct from agent-id list
    (which is comma-joined) by the literal 'group:' prefix.
    """
    from wazuh_mcp.wazuh.server_api import ServerApiClient
    from wazuh_mcp.secrets.value import SecretValue

    httpx_mock.add_response(
        method="PUT",
        url="https://manager.example/active-response?agents_list=group%3Asoc-tier1&run_as=alice",
        json={"data": {"affected_items": ["001", "002"], "failed_items": []}},
        status_code=200,
    )

    client = ServerApiClient(
        base_url="https://manager.example",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("test-pw"),
        verify_tls=False,
    )
    try:
        resp = await client.run_active_response_on_group(
            group_name="soc-tier1",
            command="restart-wazuh",
            custom_args=None,
            run_as="alice",
        )
        assert resp["data"]["affected_items"] == ["001", "002"]
    finally:
        await client.aclose()
```

Note: confirm at task start that `ServerApiClient` constructor signature is `(base_url, user: SecretValue, password: SecretValue, verify_tls: bool)` — the M4c plan-drift retro says it's `user`/`password`/`verify_tls`, NOT `username`/`password`/`verify`. If the actual signature differs at task start, adapt the test.

Confirm URL encoding: httpx URL-encodes `:` as `%3A` when in query params. The mock URL above uses the encoded form. If httpx behavior differs at the version pinned in `pyproject.toml`, adjust accordingly.

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/unit/test_server_api_writes.py::test_run_active_response_on_group_builds_group_agents_list -v
```

Expected: `AttributeError: 'ServerApiClient' object has no attribute 'run_active_response_on_group'`.

- [ ] **Step 3: Add `run_active_response_on_group` to `ServerApiClient`**

Edit `src/wazuh_mcp/wazuh/server_api.py`. After the existing `run_active_response` method (ends around line 230), add:

```python
    async def run_active_response_on_group(
        self,
        *,
        group_name: str,
        command: str,
        custom_args: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        """M5b T-A2. Group-target AR.

        Wazuh 4.9 active-response endpoint accepts agents_list=group:<name>
        as documented Wazuh syntax to fan out a command to every agent in
        the named group. Wire shape is identical to single-target AR
        otherwise: PUT /active-response with command in the JSON body.
        """
        body: dict[str, Any] = {"command": command}
        if custom_args:
            body.update(custom_args)
        return await self.put(
            "/active-response",
            json=body,
            params={"agents_list": f"group:{group_name}"},
            run_as=run_as,
        )
```

- [ ] **Step 4: Run test, verify pass**

```bash
uv run pytest tests/unit/test_server_api_writes.py::test_run_active_response_on_group_builds_group_agents_list -v
```

Expected: `PASSED`. If httpx URL-encodes `:` differently than the mock asserts, the assertion message will show the actual URL — adjust the mock URL to match.

- [ ] **Step 5: Add Args + handler in `tools/write.py`**

Edit `src/wazuh_mcp/tools/write.py`. After the existing `run_active_response` function (ends around line 299), add:

```python
# ---------- 8. run_active_response_on_group (M5b T-A2) ----------


class RunActiveResponseOnGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    group_name: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            description=(
                "Wazuh agent group name. Must be enumerated in the tenant's "
                "agent_group_allowlist; rejected with 'forbidden' otherwise."
            ),
        ),
    ]
    command_name: Annotated[str, Field(min_length=1, max_length=128)]
    custom_args: dict[str, Any] | None = None
    confirm: Literal[True]


async def run_active_response_on_group(
    *,
    args: RunActiveResponseOnGroupArgs,
    session: Session,
    server_api: Any,
    ar_group_allowlist: Sequence[str],
) -> WriteResult:
    """T-A2 handler. Two gates: write_allowlist (registration-time, in
    server.py) + agent_group_allowlist (per-call, here)."""
    if args.group_name not in ar_group_allowlist:
        raise WazuhError(
            "forbidden",
            f"agent group {args.group_name!r} not in tenant agent_group_allowlist",
            403,
        )
    resp = await server_api.run_active_response_on_group(
        group_name=args.group_name,
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

- [ ] **Step 6: Extend `_WRITE_TOOL_NAMES` in `m4_config.py`**

Edit `src/wazuh_mcp/tenancy/m4_config.py`. The existing `_WRITE_TOOL_NAMES: set[str]` literal at line 73 lists 8 names ending with `"write.restart_manager"`. Append:

```python
    "write.run_active_response_on_group",
```

(Place inside the set literal alphabetically or after `write.run_active_response` for readability — either works.)

- [ ] **Step 7: Add `ar_group_allowlist_policy` kwarg to `_register_everything`**

Edit `src/wazuh_mcp/server.py`. Modify the function signature at line 537. After line 546 (existing `ar_allowlist_policy` kwarg) add:

```python
    ar_group_allowlist_policy: Callable[[Session], list[str]] | None = None,
```

- [ ] **Step 8: Wire the new handler + registration in `_register_everything`**

Edit `src/wazuh_mcp/server.py`. After the existing `_run_ar_inner` block + its `mcp_app.tool(...)` registration (ends around line 1298), insert before the `_restart_manager_inner` block (begins line 1300):

```python
    async def _run_ar_on_group_inner(**kwargs: Any) -> Any:
        from wazuh_mcp.tools.write import (
            RunActiveResponseOnGroupArgs,
            run_active_response_on_group as _run_ar_on_group,
        )

        args = RunActiveResponseOnGroupArgs(**kwargs)
        session = current_session()
        _check_write_allowed(session, "write.run_active_response_on_group")
        if ar_group_allowlist_policy is None:
            raise WazuhError(
                "forbidden",
                "agent_group_allowlist not configured for this tenant",
                403,
            )
        ar_group_allowed = list(ar_group_allowlist_policy(session))
        sapi = await server_api_pool.acquire(session.tenant_id)
        return await _run_ar_on_group(
            args=args,
            session=session,
            server_api=sapi,
            ar_group_allowlist=ar_group_allowed,
        )

    from wazuh_mcp.tools.write import RunActiveResponseOnGroupArgs as _AR_OnGroup_Args

    mcp_app.tool(
        name="write.run_active_response_on_group",
        description=_write_desc_prefix
        + "Runs a tenant-allowlisted active-response command on every agent in "
        + "the named group. The group name must be enumerated in the tenant's "
        + "agent_group_allowlist; the command must be enumerated in "
        + "active_response_allowlist (same as write.run_active_response).",
        meta={"toolset": "writes"},
    )(
        instrumented_tool(
            tool_name="write.run_active_response_on_group",
            handler=_run_ar_on_group_inner,
            rbac_policy=rbac_policy,
            limiter=limiter,
            audit=audit_emitter,
            args_model=_AR_OnGroup_Args,
            result_model=WriteResult,
        )
    )
```

Verify the existing import block at the top of `_register_everything`'s body imports `WriteResult`. It does — `tools/write.py:41` defines `WriteResult` and the existing AR registration at `:1295` references `WriteResult`.

Note on the `_AR_OnGroup_Args` aliasing: this avoids a NameError because `args_model=` is evaluated at registration time, not lazily inside `_run_ar_on_group_inner`. Two import statements (one inside the inner, one at registration scope) is the pattern that matches the existing `_run_ar_inner`/`RunActiveResponseArgs` shape — confirm at task time.

Note: `_check_write_allowed` is a closure in `_register_everything` at line 581; it is in scope at the new handler. `current_session` is imported at the top of `server.py`. `WazuhError` is imported at the top of `server.py`.

- [ ] **Step 9: Wire the new resolver factory at both call sites**

Edit `src/wazuh_mcp/server.py`. At line 314 (currently `ar_allowlist_policy = make_ar_allowlist(_registry, audit_emitter)`), add immediately after:

```python
    from wazuh_mcp.rbac.resolver import make_ar_group_allowlist  # M5b T-A2

    ar_group_allowlist_policy = make_ar_group_allowlist(_registry, audit_emitter)
```

At line 324 (`ar_allowlist_policy=ar_allowlist_policy,`), add immediately after:

```python
        ar_group_allowlist_policy=ar_group_allowlist_policy,
```

Repeat at lines 490 and 500 for the second call site. Verify both call sites are still active (M4d/M5a may have refactored).

If the existing `make_ar_allowlist` import at the top of `server.py` already pulls from `wazuh_mcp.rbac.resolver`, extend that import to include `make_ar_group_allowlist` instead of inline-importing inside the function body. Check at task time:

```bash
grep -n "from wazuh_mcp.rbac.resolver import" src/wazuh_mcp/server.py
```

If the existing line is `from wazuh_mcp.rbac.resolver import make_rbac_policy, make_write_allowlist, make_ar_allowlist`, change to add `make_ar_group_allowlist` and drop the inline import.

- [ ] **Step 10: Add unit tests for handler + registration**

Create `tests/unit/test_run_active_response_on_group.py`:

```python
"""M5b T-A2: write.run_active_response_on_group handler tests."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.tools.write import (
    RunActiveResponseOnGroupArgs,
    run_active_response_on_group,
)
from wazuh_mcp.wazuh.errors import WazuhError


def _session(wazuh_user: str | None = "alice") -> Session:
    return Session(
        user_id="u1", tenant_id="t1", rbac_role="admin",
        auth_method="oauth", wazuh_user=wazuh_user,
    )


@pytest.mark.asyncio
async def test_handler_calls_server_api_with_group_name():
    sapi = AsyncMock()
    sapi.run_active_response_on_group.return_value = {
        "data": {"affected_items": ["001", "002"], "failed_items": []}
    }
    args = RunActiveResponseOnGroupArgs(
        group_name="soc-tier1",
        command_name="restart-wazuh",
        custom_args=None,
        confirm=True,
    )
    result = await run_active_response_on_group(
        args=args,
        session=_session(),
        server_api=sapi,
        ar_group_allowlist=["soc-tier1", "soc-tier2"],
    )
    assert result.ok is True
    assert result.affected_agents == ["001", "002"]
    assert result.failed_agents == []
    sapi.run_active_response_on_group.assert_awaited_once_with(
        group_name="soc-tier1",
        command="restart-wazuh",
        custom_args=None,
        run_as="alice",
    )


@pytest.mark.asyncio
async def test_handler_rejects_group_not_in_allowlist():
    sapi = AsyncMock()
    args = RunActiveResponseOnGroupArgs(
        group_name="prod-critical",
        command_name="restart-wazuh",
        custom_args=None,
        confirm=True,
    )
    with pytest.raises(WazuhError) as exc_info:
        await run_active_response_on_group(
            args=args,
            session=_session(),
            server_api=sapi,
            ar_group_allowlist=["soc-tier1"],
        )
    assert exc_info.value.code == "forbidden"
    assert "prod-critical" in exc_info.value.message
    assert "agent_group_allowlist" in exc_info.value.message
    sapi.run_active_response_on_group.assert_not_awaited()


def test_args_rejects_missing_confirm():
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        RunActiveResponseOnGroupArgs(
            group_name="g1",
            command_name="cmd",
            custom_args=None,
            # confirm intentionally missing  # ty: ignore[missing-argument]
        )  # type: ignore[call-arg]
    msg = str(exc_info.value)
    assert "confirm" in msg


def test_args_rejects_confirm_false():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunActiveResponseOnGroupArgs(
            group_name="g1",
            command_name="cmd",
            custom_args=None,
            confirm=False,  # type: ignore[arg-type]
        )
```

Note on `# ty: ignore[missing-argument]`: this is the directive from M4b retro. ty's static check correctly flags the missing `confirm` arg (it's required), but the test deliberately triggers `ValidationError` at runtime.

- [ ] **Step 11: Add registration-shape unit test**

Append to `tests/unit/test_run_active_response_on_group.py`:

```python
@pytest.mark.asyncio
async def test_call_via_fastmcp_emits_forbidden_when_group_not_allowlisted(
    monkeypatch,
):
    """End-to-end through FastMCP: ToolError.__cause__ is WazuhError('forbidden').

    Pattern from M4c retro: FastMCP wraps internal exceptions into ToolError.
    """
    from mcp.shared.exceptions import McpError  # noqa: F401  -- pinning import
    from mcp.server.fastmcp.exceptions import ToolError

    from wazuh_mcp.tenancy.config import TenantConfig
    from wazuh_mcp.tenancy.registry import SingleTenantRegistry

    tenant = TenantConfig(
        tenant_id="t1",
        indexer_url="https://idx:9200",  # type: ignore[arg-type]
        default_rbac_role="admin",
        write_allowlist=None,  # all writes register
        active_response_allowlist=["restart-wazuh"],
        agent_group_allowlist=["soc-tier1"],
    )
    registry = SingleTenantRegistry(tenant)

    # Build a minimal app with the new write registered. Use the helper
    # that other write tests use (see tests/unit/test_write_tools.py
    # for the existing harness; mirror that pattern).
    from tests.unit._write_test_harness import build_test_app  # adapt name to what exists

    mcp_app, _ = build_test_app(registry=registry)

    with pytest.raises(ToolError) as exc_info:
        await mcp_app.call_tool(
            "write.run_active_response_on_group",
            {
                "group_name": "prod-critical",
                "command_name": "restart-wazuh",
                "confirm": True,
            },
        )
    assert isinstance(exc_info.value.__cause__, WazuhError)
    assert exc_info.value.__cause__.code == "forbidden"
```

Note: the helper `build_test_app` may exist under a different name (e.g., `_make_app`, `mcp_app_for_writes`). Grep `tests/unit/test_write_tools.py` at task start to find the existing pattern; adapt the import. If no helper exists, inline the minimal app construction (model after `test_m4c_writes.py` integration setup but stripped to in-memory).

- [ ] **Step 12: Run new tests**

```bash
uv run pytest tests/unit/test_run_active_response_on_group.py tests/unit/test_server_api_writes.py -v
```

Expected: 5 new tests in `test_run_active_response_on_group.py` PASSED + 1 new in `test_server_api_writes.py` PASSED = 6 new PASSED. Total unit count: 525 → 531.

- [ ] **Step 13: Run full unit suite**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -10
```

Expected: 531 PASSED, 4 SKIPPED. No regressions.

- [ ] **Step 14: Lint + type check**

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check src/
```

Expected: all clean.

- [ ] **Step 15: Commit**

```bash
git add src/wazuh_mcp/wazuh/server_api.py src/wazuh_mcp/tools/write.py src/wazuh_mcp/tenancy/m4_config.py src/wazuh_mcp/server.py tests/unit/test_run_active_response_on_group.py tests/unit/test_server_api_writes.py
git commit -m "M5b T-A2: write.run_active_response_on_group tool

Adds the eighth-and-a-half write tool: group-target active-response.
ServerApiClient gains run_active_response_on_group method that builds
agents_list=group:<name>. tools/write.py gains parallel Args + handler
with agent_group_allowlist gate. _register_everything wires the new
resolver factory and registration block.

Two security gates: write_allowlist (registration-time) +
agent_group_allowlist (per-call). active_response_allowlist (the
existing per-command gate) is intentionally NOT consulted on group
calls — operators scope command exposure via per-command allowlist
and group exposure via agent_group_allowlist independently."
```

---

### Task T-A3: Integration test for group-target AR

**Tier:** B.

**Files:**
- Create: `tests/integration/test_m5b_group_ar.py`
- Reference: `tests/integration/test_m4b_writes.py` for `_mcp_session` helper + admin-role fixture pattern
- Reference: `tests/integration/test_m4c_writes.py` for `mcp_http_server_m4c` admin fixture (port 8772)

**Verified call sites:**

```bash
grep -n "mcp_http_server_writes\|mcp_http_server_m4c\|_mcp_session\|requires_manager" tests/integration/test_m4b_writes.py tests/integration/test_m4c_writes.py | head -20
```

Expected:
- `mcp_http_server_writes` fixture at `test_m4b_writes.py` (port 8770, admin role).
- `mcp_http_server_m4c` fixture (port 8772, admin role).
- `_mcp_session(url, token)` async context manager defined at `test_m4b_writes.py:186` (per project_state baseline) — inline in each integration test file rather than imported from conftest.
- `pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]` at module top.

**Steps:**

- [ ] **Step 1: Confirm fixture port + tenant config has admin role + agent_group_allowlist set**

The integration test needs a fixture that:
1. Has `default_rbac_role: admin` (analyst can't call write tools).
2. Has `agent_group_allowlist: ["test-group"]` in `tenants.yaml`.
3. Has `active_response_allowlist: ["restart-wazuh"]` (or whatever AR command we'll fire).

Approach: extend the existing `mcp_http_server_writes` fixture's tenants.yaml, OR create a new `mcp_http_server_m5b` fixture on port 8775 (next free per existing 8765/8770/8772/8773 in use).

Recommended: new fixture `mcp_http_server_m5b` on port 8775. Mirrors `mcp_http_server_writes` shape but adds `agent_group_allowlist: ["test-group"]` to the tenant config.

```bash
# Confirm port allocation at task start.
grep -rn "port=87\|MCP_URL_\|http://localhost:87" tests/integration/conftest.py tests/integration/test_m4*.py | head -20
```

- [ ] **Step 2: Add `mcp_http_server_m5b` fixture to `tests/integration/conftest.py`**

Append to `tests/integration/conftest.py` (modeling on the existing `mcp_http_server_writes` definition — find that and copy its structure):

```python
@pytest.fixture
def mcp_http_server_m5b(tmp_path_factory):
    """M5b T-A3 fixture: admin role + agent_group_allowlist + active_response_allowlist.

    Port 8775. Mirrors mcp_http_server_writes (port 8770) shape but adds
    'test-group' to agent_group_allowlist and 'restart-wazuh' to
    active_response_allowlist so write.run_active_response_on_group calls
    pass both gates.
    """
    cfg_dir = tmp_path_factory.mktemp("m5b-config")
    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
    write_allowlist: null
    active_response_allowlist:
      - restart-wazuh
    agent_group_allowlist:
      - test-group
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
local:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
""".strip()
    )

    # Use the same _spawn_server helper that mcp_http_server_writes uses.
    # Find it by grepping conftest.py for "_spawn_server" — it's the
    # private helper that all admin-role fixtures share.
    yield from _spawn_server(cfg_dir, port=8775)
```

Note: the actual `_spawn_server` helper signature may differ (it may take more kwargs like `oauth_issuer_override`). Match the existing `mcp_http_server_writes` definition exactly when authoring this fixture.

- [ ] **Step 3: Write the integration test**

```python
# tests/integration/test_m5b_group_ar.py
"""M5b T-A3: integration test for write.run_active_response_on_group."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import httpx
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

pytestmark = [pytest.mark.integration, pytest.mark.requires_manager]


@contextlib.asynccontextmanager
async def _mcp_session(url: str, token: str) -> AsyncIterator[ClientSession]:
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def _ensure_test_group_with_agent(
    server_api_base: str = "https://localhost:55000",
) -> None:
    """Create test-group via POST /groups (idempotent) + assign agent 001
    via PUT /agents/001/group/test-group (idempotent).

    Uses wazuh-wui:MCPmcp12345! basic auth → /security/user/authenticate → JWT.
    """
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        # Auth.
        r = await c.post(
            f"{server_api_base}/security/user/authenticate",
            auth=("wazuh-wui", "MCPmcp12345!"),
        )
        r.raise_for_status()
        jwt = r.json()["data"]["token"]

        # Create group (200 OK or 1905 if already exists; both fine).
        await c.post(
            f"{server_api_base}/groups",
            json={"group_id": "test-group"},
            headers={"Authorization": f"Bearer {jwt}"},
        )
        # Assign agent 001 (200 OK or already-assigned both fine).
        await c.put(
            f"{server_api_base}/agents/001/group/test-group",
            headers={"Authorization": f"Bearer {jwt}"},
        )


@pytest.mark.asyncio
async def test_run_active_response_on_group_against_test_group(
    mcp_http_server_m5b, keycloak_token
):
    """End-to-end: fire write.run_active_response_on_group against
    test-group containing agent 001. Wazuh queues the AR command;
    affected_items reflects the agents the command was queued for."""
    await _ensure_test_group_with_agent()

    async with _mcp_session(mcp_http_server_m5b, keycloak_token()) as session:
        result = await session.call_tool(
            "write.run_active_response_on_group",
            {
                "group_name": "test-group",
                "command_name": "restart-wazuh",
                "confirm": True,
            },
        )
        assert not result.isError, f"call errored: {result}"
        # M5a contract reminder (v0.7.2 lesson): use structuredContent
        # for typed-output tools.
        payload = result.structuredContent
        assert payload is not None, "structuredContent missing"
        assert payload["ok"] is True
        # affected_agents may be empty if Wazuh's affected_items is empty
        # in some edge configurations — assert presence of the key only.
        assert "affected_agents" in payload
        assert payload["failed_agents"] == []
```

- [ ] **Step 4: Run integration test (controller-side, only if docker stack is up)**

```bash
# Implementer: DO NOT run integration tests during execution. Controller
# verifies after merge via the nightly workflow.
echo "Integration test ready; controller will verify on next nightly."
```

If running locally with the docker stack already bootstrapped:

```bash
uv run pytest tests/integration/test_m5b_group_ar.py -v
```

Expected: PASSED. If FAILED with `agent_id 001 not found`, the seed_alerts.py step in bootstrap.sh hasn't run or failed silently. Re-run `bash docker/bootstrap.sh`.

- [ ] **Step 5: Lint + type check**

```bash
uv run ruff check tests/integration/test_m5b_group_ar.py tests/integration/conftest.py
uv run ty check tests/
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/test_m5b_group_ar.py tests/integration/conftest.py
git commit -m "M5b T-A3: integration test for write.run_active_response_on_group

Adds mcp_http_server_m5b fixture (port 8775, admin role,
agent_group_allowlist=['test-group'], active_response_allowlist=
['restart-wazuh']) and one @requires_manager integration test that
fires the group-target AR against agent 001 assigned to test-group.

Marked @requires_manager — runs in the amd64 nightly only."
```

---

## Phase 2 — Test infrastructure batch (11 tasks)

**Phase rationale:** Mostly Tier-B mechanical work. T-G4a + T-G4b are Tier-A spot-check (touch OAuth/IssuerIndex composition; M5a T7 invariant-wave lesson applies). All tasks independent; can be batched per-track into single implementer dispatches when sensible (T-B1+T-B2; T-C1+T-C2; T-G2a+T-G2b; T-G4a+T-G4b; T-G5a+T-G5b each a candidate batch — judgment per dispatch budget at execution time).

### Task T-B1: Wazuh version matrix — compose parameterization + workflow matrix

**Tier:** B.

**Files:**
- Modify: `docker/integration-compose.yml` (parameterize image tags)
- Modify: `.github/workflows/integration.yml` (add matrix dim, gate to nightly+manual)
- Modify: `.github/workflows/destructive-integration.yml` (parallel matrix dim)

**Plan-execute research step:** confirm Wazuh's current tag landscape at task start.

```bash
# Run at task start to verify available tags.
docker manifest inspect wazuh/wazuh-manager:4.9.x 2>&1 | head -5
docker manifest inspect wazuh/wazuh-manager:4.12.0 2>&1 | head -5
# OR query Docker Hub API
curl -s 'https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags?page_size=20' | python -m json.tool | grep -E '"name":'
```

Pick:
- LTS pin: latest 4.9.x available (currently 4.9.0 confirmed working).
- Latest pin: highest-numbered 4.x.y or 5.x.y available. Likely 4.12.0 or 4.13.0 as of 2026-05-01. **Defer to task-execute time; do NOT assume.**

**Steps:**

- [ ] **Step 1: Run docker tag query, decide on `WAZUH_LATEST_VERSION` value, document at task top.**

```bash
curl -s 'https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags/?page_size=30' | python -c "
import sys, json
tags = json.load(sys.stdin)['results']
print('\n'.join(t['name'] for t in tags if t['name'].split('.')[0].isdigit()))
"
```

Document the chosen `WAZUH_LATEST_VERSION` in this task's commit message.

- [ ] **Step 2: Parameterize `docker/integration-compose.yml`**

Find every reference to `wazuh/wazuh-manager:4.9` and `wazuh/wazuh-indexer:4.9` (and any agent image). Replace with `${WAZUH_VERSION:-4.9.0}`:

```bash
grep -n "wazuh/wazuh-" docker/integration-compose.yml
```

Edit in place:

```yaml
services:
  wazuh-manager:
    image: wazuh/wazuh-manager:${WAZUH_VERSION:-4.9.0}
  wazuh-indexer:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION:-4.9.0}
```

**Note on version-skew:** Wazuh manager + indexer must match major.minor. The single env var ensures both bump in lockstep. The custom-built `wazuh-agent` image (in `docker/wazuh-agent/Dockerfile`) likely pins to `wazuh-agent.deb` of a fixed version — check at task time whether the agent image needs a parallel `WAZUH_VERSION` build-arg.

- [ ] **Step 3: Add matrix dimension to `.github/workflows/integration.yml`**

Edit the `jobs.integration` block to add `strategy.matrix`:

```yaml
jobs:
  integration:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        wazuh_version:
          - "4.9.0"
          - "<WAZUH_LATEST_VERSION>"  # filled in from Step 1
        # PR-time runs LTS only; nightly + workflow_dispatch run both
        exclude:
          - wazuh_version: "<WAZUH_LATEST_VERSION>"
        include:
          - wazuh_version: "<WAZUH_LATEST_VERSION>"
            run_on_pr: false
    env:
      WAZUH_VERSION: ${{ matrix.wazuh_version }}
    steps:
      # ... existing steps
```

**Reality check:** GitHub Actions matrix `exclude` + `include` with conditional inclusion based on event type is non-trivial. The most reliable pattern is a job-level `if:` clause:

```yaml
jobs:
  integration:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        wazuh_version:
          - "4.9.0"
          - "<WAZUH_LATEST_VERSION>"
    if: |
      github.event_name == 'schedule' ||
      github.event_name == 'workflow_dispatch' ||
      matrix.wazuh_version == '4.9.0'
    env:
      WAZUH_VERSION: ${{ matrix.wazuh_version }}
    # ... existing steps
```

Verify at task time that GH Actions allows `if:` referencing `matrix.*` at job level. If not, alternative:

- Single-version job that runs on every event (LTS).
- Separate matrix-only job that runs on `schedule` and `workflow_dispatch` only.

Pick whichever is less brittle. Document the choice.

- [ ] **Step 4: Mirror matrix in `.github/workflows/destructive-integration.yml`**

Apply the same matrix dimension. Destructive tests run only on schedule + workflow_dispatch (no PR), so the matrix runs both versions every weekly run.

- [ ] **Step 5: Verify both versions pull cleanly locally (if possible)**

```bash
WAZUH_VERSION=4.9.0 docker compose -f docker/integration-compose.yml pull
WAZUH_VERSION=<WAZUH_LATEST_VERSION> docker compose -f docker/integration-compose.yml pull
```

Expected: both succeed. If latest fails to pull, the chosen tag is wrong — re-do Step 1.

- [ ] **Step 6: Commit**

```bash
git add docker/integration-compose.yml .github/workflows/integration.yml .github/workflows/destructive-integration.yml
git commit -m "M5b T-B1: Wazuh version matrix — LTS + latest

Parameterizes docker/integration-compose.yml via WAZUH_VERSION env var
(default 4.9.0). integration.yml + destructive-integration.yml gain
a matrix dimension; PR-time runs LTS only, nightly + manual dispatch
runs both pins.

Latest pin: <WAZUH_LATEST_VERSION> (chosen 2026-05-XX from Docker Hub
tag inventory)."
```

---

### Task T-B2: Validate matrix on first nightly + remediate any wire-shape drift

**Tier:** B.

**Files:** none initially — held in reserve.

**Steps:**

- [ ] **Step 1: After T-B1 lands on main, trigger a manual workflow_dispatch run of `integration.yml`.**

```bash
gh workflow run integration.yml
gh run list --workflow integration.yml --limit 3
```

- [ ] **Step 2: Observe both matrix jobs.**

If both PASS: T-B2 is a no-op. Commit a brief note documenting the matrix-green outcome:

```bash
git commit --allow-empty -m "M5b T-B2: Wazuh matrix CI green on first run

Both 4.9.0 + <WAZUH_LATEST_VERSION> integration jobs pass without
any wire-shape drift fixes needed."
```

- [ ] **Step 3: If latest version's job fails, triage by failure category.**

| Failure | Likely cause | Fix location |
|---|---|---|
| `bootstrap.sh` timeout | OpenSearch flood-stage threshold drift | `docker/bootstrap.sh` (relax watermark per M5a `48b213c` precedent) |
| `upload_rule_file` 415/404 | Wazuh API path drift | `src/wazuh_mcp/wazuh/server_api.py:193` |
| `run_active_response` 405 | Wazuh API verb drift (POST vs PUT) | `src/wazuh_mcp/wazuh/server_api.py:213` |
| `cluster.status` shape change | Wazuh response schema drift | `src/wazuh_mcp/wazuh/server_api.py` `restart_cluster`/`cluster_status` |
| Auth token format change | Keycloak compat | `tests/integration/conftest.py` token fixtures |

Apply minimal-diff fix; re-trigger; iterate until both jobs green.

- [ ] **Step 4: Commit fix(es) with explicit version+failure citation.**

```bash
git commit -m "M5b T-B2: <area> fix for Wazuh <version>

<one-line root cause>. <one-line fix description>."
```

---

### Task T-C1: Multi-manager fixture — compose, conftest fixture, 2 federation tests

**Tier:** B.

**Files:**
- Create: `docker/multi-manager-compose.yml` (extends `integration-compose.yml`)
- Modify: `docker/bootstrap.sh` (parallel-bootstrap second cluster, OR add a flag)
- Modify: `tests/integration/conftest.py` (new `mcp_http_server_multi_manager` fixture)
- Create: `tests/integration/test_multi_manager.py`

**Verified call sites:**

```bash
grep -n "wazuh-manager\|wazuh-indexer\|services:" docker/integration-compose.yml | head -20
grep -n "INDEXER_HOST\|MANAGER_HOST\|wait_for" docker/bootstrap.sh
```

**Steps:**

- [ ] **Step 1: Create `docker/multi-manager-compose.yml`**

```yaml
# docker/multi-manager-compose.yml
# Extends integration-compose.yml with a second Wazuh cluster on
# distinct ports for multi-manager federation tests.
#
# Usage: docker compose -f integration-compose.yml -f multi-manager-compose.yml up
# Markers: only used by tests marked @pytest.mark.multi_manager.

services:
  wazuh-manager-2:
    image: wazuh/wazuh-manager:${WAZUH_VERSION:-4.9.0}
    hostname: wazuh-manager-2
    ports:
      - "55001:55000"
      - "1516:1514"  # auth port (shifted)
      - "1517:1515"  # registration port (shifted)
    environment:
      - INDEXER_URL=https://wazuh-indexer-2:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=admin
    volumes:
      - ./config/wazuh_manager_ossec.conf:/wazuh-config-mount/etc/ossec.conf
    depends_on:
      - wazuh-indexer-2

  wazuh-indexer-2:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION:-4.9.0}
    hostname: wazuh-indexer-2
    ports:
      - "9201:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "DISABLE_INSTALL_DEMO_CONFIG=false"
      # Disk watermark relaxation (M5a 48b213c precedent).
      - "cluster.routing.allocation.disk.threshold_enabled=false"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    cap_add:
      - IPC_LOCK
```

Note: `wazuh-manager-2` reuses the same `ossec.conf` mount as `wazuh-manager`. If the existing config files reference cluster-IDs or fixed master IPs, customize per-instance — verify at task time.

- [ ] **Step 2: Adapt `docker/bootstrap.sh` to bootstrap second cluster**

Two approaches:

A. **Single bootstrap, parallel:** extend `bootstrap.sh` to wait on `wazuh-manager-2`/`wazuh-indexer-2` health if `MULTI_MANAGER=1` env is set.

B. **Separate `multi-manager-bootstrap.sh`:** new script that runs bootstrap.sh + then bootstraps cluster 2.

Pick A for simplicity. Add at end of bootstrap.sh:

```bash
if [ "${MULTI_MANAGER:-0}" = "1" ]; then
  echo "==> Waiting for wazuh-manager-2 + wazuh-indexer-2..."
  # Reuse the same securityadmin retry pattern as the primary indexer.
  for i in 1 2 3 4 5; do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T wazuh-indexer-2 \
        bash -c "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
          -cd /usr/share/wazuh-indexer/opensearch-security \
          -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem \
          -cert /etc/wazuh-indexer/certs/admin.pem \
          -key /etc/wazuh-indexer/certs/admin-key.pem \
          -h localhost"; then
      echo "wazuh-indexer-2 security init OK"
      break
    fi
    echo "wazuh-indexer-2 security init attempt $i failed, retrying..."
    sleep 10
  done

  echo "==> Waiting for wazuh-manager-2 API on port 55000 (mapped 55001)..."
  for i in {1..30}; do
    if curl -k -sf -u wazuh-wui:MCPmcp12345! \
        https://localhost:55001/security/user/authenticate >/dev/null 2>&1; then
      echo "wazuh-manager-2 API ready"
      break
    fi
    sleep 5
  done
fi
```

- [ ] **Step 3: Register `multi_manager` pytest marker**

Edit `pyproject.toml` `[tool.pytest.ini_options]` `markers` list. Append:

```toml
    "multi_manager: requires two distinct Wazuh clusters (multi-manager-integration.yml)",
```

- [ ] **Step 4: Update main `integration.yml` filter**

Modify the test step in `.github/workflows/integration.yml`:

```yaml
      - name: Run integration suite
        run: uv run pytest -m "integration and not destructive and not multi_manager" -v --junitxml=integration-report.xml
```

- [ ] **Step 5: Add `mcp_http_server_multi_manager` fixture**

Append to `tests/integration/conftest.py`:

```python
@pytest.fixture
def mcp_http_server_multi_manager(tmp_path_factory):
    """M5b T-C1. Two-tenant fixture pointing at two physically distinct
    Wazuh clusters (manager-1 + indexer-1 on standard ports; manager-2
    + indexer-2 on shifted ports). Requires multi-manager-compose.yml
    to be up.

    Port 8780.
    """
    cfg_dir = tmp_path_factory.mktemp("m5b-mm-config")
    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: tenant_a
    indexer_url: https://localhost:9200
    server_api_url: https://localhost:55000
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
  - tenant_id: tenant_b
    indexer_url: https://localhost:9201
    server_api_url: https://localhost:55001
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: admin
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
tenant_a:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
tenant_b:
  indexer_user: admin
  indexer_password: admin
  server_api_user: wazuh-wui
  server_api_password: MCPmcp12345!
""".strip()
    )
    yield from _spawn_server(cfg_dir, port=8780)
```

Verify the actual `TenantConfig` field name for the manager API URL — the existing `tenants.yaml` uses `indexer_url` for the indexer; the M3 `ServerApiClientPool` may compose the manager URL from a separate field or derive from indexer_url. Grep at task time:

```bash
grep -n "server_api_url\|manager_url\|server_api" src/wazuh_mcp/tenancy/config.py src/wazuh_mcp/tenancy/m4_config.py
```

If `server_api_url` is not a recognized field on `TenantConfig` (extra="forbid" would reject it), this task introduces the field — add to `TenantConfig` schema as `server_api_url: HttpUrl | None = None` with sensible default-derivation logic (use `indexer_url`'s host with port 55000 by default). Document the schema change in the task body.

- [ ] **Step 6: Write the 2 federation tests**

```python
# tests/integration/test_multi_manager.py
"""M5b T-C1: multi-manager federation tests.

These tests run against two physically distinct Wazuh clusters (cluster
1 on standard ports, cluster 2 on shifted ports). Requires
docker/multi-manager-compose.yml to be up alongside integration-compose.yml.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

pytestmark = [pytest.mark.integration, pytest.mark.multi_manager, pytest.mark.requires_manager]


@contextlib.asynccontextmanager
async def _mcp_session(url: str, token: str) -> AsyncIterator[ClientSession]:
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@pytest.mark.asyncio
async def test_tenant_a_session_only_hits_manager_1(
    mcp_http_server_multi_manager, keycloak_token
):
    """tenant_a session calls agents.list. Verify response shape contains
    cluster-1 agents only. Cross-pollination check: query manager-2
    directly to confirm no tenant_a query traffic landed there.

    Identifying feature: agent 001 should be on cluster 1 (registered
    by docker/seed_alerts.py against the primary manager). Cluster 2's
    agent inventory is empty (no seed_alerts run against it).
    """
    async with _mcp_session(mcp_http_server_multi_manager, keycloak_token()) as session:
        result = await session.call_tool("agents.list", {})
        assert not result.isError, f"call errored: {result}"
        payload = result.structuredContent
        assert payload is not None
        agent_ids = {a.get("id") for a in payload.get("agents", [])}
        assert "001" in agent_ids, (
            f"expected agent 001 on cluster 1; got {agent_ids}"
        )


@pytest.mark.asyncio
async def test_tenant_b_session_only_hits_manager_2(
    mcp_http_server_multi_manager, keycloak_token_tenant_b
):
    """tenant_b session calls agents.list. Verify the response is the
    manager-2 inventory (empty in default fixture; if seed_alerts is
    extended to also seed cluster 2, assert presence of those agents)."""
    async with _mcp_session(mcp_http_server_multi_manager, keycloak_token_tenant_b()) as session:
        result = await session.call_tool("agents.list", {})
        assert not result.isError, f"call errored: {result}"
        payload = result.structuredContent
        assert payload is not None
        agent_ids = {a.get("id") for a in payload.get("agents", [])}
        # Manager 2 has no seeded agents → 'agents' list either empty
        # or contains only the manager-self entry (id=000).
        assert "001" not in agent_ids, (
            f"cross-tenant leak: agent 001 (cluster 1) appeared in tenant_b call: {agent_ids}"
        )
```

- [ ] **Step 7: Commit**

```bash
git add docker/multi-manager-compose.yml docker/bootstrap.sh pyproject.toml .github/workflows/integration.yml tests/integration/conftest.py tests/integration/test_multi_manager.py src/wazuh_mcp/tenancy/config.py
git commit -m "M5b T-C1: multi-manager fixture + 2 federation tests

docker/multi-manager-compose.yml extends integration-compose.yml
with wazuh-manager-2 + wazuh-indexer-2 on shifted ports (55001 +
9201). bootstrap.sh learns MULTI_MANAGER=1 path. New 'multi_manager'
pytest marker; main integration filter now excludes it. New
mcp_http_server_multi_manager fixture (port 8780) + 2 tests pinning
tenant→cluster routing.

If TenantConfig didn't already have server_api_url, this commit also
adds it with HttpUrl|None default-None semantics (None → derive from
indexer_url host)."
```

---

### Task T-C2: Multi-manager workflow

**Tier:** B.

**Files:**
- Create: `.github/workflows/multi-manager-integration.yml`

**Steps:**

- [ ] **Step 1: Create the workflow**

```yaml
# .github/workflows/multi-manager-integration.yml
name: multi-manager-integration

on:
  schedule:
    - cron: "13 6 * * 0"  # weekly Sunday 06:13 UTC
  workflow_dispatch:

concurrency:
  group: multi-manager-${{ github.ref }}
  cancel-in-progress: false

jobs:
  multi-manager:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v6

      - name: Install uv
        uses: astral-sh/setup-uv@v7
        with:
          version: latest

      - name: Set up Python
        run: uv python install 3.12

      - name: Sync deps
        run: uv sync --all-groups

      - name: Bootstrap both Wazuh clusters
        run: bash docker/bootstrap.sh
        env:
          COMPOSE_PROJECT_NAME: wazuh-mcp-mm
          MULTI_MANAGER: "1"
          # Compose-up uses both files when MULTI_MANAGER=1 — verify
          # bootstrap.sh's compose-up command line includes the override.

      - name: Run multi-manager tests
        run: uv run pytest -m "multi_manager" -v --junitxml=mm-report.xml

      - name: Upload JUnit on failure
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: multi-manager-junit
          path: mm-report.xml

      - name: Dump compose logs on failure
        if: failure()
        run: |
          docker compose -p wazuh-mcp-mm \
            -f docker/integration-compose.yml \
            -f docker/multi-manager-compose.yml \
            logs --no-color --tail=500 > mm-compose.log 2>&1 || true

      - name: Upload compose logs
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: mm-compose-log
          path: mm-compose.log
```

- [ ] **Step 2: Verify `bootstrap.sh` honors `MULTI_MANAGER=1` to compose-up both files**

The current `bootstrap.sh` does `docker compose -p $COMPOSE_PROJECT_NAME -f docker/integration-compose.yml up -d`. Modify to:

```bash
COMPOSE_FILES=("-f" "docker/integration-compose.yml")
if [ "${MULTI_MANAGER:-0}" = "1" ]; then
  COMPOSE_FILES+=("-f" "docker/multi-manager-compose.yml")
fi

docker compose -p "${COMPOSE_PROJECT_NAME}" "${COMPOSE_FILES[@]}" up -d --quiet-pull
```

- [ ] **Step 3: Trigger first run via workflow_dispatch and validate**

```bash
gh workflow run multi-manager-integration.yml
gh run list --workflow multi-manager-integration.yml --limit 3
```

If first run fails on bootstrap timing, raise the timeout-minutes or extend bootstrap.sh's wait loops.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/multi-manager-integration.yml docker/bootstrap.sh
git commit -m "M5b T-C2: multi-manager-integration weekly workflow

Mirrors destructive-integration.yml: weekly Sunday 06:13 UTC + manual
dispatch, isolated runner, separate compose-project for fresh
container state. bootstrap.sh now layers multi-manager-compose.yml
when MULTI_MANAGER=1."
```

---

### Task T-D1: Vault container + bootstrap helper + 3 integration tests

**Tier:** B.

**Files:**
- Modify: `docker/integration-compose.yml` (add `vault` service)
- Modify: `pyproject.toml` (register `vault` marker)
- Create: `tests/integration/_vault_bootstrap.py` (httpx-based secret-write helper)
- Create: `tests/integration/test_vault_secret_store.py`
- Create: `docker/vault/README.md`

**Verified call sites:**

```bash
grep -n "VaultSecretStore\|hvac" src/wazuh_mcp/secrets/ tests/unit/ | head -10
```

Expected: `VaultSecretStore` defined at `src/wazuh_mcp/secrets/vault_store.py` (or similar). Constructor signature uses `hvac.Client(url=..., token=...)`. Confirm at task time.

**Steps:**

- [ ] **Step 1: Add `vault` service to `docker/integration-compose.yml`**

Append to the `services:` block:

```yaml
  vault:
    image: hashicorp/vault:1.18
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: test-root-token
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "8200:8200"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8200/v1/sys/health"]
      interval: 5s
      retries: 12
      start_period: 5s
```

Note: `hashicorp/vault:1.18` is the dev-mode image. The KV v2 engine is mounted at `secret/` by default in dev mode. No additional mount step needed.

- [ ] **Step 2: Register `vault` marker in `pyproject.toml`**

Append to `markers` list:

```toml
    "vault: requires Vault container in integration-compose.yml",
```

- [ ] **Step 3: Create `tests/integration/_vault_bootstrap.py`**

```python
"""M5b T-D1. Vault test-fixture bootstrap helper.

Writes a secret via Vault HTTP API. Used by test_vault_secret_store.py
and any future fixture that needs a pre-seeded Vault.
"""

from __future__ import annotations

import asyncio

import httpx

VAULT_URL = "http://localhost:8200"
VAULT_TOKEN = "test-root-token"


async def wait_until_vault_ready(timeout_s: float = 30.0) -> None:
    """Poll Vault healthcheck until 200 (or 429 sealed-but-up)."""
    deadline = asyncio.get_event_loop().time() + timeout_s
    last_exc: Exception | None = None
    async with httpx.AsyncClient() as c:
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await c.get(f"{VAULT_URL}/v1/sys/health", timeout=3.0)
                if r.status_code in (200, 429):
                    return
            except httpx.HTTPError as e:
                last_exc = e
            await asyncio.sleep(0.5)
    raise RuntimeError(
        f"vault not ready after {timeout_s}s: {last_exc}"
    )


async def write_secret(path: str, data: dict[str, str]) -> None:
    """Write to KV v2 at secret/data/<path>. Idempotent (overwrite)."""
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{VAULT_URL}/v1/secret/data/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
            json={"data": data},
            timeout=5.0,
        )
        r.raise_for_status()


async def delete_secret(path: str) -> None:
    """Soft-delete (KV v2). Used for cleanup in test teardown."""
    async with httpx.AsyncClient() as c:
        await c.delete(
            f"{VAULT_URL}/v1/secret/data/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=5.0,
        )
```

- [ ] **Step 4: Create `tests/integration/test_vault_secret_store.py`**

```python
"""M5b T-D1. Real-Vault driver integration tests.

Replaces the unit-only hvac.Client mocks. Run against the vault
container in docker/integration-compose.yml (port 8200).

Marked @pytest.mark.vault so the test collection key parameter selects
into main nightly runs (vault container is small + cheap).
"""

from __future__ import annotations

import asyncio

import pytest

from tests.integration._vault_bootstrap import (
    VAULT_TOKEN,
    VAULT_URL,
    wait_until_vault_ready,
    write_secret,
)
from wazuh_mcp.secrets.vault_store import VaultSecretStore  # confirm import path at task time

pytestmark = [pytest.mark.integration, pytest.mark.vault]


@pytest.fixture(scope="module", autouse=True)
async def _vault_ready():
    await wait_until_vault_ready()


@pytest.mark.asyncio
async def test_get_existing_secret_round_trips_through_vault():
    await write_secret(
        "wazuh-mcp/oauth_client_secret",
        {"value": "round-trip-secret-value"},
    )
    store = VaultSecretStore(
        url=VAULT_URL,
        token=VAULT_TOKEN,
        mount_point="secret",
        prefix="wazuh-mcp",
    )
    secret = await store.get("oauth_client_secret")
    assert secret.expose() == "round-trip-secret-value"
    # SecretValue redaction contract.
    assert "round-trip-secret-value" not in repr(secret)


@pytest.mark.asyncio
async def test_get_missing_secret_raises_keyerror():
    store = VaultSecretStore(
        url=VAULT_URL,
        token=VAULT_TOKEN,
        mount_point="secret",
        prefix="wazuh-mcp",
    )
    with pytest.raises(KeyError):
        await store.get("definitely-does-not-exist")


@pytest.mark.asyncio
async def test_token_renewal_refreshes_lease():
    """Vault dev-mode root token doesn't expire; this test proves the
    SDK's renewal call doesn't fail. For real periodic-token tests the
    Vault container would need a non-dev config — out of scope for v1.0.0."""
    store = VaultSecretStore(
        url=VAULT_URL,
        token=VAULT_TOKEN,
        mount_point="secret",
        prefix="wazuh-mcp",
    )
    # Trigger any internal renewal path the store exposes (varies by
    # implementation; hvac's auth.token.renew_self() is the typical
    # one). If VaultSecretStore exposes no renewal method, this test
    # devolves to "two sequential gets succeed" — still useful coverage.
    await write_secret("wazuh-mcp/renewal_canary", {"value": "v1"})
    s1 = await store.get("renewal_canary")
    assert s1.expose() == "v1"

    await asyncio.sleep(0.1)
    s2 = await store.get("renewal_canary")
    assert s2.expose() == "v1"
```

Note: confirm `VaultSecretStore` constructor signature at task time. The current unit tests at `tests/unit/test_vault_store.py` (or similar) document the actual kwargs. If `mount_point` or `prefix` are different names, adapt.

- [ ] **Step 5: Add `docker/vault/README.md`**

```markdown
# Vault dev-mode container

`hashicorp/vault:1.18` runs in dev mode for integration tests.
Root token: `test-root-token`. KV v2 engine mounted at `secret/`.

**Do not use this configuration in production** — dev mode disables
sealing, runs in-memory, and uses a fixed root token.

The `tests/integration/test_vault_secret_store.py` suite writes
secrets at `secret/data/wazuh-mcp/<key>` and reads them through
`VaultSecretStore`.
```

- [ ] **Step 6: Run new tests against the docker stack**

```bash
docker compose -f docker/integration-compose.yml up -d vault
sleep 5
uv run pytest tests/integration/test_vault_secret_store.py -v
```

Expected: 3 PASSED. If FAIL with "connection refused", vault container needs more time — extend `wait_until_vault_ready` timeout.

- [ ] **Step 7: Commit**

```bash
git add docker/integration-compose.yml docker/vault/ pyproject.toml tests/integration/_vault_bootstrap.py tests/integration/test_vault_secret_store.py
git commit -m "M5b T-D1: real Vault container + 3 driver round-trip tests

docker/integration-compose.yml gains a vault service (HashiCorp
Vault 1.18 OSS dev mode, port 8200, root token 'test-root-token',
KV v2 at secret/). New 'vault' pytest marker.
tests/integration/test_vault_secret_store.py replaces the unit-only
hvac.Client mock coverage with three end-to-end tests: get-existing,
get-missing-raises-KeyError, token-renewal canary."
```

---

### Task T-G2a: Always-upload integration log artifacts

**Tier:** B.

**Files:**
- Modify: `.github/workflows/integration.yml` (drop `if: failure()` from log upload steps; widen artifact contents)

**Steps:**

- [ ] **Step 1: Modify `.github/workflows/integration.yml`**

Change the artifact-upload steps to always run. Current:

```yaml
      - name: Upload JUnit on failure
        if: failure()
        uses: actions/upload-artifact@v7
        ...
      - name: Dump compose logs on failure
        if: failure()
        run: ...
      - name: Upload compose logs
        if: failure()
        uses: actions/upload-artifact@v7
        ...
```

New:

```yaml
      - name: Always-dump compose logs
        if: always()
        run: |
          mkdir -p integration-logs
          docker compose -p wazuh-mcp-ci -f docker/integration-compose.yml ps -a > integration-logs/compose-ps.log 2>&1 || true
          docker compose -p wazuh-mcp-ci -f docker/integration-compose.yml logs --no-color --tail=2000 > integration-logs/compose.log 2>&1 || true
          # Per-container logs for fine-grained scanning
          for svc in wazuh-manager wazuh-indexer keycloak vault wazuh-agent; do
            docker compose -p wazuh-mcp-ci -f docker/integration-compose.yml logs --no-color "$svc" > "integration-logs/${svc}.log" 2>&1 || true
          done

      - name: Always-upload integration logs
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: integration-logs-${{ matrix.wazuh_version || 'default' }}
          path: integration-logs/
          retention-days: 7

      - name: Always-upload JUnit
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: integration-junit-${{ matrix.wazuh_version || 'default' }}
          path: integration-report.xml
          if-no-files-found: ignore
```

The artifact name includes the matrix dimension so multi-job runs don't collide.

- [ ] **Step 2: Mirror the change in `.github/workflows/destructive-integration.yml` and `multi-manager-integration.yml`**

Same pattern — `if: always()` + matrix-aware artifact name.

- [ ] **Step 3: Verify by triggering manual run + downloading artifact**

```bash
gh workflow run integration.yml
sleep 60
gh run list --workflow integration.yml --limit 1
gh run download <run-id> --name integration-logs-4.9.0
ls -la
```

Expected: directory contains `compose.log`, `compose-ps.log`, `wazuh-manager.log`, `wazuh-indexer.log`, etc.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/integration.yml .github/workflows/destructive-integration.yml .github/workflows/multi-manager-integration.yml
git commit -m "M5b T-G2a: always-upload integration log artifacts

Drops 'if: failure()' from artifact uploads so green runs also produce
log artifacts. Per-container logs split for downstream secret-scanning
(T-G2b chained workflow). Artifact name includes matrix dimension to
avoid collisions on multi-job nightly runs."
```

---

### Task T-G2b: Integration log secret-scan workflow

**Tier:** B.

**Files:**
- Create: `.github/workflows/integration-log-scan.yml`

**Steps:**

- [ ] **Step 1: Create the workflow**

```yaml
# .github/workflows/integration-log-scan.yml
name: integration-log-scan

on:
  workflow_run:
    workflows: ["integration", "destructive-integration", "multi-manager-integration"]
    types: [completed]

permissions:
  actions: read       # to download artifacts
  contents: read
  security-events: write  # for SARIF upload to Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v6

      - name: Download all integration log artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts/
          pattern: 'integration-logs-*'
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: List downloaded artifacts
        run: |
          find artifacts/ -type f -name '*.log' | head -50

      - name: Run gitleaks against logs
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
        env:
          GITLEAKS_NOTIFY_USER_LIST: ""  # no per-leak email
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "true"
          GITLEAKS_ENABLE_COMMENTS: "false"  # avoid PR comment noise
          # The gitleaks-action default scans the repo working tree;
          # override to scan the artifacts/ directory.
          # Pass --source via custom args:
          GITLEAKS_ENABLE_SUMMARY: "true"
        continue-on-error: false  # fail the workflow on hit
```

Note: the `gitleaks/gitleaks-action@v2` action defaults to scanning the repo working tree (current commit). It does NOT natively support scanning an arbitrary directory like `artifacts/`. Two adaptation paths:

A. **Use `zricethezav/gitleaks` raw binary** instead of the action wrapper:

```yaml
      - name: Install gitleaks
        run: |
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xzf - -C /tmp
          sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
          gitleaks version

      - name: Scan log artifacts
        run: |
          gitleaks detect \
            --source artifacts/ \
            --config .gitleaks.toml \
            --redact \
            --report-format sarif \
            --report-path gitleaks-logs.sarif \
            --no-git \
            --verbose
        continue-on-error: false

      - name: Upload SARIF to GH Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks-logs.sarif
          category: integration-log-scan
```

Pick path A (raw binary) — more control, doesn't depend on action's `--source` support.

- [ ] **Step 2: Trigger by re-running an integration workflow**

```bash
gh workflow run integration.yml
sleep 90
# integration-log-scan should auto-trigger after integration completes
gh run list --workflow integration-log-scan.yml --limit 3
```

Expected: scan workflow runs, downloads artifacts, scans, exits 0 (no leaks). If FAIL, inspect the SARIF for what leaked.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/integration-log-scan.yml
git commit -m "M5b T-G2b: chained integration log secret-scan

Triggers on workflow_run completion of integration / destructive /
multi-manager workflows. Downloads the integration-logs-* artifacts,
runs gitleaks (raw binary, with --no-git --source artifacts/) using
.gitleaks.toml from the M5a security CI. SARIF uploaded to GH Security
tab. Fails on hit."
```

---

### Task T-G4a: Phantom-token plumbing — side-car JWKS server fixture

**Tier:** A (spot-check).

**Files:**
- Create: `tests/integration/_jwks_sidecar.py` (in-process JWKS HTTP server + key generator)
- Modify: `tests/integration/conftest.py` (replace `pytest.skip()` body of `hand_minted_phantom_token` fixture)
- Modify: `tests/integration/conftest.py` audit-sinks fixture's `tenants.yaml` to trust the side-car JWKS issuer

**Plan-author deviation from spec §7.4:** Spec listed Path A (Keycloak admin claim-injection) and Path B (Keycloak admin REST realm-key fetch + joserfc sign). Plan-time investigation reveals:

- The existing `hand_minted_phantom_token` fixture comment at `conftest.py:413-433` explicitly states "Keycloak doesn't expose [the realm private key]" — invalidating Path B.
- Keycloak's standard token endpoint refuses to mint tokens with `tenant_id` claim values for tenants not registered in any client mapper — invalidating Path A.

**Resolved approach: Path C — side-car JWKS HTTP server.** A small in-process HTTP server (started by the fixture, runs on a free port) exposes a JWKS endpoint with a test public key. The fixture also wires the matching private key for signing. The `mcp_http_server_audit_sinks` fixture's `tenants.yaml` adds an extra tenant pointing at the side-car JWKS issuer URL. The fixture mints a JWT signed by the test private key with `tenant_id="phantom"` (a value not matching any tenant in the registry → resolver-miss path).

This requires the Wazuh-MCP server to support multiple OIDC issuers (one per tenant). Verify at task start:

```bash
grep -n "oauth_issuer\|jwks_uri\|IssuerIndex" src/wazuh_mcp/auth/ src/wazuh_mcp/tenancy/
```

If the server already accepts multiple issuers via `IssuerIndex` (it does per project_state — `IssuerIndex` collapses shared issuers via M5a's a7a1f45 fix), the side-car issuer just needs to be a distinct URL not matching Keycloak's realm URL.

**Steps:**

- [ ] **Step 1: Write the side-car JWKS module**

```python
# tests/integration/_jwks_sidecar.py
"""M5b T-G4a. In-process JWKS HTTP server + key-pair generator.

Used by the hand_minted_phantom_token fixture to mint JWTs signed
by a test private key whose public key is served at a side-car JWKS
endpoint. The wazuh-mcp server is configured to trust the side-car's
issuer URL via an extra tenant in the tenants.yaml audit-sinks
fixture (mcp_http_server_audit_sinks).

Plan-author deviation from M5b spec §7.4: Path C (side-car JWKS) was
adopted instead of Path A (Keycloak admin claim-injection) or Path B
(Keycloak admin REST private-key fetch). Path A doesn't support
arbitrary tenant_id claims; Path B doesn't work because Keycloak does
not expose realm signing private keys via admin API.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from joserfc import jwt
from joserfc.jwk import RSAKey
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

# Module-level key cache so the test session reuses one key pair.
_KEY: RSAKey | None = None


def _key() -> RSAKey:
    global _KEY
    if _KEY is None:
        _KEY = RSAKey.generate_key(2048, parameters={"kid": "wazuh-mcp-phantom-test"})
    return _KEY


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_app(issuer: str) -> Starlette:
    async def jwks(_request: Any) -> JSONResponse:
        pub = _key().as_dict(private=False)
        return JSONResponse({"keys": [pub]})

    async def discovery(_request: Any) -> JSONResponse:
        # OIDC discovery doc — minimal subset wazuh-mcp needs to fetch JWKS.
        return JSONResponse(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
            }
        )

    return Starlette(
        routes=[
            Route("/.well-known/openid-configuration", discovery),
            Route("/.well-known/jwks.json", jwks),
        ]
    )


@contextlib.asynccontextmanager
async def jwks_sidecar() -> AsyncIterator[str]:
    """Yields the issuer URL. Server runs on a free localhost port for
    the fixture's lifetime."""
    port = _free_port()
    issuer = f"http://127.0.0.1:{port}"
    app = _build_app(issuer)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    # Wait for startup.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if server.started:
            break
        await asyncio.sleep(0.05)
    try:
        yield issuer
    finally:
        server.should_exit = True
        await task


def mint_phantom_token(
    *,
    issuer: str,
    audience: str,
    tenant_id: str = "phantom",
    sub: str = "phantom-user",
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a JWT signed by the side-car private key.

    Default claims target the M4c resolver-miss path: tenant_id is set
    to a value NOT in tenants.yaml, so IssuerIndex / OAuthSessionFactory
    routes the request, but the per-tenant resolver KeyError fires."""
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "tenant_id": tenant_id,
        "rbac_role": "admin",
        "wazuh_user": "phantom-svc",
        "iat": now,
        "exp": now + 300,
    }
    if extra_claims:
        claims.update(extra_claims)
    header = {"alg": "RS256", "kid": "wazuh-mcp-phantom-test"}
    return jwt.encode(header, claims, _key())
```

- [ ] **Step 2: Update `tests/integration/conftest.py` `hand_minted_phantom_token` fixture**

Replace the body (currently `pytest.skip(...)`) with:

```python
@pytest_asyncio.fixture
async def hand_minted_phantom_token() -> AsyncIterator[str]:
    """M5b T-G4a (was M5a deferred). Mints a JWT signed by a side-car
    JWKS test key, claiming tenant_id='phantom' (not in tenants.yaml).

    The mcp_http_server_audit_sinks fixture trusts the side-car's
    issuer URL via an extra tenant entry in its tenants.yaml.
    """
    from tests.integration._jwks_sidecar import jwks_sidecar, mint_phantom_token

    async with jwks_sidecar() as issuer:
        token = mint_phantom_token(
            issuer=issuer,
            audience="wazuh-mcp-api",
            tenant_id="phantom",
        )
        yield token
```

Note: `pytest_asyncio` import is already present in conftest if other async fixtures exist; verify and add `import pytest_asyncio` if absent.

- [ ] **Step 3: Update the audit-sinks fixture's `tenants.yaml` to register the side-car issuer**

The `mcp_http_server_audit_sinks` fixture (in conftest.py) writes a `tenants.yaml`. Find it and add a third tenant entry that uses the side-car issuer URL. **Problem:** the side-car issuer URL has a port chosen at fixture-runtime; the audit-sinks fixture's tenants.yaml is written before the side-car starts.

**Resolution:** the side-car must start BEFORE the audit-sinks fixture writes tenants.yaml. The audit-sinks fixture should depend on `hand_minted_phantom_token` (or at least on a `_jwks_sidecar_issuer` lower-level fixture). Restructure:

```python
# tests/integration/conftest.py
@pytest_asyncio.fixture
async def jwks_sidecar_issuer() -> AsyncIterator[str]:
    """Lower-level fixture that exposes only the issuer URL.
    Used by both hand_minted_phantom_token and mcp_http_server_audit_sinks
    so they share the same side-car instance."""
    from tests.integration._jwks_sidecar import jwks_sidecar

    async with jwks_sidecar() as issuer:
        yield issuer


@pytest_asyncio.fixture
async def hand_minted_phantom_token(jwks_sidecar_issuer: str) -> str:
    from tests.integration._jwks_sidecar import mint_phantom_token

    return mint_phantom_token(
        issuer=jwks_sidecar_issuer,
        audience="wazuh-mcp-api",
        tenant_id="phantom",
    )


# Update mcp_http_server_audit_sinks to take jwks_sidecar_issuer kwarg
# and add to its tenants.yaml a 'phantom-tenant' entry that points
# oauth_issuer at jwks_sidecar_issuer. The 'phantom-tenant' is REGISTERED
# but the phantom token's tenant_id claim is 'phantom' (different) — so
# the resolver-miss path fires, NOT the trusted-issuer-but-known-tenant path.
```

- [ ] **Step 4: Run the tests that depend on the fixture (locally)**

```bash
uv run pytest tests/integration/test_m4d_multi_tenant.py::test_unknown_tenant_token_routes_to_globals_only -v -m "integration"
```

Expected: PASSED (was previously SKIPPED via fixture's `pytest.skip` call).

- [ ] **Step 5: Lint + ty check**

```bash
uv run ruff check tests/integration/_jwks_sidecar.py tests/integration/conftest.py
uv run ty check tests/integration/_jwks_sidecar.py
```

Expected: clean. The `joserfc` import path may require `# ty: ignore[unresolved-attribute]` per the M4a native-extension pattern — apply if needed.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/_jwks_sidecar.py tests/integration/conftest.py
git commit -m "M5b T-G4a: side-car JWKS server for hand_minted_phantom_token

Replaces the pytest.skip() body of hand_minted_phantom_token with a
real implementation: in-process Starlette+uvicorn server exposes a
JWKS endpoint serving a test RS256 public key on a free port. The
matching private key signs JWTs claiming tenant_id='phantom'
(unregistered, hits the M4c resolver-miss path).

Spec §7.4 listed Path A (Keycloak admin claim-injection) and Path B
(Keycloak admin REST realm-key fetch). Path C (side-car JWKS) chosen
during plan-execute investigation: Path A doesn't support arbitrary
tenant_id claims; Path B doesn't work because Keycloak doesn't expose
realm signing private keys via admin API.

The mcp_http_server_audit_sinks fixture now trusts the side-car
issuer (third tenant in its tenants.yaml). Resolver-miss path fires
because the token's tenant_id claim ('phantom') doesn't match any
registered tenant_id."
```

---

### Task T-G4b: Verify un-skip behavior of `test_unknown_tenant_token_routes_to_globals_only`

**Tier:** A (spot-check — touches OAuth/IssuerIndex composition).

**Files:**
- Modify: `tests/integration/test_m4d_multi_tenant.py:166-203` (verify test runs cleanly with the new fixture; possibly tighten assertions)

**Cross-subsystem invariant grep (M5a T7 lesson):**

```bash
grep -rn "IssuerIndex\|get_by_tenant_id\|_build_session\|_pick_wazuh_user\|iss_tenant_cfg" src/wazuh_mcp/ tests/
```

Expected baseline at HEAD `07f5876` (per M5a a7a1f45 fix):
- `IssuerIndex.get_by_tenant_id` at `tenancy/issuer_index.py:63` (parallel-lookup helper).
- `OAuthSessionFactory._build_session` at `auth/oauth.py:110-149` uses `tenant_cfg = self._index.get_by_tenant_id(tenant_id) or iss_tenant_cfg` (line 136) for both `default_rbac_role` fallback (line 142) and `_pick_wazuh_user(claims, tenant_cfg)` (line 145).
- `_pick_wazuh_user(self, claims, iss_tenant_cfg)` at `auth/oauth.py:155` — note: param name is `iss_tenant_cfg` despite M5a fix passing the resolved `tenant_cfg`. **Cosmetic naming inconsistency from a7a1f45**; do not refactor in this task (orthogonal cleanup).

**Steps:**

- [ ] **Step 1: Run the un-skipped test against the docker stack**

```bash
uv run pytest tests/integration/test_m4d_multi_tenant.py::test_unknown_tenant_token_routes_to_globals_only -v -m "integration"
```

Expected: PASSED. The test fires a tool call, gets `r.isError == True` (resolver-miss → forbidden), and confirms no audit event landed in `local-audit-*` or `tenant-b-audit-*` indices (audit must have routed to globals = stderr only).

- [ ] **Step 2: If FAILED, triage by failure category**

| Failure | Likely cause | Fix |
|---|---|---|
| `r.isError == False` | Phantom token unexpectedly accepted | Side-car issuer not in trusted set; check audit-sinks fixture's tenants.yaml has the side-car issuer registered |
| Indexer query returns hits with `tenant=phantom` | Audit event leaked to per-tenant sink | Resolver-miss audit shape regression — check `make_rbac_policy` audit emit (`rbac/resolver.py:34-43`) keeps `outcome="error"` |
| `httpx.ConnectError: side-car at 127.0.0.1:<port>` | Server didn't start in time | Bump `jwks_sidecar` startup-wait deadline from 5.0s |
| OAuth-stack rejects token at JWKS validation | JWKS endpoint shape doesn't match what server fetches | Inspect `JwksCache.fetch` for required JWKS doc fields; ensure side-car's `/jwks.json` returns `{keys: [...]}` |

- [ ] **Step 3: After test passes, optionally tighten assertions**

The current test's assertions are at `test_m4d_multi_tenant.py:194-203`. Tighten if useful: assert resolver-miss audit landed on `<global>` sink (stderr-captured by pytest's `caplog` if the audit emitter is wired through stdlib logging).

- [ ] **Step 4: Commit (may be empty/no-op if test passes as-is)**

If no test edits were needed:

```bash
git commit --allow-empty -m "M5b T-G4b: phantom-token integration test passes

test_unknown_tenant_token_routes_to_globals_only un-skipped via
T-G4a's side-car JWKS fixture. Verified: resolver-miss audit lands on
global stderr sink only; no leak to local-audit-* or tenant-b-audit-*
per-tenant sinks."
```

If assertions tightened or test modified:

```bash
git add tests/integration/test_m4d_multi_tenant.py
git commit -m "M5b T-G4b: tighten resolver-miss audit-leak assertions

After T-G4a un-skipped this test, assertion scope tightened to also
verify <rbac.resolve> sentinel audit shape via stderr capture."
```

---

### Task T-G5a: Audit-routing investigation spike

**Tier:** B (investigation; T-G5b's tier depends on root cause).

**Files:** none (investigation only); produces a finding written into T-G5b's commit message.

**Steps:**

- [ ] **Step 1: Re-run the skipped test locally with the docker stack up**

Temporarily comment-out the `pytest.skip(...)` call at `tests/integration/test_m4d_multi_tenant.py:106-110` and run:

```bash
uv run pytest tests/integration/test_m4d_multi_tenant.py::test_per_tenant_audit_routing -v -s
```

Capture full output to a scratch file. Look for:

- Test gets to the `await asyncio.sleep(5.0)` step (passes the tool call).
- Indexer query returns 0 hits in `tenant-b-audit-*`.
- Indexer query returns 0 hits in `local-audit-*`.

- [ ] **Step 2: Check QueuedSink flush state**

Add a temporary print/log statement to confirm the `QueuedSink` for tenant_b has actually drained:

```python
# Temporarily inside the test, after the sleep:
audit_emitter = ...  # if accessible via fixture; otherwise skip this hypothesis
print("queue depth:", audit_emitter._sinks_for_tenant("tenant_b")[0].queue.qsize())
```

If queue is non-empty → flush bug.
If queue is empty but indexer has no hits → indexer-write or index-naming bug.

- [ ] **Step 3: Check indexer directly for ANY tenant-b indices**

```bash
curl -k -u admin:admin "https://localhost:9200/_cat/indices?v" | grep tenant-b
```

If no `tenant-b-audit-*` indices exist → index template or first-write naming issue.

- [ ] **Step 4: Check IndexerClient bulk API call success**

Temporarily add logging to `WazuhIndexerSink._send_with_retry` (or use the integration-log-scan logs from T-G2a) to confirm the bulk POST got 2xx and the response body's `errors: false`.

- [ ] **Step 5: Document root cause in `docs/superpowers/notes/2026-05-XX-audit-routing-spike.md`**

```markdown
# M5b T-G5a: audit-routing investigation findings

## Test: test_per_tenant_audit_routing

## Root cause (one of):

[ ] H1: QueuedSink flush not draining before test queries indexer
[ ] H2: WazuhIndexerSink writing under wrong auth (admin missing tenant-b index permission)
[ ] H3: First-write index template not registered before bulk POST
[ ] H4: Index name mismatch between expected and actual

## Evidence

(paste relevant log excerpts / curl outputs / queue depth values)

## Fix scope (T-G5b)

(one-paragraph description of what T-G5b will change)
```

- [ ] **Step 6: Commit the spike note**

```bash
git add docs/superpowers/notes/2026-05-XX-audit-routing-spike.md
git commit -m "M5b T-G5a: audit-routing investigation spike

Root cause: <H1|H2|H3|H4>.
Fix scope: see notes/2026-05-XX-audit-routing-spike.md."
```

---

### Task T-G5b: Audit-routing fix (tier per T-G5a finding)

**Tier:** B if test-infra fix; A spot-check if QueuedSink lifecycle bug.

**Files:** depends on root cause from T-G5a.

**Steps:**

Per the root-cause hypothesis from T-G5a, apply the minimal-diff fix:

| Hypothesis | Likely fix location | Fix shape |
|---|---|---|
| H1 (QueuedSink flush) | `tests/integration/conftest.py` audit-sinks fixture | Add explicit `await audit_emitter.flush()` to fixture teardown OR raise per-test flush method on `MultiSinkAuditEmitter` |
| H2 (auth) | `tests/integration/conftest.py` audit-sinks fixture's `secrets.yaml` for tenant_b | Make sure tenant_b indexer creds map to a role with `tenant-b-audit-*` index write permission |
| H3 (template) | `src/wazuh_mcp/observability/audit_indexer_sink.py` `start()` method | Ensure `put_index_template` runs before first emit (check ordering in `MultiSinkAuditEmitter.start`) |
| H4 (naming) | `tests/integration/conftest.py` audit-sinks fixture's `tenants.yaml` `audit_sinks.index_prefix` | Reconcile expected name in test query vs. actual prefix in fixture |

- [ ] **Step 1: Apply fix per T-G5a finding.**

- [ ] **Step 2: Un-skip the test in `tests/integration/test_m4d_multi_tenant.py:106-110`**

```python
# Remove the pytest.skip(...) call entirely.
@pytest.mark.asyncio
async def test_per_tenant_audit_routing(...):
    """tenant_b session's audit events land in tenant-b-audit-*, NOT
    local-audit-*."""
    # docstring updated to remove the M5b carry-forward note
    import asyncio
    # ... rest of test body
```

- [ ] **Step 3: Run test, verify pass**

```bash
uv run pytest tests/integration/test_m4d_multi_tenant.py::test_per_tenant_audit_routing -v -m "integration"
```

Expected: PASSED.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_m4d_multi_tenant.py <fix-files>
git commit -m "M5b T-G5b: fix audit-routing per T-G5a finding (<H1|H2|H3|H4>)

<one-paragraph fix description>.

test_per_tenant_audit_routing un-skipped — was a M5a carry-forward
deferred at commit 3e628e3."
```

---

## Phase 3 — `WazuhError.scope` field (1 task; Tier-A spot-check)

### Task T-G1: `WazuhError.scope` additive field + raise-site updates + metrics consumer

**Tier:** A (spot-check). Cross-cutting field — touches every error-emitting site. Plan-time grep + manual enumeration suffice; full review only if grep surfaces a structural concern.

**Files:**
- Modify: `src/wazuh_mcp/wazuh/errors.py` (add `scope` to `__slots__` + `__init__` kwarg + `__repr__`)
- Modify: `src/wazuh_mcp/rate_limit/limiter.py` (set `scope="rate_limit:tenant"` and `scope="rate_limit:session"`)
- Modify: `src/wazuh_mcp/rbac/resolver.py` (set `scope="rbac:tenant_not_registered"` if applicable; resolver currently emits audit but doesn't raise — verify if it raises elsewhere)
- Modify: `src/wazuh_mcp/server.py` (`_check_write_allowed` raise → `scope="write_allowlist"`; `_run_ar_inner` no-allowlist raise → `scope="ar_allowlist"`; T-A2's `_run_ar_on_group_inner` already sets `scope="ar_group_allowlist"` if T-A2 was authored to use the new kwarg — verify ordering)
- Modify: `src/wazuh_mcp/tools/write.py` AR-allowlist deny in `run_active_response` (line 281): set `scope="ar_allowlist"`
- Modify: `src/wazuh_mcp/observability/metrics.py` (consume `error.scope` directly; remove substring-match)
- Test: `tests/unit/test_wazuh_error_scope.py` (new)
- Test: existing rate-limit + RBAC + write-allowlist error tests (update assertions to check `.scope`)

**Verified call sites (plan-time grep results, baseline at HEAD `07f5876`):**

```bash
# Run at task start — every WazuhError raise site.
grep -rn "WazuhError(" src/ tests/ | grep -v "test_wazuh_error" | head -50
grep -rn "rate_limit:\|\"rate_limit\"" src/wazuh_mcp/observability/ src/wazuh_mcp/rate_limit/
grep -rn "\.scope\b" src/wazuh_mcp/  # confirm no attribute-name collision
```

Baseline raise sites at HEAD `07f5876` (verify):

| File:line | Code | Current | Set scope to |
|---|---|---|---|
| `wazuh/errors.py:31` | `raise WazuhError("auth_expired", ...)` | `map_http_error` 401 path | `None` (passthrough) |
| `wazuh/errors.py:33` | `raise WazuhError("forbidden", ...)` | `map_http_error` 403 path | `None` (passthrough) |
| `wazuh/errors.py:35` | `raise WazuhError("not_found", ...)` | `map_http_error` 404 path | `None` (passthrough) |
| `wazuh/errors.py:37` | `raise WazuhError("rate_limited", ...)` | `map_http_error` 429 path (upstream) | `"upstream:rate_limited"` |
| `wazuh/errors.py:40` | `raise WazuhError("invalid_query", ...)` | `map_http_error` 400 path | `None` |
| `wazuh/errors.py:43` | `raise WazuhError("upstream_error", ...)` | `map_http_error` default | `None` |
| `wazuh/errors.py:50` | `raise WazuhError("upstream_timeout", ...)` | `map_timeout` | `None` |
| `rate_limit/limiter.py:?` | `raise WazuhError("rate_limited", ...)` | tenant-budget exhaustion | `"rate_limit:tenant"` |
| `rate_limit/limiter.py:?` | `raise WazuhError("rate_limited", ...)` | session-budget exhaustion | `"rate_limit:session"` |
| `server.py:589-594` | `raise WazuhError("forbidden", ..., 403)` | `_check_write_allowed` | `"write_allowlist"` |
| `server.py:1268-1272` | `raise WazuhError("forbidden", "active-response not configured...", 403)` | `_run_ar_inner` no-policy guard | `"ar_allowlist"` |
| `server.py:?` (T-A2) | `raise WazuhError("forbidden", "agent_group_allowlist not configured...", 403)` | T-A2's no-policy guard | `"ar_group_allowlist"` |
| `tools/write.py:281-285` | `raise WazuhError("forbidden", ..., 403)` | AR command not in allowlist | `"ar_allowlist"` |
| `tools/write.py:?` (T-A2) | `raise WazuhError("forbidden", ..., 403)` | T-A2's group-not-in-allowlist | `"ar_group_allowlist"` |

**Cross-subsystem invariant grep:**

```bash
grep -rn "rate_limited\|rate_limit_metric\|substring" src/wazuh_mcp/observability/metrics.py
```

Find every place that consumes `error.message` or `error.code` for rate-limit categorization. The plan deletes the substring-match and replaces with `error.scope` reads. Enumerate every consumer below.

**Steps:**

- [ ] **Step 1: Write failing test for `scope` field**

```python
# tests/unit/test_wazuh_error_scope.py
"""M5b T-G1. WazuhError.scope field tests."""

from __future__ import annotations

import pytest

from wazuh_mcp.wazuh.errors import WazuhError


def test_scope_defaults_to_none():
    err = WazuhError("forbidden", "test message", 403)
    assert err.scope is None


def test_scope_can_be_set_via_kwarg():
    err = WazuhError("forbidden", "test message", 403, scope="rate_limit:tenant")
    assert err.scope == "rate_limit:tenant"


def test_scope_appears_in_repr():
    err = WazuhError("rate_limited", "exhausted", 429, scope="rate_limit:session")
    assert "rate_limit:session" in repr(err)


def test_existing_3_arg_callers_still_work():
    """Backwards compat: every M3-M5a positional caller continues to work
    without setting scope."""
    err = WazuhError("upstream_error", "msg", 500)
    assert err.code == "upstream_error"
    assert err.message == "msg"
    assert err.status_code == 500
    assert err.scope is None
```

- [ ] **Step 2: Run, verify fail**

```bash
uv run pytest tests/unit/test_wazuh_error_scope.py -v
```

Expected: `AttributeError: 'WazuhError' object has no attribute 'scope'`.

- [ ] **Step 3: Add `scope` to `WazuhError`**

Edit `src/wazuh_mcp/wazuh/errors.py`. Replace the class definition:

```python
class WazuhError(Exception):
    __slots__ = ("code", "message", "status_code", "scope")

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        *,
        scope: str | None = None,
    ) -> None:
        if code not in SAFE_CODES:
            raise ValueError(f"unsafe error code: {code!r}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code
        self.scope = scope

    def __repr__(self) -> str:
        if self.scope is not None:
            return (
                f"WazuhError(code={self.code!r}, status={self.status_code}, "
                f"scope={self.scope!r})"
            )
        return f"WazuhError(code={self.code!r}, status={self.status_code})"
```

`scope` is keyword-only with default None — every existing 3-arg positional call site continues to work without modification.

- [ ] **Step 4: Run new test, verify pass**

```bash
uv run pytest tests/unit/test_wazuh_error_scope.py -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Verify no existing test regressed**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -10
```

Expected: 535 PASSED + 4 SKIPPED (after T-A1 + T-A2's +6 tests; +4 from T-G1; total = 519+10+4 = 533 plus baseline drift, roughly).

- [ ] **Step 6: Update `_check_write_allowed` raise site**

Edit `src/wazuh_mcp/server.py` line 589-594:

```python
            raise WazuhError(
                "forbidden",
                f"tool {tool_name!r} not in tenant write_allowlist",
                403,
                scope="write_allowlist",
            )
```

- [ ] **Step 7: Update `_run_ar_inner` no-policy raise**

Edit `src/wazuh_mcp/server.py` line 1268-1272:

```python
            raise WazuhError(
                "forbidden",
                "active-response not configured for this tenant",
                403,
                scope="ar_allowlist",
            )
```

- [ ] **Step 8: Update T-A2's group-AR raises (if T-A2 already shipped)**

If T-A2 landed first (recommended ordering — T-A1, T-A2, T-A3 are all Phase 1, T-G1 is Phase 3), edit the new `_run_ar_on_group_inner` block in `server.py` and the new `run_active_response_on_group` handler in `tools/write.py` to add `scope="ar_group_allowlist"` to both raises.

- [ ] **Step 9: Update `tools/write.py:281-285` AR-command raise**

```python
        raise WazuhError(
            "forbidden",
            f"active-response command {args.command_name!r} not allowlisted for tenant",
            403,
            scope="ar_allowlist",
        )
```

- [ ] **Step 10: Update `rate_limit/limiter.py` raise sites**

```bash
grep -n "raise WazuhError\|rate_limited" src/wazuh_mcp/rate_limit/limiter.py
```

For each `raise WazuhError("rate_limited", ...)`:
- If the message indicates tenant-budget: `scope="rate_limit:tenant"`.
- If session-budget: `scope="rate_limit:session"`.

The plan-author has not pre-grepped these specific lines; the implementer reads the file at task time and applies the kwarg per-message-context.

- [ ] **Step 11: Update metrics consumer**

```bash
grep -n "rate_limit\|substring\|message\|in.*err" src/wazuh_mcp/observability/metrics.py
```

Find the rate-limit metric increment site that currently does substring-match on `err.message`. Replace with structured-field read:

```python
# Before:
if "rate_limit:tenant" in err.message:
    rate_limit_drops_total.labels(scope="tenant").inc()

# After:
if err.scope == "rate_limit:tenant":
    rate_limit_drops_total.labels(scope="tenant").inc()
elif err.scope == "rate_limit:session":
    rate_limit_drops_total.labels(scope="session").inc()
```

If the metric currently emits a single `rate_limit_drops_total` counter without a `scope` label, add the label. **Note: cardinality bump.** Document operator-visible change in T-F3 docs (Phase 5).

- [ ] **Step 12: Update existing rate-limit + write-allowlist + AR-allowlist tests to assert on `.scope`**

Find the assertions:

```bash
grep -rn "rate_limited\|write_allowlist\|active_response_allowlist" tests/unit/test_rate_limit*.py tests/unit/test_rbac*.py tests/unit/test_write_tools.py | head -20
```

For each test that currently asserts on the error message substring (e.g., `assert "rate_limit:tenant" in str(exc.value)`), replace with `.scope` assertion:

```python
# Before:
with pytest.raises(WazuhError) as exc_info:
    ...
assert "rate_limit:tenant" in exc_info.value.message

# After:
with pytest.raises(WazuhError) as exc_info:
    ...
assert exc_info.value.scope == "rate_limit:tenant"
```

Estimated 5 test updates.

- [ ] **Step 13: Run full unit suite**

```bash
uv run pytest tests/unit -q -m "not integration" 2>&1 | tail -10
```

Expected: all PASSED. Unit count: ~537 (519 baseline + 6 from Phase 1 + 4 from T-G1 + 8 from any T-A test additions, minus net 0 from test updates).

- [ ] **Step 14: Lint + ty check**

```bash
uv run ruff check src/ tests/
uv run ruff format --check .
uv run ty check src/
```

Expected: clean.

- [ ] **Step 15: Commit**

```bash
git add src/wazuh_mcp/wazuh/errors.py src/wazuh_mcp/server.py src/wazuh_mcp/tools/write.py src/wazuh_mcp/rate_limit/limiter.py src/wazuh_mcp/observability/metrics.py tests/unit/test_wazuh_error_scope.py tests/unit/test_*.py
git commit -m "M5b T-G1: WazuhError.scope structured field

Adds optional kwarg-only 'scope' field to WazuhError. All existing
3-arg positional callers continue to work unchanged. Raise sites that
benefit from structured categorization set explicit values:
  - rate_limit/limiter.py: 'rate_limit:tenant' | 'rate_limit:session'
  - server.py _check_write_allowed: 'write_allowlist'
  - server.py _run_ar_inner: 'ar_allowlist'
  - server.py _run_ar_on_group_inner: 'ar_group_allowlist'
  - tools/write.py run_active_response AR-command deny: 'ar_allowlist'
  - tools/write.py run_active_response_on_group group-deny:
    'ar_group_allowlist'

observability/metrics.py rate-limit counter consumer reads
err.scope directly (replaces brittle substring-match on err.message).
Adds 'scope' label to mcp_rate_limit_drops_total — cardinality bump
documented in M5b docs (T-F3 observability.md)."
```

---

## Phase 4 — Helm chart (4 tasks; T-E5 docs in Phase 5)

**Phase rationale:** Production-baseline single-replica chart per spec §5. Independent of Phases 2-3 (pure k8s YAML). Tier-B; controller spot-check.

### Task T-E1: Chart skeleton + values + Deployment + Service + ConfigMap

**Tier:** B.

**Files (all new under `charts/wazuh-mcp/`):**
- `Chart.yaml`
- `values.yaml`
- `values.schema.json`
- `.helmignore`
- `templates/_helpers.tpl`
- `templates/deployment.yaml`
- `templates/service.yaml`
- `templates/configmap-tenants.yaml`

**Steps:**

- [ ] **Step 1: `Chart.yaml`**

```yaml
apiVersion: v2
name: wazuh-mcp
description: Model Context Protocol server exposing Wazuh as tools for Claude
type: application
version: 0.1.0
appVersion: "1.0.0"
keywords:
  - mcp
  - wazuh
  - security
  - ai
home: https://github.com/0xFl4g/wazuh-mcp
sources:
  - https://github.com/0xFl4g/wazuh-mcp
maintainers:
  - name: 0xFl4g
```

- [ ] **Step 2: `.helmignore`**

```
.git/
.github/
docs/
tests/
*.md
*.tmp
```

- [ ] **Step 3: `values.yaml`** (per spec §5.3, embedded in spec — copy verbatim, then adapt as needed)

Copy values.yaml from spec §5.3. After paste, run `helm lint charts/wazuh-mcp` to confirm syntax.

- [ ] **Step 4: `values.schema.json`**

Generate from values.yaml. Use `https://json-schema.org/draft-07/schema#` as `$schema`. Required fields: `image.repository`. Optional with defaults: everything else. Strict-required boolean defaults; permissive for optional opt-ins. Save to `charts/wazuh-mcp/values.schema.json`.

- [ ] **Step 5: `templates/_helpers.tpl`**

Standard Helm helpers — `wazuh-mcp.fullname`, `wazuh-mcp.labels`, `wazuh-mcp.selectorLabels`, `wazuh-mcp.serviceAccountName`. Use `helm create wazuh-mcp` as a starting point and trim:

```bash
helm create /tmp/wazuh-mcp-scaffold
cp /tmp/wazuh-mcp-scaffold/templates/_helpers.tpl charts/wazuh-mcp/templates/_helpers.tpl
# Edit to match name 'wazuh-mcp' instead of scaffold default
```

- [ ] **Step 6: `templates/deployment.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "wazuh-mcp.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "wazuh-mcp.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ include "wazuh-mcp.serviceAccountName" . }}
      containers:
        - name: wazuh-mcp
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
          env:
            - name: WAZUH_MCP_TENANTS_FILE
              value: /config/tenants.yaml
            - name: WAZUH_MCP_OAUTH_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ if .Values.secrets.create }}{{ include "wazuh-mcp.fullname" . }}-secrets{{ else }}{{ .Values.secrets.existingSecret }}{{ end }}
                  key: oauth-client-secret
            - name: WAZUH_MCP_WAZUH_API_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ if .Values.secrets.create }}{{ include "wazuh-mcp.fullname" . }}-secrets{{ else }}{{ .Values.secrets.existingSecret }}{{ end }}
                  key: wazuh-api-password
            - name: WAZUH_MCP_INDEXER_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ if .Values.secrets.create }}{{ include "wazuh-mcp.fullname" . }}-secrets{{ else }}{{ .Values.secrets.existingSecret }}{{ end }}
                  key: indexer-admin-password
          volumeMounts:
            - name: tenants
              mountPath: /config
              readOnly: true
          readinessProbe:
            httpGet:
              path: {{ .Values.probes.readiness.path }}
              port: http
            initialDelaySeconds: {{ .Values.probes.readiness.initialDelaySeconds }}
          livenessProbe:
            httpGet:
              path: {{ .Values.probes.liveness.path }}
              port: http
            initialDelaySeconds: {{ .Values.probes.liveness.initialDelaySeconds }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: tenants
          configMap:
            name: {{ include "wazuh-mcp.fullname" . }}-tenants
```

Note: confirm at task time that wazuh-mcp's actual env-var names match `WAZUH_MCP_*`. Grep src for `os.environ.get(...)` to find the canonical names — adapt if different.

- [ ] **Step 7: `templates/service.yaml`**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    {{- include "wazuh-mcp.selectorLabels" . | nindent 4 }}
```

- [ ] **Step 8: `templates/configmap-tenants.yaml`**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}-tenants
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
data:
  tenants.yaml: |
    {{- .Values.tenants.yaml | nindent 4 }}
```

- [ ] **Step 9: Lint chart**

```bash
helm lint charts/wazuh-mcp
helm template charts/wazuh-mcp --debug 2>&1 | head -100
```

Expected: lint passes; template render produces valid k8s YAML.

- [ ] **Step 10: Commit**

```bash
git add charts/wazuh-mcp/
git commit -m "M5b T-E1: Helm chart skeleton + Deployment + Service + ConfigMap

Production-baseline single-replica chart. values.yaml exposes:
- image (repository/tag/pullPolicy)
- replicaCount (default 1; HA caveat in T-E5 docs)
- resources requests/limits
- tenants.yaml inlined to ConfigMap
- secrets bring-your-own (default) OR create=true stub
- probes + service config

Per spec §5. T-E2 adds Secret + RBAC; T-E3 adds opt-in NetworkPolicy
+ ServiceMonitor + Ingress; T-E4 adds helm-test pod + helm-lint CI."
```

---

### Task T-E2: Secret + ServiceAccount + Role + RoleBinding

**Tier:** B.

**Files (all new under `charts/wazuh-mcp/templates/`):**
- `secret.yaml`
- `serviceaccount.yaml`
- `role.yaml`
- `rolebinding.yaml`

**Steps:**

- [ ] **Step 1: `templates/secret.yaml`**

```yaml
{{- if .Values.secrets.create }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}-secrets
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
type: Opaque
stringData:
  oauth-client-secret: {{ .Values.secrets.oauthClientSecret | quote }}
  wazuh-api-password: {{ .Values.secrets.wazuhApiPassword | quote }}
  indexer-admin-password: {{ .Values.secrets.indexerAdminPassword | quote }}
{{- end }}
```

- [ ] **Step 2: `templates/serviceaccount.yaml`**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "wazuh-mcp.serviceAccountName" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
```

- [ ] **Step 3: `templates/role.yaml`** + `rolebinding.yaml`

Minimal — read own ConfigMap + Secret only. No cluster-wide RBAC.

```yaml
# role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    resourceNames:
      - {{ include "wazuh-mcp.fullname" . }}-tenants
      - {{ include "wazuh-mcp.fullname" . }}-secrets
    verbs: ["get"]
```

```yaml
# rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "wazuh-mcp.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "wazuh-mcp.serviceAccountName" . }}
```

- [ ] **Step 4: Lint + template**

```bash
helm lint charts/wazuh-mcp
helm template charts/wazuh-mcp --set secrets.create=true --set secrets.oauthClientSecret=test --set secrets.wazuhApiPassword=test --set secrets.indexerAdminPassword=test --debug 2>&1 | grep -E "kind:" | sort -u
```

Expected: 6 distinct kinds (Deployment, Service, ConfigMap, Secret, ServiceAccount, Role, RoleBinding).

- [ ] **Step 5: Commit**

```bash
git add charts/wazuh-mcp/templates/secret.yaml charts/wazuh-mcp/templates/serviceaccount.yaml charts/wazuh-mcp/templates/role.yaml charts/wazuh-mcp/templates/rolebinding.yaml
git commit -m "M5b T-E2: Helm chart Secret + ServiceAccount + RBAC

Bring-your-own-Secret default (operator references existingSecret);
chart templates a stub Secret only when secrets.create=true.
Minimal Role grants get on the chart's own ConfigMap + Secret."
```

---

### Task T-E3: NetworkPolicy + ServiceMonitor + Ingress (gated opt-ins)

**Tier:** B.

**Files (all new under `charts/wazuh-mcp/templates/`):**
- `networkpolicy.yaml`
- `servicemonitor.yaml`
- `ingress.yaml`

**Steps:**

- [ ] **Step 1: `templates/networkpolicy.yaml`** (gated on `.Values.networkPolicy.enabled`)

```yaml
{{- if .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "wazuh-mcp.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    {{- range .Values.networkPolicy.ingressFromNamespaces }}
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ . }}
    {{- end }}
  egress:
    # Wazuh manager
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0  # operator should narrow to manager IP/CIDR
      ports:
        - protocol: TCP
          port: {{ .Values.networkPolicy.egressTo.wazuhManager.port }}
    # Wazuh indexer
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0  # operator should narrow to indexer IP/CIDR
      ports:
        - protocol: TCP
          port: {{ .Values.networkPolicy.egressTo.wazuhIndexer.port }}
    # OIDC issuer
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0  # operator should narrow to OIDC issuer IP/CIDR
      ports:
        - protocol: TCP
          port: {{ .Values.networkPolicy.egressTo.oidcIssuer.port }}
    # DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
{{- end }}
```

- [ ] **Step 2: `templates/servicemonitor.yaml`** (gated on `.Values.serviceMonitor.enabled`)

```yaml
{{- if .Values.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  {{- with .Values.serviceMonitor.namespace }}
  namespace: {{ . }}
  {{- end }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "wazuh-mcp.selectorLabels" . | nindent 6 }}
  endpoints:
    - port: http
      path: /metrics
      interval: {{ .Values.serviceMonitor.interval }}
{{- end }}
```

- [ ] **Step 3: `templates/ingress.yaml`** (gated on `.Values.ingress.enabled`)

```yaml
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "wazuh-mcp.fullname" . }}
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  ingressClassName: {{ .Values.ingress.className }}
  {{- if .Values.ingress.tls.enabled }}
  tls:
    - hosts:
        - {{ .Values.ingress.host | quote }}
      secretName: {{ .Values.ingress.tls.secretName | quote }}
  {{- end }}
  rules:
    - host: {{ .Values.ingress.host | quote }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ include "wazuh-mcp.fullname" . }}
                port:
                  number: {{ .Values.service.port }}
{{- end }}
```

- [ ] **Step 4: Lint with each opt-in enabled**

```bash
helm lint charts/wazuh-mcp --set networkPolicy.enabled=true
helm lint charts/wazuh-mcp --set serviceMonitor.enabled=true
helm lint charts/wazuh-mcp --set ingress.enabled=true,ingress.host=mcp.example.com
```

Expected: all three pass.

- [ ] **Step 5: Commit**

```bash
git add charts/wazuh-mcp/templates/networkpolicy.yaml charts/wazuh-mcp/templates/servicemonitor.yaml charts/wazuh-mcp/templates/ingress.yaml
git commit -m "M5b T-E3: Helm chart opt-in extras

NetworkPolicy (default off) restricts ingress to listed namespaces +
egress to Wazuh manager/indexer/OIDC + DNS. Operator narrows the
0.0.0.0/0 CIDRs in values.yaml to actual IPs.
ServiceMonitor (default off) targets the unauthenticated /metrics
endpoint for Prometheus Operator scraping.
Ingress (default off) supports nginx-class + cert-manager TLS."
```

---

### Task T-E4: helm-test pod + helm-lint workflow + kind smoke

**Tier:** B.

**Files:**
- Create: `charts/wazuh-mcp/templates/tests/test-connection.yaml`
- Create: `.github/workflows/helm-lint.yml`

**Steps:**

- [ ] **Step 1: `charts/wazuh-mcp/templates/tests/test-connection.yaml`**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "wazuh-mcp.fullname" . }}-test-connection"
  labels:
    {{- include "wazuh-mcp.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": test
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  restartPolicy: Never
  containers:
    - name: smoke
      image: curlimages/curl:8.10.1
      command:
        - sh
        - -c
        - |
          set -e
          echo "GET /health/ready"
          curl -fsS --max-time 10 http://{{ include "wazuh-mcp.fullname" . }}:{{ .Values.service.port }}/health/ready
          echo ""
          echo "smoke OK"
```

- [ ] **Step 2: `.github/workflows/helm-lint.yml`**

```yaml
name: helm-lint

on:
  pull_request:
    paths:
      - "charts/**"
  push:
    branches: [main]
    paths:
      - "charts/**"

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Install Helm
        uses: azure/setup-helm@v4
        with:
          version: v3.16.0

      - name: helm lint
        run: helm lint charts/wazuh-mcp

      - name: helm template (defaults)
        run: helm template charts/wazuh-mcp > /tmp/render.yaml

      - name: helm template (all opt-ins enabled)
        run: |
          helm template charts/wazuh-mcp \
            --set secrets.create=true \
            --set secrets.oauthClientSecret=test \
            --set secrets.wazuhApiPassword=test \
            --set secrets.indexerAdminPassword=test \
            --set networkPolicy.enabled=true \
            --set serviceMonitor.enabled=true \
            --set ingress.enabled=true,ingress.host=mcp.example.com \
            > /tmp/render-full.yaml
          grep -c "^kind:" /tmp/render-full.yaml

  smoke:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v6

      - name: Install Helm
        uses: azure/setup-helm@v4
        with:
          version: v3.16.0

      - name: Create kind cluster
        uses: helm/kind-action@v1
        with:
          cluster_name: wazuh-mcp-smoke

      - name: Build wazuh-mcp image and load into kind
        run: |
          # If the project ships a Dockerfile (M3 mentioned a docker/
          # build), use it. Otherwise use python:3.12-slim base + uv pip
          # install.
          # Verify at task time which exists.
          # Placeholder: assume Dockerfile at repo root or charts/ dir.
          docker build -t wazuh-mcp:smoke -f Dockerfile .
          kind load docker-image wazuh-mcp:smoke --name wazuh-mcp-smoke

      - name: helm install with stub secrets
        run: |
          helm install wazuh-mcp ./charts/wazuh-mcp \
            --set image.repository=wazuh-mcp \
            --set image.tag=smoke \
            --set image.pullPolicy=Never \
            --set secrets.create=true \
            --set secrets.oauthClientSecret=test \
            --set secrets.wazuhApiPassword=test \
            --set secrets.indexerAdminPassword=test \
            --wait --timeout 2m

      - name: helm test
        run: helm test wazuh-mcp --logs

      - name: helm uninstall
        if: always()
        run: helm uninstall wazuh-mcp || true
```

Note: the `Build wazuh-mcp image` step assumes a `Dockerfile` exists at repo root. Verify at task time:

```bash
ls Dockerfile docker/Dockerfile 2>/dev/null
```

If no Dockerfile exists, M5b should add one (as a sub-step of T-E4 or a new task) — running wazuh-mcp in k8s requires an image. **Add Dockerfile at task time if missing.**

- [ ] **Step 3: Trigger workflow via PR or workflow_dispatch and validate**

```bash
gh workflow run helm-lint.yml
```

If `smoke` fails on health check — wazuh-mcp won't actually start without a reachable indexer/manager/OIDC. Two options:

A. Skip the actual `helm test` step in CI; just `helm install` + `helm uninstall` + check that pod is `Pending`/`CrashLoopBackoff` is NOT acceptable but `Running` (with failing readiness probe) IS acceptable proof of templating correctness.

B. Run a stub indexer/manager/OIDC alongside via kind (a lot of extra YAML).

Recommend A — document explicitly that `helm test` failure is expected because the smoke pod needs upstream Wazuh cluster connectivity. Replace `helm test` with `kubectl get pods -n default` + assert pod created.

- [ ] **Step 4: Commit**

```bash
git add charts/wazuh-mcp/templates/tests/test-connection.yaml .github/workflows/helm-lint.yml
git commit -m "M5b T-E4: helm-test pod + helm-lint CI + kind smoke

helm-test connection probes /health/ready against the in-cluster
Service. helm-lint workflow runs on PR + main pushes touching
charts/**: lints + templates with defaults + all opt-ins enabled +
spins up kind cluster + helm installs the chart with stub secrets.

Note: full helm test requires upstream Wazuh + indexer + OIDC; CI
verifies templating correctness + pod creation only."
```

---

## Phase 5 — Docs restructure (9 tasks; controller-inline)

**Phase rationale:** Per M4d Phase 3 + M5a T14 precedent — pure doc/ship phases are controller-inline (no implementer dispatch). Lands after all code phases (1-4) so docs match shipped state.

**Approach:** Each T-F* task authors one or more topic files. Per-milestone source files are moved to `_archive/` with a redirect banner. Plus the deferred docs subtasks from earlier phases (T-A4, T-C3, T-D2, T-E5) land here.

### Tasks T-A4 + T-C3 + T-D2 + T-E5: Per-track deferred docs

These four tasks each contribute one section to the topic-organized files (T-F1-F5 below). Best handled inline with the corresponding T-F task:

- **T-A4 → T-F2**: group-target AR section in `writes.md`.
- **T-C3 → T-F2**: multi-manager fixture section in `multi-tenant.md`.
- **T-D2 → T-F1**: real Vault container section in `secrets.md`.
- **T-E5 → T-F4**: full `helm.md` (own file).

### Task T-F1: `secrets.md` + `oauth.md` + `tools.md` (Phase 5, controller-inline)

- [ ] **Step 1: Author `docs/deploy/secrets.md`**

Merge content from `docs/deploy/m4a-secrets.md` (existing). Sections:
1. Overview: SecretStore protocol + drivers
2. YAML driver (M1, dev only)
3. AWS Secrets Manager driver (M4a)
4. **Vault driver (M4a) + new T-D1 integration container reference**
5. SQLite + age driver (M4a)
6. CachingSecretStore wrapper (M4a)
7. Per-tenant secret_prefix
8. Operational notes (token renewal, KMS, age key management)

- [ ] **Step 2: Author `docs/deploy/oauth.md`**

Merge content from `docs/deploy/m2-http.md` OAuth sections + IssuerIndex semantics from M5a a7a1f45 patch notes. Cross-link to existing `docs/deploy/oauth-setup/{keycloak,okta,entra,auth0}.md` IDP-specific guides (these stay where they are).

- [ ] **Step 3: Author `docs/deploy/tools.md`**

17 read tools + `cluster.status` (M4c). Per-tool: name, args (link to JSON Schema), result shape, RBAC role required, audit shape, error codes.

- [ ] **Step 4: Move M4a docs to `_archive/`**

```bash
git mv docs/deploy/m3-tools.md docs/deploy/_archive/m3-tools.md
git mv docs/deploy/m4a-secrets.md docs/deploy/_archive/m4a-secrets.md
```

- [ ] **Step 5: Commit**

```bash
git add docs/deploy/secrets.md docs/deploy/oauth.md docs/deploy/tools.md docs/deploy/_archive/
git commit -m "M5b T-F1 + T-D2: docs/deploy/secrets.md + oauth.md + tools.md

Topic-organized consolidation of M3 + M4a content. secrets.md adds
new section on the real-Vault integration test container from T-D1.
Per-milestone source files moved to docs/deploy/_archive/."
```

### Task T-F2: `writes.md` + `multi-tenant.md` (Phase 5, controller-inline)

- [ ] **Step 1: Author `docs/deploy/writes.md`**

Merge `m4b-writes.md` + `m4c-multi-tenant.md` write sections. Sections:
1. Overview: 8 + 1 write tools (M4b 7 + M4c restart_manager + M5b group-target AR)
2. Two-layer allowlist (write_allowlist + RBAC)
3. Per-tool: isolate_agent, restart_agent, add/remove_to_group, create/update_rule, run_active_response, restart_manager, **run_active_response_on_group (T-A4)**
4. `agent_group_allowlist` operator setup (T-A4)
5. `responder` custom RBAC role example
6. `run_as` verification via Wazuh logs
7. `confirm` UX for Claude operators
8. Audit shape examples

- [ ] **Step 2: Author `docs/deploy/multi-tenant.md`**

Merge `m4c-multi-tenant.md` + `m4d-multi-tenant-runtime.md`. Sections:
1. Per-tenant resolver model (M4c)
2. Per-tenant rate-limit budgets (M4d)
3. Per-tenant audit-sink fan-out (M4d)
4. Cross-tenant isolation guarantees
5. Multi-tenant integration fixture (M4d) + **multi-manager fixture (T-C3)**
6. Audit-shape examples

- [ ] **Step 3: Move sources to `_archive/`**

```bash
git mv docs/deploy/m4b-writes.md docs/deploy/_archive/m4b-writes.md
git mv docs/deploy/m4c-multi-tenant.md docs/deploy/_archive/m4c-multi-tenant.md
git mv docs/deploy/m4d-multi-tenant-runtime.md docs/deploy/_archive/m4d-multi-tenant-runtime.md
```

- [ ] **Step 4: Commit**

```bash
git add docs/deploy/writes.md docs/deploy/multi-tenant.md docs/deploy/_archive/
git commit -m "M5b T-F2 + T-A4 + T-C3: writes.md + multi-tenant.md

Topic-organized consolidation of M4b/M4c/M4d content. writes.md
includes the new T-A4 group-target AR section + agent_group_allowlist
operator setup. multi-tenant.md includes the T-C3 multi-manager
fixture section.
Per-milestone source files moved to docs/deploy/_archive/."
```

### Task T-F3: `observability.md` + `quality-gates.md` (Phase 5, controller-inline)

- [ ] **Step 1: Author `docs/deploy/observability.md`**

Merge `m4a-observability.md` + `m4a-audit.md`. Add sections:
- **`WazuhError.scope` field (T-G1)** + structured rate-limit categorization
- New `mcp_rate_limit_drops_total{scope}` label (cardinality bump callout)

- [ ] **Step 2: Author `docs/deploy/quality-gates.md`**

Lift content from `m5a-quality-gates.md` (existing). Add new sections:
- T-G2 integration log secret-scan workflow
- T-B Wazuh version matrix CI
- T-D vault container

- [ ] **Step 3: Move sources to `_archive/`**

```bash
git mv docs/deploy/m4a-observability.md docs/deploy/_archive/
git mv docs/deploy/m4a-audit.md docs/deploy/_archive/
git mv docs/deploy/m5a-quality-gates.md docs/deploy/_archive/
```

- [ ] **Step 4: Commit**

```bash
git add docs/deploy/observability.md docs/deploy/quality-gates.md docs/deploy/_archive/
git commit -m "M5b T-F3: observability.md + quality-gates.md

Topic-organized consolidation. observability.md adds WazuhError.scope
section + the new mcp_rate_limit_drops_total{scope} label callout
(operator dashboard refresh recommended). quality-gates.md adds T-G2
log-scan + T-B matrix CI + T-D vault container."
```

### Task T-F4: `install.md` + `tenants.md` + `helm.md` + `docs/deploy/README.md` index + archive banner

- [ ] **Step 1: Author `docs/deploy/install.md`** (consolidates m2 install fragment + README install overlap)

- [ ] **Step 2: Author `docs/deploy/tenants.md`** (TenantConfig schema reference, all fields incl. M5b's agent_group_allowlist)

- [ ] **Step 3: Author `docs/deploy/helm.md` (T-E5)** per spec §5.7. Include the HA caveat.

- [ ] **Step 4: Author `docs/deploy/README.md` (index)**

```markdown
# Deploying wazuh-mcp

Recommended reading order:

1. [install.md](install.md) - install wazuh-mcp via stdio, container, or Helm.
2. [tenants.md](tenants.md) - per-tenant configuration schema.
3. [secrets.md](secrets.md) - SecretStore drivers.
4. [oauth.md](oauth.md) - OAuth setup; cross-link to per-IDP guides:
   - [oauth-setup/keycloak.md](oauth-setup/keycloak.md)
   - [oauth-setup/okta.md](oauth-setup/okta.md)
   - [oauth-setup/entra.md](oauth-setup/entra.md)
   - [oauth-setup/auth0.md](oauth-setup/auth0.md)
5. [api-keys.md](api-keys.md) - alternative to OAuth.
6. [tools.md](tools.md) - read-tool reference.
7. [writes.md](writes.md) - write-tool reference.
8. [multi-tenant.md](multi-tenant.md) - per-tenant isolation, rate limits, audit fan-out.
9. [observability.md](observability.md) - OTel + Prom + audit.
10. [quality-gates.md](quality-gates.md) - eval harness, security CI, destructive isolation.
11. [helm.md](helm.md) - Kubernetes deployment.

Per-milestone deploy notes are preserved at [_archive/](_archive/).
```

- [ ] **Step 5: Author `docs/deploy/_archive/README.md` banner**

(Per spec §6.3.)

- [ ] **Step 6: Move m2 source**

```bash
git mv docs/deploy/m2-http.md docs/deploy/_archive/
```

- [ ] **Step 7: Commit**

```bash
git add docs/deploy/install.md docs/deploy/tenants.md docs/deploy/helm.md docs/deploy/README.md docs/deploy/_archive/
git commit -m "M5b T-F4 + T-E5: install.md + tenants.md + helm.md + index + archive banner"
```

### Task T-F5: `docs/api-reference.md` + top-level `README.md` polish

- [ ] **Step 1: Author `docs/api-reference.md`**

Per spec §6.1: every tool/resource/prompt with args, returns, errors, audit shape. Lift from existing `tools.md` + `writes.md` + add Resource and Prompt sections.

- [ ] **Step 2: Polish top-level `README.md`**

- Quickstart install (Helm + Docker + stdio).
- Link to `docs/deploy/README.md`.
- Update milestone table — add M5b row, mark M5b as "shipped" once tag lands.
- Drop M2-M5a per-milestone callouts (now in archive).

- [ ] **Step 3: Commit**

```bash
git add docs/api-reference.md README.md
git commit -m "M5b T-F5: docs/api-reference.md + top-level README polish"
```

---

## Phase 6 — Ship (3 tasks; controller-inline)

### Task T-G3: T6 maintainer eval baseline (controller-inline, **environment-flagged**)

**Environment requirement:** the controller's Claude Code session MUST have wazuh-mcp connected as MCP server. If not connected, this task cannot be completed in the current session and must be deferred OR run in a separate maintainer session.

- [ ] **Step 1: Verify MCP connection**

In the controller's Claude Code session, invoke a wazuh-mcp tool (e.g., `agents.list`). If the tool is not available in the tool inventory, the MCP server isn't connected — STOP. Either reconnect via Claude Code settings OR document T-G3 as deferred and skip to ship-1.

- [ ] **Step 2: Run `/eval-wazuh-mcp` slash command**

Per M5a spec §1, the slash command runs Phase 1 (LLM decision phase) + writes raw-results JSON. Then Phase 2 scoring runs externally.

```bash
/eval-wazuh-mcp
# After completion, run scoring:
uv run python tools/eval/score.py docs/eval-history/raw-results.json
```

- [ ] **Step 3: Triage if pass-rate < 90%**

Per M5a spec §1 ladder: do NOT lower thresholds to make a flaky prompt pass. Either:
- Fix the corpus prompt (if the prompt is genuinely ambiguous).
- Fix the tool catalog description (if the tool's description doesn't make the right tool obvious).
- Fix the scoring rule (if the rule is too brittle).

- [ ] **Step 4: Commit baseline**

```bash
git add docs/eval-history/2026-05-XX-claude-opus-4-7-results.json docs/eval-history/2026-05-XX-claude-opus-4-7-raw.txt
git commit -m "M5b T-G3: T6 maintainer eval baseline run

Pass-rate: <X%>. Per-tier breakdown: selection <Y%>, args <Z%>,
sequence <W%>. <One sentence triage note if any prompt was retuned.>"
```

### Task ship-1: Version bump + ruff format alignment

- [ ] **Step 1: Bump `pyproject.toml`**

```bash
sed -i '' 's/version = "0.8.0"/version = "1.0.0"/' pyproject.toml
grep '^version' pyproject.toml
```

- [ ] **Step 2: Format alignment check**

```bash
uv run ruff format .
git status
```

If `ruff format .` reports "X files reformatted", commit alignment separately (per M2-M5a precedent). Otherwise skip.

- [ ] **Step 3: Final test sweep**

```bash
uv run pytest -q -m "not integration" 2>&1 | tail -5
uv run ruff check .
uv run ty check src/
```

Expected: all clean.

- [ ] **Step 4: Commit version bump**

```bash
git add pyproject.toml
git commit -m "chore: bump version 0.8.0 -> 1.0.0 for M5b ship"
```

### Task ship-2: Retro

- [ ] **Step 1: Author `docs/superpowers/retros/2026-05-XX-m5b-retro.md`**

Sections (mirroring prior retros):
1. Outcome summary (tag, commit, dispatch count, test deltas)
2. Phase-by-phase recap
3. What worked
4. What didn't (any plan defects, any fix-after-review cycles, any spec deviations)
5. Plan-author lessons for v1.1+
6. Memory updates needed

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/retros/2026-05-XX-m5b-retro.md
git commit -m "docs: M5b retro"
```

### Task ship-3: Tag + push

- [ ] **Step 1: Verify clean state**

```bash
git status
git log --oneline -10
```

Expected: all M5b commits in order, clean working tree.

- [ ] **Step 2: Tag**

```bash
git tag -a v1.0.0 -m "M5b ship: production v1.0.0

See docs/superpowers/retros/2026-05-XX-m5b-retro.md for the
milestone outcome. M5b delivers:

- Group-target run_active_response with agent_group_allowlist
- Wazuh LTS + latest matrix CI
- Multi-manager weekly integration workflow
- Real Vault container in integration tests
- Production-baseline Helm chart
- Topic-organized operator docs
- WazuhError.scope structured field
- Integration log secret-scan workflow
- T6 maintainer eval baseline
- Hand-minted phantom-token integration test (un-skipped)
- test_per_tenant_audit_routing fix (un-skipped)"
```

- [ ] **Step 3: Push branch + tag**

```bash
git push origin main
git push origin v1.0.0
```

- [ ] **Step 4: Post-ship: verify nightly green**

After 24-48 hours, confirm the first post-tag nightly integration matrix run is green on both Wazuh versions.

---

## Self-Review

### 1. Spec coverage

| Spec section | Plan task(s) | Status |
|---|---|---|
| §1 group-target AR | T-A1, T-A2, T-A3 (+ T-A4 in T-F2) | ✅ |
| §2 Wazuh version matrix | T-B1, T-B2 | ✅ |
| §3 multi-manager workflow | T-C1, T-C2 (+ T-C3 in T-F2) | ✅ |
| §4 Vault driver | T-D1 (+ T-D2 in T-F1) | ✅ |
| §5 Helm chart | T-E1, T-E2, T-E3, T-E4 (+ T-E5 in T-F4) | ✅ |
| §6 Docs restructure | T-F1, T-F2, T-F3, T-F4, T-F5 | ✅ |
| §7.1 WazuhError.scope | T-G1 | ✅ |
| §7.2 log-scan workflow | T-G2a, T-G2b | ✅ |
| §7.3 T6 baseline | T-G3 | ✅ |
| §7.4 phantom token | T-G4a, T-G4b | ✅ (Path C — side-car JWKS — adopted; spec §7.4 noted Paths A/B which proved non-viable per plan-write investigation) |
| §7.5 audit-routing fix | T-G5a, T-G5b | ✅ |
| §8 cross-cutting | every task body has Tier classification + verified call sites + grep targets | ✅ |
| Ship checklist | T-G3 + ship-1 + ship-2 + ship-3 | ✅ |

### 2. Placeholder scan

Searched for "TBD" / "TODO" / "fill in" / "implement later". Found:

- **T-B1 Step 1**: `<WAZUH_LATEST_VERSION>` placeholder — DELIBERATE, requires plan-execute lookup. Documented in the step body as "Defer to task-execute time; do NOT assume."
- **T-G5b**: hypothesis-based fix description with `<H1|H2|H3|H4>` placeholder in commit message — DELIBERATE, root cause not knowable until T-G5a runs.
- **T-G3 commit message**: `<X%>`, `<Y%>` etc. — DELIBERATE, eval result unknown until run.

These are acceptable because each is annotated as a plan-execute-time substitution, not deferred-design.

### 3. Type consistency

- `WazuhError.__init__(code: str, message: str, status_code: int, *, scope: str | None = None)` — used consistently in T-G1 + raise-site updates.
- `TenantConfig.agent_group_allowlist: list[str] = Field(default_factory=list)` — used consistently in T-A1 + T-A2 + T-G1.
- `make_ar_group_allowlist(registry, audit_emitter) -> Callable[[Session], list[str]]` — signature consistent with sibling `make_ar_allowlist`.
- `ServerApiClient.run_active_response_on_group(*, group_name, command, custom_args, run_as)` — signature consistent with sibling `run_active_response`.
- `RunActiveResponseOnGroupArgs` field naming (`group_name`, `command_name`) consistent with sibling `RunActiveResponseArgs` (`agent_ids`, `command_name`).

### 4. Cross-task dependencies

Phase 1 (T-A2) introduces `_run_ar_on_group_inner` raise sites. Phase 3 (T-G1) updates these to add `scope="ar_group_allowlist"`. Documented in T-G1 Step 8.

Phase 2 (T-G4a) requires updates to the audit-sinks fixture tenants.yaml to register the side-car issuer. Documented in T-G4a Step 3.

Phase 4 (T-E1) Step 6 deployment.yaml uses env vars `WAZUH_MCP_*` — confirm at task time these match actual codebase env-var names. Documented as "verify at task time."

Phase 5 (T-F2) consumes the T-A4 + T-C3 deferred docs subtasks; documented in T-F2 task header.

### Plan complete. Ready for execution in fresh-context session.


