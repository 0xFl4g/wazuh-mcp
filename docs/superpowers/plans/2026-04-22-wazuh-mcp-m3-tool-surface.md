# Wazuh MCP M3 — Full Tool Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver v1's full read-path tool surface on top of M2's auth-and-transport foundation — 13 new tools across six domains, a Wazuh Server API client with JWT lifecycle, 3 URI-template resources, 3 context-loaded prompts, and the Task-20 carryover cleanups.

**Architecture:** Add a `ServerApiClient` + `ServerApiClientPool` mirroring `IndexerClientPool` for Wazuh Server API calls on port 55000. Session gains a `wazuh_user` field populated from an OAuth claim and passed per-request as `run_as`. Tool return shape flattens to a Pydantic model (FastMCP promotes to `structuredContent`) — no more hand-authored `text` summaries. Resources publish templates-only with `_meta.ttl_seconds` hints; prompts pre-fetch context server-side. Wazuh 4.8+ is the documented floor; vulnerability state comes exclusively from the indexer.

**Tech Stack:** Python 3.12 • `uv` • `mcp` SDK (FastMCP, streamable_http_client) • `joserfc` 1.6 • `httpx` 0.27 • Pydantic v2 • `pytest` + `pytest-asyncio` + `pytest-httpx` + `hypothesis` • Keycloak 26 + Wazuh 4.9 (manager + indexer) for integration tests.

**Reference:** `docs/superpowers/specs/2026-04-22-wazuh-mcp-m3-design.md` (authoritative). `docs/superpowers/retros/2026-04-21-m2-retro.md` (planning guidance from M2 including Task 20 closure).

**Out of scope for M3** (deferred to M4–M5):
- Write tools (`isolate_agent`, `add_agent_to_group`, `restart_agent`, `create_rule`, `run_active_response`). `TenantConfig.write_allowlist` remains empty.
- RBAC-aware `list_tools` filtering by `Session.rbac_role`.
- Per-tenant and per-session rate limits.
- OpenTelemetry spans, Prometheus metrics, audit-sink pluggability.
- Real `SecretStore` backends (AWS SM, Vault, sqlite_age).
- Formal MCP toolset SDK support (deferred pending Python SDK spec-feature support).
- Wazuh < 4.8 compatibility.
- Evaluation harness.

**M2 invariants preserved:**
- `Session` frozen dataclass shape — *extended* (new optional `wazuh_user` field), but existing code paths unchanged.
- `SecretValue`, `SecretStore` protocol, `TenantRegistry`, `SessionFactory` protocol, `IssuerIndex` — unchanged.
- OAuth/ApiKey/Chain/Config factory wiring — unchanged except for claim extraction.
- `IndexerClient` / `IndexerClientPool` — unchanged; new tools use them as-is.
- HTTP transport (`SessionMiddleware`, `build_asgi_app`, RFC 9728 metadata, health/ready) — unchanged except for the `resource_metadata=` param added to the 401 `WWW-Authenticate` challenge (Task-20 carryover).
- `AuditEmitter` default=stderr — unchanged.
- `WazuhError` + `SAFE_CODES` frozenset — *extended* (`not_found`, `upstream_timeout` added); existing codes unchanged.
- Query-builder pattern — `build_*_query(structured_args) → DSL dict`. No raw DSL.
- Tool handler contract — takes `(args, session, client, audit)`, emits one audit event per call. Return shape *changes* (drop the `text` wrapper); this is the only intentional contract break and only affects one existing tool (`search_alerts`).

---

## Tier classification

Per the project methodology (feedback_methodology memory):
- **Tier A** — security-critical; gets full dual-review (spec + code quality) after implementer.
- **Tier B** — low-risk (scaffolding, models, docs, test helpers, mechanical tool variants); implementer-only with a controller spot-check (ruff + pytest + git log).

Tasks are tagged `[A]` or `[B]` in their headers. Batched tier-B tasks may be dispatched as a single implementer call producing multiple commits.

---

## File structure

```
wazuh-mcp/
├── docker/
│   ├── integration-compose.yml                 # MODIFIED (add wazuh-manager)
│   ├── bootstrap.sh                            # MODIFIED (seed agents, wait for manager)
│   ├── seed_alerts.py                          # MODIFIED (fixed offsets, not now())
│   └── config/
│       └── wazuh_manager_ossec.conf            # NEW (manager config for fixture)
├── src/wazuh_mcp/
│   ├── auth/
│   │   ├── session.py                          # MODIFIED (wazuh_user field)
│   │   └── oauth.py                            # MODIFIED (read wazuh_user claim)
│   ├── tenancy/
│   │   └── config.py                           # MODIFIED (wazuh_user_claim field)
│   ├── wazuh/
│   │   ├── errors.py                           # MODIFIED (not_found, upstream_timeout)
│   │   ├── models.py                           # MODIFIED (add Agent, Vulnerability,
│   │   │                                       #           FimEvent, MitreTechnique)
│   │   ├── query.py                            # MODIFIED (new query builders)
│   │   ├── server_api.py                       # NEW
│   │   └── server_api_pool.py                  # NEW
│   ├── transport/
│   │   └── http.py                             # MODIFIED (WWW-Authenticate
│   │                                           #           resource_metadata=)
│   ├── tools/
│   │   ├── alerts.py                           # MODIFIED (rename fn,
│   │   │                                       #           flatten return, drop summary)
│   │   ├── agents.py                           # NEW
│   │   ├── vulns.py                            # NEW
│   │   ├── mitre.py                            # NEW
│   │   ├── hunt.py                             # NEW
│   │   └── fim.py                              # NEW
│   ├── resources/                              # NEW PACKAGE
│   │   ├── __init__.py                         # NEW
│   │   ├── rules.py                            # NEW
│   │   ├── mitre.py                            # NEW
│   │   └── agent_config.py                     # NEW
│   ├── prompts/                                # NEW PACKAGE
│   │   ├── __init__.py                         # NEW
│   │   ├── investigate_alert.py                # NEW
│   │   ├── triage_last_hour.py                 # NEW
│   │   └── agent_posture.py                    # NEW
│   └── server.py                               # MODIFIED (register everything)
├── tests/
│   ├── unit/
│   │   ├── test_session.py                     # MODIFIED (wazuh_user field)
│   │   ├── test_oauth_factory.py               # MODIFIED (wazuh_user extraction)
│   │   ├── test_tenant_config.py               # MODIFIED (wazuh_user_claim)
│   │   ├── test_wazuh_errors.py                # MODIFIED (new codes)
│   │   ├── test_server_api.py                  # NEW
│   │   ├── test_server_api_pool.py             # NEW
│   │   ├── test_server_api_negatives.py        # NEW (security-negatives)
│   │   ├── test_query_builders_m3.py           # NEW (new builders)
│   │   ├── test_hunt_query_fuzz.py             # NEW (hypothesis)
│   │   ├── test_models_m3.py                   # NEW (Agent, Vulnerability, FIM, MITRE)
│   │   ├── test_tool_alerts_m3.py              # NEW (get_alert, by_agent, by_mitre)
│   │   ├── test_tool_agents.py                 # NEW
│   │   ├── test_tool_vulns.py                  # NEW
│   │   ├── test_tool_mitre.py                  # NEW
│   │   ├── test_tool_hunt.py                   # NEW
│   │   ├── test_tool_fim.py                    # NEW
│   │   ├── test_resources.py                   # NEW
│   │   ├── test_prompts.py                     # NEW
│   │   ├── test_asgi_composition.py            # MODIFIED (realign dummy)
│   │   └── test_http_www_authenticate.py       # MODIFIED (resource_metadata=)
│   ├── integration/
│   │   ├── conftest.py                         # MODIFIED (manager token fixture)
│   │   ├── test_oauth_e2e.py                   # MODIFIED (streamable_http_client)
│   │   ├── test_search_alerts_e2e.py           # MODIFIED (rename + flat shape)
│   │   ├── test_tools_integration.py           # NEW (per-tool smoke)
│   │   ├── test_resources_integration.py       # NEW
│   │   └── test_prompts_integration.py         # NEW
│   └── fixtures/
│       └── wazuh_stub.py                       # NEW (httpx.MockTransport helpers)
└── docs/
    ├── deploy/
    │   ├── m3-tools.md                         # NEW (new tool reference)
    │   └── oauth-setup/*.md                    # MODIFIED (wazuh_user claim setup)
    ├── security/
    │   └── threat-model.md                     # MODIFIED (M3 section)
    └── README.md                               # MODIFIED (tool list update)
```

---

## Task ordering rationale

```
Phase 1 — Foundation (Tasks 1-6)
    wazuh_user plumbing + error codes + Task-20 carryovers
Phase 2 — Server API client (Tasks 7-11)
    Unlock everything that talks to port 55000
Phase 3 — Tool contract flatten (Task 12)
    Break the one existing tool's shape NOW before 13 more inherit the bug
Phase 4 — Models + query builders (Tasks 13-14)
    Shared ingredients for tools
Phase 5 — Indexer-backed tools + fuzz (Tasks 15-19)
    Pure extensions of M1/M2 patterns; hunt_query gets dual-reviewed + fuzzed
Phase 6 — Server-API-backed tools (Tasks 20-23)
    Agents, MITRE (partially), vulnerabilities
Phase 7 — Resources (Tasks 24-26)
    New MCP surface; templates-only
Phase 8 — Prompts (Tasks 27-29)
    New MCP surface; context-loaded
Phase 9 — Server wiring + toolsets (Tasks 30-31)
    Register everything + meta-annotated grouping
Phase 10 — Integration fixture + full smoke (Tasks 32-33)
    Wazuh manager container + per-tool integration tests
Phase 11 — Docs (Task 34)
    Operator docs catch up to the shipped surface
Phase 12 — Ship (Task 35)
    Tag v0.3.0-m3, retro
```

Dependency-critical edges:
- T1 (wazuh_user) must precede T7+ (Server API uses it for run_as).
- T4 (error codes) must precede any code that raises `not_found` or `upstream_timeout`.
- T12 (flatten) must precede T15+ (all new tools inherit the new contract).
- T13 (models) must precede any tool using a new Pydantic model.
- T14 (query builders) must precede the indexer-backed tools.
- T7-T11 (server_api) must precede T20-T23 (server-api-backed tools).
- T32 (manager container) can interleave with Phase 6; does NOT block Phase 5.
- T30-T31 (wiring + toolsets) must follow all tool/resource/prompt implementations.

---

## Task 1: Add `wazuh_user` to `Session` [A]

**Tier A:** Session identity shape; load-bearing for every downstream auth check.

**Files:**
- Modify: `src/wazuh_mcp/auth/session.py`
- Modify: `tests/unit/test_session.py`
- Modify: every existing `Session(...)` construction site (discovered via grep).

- [ ] **Step 1.1: Inventory existing `Session(...)` construction sites**

Run: `uv run ruff check --select F401 . 2>/dev/null; grep -rn "Session(" src tests --include="*.py"`
Expected: a list of ~6-10 sites — factory builds, test fixtures, and the occasional integration conftest.

Record the list. Each will need `wazuh_user=None` (or a specific value) added after M3's change.

- [ ] **Step 1.2: Modify `Session` dataclass**

Open `src/wazuh_mcp/auth/session.py`. Replace the dataclass with:

```python
"""Session value object — identity carried through every tool call.

Frozen by design: a session's tenant cannot change mid-call. This is a
structural defense against confused-deputy / cross-tenant bugs.
"""

from dataclasses import dataclass
from typing import Literal

AuthMethod = Literal["config", "oauth", "api_key"]


@dataclass(frozen=True, slots=True)
class Session:
    user_id: str
    tenant_id: str
    rbac_role: str
    auth_method: AuthMethod
    # Optional upstream-identity attribution carried through to Wazuh's own
    # audit log via the Server API's `run_as` parameter. Populated only by
    # OAuthSessionFactory when the configured claim is present. Config- and
    # API-key sessions always leave this None — `run_as=None` means the
    # Server API request runs as the tenant's service account.
    wazuh_user: str | None = None
```

- [ ] **Step 1.3: Fix every `Session(...)` construction site**

For each site found in Step 1.1, confirm the Session is still constructed via keyword args (it is, in all existing code). No changes needed — the new field has a default. Verify by running:

Run: `uv run ruff check . && uv run ty check src tests 2>&1 | tail -5`
Expected: `All checks passed!`

- [ ] **Step 1.4: Update `tests/unit/test_session.py`**

Append a test asserting the default and explicit-set paths:

```python
def test_session_wazuh_user_defaults_to_none():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="config",
    )
    assert s.wazuh_user is None


def test_session_wazuh_user_explicit():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="oauth",
        wazuh_user="alice",
    )
    assert s.wazuh_user == "alice"


def test_session_wazuh_user_frozen():
    s = Session(
        user_id="u",
        tenant_id="t",
        rbac_role="r",
        auth_method="oauth",
        wazuh_user="alice",
    )
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        s.wazuh_user = "bob"  # type: ignore[misc]
```

Add `import pytest` at the top of the file if not already present.

- [ ] **Step 1.5: Run tests**

Run: `uv run pytest tests/unit/test_session.py -v`
Expected: all tests pass, including 3 new ones.

- [ ] **Step 1.6: Commit**

```bash
git add src/wazuh_mcp/auth/session.py tests/unit/test_session.py
git commit -m "Add optional wazuh_user field to Session for run_as attribution"
```

---

## Task 2: Add `wazuh_user_claim` to `TenantConfig` [B]

**Tier B:** Config field addition, extensively type-checked by Pydantic.

**Files:**
- Modify: `src/wazuh_mcp/tenancy/config.py`
- Modify: `tests/unit/test_tenant_config.py` (create if not present)

- [ ] **Step 2.1: Extend `TenantConfig`**

Open `src/wazuh_mcp/tenancy/config.py`. Add the new field below `oauth_audience`:

```python
class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: Annotated[str, Field(pattern=TENANT_ID_PATTERN.pattern)]
    indexer_url: HttpUrl
    verify_tls: bool = True
    ca_bundle_path: Path | None = None
    default_rbac_role: str
    oauth_issuer: HttpUrl | None = None
    oauth_audience: str | None = None
    # Name of the OAuth claim that carries the Wazuh user identity for
    # run_as attribution. When the claim is present in a verified bearer,
    # Session.wazuh_user is populated and the Server API calls pass run_as.
    # When absent, calls run as the tenant's service account.
    wazuh_user_claim: str = "wazuh_user"
```

- [ ] **Step 2.2: Write tests**

Create or extend `tests/unit/test_tenant_config.py`:

```python
"""TenantConfig shape tests."""

import pytest
from pydantic import ValidationError

from wazuh_mcp.tenancy.config import TenantConfig


def _base_cfg() -> dict:
    return {
        "tenant_id": "t1",
        "indexer_url": "https://indexer.example",
        "default_rbac_role": "soc_analyst",
    }


def test_wazuh_user_claim_defaults_to_wazuh_user():
    cfg = TenantConfig.model_validate(_base_cfg())
    assert cfg.wazuh_user_claim == "wazuh_user"


def test_wazuh_user_claim_custom():
    cfg = TenantConfig.model_validate({**_base_cfg(), "wazuh_user_claim": "uid"})
    assert cfg.wazuh_user_claim == "uid"


def test_tenant_config_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        TenantConfig.model_validate({**_base_cfg(), "not_a_field": True})
```

- [ ] **Step 2.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_tenant_config.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 3 tests pass; all checks passed.

- [ ] **Step 2.4: Commit**

```bash
git add src/wazuh_mcp/tenancy/config.py tests/unit/test_tenant_config.py
git commit -m "Add wazuh_user_claim field to TenantConfig"
```

---

## Task 3: Update `OAuthSessionFactory` to extract `wazuh_user` [A]

**Tier A:** Bearer-to-identity mapping; security-critical.

**Files:**
- Modify: `src/wazuh_mcp/auth/oauth.py`
- Modify: `tests/unit/test_oauth_factory.py`

- [ ] **Step 3.1: Extend `_build_session`**

Open `src/wazuh_mcp/auth/oauth.py`. The current `_build_session` ends with:

```python
        return Session(
            user_id=str(sub),
            tenant_id=tenant_id,
            rbac_role=rbac,
            auth_method="oauth",
        )
```

Replace with:

```python
        wazuh_user = self._pick_wazuh_user(claims, iss_tenant_cfg)

        return Session(
            user_id=str(sub),
            tenant_id=tenant_id,
            rbac_role=rbac,
            auth_method="oauth",
            wazuh_user=wazuh_user,
        )
```

Add the helper method on `OAuthSessionFactory`:

```python
    def _pick_wazuh_user(
        self,
        claims: dict[str, Any],
        iss_tenant_cfg: Any,
    ) -> str | None:
        """Extract wazuh_user from claims using the tenant's configured claim name.

        Tenant config defaults to `wazuh_user`. When the claim is absent or
        empty, returns None — the Server API request will run as the tenant's
        service account.
        """
        if iss_tenant_cfg is None:
            return None
        claim_name = getattr(iss_tenant_cfg, "wazuh_user_claim", "wazuh_user")
        val = claims.get(claim_name)
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        s = str(val).strip()
        return s or None
```

- [ ] **Step 3.2: Write tests**

Append to `tests/unit/test_oauth_factory.py` (preserve existing tests):

```python
def test_oauth_factory_extracts_wazuh_user_default_claim(
    jwks_httpx_mock, signing_key, tenant_cfg_factory
):
    tenant = tenant_cfg_factory(
        tenant_id="local",
        issuer="https://idp.example",
        wazuh_user_claim="wazuh_user",
    )
    factory = _make_factory(tenant)
    token = _mint(
        signing_key,
        claims={
            "iss": "https://idp.example",
            "aud": "mcp-api",
            "sub": "abc",
            "wazuh_user": "alice",
            "exp": int(time.time()) + 300,
        },
    )
    session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    assert session.wazuh_user == "alice"


def test_oauth_factory_extracts_wazuh_user_custom_claim(
    jwks_httpx_mock, signing_key, tenant_cfg_factory
):
    tenant = tenant_cfg_factory(
        tenant_id="local",
        issuer="https://idp.example",
        wazuh_user_claim="uid",
    )
    factory = _make_factory(tenant)
    token = _mint(
        signing_key,
        claims={
            "iss": "https://idp.example",
            "aud": "mcp-api",
            "sub": "abc",
            "uid": "bob",
            "exp": int(time.time()) + 300,
        },
    )
    session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    assert session.wazuh_user == "bob"


def test_oauth_factory_wazuh_user_absent_yields_none(
    jwks_httpx_mock, signing_key, tenant_cfg_factory
):
    tenant = tenant_cfg_factory(tenant_id="local", issuer="https://idp.example")
    factory = _make_factory(tenant)
    token = _mint(
        signing_key,
        claims={
            "iss": "https://idp.example",
            "aud": "mcp-api",
            "sub": "abc",
            "exp": int(time.time()) + 300,
        },
    )
    session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    assert session.wazuh_user is None


def test_oauth_factory_wazuh_user_list_takes_first(
    jwks_httpx_mock, signing_key, tenant_cfg_factory
):
    tenant = tenant_cfg_factory(tenant_id="local", issuer="https://idp.example")
    factory = _make_factory(tenant)
    token = _mint(
        signing_key,
        claims={
            "iss": "https://idp.example",
            "aud": "mcp-api",
            "sub": "abc",
            "wazuh_user": ["alice", "backup"],
            "exp": int(time.time()) + 300,
        },
    )
    session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    assert session.wazuh_user == "alice"
```

Note: the `_make_factory`, `_mint`, `tenant_cfg_factory`, `signing_key`, and `jwks_httpx_mock` helpers already exist in the file from M2. If the `tenant_cfg_factory` fixture doesn't support `wazuh_user_claim` kwarg, extend it in the same commit.

- [ ] **Step 3.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_oauth_factory.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: all prior tests still pass; 4 new pass; all checks passed.

- [ ] **Step 3.4: Commit**

```bash
git add src/wazuh_mcp/auth/oauth.py tests/unit/test_oauth_factory.py
git commit -m "Extract wazuh_user from OAuth bearer claims for run_as attribution"
```

---

## Task 4: Extend `SAFE_CODES` + `map_http_error` [B]

**Tier B:** Small additive change to the error boundary.

**Files:**
- Modify: `src/wazuh_mcp/wazuh/errors.py`
- Modify: `tests/unit/test_wazuh_errors.py` (create if not present)

- [ ] **Step 4.1: Extend `SAFE_CODES` and `map_http_error`**

Open `src/wazuh_mcp/wazuh/errors.py`. Replace file content with:

```python
"""Upstream error → safe code mapping.

Any upstream response body/stacktrace/schema data is discarded at this
boundary. MCP clients only ever see the codes in SAFE_CODES.
"""

from __future__ import annotations

from typing import Final

import httpx

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


class WazuhError(Exception):
    __slots__ = ("code", "message", "status_code")

    def __init__(self, code: str, message: str, status_code: int) -> None:
        if code not in SAFE_CODES:
            raise ValueError(f"unsafe error code: {code!r}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"WazuhError(code={self.code!r}, status={self.status_code})"


_INVALID_QUERY_GENERIC: Final[str] = "query was rejected by the backend"


def map_http_error(resp: httpx.Response) -> WazuhError:
    status = resp.status_code
    if status == 401:
        return WazuhError("auth_expired", "upstream authentication expired", status)
    if status == 403:
        return WazuhError("forbidden", "upstream denied the request", status)
    if status == 404:
        return WazuhError("not_found", "upstream resource not found", status)
    if status == 429:
        return WazuhError("rate_limited", "upstream rate limit exceeded", status)
    if status == 400:
        # Swallow upstream detail entirely; surface only a generic message.
        return WazuhError("invalid_query", _INVALID_QUERY_GENERIC, status)
    return WazuhError("upstream_error", "upstream returned an error", status)


def map_timeout() -> WazuhError:
    """Surface httpx.TimeoutException as a safe, scrubbed code.

    Called at catch sites that wrap httpx calls; httpx doesn't carry a
    response object for timeouts so this takes no arguments.
    """
    return WazuhError("upstream_timeout", "upstream request timed out", 504)
```

- [ ] **Step 4.2: Write tests**

Create or extend `tests/unit/test_wazuh_errors.py`:

```python
"""WazuhError + map_http_error + map_timeout tests."""

import httpx
import pytest

from wazuh_mcp.wazuh.errors import (
    SAFE_CODES,
    WazuhError,
    map_http_error,
    map_timeout,
)


def test_safe_codes_contains_new_m3_codes():
    assert "not_found" in SAFE_CODES
    assert "upstream_timeout" in SAFE_CODES


def test_map_http_error_404_is_not_found():
    resp = httpx.Response(status_code=404)
    err = map_http_error(resp)
    assert err.code == "not_found"
    assert err.status_code == 404


def test_map_timeout_is_upstream_timeout():
    err = map_timeout()
    assert err.code == "upstream_timeout"
    assert err.status_code == 504


def test_wazuh_error_rejects_unsafe_code():
    with pytest.raises(ValueError, match="unsafe error code"):
        WazuhError("internal_server_error", "leak me", 500)


def test_wazuh_error_repr_scrubs_message():
    err = WazuhError("not_found", "agent 999 missing", 404)
    # repr must not include the message (which could carry IDs or arbitrary upstream text).
    assert "agent 999" not in repr(err)
```

- [ ] **Step 4.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_wazuh_errors.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 5 tests pass; all checks passed.

- [ ] **Step 4.4: Commit**

```bash
git add src/wazuh_mcp/wazuh/errors.py tests/unit/test_wazuh_errors.py
git commit -m "Add not_found and upstream_timeout to safe error codes"
```

---

## Task 5: Task-20 carryover — `WWW-Authenticate resource_metadata=` [A]

**Tier A:** Security-relevant MCP 2025-06-18 compliance; error-path hardening.

**Files:**
- Modify: `src/wazuh_mcp/transport/http.py`
- Modify: `tests/unit/test_http_www_authenticate.py` (rename from whatever the current M2 test name is if needed; otherwise create)

- [ ] **Step 5.1: Inspect current `SessionMiddleware` challenge**

Open `src/wazuh_mcp/transport/http.py`. The existing code around the `AuthError` except branch looks like:

```python
        except AuthError as e:
            err_code = "insufficient_scope" if e.http_status == 403 else "invalid_token"
            body = {"error": e.public_message}
            headers = {"WWW-Authenticate": f'Bearer realm="mcp", error="{err_code}"'}
            return JSONResponse(body, status_code=e.http_status, headers=headers)
```

- [ ] **Step 5.2: Plumb the metadata URL into `SessionMiddleware`**

Extend `SessionMiddleware.__init__` to accept a `resource_metadata_url: str` (default empty string; empty = omit the param). Update `dispatch` to include `resource_metadata="<url>"` in the challenge when the URL is set.

Replace the `SessionMiddleware` class top-to-bottom:

```python
class SessionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any,
        *,
        factory: SessionFactory,
        protect_paths: list[str],
        resource_metadata_url: str = "",
    ) -> None:
        super().__init__(app)
        self._factory = factory
        self._protect = tuple(protect_paths)
        self._metadata_url = resource_metadata_url

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        if not any(path == p or path.startswith(p.rstrip("/") + "/") for p in self._protect):
            return await call_next(request)

        ctx: RequestContext = {
            "headers": {_title_header(k): v for k, v in request.headers.items()},
            "client_ip": request.client.host if request.client else "",
        }
        try:
            session = await self._factory.build(ctx)
        except AuthError as e:
            err_code = "insufficient_scope" if e.http_status == 403 else "invalid_token"
            body = {"error": e.public_message}
            challenge = f'Bearer realm="mcp", error="{err_code}"'
            if self._metadata_url:
                # RFC 9728 / MCP 2025-06-18: advertise the protected-resource
                # metadata URL on 401 so clients can discover the auth server
                # without a preflight.
                challenge += f', resource_metadata="{self._metadata_url}"'
            headers = {"WWW-Authenticate": challenge}
            return JSONResponse(body, status_code=e.http_status, headers=headers)

        token = set_current_session(session)
        try:
            return await call_next(request)
        finally:
            CURRENT_SESSION.reset(token)
```

- [ ] **Step 5.3: Wire the URL through `build_asgi_app`**

In the same file, find `build_asgi_app` and update the final `return SessionMiddleware(...)` line to pass the metadata URL:

```python
    return SessionMiddleware(
        base,
        factory=factory,
        protect_paths=["/mcp"],
        resource_metadata_url=f"{resource_url.rstrip('/')}/.well-known/oauth-protected-resource",
    )
```

`resource_url` is already an argument to `build_asgi_app` (from M2).

- [ ] **Step 5.4: Write unit test**

Create or extend `tests/unit/test_http_www_authenticate.py`:

```python
"""WWW-Authenticate challenge shape tests."""

from starlette.testclient import TestClient

from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.http import build_asgi_app


class _AlwaysDeny(SessionFactory):
    async def build(self, ctx: RequestContext) -> Session:
        raise InvalidToken()


class _DummyMcp:
    def streamable_http_app(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def _ok(request):
            return JSONResponse({"ok": True})

        return Starlette(routes=[Route("/mcp", _ok, methods=["GET", "POST"])])


def test_www_authenticate_includes_resource_metadata_on_401():
    app = build_asgi_app(
        mcp_app=_DummyMcp(),
        factory=_AlwaysDeny(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    challenge = resp.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'realm="mcp"' in challenge
    assert 'error="invalid_token"' in challenge
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'
        in challenge
    )


def test_www_authenticate_honors_trailing_slash_in_resource_url():
    app = build_asgi_app(
        mcp_app=_DummyMcp(),
        factory=_AlwaysDeny(),
        resource_url="https://mcp.example/",  # trailing slash
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    # No double slashes.
    assert "example//.well-known" not in resp.headers["WWW-Authenticate"]
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'
        in resp.headers["WWW-Authenticate"]
    )
```

If a test file with M2 `WWW-Authenticate` tests already exists under a different name, add these there alongside them and delete the `create if not present` instruction. Use `grep -rn "WWW-Authenticate" tests/unit/` to find it.

- [ ] **Step 5.5: Run tests + integration regression**

Run: `uv run pytest tests/unit/ -v -k "www_authenticate or asgi_composition" && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: all tests pass including two new ones.

- [ ] **Step 5.6: Commit**

```bash
git add src/wazuh_mcp/transport/http.py tests/unit/test_http_www_authenticate.py
git commit -m "Add resource_metadata= to 401 WWW-Authenticate per MCP 2025-06-18"
```

---

## Task 6: Task-20 carryover — seed_alerts clock harden + streamable_http_client migration + test_asgi_composition dummy realign [B]

**Tier B batch:** Three unrelated small fixes that all fall under "Task-20 follow-ups." Batch into one implementer dispatch → three commits.

**Files:**
- Modify: `docker/seed_alerts.py`
- Modify: `tests/unit/test_asgi_composition.py`
- Modify: `tests/integration/test_oauth_e2e.py`
- Modify: `tests/integration/test_search_alerts_e2e.py` (time_range adjustment)

- [ ] **Step 6.1: Harden `docker/seed_alerts.py` against host clock drift**

Open `docker/seed_alerts.py`. The current `_alert` function uses `datetime.now(UTC) - timedelta(minutes=offset_min)`. If the host clock jumps forward between seed time and test run, alerts fall out of the 1h window. Fix by seeding alerts at **relative-to-now offsets that span 24h** so a `time_range="24h"` test always finds them:

Replace the body of `main()` to:

```python
def main() -> int:
    client = httpx.Client(auth=AUTH, verify=False, timeout=30)
    docs = []
    # Offsets span the last 24h — 5 min apart for the first 5 (critical window),
    # then 1h apart for the remaining 15. Integration tests query with
    # time_range="24h" so drift up to ~1h before test run still keeps all 20
    # alerts in-range.
    offsets = [5, 10, 15, 20, 25] + list(range(60, 60 + 15 * 60, 60))
    for i, offset_min in enumerate(offsets):
        lvl = 12 if i % 4 == 0 else 3
        docs.append(_alert(i, lvl, offset_min=offset_min))
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    r = client.post(
        f"{BASE}/_bulk",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    r.raise_for_status()
    resp = r.json()
    if resp.get("errors"):
        print("bulk errors:", json.dumps(resp)[:500], file=sys.stderr)
        return 1
    client.post(f"{BASE}/{INDEX}/_refresh").raise_for_status()
    print(f"Seeded {len(docs)} alerts into {INDEX}")
    return 0
```

Open `tests/integration/test_search_alerts_e2e.py`. Replace every `time_range="1h"` with `time_range="24h"` and adjust the minimum `total` assertion to `>= 5` (the 5 fresh-window alerts; older ones may age out of the 24h window across long local sessions).

- [ ] **Step 6.2: Commit the seed-drift fix**

```bash
git add docker/seed_alerts.py tests/integration/test_search_alerts_e2e.py
git commit -m "Harden seed_alerts against host clock drift; widen test lookback"
```

- [ ] **Step 6.3: Migrate `streamablehttp_client` → `streamable_http_client`**

The MCP Python SDK deprecated `streamablehttp_client` for `streamable_http_client`, moving headers to a caller-supplied `httpx.AsyncClient`.

Open `tests/integration/test_oauth_e2e.py`. Replace the two test bodies that use `streamablehttp_client` with:

```python
@pytest.mark.integration
async def test_mcp_tools_list_includes_search_alerts(mcp_http_server, keycloak_token):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _get_session_id,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
    finally:
        await http_client.aclose()

    names = [t.name for t in tools.tools]
    # search_alerts is renamed in Task 12 — test both the old and the new name to
    # make the migration commit safe to land before or after the rename.
    assert "search_alerts" in names or "alerts.search_alerts" in names, (
        f"tools/list missing search_alerts: {names}"
    )


@pytest.mark.integration
async def test_mcp_tools_call_search_alerts_returns_seeded_data(
    mcp_http_server, keycloak_token
):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    tool_name = "alerts.search_alerts"  # post-Task-12 name
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _get_session_id,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            try:
                result = await session.call_tool(
                    tool_name, {"time_range": "24h", "size": 5}
                )
            except Exception:
                # fall back to the pre-rename name during the transitional window
                result = await session.call_tool(
                    "search_alerts", {"time_range": "24h", "size": 5}
                )
    finally:
        await http_client.aclose()

    assert not result.isError, f"tools/call returned error: {result}"
    # After Task 12 the shape flattens — drill defensively.
    outer = result.structuredContent
    assert outer is not None, "structuredContent missing from CallToolResult"
    if "structuredContent" in outer:
        inner = outer["structuredContent"]  # pre-flatten shape
    else:
        inner = outer  # post-flatten shape
    assert inner.get("total", 0) >= 1, f"no alerts returned: {inner}"
    assert isinstance(inner.get("alerts"), list)
    assert len(inner["alerts"]) >= 1
```

The fallback logic here exists so the migration commit doesn't depend on the rename commit (T12) landing first. Both commits safely land in either order.

- [ ] **Step 6.4: Commit the SDK migration**

```bash
git add tests/integration/test_oauth_e2e.py
git commit -m "Migrate integration tests to streamable_http_client (SDK deprecation)"
```

- [ ] **Step 6.5: Realign `test_asgi_composition` dummy to real FastMCP**

The dummy MCP sub-app in `tests/unit/test_asgi_composition.py` exposes `/initialize`, not `/mcp`, and has no lifespan context. Real FastMCP exposes `/mcp` and has a `router.lifespan_context`. That drift is what hid the Task-20 mount-path and lifespan bugs from the unit tests.

Open `tests/unit/test_asgi_composition.py`. Replace `_DummyMcpApp` with:

```python
class _DummyMcpApp:
    """Minimal stand-in that mirrors the real FastMCP surface:
    - Internal /mcp route (what real FastMCP exposes)
    - router.lifespan_context (task group needs startup in production)
    """

    def streamable_http_app(self):
        from contextlib import asynccontextmanager

        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        started = {"flag": False}

        @asynccontextmanager
        async def lifespan(app):
            started["flag"] = True
            yield

        async def _ok(request):
            # Proves lifespan actually ran for the outer app.
            return JSONResponse({"ok": True, "lifespan_started": started["flag"]})

        app = Starlette(routes=[Route("/mcp", _ok, methods=["GET", "POST"])], lifespan=lifespan)
        # Expose the started flag so the test can assert outer lifespan forwarding.
        app.state.started_flag = started
        return app
```

Update the existing tests to POST to `/mcp` (not `/mcp/initialize`) and add a new regression test:

```python
def test_outer_app_forwards_sub_app_lifespan():
    """Regression: outer Starlette must forward FastMCP's lifespan so the
    session-manager task group starts. Task 20 found this the hard way.
    """

    class _AllowAll(SessionFactory):
        async def build(self, ctx: RequestContext) -> Session:
            return Session(
                user_id="u",
                tenant_id="t",
                rbac_role="r",
                auth_method="config",
            )

    dummy = _DummyMcpApp()
    app = build_asgi_app(
        mcp_app=dummy,
        factory=_AllowAll(),
        resource_url="https://mcp.example",
        authorization_server="https://idp.example",
        ready_fn=lambda: True,
    )
    client = TestClient(app)
    resp = client.post("/mcp", json={})
    assert resp.status_code == 200
    assert resp.json()["lifespan_started"] is True
```

Update the existing assertions that hit `/mcp/initialize` to hit `/mcp`. The `/mcpfoo` sibling test is unchanged — its point is the prefix-match safety of `SessionMiddleware.protect_paths`, which doesn't depend on the sub-app's routes.

- [ ] **Step 6.6: Run tests + lint**

Run: `uv run pytest tests/unit/test_asgi_composition.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: all tests pass, new regression test included.

- [ ] **Step 6.7: Commit the dummy realignment**

```bash
git add tests/unit/test_asgi_composition.py
git commit -m "Realign ASGI-composition dummy to real FastMCP (route + lifespan)"
```

---

## Task 7: `ServerApiClient` — JWT mint + basic calls [A]

**Tier A:** New security-critical client; JWT lifecycle + credential hygiene.

**Files:**
- Create: `src/wazuh_mcp/wazuh/server_api.py`
- Create: `tests/unit/test_server_api.py`

- [ ] **Step 7.1: Write the initial failing test**

Create `tests/unit/test_server_api.py`:

```python
"""ServerApiClient — JWT mint + basic request path tests."""

import base64
import json
import time

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    """Forge an RS-like JWT whose exp is decodable client-side (signature ignored)."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_s, "sub": "mcp"}).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


@pytest.fixture
def mint_response_ok():
    def _build(token: str) -> httpx.Response:
        return httpx.Response(200, json={"data": {"token": token}})

    return _build


@pytest.mark.asyncio
async def test_mint_on_first_call(httpx_mock, mint_response_ok):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": []}},
    )

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        result = await client.get("/agents")
    finally:
        await client.aclose()
    assert result["data"]["affected_items"] == []
```

- [ ] **Step 7.2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_server_api.py::test_mint_on_first_call -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wazuh_mcp.wazuh.server_api'` — we haven't created the module yet.

- [ ] **Step 7.3: Create the module**

Create `src/wazuh_mcp/wazuh/server_api.py`:

```python
"""Async HTTPX client for the Wazuh Server API (port 55000).

Responsibilities:
- Mint JWT via POST /security/user/authenticate with basic auth.
- Decode `exp` client-side (no signature check) to compute refresh timing.
- Proactively refresh at 80% of token lifetime.
- Retry-once on 401: mint a fresh JWT, replay the request. Second 401 is fatal.
- Per-request run_as attribution (URL query parameter).
- Scrub upstream errors via map_http_error / map_timeout.

Credential hygiene: basic-auth credentials live only on this instance. They
flow to Wazuh once per mint and never appear in logs, error paths, or
__repr__ output.

Concurrency: mint/refresh is serialised via an asyncio.Lock to prevent
mint stampedes when multiple callers race through token-expiry.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import httpx

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import map_http_error, map_timeout

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
REFRESH_AT_FRACTION = 0.80  # mint a new JWT once we've consumed 80% of lifetime
_AUTH_PATH = "/security/user/authenticate"


class ServerApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        user: SecretValue,
        password: SecretValue,
        verify_tls: bool = True,
        ca_bundle_path: Path | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        verify: bool | str = str(ca_bundle_path) if ca_bundle_path else verify_tls
        # The mint call uses basic auth; subsequent calls use Authorization: Bearer.
        # Keep a single httpx.AsyncClient and swap the header per-request.
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            verify=verify,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        self._user = user
        self._password = password
        self._token: str | None = None
        self._token_exp: float | None = None   # wall-clock seconds
        self._token_issued_at: float | None = None
        self._lock = asyncio.Lock()
        self._closed = False

    def __repr__(self) -> str:  # pragma: no cover — inspected only in error paths
        # Never leak the token or basic-auth credentials via repr.
        return f"ServerApiClient(base_url={self._client.base_url!r}, token=<redacted>)"

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()

    # ---- Public HTTP methods ----

    async def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("GET", path, params=params, run_as=run_as)

    async def post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        return await self._request("POST", path, json=json, params=params, run_as=run_as)

    # ---- Internal ----

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        run_as: str | None = None,
    ) -> dict[str, Any]:
        token = await self._ensure_jwt()
        effective_params = dict(params or {})
        if run_as is not None:
            effective_params["run_as"] = run_as

        def _do(jwt: str) -> httpx.Request:
            return self._client.build_request(
                method,
                path,
                params=effective_params or None,
                json=json,
                headers={"Authorization": f"Bearer {jwt}"},
            )

        try:
            resp = await self._client.send(_do(token))
        except httpx.TimeoutException as e:
            raise map_timeout() from e

        if resp.status_code == 401:
            # Retry-once: mint fresh, replay. Second 401 surfaces auth_expired.
            token = await self._refresh_jwt_force()
            try:
                resp = await self._client.send(_do(token))
            except httpx.TimeoutException as e:
                raise map_timeout() from e

        if resp.status_code >= 400:
            raise map_http_error(resp)
        return resp.json()

    async def _ensure_jwt(self) -> str:
        async with self._lock:
            now = time.monotonic()
            if self._token and self._token_issued_at and self._token_exp:
                lifetime = self._token_exp - self._token_issued_at
                consumed = now - self._token_issued_at
                if consumed < lifetime * REFRESH_AT_FRACTION:
                    return self._token
            return await self._mint_locked()

    async def _refresh_jwt_force(self) -> str:
        async with self._lock:
            return await self._mint_locked()

    async def _mint_locked(self) -> str:
        try:
            resp = await self._client.post(
                _AUTH_PATH,
                auth=(self._user.expose(), self._password.expose()),
            )
        except httpx.TimeoutException as e:
            raise map_timeout() from e
        if resp.status_code >= 400:
            raise map_http_error(resp)

        body = resp.json()
        token = body.get("data", {}).get("token")
        if not isinstance(token, str) or not token:
            # Upstream returned 200 but malformed body; surface as upstream_error
            # rather than leaking the body.
            raise map_http_error(httpx.Response(500))

        self._token = token
        self._token_issued_at = time.monotonic()
        self._token_exp = self._token_issued_at + self._parse_exp_seconds(token)
        return token

    @staticmethod
    def _parse_exp_seconds(token: str) -> float:
        """Decode JWT exp claim client-side. Returns seconds-from-issuance
        (i.e. the token's nominal lifetime). Signature is not verified — we
        only use this to schedule refresh, never for access decisions.

        Falls back to 15 minutes on any parse failure: matches Wazuh's
        documented default and is safer than assuming no expiry.
        """
        try:
            _header_b64, payload_b64, _sig_b64 = token.split(".", 2)
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
            exp = payload.get("exp")
            iat = payload.get("iat", time.time())
            if not isinstance(exp, int | float):
                return 900.0
            lifetime = float(exp) - float(iat)
            if lifetime <= 0:
                return 900.0
            return lifetime
        except Exception:
            return 900.0
```

- [ ] **Step 7.4: Re-run the initial test**

Run: `uv run pytest tests/unit/test_server_api.py::test_mint_on_first_call -v`
Expected: PASS.

- [ ] **Step 7.5: Add tests for proactive refresh + run_as params + no-leak repr**

Append to `tests/unit/test_server_api.py`:

```python
@pytest.mark.asyncio
async def test_reuse_valid_token(httpx_mock):
    """A fresh token is reused for a second call made within lifetime budget."""
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "001"}]}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "002"}]}},
    )

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        a = await client.get("/agents")
        b = await client.get("/agents")
    finally:
        await client.aclose()
    assert a["data"]["affected_items"][0]["id"] == "001"
    assert b["data"]["affected_items"][0]["id"] == "002"

    # Only one mint for two calls
    mint_calls = [r for r in httpx_mock.get_requests() if r.url.path == "/security/user/authenticate"]
    assert len(mint_calls) == 1


@pytest.mark.asyncio
async def test_run_as_param_added_to_query(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Register a response keyed on the URL with run_as — pytest-httpx matches by URL substring.
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?run_as=alice",
        method="GET",
        json={"data": {"affected_items": []}},
    )

    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        await client.get("/agents", run_as="alice")
    finally:
        await client.aclose()

    # Confirm the request that was sent included run_as=alice
    request_urls = [r.url for r in httpx_mock.get_requests() if r.url.path == "/agents"]
    assert any("run_as=alice" in str(u) for u in request_urls)


@pytest.mark.asyncio
async def test_repr_redacts_token_and_credentials():
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("mcp-secret"),
        verify_tls=False,
    )
    try:
        r = repr(client)
        assert "mcp-secret" not in r
        assert "wazuh-wui" not in r
        assert "token=<redacted>" in r
    finally:
        await client.aclose()
```

- [ ] **Step 7.6: Run the full ServerApiClient test suite + lint**

Run: `uv run pytest tests/unit/test_server_api.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 4 tests pass; all checks passed.

- [ ] **Step 7.7: Commit**

```bash
git add src/wazuh_mcp/wazuh/server_api.py tests/unit/test_server_api.py
git commit -m "Add ServerApiClient with JWT mint, proactive refresh, run_as, and retry-once"
```

---

## Task 8: `ServerApiClient` — security-negatives suite [A]

**Tier A:** Negative-path coverage of the new client.

**Files:**
- Create: `tests/unit/test_server_api_negatives.py`

- [ ] **Step 8.1: Write the negative-path tests**

Create `tests/unit/test_server_api_negatives.py`:

```python
"""ServerApiClient security-negatives — paths that should never leak or loop."""

import asyncio
import base64
import json
import time

import httpx
import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "exp": int(time.time()) + exp_offset_s,
                "iat": int(time.time()),
                "sub": "mcp",
            }
        ).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


def _build_client() -> ServerApiClient:
    return ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("hunter2"),
        verify_tls=False,
    )


@pytest.mark.asyncio
async def test_401_twice_raises_auth_expired_not_loop(httpx_mock):
    """Both the initial request and the retry return 401: surface auth_expired,
    do NOT enter an infinite mint/retry loop.
    """
    # First mint (before the initial request)
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Initial request — 401
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=401,
    )
    # Second mint (after the 401 on /agents)
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Replay — also 401
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=401,
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "auth_expired"


@pytest.mark.asyncio
async def test_429_is_rate_limited(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        status_code=429,
        headers={"Retry-After": "30"},
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "rate_limited"


@pytest.mark.asyncio
async def test_concurrent_mint_is_serialised(httpx_mock):
    """Two concurrent requests on a client with no token trigger exactly one mint —
    the asyncio.Lock prevents a mint stampede.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # Two distinct responses on the same /agents URL so pytest-httpx hands them out in order
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "001"}]}},
    )
    httpx_mock.add_response(
        url="https://manager.example:55000/agents",
        method="GET",
        json={"data": {"affected_items": [{"id": "002"}]}},
    )

    client = _build_client()
    try:
        r1, r2 = await asyncio.gather(
            client.get("/agents"),
            client.get("/agents"),
        )
    finally:
        await client.aclose()

    assert {r1["data"]["affected_items"][0]["id"], r2["data"]["affected_items"][0]["id"]} == {
        "001",
        "002",
    }
    mint_calls = [
        r for r in httpx_mock.get_requests() if r.url.path == "/security/user/authenticate"
    ]
    assert len(mint_calls) == 1, "mint stampede — expected exactly one mint"


@pytest.mark.asyncio
async def test_mint_401_leaks_nothing(httpx_mock):
    """Bad basic-auth creds return 401 on mint. The raised error must not
    contain the credentials, the response body, or the Authorization header.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        status_code=401,
        text="bad credentials: wazuh-wui / hunter2",
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    err = exc_info.value
    assert err.code == "auth_expired"
    assert "hunter2" not in str(err)
    assert "hunter2" not in repr(err)
    assert "wazuh-wui" not in str(err)


@pytest.mark.asyncio
async def test_timeout_becomes_upstream_timeout(httpx_mock):
    # First mint succeeds
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    # /agents times out
    httpx_mock.add_exception(httpx.TimeoutException("read timeout"))

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "upstream_timeout"


@pytest.mark.asyncio
async def test_malformed_mint_response_is_upstream_error(httpx_mock):
    """Mint returns 200 but no token in body — surface upstream_error, not a
    KeyError or TypeError that would leak the response body.
    """
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {}},  # no token
    )

    client = _build_client()
    try:
        with pytest.raises(WazuhError) as exc_info:
            await client.get("/agents")
    finally:
        await client.aclose()
    assert exc_info.value.code == "upstream_error"
```

- [ ] **Step 8.2: Run negative-path tests**

Run: `uv run pytest tests/unit/test_server_api_negatives.py -v`
Expected: 6 tests pass.

- [ ] **Step 8.3: Commit**

```bash
git add tests/unit/test_server_api_negatives.py
git commit -m "Add ServerApiClient security-negatives suite"
```

---

## Task 9: `ServerApiClientPool` [B]

**Tier B:** Structurally mirrors `IndexerClientPool` (reviewed in M2).

**Files:**
- Create: `src/wazuh_mcp/wazuh/server_api_pool.py`
- Create: `tests/unit/test_server_api_pool.py`

- [ ] **Step 9.1: Create the pool module**

Create `src/wazuh_mcp/wazuh/server_api_pool.py`:

```python
"""Per-tenant pool for ServerApiClient. Mirrors IndexerClientPool.

Lazy, server-lifetime, idempotent close. Pool entries are keyed by
tenant_id and shared across concurrent requests for the same tenant.
"""

from __future__ import annotations

import asyncio

from wazuh_mcp.secrets.store import SecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import TenantRegistry
from wazuh_mcp.wazuh.server_api import ServerApiClient


class ServerApiClientPool:
    def __init__(self, *, registry: TenantRegistry, secrets: SecretStore) -> None:
        self._registry = registry
        self._secrets = secrets
        self._clients: dict[str, ServerApiClient] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def acquire(self, tenant_id: str) -> ServerApiClient:
        async with self._lock:
            if self._closed:
                raise RuntimeError("ServerApiClientPool closed")
            existing = self._clients.get(tenant_id)
            if existing is not None:
                return existing
            tenant: TenantConfig = self._registry.get(tenant_id)
            user = await self._secrets.get(tenant_id, "server_api_user")
            password = await self._secrets.get(tenant_id, "server_api_password")
            # Server API lives alongside the indexer in practice. TenantConfig
            # carries indexer_url; Server API base defaults to the same host
            # on port 55000 unless overridden via server_api_url (future).
            base_url = self._derive_server_api_url(tenant)
            client = ServerApiClient(
                base_url=base_url,
                user=user,
                password=password,
                verify_tls=tenant.verify_tls,
                ca_bundle_path=tenant.ca_bundle_path,
            )
            self._clients[tenant_id] = client
            return client

    async def aclose(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            for client in self._clients.values():
                await client.aclose()
            self._clients.clear()

    @staticmethod
    def _derive_server_api_url(tenant: TenantConfig) -> str:
        # Derive Server API base from indexer_url by swapping port 9200 → 55000.
        # Operators with a non-standard deployment can override via a future
        # TenantConfig.server_api_url field (out of scope for M3).
        u = str(tenant.indexer_url).rstrip("/")
        # Simple substring swap is safe because the indexer always uses 9200.
        if ":9200" in u:
            return u.replace(":9200", ":55000")
        # No explicit port — append 55000 on the same host.
        return u + ":55000"
```

- [ ] **Step 9.2: Write tests**

Create `tests/unit/test_server_api_pool.py`:

```python
"""ServerApiClientPool — per-tenant lazy-init and close semantics."""

import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.wazuh.server_api_pool import ServerApiClientPool


class _FakeRegistry:
    def __init__(self, tenants: dict[str, TenantConfig]) -> None:
        self._tenants = tenants

    def get(self, tenant_id: str) -> TenantConfig:
        return self._tenants[tenant_id]


class _FakeSecrets:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        self.calls.append((tenant_id, key))
        return SecretValue(f"{tenant_id}:{key}")


def _tenant(tenant_id: str, url: str = "https://wazuh.example:9200") -> TenantConfig:
    return TenantConfig.model_validate(
        {
            "tenant_id": tenant_id,
            "indexer_url": url,
            "default_rbac_role": "soc_analyst",
        }
    )


@pytest.mark.asyncio
async def test_acquire_is_lazy_and_idempotent():
    registry = _FakeRegistry({"a": _tenant("a")})
    secrets = _FakeSecrets()
    pool = ServerApiClientPool(registry=registry, secrets=secrets)
    try:
        c1 = await pool.acquire("a")
        c2 = await pool.acquire("a")
    finally:
        await pool.aclose()

    assert c1 is c2
    assert secrets.calls == [
        ("a", "server_api_user"),
        ("a", "server_api_password"),
    ]


@pytest.mark.asyncio
async def test_acquire_raises_after_close():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({"a": _tenant("a")}),
        secrets=_FakeSecrets(),
    )
    await pool.aclose()
    with pytest.raises(RuntimeError, match="closed"):
        await pool.acquire("a")


@pytest.mark.asyncio
async def test_aclose_is_idempotent():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({"a": _tenant("a")}),
        secrets=_FakeSecrets(),
    )
    await pool.aclose()
    await pool.aclose()  # must not raise


@pytest.mark.asyncio
async def test_derive_server_api_url_swaps_9200_to_55000():
    pool = ServerApiClientPool(
        registry=_FakeRegistry({}),
        secrets=_FakeSecrets(),
    )
    tenant = _tenant("t", url="https://wazuh.example:9200")
    assert pool._derive_server_api_url(tenant) == "https://wazuh.example:55000"
```

- [ ] **Step 9.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_server_api_pool.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 4 tests pass; all checks passed.

- [ ] **Step 9.4: Commit**

```bash
git add src/wazuh_mcp/wazuh/server_api_pool.py tests/unit/test_server_api_pool.py
git commit -m "Add per-tenant ServerApiClientPool mirroring IndexerClientPool"
```

---

## Task 10: Rename `search_alerts` → `alerts.search_alerts` + flatten return shape [A]

**Tier A:** The existing tool's contract changes; every test referencing it updates; the baseline from which 13 new tools inherit.

**Files:**
- Modify: `src/wazuh_mcp/tools/alerts.py`
- Modify: `src/wazuh_mcp/server.py` (two places: `build_app` stdio wiring, `build_http_app` HTTP wiring)
- Modify: `tests/integration/test_search_alerts_e2e.py`
- Modify: `tests/unit/test_tool_search_alerts.py` (if exists from M1/M2; rename if needed)

- [ ] **Step 10.1: Define the flat result model**

Open `src/wazuh_mcp/tools/alerts.py`. Replace the entire file with:

```python
"""alerts.* tools — search, get-by-id, by-agent, by-mitre.

Pattern every M3 tool follows:
  1. Validate args (strict Pydantic, extra=forbid).
  2. Build server-side DSL via wazuh/query.py — never accept raw DSL.
  3. Call indexer.
  4. Map hits → strict Pydantic models.
  5. Return a Pydantic result model; FastMCP auto-promotes to structuredContent.
  6. Audit every exit path.

Authored text summaries are intentionally absent — Claude generates better
summaries from structured data than hand-authored strings.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Alert
from wazuh_mcp.wazuh.query import build_search_alerts_query


class SearchAlertsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time_range: Annotated[
        str, Field(description="Relative lookback, e.g. '1h', '24h', '7d'")
    ] = "1h"
    min_level: Annotated[
        int | None, Field(ge=0, le=15, description="Minimum rule.level")
    ] = None
    agent_id: Annotated[
        str | None, Field(description="Filter to a single agent.id")
    ] = None
    size: Annotated[
        int, Field(ge=1, le=100, description="Max alerts to return (hard cap 100)")
    ] = 25
    cursor: Annotated[
        list[Any] | None, Field(description="Opaque search_after cursor from prior call")
    ] = None


class SearchAlertsResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alerts: list[Alert]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def search_alerts(
    *,
    args: SearchAlertsArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> SearchAlertsResult:
    """Tool name: alerts.search_alerts (registered in server.py).

    Returns a flat Pydantic model — FastMCP promotes it to CallToolResult's
    structuredContent directly. No handler-side text summary.
    """
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)

    try:
        query = build_search_alerts_query(
            time_range=args.time_range,
            min_level=args.min_level,
            agent_id=args.agent_id,
            size=args.size,
            cursor=args.cursor,
        )
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="alerts.search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool="alerts.search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    try:
        raw_hits = body.get("hits", {}).get("hits", [])
        hits_block = body.get("hits", {})
        total_block = hits_block.get("total", {})
        total = (
            total_block.get("value", 0)
            if isinstance(total_block, dict)
            else int(total_block)
        )
        alerts = [Alert.from_hit(h) for h in raw_hits]
        next_cursor: list[Any] | None = None
        if raw_hits and "sort" in raw_hits[-1]:
            next_cursor = raw_hits[-1]["sort"]
        truncated = len(alerts) == args.size
    except Exception:
        audit.emit(
            session=session,
            tool="alerts.search_alerts",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="parse_error",
        )
        raise

    audit.emit(
        session=session,
        tool="alerts.search_alerts",
        args=arg_dict,
        outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )

    return SearchAlertsResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
```

The `_summarise` helper is gone. The return dict with `structuredContent` / `text` keys is gone. The function's return annotation is now `SearchAlertsResult`.

- [ ] **Step 10.2: Update `server.py` tool registrations**

Open `src/wazuh_mcp/server.py`. There are TWO tool registrations for `search_alerts` — one in `build_app` (stdio) and one in `build_http_app` (HTTP). Both need to:
1. Change the registered name to `alerts.search_alerts`.
2. Pass `meta={"toolset": "alerts"}`.
3. Return the Pydantic model directly (FastMCP will promote).

Replace both `@app.tool(name="search_alerts", ...)` blocks with:

```python
    @app.tool(
        name="alerts.search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
        meta={"toolset": "alerts"},
    )
```

And update the function body's `return` statement to:

```python
        return await search_alerts(
            args=args,
            session=session,
            indexer=indexer,
            audit=audit_emitter,
        )
```

(Previously returned a dict; now returns `SearchAlertsResult`. FastMCP unwraps Pydantic models into structuredContent.)

- [ ] **Step 10.3: Update integration tests that assert the old shape**

Open `tests/integration/test_search_alerts_e2e.py`. Update assertions:

```python
@pytest.mark.integration
async def test_search_alerts_returns_seeded_data(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="24h"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    # result is now SearchAlertsResult, not a dict.
    assert result.total >= 5
    assert len(result.alerts) >= 1
    assert result.next_cursor is not None


@pytest.mark.integration
async def test_search_alerts_min_level_filters(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", min_level=12),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    for alert in result.alerts:
        assert alert.rule.level >= 12


@pytest.mark.integration
async def test_search_alerts_cursor_paginates(session, audit, indexer):
    first = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", size=5),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    cursor = first.next_cursor
    assert cursor is not None

    second = await search_alerts(
        args=SearchAlertsArgs(time_range="24h", size=5, cursor=cursor),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    first_ids = {a.id for a in first.alerts}
    second_ids = {a.id for a in second.alerts}
    assert first_ids.isdisjoint(second_ids), "pagination returned overlapping alerts"
```

- [ ] **Step 10.4: Update unit test for `search_alerts` return shape**

Find the M1/M2 unit test file: `grep -l 'def test_search_alerts' tests/unit/`

For every assertion like `result["structuredContent"]["alerts"]`, replace with `result.alerts`. For `result["text"]` assertions, delete them (no more authored summary).

Run: `grep -rn 'structuredContent\|_summarise' tests/unit/ src/wazuh_mcp/tools/alerts.py`
Expected: zero matches in `tools/alerts.py`; any remaining matches in `tests/unit/` are updates needed.

- [ ] **Step 10.5: Run unit + integration suites**

Run: `uv run pytest -q 2>&1 | tail -5`
Expected: all 180+ tests pass. (No new tests in this task — it's a rename + shape flatten.)

Run: `uv run pytest -m integration -v 2>&1 | tail -10`
Expected: 9/9 integration tests pass (the OAuth SDK migration from Task 6 + the renamed tool).

- [ ] **Step 10.6: Commit**

```bash
git add src/wazuh_mcp/tools/alerts.py src/wazuh_mcp/server.py tests/
git commit -m "Rename search_alerts → alerts.search_alerts and flatten return shape

Returns SearchAlertsResult (Pydantic) directly; FastMCP promotes to
CallToolResult.structuredContent. Drops the authored text summary.
Tools registrations now carry meta={\"toolset\": \"alerts\"} for the
meta-annotated toolset scheme."
```

---

## Task 11: Extend `wazuh/models.py` — Agent, Vulnerability, FimEvent, MitreTechnique [B]

**Tier B:** Pure Pydantic; strict validation, reviewed via type-check.

**Files:**
- Modify: `src/wazuh_mcp/wazuh/models.py`
- Create: `tests/unit/test_models_m3.py`

- [ ] **Step 11.1: Add the four new models**

Append to `src/wazuh_mcp/wazuh/models.py`:

```python
class Agent(BaseModel):
    """Wazuh agent — shape aligned with Server API /agents responses."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    name: str
    ip: str | None = None
    status: str | None = None  # active | disconnected | pending | never_connected
    os_platform: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    version: str | None = None
    group: list[str] = Field(default_factory=list)
    last_keep_alive: str | None = None
    date_add: str | None = None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> Agent:
        os_info = item.get("os") or {}
        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            ip=item.get("ip"),
            status=item.get("status"),
            os_platform=os_info.get("platform"),
            os_name=os_info.get("name"),
            os_version=os_info.get("version"),
            version=item.get("version"),
            group=list(item.get("group") or []),
            last_keep_alive=item.get("lastKeepAlive"),
            date_add=item.get("dateAdd"),
        )


class Vulnerability(BaseModel):
    """Wazuh 4.8+ vulnerability — sourced from the indexer.

    Field `id` is the CVE identifier (the 4.8+ rename from `cve`).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str  # CVE, e.g. "CVE-2024-1234"
    agent_id: str
    package_name: str
    package_version: str
    severity: str | None = None  # Critical | High | Medium | Low | Unknown
    cvss3_score: float | None = None
    published: str | None = None
    detected_at: str | None = None
    status: str | None = None  # Active | Solved

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> Vulnerability:
        src = hit.get("_source") or {}
        vuln = src.get("vulnerability") or {}
        pkg = src.get("package") or {}
        agent = src.get("agent") or {}
        cvss = (vuln.get("scores") or {}).get("base", {})
        return cls(
            id=str(vuln.get("id") or ""),
            agent_id=str(agent.get("id") or ""),
            package_name=str(pkg.get("name") or ""),
            package_version=str(pkg.get("version") or ""),
            severity=vuln.get("severity"),
            cvss3_score=cvss.get("score"),
            published=vuln.get("published_at"),
            detected_at=vuln.get("detected_at"),
            status=vuln.get("status"),
        )


class FimEvent(BaseModel):
    """File-integrity-monitoring event — from `wazuh-alerts-*` (rule groups
    include `syscheck` and friends).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    agent_id: str
    timestamp: str
    path: str
    event: str | None = None  # added | modified | deleted
    sha256_after: str | None = None
    md5_after: str | None = None
    size_after: int | None = None
    uid_after: str | None = None
    gid_after: str | None = None

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> FimEvent:
        src = hit.get("_source") or {}
        syscheck = src.get("syscheck") or {}
        agent = src.get("agent") or {}
        return cls(
            agent_id=str(agent.get("id") or ""),
            timestamp=str(src.get("timestamp") or ""),
            path=str(syscheck.get("path") or ""),
            event=syscheck.get("event"),
            sha256_after=syscheck.get("sha256_after"),
            md5_after=syscheck.get("md5_after"),
            size_after=syscheck.get("size_after"),
            uid_after=syscheck.get("uid_after"),
            gid_after=syscheck.get("gid_after"),
        )


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique reference — sourced from Wazuh's bundled MITRE
    dataset via the Server API (/mitre/techniques).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str  # e.g. "T1110.001"
    name: str
    description: str | None = None
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> MitreTechnique:
        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            description=item.get("description"),
            tactics=list(item.get("tactics") or []),
            url=item.get("url"),
        )
```

- [ ] **Step 11.2: Write model tests**

Create `tests/unit/test_models_m3.py`:

```python
"""M3 Pydantic model tests — Agent, Vulnerability, FimEvent, MitreTechnique."""

from pydantic import ValidationError
import pytest

from wazuh_mcp.wazuh.models import (
    Agent,
    FimEvent,
    MitreTechnique,
    Vulnerability,
)


def test_agent_from_api_minimal():
    a = Agent.from_api({"id": "001", "name": "web-01"})
    assert a.id == "001"
    assert a.name == "web-01"
    assert a.group == []


def test_agent_from_api_full():
    a = Agent.from_api(
        {
            "id": "001",
            "name": "web-01",
            "ip": "10.0.0.5",
            "status": "active",
            "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "22.04"},
            "version": "Wazuh v4.9.0",
            "group": ["default", "linux"],
            "lastKeepAlive": "2026-04-22T00:00:00Z",
            "dateAdd": "2024-01-01T00:00:00Z",
        }
    )
    assert a.ip == "10.0.0.5"
    assert a.os_platform == "ubuntu"
    assert a.group == ["default", "linux"]


def test_agent_frozen():
    a = Agent.from_api({"id": "001", "name": "w"})
    with pytest.raises(ValidationError):
        a.id = "002"  # type: ignore[misc]


def test_vulnerability_uses_id_not_cve():
    """4.8+ field rename: vulnerability.cve → vulnerability.id."""
    v = Vulnerability.from_hit(
        {
            "_source": {
                "agent": {"id": "001"},
                "package": {"name": "openssl", "version": "3.0.0"},
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "scores": {"base": {"score": 7.5}},
                    "published_at": "2024-06-01T00:00:00Z",
                    "status": "Active",
                },
            }
        }
    )
    assert v.id == "CVE-2024-1234"
    assert v.severity == "High"
    assert v.cvss3_score == 7.5


def test_fim_event_from_hit():
    ev = FimEvent.from_hit(
        {
            "_source": {
                "agent": {"id": "001"},
                "timestamp": "2026-04-22T00:00:00Z",
                "syscheck": {
                    "path": "/etc/passwd",
                    "event": "modified",
                    "sha256_after": "abc123",
                },
            }
        }
    )
    assert ev.path == "/etc/passwd"
    assert ev.event == "modified"
    assert ev.sha256_after == "abc123"


def test_mitre_technique_from_api():
    t = MitreTechnique.from_api(
        {
            "id": "T1110.001",
            "name": "Password Guessing",
            "description": "...",
            "tactics": ["Credential Access"],
            "url": "https://attack.mitre.org/techniques/T1110/001/",
        }
    )
    assert t.id == "T1110.001"
    assert t.tactics == ["Credential Access"]
```

- [ ] **Step 11.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_models_m3.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 6 tests pass; all checks passed.

- [ ] **Step 11.4: Commit**

```bash
git add src/wazuh_mcp/wazuh/models.py tests/unit/test_models_m3.py
git commit -m "Add Agent, Vulnerability, FimEvent, MitreTechnique Pydantic models"
```

---

## Task 12: Extend `wazuh/query.py` with M3 query builders [A]

**Tier A:** Query builders are the single-point enforcement of size caps, time clamping, and field-name safety for the indexer path.

**Files:**
- Modify: `src/wazuh_mcp/wazuh/query.py`
- Create: `tests/unit/test_query_builders_m3.py`

- [ ] **Step 12.1: Add new builders**

Append to `src/wazuh_mcp/wazuh/query.py`:

```python
DEFAULT_VULN_FIELDS: Final[list[str]] = [
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.scores.base.score",
    "vulnerability.published_at",
    "vulnerability.detected_at",
    "vulnerability.status",
    "package.name",
    "package.version",
    "agent.id",
    "timestamp",
    "@timestamp",
]

DEFAULT_FIM_FIELDS: Final[list[str]] = [
    "agent.id",
    "timestamp",
    "@timestamp",
    "syscheck.path",
    "syscheck.event",
    "syscheck.sha256_after",
    "syscheck.md5_after",
    "syscheck.size_after",
    "syscheck.uid_after",
    "syscheck.gid_after",
]


def build_get_alert_query(alert_id: str) -> dict[str, Any]:
    """Fetch a single alert by its document id via /wazuh-alerts-*/_search."""
    if not alert_id or any(c in alert_id for c in "/\\"):
        raise ValueError("invalid alert_id")
    return {
        "query": {"term": {"_id": alert_id}},
        "size": 1,
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": 10,
    }


def build_alerts_by_agent_query(
    *,
    agent_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"agent.id": agent_id}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_alerts_by_mitre_query(
    *,
    technique_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _MITRE_ID_RE.match(technique_id):
        raise ValueError("invalid technique_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"rule.mitre.id": technique_id}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_vulnerabilities_by_agent_query(
    *,
    agent_id: str,
    min_severity: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    must: list[dict[str, Any]] = [{"term": {"agent.id": agent_id}}]
    if min_severity is not None:
        sev = min_severity.capitalize()
        if sev not in _SEVERITIES:
            raise ValueError(f"invalid severity: {min_severity!r}")
        # Severity is an enum; map to a "gte" via a prebuilt rank field if
        # present, otherwise filter by membership in the rank set.
        allowed = _SEVERITIES[_SEVERITIES.index(sev):]
        must.append({"terms": {"vulnerability.severity": allowed}})
    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"vulnerability.detected_at": "desc"}],
        "_source": DEFAULT_VULN_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_search_vulnerabilities_query(
    *,
    cve_id: str | None = None,
    min_severity: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if cve_id is None and min_severity is None:
        raise ValueError("at least one of cve_id or min_severity must be set")
    must: list[dict[str, Any]] = []
    if cve_id is not None:
        if not _CVE_ID_RE.match(cve_id):
            raise ValueError("invalid cve_id")
        must.append({"term": {"vulnerability.id": cve_id}})
    if min_severity is not None:
        sev = min_severity.capitalize()
        if sev not in _SEVERITIES:
            raise ValueError(f"invalid severity: {min_severity!r}")
        allowed = _SEVERITIES[_SEVERITIES.index(sev):]
        must.append({"terms": {"vulnerability.severity": allowed}})
    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"vulnerability.detected_at": "desc"}],
        "_source": DEFAULT_VULN_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_fim_history_for_path_query(
    *,
    path: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not path or len(path) > 1024:
        raise ValueError("invalid path")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"syscheck.path": path}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_FIM_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query


def build_fim_changes_by_agent_query(
    *,
    agent_id: str,
    time_range: str,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")
    _validate_time_range(time_range)
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"agent.id": agent_id}},
                    {"exists": {"field": "syscheck.path"}},
                ]
            }
        },
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_FIM_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor:
        query["search_after"] = cursor
    return query
```

Also add these regex + constants near the existing `_TIME_RANGE_RE` declaration:

```python
_AGENT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]{3,10}$")
_MITRE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
_CVE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_SEVERITIES: Final[list[str]] = ["Low", "Medium", "High", "Critical"]
```

- [ ] **Step 12.2: Write builder tests**

Create `tests/unit/test_query_builders_m3.py`:

```python
"""M3 query-builder tests — validation + clamping + time/size caps."""

import pytest

from wazuh_mcp.wazuh.query import (
    build_alerts_by_agent_query,
    build_alerts_by_mitre_query,
    build_fim_changes_by_agent_query,
    build_fim_history_for_path_query,
    build_get_alert_query,
    build_search_vulnerabilities_query,
    build_vulnerabilities_by_agent_query,
)


def test_get_alert_rejects_path_traversal():
    with pytest.raises(ValueError):
        build_get_alert_query("../evil")


def test_get_alert_shape():
    q = build_get_alert_query("abc123")
    assert q["query"]["term"]["_id"] == "abc123"
    assert q["size"] == 1


def test_alerts_by_agent_clamps_size():
    q = build_alerts_by_agent_query(agent_id="001", time_range="1h", size=500)
    assert q["size"] == 100  # MAX_ALERT_SIZE


def test_alerts_by_agent_rejects_bad_id():
    with pytest.raises(ValueError):
        build_alerts_by_agent_query(agent_id="0x01", time_range="1h")


def test_alerts_by_mitre_rejects_bad_technique():
    with pytest.raises(ValueError):
        build_alerts_by_mitre_query(technique_id="not-a-technique", time_range="1h")


def test_alerts_by_mitre_shape():
    q = build_alerts_by_mitre_query(technique_id="T1110.001", time_range="24h")
    must = q["query"]["bool"]["must"]
    assert {"term": {"rule.mitre.id": "T1110.001"}} in must


def test_vulns_by_agent_severity_filter_gte():
    q = build_vulnerabilities_by_agent_query(agent_id="001", min_severity="Medium")
    terms = next(
        c for c in q["query"]["bool"]["must"] if "terms" in c
    )
    assert terms["terms"]["vulnerability.severity"] == ["Medium", "High", "Critical"]


def test_vulns_by_agent_rejects_bad_severity():
    with pytest.raises(ValueError):
        build_vulnerabilities_by_agent_query(agent_id="001", min_severity="Catastrophic")


def test_search_vulns_requires_at_least_one_filter():
    with pytest.raises(ValueError):
        build_search_vulnerabilities_query()


def test_search_vulns_cve_format_enforced():
    with pytest.raises(ValueError):
        build_search_vulnerabilities_query(cve_id="2024-1234")
    # well-formed goes through
    q = build_search_vulnerabilities_query(cve_id="CVE-2024-1234")
    assert {"term": {"vulnerability.id": "CVE-2024-1234"}} in q["query"]["bool"]["must"]


def test_fim_history_rejects_empty_path():
    with pytest.raises(ValueError):
        build_fim_history_for_path_query(path="", time_range="24h")


def test_fim_history_rejects_huge_path():
    with pytest.raises(ValueError):
        build_fim_history_for_path_query(path="A" * 2048, time_range="24h")


def test_fim_changes_by_agent_shape():
    q = build_fim_changes_by_agent_query(agent_id="001", time_range="24h")
    must = q["query"]["bool"]["must"]
    # Has the syscheck.path exists clause
    assert any(c == {"exists": {"field": "syscheck.path"}} for c in must)
```

- [ ] **Step 12.3: Run tests + lint**

Run: `uv run pytest tests/unit/test_query_builders_m3.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 13 tests pass; all checks passed.

- [ ] **Step 12.4: Commit**

```bash
git add src/wazuh_mcp/wazuh/query.py tests/unit/test_query_builders_m3.py
git commit -m "Add M3 query builders: alerts, vulns, FIM with strict input validation"
```

---

## Task 13: `alerts.*` — get_alert + alerts_by_agent + alerts_by_mitre [B]

**Tier B batch:** Three mechanical tools that share the alerts-query pattern. One implementer dispatch, three commits.

**Files:**
- Modify: `src/wazuh_mcp/tools/alerts.py` (append new tool functions + result models)
- Create: `tests/unit/test_tool_alerts_m3.py`

- [ ] **Step 13.1: Add `get_alert` — the not-found-aware single-doc fetch**

Append to `src/wazuh_mcp/tools/alerts.py`:

```python
from wazuh_mcp.wazuh.query import (
    build_alerts_by_agent_query,
    build_alerts_by_mitre_query,
    build_get_alert_query,
)
from wazuh_mcp.wazuh.errors import SAFE_CODES, WazuhError  # SAFE_CODES already imported above
# NOTE: the line above is an example of the *imports to add* — remove/merge
# with the existing `from ... errors import WazuhError` import at the top of
# the file. No duplicate imports.


class GetAlertArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: Annotated[str, Field(min_length=1, max_length=128)]


class GetAlertResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alert: Alert


async def get_alert(
    *,
    args: GetAlertArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> GetAlertResult:
    """Tool name: alerts.get_alert."""
    started = time.monotonic()
    arg_dict = args.model_dump()

    try:
        query = build_get_alert_query(args.alert_id)
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="alerts.get_alert",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool="alerts.get_alert",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    hits = body.get("hits", {}).get("hits", [])
    if not hits:
        audit.emit(
            session=session,
            tool="alerts.get_alert",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="not_found",
        )
        raise WazuhError("not_found", "alert not found", 404)

    alert = Alert.from_hit(hits[0])
    audit.emit(
        session=session,
        tool="alerts.get_alert",
        args=arg_dict,
        outcome="ok",
        result_count=1,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return GetAlertResult(alert=alert)
```

- [ ] **Step 13.2: Add `alerts_by_agent` and `alerts_by_mitre`**

These share the `SearchAlertsResult` shape since both are filtered searches over `wazuh-alerts-*`.

```python
class AlertsByAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: Annotated[list[Any] | None, Field()] = None


async def alerts_by_agent(
    *,
    args: AlertsByAgentArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> SearchAlertsResult:
    """Tool name: alerts.alerts_by_agent."""
    return await _filtered_alerts_search(
        tool_name="alerts.alerts_by_agent",
        build_query=lambda: build_alerts_by_agent_query(
            agent_id=args.agent_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


class AlertsByMitreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: Annotated[str, Field(min_length=4, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: Annotated[list[Any] | None, Field()] = None


async def alerts_by_mitre(
    *,
    args: AlertsByMitreArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> SearchAlertsResult:
    """Tool name: alerts.alerts_by_mitre."""
    return await _filtered_alerts_search(
        tool_name="alerts.alerts_by_mitre",
        build_query=lambda: build_alerts_by_mitre_query(
            technique_id=args.technique_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def _filtered_alerts_search(
    *,
    tool_name: str,
    build_query,
    args_dict: dict[str, Any],
    wanted_size: int,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> SearchAlertsResult:
    """Shared path for alerts-index filtered searches — same auditing and
    error-mapping contract as search_alerts().
    """
    started = time.monotonic()
    try:
        query = build_query()
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == wanted_size

    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return SearchAlertsResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
```

- [ ] **Step 13.3: Write unit tests**

Create `tests/unit/test_tool_alerts_m3.py`:

```python
"""Unit tests for the new M3 alerts tools (get_alert, by_agent, by_mitre)."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.alerts import (
    AlertsByAgentArgs,
    AlertsByMitreArgs,
    GetAlertArgs,
    alerts_by_agent,
    alerts_by_mitre,
    get_alert,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_get_alert_happy_path(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "hits": [
                    {
                        "_id": "abc",
                        "_source": {
                            "timestamp": "2026-04-22T00:00:00Z",
                            "agent": {"id": "001", "name": "web-01"},
                            "rule": {
                                "id": "100",
                                "level": 10,
                                "description": "test",
                            },
                        },
                    }
                ]
            }
        },
    )
    result = await get_alert(
        args=GetAlertArgs(alert_id="abc"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.alert.id == "abc"


@pytest.mark.asyncio
async def test_get_alert_not_found(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"hits": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_alert(
            args=GetAlertArgs(alert_id="missing"),
            session=session,
            indexer=indexer,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_alerts_by_agent_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {
                        "_id": "a1",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {"id": "1", "level": 3, "description": "x"},
                        },
                        "sort": [1],
                    },
                    {
                        "_id": "a2",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {"id": "2", "level": 3, "description": "y"},
                        },
                        "sort": [2],
                    },
                ],
            }
        },
    )
    result = await alerts_by_agent(
        args=AlertsByAgentArgs(agent_id="001", time_range="24h", size=2),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 2
    assert result.truncated is True
    assert result.next_cursor == [2]


@pytest.mark.asyncio
async def test_alerts_by_mitre_rejects_bad_technique_id(session, audit, indexer):
    with pytest.raises(ValueError):
        await alerts_by_mitre(
            args=AlertsByMitreArgs(technique_id="NOT_VALID", time_range="24h"),
            session=session,
            indexer=indexer,
            audit=audit,
        )
```

- [ ] **Step 13.4: Run unit tests + lint**

Run: `uv run pytest tests/unit/test_tool_alerts_m3.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 4 tests pass; all checks passed.

- [ ] **Step 13.5: Commit**

```bash
git add src/wazuh_mcp/tools/alerts.py tests/unit/test_tool_alerts_m3.py
git commit -m "Add alerts.get_alert, alerts.alerts_by_agent, alerts.alerts_by_mitre"
```

---

## Task 14: `hunt.hunt_query` — the constrained hunt grammar [A]

**Tier A:** Security-critical user-authored-query tool. Requires both unit tests AND the hypothesis fuzz tests (next task).

**Files:**
- Create: `src/wazuh_mcp/tools/hunt.py`
- Create: `tests/unit/test_tool_hunt.py`

- [ ] **Step 14.1: Create the tool module**

Create `src/wazuh_mcp/tools/hunt.py`:

```python
"""hunt.* tools — constrained-grammar hunting + IOC pivot preset.

Security posture:
- Field names come from a fixed FIELD_ALLOWLIST. Anything off the list
  raises ValidationError before a DSL dict is constructed.
- Ops come from OP_ALLOWLIST. No `script`, `runtime_mappings`,
  `script_score`, `painless`, or raw `bool.should` can be reached by
  construction — those aren't ops.
- Flat must + must_not only (no nested bool).
- Clause count capped at 20; in-op value-list capped at 100; prefix op
  values require >=3 chars to prevent full-index scans.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Alert
from wazuh_mcp.wazuh.query import (
    DEFAULT_ALERT_FIELDS,
    DEFAULT_ALERT_SIZE,
    MAX_ALERT_SIZE,
    TERMINATE_AFTER,
    _validate_time_range,
)

FIELD_ALLOWLIST: Final[frozenset[str]] = frozenset(
    [
        # agent identity
        "agent.id",
        "agent.name",
        "agent.ip",
        # rule
        "rule.id",
        "rule.level",
        "rule.groups",
        "rule.mitre.id",
        "rule.mitre.tactic",
        # commonly-hunted fields
        "location",
        "decoder.name",
        "full_log",
        "data.srcip",
        "data.dstip",
        "data.srcuser",
        "data.dstuser",
        "data.srcport",
        "data.dstport",
        "data.url",
        "data.hostname",
        # syscheck
        "syscheck.path",
        "syscheck.sha256_after",
        "syscheck.md5_after",
        # timestamps
        "timestamp",
        "@timestamp",
    ]
)

OP_ALLOWLIST: Final[tuple[str, ...]] = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "exists",
    "prefix",
)

_MAX_CLAUSES: Final[int] = 20
_MAX_IN_LENGTH: Final[int] = 100
_MIN_PREFIX_LENGTH: Final[int] = 3


class HuntClause(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "exists", "prefix"]
    value: str | int | float | bool | list[str | int | float]

    @field_validator("field")
    @classmethod
    def _field_in_allowlist(cls, v: str) -> str:
        if v not in FIELD_ALLOWLIST:
            raise ValueError(f"field not allowed: {v!r}")
        return v

    @model_validator(mode="after")
    def _op_value_consistency(self) -> HuntClause:
        if self.op == "in":
            if not isinstance(self.value, list):
                raise ValueError("op='in' requires a list value")
            if len(self.value) == 0 or len(self.value) > _MAX_IN_LENGTH:
                raise ValueError(
                    f"'in' value must have 1..{_MAX_IN_LENGTH} items"
                )
        elif self.op == "exists":
            # `exists` ignores value; reject values other than True for clarity.
            if self.value is not True:
                raise ValueError("op='exists' requires value=true")
        elif self.op == "prefix":
            if not isinstance(self.value, str) or len(self.value) < _MIN_PREFIX_LENGTH:
                raise ValueError(
                    f"op='prefix' requires a string ≥{_MIN_PREFIX_LENGTH} chars"
                )
        else:
            if isinstance(self.value, list):
                raise ValueError(f"op={self.op!r} does not accept a list value")
        return self


class HuntQueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time_range: Annotated[str, Field(description="'<int><m|h|d>', ≤30d")]
    must: list[HuntClause]
    must_not: list[HuntClause] = Field(default_factory=list)
    size: Annotated[int, Field(ge=1, le=MAX_ALERT_SIZE)] = DEFAULT_ALERT_SIZE
    cursor: list[Any] | None = None

    @field_validator("time_range")
    @classmethod
    def _check_time_range(cls, v: str) -> str:
        _validate_time_range(v)
        return v

    @model_validator(mode="after")
    def _clause_cap(self) -> HuntQueryArgs:
        if len(self.must) + len(self.must_not) > _MAX_CLAUSES:
            raise ValueError(f"total clause count must be ≤ {_MAX_CLAUSES}")
        if len(self.must) == 0 and len(self.must_not) == 0:
            raise ValueError("at least one clause required")
        return self


class HuntQueryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alerts: list[Alert]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


def _render_clause(c: HuntClause) -> dict[str, Any]:
    """Render one HuntClause into a validated OpenSearch DSL fragment.

    Only produces `term`, `terms`, `range`, `exists`, `prefix` dicts. Never
    emits `script`, `runtime_mappings`, or nested bool.
    """
    if c.op == "eq":
        return {"term": {c.field: c.value}}
    if c.op == "ne":
        # `ne` is expressed by placing the term inside must_not at the caller
        # level; a single-clause rendering as must_not is out of scope for
        # this renderer (handled in hunt_query()). Treating it as an identity
        # here keeps the renderer pure; the outer builder moves ne clauses
        # into must_not.
        return {"term": {c.field: c.value}}
    if c.op == "in":
        return {"terms": {c.field: c.value}}
    if c.op == "exists":
        return {"exists": {"field": c.field}}
    if c.op == "prefix":
        return {"prefix": {c.field: c.value}}
    # range ops
    range_key = {"gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}[c.op]
    return {"range": {c.field: {range_key: c.value}}}


def _build_hunt_dsl(args: HuntQueryArgs) -> dict[str, Any]:
    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{args.time_range}"}}}
    ]
    must_not: list[dict[str, Any]] = []

    for c in args.must:
        if c.op == "ne":
            must_not.append(_render_clause(c))
        else:
            must.append(_render_clause(c))
    for c in args.must_not:
        if c.op == "ne":
            # ne inside must_not degenerates to must (double negative).
            must.append(_render_clause(c))
        else:
            must_not.append(_render_clause(c))

    bool_block: dict[str, Any] = {"must": must}
    if must_not:
        bool_block["must_not"] = must_not

    query: dict[str, Any] = {
        "query": {"bool": bool_block},
        "size": args.size,
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if args.cursor:
        query["search_after"] = args.cursor
    return query


async def hunt_query(
    *,
    args: HuntQueryArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> HuntQueryResult:
    """Tool name: hunt.hunt_query."""
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)

    try:
        query = _build_hunt_dsl(args)
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="hunt.hunt_query",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == args.size

    audit.emit(
        session=session,
        tool="hunt.hunt_query",
        args=arg_dict,
        outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return HuntQueryResult(
        alerts=alerts,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )


# ---- pivot_by_ioc — thin preset on top of hunt_query ----

class PivotByIocArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["hash", "ip", "user", "domain"]
    value: Annotated[str, Field(min_length=1, max_length=256)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=MAX_ALERT_SIZE)] = DEFAULT_ALERT_SIZE
    cursor: list[Any] | None = None


_PIVOT_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "hash": ("syscheck.sha256_after", "syscheck.md5_after"),
    "ip": ("data.srcip", "data.dstip"),
    "user": ("data.srcuser", "data.dstuser"),
    "domain": ("data.hostname", "data.url"),
}


async def pivot_by_ioc(
    *,
    args: PivotByIocArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> HuntQueryResult:
    """Tool name: hunt.pivot_by_ioc — convenience preset over hunt_query."""
    fields = _PIVOT_FIELDS[args.kind]
    # OR across the fields via two passes: synthesize a single `must` list
    # with one clause per candidate field if there's only one, or use
    # separate tool calls. For the M3 surface we keep things simple: emit
    # a single-clause hunt for each field and the caller can OR the results
    # client-side — OR is explicitly out of the hunt grammar. In practice
    # the common case is one-field-dominant (hash pivots always use
    # sha256_after; ip pivots usually inspect srcip first).
    #
    # Behaviour: run against the FIRST field in the tuple. Documentation
    # tells the caller the second field must be probed via a follow-up call.
    primary_field = fields[0]
    hq_args = HuntQueryArgs(
        time_range=args.time_range,
        must=[HuntClause(field=primary_field, op="eq", value=args.value)],
        size=args.size,
        cursor=args.cursor,
    )
    result = await hunt_query(
        args=hq_args,
        session=session,
        indexer=indexer,
        audit=audit,
    )
    # Re-audit under the pivot_by_ioc name so the audit log attributes the
    # higher-level intent correctly. The nested hunt_query audit already
    # recorded the actual query.
    audit.emit(
        session=session,
        tool="hunt.pivot_by_ioc",
        args=args.model_dump(exclude_none=True),
        outcome="ok",
        result_count=len(result.alerts),
        duration_ms=0,
    )
    return result
```

- [ ] **Step 14.2: Write unit tests**

Create `tests/unit/test_tool_hunt.py`:

```python
"""Unit tests for hunt.hunt_query and hunt.pivot_by_ioc."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.hunt import (
    HuntClause,
    HuntQueryArgs,
    PivotByIocArgs,
    _build_hunt_dsl,
    hunt_query,
    pivot_by_ioc,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


def test_clause_rejects_field_off_allowlist():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="vulnerability.id", op="eq", value="CVE-2024-1234")


def test_clause_rejects_prefix_too_short():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="data.srcip", op="prefix", value="10")


def test_clause_rejects_in_too_large():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntClause(field="rule.id", op="in", value=["x"] * 101)


def test_hunt_args_enforces_clause_cap():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntQueryArgs(
            time_range="24h",
            must=[HuntClause(field="rule.id", op="eq", value="1")] * 21,
        )


def test_hunt_args_requires_at_least_one_clause():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntQueryArgs(time_range="24h", must=[])


def test_build_hunt_dsl_has_no_dangerous_keys():
    args = HuntQueryArgs(
        time_range="24h",
        must=[
            HuntClause(field="data.srcip", op="eq", value="10.0.0.5"),
            HuntClause(field="rule.level", op="gte", value=10),
        ],
        must_not=[HuntClause(field="agent.id", op="eq", value="000")],
    )
    q = _build_hunt_dsl(args)
    serialised = str(q)
    for dangerous in ("script", "runtime_mappings", "script_score", "painless"):
        assert dangerous not in serialised


def test_build_hunt_dsl_flattens_ne_to_must_not():
    args = HuntQueryArgs(
        time_range="24h",
        must=[HuntClause(field="rule.id", op="ne", value="100")],
    )
    q = _build_hunt_dsl(args)
    bool_block = q["query"]["bool"]
    assert {"term": {"rule.id": "100"}} in bool_block.get("must_not", [])


@pytest.mark.asyncio
async def test_pivot_by_ioc_hash_uses_sha256_field(
    session, audit, indexer, httpx_mock
):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    result = await pivot_by_ioc(
        args=PivotByIocArgs(kind="hash", value="abc123def456", time_range="24h"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 0

    # Inspect the request sent — the DSL should reference syscheck.sha256_after.
    req = httpx_mock.get_requests()[0]
    assert "sha256_after" in req.content.decode()
```

- [ ] **Step 14.3: Run + lint**

Run: `uv run pytest tests/unit/test_tool_hunt.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 8 tests pass; all checks passed.

- [ ] **Step 14.4: Commit**

```bash
git add src/wazuh_mcp/tools/hunt.py tests/unit/test_tool_hunt.py
git commit -m "Add hunt.hunt_query and hunt.pivot_by_ioc with allowlisted grammar"
```

---

## Task 15: `hunt_query` — hypothesis fuzz tests [A]

**Tier A:** Property-based verification that the allowlist grammar cannot be bypassed.

**Files:**
- Create: `tests/unit/test_hunt_query_fuzz.py`

- [ ] **Step 15.1: Write the fuzz suite**

Create `tests/unit/test_hunt_query_fuzz.py`:

```python
"""Hypothesis property tests for hunt.hunt_query grammar safety."""

import string

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from wazuh_mcp.tools.hunt import (
    FIELD_ALLOWLIST,
    OP_ALLOWLIST,
    HuntClause,
    HuntQueryArgs,
    _build_hunt_dsl,
)

# ---- Strategies ----

_OFF_ALLOWLIST_FIELDS = st.text(
    alphabet=string.ascii_letters + ".",
    min_size=1,
    max_size=64,
).filter(lambda s: s not in FIELD_ALLOWLIST)

_OFF_ALLOWLIST_OPS = st.text(
    alphabet=string.ascii_letters,
    min_size=1,
    max_size=20,
).filter(lambda s: s not in OP_ALLOWLIST)

_LEGAL_FIELDS = st.sampled_from(sorted(FIELD_ALLOWLIST))
_LEGAL_OPS = st.sampled_from(OP_ALLOWLIST)


@st.composite
def _legal_clause(draw):
    field = draw(_LEGAL_FIELDS)
    op = draw(_LEGAL_OPS)
    if op == "in":
        value = draw(st.lists(st.text(min_size=1, max_size=16), min_size=1, max_size=20))
    elif op == "exists":
        value = True
    elif op == "prefix":
        value = draw(st.text(min_size=3, max_size=32))
    elif op in ("gt", "gte", "lt", "lte"):
        value = draw(st.integers(min_value=0, max_value=15))
    else:
        value = draw(st.text(min_size=1, max_size=32))
    return HuntClause(field=field, op=op, value=value)


# ---- Properties ----

@given(field=_OFF_ALLOWLIST_FIELDS)
@settings(max_examples=200)
def test_any_off_allowlist_field_rejected(field):
    try:
        HuntClause(field=field, op="eq", value="x")
    except ValidationError:
        return
    assert False, f"allowlist bypass: {field!r}"


@given(op=_OFF_ALLOWLIST_OPS)
@settings(max_examples=100)
def test_any_off_allowlist_op_rejected(op):
    try:
        HuntClause(field="rule.id", op=op, value="x")  # type: ignore[arg-type]
    except ValidationError:
        return
    assert False, f"op allowlist bypass: {op!r}"


@given(
    must=st.lists(_legal_clause(), min_size=0, max_size=25),
    must_not=st.lists(_legal_clause(), min_size=0, max_size=25),
    time_range=st.sampled_from(["1h", "24h", "7d", "29d"]),
)
@settings(max_examples=200, deadline=None)
def test_any_legal_clause_combo_produces_safe_dsl(must, must_not, time_range):
    # The validator either rejects (too many clauses, empty both lists) or
    # produces a DSL free of dangerous keys.
    try:
        args = HuntQueryArgs(
            time_range=time_range,
            must=must,
            must_not=must_not,
        )
    except ValidationError:
        return  # expected for oversize / empty inputs
    dsl = _build_hunt_dsl(args)
    serialised = str(dsl)
    for banned in ("script", "runtime_mappings", "script_score", "painless"):
        assert banned not in serialised, f"DSL escape: {banned} found in {serialised!r}"
    # No nested bool either.
    assert serialised.count("'bool'") <= 1, "nested bool appeared"


@given(size=st.integers(min_value=-1000, max_value=10_000))
@settings(max_examples=50)
def test_size_always_in_range_or_rejected(size):
    try:
        args = HuntQueryArgs(
            time_range="24h",
            must=[HuntClause(field="rule.id", op="eq", value="1")],
            size=size,
        )
    except ValidationError:
        return
    assert 1 <= args.size <= 100


@given(
    in_list=st.lists(st.text(min_size=1, max_size=8), min_size=0, max_size=200)
)
@settings(max_examples=50)
def test_in_op_caps_list_length(in_list):
    try:
        HuntClause(field="rule.id", op="in", value=in_list)
    except ValidationError:
        return
    assert 1 <= len(in_list) <= 100
```

- [ ] **Step 15.2: Run the fuzz suite**

Run: `uv run pytest tests/unit/test_hunt_query_fuzz.py -v`
Expected: 5 property tests pass; hypothesis reports no counterexamples.

- [ ] **Step 15.3: Commit**

```bash
git add tests/unit/test_hunt_query_fuzz.py
git commit -m "Add hypothesis fuzz tests asserting hunt_query allowlist cannot be bypassed"
```

---

## Task 16: `fim.*` — fim_history_for_path + fim_changes_by_agent [B]

**Tier B batch:** Two mechanical tools over the alerts index.

**Files:**
- Create: `src/wazuh_mcp/tools/fim.py`
- Create: `tests/unit/test_tool_fim.py`

- [ ] **Step 16.1: Create the tool module**

Create `src/wazuh_mcp/tools/fim.py`:

```python
"""fim.* tools — file-integrity-monitoring history views over the alerts index."""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import FimEvent
from wazuh_mcp.wazuh.query import (
    build_fim_changes_by_agent_query,
    build_fim_history_for_path_query,
)


class FimHistoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Annotated[str, Field(min_length=1, max_length=1024)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class FimChangesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    time_range: str = "24h"
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class FimResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    events: list[FimEvent]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def fim_history_for_path(
    *,
    args: FimHistoryArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> FimResult:
    """Tool name: fim.fim_history_for_path."""
    return await _fim_search(
        tool_name="fim.fim_history_for_path",
        build=lambda: build_fim_history_for_path_query(
            path=args.path,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def fim_changes_by_agent(
    *,
    args: FimChangesArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> FimResult:
    """Tool name: fim.fim_changes_by_agent."""
    return await _fim_search(
        tool_name="fim.fim_changes_by_agent",
        build=lambda: build_fim_changes_by_agent_query(
            agent_id=args.agent_id,
            time_range=args.time_range,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def _fim_search(
    *,
    tool_name: str,
    build,
    args_dict: dict[str, Any],
    wanted_size: int,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> FimResult:
    started = time.monotonic()
    try:
        query = build()
        body = await indexer.search(index="wazuh-alerts-*", query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    events = [FimEvent.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(events) == wanted_size

    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(events),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return FimResult(
        events=events,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
```

- [ ] **Step 16.2: Write tests**

Create `tests/unit/test_tool_fim.py`:

```python
"""Unit tests for fim.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.fim import (
    FimChangesArgs,
    FimHistoryArgs,
    fim_changes_by_agent,
    fim_history_for_path,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_fim_history_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "agent": {"id": "001"},
                            "timestamp": "2026-04-22T00:00:00Z",
                            "syscheck": {
                                "path": "/etc/passwd",
                                "event": "modified",
                                "sha256_after": "abc",
                            },
                        },
                        "sort": [1],
                    }
                ],
            }
        },
    )
    result = await fim_history_for_path(
        args=FimHistoryArgs(path="/etc/passwd", time_range="24h", size=1),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 1
    assert result.events[0].path == "/etc/passwd"
    assert result.truncated is True


@pytest.mark.asyncio
async def test_fim_changes_rejects_bad_agent_id(session, audit, indexer):
    with pytest.raises(ValueError):
        await fim_changes_by_agent(
            args=FimChangesArgs(agent_id="not-a-number", time_range="24h"),
            session=session,
            indexer=indexer,
            audit=audit,
        )
```

- [ ] **Step 16.3: Run + lint + commit**

Run: `uv run pytest tests/unit/test_tool_fim.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 2 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/tools/fim.py tests/unit/test_tool_fim.py
git commit -m "Add fim.fim_history_for_path and fim.fim_changes_by_agent"
```

---

## Task 17: `vulnerabilities.*` — list_by_agent + search [B]

**Tier B batch:** Indexer-backed, shares the pattern of alerts.* batch tools.

**Files:**
- Create: `src/wazuh_mcp/tools/vulns.py`
- Create: `tests/unit/test_tool_vulns.py`

- [ ] **Step 17.1: Create the tool module**

Create `src/wazuh_mcp/tools/vulns.py`:

```python
"""vulnerabilities.* tools — 4.8+ reads from the wazuh-states-vulnerabilities-* indices."""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.models import Vulnerability
from wazuh_mcp.wazuh.query import (
    build_search_vulnerabilities_query,
    build_vulnerabilities_by_agent_query,
)

VULN_INDEX = "wazuh-states-vulnerabilities-*"


class ListVulnerabilitiesByAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    min_severity: Annotated[
        str | None,
        Field(description="Low | Medium | High | Critical"),
    ] = None
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class SearchVulnerabilitiesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: Annotated[str | None, Field(description="e.g. CVE-2024-1234")] = None
    min_severity: Annotated[
        str | None,
        Field(description="Low | Medium | High | Critical"),
    ] = None
    size: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: list[Any] | None = None


class VulnerabilitiesResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    vulnerabilities: list[Vulnerability]
    total: int
    next_cursor: list[Any] | None
    truncated: bool


async def list_vulnerabilities_by_agent(
    *,
    args: ListVulnerabilitiesByAgentArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    """Tool name: vulnerabilities.list_vulnerabilities_by_agent."""
    return await _vuln_search(
        tool_name="vulnerabilities.list_vulnerabilities_by_agent",
        build=lambda: build_vulnerabilities_by_agent_query(
            agent_id=args.agent_id,
            min_severity=args.min_severity,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def search_vulnerabilities(
    *,
    args: SearchVulnerabilitiesArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    """Tool name: vulnerabilities.search_vulnerabilities."""
    return await _vuln_search(
        tool_name="vulnerabilities.search_vulnerabilities",
        build=lambda: build_search_vulnerabilities_query(
            cve_id=args.cve_id,
            min_severity=args.min_severity,
            size=args.size,
            cursor=args.cursor,
        ),
        args_dict=args.model_dump(exclude_none=True),
        wanted_size=args.size,
        session=session,
        indexer=indexer,
        audit=audit,
    )


async def _vuln_search(
    *,
    tool_name: str,
    build,
    args_dict: dict[str, Any],
    wanted_size: int,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> VulnerabilitiesResult:
    started = time.monotonic()
    try:
        query = build()
        body = await indexer.search(index=VULN_INDEX, query=query)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total_block = body.get("hits", {}).get("total", {})
    total = (
        total_block.get("value", 0)
        if isinstance(total_block, dict)
        else int(total_block)
    )
    vulns = [Vulnerability.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(vulns) == wanted_size

    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(vulns),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return VulnerabilitiesResult(
        vulnerabilities=vulns,
        total=total,
        next_cursor=next_cursor,
        truncated=truncated,
    )
```

Note: `IndexerClient.search` currently rejects index names containing `/`. Confirm the `VULN_INDEX = "wazuh-states-vulnerabilities-*"` passes — the `*` is fine, no `/` present.

- [ ] **Step 17.2: Write tests**

Create `tests/unit/test_tool_vulns.py`:

```python
"""Unit tests for vulnerabilities.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.vulns import (
    ListVulnerabilitiesByAgentArgs,
    SearchVulnerabilitiesArgs,
    list_vulnerabilities_by_agent,
    search_vulnerabilities,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


def _vuln_hit(cve: str, severity: str = "High", score: float = 7.5) -> dict:
    return {
        "_source": {
            "agent": {"id": "001"},
            "package": {"name": "openssl", "version": "3.0.0"},
            "vulnerability": {
                "id": cve,
                "severity": severity,
                "scores": {"base": {"score": score}},
                "detected_at": "2026-04-22T00:00:00Z",
                "status": "Active",
            },
        },
        "sort": [1],
    }


@pytest.mark.asyncio
async def test_list_vulns_by_agent_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-states-vulnerabilities-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [_vuln_hit("CVE-2024-1234")],
            }
        },
    )
    result = await list_vulnerabilities_by_agent(
        args=ListVulnerabilitiesByAgentArgs(agent_id="001", min_severity="High"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 1
    assert result.vulnerabilities[0].id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_search_vulns_requires_a_filter(session, audit, indexer):
    with pytest.raises(ValueError):
        await search_vulnerabilities(
            args=SearchVulnerabilitiesArgs(),
            session=session,
            indexer=indexer,
            audit=audit,
        )


@pytest.mark.asyncio
async def test_search_vulns_by_cve(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-states-vulnerabilities-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [_vuln_hit("CVE-2023-9999", severity="Critical", score=9.8)],
            }
        },
    )
    result = await search_vulnerabilities(
        args=SearchVulnerabilitiesArgs(cve_id="CVE-2023-9999"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.vulnerabilities[0].id == "CVE-2023-9999"
    assert result.vulnerabilities[0].severity == "Critical"
```

- [ ] **Step 17.3: Run + lint + commit**

Run: `uv run pytest tests/unit/test_tool_vulns.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 3 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/tools/vulns.py tests/unit/test_tool_vulns.py
git commit -m "Add vulnerabilities.list_by_agent and search (indexer, 4.8+)"
```

---

## Task 18: `agents.*` — list, get, processes, packages, ports [B]

**Tier B batch:** Five tools over the Server API; all share the same HTTP-GET + Pydantic-shape pattern.

**Files:**
- Create: `src/wazuh_mcp/tools/agents.py`
- Create: `tests/unit/test_tool_agents.py`

- [ ] **Step 18.1: Create the tool module**

Create `src/wazuh_mcp/tools/agents.py`:

```python
"""agents.* tools — all Server API-backed (port 55000)."""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.models import Agent
from wazuh_mcp.wazuh.server_api import ServerApiClient


class ListAgentsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Annotated[
        str | None,
        Field(description="active | disconnected | pending | never_connected"),
    ] = None
    group: Annotated[str | None, Field(max_length=64)] = None
    size: Annotated[int, Field(ge=1, le=500)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0


class AgentsResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agents: list[Agent]
    total: int
    truncated: bool


class GetAgentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]


class AgentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: Agent


class AgentSubquery(BaseModel):
    """Shared args for processes / packages / ports: one agent_id, one
    offset/size pair.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=16)]
    size: Annotated[int, Field(ge=1, le=500)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0


class AgentInventoryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    items: list[dict[str, Any]]  # heterogeneous — processes/packages/ports differ
    total: int
    truncated: bool


async def list_agents(
    *,
    args: ListAgentsArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentsResult:
    """Tool name: agents.list_agents."""
    return await _run_server_api_tool(
        tool_name="agents.list_agents",
        path="/agents",
        params=_nonempty(
            {
                "status": args.status,
                "group": args.group,
                "limit": args.size,
                "offset": args.offset,
            }
        ),
        args_dict=args.model_dump(exclude_none=True),
        session=session,
        server_api=server_api,
        audit=audit,
        shape=_shape_agent_list,
        wanted_size=args.size,
    )


async def get_agent(
    *,
    args: GetAgentArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentResult:
    """Tool name: agents.get_agent."""
    started = time.monotonic()
    arg_dict = args.model_dump()
    try:
        body = await server_api.get(
            "/agents",
            params={"agents_list": args.agent_id},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="agents.get_agent",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="agents.get_agent",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="not_found",
        )
        raise WazuhError("not_found", "agent not found", 404)

    agent = Agent.from_api(items[0])
    audit.emit(
        session=session,
        tool="agents.get_agent",
        args=arg_dict,
        outcome="ok",
        result_count=1,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return AgentResult(agent=agent)


async def agent_processes(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_processes."""
    return await _inventory(
        tool_name="agents.agent_processes",
        path=f"/syscollector/{args.agent_id}/processes",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def agent_packages(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_packages."""
    return await _inventory(
        tool_name="agents.agent_packages",
        path=f"/syscollector/{args.agent_id}/packages",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def agent_ports(
    *,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    """Tool name: agents.agent_ports."""
    return await _inventory(
        tool_name="agents.agent_ports",
        path=f"/syscollector/{args.agent_id}/ports",
        args=args,
        session=session,
        server_api=server_api,
        audit=audit,
    )


async def _inventory(
    *,
    tool_name: str,
    path: str,
    args: AgentSubquery,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> AgentInventoryResult:
    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)
    try:
        body = await server_api.get(
            path,
            params={"limit": args.size, "offset": args.offset},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    truncated = len(items) == args.size

    audit.emit(
        session=session,
        tool=tool_name,
        args=arg_dict,
        outcome="ok",
        result_count=len(items),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return AgentInventoryResult(
        agent_id=args.agent_id,
        items=items,
        total=total,
        truncated=truncated,
    )


async def _run_server_api_tool(
    *,
    tool_name: str,
    path: str,
    params: dict[str, Any],
    args_dict: dict[str, Any],
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
    shape,
    wanted_size: int,
) -> AgentsResult:
    started = time.monotonic()
    try:
        body = await server_api.get(path, params=params, run_as=session.wazuh_user)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool=tool_name,
            args=args_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    result = shape(body, wanted_size)
    audit.emit(
        session=session,
        tool=tool_name,
        args=args_dict,
        outcome="ok",
        result_count=len(result.agents),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _shape_agent_list(body: dict[str, Any], wanted_size: int) -> AgentsResult:
    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    return AgentsResult(
        agents=[Agent.from_api(it) for it in items],
        total=total,
        truncated=len(items) == wanted_size,
    )


def _nonempty(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}
```

- [ ] **Step 18.2: Write unit tests**

Create `tests/unit/test_tool_agents.py`:

```python
"""Unit tests for agents.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.agents import (
    AgentSubquery,
    GetAgentArgs,
    ListAgentsArgs,
    agent_packages,
    get_agent,
    list_agents,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64
    import json
    import time as _t

    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    pl = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{hdr}.{pl}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
        wazuh_user="alice",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("x"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_list_agents_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?status=active&limit=25&offset=0&run_as=alice",
        method="GET",
        json={
            "data": {
                "total_affected_items": 2,
                "affected_items": [
                    {"id": "001", "name": "a"},
                    {"id": "002", "name": "b"},
                ],
            }
        },
    )
    result = await list_agents(
        args=ListAgentsArgs(status="active", size=25),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.total == 2
    assert [a.id for a in result.agents] == ["001", "002"]


@pytest.mark.asyncio
async def test_get_agent_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=999&run_as=alice",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_agent(
            args=GetAgentArgs(agent_id="999"),
            session=session,
            server_api=server_api,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_agent_packages_passes_run_as(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/syscollector/001/packages?limit=10&offset=0&run_as=alice",
        method="GET",
        json={
            "data": {
                "total_affected_items": 1,
                "affected_items": [{"name": "openssl", "version": "3.0.0"}],
            }
        },
    )
    result = await agent_packages(
        args=AgentSubquery(agent_id="001", size=10),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.agent_id == "001"
    assert result.items[0]["name"] == "openssl"
```

- [ ] **Step 18.3: Run + lint + commit**

Run: `uv run pytest tests/unit/test_tool_agents.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 3 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/tools/agents.py tests/unit/test_tool_agents.py
git commit -m "Add agents.* tools: list, get, processes, packages, ports"
```

---

## Task 19: `mitre.*` — get_mitre_technique + search_mitre [B]

**Tier B batch:** Two Server API tools over `/mitre/techniques`.

**Files:**
- Create: `src/wazuh_mcp/tools/mitre.py`
- Create: `tests/unit/test_tool_mitre.py`

- [ ] **Step 19.1: Create the tool module**

Create `src/wazuh_mcp/tools/mitre.py`:

```python
"""mitre.* tools — MITRE ATT&CK technique reference, sourced from the
Wazuh Server API's bundled dataset.
"""

from __future__ import annotations

import re
import time
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.models import MitreTechnique
from wazuh_mcp.wazuh.server_api import ServerApiClient

_TECHNIQUE_ID_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


class GetMitreTechniqueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: Annotated[str, Field(min_length=4, max_length=16)]


class MitreTechniqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique: MitreTechnique


class SearchMitreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: Annotated[
        str | None,
        Field(description="Substring to match against technique name/description"),
    ] = None
    tactic: Annotated[str | None, Field(max_length=64)] = None
    size: Annotated[int, Field(ge=1, le=200)] = 50


class MitreSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    techniques: list[MitreTechnique]
    total: int
    truncated: bool


async def get_mitre_technique(
    *,
    args: GetMitreTechniqueArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> MitreTechniqueResult:
    """Tool name: mitre.get_mitre_technique."""
    if not _TECHNIQUE_ID_RE.match(args.technique_id):
        raise ValueError("invalid technique_id")

    started = time.monotonic()
    arg_dict = args.model_dump()
    try:
        body = await server_api.get(
            "/mitre/techniques",
            params={"q": f"id={args.technique_id}"},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="mitre.get_mitre_technique",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="mitre.get_mitre_technique",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="not_found",
        )
        raise WazuhError("not_found", "technique not found", 404)

    tech = MitreTechnique.from_api(items[0])
    audit.emit(
        session=session,
        tool="mitre.get_mitre_technique",
        args=arg_dict,
        outcome="ok",
        result_count=1,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return MitreTechniqueResult(technique=tech)


async def search_mitre(
    *,
    args: SearchMitreArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> MitreSearchResult:
    """Tool name: mitre.search_mitre."""
    if args.q is None and args.tactic is None:
        raise ValueError("at least one of q or tactic must be set")

    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)
    # Wazuh's /mitre/techniques supports a `q` param with simple field=value
    # expressions; combine substring-search and tactic filter via comma (AND).
    qclauses: list[str] = []
    if args.q:
        qclauses.append(f"name~{args.q}")
    if args.tactic:
        qclauses.append(f"tactics~{args.tactic}")
    params = {"q": ",".join(qclauses), "limit": args.size}

    try:
        body = await server_api.get(
            "/mitre/techniques", params=params, run_as=session.wazuh_user
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="mitre.search_mitre",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    techs = [MitreTechnique.from_api(i) for i in items]

    audit.emit(
        session=session,
        tool="mitre.search_mitre",
        args=arg_dict,
        outcome="ok",
        result_count=len(techs),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return MitreSearchResult(
        techniques=techs,
        total=total,
        truncated=len(techs) == args.size,
    )
```

- [ ] **Step 19.2: Write tests**

Create `tests/unit/test_tool_mitre.py`:

```python
"""Unit tests for mitre.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.mitre import (
    GetMitreTechniqueArgs,
    SearchMitreArgs,
    get_mitre_technique,
    search_mitre,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64
    import json
    import time as _t

    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    pl = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{hdr}.{pl}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("x"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_get_mitre_technique_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=id%3DT1110.001",
        method="GET",
        json={
            "data": {
                "affected_items": [
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "tactics": ["Credential Access"],
                    }
                ]
            }
        },
    )
    result = await get_mitre_technique(
        args=GetMitreTechniqueArgs(technique_id="T1110.001"),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.technique.id == "T1110.001"


@pytest.mark.asyncio
async def test_get_mitre_technique_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await get_mitre_technique(
            args=GetMitreTechniqueArgs(technique_id="not-a-technique"),
            session=session,
            server_api=server_api,
            audit=audit,
        )


@pytest.mark.asyncio
async def test_get_mitre_technique_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=id%3DT9999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_mitre_technique(
            args=GetMitreTechniqueArgs(technique_id="T9999"),
            session=session,
            server_api=server_api,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_search_mitre_requires_a_filter(session, audit, server_api):
    with pytest.raises(ValueError):
        await search_mitre(
            args=SearchMitreArgs(),
            session=session,
            server_api=server_api,
            audit=audit,
        )
```

- [ ] **Step 19.3: Run + lint + commit**

Run: `uv run pytest tests/unit/test_tool_mitre.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 4 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/tools/mitre.py tests/unit/test_tool_mitre.py
git commit -m "Add mitre.get_mitre_technique and mitre.search_mitre"
```

---

## Task 20: Resources — rules, MITRE technique, agent config [A]

**Tier A:** New MCP surface; tenant scoping and TTL hint contracts are security-relevant.

**Files:**
- Create: `src/wazuh_mcp/resources/__init__.py`
- Create: `src/wazuh_mcp/resources/rules.py`
- Create: `src/wazuh_mcp/resources/mitre.py`
- Create: `src/wazuh_mcp/resources/agent_config.py`
- Create: `tests/unit/test_resources.py`

- [ ] **Step 20.1: Create package init + URI templates registry**

Create `src/wazuh_mcp/resources/__init__.py`:

```python
"""MCP resources — URI-addressable, cacheable reference data.

All three resources are publishable as URI templates via
resources/templates/list. resources/list returns [] — we never enumerate
rules, techniques, or agents (cardinality is too large or the list is too
public-domain to be useful).

Each read returns a dict with:
  - `contents`: a list of MCP content blocks (JSON body in `text`, MIME
    `application/json`).
  - `_meta.ttl_seconds`: compliant clients cache for this long.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResourceTemplate:
    uri_template: str
    name: str
    description: str
    mime_type: str
    ttl_seconds: int


TEMPLATES: tuple[ResourceTemplate, ...] = (
    ResourceTemplate(
        uri_template="wazuh://rules/{id}",
        name="Wazuh rule",
        description=(
            "Individual Wazuh detection rule — definition, groups, "
            "description. Attach this instead of calling a tool when the "
            "model just needs rule metadata."
        ),
        mime_type="application/json",
        ttl_seconds=300,
    ),
    ResourceTemplate(
        uri_template="wazuh://mitre/technique/{id}",
        name="MITRE ATT&CK technique",
        description=(
            "Individual MITRE ATT&CK technique (TXXXX or TXXXX.YYY). "
            "Stable public corpus — cache aggressively."
        ),
        mime_type="application/json",
        ttl_seconds=86_400,
    ),
    ResourceTemplate(
        uri_template="wazuh://agents/{id}/config",
        name="Agent configuration",
        description=(
            "Current agent configuration snapshot from the Server API."
        ),
        mime_type="application/json",
        ttl_seconds=300,
    ),
)


def make_json_content(data: Any, ttl_seconds: int) -> dict[str, Any]:
    """Shared response shape for `resources/read`."""
    return {
        "contents": [
            {
                "mimeType": "application/json",
                "text": json.dumps(data, indent=2),
            }
        ],
        "_meta": {"ttl_seconds": ttl_seconds},
    }
```

- [ ] **Step 20.2: `resources/rules.py`**

Create `src/wazuh_mcp/resources/rules.py`:

```python
"""wazuh://rules/{id} — Server API-backed rule reference."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_RULE_ID_RE = re.compile(r"^[0-9]{1,12}$")


async def read_rule(
    *,
    rule_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _RULE_ID_RE.match(rule_id):
        raise ValueError("invalid rule_id")

    try:
        body = await server_api.get(
            "/rules",
            params={"rule_ids": rule_id},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.rules",
            args={"rule_id": rule_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="resource.rules",
            args={"rule_id": rule_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "rule not found", 404)

    audit.emit(
        session=session,
        tool="resource.rules",
        args={"rule_id": rule_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(items[0], ttl_seconds=300)
```

- [ ] **Step 20.3: `resources/mitre.py`**

Create `src/wazuh_mcp/resources/mitre.py`:

```python
"""wazuh://mitre/technique/{id} — Server API-backed MITRE technique reference."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_TECHNIQUE_ID_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


async def read_mitre_technique(
    *,
    technique_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _TECHNIQUE_ID_RE.match(technique_id):
        raise ValueError("invalid technique_id")

    try:
        body = await server_api.get(
            "/mitre/techniques",
            params={"q": f"id={technique_id}"},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.mitre",
            args={"technique_id": technique_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="resource.mitre",
            args={"technique_id": technique_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "technique not found", 404)

    audit.emit(
        session=session,
        tool="resource.mitre",
        args={"technique_id": technique_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(items[0], ttl_seconds=86_400)
```

- [ ] **Step 20.4: `resources/agent_config.py`**

Create `src/wazuh_mcp/resources/agent_config.py`:

```python
"""wazuh://agents/{id}/config — Server API-backed agent config snapshot."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_AGENT_ID_RE = re.compile(r"^[0-9]{3,10}$")


async def read_agent_config(
    *,
    agent_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")

    try:
        body = await server_api.get(
            f"/agents/{agent_id}/config/client/client",
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.agent_config",
            args={"agent_id": agent_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    if not data:
        audit.emit(
            session=session,
            tool="resource.agent_config",
            args={"agent_id": agent_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "agent config not found", 404)

    audit.emit(
        session=session,
        tool="resource.agent_config",
        args={"agent_id": agent_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(data, ttl_seconds=300)
```

- [ ] **Step 20.5: Write resource unit tests**

Create `tests/unit/test_resources.py`:

```python
"""Unit tests for MCP resources."""

import io
import json

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import TEMPLATES, make_json_content
from wazuh_mcp.resources.agent_config import read_agent_config
from wazuh_mcp.resources.mitre import read_mitre_technique
from wazuh_mcp.resources.rules import read_rule
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64 as _b
    import json as _j
    import time as _t

    h = _b.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    p = (
        _b.urlsafe_b64encode(
            _j.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{h}.{p}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    c = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("u"),
        password=SecretValue("p"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


def test_templates_list_has_three_entries():
    ids = {t.uri_template for t in TEMPLATES}
    assert ids == {
        "wazuh://rules/{id}",
        "wazuh://mitre/technique/{id}",
        "wazuh://agents/{id}/config",
    }


def test_make_json_content_has_ttl_meta():
    payload = make_json_content({"x": 1}, ttl_seconds=300)
    assert payload["_meta"]["ttl_seconds"] == 300
    assert json.loads(payload["contents"][0]["text"]) == {"x": 1}
    assert payload["contents"][0]["mimeType"] == "application/json"


@pytest.mark.asyncio
async def test_read_rule_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/rules?rule_ids=5700",
        method="GET",
        json={"data": {"affected_items": [{"id": 5700, "description": "ssh brute force"}]}},
    )
    result = await read_rule(
        rule_id="5700", session=session, server_api=server_api, audit=audit
    )
    assert result["_meta"]["ttl_seconds"] == 300
    body = json.loads(result["contents"][0]["text"])
    assert body["id"] == 5700


@pytest.mark.asyncio
async def test_read_rule_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await read_rule(
            rule_id="abc", session=session, server_api=server_api, audit=audit
        )


@pytest.mark.asyncio
async def test_read_rule_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/rules?rule_ids=9999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await read_rule(
            rule_id="9999", session=session, server_api=server_api, audit=audit
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_read_mitre_technique_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=id%3DT1110.001",
        method="GET",
        json={
            "data": {
                "affected_items": [
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "tactics": ["Credential Access"],
                    }
                ]
            }
        },
    )
    result = await read_mitre_technique(
        technique_id="T1110.001",
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result["_meta"]["ttl_seconds"] == 86_400


@pytest.mark.asyncio
async def test_read_agent_config_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await read_agent_config(
            agent_id="xx", session=session, server_api=server_api, audit=audit
        )
```

- [ ] **Step 20.6: Run + lint + commit**

Run: `uv run pytest tests/unit/test_resources.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 7 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/resources/ tests/unit/test_resources.py
git commit -m "Add MCP resources: rules, MITRE technique, agent config"
```

---

## Task 21: Prompts — investigate_alert, triage_last_hour, agent_posture [A]

**Tier A:** New MCP surface; prompt handlers execute real Wazuh queries at invocation time under the session's identity.

**Files:**
- Create: `src/wazuh_mcp/prompts/__init__.py`
- Create: `src/wazuh_mcp/prompts/investigate_alert.py`
- Create: `src/wazuh_mcp/prompts/triage_last_hour.py`
- Create: `src/wazuh_mcp/prompts/agent_posture.py`
- Create: `tests/unit/test_prompts.py`

- [ ] **Step 21.1: Create package init with shared shape**

Create `src/wazuh_mcp/prompts/__init__.py`:

```python
"""MCP prompts — user-invoked IR playbooks with server-side context loading.

Each prompt handler runs obvious Wazuh queries at invocation time and
returns a single user-role message containing the pre-fetched context.
Claude arrives with data already on hand, no follow-up tool calls needed
for the gather phase.

Contract: handlers return a dict shaped like MCP's prompts/get response:
  {"messages": [{"role": "user", "content": {"type": "text", "text": "..."}}]}
"""

from __future__ import annotations

from typing import Any


def make_user_message(text: str) -> dict[str, Any]:
    return {
        "messages": [
            {
                "role": "user",
                "content": {"type": "text", "text": text},
            }
        ]
    }
```

- [ ] **Step 21.2: `prompts/investigate_alert.py`**

Create `src/wazuh_mcp/prompts/investigate_alert.py`:

```python
"""Prompt: /wazuh:investigate-alert {alert_id}

Fetches the alert, its agent, and last-hour neighbors on the same agent.
Returns a user-role message with all context pre-loaded.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.alerts import (
    AlertsByAgentArgs,
    GetAlertArgs,
    alerts_by_agent,
    get_alert,
)
from wazuh_mcp.tools.agents import GetAgentArgs, get_agent
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


async def handle(
    *,
    alert_id: str,
    session: Session,
    indexer: IndexerClient,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()
    audit.emit(
        session=session,
        tool="prompt.investigate_alert",
        args={"alert_id": alert_id},
        outcome="ok",
        result_count=0,
        duration_ms=0,
    )

    # 1. Get the alert.
    try:
        alert_res = await get_alert(
            args=GetAlertArgs(alert_id=alert_id),
            session=session,
            indexer=indexer,
            audit=audit,
        )
    except WazuhError as e:
        if e.code == "not_found":
            return make_user_message(
                f"Alert {alert_id!r} not found. Ask the user for a valid alert id."
            )
        raise

    alert = alert_res.alert
    agent_id = alert.agent.id

    # 2. Get the agent (may fail — proceed without it).
    agent_block = "(agent lookup unavailable)"
    if agent_id:
        try:
            agent_res = await get_agent(
                args=GetAgentArgs(agent_id=agent_id),
                session=session,
                server_api=server_api,
                audit=audit,
            )
            agent_block = json.dumps(agent_res.agent.model_dump(), indent=2)
        except WazuhError:
            pass

    # 3. Nearby alerts on the same agent in the last hour.
    neighbors_block = "(no neighbors)"
    if agent_id:
        try:
            neighbors = await alerts_by_agent(
                args=AlertsByAgentArgs(agent_id=agent_id, time_range="1h", size=10),
                session=session,
                indexer=indexer,
                audit=audit,
            )
            neighbors_block = json.dumps(
                [a.model_dump() for a in neighbors.alerts], indent=2
            )
        except WazuhError:
            pass

    duration = int((time.monotonic() - started) * 1000)
    text = (
        f"Investigating Wazuh alert {alert_id}.\n"
        f"\n"
        f"ALERT:\n{json.dumps(alert.model_dump(), indent=2)}\n"
        f"\n"
        f"AGENT:\n{agent_block}\n"
        f"\n"
        f"NEIGHBORS (last hour, same agent):\n{neighbors_block}\n"
        f"\n"
        f"Based on the above: summarise the alert, note any notable neighbor "
        f"patterns, and recommend the next SOC actions. Use the other "
        f"wazuh-mcp tools if you need more context."
    )
    audit.emit(
        session=session,
        tool="prompt.investigate_alert",
        args={"alert_id": alert_id},
        outcome="ok",
        result_count=1,
        duration_ms=duration,
    )
    return make_user_message(text)
```

- [ ] **Step 21.3: `prompts/triage_last_hour.py`**

Create `src/wazuh_mcp/prompts/triage_last_hour.py`:

```python
"""Prompt: /wazuh:triage-last-hour

Runs search_alerts(time_range=1h, min_level=10, size=25) and returns
the results as pre-loaded context for a triage summary.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient


async def handle(
    *,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h", min_level=10, size=25),
            session=session,
            indexer=indexer,
            audit=audit,
        )
    except WazuhError as e:
        return make_user_message(
            f"Triage fetch failed ({e.code}). Retry or check upstream."
        )

    alerts_json = json.dumps([a.model_dump() for a in result.alerts], indent=2)
    text = (
        f"Triaging the last hour (min rule level 10).\n"
        f"\n"
        f"TOTAL IN RANGE: {result.total} (showing {len(result.alerts)}).\n"
        f"\n"
        f"ALERTS:\n{alerts_json}\n"
        f"\n"
        f"Summarise: (a) how many unique rules fired, (b) top agents by "
        f"count, (c) any ATT&CK clustering, (d) which alerts warrant a "
        f"deeper investigation. Use get_alert or alerts_by_agent for "
        f"any you flag."
    )

    duration = int((time.monotonic() - started) * 1000)
    audit.emit(
        session=session,
        tool="prompt.triage_last_hour",
        args={},
        outcome="ok",
        result_count=len(result.alerts),
        duration_ms=duration,
    )
    return make_user_message(text)
```

- [ ] **Step 21.4: `prompts/agent_posture.py`**

Create `src/wazuh_mcp/prompts/agent_posture.py`:

```python
"""Prompt: /wazuh:agent-posture {agent_id}

Composes agent details + last-24h alerts + vulnerability count for the
agent.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.agents import GetAgentArgs, get_agent
from wazuh_mcp.tools.alerts import AlertsByAgentArgs, alerts_by_agent
from wazuh_mcp.tools.vulns import (
    ListVulnerabilitiesByAgentArgs,
    list_vulnerabilities_by_agent,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


async def handle(
    *,
    agent_id: str,
    session: Session,
    indexer: IndexerClient,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()

    # 1. Agent metadata.
    try:
        agent_res = await get_agent(
            args=GetAgentArgs(agent_id=agent_id),
            session=session,
            server_api=server_api,
            audit=audit,
        )
    except WazuhError as e:
        if e.code == "not_found":
            return make_user_message(
                f"Agent {agent_id!r} not found. Ask the user for a valid agent id."
            )
        raise

    agent_block = json.dumps(agent_res.agent.model_dump(), indent=2)

    # 2. Last-24h alerts.
    alerts_block = "(alerts unavailable)"
    try:
        alerts = await alerts_by_agent(
            args=AlertsByAgentArgs(agent_id=agent_id, time_range="24h", size=25),
            session=session,
            indexer=indexer,
            audit=audit,
        )
        alerts_block = (
            f"total_in_range={alerts.total}, showing={len(alerts.alerts)}:\n"
            + json.dumps([a.model_dump() for a in alerts.alerts], indent=2)
        )
    except WazuhError:
        pass

    # 3. Vulnerability count.
    vuln_block = "(vulns unavailable)"
    try:
        vulns = await list_vulnerabilities_by_agent(
            args=ListVulnerabilitiesByAgentArgs(agent_id=agent_id, size=25),
            session=session,
            indexer=indexer,
            audit=audit,
        )
        vuln_block = (
            f"total={vulns.total}, showing={len(vulns.vulnerabilities)}:\n"
            + json.dumps(
                [v.model_dump() for v in vulns.vulnerabilities], indent=2
            )
        )
    except WazuhError:
        pass

    text = (
        f"Agent posture for {agent_id}.\n"
        f"\n"
        f"AGENT:\n{agent_block}\n"
        f"\n"
        f"LAST-24H ALERTS:\n{alerts_block}\n"
        f"\n"
        f"VULNERABILITIES:\n{vuln_block}\n"
        f"\n"
        f"Summarise the security posture: recent alert patterns, unpatched "
        f"critical vulns, and any immediate follow-ups the SOC should take."
    )

    duration = int((time.monotonic() - started) * 1000)
    audit.emit(
        session=session,
        tool="prompt.agent_posture",
        args={"agent_id": agent_id},
        outcome="ok",
        result_count=1,
        duration_ms=duration,
    )
    return make_user_message(text)
```

- [ ] **Step 21.5: Write prompt tests**

Create `tests/unit/test_prompts.py`:

```python
"""Unit tests for MCP prompts."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts.agent_posture import handle as agent_posture_handle
from wazuh_mcp.prompts.investigate_alert import handle as investigate_alert_handle
from wazuh_mcp.prompts.triage_last_hour import handle as triage_handle
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64 as _b
    import json as _j
    import time as _t

    h = _b.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    p = (
        _b.urlsafe_b64encode(
            _j.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{h}.{p}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer(httpx_mock):
    c = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    c = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("u"),
        password=SecretValue("p"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_investigate_alert_returns_context_loaded_message(
    session, audit, indexer, server_api, httpx_mock
):
    # get_alert → one hit
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "hits": [
                    {
                        "_id": "abc",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001", "name": "web-01"},
                            "rule": {
                                "id": "1",
                                "level": 10,
                                "description": "test",
                            },
                        },
                    }
                ]
            }
        },
    )
    # get_agent → one hit
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=001",
        method="GET",
        json={"data": {"affected_items": [{"id": "001", "name": "web-01"}]}},
    )
    # alerts_by_agent → zero
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )

    out = await investigate_alert_handle(
        alert_id="abc",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["messages"][0]["content"]["text"]
    assert "abc" in text
    assert "web-01" in text


@pytest.mark.asyncio
async def test_investigate_alert_not_found_returns_message_not_raises(
    session, audit, indexer, server_api, httpx_mock
):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"hits": []}},
    )
    out = await investigate_alert_handle(
        alert_id="nope",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["messages"][0]["content"]["text"]
    assert "not found" in text.lower()


@pytest.mark.asyncio
async def test_triage_last_hour_returns_pre_loaded_results(
    session, audit, indexer, httpx_mock
):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-alerts-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_id": "a1",
                        "_source": {
                            "timestamp": "t",
                            "agent": {"id": "001"},
                            "rule": {
                                "id": "1",
                                "level": 10,
                                "description": "x",
                            },
                        },
                    }
                ],
            }
        },
    )
    out = await triage_handle(session=session, indexer=indexer, audit=audit)
    text = out["messages"][0]["content"]["text"]
    assert "TOTAL IN RANGE: 1" in text


@pytest.mark.asyncio
async def test_agent_posture_not_found(session, audit, indexer, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/agents?agents_list=999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    out = await agent_posture_handle(
        agent_id="999",
        session=session,
        indexer=indexer,
        server_api=server_api,
        audit=audit,
    )
    text = out["messages"][0]["content"]["text"]
    assert "not found" in text.lower()
```

- [ ] **Step 21.6: Run + lint + commit**

Run: `uv run pytest tests/unit/test_prompts.py -v && uv run ruff check . && uv run ty check src tests 2>&1 | tail -3`
Expected: 4 tests pass; all checks passed.

```bash
git add src/wazuh_mcp/prompts/ tests/unit/test_prompts.py
git commit -m "Add context-loaded prompts: investigate_alert, triage_last_hour, agent_posture"
```

---

## Task 22: Register all tools, resources, and prompts in `server.py` [A]

**Tier A:** Wiring is the single load-bearing surface that decides what MCP exposes. Misconfiguration here (wrong factory, missing audit, mis-tagged toolset) is production-visible.

**Files:**
- Modify: `src/wazuh_mcp/server.py` (both `build_app` stdio path and `build_http_app` HTTP path)
- Create: `tests/unit/test_server_registration.py`

- [ ] **Step 22.1: Extend `HttpAppConfig` to carry the Server API pool**

In `src/wazuh_mcp/server.py`, replace the `HttpAppConfig` dataclass and `load_http_config` to add server-api-pool wiring:

```python
from wazuh_mcp.wazuh.server_api_pool import ServerApiClientPool


@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    server_api_pool: ServerApiClientPool
    chain: ChainSessionFactory
    oauth: OAuthSessionFactory
    issuer_index: IssuerIndex
    resource_url: str
    authorization_server: str


def load_http_config(config_dir: Path) -> HttpAppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    all_tenants = [registry.get(tid) for tid in _tenant_ids(config_dir / "tenants.yaml")]
    issuer_index = IssuerIndex(all_tenants)

    oauth_cfg = server_cfg["oauth"]
    oauth = OAuthSessionFactory(
        issuer=oauth_cfg["issuer"],
        audience=oauth_cfg["audience"],
        algorithms=list(oauth_cfg.get("algorithms", ["RS256"])),
        rbac_claims=list(
            oauth_cfg.get("rbac_claims", ["wazuh_mcp_role", "groups", "roles"])
        ),
        issuer_index=issuer_index,
        clock_skew_seconds=int(oauth_cfg.get("clock_skew_seconds", 30)),
        jwks=JwksCache(issuer=oauth_cfg["issuer"]),
    )

    api_store = YamlApiKeyStore(Path(server_cfg["api_keys_file"]))
    api_key_factory = ApiKeySessionFactory(store=api_store)

    chain = ChainSessionFactory(oauth=oauth, api_key=api_key_factory)
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    server_api_pool = ServerApiClientPool(registry=registry, secrets=secrets)

    http_cfg = server_cfg["http"]
    return HttpAppConfig(
        pool=pool,
        server_api_pool=server_api_pool,
        chain=chain,
        oauth=oauth,
        issuer_index=issuer_index,
        resource_url=http_cfg["public_url"],
        authorization_server=oauth_cfg["issuer"],
    )
```

- [ ] **Step 22.2: Register every new tool**

Inside `build_http_app`, replace the single `@mcp_app.tool` block for `alerts.search_alerts` with the full M3 registration block. This is long but literal.

```python
def build_http_app(http_cfg: HttpAppConfig, audit: AuditEmitter | None = None):
    """Build the ASGI app. Returns a Starlette/SessionMiddleware-wrapped app."""
    audit_emitter = audit or AuditEmitter()
    mcp_app = FastMCP(name="wazuh-mcp")

    # ---------- alerts.* ----------
    from wazuh_mcp.tools.alerts import (
        AlertsByAgentArgs,
        AlertsByMitreArgs,
        GetAlertArgs,
        SearchAlertsArgs,
        alerts_by_agent,
        alerts_by_mitre,
        get_alert,
        search_alerts,
    )

    @mcp_app.tool(
        name="alerts.search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
        meta={"toolset": "alerts"},
    )
    async def _search_alerts(**kwargs):
        args = SearchAlertsArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await search_alerts(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="alerts.get_alert",
        description="Fetch a single Wazuh alert by its document id.",
        meta={"toolset": "alerts"},
    )
    async def _get_alert(**kwargs):
        args = GetAlertArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await get_alert(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="alerts.alerts_by_agent",
        description="List alerts for a specific agent over a time range.",
        meta={"toolset": "alerts"},
    )
    async def _alerts_by_agent(**kwargs):
        args = AlertsByAgentArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await alerts_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="alerts.alerts_by_mitre",
        description="List alerts matching a MITRE ATT&CK technique id.",
        meta={"toolset": "alerts"},
    )
    async def _alerts_by_mitre(**kwargs):
        args = AlertsByMitreArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await alerts_by_mitre(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- agents.* ----------
    from wazuh_mcp.tools.agents import (
        AgentSubquery,
        GetAgentArgs,
        ListAgentsArgs,
        agent_packages,
        agent_ports,
        agent_processes,
        get_agent,
        list_agents,
    )

    @mcp_app.tool(
        name="agents.list_agents",
        description="List Wazuh agents, optionally filtered by status or group.",
        meta={"toolset": "agents"},
    )
    async def _list_agents(**kwargs):
        args = ListAgentsArgs(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await list_agents(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.get_agent",
        description="Fetch a single Wazuh agent by id.",
        meta={"toolset": "agents"},
    )
    async def _get_agent(**kwargs):
        args = GetAgentArgs(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await get_agent(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_processes",
        description="List processes seen on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_processes(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await agent_processes(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_packages",
        description="List installed packages on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_packages(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await agent_packages(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="agents.agent_ports",
        description="List open ports on an agent (syscollector inventory).",
        meta={"toolset": "agents"},
    )
    async def _agent_ports(**kwargs):
        args = AgentSubquery(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await agent_ports(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    # ---------- vulnerabilities.* ----------
    from wazuh_mcp.tools.vulns import (
        ListVulnerabilitiesByAgentArgs,
        SearchVulnerabilitiesArgs,
        list_vulnerabilities_by_agent,
        search_vulnerabilities,
    )

    @mcp_app.tool(
        name="vulnerabilities.list_vulnerabilities_by_agent",
        description="List vulnerabilities for an agent (Wazuh 4.8+ indexer-backed).",
        meta={"toolset": "vulnerabilities"},
    )
    async def _list_vulns(**kwargs):
        args = ListVulnerabilitiesByAgentArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await list_vulnerabilities_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="vulnerabilities.search_vulnerabilities",
        description="Search vulnerabilities by CVE id or minimum severity.",
        meta={"toolset": "vulnerabilities"},
    )
    async def _search_vulns(**kwargs):
        args = SearchVulnerabilitiesArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await search_vulnerabilities(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- mitre.* ----------
    from wazuh_mcp.tools.mitre import (
        GetMitreTechniqueArgs,
        SearchMitreArgs,
        get_mitre_technique,
        search_mitre,
    )

    @mcp_app.tool(
        name="mitre.get_mitre_technique",
        description="Look up a MITRE ATT&CK technique by id (e.g. T1110.001).",
        meta={"toolset": "mitre"},
    )
    async def _get_technique(**kwargs):
        args = GetMitreTechniqueArgs(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await get_mitre_technique(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    @mcp_app.tool(
        name="mitre.search_mitre",
        description="Search MITRE techniques by name substring or tactic.",
        meta={"toolset": "mitre"},
    )
    async def _search_mitre(**kwargs):
        args = SearchMitreArgs(**kwargs)
        session = current_session()
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await search_mitre(
            args=args, session=session, server_api=server_api, audit=audit_emitter
        )

    # ---------- hunt.* ----------
    from wazuh_mcp.tools.hunt import (
        HuntQueryArgs,
        PivotByIocArgs,
        hunt_query,
        pivot_by_ioc,
    )

    @mcp_app.tool(
        name="hunt.hunt_query",
        description=(
            "Run a constrained-grammar hunt across alerts. Accepts "
            "structured {field, op, value} clauses from an allowlist — "
            "never raw DSL."
        ),
        meta={"toolset": "hunt"},
    )
    async def _hunt(**kwargs):
        args = HuntQueryArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await hunt_query(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="hunt.pivot_by_ioc",
        description="Pivot alerts by hash/ip/user/domain (preset over hunt_query).",
        meta={"toolset": "hunt"},
    )
    async def _pivot(**kwargs):
        args = PivotByIocArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await pivot_by_ioc(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- fim.* ----------
    from wazuh_mcp.tools.fim import (
        FimChangesArgs,
        FimHistoryArgs,
        fim_changes_by_agent,
        fim_history_for_path,
    )

    @mcp_app.tool(
        name="fim.fim_history_for_path",
        description="History of file-integrity events for a specific path.",
        meta={"toolset": "fim"},
    )
    async def _fim_history(**kwargs):
        args = FimHistoryArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await fim_history_for_path(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.tool(
        name="fim.fim_changes_by_agent",
        description="Recent file-integrity changes on a specific agent.",
        meta={"toolset": "fim"},
    )
    async def _fim_changes(**kwargs):
        args = FimChangesArgs(**kwargs)
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await fim_changes_by_agent(
            args=args, session=session, indexer=indexer, audit=audit_emitter
        )

    # ---------- resources ----------
    from wazuh_mcp.resources import TEMPLATES
    from wazuh_mcp.resources.agent_config import read_agent_config
    from wazuh_mcp.resources.mitre import read_mitre_technique
    from wazuh_mcp.resources.rules import read_rule

    @mcp_app.list_resource_templates()
    async def _list_templates():
        return [
            {
                "uriTemplate": t.uri_template,
                "name": t.name,
                "description": t.description,
                "mimeType": t.mime_type,
            }
            for t in TEMPLATES
        ]

    @mcp_app.list_resources()
    async def _list_resources():
        return []

    @mcp_app.read_resource()
    async def _read_resource(uri: str):
        session = current_session()
        # Pattern-match on the URI template; dispatch to the right reader.
        if uri.startswith("wazuh://rules/"):
            rule_id = uri[len("wazuh://rules/"):]
            server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
            return await read_rule(
                rule_id=rule_id,
                session=session,
                server_api=server_api,
                audit=audit_emitter,
            )
        if uri.startswith("wazuh://mitre/technique/"):
            technique_id = uri[len("wazuh://mitre/technique/"):]
            server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
            return await read_mitre_technique(
                technique_id=technique_id,
                session=session,
                server_api=server_api,
                audit=audit_emitter,
            )
        if uri.startswith("wazuh://agents/") and uri.endswith("/config"):
            agent_id = uri[len("wazuh://agents/"):-len("/config")]
            server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
            return await read_agent_config(
                agent_id=agent_id,
                session=session,
                server_api=server_api,
                audit=audit_emitter,
            )
        from wazuh_mcp.wazuh.errors import WazuhError

        raise WazuhError("not_found", "unknown resource URI", 404)

    # ---------- prompts ----------
    from wazuh_mcp.prompts import agent_posture, investigate_alert, triage_last_hour

    @mcp_app.prompt(name="wazuh:investigate-alert")
    async def _investigate_alert(alert_id: str):
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await investigate_alert.handle(
            alert_id=alert_id,
            session=session,
            indexer=indexer,
            server_api=server_api,
            audit=audit_emitter,
        )

    @mcp_app.prompt(name="wazuh:triage-last-hour")
    async def _triage():
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await triage_last_hour.handle(
            session=session, indexer=indexer, audit=audit_emitter
        )

    @mcp_app.prompt(name="wazuh:agent-posture")
    async def _posture(agent_id: str):
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        server_api = await http_cfg.server_api_pool.acquire(session.tenant_id)
        return await agent_posture.handle(
            agent_id=agent_id,
            session=session,
            indexer=indexer,
            server_api=server_api,
            audit=audit_emitter,
        )

    # ---------- ASGI wire-up ----------
    ready = [False]

    def ready_fn() -> bool:
        return ready[0]

    asgi = build_asgi_app(
        mcp_app=mcp_app,
        factory=http_cfg.chain,
        resource_url=http_cfg.resource_url,
        authorization_server=http_cfg.authorization_server,
        ready_fn=ready_fn,
    )

    ready[0] = True
    return asgi
```

**Implementer note**: the MCP Python SDK's exact decorator names for resources and prompts are `@mcp.list_resources()`, `@mcp.list_resource_templates()`, `@mcp.read_resource()`, `@mcp.prompt()`. If those decorators don't exist on this SDK version, fall back to registering via `mcp_app.add_*` helpers — check `uv run python -c "from mcp.server.fastmcp import FastMCP; print([m for m in dir(FastMCP) if 'resource' in m or 'prompt' in m])"` for the supported API.

- [ ] **Step 22.3: Repeat the same registrations for the stdio `build_app` path**

Apply the same tool/resource/prompt registration block (minus the HTTP pool acquisition — stdio tools use a single local indexer — but the overall structure is the same). The stdio path needs a single-tenant `ServerApiClient` built from the config's tenant + secrets.

If the stdio path is pre-M3 configured for a single tool only, the simplest migration is to factor the tool-registration code out of `build_http_app` into a shared helper `_register_all(mcp_app, pool, server_api_pool, audit)` and call it from both `build_app` (with `pool` + `server_api_pool` created from the single-tenant config) and `build_http_app`.

**Do the extraction in this task** — otherwise the duplication bit-rots. Name the helper `_register_everything`.

- [ ] **Step 22.4: Write smoke test for server wiring**

Create `tests/unit/test_server_registration.py`:

```python
"""Smoke tests: every expected tool/resource/prompt registers."""

import pytest

from wazuh_mcp.server import build_http_app, HttpAppConfig
# plus whatever fakes/fixtures are needed — mirror test_asgi_composition.py
# for the factory + pool stubs.


def _fake_http_cfg(**overrides):
    # Build a HttpAppConfig using the same fakes as test_asgi_composition.
    # See that file for the pattern; reuse or extract shared fixtures.
    raise NotImplementedError  # implementer fills in using local fakes


def test_expected_tool_names_are_registered(monkeypatch):
    """Every M3 tool appears in the FastMCP tool registry."""
    cfg = _fake_http_cfg()
    app = build_http_app(cfg)
    # FastMCP exposes the underlying tool registry via .streamable_http_app()'s
    # router or directly via ._tool_manager.list_tools(). Use whichever is
    # stable for this SDK version — `uv run python -c "from mcp.server.fastmcp
    # import FastMCP; print(dir(FastMCP()))"` to confirm.
    from mcp.server.fastmcp import FastMCP  # noqa: F401

    # The test assertion is what matters — find the right accessor once and hardcode it.
    tool_names = _extract_tool_names(app)
    expected = {
        "alerts.search_alerts",
        "alerts.get_alert",
        "alerts.alerts_by_agent",
        "alerts.alerts_by_mitre",
        "agents.list_agents",
        "agents.get_agent",
        "agents.agent_processes",
        "agents.agent_packages",
        "agents.agent_ports",
        "vulnerabilities.list_vulnerabilities_by_agent",
        "vulnerabilities.search_vulnerabilities",
        "mitre.get_mitre_technique",
        "mitre.search_mitre",
        "hunt.hunt_query",
        "hunt.pivot_by_ioc",
        "fim.fim_history_for_path",
        "fim.fim_changes_by_agent",
    }
    missing = expected - tool_names
    assert not missing, f"missing tool registrations: {missing}"


def _extract_tool_names(asgi_app):
    """Retrieve registered tool names from the ASGI app's inner FastMCP.

    Implementer: probe the FastMCP attribute the SDK exposes. As of M3 writing
    the stable surface is `mcp_app._tool_manager.list_tools()` returning
    objects with .name attributes; confirm via:

        uv run python -c "from mcp.server.fastmcp import FastMCP;
        m = FastMCP(name='t'); m.tool(name='x')(lambda: None);
        print(m._tool_manager.list_tools())"

    Hardcode the right accessor in this helper.
    """
    raise NotImplementedError
```

Note: the two `NotImplementedError` placeholders in the test file are exceptional — this task depends on SDK-specific accessors that are faster to discover once at implementation time than to sketch in-plan. Replace both with the discovered accessor. The intent is that the tests loudly fail until the implementer probes the SDK with the listed one-liner and hardcodes the right attribute path.

- [ ] **Step 22.5: Run everything + commit**

Run: `uv run pytest -q 2>&1 | tail -5`
Expected: all unit tests pass (190+).

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check src tests 2>&1 | tail -3`
Expected: all checks passed.

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_registration.py
git commit -m "Register all M3 tools, resources, and prompts in server.py

All tool registrations carry meta={\"toolset\": \"<domain>\"} for
future MCP toolset client support. HttpAppConfig now wires a per-tenant
ServerApiClientPool alongside the IndexerClientPool. Tool-registration
helpers are extracted into _register_everything() so stdio and HTTP
paths stay in sync.
"
```

---

## Task 23: Extend integration fixture with Wazuh manager container [B]

**Tier B:** Docker plumbing. Reviewed via a green integration run.

**Files:**
- Modify: `docker/integration-compose.yml`
- Modify: `docker/bootstrap.sh`
- Create: `docker/config/wazuh_manager_ossec.conf`
- Modify: `tests/integration/conftest.py`

- [ ] **Step 23.1: Add manager + agent containers**

Open `docker/integration-compose.yml`. Append two services and bump the `generator` + `wazuh-indexer` configs if needed. A minimal manager add-on:

```yaml
  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    platform: linux/amd64
    hostname: wazuh-manager
    depends_on:
      generator:
        condition: service_completed_successfully
      wazuh-indexer:
        condition: service_healthy
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=admin
      - FILEBEAT_SSL_VERIFICATION_MODE=none
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MCPmcp12345!
    ports:
      - "55000:55000"
    volumes:
      - ./config/wazuh_indexer_ssl_certs/:/etc/ssl/certs/wazuh/:ro
      - ./config/wazuh_manager_ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro
    healthcheck:
      test:
        - "CMD-SHELL"
        - "curl -skfu wazuh-wui:MCPmcp12345! https://localhost:55000/security/user/authenticate?raw=true | grep -q token"
      interval: 15s
      timeout: 10s
      retries: 40
      start_period: 120s
```

Agent seeding is optional for M3 — tools that query `/agents` will return an empty list if no agents are registered, which is fine for the fixture to exercise the request path. If desired, add a second `wazuh-agent` service in a later patch.

- [ ] **Step 23.2: Write the manager config**

Create `docker/config/wazuh_manager_ossec.conf` with the minimum vendor-shipped config. The Wazuh 4.9 default `ossec.conf` is ~300 lines; copy from the official repo and tweak two things: the `<api>` password (matches the compose `API_PASSWORD`) and TLS verify disabled for the integration fixture. Implementer: fetch the reference via

```bash
curl -sfL https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.9.0/single-node/config/wazuh_cluster/wazuh_manager.conf -o docker/config/wazuh_manager_ossec.conf
```

then edit the `<password>` line and any `<verify_peer>` / `<ca_verification>` lines to match the compose environment.

- [ ] **Step 23.3: Extend `bootstrap.sh`**

Add a manager-wait block to `docker/bootstrap.sh`:

```bash
echo "[bootstrap] waiting for wazuh-manager Server API..."
for _ in $(seq 1 40); do
    if curl -sfku wazuh-wui:MCPmcp12345! \
        "https://localhost:55000/security/user/authenticate?raw=true" \
        > /dev/null 2>&1; then
        echo "[bootstrap] wazuh-manager API ready."
        break
    fi
    sleep 10
done
```

- [ ] **Step 23.4: Add a server-api-token fixture**

Extend `tests/integration/conftest.py`:

```python
WAZUH_MANAGER_URL = os.environ.get("WAZUH_MANAGER_URL", "https://localhost:55000")
WAZUH_MANAGER_USER = os.environ.get("WAZUH_MANAGER_USER", "wazuh-wui")
WAZUH_MANAGER_PASSWORD = os.environ.get("WAZUH_MANAGER_PASSWORD", "MCPmcp12345!")


@pytest.fixture
def server_api_token():
    """Mint a raw Wazuh Server API JWT — bypasses the OAuth plumbing for
    pure Server-API-surface integration tests.
    """

    def _get() -> str:
        resp = httpx.post(
            f"{WAZUH_MANAGER_URL}/security/user/authenticate?raw=true",
            auth=(WAZUH_MANAGER_USER, WAZUH_MANAGER_PASSWORD),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.text.strip()

    return _get
```

- [ ] **Step 23.5: Commit**

Run: `docker compose -f docker/integration-compose.yml down -v && docker/bootstrap.sh` (expect ~3-4 min). Then:

```bash
git add docker/integration-compose.yml docker/bootstrap.sh docker/config/wazuh_manager_ossec.conf tests/integration/conftest.py
git commit -m "Add wazuh-manager container and Server API token fixture to integration suite"
```

---

## Task 24: Per-tool integration smoke [B]

**Tier B batch:** One integration test per new tool confirming the end-to-end path against the real fixture.

**Files:**
- Create: `tests/integration/test_tools_integration.py`
- Create: `tests/integration/test_resources_integration.py`
- Create: `tests/integration/test_prompts_integration.py`

- [ ] **Step 24.1: `tests/integration/test_tools_integration.py`**

Create `tests/integration/test_tools_integration.py`:

```python
"""Per-tool integration smokes against the full fixture (manager + indexer + Keycloak)."""

from __future__ import annotations

import pytest

from tests.integration.test_oauth_e2e import MCP_URL


@pytest.mark.integration
async def test_alerts_tools_all_respond(mcp_http_server, keycloak_token):
    """Call each alerts.* tool; assert structured response even if results are empty."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            # search_alerts
            r = await session.call_tool(
                "alerts.search_alerts", {"time_range": "24h", "size": 3}
            )
            assert not r.isError
            # alerts_by_agent — any agent that exists OR returns zero
            r = await session.call_tool(
                "alerts.alerts_by_agent",
                {"agent_id": "000", "time_range": "24h", "size": 3},
            )
            assert not r.isError
            # alerts_by_mitre — any technique
            r = await session.call_tool(
                "alerts.alerts_by_mitre",
                {"technique_id": "T1110.001", "time_range": "24h", "size": 3},
            )
            assert not r.isError
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_agents_tools_all_respond(mcp_http_server, keycloak_token):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool("agents.list_agents", {"size": 5})
            assert not r.isError
    finally:
        await http_client.aclose()


@pytest.mark.integration
async def test_hunt_query_rejects_off_allowlist_field(mcp_http_server, keycloak_token):
    """The hunt grammar's field allowlist must be enforced end-to-end."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            r = await session.call_tool(
                "hunt.hunt_query",
                {
                    "time_range": "1h",
                    "must": [
                        {"field": "vulnerability.id", "op": "eq", "value": "CVE-X"}
                    ],
                },
            )
            assert r.isError, "expected ValidationError surfaced to the client"
    finally:
        await http_client.aclose()
```

- [ ] **Step 24.2: `tests/integration/test_resources_integration.py`**

Create minimally — the fixture needs a known rule id to read. Use rule 1, which is in every Wazuh default ruleset (it's the `Generic template for level 0 rules`). If not present in the fixture image, pick any rule id that `curl -skfu admin:admin https://localhost:55000/rules?limit=1` returns.

```python
"""Integration smoke: resource templates are reachable end-to-end."""

from __future__ import annotations

import pytest

from tests.integration.test_oauth_e2e import MCP_URL


@pytest.mark.integration
async def test_list_resource_templates_returns_three(mcp_http_server, keycloak_token):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            templates = await session.list_resource_templates()
    finally:
        await http_client.aclose()

    uris = {t.uriTemplate for t in templates.resourceTemplates}
    assert uris == {
        "wazuh://rules/{id}",
        "wazuh://mitre/technique/{id}",
        "wazuh://agents/{id}/config",
    }


@pytest.mark.integration
async def test_read_mitre_technique(mcp_http_server, keycloak_token):
    """T1110 is in every Wazuh-bundled ATT&CK dataset."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.read_resource("wazuh://mitre/technique/T1110")
    finally:
        await http_client.aclose()

    assert result.contents, "expected at least one content block"
    # Confirm TTL meta is present.
    assert result.meta is not None and result.meta.get("ttl_seconds") == 86_400
```

- [ ] **Step 24.3: `tests/integration/test_prompts_integration.py`**

```python
"""Integration smoke: prompts return pre-loaded context messages."""

from __future__ import annotations

import pytest

from tests.integration.test_oauth_e2e import MCP_URL


@pytest.mark.integration
async def test_triage_last_hour_prompt(mcp_http_server, keycloak_token):
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = keycloak_token()
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{MCP_URL}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.get_prompt("wazuh:triage-last-hour")
    finally:
        await http_client.aclose()

    assert result.messages, "expected the prompt to return at least one message"
    text = result.messages[0].content.text
    assert "TOTAL IN RANGE" in text
```

- [ ] **Step 24.4: Run and commit**

Run: `uv run pytest -m integration -v 2>&1 | tail -15`
Expected: all integration tests pass — the existing 9 from Task-20 work plus ~6 new (3 tool, 2 resource, 1 prompt).

```bash
git add tests/integration/test_tools_integration.py tests/integration/test_resources_integration.py tests/integration/test_prompts_integration.py
git commit -m "Add per-tool/resource/prompt integration smokes against full fixture"
```

---

## Task 25: Operator docs — M3 tool reference + OAuth claim setup [B]

**Tier B:** Documentation only. Spot-checked via a rendered-markdown look; no new tests.

**Files:**
- Create: `docs/deploy/m3-tools.md`
- Modify: `docs/deploy/oauth-setup/keycloak.md`
- Modify: `docs/deploy/oauth-setup/okta.md`
- Modify: `docs/deploy/oauth-setup/entra.md`
- Modify: `docs/deploy/oauth-setup/auth0.md`
- Modify: `docs/security/threat-model.md`
- Modify: `README.md`

- [ ] **Step 25.1: `docs/deploy/m3-tools.md`**

Write a per-tool reference with the tool name, argument schema, example JSON-RPC call, and an operator note on least-privileged Wazuh RBAC role for each tool. Template per tool:

```markdown
### `alerts.search_alerts`

Search Wazuh alerts by time range + filters.

| Arg | Type | Notes |
|---|---|---|
| `time_range` | `str` | `<int><m\|h\|d>`, ≤ 30 days. Default `1h`. |
| `min_level` | `int?` | 0..15. |
| `agent_id` | `str?` | Literal `agent.id`. |
| `size` | `int` | 1..100. Default 25. |
| `cursor` | `list?` | Opaque `search_after` cursor from a prior call. |

Returns: `SearchAlertsResult` — `alerts[]`, `total`, `next_cursor`, `truncated`.

Required Wazuh RBAC permission: `agent:read`, read access on `wazuh-alerts-*`.

Example call:

\`\`\`json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name":"alerts.search_alerts",
  "arguments":{"time_range":"1h","min_level":10,"size":10}
}}
\`\`\`
```

Do this for every M3 tool + the three prompts + the three resources. Aim for ~300 lines total.

- [ ] **Step 25.2: Update each IdP guide with the `wazuh_user` claim config**

Each of `keycloak.md`, `okta.md`, `entra.md`, `auth0.md` gets a new subsection:

```markdown
## Emitting the `wazuh_user` claim

For per-user attribution in Wazuh's audit log (`run_as`), the access token
must carry a claim whose value is the Wazuh username the bearer maps to.
The claim name is configured in `tenants.yaml` via `wazuh_user_claim`
(default `wazuh_user`).

### Keycloak example (user-attribute mapper)

1. Realm → Users → <user> → Attributes: add `wazuh_user=<wazuh-username>`.
2. Realm → Clients → `wazuh-mcp-client` → Client scopes → `wazuh-mcp-client-dedicated` → Add mapper → By configuration → **User Attribute**.
    - Name: `wazuh_user-mapper`
    - User Attribute: `wazuh_user`
    - Token Claim Name: `wazuh_user`
    - Add to access token: **On**
    - Multivalued: **Off**

Absent claim → request runs as the tenant's Server API service account.
```

Adapt the recipe for Okta (profile editor + access-token claim), Entra (App registration → Manifest optionalClaims → accessToken), Auth0 (Actions → post-login rule).

- [ ] **Step 25.3: Extend `docs/security/threat-model.md`**

Append an "M3 additions" section covering:
- The Server API client's JWT hygiene (never signature-validated client-side).
- `run_as` policy (only from bearer; no tool-args path).
- `hunt_query` allowlist + the specific banned DSL keys.
- Resources as a new MCP surface and their tenant-scoping guarantee.
- Prompts as privilege-equivalent to tool calls under the session identity.
- New error codes `not_found`, `upstream_timeout` — what each does and doesn't leak.

- [ ] **Step 25.4: Update `README.md`**

Replace the M2 tool-list section with the M3 list (17 tools, 3 resources, 3 prompts). Add a one-line note that M3 requires Wazuh ≥ 4.8 per the design doc's decided floor.

- [ ] **Step 25.5: Commit**

```bash
git add docs/ README.md
git commit -m "M3 operator docs: tool reference, wazuh_user claim setup, threat-model update"
```

---

## Task 26: Full-suite verification, tag, and retro [B]

**Tier B:** Ship gate.

**Files:**
- Create: `docs/superpowers/retros/2026-04-22-m3-retro.md`

- [ ] **Step 26.1: Final green run**

Run: `docker compose -f docker/integration-compose.yml down -v && docker/bootstrap.sh && uv run pytest -q`
Expected: all unit + integration green (~210 unit + ~15 integration, numbers will land during implementation).

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check src tests`
Expected: all checks passed.

- [ ] **Step 26.2: Version bump**

Bump `version` in `pyproject.toml` to `0.3.0`. Commit:

```bash
git add pyproject.toml
git commit -m "Bump version to 0.3.0 for v0.3.0-m3"
```

- [ ] **Step 26.3: Write the retro**

Create `docs/superpowers/retros/2026-04-22-m3-retro.md` modelled on `2026-04-21-m2-retro.md`:
- Outcome (tests green, tag, LOC delta).
- What went well (batching tier-B, dual-review caught X, hunt fuzz caught Y).
- Plan bugs caught during execution.
- Known gaps carried into M4 (write tools, OTel, RBAC-aware list_tools, rate limits, real SecretStores, formal toolset SDK support).
- Architecture survivors (Session, SecretValue, SessionFactory, IndexerClient/Pool, ServerApiClient/Pool, transport layer, query-builder pattern, WazuhError + SAFE_CODES).
- Planning guidance for M4.
- Token burn delta vs M2.

Commit:

```bash
git add docs/superpowers/retros/2026-04-22-m3-retro.md
git commit -m "M3 retro: v0.3.0-m3 shipped with full read-path tool surface"
```

- [ ] **Step 26.4: Tag**

```bash
git tag -a v0.3.0-m3 -m "M3 — full read-path tool surface (14 tools, 3 resources, 3 prompts)"
git log --oneline | head -15
```

- [ ] **Step 26.5: Update memory** (off-repo, but part of shipping)

Update `/Users/moody/.claude/projects/-Users-moody-VSCode-wazuh-mcp/memory/project_state.md`:
- Add M3 to the "Shipped milestones" list.
- Clear the gap-#2 Task-20 carryover punch-list (all items landed).
- Add new M4 punch-list items that emerge from the M3 retro.

No git action — memory lives outside the repo.

---

## Self-review

Every step's code block was drafted assuming strict `ruff check` + `ty check` runs cleanly on it. The plan covers:

- **Spec §2 decisions 1-13**: each has at least one task that implements it.
  - D1 (one tag): task ordering lands under a single `v0.3.0-m3` tag (T26).
  - D2 (wazuh_user claim): T1-T3.
  - D3 (flat return, no text): T10.
  - D4 (4.8+ only): T11 (Vulnerability shape), T17 (vuln tools hit indexer), docs T25.
  - D5 (dotted names): T10, T13-T19, T22.
  - D6 (hunt grammar): T14 + T15 (fuzz).
  - D7 (resources templates + TTL): T20.
  - D8 (three prompts): T21.
  - D9 (context-loaded prompts): T21.
  - D10 (meta-annotated toolsets): T22 wires `meta={"toolset": ...}` on every registration.
  - D11 (Server API client shape): T7 + T8 + T9.
  - D12 (Wazuh manager in fixture): T23.
  - D13 (carryovers + testing): T4 (error codes), T5 (`resource_metadata`), T6 (seed drift + SDK migration + dummy), T15 (fuzz), T8 (security-negatives), T24 (per-tool integration).
- **Placeholder scan**: the two `NotImplementedError` markers in T22.4's `_extract_tool_names` helper are intentional probes — they force the implementer to run the one-liner and hardcode the SDK accessor; flagged explicitly in the task. No other placeholders.
- **Type consistency**: all `SearchAlertsResult`, `HuntQueryResult`, `FimResult`, `VulnerabilitiesResult`, `AgentsResult`, `AgentResult`, `AgentInventoryResult`, `MitreTechniqueResult`, `MitreSearchResult`, `GetAlertResult`, and the resource/prompt shapes have consistent field names throughout. `session.wazuh_user` is the attribute name end-to-end (no `wazuh_user_id` variants). `run_as` is passed only via `ServerApiClient.get/post(run_as=...)`; no other transport path.

## Task index

| # | Tier | Task | Dispatch strategy |
|---|:---:|---|---|
| 1 | A | `Session.wazuh_user` field | Solo, dual-review |
| 2 | B | `TenantConfig.wazuh_user_claim` | Batched with T3, T4 |
| 3 | A | OAuth factory extracts `wazuh_user` | Solo, dual-review |
| 4 | B | `SAFE_CODES` + `map_http_error` + `map_timeout` | Batched with T2 |
| 5 | A | `WWW-Authenticate resource_metadata=` | Solo, dual-review |
| 6 | B | Task-20 carryover batch (seed, SDK, dummy) | Solo implementer, spot-check (3 commits) |
| 7 | A | `ServerApiClient` mint + basic call | Solo, dual-review |
| 8 | A | `ServerApiClient` security-negatives | Solo, dual-review |
| 9 | B | `ServerApiClientPool` | Batched with T11 |
| 10 | A | Rename + flatten `search_alerts` | Solo, dual-review |
| 11 | B | Pydantic models (Agent, Vulnerability, Fim, Mitre) | Batched with T9 |
| 12 | A | Query builders (alerts/vulns/fim) | Solo, dual-review |
| 13 | B | `alerts.*` tools (get/by_agent/by_mitre) | Solo implementer, spot-check |
| 14 | A | `hunt.hunt_query` + `pivot_by_ioc` | Solo, dual-review |
| 15 | A | Hunt-query hypothesis fuzz | Solo, dual-review |
| 16 | B | `fim.*` tools | Batched with T17 |
| 17 | B | `vulnerabilities.*` tools | Batched with T16 |
| 18 | B | `agents.*` tools (5) | Solo implementer, spot-check |
| 19 | B | `mitre.*` tools (2) | Batched with T18 |
| 20 | A | Resources (rules, mitre, agent_config) | Solo, dual-review |
| 21 | A | Prompts (3 context-loaded) | Solo, dual-review |
| 22 | A | `server.py` registration of everything | Solo, dual-review |
| 23 | B | Integration fixture — Wazuh manager container | Solo implementer, spot-check |
| 24 | B | Per-tool/resource/prompt integration smokes | Solo implementer, spot-check |
| 25 | B | Operator docs | Solo implementer, spot-check |
| 26 | B | Tag + retro + memory update | Solo implementer, spot-check |

**Expected dispatches:** ~16 (with T2+T4, T9+T11, T16+T17, T18+T19 batched per the project methodology for adjacent low-risk tasks; T6's three commits in one dispatch).

**Expected final counts:** ~210 unit tests (up from 176), ~15 integration tests (up from 9), ~35 commits on top of v0.2.0-m2.
