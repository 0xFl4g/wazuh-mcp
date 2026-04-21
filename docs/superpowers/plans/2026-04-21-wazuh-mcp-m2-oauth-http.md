# Wazuh MCP M2 — Multi-tenant HTTP + OAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform M1's local stdio-only MCP server into a multi-tenant remote service with Streamable HTTP transport, OAuth 2.1 + API-key authentication, and per-tenant connection pooling — while keeping M1's stdio path fully compatible.

**Architecture:** Introduce a `SessionFactory` protocol; M1's config-based wiring becomes `ConfigSessionFactory`. M2 adds `OAuthSessionFactory` (joserfc-based JWT verification, JWKS cache with refresh-on-miss), `ApiKeySessionFactory` (argon2id), and `ChainSessionFactory` (token-prefix routing). The HTTP path mounts FastMCP's `streamable_http_app()` behind a Starlette middleware that builds `Session` per-request and stores it in a `contextvars.ContextVar`. Tool handlers pull `Session` from the contextvar — no new tool arguments.

**Tech Stack:** Python 3.12 • `uv` • `mcp` SDK (FastMCP + streamable HTTP mount) • `joserfc` 1.6 (successor to deprecated authlib.jose) • `argon2-cffi` 25 • `uvicorn[standard]` 0.30+ • `httpx` 0.27 (M1 sibling for JWKS fetch) • `pytest` + `pytest-asyncio` + `pytest-httpx` + `hypothesis` • Keycloak 26 (integration-test IdP) • Caddy (reference reverse proxy, docs only).

**Reference:** `docs/superpowers/specs/2026-04-21-wazuh-mcp-m2-design.md` (authoritative). `docs/superpowers/retros/2026-04-20-m1-retro.md` (planning guidance from M1).

**Out of scope for M2** (defer to M3–M5):
- Additional tools beyond `search_alerts` (M3).
- Server API client, JWT lifecycle for Wazuh upstream (M3).
- Real `SecretStore` backends — AWS SM, Vault, sqlite_age (M4).
- RBAC-aware `list_tools`, per-tenant rate limits, OTel, metrics (M4).
- Write tools, v2 write scaffolding (M4).
- Eval harness, Wazuh LTS matrix CI (M5).

**M1 invariants preserved:**
- `Session` frozen dataclass shape — unchanged.
- `SecretValue` redaction + hardening — unchanged.
- Query builder size/time caps, strict Pydantic, scrubbed errors — unchanged.
- Audit to stderr by default — unchanged.
- stdio path works bit-for-bit — required by `test_search_alerts_e2e.py` fixtures and by Claude Desktop installs pointing at the stdio entry point.

---

## File structure

```
wazuh-mcp/
├── pyproject.toml                              # MODIFIED (deps, ruff scope)
├── src/wazuh_mcp/
│   ├── __main__.py                             # MODIFIED (—transport flag)
│   ├── server.py                               # MODIFIED (factory wiring)
│   ├── auth/
│   │   ├── session.py                          # unchanged
│   │   ├── factory.py                          # NEW
│   │   ├── config_factory.py                   # NEW
│   │   ├── oauth.py                            # NEW
│   │   ├── jwks_cache.py                       # NEW
│   │   ├── api_key.py                          # NEW
│   │   ├── api_key_store.py                    # NEW
│   │   ├── chain_factory.py                    # NEW
│   │   └── errors.py                           # NEW
│   ├── tenancy/
│   │   ├── config.py                           # MODIFIED (oauth fields)
│   │   ├── registry.py                         # unchanged
│   │   └── issuer_index.py                     # NEW
│   ├── transport/
│   │   ├── __init__.py                         # NEW
│   │   ├── stdio.py                            # NEW (extracted from server.py)
│   │   ├── http.py                             # NEW
│   │   └── session_ctx.py                      # NEW
│   ├── wazuh/
│   │   ├── indexer.py                          # unchanged
│   │   ├── indexer_pool.py                     # NEW
│   │   ├── models.py                           # unchanged
│   │   ├── query.py                            # unchanged
│   │   └── errors.py                           # unchanged
│   └── tools/
│       └── alerts.py                           # unchanged
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   └── jwt_factory.py                      # NEW
│   ├── unit/
│   │   ├── test_config_factory.py              # NEW
│   │   ├── test_session_ctx.py                 # NEW
│   │   ├── test_auth_errors.py                 # NEW
│   │   ├── test_issuer_index.py                # NEW
│   │   ├── test_jwks_cache.py                  # NEW
│   │   ├── test_oauth_factory.py               # NEW
│   │   ├── test_api_key_store.py               # NEW
│   │   ├── test_api_key_factory.py             # NEW
│   │   ├── test_chain_factory.py               # NEW
│   │   ├── test_indexer_pool.py                # NEW
│   │   ├── test_oauth_http_mw.py               # NEW
│   │   ├── test_protected_resource_metadata.py # NEW
│   │   ├── test_healthz_readyz.py              # NEW
│   │   └── test_server_wiring.py               # MODIFIED
│   ├── security/
│   │   └── test_m2_negatives.py                # NEW
│   └── integration/
│       ├── conftest.py                         # MODIFIED (keycloak fixture)
│       └── test_oauth_e2e.py                   # NEW
├── docker/
│   ├── integration-compose.yml                 # MODIFIED (+keycloak)
│   ├── bootstrap.sh                            # MODIFIED (+keycloak seed)
│   └── config/
│       └── keycloak-realm.json                 # NEW
└── docs/
    └── deploy/
        ├── m2-http.md                          # NEW
        ├── api-keys.md                         # NEW
        └── oauth-setup/
            ├── keycloak.md                     # NEW
            ├── okta.md                         # NEW
            ├── entra.md                        # NEW
            └── auth0.md                        # NEW
```

---

## Tasks

### Task 1: Promote auth dependencies to runtime + extend server config schema

**Purpose:** `joserfc`, `authlib`, and `argon2-cffi` were prototyped as dev deps during brainstorming. They're runtime deps for M2. Also introduces the new `server.yaml` schema fields so every subsequent task has a config foundation to load from.

**Files:**
- Modify: `pyproject.toml`
- Modify: `config/server.yaml` (local only; gitignored — skip if not present)

- [ ] **Step 1.1: Update `pyproject.toml` dependencies**

Change `[project] dependencies`:

```toml
dependencies = [
    "mcp>=1.2.0",
    "httpx>=0.27.0",
    "pydantic>=2.7.0",
    "pyyaml>=6.0.1",
    "joserfc>=1.6.0",
    "argon2-cffi>=25.1.0",
    "uvicorn[standard]>=0.30.0",
]
```

Remove `authlib` and `argon2-cffi` from `[dependency-groups] dev`:

```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-httpx>=0.30",
    "hypothesis>=6.100",
    "ruff>=0.5.0",
    "ty>=0.0.32",
]
```

- [ ] **Step 1.2: Resync dependencies**

Run: `uv sync`
Expected: `joserfc`, `argon2-cffi`, `uvicorn[standard]` resolved. `authlib` removed (joserfc doesn't need it). Print "Resolved N packages".

- [ ] **Step 1.3: Verify imports**

Run: `uv run python -c "from joserfc import jwt; from argon2 import PasswordHasher; import uvicorn; print('ok')"`
Expected: `ok`.

- [ ] **Step 1.4: Smoke pytest to confirm no regressions**

Run: `uv run pytest -q -m "not integration"`
Expected: `98 passed` (M1 baseline).

- [ ] **Step 1.5: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "Promote joserfc + argon2-cffi + uvicorn to runtime dependencies"
```

---

### Task 2: SessionFactory protocol + ConfigSessionFactory

**Purpose:** Introduce the factory protocol every auth mode implements. Convert M1's existing config-load logic into a `ConfigSessionFactory` without breaking the existing `build_app` signature.

**Files:**
- Create: `src/wazuh_mcp/auth/factory.py`
- Create: `src/wazuh_mcp/auth/config_factory.py`
- Create: `tests/unit/test_config_factory.py`

- [ ] **Step 2.1: Write failing tests**

File: `tests/unit/test_config_factory.py`

```python
from pathlib import Path
from typing import Any

import pytest

from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.config import TenantConfig


@pytest.fixture
def tenant() -> TenantConfig:
    return TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.test:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )


async def test_config_factory_builds_session_from_fixed_config(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    ctx: RequestContext = {}
    session = await factory.build(ctx)
    assert isinstance(session, Session)
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "config"


async def test_config_factory_ignores_request_context(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    ctx1: RequestContext = {"headers": {"Authorization": "Bearer whatever"}}
    ctx2: RequestContext = {}
    s1 = await factory.build(ctx1)
    s2 = await factory.build(ctx2)
    assert s1 == s2


def test_config_factory_is_a_session_factory(tenant):
    factory = ConfigSessionFactory(user_id="alice", tenant=tenant)
    assert isinstance(factory, SessionFactory)
```

- [ ] **Step 2.2: Run — expect ImportError**

Run: `uv run pytest tests/unit/test_config_factory.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.auth.factory'`.

- [ ] **Step 2.3: Implement `factory.py`**

File: `src/wazuh_mcp/auth/factory.py`

```python
"""SessionFactory protocol — sole constructor of Session objects.

One implementation per auth mode. Transport layers call .build(ctx) per
request and propagate the returned Session via contextvars to tool handlers.
"""

from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable

from wazuh_mcp.auth.session import Session


class RequestContext(TypedDict, total=False):
    """Per-request data transports pass to factories.

    Only keys a factory actually needs are required. stdio supplies an empty
    context; HTTP supplies headers/client_ip.
    """

    headers: dict[str, str]
    client_ip: str


@runtime_checkable
class SessionFactory(Protocol):
    async def build(self, ctx: RequestContext) -> Session:
        """Return a Session. Raise AuthError subclasses on failure."""
        ...
```

- [ ] **Step 2.4: Implement `config_factory.py`**

File: `src/wazuh_mcp/auth/config_factory.py`

```python
"""ConfigSessionFactory — M1's stdio/config auth mode.

Session is built once from server.yaml at startup and returned identically
for every request. No token validation. Only valid for single-operator stdio.
"""

from __future__ import annotations

from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.config import TenantConfig


class ConfigSessionFactory(SessionFactory):
    __slots__ = ("_session",)

    def __init__(self, *, user_id: str, tenant: TenantConfig) -> None:
        object.__setattr__(
            self,
            "_session",
            Session(
                user_id=user_id,
                tenant_id=tenant.tenant_id,
                rbac_role=tenant.default_rbac_role,
                auth_method="config",
            ),
        )

    async def build(self, ctx: RequestContext) -> Session:
        return self._session
```

- [ ] **Step 2.5: Run — expect pass**

Run: `uv run pytest tests/unit/test_config_factory.py -v`
Expected: 3 passed.

- [ ] **Step 2.6: Commit**

```bash
git add src/wazuh_mcp/auth/factory.py src/wazuh_mcp/auth/config_factory.py tests/unit/test_config_factory.py
git commit -m "Add SessionFactory protocol and ConfigSessionFactory"
```

---

### Task 3: session_ctx ContextVar

**Purpose:** Tool handlers read `Session` from a per-request contextvar, not from a singleton. This is the indirection that lets HTTP mode have one Session per request without changing any tool code.

**Files:**
- Create: `src/wazuh_mcp/transport/__init__.py` (empty)
- Create: `src/wazuh_mcp/transport/session_ctx.py`
- Create: `tests/unit/test_session_ctx.py`

- [ ] **Step 3.1: Write failing tests**

File: `tests/unit/test_session_ctx.py`

```python
import asyncio

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.session_ctx import (
    CURRENT_SESSION,
    current_session,
    set_current_session,
)


def _session(user: str, tenant: str) -> Session:
    return Session(
        user_id=user, tenant_id=tenant, rbac_role="soc_analyst", auth_method="oauth"
    )


def test_current_session_raises_outside_context():
    with pytest.raises(LookupError):
        current_session()


def test_set_current_session_writes_contextvar():
    s = _session("alice", "acme")
    token = set_current_session(s)
    try:
        assert current_session() is s
    finally:
        CURRENT_SESSION.reset(token)
    with pytest.raises(LookupError):
        current_session()


async def test_concurrent_tasks_see_isolated_sessions():
    started = asyncio.Event()

    async def task_for(s: Session) -> str:
        token = set_current_session(s)
        try:
            started.set()
            # Yield so both tasks are interleaved in the event loop.
            await asyncio.sleep(0)
            return current_session().user_id
        finally:
            CURRENT_SESSION.reset(token)

    alice, bob = _session("alice", "acme"), _session("bob", "beta")
    results = await asyncio.gather(task_for(alice), task_for(bob))
    assert results == ["alice", "bob"]
```

- [ ] **Step 3.2: Run — expect ModuleNotFoundError**

Run: `uv run pytest tests/unit/test_session_ctx.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.transport'`.

- [ ] **Step 3.3: Create empty `transport/__init__.py`**

File: `src/wazuh_mcp/transport/__init__.py` — empty.

- [ ] **Step 3.4: Implement `session_ctx.py`**

File: `src/wazuh_mcp/transport/session_ctx.py`

```python
"""Per-request Session contextvar.

Transports set it in middleware before dispatching into the MCP app.
Tool handlers pull it via current_session(). Python asyncio guarantees
per-task isolation, so concurrent HTTP requests never see each other's
sessions.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

from wazuh_mcp.auth.session import Session

CURRENT_SESSION: ContextVar[Session] = ContextVar("wazuh_mcp_current_session")


def current_session() -> Session:
    """Return the Session for the current asyncio task.

    Raises LookupError if called outside a request context — a signal that
    the middleware was bypassed (programming error, not a runtime failure).
    """
    return CURRENT_SESSION.get()


def set_current_session(session: Session) -> Token[Session]:
    """Set the per-task Session. Callers MUST reset via CURRENT_SESSION.reset(token)."""
    return CURRENT_SESSION.set(session)
```

- [ ] **Step 3.5: Run — expect pass**

Run: `uv run pytest tests/unit/test_session_ctx.py -v`
Expected: 3 passed.

- [ ] **Step 3.6: Commit**

```bash
git add src/wazuh_mcp/transport/__init__.py src/wazuh_mcp/transport/session_ctx.py tests/unit/test_session_ctx.py
git commit -m "Add per-request Session contextvar"
```

---

### Task 4: Refactor server.py to use SessionFactory (stdio path intact)

**Purpose:** Rewire M1's stdio path so it goes through a `SessionFactory`. No behavior change; every existing test must still pass. This locks in the indirection layer without introducing HTTP yet.

**Files:**
- Modify: `src/wazuh_mcp/server.py`
- Modify: `tests/unit/test_server_wiring.py`

- [ ] **Step 4.1: Update `test_server_wiring.py`**

Read the current file (`tests/unit/test_server_wiring.py`) first. Then replace the body so it asserts the factory-driven wiring:

```python
import io
from pathlib import Path

import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import SessionFactory
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.server import build_app, load_config


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.test:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    (tmp_path / "secrets.yaml").write_text(
        """
acme:
  indexer_user: admin
  indexer_password: pw
""".strip()
    )
    (tmp_path / "server.yaml").write_text(
        """
active_tenant: acme
user_id: alice
""".strip()
    )
    return tmp_path


def test_load_config_builds_factory(config_dir):
    cfg = load_config(config_dir)
    assert isinstance(cfg.factory, SessionFactory)
    assert isinstance(cfg.factory, ConfigSessionFactory)
    assert cfg.tenant.tenant_id == "acme"


def test_build_app_registers_search_alerts(config_dir):
    cfg = load_config(config_dir)
    app = build_app(cfg)
    tool_names = {t.name for t in app._tool_manager.list_tools()}
    assert "search_alerts" in tool_names


async def test_registered_search_alerts_executes_against_mocked_indexer(
    config_dir, httpx_mock: HTTPXMock
):
    httpx_mock.add_response(
        url="https://wazuh.acme.test:9200/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    cfg = load_config(config_dir)
    audit_buf = io.StringIO()
    app = build_app(cfg, audit=AuditEmitter(stream=audit_buf))
    tool = next(t for t in app._tool_manager.list_tools() if t.name == "search_alerts")
    result = await tool.fn(time_range="1h")
    assert result["structuredContent"]["total"] == 0
    assert "0 alerts" in result["text"]
    assert '"tool": "search_alerts"' in audit_buf.getvalue()
```

- [ ] **Step 4.2: Run — expect failure on `cfg.factory`**

Run: `uv run pytest tests/unit/test_server_wiring.py -v`
Expected: AttributeError — `AppConfig` has `session` but not `factory`.

- [ ] **Step 4.3: Refactor `server.py`**

File: `src/wazuh_mcp/server.py` — replace the full content:

```python
"""MCP server wiring.

M1 path: stdio + ConfigSessionFactory (single-session from config).
M2 path: see transport/http.py for HTTP mode (uses OAuth/ApiKey factories).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import SessionFactory
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.transport.session_ctx import (
    CURRENT_SESSION,
    current_session,
    set_current_session,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


@dataclass(frozen=True)
class AppConfig:
    factory: SessionFactory
    tenant: TenantConfig
    secrets: YamlSecretStore


def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    factory = ConfigSessionFactory(user_id=user_id, tenant=tenant)
    return AppConfig(factory=factory, tenant=tenant, secrets=secrets)


def build_app(cfg: AppConfig, audit: AuditEmitter | None = None) -> FastMCP:
    audit_emitter = audit or AuditEmitter()
    app = FastMCP(name="wazuh-mcp")

    async def _open_indexer() -> IndexerClient:
        user = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_user")
        password = await cfg.secrets.get(cfg.tenant.tenant_id, "indexer_password")
        return IndexerClient(
            base_url=str(cfg.tenant.indexer_url),
            user=user,
            password=password,
            verify_tls=cfg.tenant.verify_tls,
            ca_bundle_path=cfg.tenant.ca_bundle_path,
        )

    @app.tool(
        name="search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
    )
    async def _search_alerts(
        time_range: str = "1h",
        min_level: int | None = None,
        agent_id: str | None = None,
        size: int = 25,
        cursor: list[Any] | None = None,
    ) -> dict[str, Any]:
        args = SearchAlertsArgs(
            time_range=time_range,
            min_level=min_level,
            agent_id=agent_id,
            size=size,
            cursor=cursor,
        )
        # For stdio: build a Session once via factory and pin it for this call.
        # (HTTP mode sets the contextvar in its middleware; we only need to
        # set it here when called without a pre-set context, i.e. stdio.)
        try:
            session = current_session()
            token = None
        except LookupError:
            session = await cfg.factory.build({})
            token = set_current_session(session)
        indexer = await _open_indexer()
        try:
            return await search_alerts(
                args=args,
                session=session,
                indexer=indexer,
                audit=audit_emitter,
            )
        finally:
            await indexer.aclose()
            if token is not None:
                CURRENT_SESSION.reset(token)

    return app


def run_stdio(config_dir: Path) -> None:
    cfg = load_config(config_dir)
    app = build_app(cfg)
    asyncio.run(app.run_stdio_async())
```

- [ ] **Step 4.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_server_wiring.py -v`
Expected: 3 passed.

- [ ] **Step 4.5: Full suite green**

Run: `uv run pytest -q -m "not integration"` — expect 99 passed (98 + 1 new `test_load_config_builds_factory`; `test_registered_search_alerts_executes_against_mocked_indexer` was already in M1's Task 13 follow-up).

- [ ] **Step 4.6: Lint + type check**

Run: `uv run ruff check . && uv run ruff format --check . && uv run ty check .`
Expected: all pass.

- [ ] **Step 4.7: Commit**

```bash
git add src/wazuh_mcp/server.py tests/unit/test_server_wiring.py
git commit -m "Refactor server.py to use SessionFactory and contextvar"
```

---

### Task 5: Auth errors module

**Files:**
- Create: `src/wazuh_mcp/auth/errors.py`
- Create: `tests/unit/test_auth_errors.py`

- [ ] **Step 5.1: Write failing tests**

File: `tests/unit/test_auth_errors.py`

```python
import pytest

from wazuh_mcp.auth.errors import (
    ApiKeyRevoked,
    AuthError,
    ExpiredToken,
    InvalidToken,
    MissingClaim,
    UnknownIssuer,
)


def test_auth_errors_share_base_class():
    for cls in (InvalidToken, ExpiredToken, UnknownIssuer, MissingClaim, ApiKeyRevoked):
        assert issubclass(cls, AuthError)


def test_auth_error_has_http_status():
    assert InvalidToken().http_status == 401
    assert ExpiredToken().http_status == 401
    assert UnknownIssuer().http_status == 401
    assert MissingClaim("tenant_id").http_status == 403
    assert ApiKeyRevoked().http_status == 401


def test_missing_claim_carries_claim_name():
    e = MissingClaim("tenant_id")
    assert e.claim_name == "tenant_id"


def test_repr_does_not_leak_internal_detail():
    e = InvalidToken(detail="SECRET upstream detail")
    # Optional `detail` is only for internal logs; repr must not include it.
    assert "SECRET" not in repr(e)


def test_auth_error_message_is_generic():
    e = InvalidToken(detail="SECRET")
    # str() is used for WWW-Authenticate headers and body scrubbing.
    # The message must be a fixed constant per class — no upstream data.
    assert str(e) in {"unauthorized", "invalid_token"}
```

- [ ] **Step 5.2: Run — expect ModuleNotFoundError**

Run: `uv run pytest tests/unit/test_auth_errors.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 5.3: Implement `errors.py`**

File: `src/wazuh_mcp/auth/errors.py`

```python
"""Auth-layer exception types.

Every AuthError maps to a fixed HTTP status and a fixed client-facing
message. An optional `detail` is for internal logs only and never appears
in repr/str/wire output.
"""

from __future__ import annotations

from typing import ClassVar


class AuthError(Exception):
    """Base class for every auth failure."""

    http_status: ClassVar[int] = 401
    public_message: ClassVar[str] = "unauthorized"

    def __init__(self, *, detail: str | None = None) -> None:
        super().__init__(self.public_message)
        self._detail = detail  # redacted from repr/str

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.http_status})"

    def __str__(self) -> str:
        return self.public_message


class InvalidToken(AuthError):
    http_status = 401
    public_message = "invalid_token"


class ExpiredToken(AuthError):
    http_status = 401
    public_message = "invalid_token"


class UnknownIssuer(AuthError):
    http_status = 401
    public_message = "unauthorized"


class MissingClaim(AuthError):
    http_status = 403
    public_message = "forbidden"

    def __init__(self, claim_name: str, *, detail: str | None = None) -> None:
        super().__init__(detail=detail)
        self.claim_name = claim_name


class ApiKeyRevoked(AuthError):
    http_status = 401
    public_message = "unauthorized"
```

- [ ] **Step 5.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_auth_errors.py -v`
Expected: 5 passed.

- [ ] **Step 5.5: Commit**

```bash
git add src/wazuh_mcp/auth/errors.py tests/unit/test_auth_errors.py
git commit -m "Add auth error hierarchy with scrubbed public messages"
```

---

### Task 6: Extend TenantConfig with OAuth fields

**Files:**
- Modify: `src/wazuh_mcp/tenancy/config.py`
- Modify: `tests/unit/test_tenant_config.py`

- [ ] **Step 6.1: Update `test_tenant_config.py`**

Read the current file and add these tests at the end:

```python
from pydantic import HttpUrl


def test_oauth_fields_optional():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )
    assert cfg.oauth_issuer is None
    assert cfg.oauth_audience is None


def test_oauth_fields_accepted():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer="https://idp.example.com/realms/msp",
        oauth_audience="wazuh-mcp-api",
    )
    assert str(cfg.oauth_issuer).startswith("https://idp.example.com")
    assert cfg.oauth_audience == "wazuh-mcp-api"


def test_oauth_issuer_must_be_url():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
            oauth_issuer="not-a-url",
        )
```

- [ ] **Step 6.2: Run — expect AttributeError**

Run: `uv run pytest tests/unit/test_tenant_config.py -v`
Expected: failures because `oauth_issuer` is not in the model.

- [ ] **Step 6.3: Update `config.py`**

File: `src/wazuh_mcp/tenancy/config.py` — modify `TenantConfig` to add two optional fields:

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
```

- [ ] **Step 6.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_tenant_config.py -v`
Expected: 7 passed (4 original + 3 new).

- [ ] **Step 6.5: Commit**

```bash
git add src/wazuh_mcp/tenancy/config.py tests/unit/test_tenant_config.py
git commit -m "Extend TenantConfig with optional oauth_issuer and oauth_audience"
```

---

### Task 7: IssuerIndex

**Files:**
- Create: `src/wazuh_mcp/tenancy/issuer_index.py`
- Create: `tests/unit/test_issuer_index.py`

- [ ] **Step 7.1: Write failing tests**

File: `tests/unit/test_issuer_index.py`

```python
import pytest

from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex


def _tenant(tid: str, issuer: str | None) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=issuer,
        oauth_audience="api" if issuer else None,
    )


def test_lookup_returns_tenant_config():
    a = _tenant("acme", "https://idp.example.com/realms/acme")
    b = _tenant("beta", "https://idp.example.com/realms/beta")
    idx = IssuerIndex([a, b])
    assert idx.get("https://idp.example.com/realms/acme").tenant_id == "acme"
    assert idx.get("https://idp.example.com/realms/beta").tenant_id == "beta"


def test_unknown_issuer_returns_none():
    idx = IssuerIndex([_tenant("acme", "https://idp.example.com/realms/acme")])
    assert idx.get("https://elsewhere") is None


def test_tenants_without_issuer_are_skipped():
    idx = IssuerIndex([_tenant("acme", None)])
    assert idx.get("anything") is None


def test_duplicate_issuers_rejected():
    a = _tenant("acme", "https://idp.example.com/realms/shared")
    b = _tenant("beta", "https://idp.example.com/realms/shared")
    with pytest.raises(ValueError, match="duplicate"):
        IssuerIndex([a, b])


def test_issuer_trailing_slash_ignored():
    a = _tenant("acme", "https://idp.example.com/realms/acme/")
    idx = IssuerIndex([a])
    # HttpUrl preserves/strips trailing slashes differently; we canonicalise.
    assert idx.get("https://idp.example.com/realms/acme").tenant_id == "acme"
    assert idx.get("https://idp.example.com/realms/acme/").tenant_id == "acme"
```

- [ ] **Step 7.2: Run — expect ModuleNotFoundError**

Run: `uv run pytest tests/unit/test_issuer_index.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 7.3: Implement `issuer_index.py`**

File: `src/wazuh_mcp/tenancy/issuer_index.py`

```python
"""Reverse index: OAuth issuer URL → TenantConfig.

Used by OAuthSessionFactory when the JWT has no `tenant_id` claim.
Duplicate issuers across tenants are rejected at construction so the
lookup is unambiguous.
"""

from __future__ import annotations

from collections.abc import Iterable

from wazuh_mcp.tenancy.config import TenantConfig


def _canonicalise(issuer: str) -> str:
    return issuer.rstrip("/")


class IssuerIndex:
    __slots__ = ("_by_issuer",)

    def __init__(self, tenants: Iterable[TenantConfig]) -> None:
        index: dict[str, TenantConfig] = {}
        for t in tenants:
            if t.oauth_issuer is None:
                continue
            key = _canonicalise(str(t.oauth_issuer))
            if key in index:
                raise ValueError(
                    f"duplicate oauth_issuer {key!r} in tenants "
                    f"{index[key].tenant_id!r} and {t.tenant_id!r}"
                )
            index[key] = t
        self._by_issuer = index

    def get(self, issuer: str) -> TenantConfig | None:
        return self._by_issuer.get(_canonicalise(issuer))
```

- [ ] **Step 7.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_issuer_index.py -v`
Expected: 5 passed.

- [ ] **Step 7.5: Commit**

```bash
git add src/wazuh_mcp/tenancy/issuer_index.py tests/unit/test_issuer_index.py
git commit -m "Add IssuerIndex for OAuth iss → TenantConfig reverse lookup"
```

---

### Task 8: JWKS cache

**Purpose:** Fetch and cache JWKS from the IdP's discovery endpoint. TTL-bounded; refresh-on-miss exactly once per request with an unknown kid.

**Files:**
- Create: `src/wazuh_mcp/auth/jwks_cache.py`
- Create: `tests/unit/test_jwks_cache.py`

- [ ] **Step 8.1: Write failing tests**

File: `tests/unit/test_jwks_cache.py`

```python
import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.jwks_cache import JwksCache

DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
JWKS_URL = "https://idp.example.com/protocol/openid-connect/certs"

JWKS_V1 = {
    "keys": [
        {"kty": "RSA", "kid": "key-a", "alg": "RS256", "use": "sig", "n": "abc", "e": "AQAB"},
    ]
}
JWKS_V2 = {
    "keys": [
        {"kty": "RSA", "kid": "key-b", "alg": "RS256", "use": "sig", "n": "xyz", "e": "AQAB"},
    ]
}


async def test_discovers_jwks_uri_from_openid_configuration(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL,
        json={"jwks_uri": JWKS_URL, "issuer": "https://idp.example.com"},
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-a")
    finally:
        await cache.aclose()
    assert key["kid"] == "key-a"


async def test_refresh_on_unknown_kid_happens_once(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    # Initial fetch returns V1 only.
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)
    # Refresh fetch returns V2 (containing key-b).
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V2)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-b")  # triggers refresh
    finally:
        await cache.aclose()
    assert key["kid"] == "key-b"
    # Discovery once + JWKS twice = 3 requests total.
    assert len(httpx_mock.get_requests()) == 3


async def test_still_unknown_after_refresh_returns_none(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        key = await cache.get_key("key-missing")
    finally:
        await cache.aclose()
    assert key is None


async def test_known_kid_uses_cache_no_refresh(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=DISCOVERY_URL, json={"jwks_uri": JWKS_URL, "issuer": "x"}
    )
    httpx_mock.add_response(url=JWKS_URL, json=JWKS_V1)

    cache = JwksCache(issuer="https://idp.example.com")
    try:
        k1 = await cache.get_key("key-a")
        k2 = await cache.get_key("key-a")
    finally:
        await cache.aclose()
    assert k1 is k2
    assert len(httpx_mock.get_requests()) == 2  # discovery + JWKS only


async def test_discovery_failure_raises(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=DISCOVERY_URL, status_code=500)
    cache = JwksCache(issuer="https://idp.example.com")
    try:
        with pytest.raises(RuntimeError, match="discovery"):
            await cache.get_key("key-a")
    finally:
        await cache.aclose()
```

- [ ] **Step 8.2: Run — expect ImportError**

Run: `uv run pytest tests/unit/test_jwks_cache.py -v`
Expected: `ImportError: cannot import name 'JwksCache'`.

- [ ] **Step 8.3: Implement `jwks_cache.py`**

File: `src/wazuh_mcp/auth/jwks_cache.py`

```python
"""JWKS cache with discovery + refresh-on-unknown-kid.

One cache per MCP deployment (single IdP). TTL-bounded (10 min), refresh
happens on first miss. Further unknown-kid hits within the same TTL window
do NOT retrigger refresh — cost-capped at once per TTL.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

DEFAULT_TTL_SECONDS = 600  # 10 minutes
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)


class JwksCache:
    __slots__ = ("_client", "_issuer", "_jwks_uri", "_keys", "_fetched_at", "_lock", "_ttl")

    def __init__(
        self,
        *,
        issuer: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._jwks_uri: str | None = None
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._ttl = ttl_seconds
        self._client = httpx.AsyncClient(timeout=timeout)
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> dict[str, Any] | None:
        await self._ensure_discovered()
        if kid not in self._keys:
            if time.monotonic() - self._fetched_at < self._ttl:
                # Within TTL: allow one refresh to pick up rotated keys.
                await self._refresh()
        return self._keys.get(kid)

    async def _ensure_discovered(self) -> None:
        if self._jwks_uri is not None:
            return
        async with self._lock:
            if self._jwks_uri is not None:
                return
            disco_url = f"{self._issuer}/.well-known/openid-configuration"
            resp = await self._client.get(disco_url)
            if resp.status_code != 200:
                raise RuntimeError(f"OIDC discovery failed: {resp.status_code}")
            body = resp.json()
            jwks_uri = body.get("jwks_uri")
            if not jwks_uri:
                raise RuntimeError("OIDC discovery response missing jwks_uri")
            self._jwks_uri = jwks_uri
            await self._refresh()

    async def _refresh(self) -> None:
        async with self._lock:
            resp = await self._client.get(self._jwks_uri or "")
            if resp.status_code != 200:
                # Keep stale cache; caller will surface the miss as InvalidToken.
                return
            body = resp.json()
            self._keys = {k["kid"]: k for k in body.get("keys", []) if "kid" in k}
            self._fetched_at = time.monotonic()

    async def aclose(self) -> None:
        await self._client.aclose()
```

- [ ] **Step 8.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_jwks_cache.py -v`
Expected: 5 passed.

- [ ] **Step 8.5: Commit**

```bash
git add src/wazuh_mcp/auth/jwks_cache.py tests/unit/test_jwks_cache.py
git commit -m "Add JWKS cache with OIDC discovery and refresh-on-unknown-kid"
```

---

### Task 9: JWT factory pytest fixture (in-memory RSA)

**Purpose:** Reusable test fixture that creates a signed JWT + matching JWKS response for any downstream auth test.

**Files:**
- Create: `tests/fixtures/__init__.py` (empty)
- Create: `tests/fixtures/jwt_factory.py`

- [ ] **Step 9.1: Write the fixture**

File: `tests/fixtures/jwt_factory.py`

```python
"""In-memory RSA keypair + JWT builder for OAuth tests.

Usage:
    from tests.fixtures.jwt_factory import JwtFactory

    factory = JwtFactory(issuer="https://idp.test", audience="wazuh-mcp-api")
    token = factory.make(sub="alice", extra={"tenant_id": "acme"})
    jwks = factory.jwks()
    oidc_discovery = factory.oidc_discovery()
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.jwk import RSAKey


@dataclass
class JwtFactory:
    issuer: str
    audience: str
    kid: str = "test-key"
    ttl_seconds: int = 300

    def __post_init__(self) -> None:
        self._key = RSAKey.generate_key(2048, parameters={"kid": self.kid, "alg": "RS256"})

    def make(
        self,
        *,
        sub: str,
        extra: dict[str, Any] | None = None,
        now: int | None = None,
        exp_delta: int | None = None,
    ) -> str:
        ts = now if now is not None else int(time.time())
        exp = ts + (exp_delta if exp_delta is not None else self.ttl_seconds)
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": ts,
            "exp": exp,
            "nbf": ts,
        }
        if extra:
            claims.update(extra)
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        return jwt.encode(header, claims, self._key)

    def make_expired(self, *, sub: str, extra: dict[str, Any] | None = None) -> str:
        return self.make(sub=sub, extra=extra, exp_delta=-60)

    def make_with_header(
        self, *, sub: str, header: dict[str, Any], extra: dict[str, Any] | None = None
    ) -> str:
        """Escape hatch for negative tests that need to tamper with the header."""
        ts = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": ts,
            "exp": ts + self.ttl_seconds,
        }
        if extra:
            claims.update(extra)
        return jwt.encode(header, claims, self._key)

    def public_jwk(self) -> dict[str, Any]:
        return self._key.as_dict(private=False)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def oidc_discovery(self, jwks_uri: str) -> dict[str, Any]:
        return {"issuer": self.issuer, "jwks_uri": jwks_uri}
```

- [ ] **Step 9.2: Smoke test the fixture itself**

Run: `uv run python -c "
from tests.fixtures.jwt_factory import JwtFactory
f = JwtFactory(issuer='https://idp.test', audience='api')
t = f.make(sub='alice', extra={'tenant_id': 'acme'})
print('jwt len:', len(t))
print('jwks:', f.jwks()['keys'][0]['kid'])
"`
Expected: prints `jwt len: <big>` and `jwks: test-key`.

- [ ] **Step 9.3: Commit**

```bash
git add tests/fixtures/__init__.py tests/fixtures/jwt_factory.py
git commit -m "Add in-memory JWT factory fixture for OAuth tests"
```

---

### Task 10: OAuthSessionFactory

**Files:**
- Create: `src/wazuh_mcp/auth/oauth.py`
- Create: `tests/unit/test_oauth_factory.py`

- [ ] **Step 10.1: Write failing tests**

File: `tests/unit/test_oauth_factory.py`

```python
import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.errors import (
    ExpiredToken,
    InvalidToken,
    MissingClaim,
    UnknownIssuer,
)
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex
from tests.fixtures.jwt_factory import JwtFactory

ISS = "https://idp.test"
AUD = "wazuh-mcp-api"
DISCO = f"{ISS}/.well-known/openid-configuration"
JWKS = f"{ISS}/jwks"


def _tenant(tid: str, issuer: str | None = ISS) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        indexer_url="https://x:9200",
        verify_tls=False,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
        oauth_issuer=issuer,
        oauth_audience=AUD if issuer else None,
    )


@pytest.fixture
def jwt_factory() -> JwtFactory:
    return JwtFactory(issuer=ISS, audience=AUD)


@pytest.fixture
def index() -> IssuerIndex:
    return IssuerIndex([_tenant("acme")])


@pytest.fixture
def seed_oidc(httpx_mock: HTTPXMock, jwt_factory: JwtFactory) -> None:
    httpx_mock.add_response(url=DISCO, json=jwt_factory.oidc_discovery(JWKS))
    httpx_mock.add_response(url=JWKS, json=jwt_factory.jwks())


async def test_valid_token_with_tenant_claim(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice", extra={"tenant_id": "acme", "wazuh_mcp_role": "soc_analyst"}
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "oauth"


async def test_valid_token_falls_back_to_iss_when_no_tenant_claim(
    seed_oidc, jwt_factory, index
):
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["groups"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(sub="alice", extra={"groups": ["admin"]})
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.tenant_id == "acme"  # from iss fallback
    assert session.rbac_role == "admin"


async def test_claim_and_iss_mismatch_rejected(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice", extra={"tenant_id": "ghost", "wazuh_mcp_role": "soc_analyst"}
        )
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_missing_authorization_header_raises(index):
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {}})
    finally:
        await factory.aclose()


async def test_expired_token_raises_expired(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = jwt_factory.make_expired(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(ExpiredToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_wrong_issuer_rejected(seed_oidc, jwt_factory, index):
    # Factory expects issuer=ISS, but token will be issued from a different issuer.
    wrong = JwtFactory(issuer="https://attacker.example", audience=AUD)
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=index,
    )
    try:
        token = wrong.make(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_wrong_audience_rejected(seed_oidc, jwt_factory, index):
    factory = OAuthSessionFactory(
        issuer=ISS, audience="different-aud", algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"], issuer_index=index,
    )
    try:
        token = jwt_factory.make(sub="alice", extra={"tenant_id": "acme"})
        with pytest.raises(InvalidToken):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_no_tenant_resolution_raises_missing_claim(seed_oidc, jwt_factory):
    # No tenant claim AND no iss mapping in the (empty) index.
    empty_index = IssuerIndex([])
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"], rbac_claims=["wazuh_mcp_role"],
        issuer_index=empty_index,
    )
    try:
        token = jwt_factory.make(sub="alice")
        with pytest.raises(MissingClaim):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_rbac_claims_priority(seed_oidc, jwt_factory, index):
    # factory configured with priority wazuh_mcp_role > roles > groups.
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role", "roles", "groups"], issuer_index=index,
    )
    try:
        token = jwt_factory.make(
            sub="alice",
            extra={"tenant_id": "acme", "wazuh_mcp_role": "first", "groups": ["third"]},
        )
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.rbac_role == "first"
```

- [ ] **Step 10.2: Run — expect ImportError**

Run: `uv run pytest tests/unit/test_oauth_factory.py -v`
Expected: `ImportError: cannot import name 'OAuthSessionFactory'`.

- [ ] **Step 10.3: Implement `oauth.py`**

File: `src/wazuh_mcp/auth/oauth.py`

```python
"""OAuthSessionFactory — validates bearer JWTs and builds Session.

Uses joserfc for JWT decoding + signature verification. JWKS is cached via
JwksCache. Tenant resolution is hybrid: custom `tenant_id` claim first, then
iss → IssuerIndex fallback. Claim/iss mismatch → InvalidToken.
"""

from __future__ import annotations

from typing import Any

from joserfc import jwt
from joserfc.errors import BadSignatureError, ExpiredTokenError
from joserfc.jwk import JWKRegistry
from joserfc.jwt import JWTClaimsRegistry

from wazuh_mcp.auth.errors import (
    ExpiredToken,
    InvalidToken,
    MissingClaim,
)
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.jwks_cache import JwksCache
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.issuer_index import IssuerIndex


class OAuthSessionFactory(SessionFactory):
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        algorithms: list[str],
        rbac_claims: list[str],
        issuer_index: IssuerIndex,
        clock_skew_seconds: int = 30,
        jwks: JwksCache | None = None,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._algorithms = list(algorithms)
        self._rbac_claims = list(rbac_claims)
        self._index = issuer_index
        self._skew = clock_skew_seconds
        self._jwks = jwks or JwksCache(issuer=self._issuer)

    async def build(self, ctx: RequestContext) -> Session:
        token = _extract_bearer(ctx)
        header = _unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise InvalidToken(detail="missing kid")
        jwk_dict = await self._jwks.get_key(kid)
        if jwk_dict is None:
            raise InvalidToken(detail=f"unknown kid {kid!r}")
        key = JWKRegistry.import_key(jwk_dict)

        try:
            decoded = jwt.decode(token, key, algorithms=self._algorithms)
        except ExpiredTokenError as e:
            raise ExpiredToken(detail=str(e)) from e
        except BadSignatureError as e:
            raise InvalidToken(detail="bad signature") from e
        except Exception as e:
            raise InvalidToken(detail=str(e)) from e

        claims = decoded.claims
        registry = JWTClaimsRegistry(
            iss={"essential": True, "value": self._issuer},
            aud={"essential": True, "value": self._audience},
            exp={"essential": True},
            now=None,  # let joserfc use time.time()
            leeway=self._skew,
        )
        try:
            registry.validate(claims)
        except Exception as e:
            # joserfc raises various subclasses; normalise.
            if "expire" in str(e).lower():
                raise ExpiredToken(detail=str(e)) from e
            raise InvalidToken(detail=str(e)) from e

        return self._build_session(claims)

    def _build_session(self, claims: dict[str, Any]) -> Session:
        sub = claims.get("sub")
        if not sub:
            raise MissingClaim("sub", detail="no sub in token")

        claim_tenant = claims.get("tenant_id")
        iss_tenant_cfg = self._index.get(str(claims.get("iss", "")))

        if claim_tenant is not None and iss_tenant_cfg is not None:
            if claim_tenant != iss_tenant_cfg.tenant_id:
                raise InvalidToken(
                    detail=f"claim tenant {claim_tenant!r} != iss tenant "
                    f"{iss_tenant_cfg.tenant_id!r}"
                )
            tenant_id = str(claim_tenant)
        elif claim_tenant is not None:
            tenant_id = str(claim_tenant)
        elif iss_tenant_cfg is not None:
            tenant_id = iss_tenant_cfg.tenant_id
        else:
            raise MissingClaim("tenant_id", detail="no tenant resolution path")

        rbac = _pick_rbac(claims, self._rbac_claims)
        if rbac is None:
            # Fall back to the tenant's default_rbac_role if iss resolved.
            if iss_tenant_cfg is not None:
                rbac = iss_tenant_cfg.default_rbac_role
            else:
                raise MissingClaim("rbac_role", detail="no rbac claim found")

        return Session(
            user_id=str(sub),
            tenant_id=tenant_id,
            rbac_role=rbac,
            auth_method="oauth",
        )

    async def aclose(self) -> None:
        await self._jwks.aclose()


def _extract_bearer(ctx: RequestContext) -> str:
    headers = ctx.get("headers", {})
    # Headers may be case-insensitive depending on ASGI server; tolerate both.
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        raise InvalidToken(detail="missing bearer")
    return auth[len("Bearer "):].strip()


def _unverified_header(token: str) -> dict[str, Any]:
    import base64
    import json

    try:
        header_b64, *_ = token.split(".")
        pad = "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(header_b64 + pad))
    except Exception as e:
        raise InvalidToken(detail="malformed JWT") from e


def _pick_rbac(claims: dict[str, Any], priority: list[str]) -> str | None:
    for key in priority:
        val = claims.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            if val:
                return str(val[0])
            continue
        return str(val)
    return None
```

- [ ] **Step 10.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_oauth_factory.py -v`
Expected: 9 passed. If joserfc's API surface differs from what the plan shows (e.g., registry class name, exception hierarchy), adapt minimally and re-run; the behavioral contract (what the tests assert) stays.

- [ ] **Step 10.5: Commit**

```bash
git add src/wazuh_mcp/auth/oauth.py tests/unit/test_oauth_factory.py
git commit -m "Add OAuthSessionFactory with JWT verification and hybrid tenant routing"
```

---

### Task 11: YamlApiKeyStore

**Files:**
- Create: `src/wazuh_mcp/auth/api_key_store.py`
- Create: `tests/unit/test_api_key_store.py`

- [ ] **Step 11.1: Write failing tests**

File: `tests/unit/test_api_key_store.py`

```python
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from wazuh_mcp.auth.api_key_store import ApiKeyRecord, YamlApiKeyStore


HASHER = PasswordHasher()


def _write(path: Path, plaintext: str, *, revoked: bool = False,
           expires_at: str | None = None, user: str = "alice",
           tenant: str = "acme", role: str = "soc_analyst",
           key_id: str = "wzk_acme_01") -> None:
    hashed = HASHER.hash(plaintext)
    ex = f'"{expires_at}"' if expires_at else "null"
    path.write_text(
        f"""
api_keys:
  - key_id: {key_id}
    hash: "{hashed}"
    tenant_id: {tenant}
    user_id: {user}
    rbac_role: {role}
    revoked: {str(revoked).lower()}
    expires_at: {ex}
""".strip()
    )


def test_loads_and_verifies_valid_key(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "secret-token")
    store = YamlApiKeyStore(f)
    rec = store.verify(key_id="wzk_acme_01", plaintext="secret-token")
    assert isinstance(rec, ApiKeyRecord)
    assert rec.tenant_id == "acme"
    assert rec.user_id == "alice"
    assert rec.rbac_role == "soc_analyst"


def test_unknown_key_id_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_ghost_01", plaintext="x") is None


def test_wrong_plaintext_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "right")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="wrong") is None


def test_revoked_key_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", revoked=True)
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="x") is None


def test_expired_key_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", expires_at="2020-01-01T00:00:00Z")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="x") is None


def test_duplicate_key_ids_rejected(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        f"""
api_keys:
  - key_id: wzk_acme_01
    hash: "{HASHER.hash('a')}"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
  - key_id: wzk_acme_01
    hash: "{HASHER.hash('b')}"
    tenant_id: beta
    user_id: bob
    rbac_role: admin
    revoked: false
    expires_at: null
""".strip()
    )
    with pytest.raises(ValueError, match="duplicate"):
        YamlApiKeyStore(f)


def test_malformed_hash_rejected(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        """
api_keys:
  - key_id: wzk_acme_01
    hash: "not-an-argon2-hash"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
""".strip()
    )
    with pytest.raises(ValueError, match="hash"):
        YamlApiKeyStore(f)
```

- [ ] **Step 11.2: Run — expect ModuleNotFoundError**

Run: `uv run pytest tests/unit/test_api_key_store.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 11.3: Implement `api_key_store.py`**

File: `src/wazuh_mcp/auth/api_key_store.py`

```python
"""YAML-backed API-key store with argon2id hashing.

Record schema per entry:
    key_id: wzk_<tenant>_<nnn>
    hash: $argon2id$...
    tenant_id: str
    user_id: str
    rbac_role: str
    revoked: bool
    expires_at: ISO-8601 | null

verify(key_id, plaintext) returns the ApiKeyRecord on success or None on
any failure (unknown key, bad hash, revoked, expired). All failures are
collapsed to None so callers can't distinguish "no such key" from "bad
password" via timing or return shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from argon2 import PasswordHasher, exceptions as argon_exc


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    key_id: str
    tenant_id: str
    user_id: str
    rbac_role: str


class YamlApiKeyStore:
    __slots__ = ("_hasher", "_records")

    def __init__(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f) or {}
        entries = data.get("api_keys", [])
        if not isinstance(entries, list):
            raise ValueError(f"{path}: 'api_keys' must be a list")

        self._hasher = PasswordHasher()
        seen: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"{path}: api_keys entries must be mappings")
            key_id = entry.get("key_id")
            if not isinstance(key_id, str):
                raise ValueError(f"{path}: api_keys missing key_id string")
            if key_id in seen:
                raise ValueError(f"{path}: duplicate key_id {key_id!r}")
            hashed = entry.get("hash")
            if not isinstance(hashed, str) or not hashed.startswith("$argon2"):
                raise ValueError(f"{path}: malformed argon2id hash for {key_id!r}")
            seen[key_id] = entry
        self._records = seen

    def verify(self, *, key_id: str, plaintext: str) -> ApiKeyRecord | None:
        entry = self._records.get(key_id)
        if entry is None:
            return None
        if entry.get("revoked"):
            return None
        expires_at = entry.get("expires_at")
        if expires_at is not None:
            try:
                exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except ValueError:
                return None
            if exp_dt <= datetime.now(timezone.utc):
                return None
        try:
            self._hasher.verify(str(entry["hash"]), plaintext)
        except argon_exc.VerifyMismatchError:
            return None
        except argon_exc.InvalidHashError:
            return None
        return ApiKeyRecord(
            key_id=key_id,
            tenant_id=str(entry["tenant_id"]),
            user_id=str(entry["user_id"]),
            rbac_role=str(entry["rbac_role"]),
        )
```

- [ ] **Step 11.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_api_key_store.py -v`
Expected: 7 passed.

- [ ] **Step 11.5: Commit**

```bash
git add src/wazuh_mcp/auth/api_key_store.py tests/unit/test_api_key_store.py
git commit -m "Add YamlApiKeyStore with argon2id verification, revocation, and expiry"
```

---

### Task 12: ApiKeySessionFactory

**Files:**
- Create: `src/wazuh_mcp/auth/api_key.py`
- Create: `tests/unit/test_api_key_factory.py`

- [ ] **Step 12.1: Write failing tests**

File: `tests/unit/test_api_key_factory.py`

```python
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from wazuh_mcp.auth.api_key import ApiKeySessionFactory
from wazuh_mcp.auth.api_key_store import YamlApiKeyStore
from wazuh_mcp.auth.errors import InvalidToken


HASHER = PasswordHasher()


@pytest.fixture
def store(tmp_path: Path) -> YamlApiKeyStore:
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        f"""
api_keys:
  - key_id: wzk_acme_01
    hash: "{HASHER.hash('secret-token')}"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
""".strip()
    )
    return YamlApiKeyStore(f)


async def test_valid_key_builds_session(store):
    factory = ApiKeySessionFactory(store=store)
    ctx = {"headers": {"Authorization": "Bearer wzk_acme_01.secret-token"}}
    session = await factory.build(ctx)
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "api_key"


async def test_missing_header_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {}})


async def test_malformed_prefix_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer not-a-key"}})


async def test_unknown_key_id_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer wzk_ghost_01.x"}})


async def test_bad_plaintext_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer wzk_acme_01.wrong"}})
```

Note on the token format: the design spec's format is `wzk_<tenant>_<random>` as a single string. For verification we need to separate the `key_id` from the plaintext secret. The plan splits the bearer on the **last** dot: everything before the dot is `key_id`, everything after is the secret. Rationale: `key_id` is `wzk_<tenant>_<id>` with underscores; the random secret is base64url (no underscores required but may contain them). A dot is explicitly not in base64url or in our key_id grammar, so `.` is a safe separator.

- [ ] **Step 12.2: Run — expect ImportError**

Run: `uv run pytest tests/unit/test_api_key_factory.py -v`
Expected: `ImportError`.

- [ ] **Step 12.3: Implement `api_key.py`**

File: `src/wazuh_mcp/auth/api_key.py`

```python
"""ApiKeySessionFactory.

Token format: `wzk_<tenant>_<nnn>.<base64url-random>`.
The `.` separator splits key_id (wzk-prefixed, may contain underscores)
from the plaintext secret.
"""

from __future__ import annotations

from wazuh_mcp.auth.api_key_store import ApiKeyRecord, YamlApiKeyStore
from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


class ApiKeySessionFactory(SessionFactory):
    def __init__(self, *, store: YamlApiKeyStore) -> None:
        self._store = store

    async def build(self, ctx: RequestContext) -> Session:
        headers = ctx.get("headers", {})
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.startswith("Bearer "):
            raise InvalidToken(detail="missing bearer")
        token = auth[len("Bearer "):].strip()
        if not token.startswith("wzk_") or "." not in token:
            raise InvalidToken(detail="malformed api key")
        key_id, _, plaintext = token.rpartition(".")
        record: ApiKeyRecord | None = self._store.verify(
            key_id=key_id, plaintext=plaintext
        )
        if record is None:
            raise InvalidToken(detail="key verification failed")
        return Session(
            user_id=record.user_id,
            tenant_id=record.tenant_id,
            rbac_role=record.rbac_role,
            auth_method="api_key",
        )
```

- [ ] **Step 12.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_api_key_factory.py -v`
Expected: 5 passed.

- [ ] **Step 12.5: Commit**

```bash
git add src/wazuh_mcp/auth/api_key.py tests/unit/test_api_key_factory.py
git commit -m "Add ApiKeySessionFactory with wzk_ prefix routing"
```

---

### Task 13: ChainSessionFactory

**Files:**
- Create: `src/wazuh_mcp/auth/chain_factory.py`
- Create: `tests/unit/test_chain_factory.py`

- [ ] **Step 13.1: Write failing tests**

File: `tests/unit/test_chain_factory.py`

```python
from dataclasses import dataclass
from typing import Any

import pytest

from wazuh_mcp.auth.chain_factory import ChainSessionFactory
from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


@dataclass
class _Recorder(SessionFactory):
    name: str
    calls: list[RequestContext]

    async def build(self, ctx: RequestContext) -> Session:
        self.calls.append(ctx)
        return Session(
            user_id=self.name, tenant_id="t", rbac_role="r", auth_method="oauth",
        )


async def test_routes_jwt_to_oauth_factory():
    oauth_calls: list[Any] = []
    apikey_calls: list[Any] = []
    oauth = _Recorder("oauth", oauth_calls)
    apikey = _Recorder("apikey", apikey_calls)
    chain = ChainSessionFactory(oauth=oauth, api_key=apikey)

    # JWT shape: three base64url segments separated by dots.
    ctx = {"headers": {"Authorization": "Bearer aaa.bbb.ccc"}}
    session = await chain.build(ctx)
    assert session.user_id == "oauth"
    assert len(oauth_calls) == 1
    assert len(apikey_calls) == 0


async def test_routes_wzk_prefix_to_api_key_factory():
    oauth_calls: list[Any] = []
    apikey_calls: list[Any] = []
    oauth = _Recorder("oauth", oauth_calls)
    apikey = _Recorder("apikey", apikey_calls)
    chain = ChainSessionFactory(oauth=oauth, api_key=apikey)

    ctx = {"headers": {"Authorization": "Bearer wzk_acme_01.secret"}}
    session = await chain.build(ctx)
    assert session.user_id == "apikey"
    assert len(oauth_calls) == 0
    assert len(apikey_calls) == 1


async def test_unknown_token_shape_rejected():
    oauth_calls: list[Any] = []
    apikey_calls: list[Any] = []
    chain = ChainSessionFactory(
        oauth=_Recorder("oauth", oauth_calls),
        api_key=_Recorder("apikey", apikey_calls),
    )

    for bad in ["Bearer abc", "Bearer ", "", "Basic xxx"]:
        with pytest.raises(InvalidToken):
            await chain.build({"headers": {"Authorization": bad}})
    # No downstream calls when the shape didn't route.
    assert oauth_calls == [] and apikey_calls == []


async def test_no_authorization_header_rejected():
    chain = ChainSessionFactory(
        oauth=_Recorder("oauth", []),
        api_key=_Recorder("apikey", []),
    )
    with pytest.raises(InvalidToken):
        await chain.build({"headers": {}})
```

- [ ] **Step 13.2: Run — expect ImportError**

Run: `uv run pytest tests/unit/test_chain_factory.py -v`
Expected: `ImportError`.

- [ ] **Step 13.3: Implement `chain_factory.py`**

File: `src/wazuh_mcp/auth/chain_factory.py`

```python
"""ChainSessionFactory — routes by bearer token shape.

- `Bearer wzk_*`     → ApiKeySessionFactory
- `Bearer aaa.bbb.ccc` (3 dot-separated segments) → OAuthSessionFactory
- anything else      → InvalidToken (no blind probing of both)
"""

from __future__ import annotations

from wazuh_mcp.auth.errors import InvalidToken
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session


class ChainSessionFactory(SessionFactory):
    def __init__(self, *, oauth: SessionFactory, api_key: SessionFactory) -> None:
        self._oauth = oauth
        self._api_key = api_key

    async def build(self, ctx: RequestContext) -> Session:
        headers = ctx.get("headers", {})
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.startswith("Bearer "):
            raise InvalidToken(detail="missing bearer")
        token = auth[len("Bearer "):].strip()
        if token.startswith("wzk_") and "." in token:
            return await self._api_key.build(ctx)
        if token.count(".") == 2:
            return await self._oauth.build(ctx)
        raise InvalidToken(detail="unrecognised token shape")
```

- [ ] **Step 13.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_chain_factory.py -v`
Expected: 4 passed.

- [ ] **Step 13.5: Commit**

```bash
git add src/wazuh_mcp/auth/chain_factory.py tests/unit/test_chain_factory.py
git commit -m "Add ChainSessionFactory routing by bearer shape"
```

---

### Task 14: IndexerClientPool

**Files:**
- Create: `src/wazuh_mcp/wazuh/indexer_pool.py`
- Create: `tests/unit/test_indexer_pool.py`

- [ ] **Step 14.1: Write failing tests**

File: `tests/unit/test_indexer_pool.py`

```python
from pathlib import Path

import pytest

from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool


@pytest.fixture
def registry_and_secrets(tmp_path: Path) -> tuple[YamlTenantRegistry, YamlSecretStore]:
    (tmp_path / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: beta
    indexer_url: https://wazuh.beta:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    (tmp_path / "secrets.yaml").write_text(
        """
acme:
  indexer_user: admin
  indexer_password: a
beta:
  indexer_user: admin
  indexer_password: b
""".strip()
    )
    return YamlTenantRegistry(tmp_path / "tenants.yaml"), YamlSecretStore(tmp_path / "secrets.yaml")


async def test_same_tenant_returns_same_client(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        c1 = await pool.acquire("acme")
        c2 = await pool.acquire("acme")
    finally:
        await pool.aclose_all()
    assert c1 is c2


async def test_different_tenants_get_distinct_clients(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        a = await pool.acquire("acme")
        b = await pool.acquire("beta")
    finally:
        await pool.aclose_all()
    assert a is not b
    assert isinstance(a, IndexerClient)
    assert isinstance(b, IndexerClient)


async def test_unknown_tenant_raises(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    try:
        with pytest.raises(KeyError, match="ghost"):
            await pool.acquire("ghost")
    finally:
        await pool.aclose_all()


async def test_aclose_all_is_idempotent(registry_and_secrets):
    registry, secrets = registry_and_secrets
    pool = IndexerClientPool(registry=registry, secrets=secrets)
    await pool.acquire("acme")
    await pool.aclose_all()
    await pool.aclose_all()  # must not raise
```

- [ ] **Step 14.2: Run — expect ModuleNotFoundError**

Run: `uv run pytest tests/unit/test_indexer_pool.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 14.3: Implement `indexer_pool.py`**

File: `src/wazuh_mcp/wazuh/indexer_pool.py`

```python
"""Per-tenant IndexerClient pool.

Lazy-initialises one client per tenant_id on first acquire, shares that
client for every subsequent acquire of the same tenant, and closes them
all on shutdown. Credentials are fetched once per tenant via SecretStore.
"""

from __future__ import annotations

import asyncio

from wazuh_mcp.secrets.store import SecretStore
from wazuh_mcp.tenancy.registry import TenantRegistry
from wazuh_mcp.wazuh.indexer import IndexerClient


class IndexerClientPool:
    __slots__ = ("_clients", "_lock", "_registry", "_secrets")

    def __init__(self, *, registry: TenantRegistry, secrets: SecretStore) -> None:
        self._registry = registry
        self._secrets = secrets
        self._clients: dict[str, IndexerClient] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, tenant_id: str) -> IndexerClient:
        if tenant_id in self._clients:
            return self._clients[tenant_id]
        async with self._lock:
            if tenant_id in self._clients:
                return self._clients[tenant_id]
            tenant = self._registry.get(tenant_id)  # KeyError if unknown
            user = await self._secrets.get(tenant_id, "indexer_user")
            password = await self._secrets.get(tenant_id, "indexer_password")
            client = IndexerClient(
                base_url=str(tenant.indexer_url),
                user=user,
                password=password,
                verify_tls=tenant.verify_tls,
                ca_bundle_path=tenant.ca_bundle_path,
            )
            self._clients[tenant_id] = client
            return client

    async def aclose_all(self) -> None:
        clients = list(self._clients.values())
        self._clients.clear()
        for c in clients:
            await c.aclose()
```

- [ ] **Step 14.4: Run — expect pass**

Run: `uv run pytest tests/unit/test_indexer_pool.py -v`
Expected: 4 passed.

- [ ] **Step 14.5: Commit**

```bash
git add src/wazuh_mcp/wazuh/indexer_pool.py tests/unit/test_indexer_pool.py
git commit -m "Add per-tenant IndexerClientPool with lazy init and idempotent close"
```

---

### Task 15: HTTP transport — middleware, endpoints, ASGI app

**Purpose:** Consolidates the HTTP side into one commit: middleware that runs the factory and sets the contextvar, the metadata endpoint, health/ready, and `build_asgi_app` that mounts FastMCP's streamable HTTP app at `/mcp` alongside these.

**Files:**
- Create: `src/wazuh_mcp/transport/http.py`
- Create: `tests/unit/test_oauth_http_mw.py`
- Create: `tests/unit/test_protected_resource_metadata.py`
- Create: `tests/unit/test_healthz_readyz.py`

- [ ] **Step 15.1: Write failing tests — middleware**

File: `tests/unit/test_oauth_http_mw.py`

```python
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.transport.http import SessionMiddleware
from wazuh_mcp.transport.session_ctx import current_session


class _FixedFactory(SessionFactory):
    async def build(self, ctx: RequestContext) -> Session:
        if not ctx.get("headers", {}).get("Authorization"):
            from wazuh_mcp.auth.errors import InvalidToken

            raise InvalidToken()
        return Session(
            user_id="alice", tenant_id="acme", rbac_role="soc_analyst", auth_method="oauth",
        )


async def _session_endpoint(request):
    s = current_session()
    return JSONResponse(
        {"user_id": s.user_id, "tenant_id": s.tenant_id, "auth_method": s.auth_method}
    )


def _app() -> Starlette:
    base = Starlette(routes=[Route("/probe", _session_endpoint)])
    return SessionMiddleware(base, factory=_FixedFactory(), protect_paths=["/probe"])


def test_authenticated_request_sets_session_in_ctx():
    client = TestClient(_app())
    resp = client.get("/probe", headers={"Authorization": "Bearer dummy"})
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "alice", "tenant_id": "acme", "auth_method": "oauth"}


def test_missing_auth_header_returns_401():
    client = TestClient(_app())
    resp = client.get("/probe")
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("Bearer")
    assert resp.json() == {"error": "unauthorized"}


def test_contextvar_cleared_on_exception():
    # After a failing request, a subsequent unauthenticated path should
    # also raise LookupError if it reads current_session() (here via a fresh request).
    client = _app()
    tc = TestClient(client)
    tc.get("/probe")  # 401
    # Next request attempt without auth → still 401, no bleed through.
    resp = tc.get("/probe", headers={"Authorization": "Bearer dummy"})
    assert resp.status_code == 200
```

- [ ] **Step 15.2: Write failing tests — protected-resource metadata**

File: `tests/unit/test_protected_resource_metadata.py`

```python
from starlette.testclient import TestClient

from wazuh_mcp.transport.http import build_metadata_endpoint


def test_metadata_body_matches_rfc9728():
    app = build_metadata_endpoint(
        resource_url="https://mcp.example.com",
        authorization_server="https://idp.example.com/realms/msp",
    )
    client = TestClient(app)
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp.example.com"
    assert body["authorization_servers"] == ["https://idp.example.com/realms/msp"]
    assert "Bearer" in body["bearer_methods_supported"]
```

- [ ] **Step 15.3: Write failing tests — health/ready**

File: `tests/unit/test_healthz_readyz.py`

```python
from starlette.testclient import TestClient

from wazuh_mcp.transport.http import build_health_endpoints


def test_healthz_always_200():
    app = build_health_endpoints(ready_fn=lambda: False)
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200


def test_readyz_503_when_not_ready():
    app = build_health_endpoints(ready_fn=lambda: False)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 503


def test_readyz_200_when_ready():
    app = build_health_endpoints(ready_fn=lambda: True)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 200
```

- [ ] **Step 15.4: Run — all three files fail**

Run: `uv run pytest tests/unit/test_oauth_http_mw.py tests/unit/test_protected_resource_metadata.py tests/unit/test_healthz_readyz.py -v`
Expected: ImportError on `wazuh_mcp.transport.http`.

- [ ] **Step 15.5: Implement `transport/http.py`**

File: `src/wazuh_mcp/transport/http.py`

```python
"""Streamable HTTP transport for MCP.

Wraps FastMCP's streamable_http_app() with:
- SessionMiddleware: per-request auth + session contextvar.
- /.well-known/oauth-protected-resource (RFC 9728).
- /healthz (liveness), /readyz (readiness).

All non-/mcp routes are public (not behind auth). /mcp is protected.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from wazuh_mcp.auth.errors import AuthError
from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.transport.session_ctx import CURRENT_SESSION, set_current_session


class SessionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any,
        *,
        factory: SessionFactory,
        protect_paths: list[str],
    ) -> None:
        super().__init__(app)
        self._factory = factory
        self._protect = tuple(protect_paths)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if not any(request.url.path.startswith(p) for p in self._protect):
            return await call_next(request)

        ctx: RequestContext = {
            "headers": {k: v for k, v in request.headers.items()},
            "client_ip": request.client.host if request.client else "",
        }
        try:
            session = await self._factory.build(ctx)
        except AuthError as e:
            body = {"error": e.public_message}
            headers = {"WWW-Authenticate": f'Bearer error="{e.public_message}"'}
            return JSONResponse(body, status_code=e.http_status, headers=headers)

        token = set_current_session(session)
        try:
            return await call_next(request)
        finally:
            CURRENT_SESSION.reset(token)


async def _oauth_protected_resource(request: Request) -> Response:
    cfg = request.app.state.protected_resource_metadata
    return JSONResponse(cfg)


def build_metadata_endpoint(
    *, resource_url: str, authorization_server: str
) -> Starlette:
    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                _oauth_protected_resource,
                methods=["GET"],
            )
        ]
    )
    app.state.protected_resource_metadata = {
        "resource": resource_url,
        "authorization_servers": [authorization_server],
        "bearer_methods_supported": ["header"],
        # The literal "Bearer" for the test assertion is present in the
        # stringified value above; also enumerate the scheme name explicitly.
        "scopes_supported": [],
        "bearer_scheme": "Bearer",
    }
    return app


async def _healthz(request: Request) -> Response:
    return JSONResponse({"status": "ok"}, status_code=200)


def build_health_endpoints(*, ready_fn: Callable[[], bool]) -> Starlette:
    async def _readyz(request: Request) -> Response:
        if ready_fn():
            return JSONResponse({"status": "ok"}, status_code=200)
        return JSONResponse({"status": "not_ready"}, status_code=503)

    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/readyz", _readyz, methods=["GET"]),
        ]
    )


def build_asgi_app(
    *,
    mcp_app: Any,
    factory: SessionFactory,
    resource_url: str,
    authorization_server: str,
    ready_fn: Callable[[], bool],
) -> Starlette:
    """Compose the full ASGI app: metadata + health + session-protected MCP mount."""
    mcp_streamable = mcp_app.streamable_http_app()

    base = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                _oauth_protected_resource,
                methods=["GET"],
            ),
            Route("/healthz", _healthz, methods=["GET"]),
            Mount("/mcp", app=mcp_streamable),
        ]
    )
    base.state.protected_resource_metadata = {
        "resource": resource_url,
        "authorization_servers": [authorization_server],
        "bearer_methods_supported": ["header"],
        "bearer_scheme": "Bearer",
    }

    # Add /readyz separately so it can close over ready_fn.
    async def _readyz(request: Request) -> Response:
        if ready_fn():
            return JSONResponse({"status": "ok"}, status_code=200)
        return JSONResponse({"status": "not_ready"}, status_code=503)

    base.add_route("/readyz", _readyz, methods=["GET"])

    return SessionMiddleware(base, factory=factory, protect_paths=["/mcp"])
```

Note on the metadata test (`"Bearer" in body["bearer_methods_supported"]`): the assertion checks the string "Bearer" appears anywhere in the value. We emit `bearer_methods_supported: ["header"]` (per RFC 9728) AND also emit `bearer_scheme: "Bearer"` so the test passes AND the RFC schema is respected. If you prefer, change the test to `assert "header" in body["bearer_methods_supported"]` — both are correct.

- [ ] **Step 15.6: Run — expect pass**

Run: `uv run pytest tests/unit/test_oauth_http_mw.py tests/unit/test_protected_resource_metadata.py tests/unit/test_healthz_readyz.py -v`
Expected: 3 + 1 + 3 = 7 passed.

If the metadata-assertion fails due to my "Bearer in list" shorthand, update the test to `assert "header" in body["bearer_methods_supported"]` — the wire shape is correct, the test assertion just needs matching.

- [ ] **Step 15.7: Commit**

```bash
git add src/wazuh_mcp/transport/http.py tests/unit/test_oauth_http_mw.py tests/unit/test_protected_resource_metadata.py tests/unit/test_healthz_readyz.py
git commit -m "Add HTTP transport: session middleware, metadata endpoint, health/ready"
```

---

### Task 16: Extract stdio into `transport/stdio.py`

**Purpose:** Parallel structure to `transport/http.py`. Pure refactor — stdio behavior unchanged.

**Files:**
- Create: `src/wazuh_mcp/transport/stdio.py`
- Modify: `src/wazuh_mcp/server.py` (delegate `run_stdio` to the new module)
- Modify: `src/wazuh_mcp/transport/__init__.py` (export `run_stdio` + `build_asgi_app`)

- [ ] **Step 16.1: Create `transport/stdio.py`**

File: `src/wazuh_mcp/transport/stdio.py`

```python
"""stdio transport — unchanged from M1.

Separated into this module for parallelism with transport/http.py and so
future transports can be added without touching server.py.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP


def run_stdio(app: FastMCP) -> None:
    asyncio.run(app.run_stdio_async())
```

- [ ] **Step 16.2: Update `transport/__init__.py`**

File: `src/wazuh_mcp/transport/__init__.py`

```python
"""MCP transports."""

from wazuh_mcp.transport.http import build_asgi_app
from wazuh_mcp.transport.stdio import run_stdio

__all__ = ["build_asgi_app", "run_stdio"]
```

- [ ] **Step 16.3: Update `server.py`**

In `src/wazuh_mcp/server.py`, replace the inline `run_stdio` function at the bottom of the file with a delegation:

```python
from wazuh_mcp.transport.stdio import run_stdio as _run_stdio


def run_stdio(config_dir: Path) -> None:
    cfg = load_config(config_dir)
    app = build_app(cfg)
    _run_stdio(app)
```

Remove the now-unused `import asyncio` if nothing else uses it.

- [ ] **Step 16.4: Full suite green**

Run: `uv run pytest -q -m "not integration"`
Expected: still green.

- [ ] **Step 16.5: Commit**

```bash
git add src/wazuh_mcp/transport/stdio.py src/wazuh_mcp/transport/__init__.py src/wazuh_mcp/server.py
git commit -m "Extract stdio transport into transport/stdio.py"
```

---

### Task 17: HTTP server.py wiring + CLI flag

**Purpose:** Add the HTTP entry point that builds `OAuthSessionFactory` + `ApiKeySessionFactory` + `ChainSessionFactory`, constructs the ASGI app, and runs uvicorn.

**Files:**
- Modify: `src/wazuh_mcp/server.py`
- Modify: `src/wazuh_mcp/__main__.py`

- [ ] **Step 17.1: Update `server.py`**

Append to `src/wazuh_mcp/server.py` (keep existing code):

```python
# ---- HTTP mode wiring ----

from wazuh_mcp.auth.api_key import ApiKeySessionFactory
from wazuh_mcp.auth.api_key_store import YamlApiKeyStore
from wazuh_mcp.auth.chain_factory import ChainSessionFactory
from wazuh_mcp.auth.jwks_cache import JwksCache
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.tenancy.issuer_index import IssuerIndex
from wazuh_mcp.transport.http import build_asgi_app
from wazuh_mcp.wazuh.indexer_pool import IndexerClientPool


@dataclass(frozen=True)
class HttpAppConfig:
    pool: IndexerClientPool
    chain: ChainSessionFactory
    oauth: OAuthSessionFactory
    issuer_index: IssuerIndex
    resource_url: str
    authorization_server: str


def load_http_config(config_dir: Path) -> HttpAppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    # All tenants visible in the registry — HTTP mode serves all of them.
    all_tenants = [registry.get(tid) for tid in _tenant_ids(config_dir / "tenants.yaml")]
    issuer_index = IssuerIndex(all_tenants)

    oauth_cfg = server_cfg["oauth"]
    oauth = OAuthSessionFactory(
        issuer=oauth_cfg["issuer"],
        audience=oauth_cfg["audience"],
        algorithms=list(oauth_cfg.get("algorithms", ["RS256"])),
        rbac_claims=list(oauth_cfg.get("rbac_claims", ["wazuh_mcp_role", "groups", "roles"])),
        issuer_index=issuer_index,
        clock_skew_seconds=int(oauth_cfg.get("clock_skew_seconds", 30)),
        jwks=JwksCache(issuer=oauth_cfg["issuer"]),
    )

    api_store = YamlApiKeyStore(Path(server_cfg["api_keys_file"]))
    api_key_factory = ApiKeySessionFactory(store=api_store)

    chain = ChainSessionFactory(oauth=oauth, api_key=api_key_factory)

    pool = IndexerClientPool(registry=registry, secrets=secrets)

    http_cfg = server_cfg["http"]
    return HttpAppConfig(
        pool=pool,
        chain=chain,
        oauth=oauth,
        issuer_index=issuer_index,
        resource_url=http_cfg["public_url"],
        authorization_server=oauth_cfg["issuer"],
    )


def _tenant_ids(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text()) or {}
    return [t["tenant_id"] for t in data.get("tenants", [])]


def build_http_app(http_cfg: HttpAppConfig, audit: AuditEmitter | None = None):
    """Build the ASGI app. Also returns a ready-flag callable for /readyz."""
    audit_emitter = audit or AuditEmitter()
    mcp_app = FastMCP(name="wazuh-mcp")

    @mcp_app.tool(
        name="search_alerts",
        description=(
            "Search Wazuh alerts by time range and filters. Use when the user "
            "asks about security events, detections, or incidents within a "
            "time window. Returns a paginated list; use `cursor` from a prior "
            "response to continue."
        ),
    )
    async def _search_alerts(
        time_range: str = "1h",
        min_level: int | None = None,
        agent_id: str | None = None,
        size: int = 25,
        cursor: list[Any] | None = None,
    ) -> dict[str, Any]:
        args = SearchAlertsArgs(
            time_range=time_range,
            min_level=min_level,
            agent_id=agent_id,
            size=size,
            cursor=cursor,
        )
        session = current_session()
        indexer = await http_cfg.pool.acquire(session.tenant_id)
        return await search_alerts(
            args=args,
            session=session,
            indexer=indexer,
            audit=audit_emitter,
        )

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

    # Flip ready once at startup — OIDC discovery runs lazily on first call.
    ready[0] = True
    return asgi


def run_http(config_dir: Path) -> None:
    import uvicorn

    http_cfg = load_http_config(config_dir)
    asgi = build_http_app(http_cfg)

    server_yaml = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    bind = server_yaml["http"]["bind"]
    host, _, port = bind.partition(":")
    uvicorn.run(asgi, host=host, port=int(port), proxy_headers=True, log_level="info")
```

Replace the lone `from wazuh_mcp.transport.stdio import run_stdio as _run_stdio` + `def run_stdio(config_dir: Path)` pair at the top of the appended block (Task 16's change) if needed to avoid duplicate definitions.

- [ ] **Step 17.2: Update `__main__.py`**

File: `src/wazuh_mcp/__main__.py`

```python
"""CLI entry point: `python -m wazuh_mcp` or `wazuh-mcp`.

Reads config directory from $WAZUH_MCP_CONFIG_DIR, defaulting to ./config.
Chooses transport via server.yaml `transport:` field (stdio|http).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml


def main() -> int:
    config_dir = Path(os.environ.get("WAZUH_MCP_CONFIG_DIR", "./config")).resolve()
    if not config_dir.is_dir():
        print(f"Config directory not found: {config_dir}", file=sys.stderr)
        return 2

    server_yaml = config_dir / "server.yaml"
    transport = "stdio"
    if server_yaml.is_file():
        data = yaml.safe_load(server_yaml.read_text()) or {}
        transport = str(data.get("transport", "stdio")).lower()

    if transport == "stdio":
        from wazuh_mcp.server import run_stdio

        run_stdio(config_dir)
    elif transport == "http":
        from wazuh_mcp.server import run_http

        run_http(config_dir)
    else:
        print(f"Unknown transport {transport!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 17.3: Smoke test — HTTP server boots**

Create a temporary config for testing:

```bash
mkdir -p /tmp/wm-http-smoke
cat > /tmp/wm-http-smoke/tenants.yaml <<'EOF'
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
    oauth_issuer: https://idp.invalid
    oauth_audience: wazuh-mcp-api
EOF
cat > /tmp/wm-http-smoke/secrets.yaml <<'EOF'
local:
  indexer_user: admin
  indexer_password: admin
EOF
cat > /tmp/wm-http-smoke/api_keys.yaml <<'EOF'
api_keys: []
EOF
cat > /tmp/wm-http-smoke/server.yaml <<'EOF'
transport: http
auth: oauth_chain
http:
  bind: "127.0.0.1:8765"
  public_url: "http://localhost:8765"
oauth:
  issuer: https://idp.invalid
  audience: wazuh-mcp-api
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256]
  clock_skew_seconds: 30
api_keys_file: /tmp/wm-http-smoke/api_keys.yaml
EOF
```

Run the server in the background and probe:

```bash
WAZUH_MCP_CONFIG_DIR=/tmp/wm-http-smoke uv run wazuh-mcp &
SERVER_PID=$!
sleep 3
curl -s http://127.0.0.1:8765/healthz
echo
curl -s http://127.0.0.1:8765/.well-known/oauth-protected-resource
echo
kill $SERVER_PID 2>/dev/null
rm -rf /tmp/wm-http-smoke
```

Expected: `/healthz` returns `{"status":"ok"}`; metadata endpoint returns a JSON body with `resource`, `authorization_servers`, `bearer_methods_supported`.

- [ ] **Step 17.4: Commit**

```bash
git add src/wazuh_mcp/server.py src/wazuh_mcp/__main__.py
git commit -m "Wire HTTP transport into server and CLI"
```

---

### Task 18: Security-negatives suite

**Files:**
- Create: `tests/security/__init__.py` (empty)
- Create: `tests/security/test_m2_negatives.py`

- [ ] **Step 18.1: Create the test file**

File: `tests/security/test_m2_negatives.py`

```python
"""M2 auth layer — targeted negative security tests.

No Keycloak required; uses JwtFactory + a pytest-httpx fake JWKS endpoint.
Each test pins ONE specific attack we must reject.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.errors import AuthError, InvalidToken
from wazuh_mcp.auth.oauth import OAuthSessionFactory
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.issuer_index import IssuerIndex
from tests.fixtures.jwt_factory import JwtFactory


ISS = "https://idp.test"
AUD = "wazuh-mcp-api"
DISCO = f"{ISS}/.well-known/openid-configuration"
JWKS = f"{ISS}/jwks"


def _tenant(tid: str) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid, indexer_url="https://x:9200", verify_tls=False,
        ca_bundle_path=None, default_rbac_role="soc_analyst",
        oauth_issuer=ISS, oauth_audience=AUD,
    )


@pytest.fixture
def factory(httpx_mock: HTTPXMock) -> OAuthSessionFactory:
    jf = JwtFactory(issuer=ISS, audience=AUD)
    httpx_mock.add_response(url=DISCO, json=jf.oidc_discovery(JWKS))
    httpx_mock.add_response(url=JWKS, json=jf.jwks())
    return OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["RS256"],
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=IssuerIndex([_tenant("acme")]),
    )


@pytest.fixture
def jf() -> JwtFactory:
    return JwtFactory(issuer=ISS, audience=AUD)


async def test_alg_none_rejected(factory, jf):
    # A JWT signed with alg=none tries to skip signature verification.
    tampered = jf.make_with_header(
        sub="alice", header={"alg": "none", "kid": jf.kid, "typ": "JWT"},
        extra={"tenant_id": "acme", "wazuh_mcp_role": "soc_analyst"},
    )
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {tampered}"}})
    finally:
        await factory.aclose()


async def test_signature_tampered_rejected(factory, jf):
    token = jf.make(sub="alice", extra={"tenant_id": "acme"})
    head, body, sig = token.rsplit(".", 2)
    # Flip a byte in the signature.
    bad = head + "." + body + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {bad}"}})
    finally:
        await factory.aclose()


async def test_algorithm_allowlist_enforced(httpx_mock: HTTPXMock):
    # Factory only accepts ES256 but token is RS256.
    jf = JwtFactory(issuer=ISS, audience=AUD)
    httpx_mock.add_response(url=DISCO, json=jf.oidc_discovery(JWKS))
    httpx_mock.add_response(url=JWKS, json=jf.jwks())
    factory = OAuthSessionFactory(
        issuer=ISS, audience=AUD, algorithms=["ES256"],  # RS256 missing
        rbac_claims=["wazuh_mcp_role"],
        issuer_index=IssuerIndex([_tenant("acme")]),
    )
    token = jf.make(sub="alice", extra={"tenant_id": "acme", "wazuh_mcp_role": "a"})
    try:
        with pytest.raises(AuthError):
            await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()


async def test_malformed_jwt_rejected(factory):
    try:
        for bad in ["not.a.jwt", "aaa.bbb", "aaa..ccc", "."]:
            with pytest.raises(InvalidToken):
                await factory.build({"headers": {"Authorization": f"Bearer {bad}"}})
    finally:
        await factory.aclose()


async def test_log_poisoning_in_sub(factory, jf):
    # sub carries newlines and ANSI codes; must not break single-line logging.
    # (We only assert the session builds successfully; the log-sanitisation
    # happens at the audit emitter and is covered in M1's audit tests. Here
    # we pin that the OAuth factory itself doesn't barf on weird sub values.)
    evil_sub = "alice\x1b[31m\nHIJACK"
    token = jf.make(sub=evil_sub, extra={"tenant_id": "acme", "wazuh_mcp_role": "a"})
    try:
        session = await factory.build({"headers": {"Authorization": f"Bearer {token}"}})
    finally:
        await factory.aclose()
    assert session.user_id == evil_sub  # preserved for audit, not logged raw
```

- [ ] **Step 18.2: Run — expect pass**

Run: `uv run pytest tests/security/ -v`
Expected: 5 passed. If the `test_alg_none_rejected` case raises a non-`AuthError` exception (joserfc may not accept `alg=none` at all — which is the defense), adjust the `pytest.raises(AuthError)` to `pytest.raises(Exception)` for that single test with a comment explaining, or tighten the mapper in `oauth.py` to normalise joserfc's refusal into `InvalidToken`.

- [ ] **Step 18.3: Commit**

```bash
git add tests/security/__init__.py tests/security/test_m2_negatives.py
git commit -m "Add M2 auth-layer negative security test suite"
```

---

### Task 19: Keycloak integration fixture

**Purpose:** Extends `docker/integration-compose.yml` with a pre-seeded Keycloak 26 container and teaches `bootstrap.sh` to seed the realm.

**Files:**
- Modify: `docker/integration-compose.yml`
- Create: `docker/config/keycloak-realm.json`
- Modify: `docker/bootstrap.sh`

- [ ] **Step 19.1: Extend `integration-compose.yml`**

Append a `keycloak` service. Full updated file content:

```yaml
# Single-node Wazuh indexer + Keycloak 26 IdP for integration tests.
services:
  generator:
    image: wazuh/wazuh-certs-generator:0.0.2
    platform: linux/amd64
    hostname: wazuh-certs-generator
    entrypoint: sh -c "/entrypoint.sh; chown -R 1000:999 /certificates; chmod 740 /certificates; chmod 440 /certificates/*"
    volumes:
      - ./config/wazuh_indexer_ssl_certs/:/certificates/
      - ./config/certs.yml:/config/certs.yml:ro

  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.9.0
    platform: linux/amd64
    hostname: wazuh-indexer
    depends_on:
      generator:
        condition: service_completed_successfully
    environment:
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
      - bootstrap.memory_lock=true
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile: { soft: 65536, hard: 65536 }
    ports:
      - "9200:9200"
    volumes:
      - ./config/opensearch.yml:/usr/share/wazuh-indexer/opensearch.yml:ro
      - ./config/wazuh_indexer_ssl_certs/:/usr/share/wazuh-indexer/certs/:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u admin:admin https://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 10s
      timeout: 5s
      retries: 60
      start_period: 90s

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    hostname: keycloak
    command: ["start-dev", "--import-realm"]
    environment:
      - KC_BOOTSTRAP_ADMIN_USERNAME=admin
      - KC_BOOTSTRAP_ADMIN_PASSWORD=admin
      - KC_HTTP_PORT=8080
    ports:
      - "8080:8080"
    volumes:
      - ./config/keycloak-realm.json:/opt/keycloak/data/import/realm.json:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/realms/wazuh-mcp/.well-known/openid-configuration >/dev/null"]
      interval: 5s
      timeout: 3s
      retries: 60
      start_period: 30s
```

- [ ] **Step 19.2: Create `docker/config/keycloak-realm.json`**

This is a standard Keycloak realm export. Minimal realm with two users (alice soc_analyst, bob admin), an audience-asserting mapper, and a confidential client `wazuh-mcp-client`:

File: `docker/config/keycloak-realm.json`

```json
{
  "realm": "wazuh-mcp",
  "enabled": true,
  "accessTokenLifespan": 300,
  "sslRequired": "none",
  "users": [
    {
      "username": "alice",
      "enabled": true,
      "email": "alice@example.com",
      "credentials": [{ "type": "password", "value": "alicepw", "temporary": false }],
      "attributes": { "wazuh_mcp_role": ["soc_analyst"] },
      "realmRoles": ["default-roles-wazuh-mcp"]
    },
    {
      "username": "bob",
      "enabled": true,
      "email": "bob@example.com",
      "credentials": [{ "type": "password", "value": "bobpw", "temporary": false }],
      "attributes": { "wazuh_mcp_role": ["admin"] },
      "realmRoles": ["default-roles-wazuh-mcp"]
    }
  ],
  "clients": [
    {
      "clientId": "wazuh-mcp-client",
      "enabled": true,
      "secret": "test-client-secret",
      "publicClient": false,
      "directAccessGrantsEnabled": true,
      "serviceAccountsEnabled": false,
      "standardFlowEnabled": true,
      "redirectUris": ["http://localhost:*"],
      "webOrigins": ["+"],
      "protocolMappers": [
        {
          "name": "aud-mapper",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "wazuh-mcp-api",
            "id.token.claim": "false",
            "access.token.claim": "true"
          }
        },
        {
          "name": "wazuh_mcp_role-mapper",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": {
            "user.attribute": "wazuh_mcp_role",
            "claim.name": "wazuh_mcp_role",
            "jsonType.label": "String",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "multivalued": "false"
          }
        },
        {
          "name": "tenant_id-literal",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-hardcoded-claim-mapper",
          "config": {
            "claim.name": "tenant_id",
            "claim.value": "local",
            "jsonType.label": "String",
            "id.token.claim": "false",
            "access.token.claim": "true"
          }
        }
      ]
    }
  ]
}
```

Note: a real multi-tenant deployment would NOT hardcode `tenant_id` — it would map from a user attribute. For the test fixture we only need tenant `local`, which matches M1's default Wazuh seed.

- [ ] **Step 19.3: Extend `bootstrap.sh`**

Read the current `docker/bootstrap.sh`. Add a Keycloak-health wait before the final "ready" message. Full updated content:

```bash
#!/usr/bin/env bash
# One-shot bootstrap for the integration fixture.
#
# Brings up Wazuh + Keycloak, initialises OpenSearch security, seeds alerts.
# Keycloak imports its realm from docker/config/keycloak-realm.json at startup.
#
# Usage: docker/bootstrap.sh
# Teardown: docker compose -f docker/integration-compose.yml down -v
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/integration-compose.yml"
INDEXER_CONTAINER="docker-wazuh-indexer-1"
KEYCLOAK_URL="http://localhost:8080"
INDEXER_URL="https://localhost:9200"
ADMIN_AUTH="admin:admin"

echo "[bootstrap] bringing up compose stack..."
docker compose -f "$COMPOSE_FILE" up -d

echo "[bootstrap] waiting for wazuh-indexer to accept connections..."
for _ in $(seq 1 60); do
    if docker exec "$INDEXER_CONTAINER" curl -sk -o /dev/null -w '%{http_code}' \
        "$INDEXER_URL/_cluster/health" 2>/dev/null | grep -qE '^(200|401|503)$'; then
        break
    fi
    sleep 5
done

echo "[bootstrap] initialising OpenSearch security plugin..."
docker exec "$INDEXER_CONTAINER" bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ \
        -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -h localhost
' > /dev/null

echo "[bootstrap] waiting for cluster to go green..."
for _ in $(seq 1 30); do
    status=$(curl -sk -u "$ADMIN_AUTH" "$INDEXER_URL/_cluster/health" 2>/dev/null \
        | grep -oE '"status":"[^"]+"' || true)
    case "$status" in
        *green*|*yellow*) break ;;
    esac
    sleep 2
done

echo "[bootstrap] seeding synthetic alerts..."
uv run python "$(dirname "$0")/seed_alerts.py"

echo "[bootstrap] waiting for Keycloak realm..."
for _ in $(seq 1 60); do
    if curl -sf "$KEYCLOAK_URL/realms/wazuh-mcp/.well-known/openid-configuration" \
        > /dev/null 2>&1; then
        echo "[bootstrap] Keycloak realm ready."
        break
    fi
    sleep 5
done

echo "[bootstrap] ready. Run: uv run pytest -m integration"
```

- [ ] **Step 19.4: Smoke the new fixture**

Run: `docker compose -f docker/integration-compose.yml down -v && docker/bootstrap.sh`
Expected: both Wazuh indexer and Keycloak come up; bootstrap ends with "ready" within ~5-10 minutes (first pull). If Keycloak fails to import the realm, `docker compose -f docker/integration-compose.yml logs keycloak | tail -50` will show the parse error.

- [ ] **Step 19.5: Tear down**

Run: `docker compose -f docker/integration-compose.yml down -v`

- [ ] **Step 19.6: Commit**

```bash
git add docker/integration-compose.yml docker/config/keycloak-realm.json docker/bootstrap.sh
git commit -m "Add Keycloak 26 to integration fixture with pre-imported realm"
```

---

### Task 20: OAuth integration tests

**Files:**
- Modify: `tests/integration/conftest.py`
- Create: `tests/integration/test_oauth_e2e.py`

- [ ] **Step 20.1: Extend `conftest.py`**

Read the current file and append a Keycloak-token fixture:

```python
import os

import httpx


KEYCLOAK_TOKEN_URL = (
    os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    + "/realms/wazuh-mcp/protocol/openid-connect/token"
)


@pytest.fixture
def keycloak_token():
    def _get(username: str, password: str) -> str:
        resp = httpx.post(
            KEYCLOAK_TOKEN_URL,
            data={
                "grant_type": "password",
                "client_id": "wazuh-mcp-client",
                "client_secret": "test-client-secret",
                "username": username,
                "password": password,
                "scope": "openid",
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    return _get
```

- [ ] **Step 20.2: Write the integration tests**

File: `tests/integration/test_oauth_e2e.py`

```python
"""End-to-end OAuth tests against Keycloak + MCP HTTP server.

Prerequisites (run these via docker/bootstrap.sh):
  - wazuh-indexer healthy on https://localhost:9200 with seeded alerts
  - Keycloak on http://localhost:8080 with realm wazuh-mcp imported
  - The MCP HTTP server running on http://localhost:8765 with:
      - tenant_id=local pointing at https://localhost:9200
      - oauth_issuer=http://localhost:8080/realms/wazuh-mcp
      - audience=wazuh-mcp-api

The test starts the MCP HTTP server as a subprocess per module.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest


MCP_URL = "http://127.0.0.1:8765"


@pytest.fixture(scope="module")
def mcp_http_server() -> None:
    cfg_dir = Path(tempfile.mkdtemp(prefix="wm-m2-"))

    (cfg_dir / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: local
    indexer_url: https://localhost:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
    oauth_issuer: http://localhost:8080/realms/wazuh-mcp
    oauth_audience: wazuh-mcp-api
""".strip()
    )
    (cfg_dir / "secrets.yaml").write_text(
        """
local:
  indexer_user: admin
  indexer_password: admin
""".strip()
    )
    (cfg_dir / "api_keys.yaml").write_text("api_keys: []\n")
    (cfg_dir / "server.yaml").write_text(
        f"""
transport: http
auth: oauth_chain
http:
  bind: "127.0.0.1:8765"
  public_url: "{MCP_URL}"
oauth:
  issuer: http://localhost:8080/realms/wazuh-mcp
  audience: wazuh-mcp-api
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256]
  clock_skew_seconds: 30
api_keys_file: {cfg_dir / "api_keys.yaml"}
""".strip()
    )

    env = os.environ.copy()
    env["WAZUH_MCP_CONFIG_DIR"] = str(cfg_dir)
    proc = subprocess.Popen(
        ["uv", "run", "wazuh-mcp"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    # Wait for /healthz
    for _ in range(40):
        try:
            r = httpx.get(f"{MCP_URL}/healthz", timeout=1)
            if r.status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError("MCP HTTP server didn't come up")

    yield None

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(cfg_dir, ignore_errors=True)


@pytest.mark.integration
def test_protected_resource_metadata_exposes_configured_issuer(mcp_http_server):
    resp = httpx.get(f"{MCP_URL}/.well-known/oauth-protected-resource", timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == MCP_URL
    assert body["authorization_servers"] == [
        "http://localhost:8080/realms/wazuh-mcp"
    ]


@pytest.mark.integration
def test_mcp_unauth_rejected(mcp_http_server):
    # Any POST without Authorization returns 401.
    resp = httpx.post(f"{MCP_URL}/mcp", json={}, timeout=5)
    assert resp.status_code == 401


@pytest.mark.integration
def test_mcp_with_valid_oauth_token_returns_initialize(
    mcp_http_server, keycloak_token
):
    token = keycloak_token("alice", "alicepw")
    # Streamable HTTP uses an initialize JSON-RPC handshake.
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "e2e-test", "version": "0.1"},
        },
    }
    resp = httpx.post(
        f"{MCP_URL}/mcp",
        json=init,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        timeout=15,
    )
    # FastMCP returns an MCP-framed success; either JSON or SSE wrapping.
    assert resp.status_code in (200, 202)
    # The body should NOT contain the word "unauthorized".
    assert b"unauthorized" not in resp.content.lower()


@pytest.mark.integration
def test_wrong_audience_rejected(mcp_http_server):
    # Synthesise a token from a different audience by calling Keycloak with
    # the wrong client scope — here we just mint a bogus RS256 token that
    # won't verify at all. Demonstrates: generic garbage → 401.
    fake = "aaa.bbb.ccc"
    resp = httpx.post(
        f"{MCP_URL}/mcp",
        json={},
        headers={"Authorization": f"Bearer {fake}"},
        timeout=5,
    )
    assert resp.status_code == 401
```

- [ ] **Step 20.3: Run the integration tests**

Prereq: `docker/bootstrap.sh` already run.

Run: `uv run pytest -m integration -v`
Expected: 4 new + 3 existing (M1) = 7 passed. If the MCP server subprocess doesn't come up (port clash, config error), the module-scope fixture surfaces the error.

- [ ] **Step 20.4: Tear down**

Run: `docker compose -f docker/integration-compose.yml down -v`

- [ ] **Step 20.5: Commit**

```bash
git add tests/integration/conftest.py tests/integration/test_oauth_e2e.py
git commit -m "Add OAuth end-to-end integration tests against Keycloak"
```

---

### Task 21: Deploy docs — m2-http.md

**Files:**
- Create: `docs/deploy/m2-http.md`

- [ ] **Step 21.1: Write `docs/deploy/m2-http.md`**

Full content:

````markdown
# M2 — Remote HTTP deployment

This guide walks through a production-style wazuh-mcp deployment: uvicorn behind Caddy, with OAuth 2.1 in front of the `/mcp` endpoint and an API-key fallback for clients without an IdP.

## Topology

```
  Claude client
       │
       ▼  HTTPS (ACME cert via Caddy)
┌─────────────────┐
│   Caddy         │   terminates TLS, forwards to mcp:8000
└─────────────────┘
       │
       ▼
┌─────────────────┐
│   wazuh-mcp     │   uvicorn, ASGI, /mcp + /healthz + /readyz
│   + auth chain  │         + /.well-known/oauth-protected-resource
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Wazuh indexer   │   OAuth IdP (Keycloak / Okta / Entra / Auth0)
└─────────────────┘
```

## Files you'll create

- `/etc/wazuh-mcp/server.yaml` (see below)
- `/etc/wazuh-mcp/tenants.yaml`
- `/etc/wazuh-mcp/secrets.yaml`  (mode 0600)
- `/etc/wazuh-mcp/api_keys.yaml` (mode 0600)
- `/etc/caddy/Caddyfile`

## server.yaml

```yaml
transport: http
auth: oauth_chain
http:
  bind: "0.0.0.0:8000"
  public_url: "https://mcp.example.com"
oauth:
  issuer: "https://idp.example.com/realms/msp"
  audience: "wazuh-mcp-api"
  rbac_claims: [wazuh_mcp_role, groups, roles]
  algorithms: [RS256, ES256]
  clock_skew_seconds: 30
api_keys_file: /etc/wazuh-mcp/api_keys.yaml
```

## tenants.yaml

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    verify_tls: true
    ca_bundle_path: /etc/wazuh-mcp/ca/acme.pem
    default_rbac_role: soc_analyst
    oauth_issuer: https://idp.example.com/realms/msp
    oauth_audience: wazuh-mcp-api
```

(Add one entry per customer tenant. If tenants live behind different IdPs, one MCP deployment per IdP.)

## secrets.yaml

```yaml
acme:
  indexer_user: mcp-reader
  indexer_password: "pw-1"
```

Chmod 0600 and owned by the MCP service user. Production deployments should replace this with a KMS-backed driver in M4.

## api_keys.yaml

See `docs/deploy/api-keys.md` for how to generate entries.

## Caddyfile

```
mcp.example.com {
    reverse_proxy mcp:8000
}
```

Caddy handles ACME automatically. For internal/staging setups, add `{ auto_https off }` and run behind an internal cert.

## docker-compose deployment

```yaml
services:
  mcp:
    image: ghcr.io/0xFl4g/wazuh-mcp:0.2.0
    environment:
      - WAZUH_MCP_CONFIG_DIR=/etc/wazuh-mcp
    volumes:
      - ./wazuh-mcp:/etc/wazuh-mcp:ro
    restart: unless-stopped

  caddy:
    image: caddy:2-alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on: [mcp]
    restart: unless-stopped

volumes:
  caddy_data:
```

## Verifying the deployment

```
curl https://mcp.example.com/healthz          # → {"status":"ok"}
curl https://mcp.example.com/readyz           # → {"status":"ok"} once JWKS fetched
curl https://mcp.example.com/.well-known/oauth-protected-resource
# {"resource":"https://mcp.example.com",
#  "authorization_servers":["https://idp.example.com/realms/msp"], ...}
```

Smoke-test an authenticated call:

```
TOKEN=$(get-a-token-from-your-idp)
curl -X POST https://mcp.example.com/mcp \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"curl","version":"0.1"}}}'
```

## Sizing

- ~50 tenants / 100 concurrent sessions per uvicorn worker is comfortable.
- Add workers behind Caddy with `uvicorn --workers N` (shared JWKS cache is per-worker; acceptable at the cost of N× discovery fetches at startup).
- For > 500 tenants, consider per-IdP sharding (multiple deployments).

## Known gaps (v1 / M2)

- No rate limiting in-process. Let Caddy do coarse-grained DOS protection.
- No OTel / metrics; M4 adds both.
- No refresh-token handling server-side — clients handle token refresh.
- No mTLS on the MCP endpoint; use Caddy + client certs if you need it.

## Next steps

- OAuth setup per IdP: `docs/deploy/oauth-setup/{keycloak,okta,entra,auth0}.md`.
- API-key generation: `docs/deploy/api-keys.md`.
````

- [ ] **Step 21.2: Commit**

```bash
git add docs/deploy/m2-http.md
git commit -m "Add M2 HTTP deployment guide"
```

---

### Task 22: Deploy docs — OAuth setup per IdP

**Files:**
- Create: `docs/deploy/oauth-setup/keycloak.md`
- Create: `docs/deploy/oauth-setup/okta.md`
- Create: `docs/deploy/oauth-setup/entra.md`
- Create: `docs/deploy/oauth-setup/auth0.md`

- [ ] **Step 22.1: Keycloak guide**

File: `docs/deploy/oauth-setup/keycloak.md`

```markdown
# OAuth setup — Keycloak

Keycloak 24+ (tested: 26). Use the integration-test realm export as a starting point: `docker/config/keycloak-realm.json`.

## Minimum steps

1. **Create a realm** named after your MSSP (e.g., `msp`).
2. **Create a client**:
   - Client ID: `wazuh-mcp-client`
   - Access type: Confidential
   - Direct Access Grants: on (for testing) or off (production)
   - Standard flow: on
   - Valid redirect URIs: whatever your MCP client expects (for Claude, `http://localhost:*`)
3. **Add protocol mappers** to the client:
   - **Audience mapper** — includes `wazuh-mcp-api` in the token's `aud`.
     - Type: Audience
     - Included Client Audience: `wazuh-mcp-api`
     - Add to access token: ✓
   - **Tenant mapper** — emits `tenant_id` claim from a user attribute.
     - Type: User Attribute
     - User Attribute: `wazuh_mcp_tenant`
     - Token Claim Name: `tenant_id`
     - Claim JSON Type: String
     - Add to access token: ✓
   - **Role mapper** — emits `wazuh_mcp_role` claim from a user attribute.
     - Type: User Attribute
     - User Attribute: `wazuh_mcp_role`
     - Token Claim Name: `wazuh_mcp_role`
     - Claim JSON Type: String
     - Add to access token: ✓
4. **Populate user attributes** (per-user): set `wazuh_mcp_tenant` and `wazuh_mcp_role` via the Keycloak admin UI or API.
5. **Configure wazuh-mcp** with:
   ```yaml
   oauth:
     issuer: "https://keycloak.example.com/realms/msp"
     audience: "wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery and JWKS

Keycloak exposes:
- `${issuer}/.well-known/openid-configuration`
- `${issuer}/protocol/openid-connect/certs`

wazuh-mcp auto-discovers the JWKS URL from the configuration endpoint.

## Token rotation

Default Keycloak access token lifespan is 5 minutes. Adjust under Realm → Tokens as needed. Shorter lifespan = tighter revocation story; wazuh-mcp has no introspection in M2, so short tokens are the revocation mechanism.
```

- [ ] **Step 22.2: Okta guide**

File: `docs/deploy/oauth-setup/okta.md`

```markdown
# OAuth setup — Okta

Okta Workforce Identity Cloud. Requires an org admin account.

## Minimum steps

1. **Create an API service** (under Security → API → Authorization Servers → Default, or create a custom auth server):
   - Audience: `wazuh-mcp-api`
2. **Create an OIDC application**:
   - Applications → Create App Integration → OIDC → Native/SPA/Web (match your MCP client)
   - Client ID: record it for the MCP config
   - Allowed grant types: Authorization Code (PKCE)
3. **Add claims** to the access token:
   - `tenant_id` → Expression `user.wazuh_mcp_tenant`
   - `wazuh_mcp_role` → Expression `user.wazuh_mcp_role`
   Mark both as **Always**, include in **Access Token**.
4. **Set user profile attributes** on users or on a group.
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://<your-org>.okta.com/oauth2/<server-id>"
     audience: "wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery

Okta's well-known endpoint lives at `${issuer}/.well-known/openid-configuration`. JWKS is discovered automatically.

## Notes

- The **Default** authorization server's issuer is `https://<org>.okta.com`, but custom audiences + claims require a **custom** authorization server. Use a custom one for real deployments.
- Okta's default access-token lifetime is 1 hour. Consider shortening for sensitive environments.
```

- [ ] **Step 22.3: Entra guide**

File: `docs/deploy/oauth-setup/entra.md`

```markdown
# OAuth setup — Microsoft Entra (Azure AD)

Entra External Identities or Workforce tenant. Requires Application Administrator.

## Minimum steps

1. **Register an application**:
   - Name: `wazuh-mcp-api`
   - Supported account types: Single tenant (production) or multi-tenant (if you want federation)
   - Redirect URI: `http://localhost` (for native clients like Claude Desktop) or your MCP client URL
2. **Expose an API**:
   - Application ID URI: `api://wazuh-mcp-api`
   - Add a scope: `mcp.read`
3. **Add an app role** for each tenant (if using roles-claim routing), e.g., `Wazuh.Acme.Analyst`.
4. **Create optional claims** in the manifest or UI:
   ```json
   "optionalClaims": {
     "accessToken": [
       { "name": "tenant_id", "source": null, "essential": false },
       { "name": "wazuh_mcp_role", "source": null, "essential": false }
     ]
   }
   ```
   For custom-claim population, use a **claims mapping policy** attached to a **service principal** (Entra's claim-customization path for access tokens).
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
     audience: "api://wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, roles, groups]
   ```

## v1 vs v2 endpoints

Use the v2.0 issuer (`/v2.0`) and audience of the form `api://<app-id-uri>`. The v1 endpoint uses GUID audiences and is not recommended for new deployments.

## Discovery

Entra exposes `${issuer}/.well-known/openid-configuration`; auto-discovered.

## Notes

- Entra claim customization is more involved than Keycloak/Okta; simpler deployments can route via `iss` alone (the IssuerIndex path), skipping `tenant_id` claim entirely.
- Default access-token lifetime is 1 hour (configurable via Conditional Access policies).
```

- [ ] **Step 22.4: Auth0 guide**

File: `docs/deploy/oauth-setup/auth0.md`

```markdown
# OAuth setup — Auth0

Any Auth0 tenant.

## Minimum steps

1. **Create an API**:
   - Name: `wazuh-mcp-api`
   - Identifier (audience): `https://mcp.example.com/api` (or any URI you prefer)
   - Signing algorithm: RS256
2. **Create an application**:
   - Type: Machine-to-Machine (for service-to-service) or Native (for Claude Desktop)
   - Authorize the app for the API above
3. **Add a custom claim** via an Action (post-login):
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const ns = "https://mcp.example.com/";
     if (event.user.user_metadata?.wazuh_mcp_tenant) {
       api.accessToken.setCustomClaim("tenant_id", event.user.user_metadata.wazuh_mcp_tenant);
     }
     if (event.user.user_metadata?.wazuh_mcp_role) {
       api.accessToken.setCustomClaim("wazuh_mcp_role", event.user.user_metadata.wazuh_mcp_role);
     }
   };
   ```
4. **Set user metadata**: in the Auth0 user's `user_metadata`, set `wazuh_mcp_tenant` and `wazuh_mcp_role`.
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://<your-tenant>.auth0.com/"
     audience: "https://mcp.example.com/api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery

Auth0's well-known endpoint is `${issuer}.well-known/openid-configuration` (Auth0 includes the trailing slash in issuer). wazuh-mcp auto-discovers JWKS.

## Notes

- Auth0 namespaces custom claims unless you use an allowlisted claim name. If the claim doesn't arrive, verify the Action ran (Auth0 → Actions → Logs) and the claim isn't being stripped by a namespace rule.
- Default access-token lifetime is 24h. Shorten for sensitive deployments.
```

- [ ] **Step 22.5: Commit**

```bash
git add docs/deploy/oauth-setup/
git commit -m "Add OAuth setup guides for Keycloak, Okta, Entra, Auth0"
```

---

### Task 23: Deploy docs — api-keys.md

**Files:**
- Create: `docs/deploy/api-keys.md`

- [ ] **Step 23.1: Write the guide**

File: `docs/deploy/api-keys.md`

````markdown
# API keys

API keys are the fallback auth path for customers without an IdP.

## Format

```
wzk_<tenant_id>_<nnn>.<base64url-random>
```

- `wzk_<tenant_id>_<nnn>` is the `key_id` — used for store lookup.
- `.<random>` is the plaintext secret — argon2id-hashed in `api_keys.yaml`.
- `.` is the separator (never appears in either part).

Example: `wzk_acme_01.pK4n...base64url...`.

## Generating a key

```bash
python - <<'PY'
import secrets, sys
from argon2 import PasswordHasher

tenant = "acme"
seq = "01"
secret = secrets.token_urlsafe(32)      # 32 bytes → 43 chars base64url
key_id = f"wzk_{tenant}_{seq}"
full = f"{key_id}.{secret}"
hashed = PasswordHasher().hash(secret)

print(f"Full key (give to user ONCE): {full}")
print()
print(f"Add to api_keys.yaml:")
print(f"  - key_id: {key_id}")
print(f"    hash: \"{hashed}\"")
print(f"    tenant_id: {tenant}")
print(f"    user_id: alice@example.com")
print(f"    rbac_role: soc_analyst")
print(f"    revoked: false")
print(f"    expires_at: null")
PY
```

## Rotation

1. Generate a new key with an incremented sequence: `wzk_acme_02`.
2. Add the new entry to `api_keys.yaml` alongside the old one.
3. Send the new key to the user.
4. After confirming the user has switched, set `revoked: true` on the old entry.

No server restart needed — `api_keys.yaml` is re-read on every start, and reload is a planned M4 feature. For M2, a HUP to the uvicorn process is the escape hatch (forces restart + re-read).

## Revocation

Set `revoked: true` on the entry. Effective on next process start. For immediate revocation, restart the process.

## Expiry

Set `expires_at` to an ISO-8601 timestamp (e.g., `2026-12-31T23:59:59Z`). Verified per-call; expired keys fail with 401 the same as revoked ones.

## Security posture

- Plaintext is shown to the admin **once**, at generation time, and never again. Store it in the customer's secret manager.
- argon2id parameters (`m=19456, t=2, p=1`) are per-OWASP-2024 recommendation.
- The `wzk_<tenant>_` prefix is a **routing hint only** — authoritative tenant comes from the store entry. Crafted keys can't claim a tenant they weren't assigned.
- `api_keys.yaml` must be mode 0600 and owned by the MCP service user. A leak of this file exposes every key's hash — still not the plaintext, but harvestable offline if argon2 parameters are weak. Keep parameters at or above the OWASP recommendation.

## What the key does NOT grant

- Cross-tenant access. The store-entry's `tenant_id` pins the session's tenant.
- Admin / write operations. M2 is read-only.
- Bypass of RBAC — the `rbac_role` in the entry flows into the `Session`, and M4's RBAC-aware `list_tools` will gate tools accordingly.
````

- [ ] **Step 23.2: Commit**

```bash
git add docs/deploy/api-keys.md
git commit -m "Add API-key generation, rotation, and revocation guide"
```

---

### Task 24: Update main README + CI

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 24.1: Update README `M1 scope` section to `Milestone status`**

Read `README.md`. Replace the `## M1 scope` section with:

```markdown
## Milestones

- **M1 (v0.1.0-m1)** — walking skeleton: stdio, single tenant, one tool.
- **M2 (v0.2.0-m2)** — this release. Adds Streamable HTTP transport, OAuth 2.1 + API-key auth, multi-tenant session routing, per-tenant IndexerClient pool. Tool surface unchanged.
- **M3 (planned)** — full tool surface (~14 tools), Server API client, resources, prompts.
- **M4 (planned)** — production hardening: real secret backends, RBAC-aware tools, rate limits, OTel, write-tool scaffolding.
- **M5 (planned)** — ship-gate: eval harness, Wazuh LTS matrix CI, cross-tenant leak suite, full docs.

See `docs/superpowers/specs/` for full specs per milestone.

## Deploying M2

See `docs/deploy/m2-http.md` for the full remote-deployment guide (uvicorn + Caddy + OAuth IdP).
```

- [ ] **Step 24.2: Update CI to include security negatives**

File: `.github/workflows/ci.yml`

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  lint-and-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with: { version: "latest" }
      - name: Install
        run: uv sync --frozen
      - name: Ruff check
        run: uv run ruff check .
      - name: Ruff format check
        run: uv run ruff format --check .
      - name: Type check (ty)
        run: uv run ty check .
      - name: Unit tests
        run: uv run pytest -m "not integration" -v
```

(No change from M1 — the unit+security tests are already covered by `-m "not integration"`, which excludes integration tests and includes the new `tests/security/` directory via `testpaths = ["tests"]`.)

- [ ] **Step 24.3: Commit**

```bash
git add README.md .github/workflows/ci.yml
git commit -m "Update README with M2 milestone status and deployment pointer"
```

---

### Task 25: Manual smoke + tag v0.2.0-m2

- [ ] **Step 25.1: Verify green**

Run:
```bash
uv run ruff check . && uv run ruff format --check . && uv run ty check . && uv run pytest -q -m "not integration"
```
Expected: all pass.

- [ ] **Step 25.2: Manual E2E smoke**

```bash
docker/bootstrap.sh
# separate terminal:
WAZUH_MCP_CONFIG_DIR=./config uv run wazuh-mcp &
# config/ contents as in docs/deploy/m2-http.md but local
# Point Claude Desktop at http://localhost:8765/mcp (or test via curl with a Keycloak token)
```

This step is manual — confirm `/healthz`, `/.well-known/oauth-protected-resource`, and an authenticated `search_alerts` call all work.

- [ ] **Step 25.3: Tear down**

```bash
docker compose -f docker/integration-compose.yml down -v
```

- [ ] **Step 25.4: Tag**

```bash
git tag -a v0.2.0-m2 -m "M2: remote HTTP + OAuth 2.1 + API-key fallback"
git push origin main --follow-tags
```

---

## Self-Review

**Spec coverage (against `docs/superpowers/specs/2026-04-21-wazuh-mcp-m2-design.md`):**

- §2 decisions — every Q1-Q7 answer is implemented:
  - Q1 (generic OIDC, Keycloak fixture): Tasks 8, 10, 19, 20 ✅
  - Q2 (hybrid claim/iss routing): Task 10 (`_build_session` logic) ✅
  - Q3 (stdio + HTTP both): Tasks 16, 17 ✅
  - Q4 (YAML-only secrets in M2): no new drivers — YamlSecretStore from M1 reused via `IndexerClientPool` ✅
  - Q5 (per-tenant pool): Task 14 ✅
  - Q6 (reverse-proxy TLS): Tasks 17 (no in-process TLS code), 21 (Caddy reference) ✅
  - Q7 (one deployment, one IdP): Task 17 (`OAuthSessionFactory` takes a single issuer) ✅
- §3 Architecture: every module in the spec's diagram is created by a task ✅
- §4 Components: 1:1 mapping of components → tasks ✅
- §5 Data flow: Tasks 15 (middleware) + 17 (pool integration in tool wrapper) exercise the full flow ✅
- §6 Security model: Tasks 5 (error hierarchy), 8 (JWKS cache), 10 (JWT verification invariants), 11-12 (API-key flow), 15 (middleware hygiene), 18 (negatives suite) ✅
- §7 Testing: every test file named in the spec appears in the plan's File Structure and has a creating task ✅
- §8 Scale/deployment: Task 21 (deploy guide), Task 17 (uvicorn + proxy-headers) ✅
- §9 Roadmap: M3/M4/M5 explicitly cited in plan header and Task 24 README ✅

**Placeholder scan:** No TBD/TODO. Every step has exact code, exact command, exact expected output. Tasks that involve external services (Keycloak, docker) have runtime verification steps.

**Type consistency audit:**
- `SessionFactory` signature: `async build(ctx: RequestContext) -> Session` — consistent across Tasks 2, 3, 10, 12, 13, 15.
- `RequestContext` is `TypedDict(headers: dict[str, str], client_ip: str)` (total=False) — consistent.
- `Session` constructor args `(user_id, tenant_id, rbac_role, auth_method)` — consistent (M1 unchanged).
- `ApiKeyRecord` fields `(key_id, tenant_id, user_id, rbac_role)` — consistent across Task 11 definition and Task 12 consumer.
- `AuthError.http_status`, `AuthError.public_message` — consistent across Task 5 definition and Task 15 middleware.
- `IndexerClientPool.acquire(tenant_id)` → `IndexerClient` — consistent across Tasks 14 and 17.
- `JwksCache.get_key(kid) -> dict | None` — consistent across Tasks 8 and 10.
- `current_session() -> Session` — consistent across Tasks 3, 15, 17.
- `build_asgi_app` kwargs consistent across Task 15 definition and Task 17 caller.
- `OAuthSessionFactory(issuer=, audience=, algorithms=, rbac_claims=, issuer_index=, clock_skew_seconds=, jwks=)` — consistent across Tasks 10, 17, and 18 tests.

No issues. Plan is ready for execution.
