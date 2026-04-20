# Wazuh MCP M1 — Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the minimal-but-complete slice of the Wazuh MCP server — stdio transport, one YAML-configured tenant, one tool (`search_alerts`) — proving the full stack wires together end-to-end against a real Wazuh deployment.

**Architecture:** Python 3.12, async throughout. Dependency-injected module layout per spec §4. Single tool (`search_alerts`) backed by Wazuh Indexer only (port 9200). Pluggable-by-construction (`SecretStore` protocol, `TenantRegistry` protocol) but shipping only YAML drivers in M1. All interfaces needed by later milestones (sessions, tenancy, secrets, audit, error scrubbing, cursor pagination, strict Pydantic, TLS config) are exercised by the one tool — later milestones add breadth, not foundational pieces.

**Tech Stack:** Python 3.12 • `uv` package manager • official `mcp` SDK (FastMCP-style) • `httpx` async client • Pydantic v2 (strict) • `PyYAML` • `pytest` + `pytest-asyncio` + `pytest-httpx` + `hypothesis` • `ruff` (lint + format) • Docker Compose for integration Wazuh fixture.

**Out of scope for M1** (these land in later milestones):
- Streamable HTTP transport, OAuth, API keys (M2)
- Additional tools beyond `search_alerts`, resources, prompts (M3)
- AWS SM / Vault secret drivers, RBAC-aware `list_tools`, rate limits, OTel, back-to-Wazuh audit sink, v2 write scaffolding (M4)
- Eval harness, Wazuh LTS matrix CI, cross-tenant leak suite, full docs (M5)

**Reference:** `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md`.

---

## File Structure

```
wazuh-mcp/
├── pyproject.toml
├── .python-version
├── .gitignore
├── README.md
├── src/
│   └── wazuh_mcp/
│       ├── __init__.py
│       ├── __main__.py           # `python -m wazuh_mcp` entry point
│       ├── server.py             # DI wiring; stdio transport
│       ├── auth/
│       │   ├── __init__.py
│       │   └── session.py        # Session dataclass
│       ├── secrets/
│       │   ├── __init__.py
│       │   ├── value.py          # SecretValue (redacting wrapper)
│       │   ├── store.py          # SecretStore protocol
│       │   └── yaml_driver.py    # YAML-backed SecretStore
│       ├── tenancy/
│       │   ├── __init__.py
│       │   ├── config.py         # TenantConfig Pydantic model
│       │   └── registry.py       # TenantRegistry protocol + YAML driver
│       ├── wazuh/
│       │   ├── __init__.py
│       │   ├── indexer.py        # async httpx indexer client
│       │   ├── models.py         # Alert Pydantic model
│       │   ├── query.py          # search-alerts query builder
│       │   └── errors.py         # error → scrubbed code mapper
│       ├── tools/
│       │   ├── __init__.py
│       │   └── alerts.py         # search_alerts tool
│       └── observability/
│           ├── __init__.py
│           └── audit.py          # stdout JSON audit emitter
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_session.py
│   │   ├── test_secret_value.py
│   │   ├── test_yaml_secret_store.py
│   │   ├── test_tenant_config.py
│   │   ├── test_yaml_registry.py
│   │   ├── test_alert_model.py
│   │   ├── test_query_builder.py
│   │   ├── test_indexer_client.py
│   │   ├── test_error_mapper.py
│   │   ├── test_audit.py
│   │   └── test_search_alerts_tool.py
│   └── integration/
│       ├── __init__.py
│       ├── conftest.py
│       └── test_search_alerts_e2e.py
└── docker/
    ├── integration-compose.yml
    └── seed_alerts.py
```

**Rationale:** Each module stays small and has one responsibility (§ design spec §4). `secrets/` and `tenancy/` both expose a protocol + one M1 driver — the protocol locks in the interface every later milestone consumes. `wazuh/indexer.py` is the only upstream client in M1; `server_api.py` lands in M3. `tools/alerts.py` is the first of many; the pattern it establishes is reused in M3.

---

## Tasks

### Task 1: Project scaffolding

**Files:**
- Create: `.python-version`
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `src/wazuh_mcp/__init__.py`
- Create: `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1.1: Create `.python-version`**

```
3.12
```

- [ ] **Step 1.2: Create `pyproject.toml`**

```toml
[project]
name = "wazuh-mcp"
version = "0.1.0"
description = "Model Context Protocol server for Wazuh SIEM/XDR"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "mcp>=1.2.0",
    "httpx>=0.27.0",
    "pydantic>=2.7.0",
    "pyyaml>=6.0.1",
]

[project.scripts]
wazuh-mcp = "wazuh_mcp.__main__:main"

[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-httpx>=0.30",
    "hypothesis>=6.100",
    "ruff>=0.5.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/wazuh_mcp"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "integration: end-to-end tests requiring docker-compose Wazuh",
]
addopts = "-ra --strict-markers"

[tool.ruff]
line-length = 100
target-version = "py312"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "RUF", "N", "ASYNC"]
ignore = ["E501"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]
```

- [ ] **Step 1.3: Create `.gitignore`**

```
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.ruff_cache/
.venv/
.env
dist/
build/
htmlcov/
.coverage
*.log
```

- [ ] **Step 1.4: Create source and test package markers**

Create these files, each with empty content:
- `src/wazuh_mcp/__init__.py`
- `tests/__init__.py`
- `tests/unit/__init__.py`
- `tests/integration/__init__.py`

- [ ] **Step 1.5: Create `tests/conftest.py`**

```python
"""Shared pytest fixtures for wazuh-mcp tests."""
```

- [ ] **Step 1.6: Sync dependencies**

Run: `uv sync`
Expected: creates `.venv/`, installs all deps, prints "Resolved N packages".

- [ ] **Step 1.7: Verify test discovery**

Run: `uv run pytest --collect-only`
Expected: "collected 0 items" — no tests yet, but discovery succeeds.

- [ ] **Step 1.8: Commit**

```bash
git add pyproject.toml .python-version .gitignore src/ tests/
git commit -m "Scaffold Python project layout and dev tooling"
```

---

### Task 2: Session dataclass

**Purpose:** `Session` is the value object every tool call receives. In M1 it's populated from config; in M2 it's populated from OAuth. Locking the shape now prevents churn.

**Files:**
- Create: `src/wazuh_mcp/auth/__init__.py`
- Create: `src/wazuh_mcp/auth/session.py`
- Create: `tests/unit/test_session.py`

- [ ] **Step 2.1: Write the failing test**

File: `tests/unit/test_session.py`

```python
from wazuh_mcp.auth.session import Session


def test_session_holds_identity_and_tenant():
    session = Session(
        user_id="alice",
        tenant_id="acme",
        rbac_role="soc_analyst",
        auth_method="config",
    )
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "config"


def test_session_is_immutable():
    import dataclasses
    session = Session(
        user_id="alice",
        tenant_id="acme",
        rbac_role="soc_analyst",
        auth_method="config",
    )
    try:
        session.tenant_id = "hostile"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Session must be frozen to prevent mid-call tenant swap")
```

- [ ] **Step 2.2: Run the test — expect failure**

Run: `uv run pytest tests/unit/test_session.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.auth'`.

- [ ] **Step 2.3: Create empty `auth/__init__.py`**

File: `src/wazuh_mcp/auth/__init__.py` — empty.

- [ ] **Step 2.4: Implement `Session`**

File: `src/wazuh_mcp/auth/session.py`

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
```

- [ ] **Step 2.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_session.py -v`
Expected: 2 passed.

- [ ] **Step 2.6: Commit**

```bash
git add src/wazuh_mcp/auth/ tests/unit/test_session.py
git commit -m "Add frozen Session value object"
```

---

### Task 3: SecretValue — redacting wrapper

**Purpose:** Guarantee at the type level that secrets cannot leak via `repr`, `str`, `json.dumps`, or log formatters. This is the single most important piece of infrastructure in the security model.

**Files:**
- Create: `src/wazuh_mcp/secrets/__init__.py`
- Create: `src/wazuh_mcp/secrets/value.py`
- Create: `tests/unit/test_secret_value.py`

- [ ] **Step 3.1: Write the failing tests**

File: `tests/unit/test_secret_value.py`

```python
import json
import logging

from hypothesis import assume, given
from hypothesis import strategies as st

from wazuh_mcp.secrets.value import SecretValue


def test_repr_does_not_leak():
    s = SecretValue("hunter2")
    assert "hunter2" not in repr(s)
    assert "<redacted>" in repr(s)


def test_str_does_not_leak():
    s = SecretValue("hunter2")
    assert "hunter2" not in str(s)


def test_expose_returns_plaintext():
    s = SecretValue("hunter2")
    assert s.expose() == "hunter2"


def test_json_dumps_refuses_to_serialize():
    s = SecretValue("hunter2")
    try:
        json.dumps({"pw": s})
    except TypeError:
        return
    raise AssertionError("SecretValue must not be JSON-serializable")


def test_log_formatter_does_not_leak(caplog):
    s = SecretValue("hunter2")
    logger = logging.getLogger("test_secret")
    with caplog.at_level(logging.INFO, logger="test_secret"):
        logger.info("value is %s", s)
    for rec in caplog.records:
        assert "hunter2" not in rec.getMessage()


def test_equality_by_value():
    assert SecretValue("a") == SecretValue("a")
    assert SecretValue("a") != SecretValue("b")


def test_hash_does_not_leak():
    s = SecretValue("hunter2")
    _ = hash(s)  # must not raise


@given(secret=st.text(min_size=1, max_size=200))
def test_redaction_property(secret):
    # Skip secrets that are substrings of the redaction template — those
    # appear in formatted output by coincidence, not by leaking plaintext.
    redaction_template = "SecretValue(<redacted>)"
    assume(secret not in redaction_template)

    s = SecretValue(secret)
    assert secret not in repr(s)
    assert secret not in str(s)
    assert secret not in format(s, "")
    assert secret not in f"{s}"
    assert secret not in f"{s!r}"
```

- [ ] **Step 3.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_secret_value.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.secrets'`.

- [ ] **Step 3.3: Create empty `secrets/__init__.py`**

File: `src/wazuh_mcp/secrets/__init__.py` — empty.

- [ ] **Step 3.4: Implement `SecretValue`**

File: `src/wazuh_mcp/secrets/value.py`

```python
"""SecretValue — wraps sensitive strings so they cannot leak via
repr/str/json/logging/pickle/copy. Callers must call .expose() to access
plaintext, which makes every plaintext read site grep-able.
"""

from __future__ import annotations

import hashlib
from typing import Final, final

_REDACTED: Final[str] = "<redacted>"


@final
class SecretValue:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretValue requires a str")
        object.__setattr__(self, "_value", value)

    def expose(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"SecretValue({_REDACTED})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        # Hash the sha256, not the plaintext — prevents accidental
        # plaintext leak via hash-collision dictionaries or debuggers.
        return int.from_bytes(
            hashlib.sha256(self._value.encode()).digest()[:8], "big"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretValue is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SecretValue is immutable")

    def __copy__(self) -> "SecretValue":
        return SecretValue(self._value)

    def __deepcopy__(self, memo: dict) -> "SecretValue":
        return SecretValue(self._value)

    def __reduce__(self) -> tuple:
        # Refuse pickle — pickling a SecretValue would emit plaintext in the
        # serialized blob. Callers must re-fetch from the SecretStore.
        raise TypeError("SecretValue is not picklable; fetch from SecretStore")
```

- [ ] **Step 3.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_secret_value.py -v`
Expected: 14 passed (the `hypothesis` property test counts as 1; the parametrized `test_non_str_init_raises` expands to 6 cases at collection time, yielding 19 reported items from 14 test functions).

- [ ] **Step 3.6: Commit**

```bash
git add src/wazuh_mcp/secrets/__init__.py src/wazuh_mcp/secrets/value.py tests/unit/test_secret_value.py
git commit -m "Add SecretValue with repr/str/json/log redaction and property test"
```

---

### Task 4: SecretStore protocol and YAML driver

**Purpose:** Defines the interface every v1+ secret backend implements. Locking the protocol in M1 means AWS SM / Vault drivers in M4 are drop-in replacements, not refactors.

**Files:**
- Create: `src/wazuh_mcp/secrets/store.py`
- Create: `src/wazuh_mcp/secrets/yaml_driver.py`
- Create: `tests/unit/test_yaml_secret_store.py`

- [ ] **Step 4.1: Write the failing tests**

File: `tests/unit/test_yaml_secret_store.py`

```python
from pathlib import Path

import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore


@pytest.fixture
def secrets_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.yaml"
    p.write_text(
        """
acme:
  indexer_user: admin
  indexer_password: s3cret
beta:
  indexer_user: admin
  indexer_password: other
""".strip()
    )
    return p


async def test_get_returns_secret_value(secrets_file):
    store = YamlSecretStore(secrets_file)
    value = await store.get("acme", "indexer_password")
    assert isinstance(value, SecretValue)
    assert value.expose() == "s3cret"


async def test_get_is_tenant_scoped(secrets_file):
    store = YamlSecretStore(secrets_file)
    acme = await store.get("acme", "indexer_password")
    beta = await store.get("beta", "indexer_password")
    assert acme.expose() == "s3cret"
    assert beta.expose() == "other"


async def test_unknown_tenant_raises(secrets_file):
    store = YamlSecretStore(secrets_file)
    with pytest.raises(KeyError, match="ghost"):
        await store.get("ghost", "indexer_password")


async def test_unknown_key_raises(secrets_file):
    store = YamlSecretStore(secrets_file)
    with pytest.raises(KeyError, match="missing"):
        await store.get("acme", "missing")
```

- [ ] **Step 4.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_yaml_secret_store.py -v`
Expected: `ModuleNotFoundError: ... yaml_driver`.

- [ ] **Step 4.3: Implement `SecretStore` protocol**

File: `src/wazuh_mcp/secrets/store.py`

```python
"""SecretStore protocol — the contract every backend implements.

M1 ships YamlSecretStore. M4 adds AwsSecretsManagerStore,
VaultSecretStore, SqliteAgeSecretStore.
"""

from __future__ import annotations

from typing import Protocol

from wazuh_mcp.secrets.value import SecretValue


class SecretStore(Protocol):
    async def get(self, tenant_id: str, key: str) -> SecretValue:
        """Return the secret for (tenant_id, key).

        Raises KeyError if tenant or key is unknown.
        Never returns or logs plaintext; the returned SecretValue is the
        only way callers can access it via .expose().
        """
        ...
```

- [ ] **Step 4.4: Implement `YamlSecretStore`**

File: `src/wazuh_mcp/secrets/yaml_driver.py`

```python
"""YAML-backed SecretStore for development and single-operator deploys.

M4 ships production backends (AWS Secrets Manager, Vault, encrypted SQLite).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from wazuh_mcp.secrets.value import SecretValue


class YamlSecretStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        with path.open("r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Secrets file {path} must be a mapping")
        self._data: dict[str, dict[str, str]] = {}
        for tenant, kv in data.items():
            if not isinstance(kv, dict):
                raise ValueError(f"Tenant {tenant!r} must be a mapping")
            self._data[str(tenant)] = {str(k): str(v) for k, v in kv.items()}

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        if tenant_id not in self._data:
            raise KeyError(f"unknown tenant: {tenant_id}")
        tenant_secrets = self._data[tenant_id]
        if key not in tenant_secrets:
            raise KeyError(f"missing secret {key!r} for tenant {tenant_id!r}")
        return SecretValue(tenant_secrets[key])
```

- [ ] **Step 4.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_yaml_secret_store.py -v`
Expected: 4 passed.

- [ ] **Step 4.6: Commit**

```bash
git add src/wazuh_mcp/secrets/store.py src/wazuh_mcp/secrets/yaml_driver.py tests/unit/test_yaml_secret_store.py
git commit -m "Add SecretStore protocol and YAML driver"
```

---

### Task 5: TenantConfig model

**Purpose:** Strict-validated per-tenant configuration. Every field a later milestone adds (write_allowlist, rbac_role map, rate-limit overrides) extends this model, so nailing it here minimises later churn.

**Files:**
- Create: `src/wazuh_mcp/tenancy/__init__.py`
- Create: `src/wazuh_mcp/tenancy/config.py`
- Create: `tests/unit/test_tenant_config.py`

- [ ] **Step 5.1: Write the failing tests**

File: `tests/unit/test_tenant_config.py`

```python
import pytest
from pydantic import ValidationError

from wazuh_mcp.tenancy.config import TenantConfig


def test_valid_config():
    cfg = TenantConfig(
        tenant_id="acme",
        indexer_url="https://wazuh.acme.example:9200",
        verify_tls=True,
        ca_bundle_path=None,
        default_rbac_role="soc_analyst",
    )
    assert cfg.tenant_id == "acme"


def test_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
            extra_field="nope",
        )


def test_rejects_invalid_url():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme",
            indexer_url="not-a-url",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
        )


def test_tenant_id_charset():
    with pytest.raises(ValidationError):
        TenantConfig(
            tenant_id="acme/../etc",
            indexer_url="https://x:9200",
            verify_tls=True,
            ca_bundle_path=None,
            default_rbac_role="soc_analyst",
        )
```

- [ ] **Step 5.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_tenant_config.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.tenancy'`.

- [ ] **Step 5.3: Create empty `tenancy/__init__.py`**

File: `src/wazuh_mcp/tenancy/__init__.py` — empty.

- [ ] **Step 5.4: Implement `TenantConfig`**

File: `src/wazuh_mcp/tenancy/config.py`

```python
"""TenantConfig — per-tenant routing and trust configuration.

Strict Pydantic. Unknown fields rejected so config drift surfaces loudly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: Annotated[str, Field(pattern=TENANT_ID_PATTERN.pattern)]
    indexer_url: HttpUrl
    verify_tls: bool = True
    ca_bundle_path: Path | None = None
    default_rbac_role: str
```

- [ ] **Step 5.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_tenant_config.py -v`
Expected: 4 passed.

- [ ] **Step 5.6: Commit**

```bash
git add src/wazuh_mcp/tenancy/__init__.py src/wazuh_mcp/tenancy/config.py tests/unit/test_tenant_config.py
git commit -m "Add strict TenantConfig model"
```

---

### Task 6: TenantRegistry protocol and YAML driver

**Files:**
- Create: `src/wazuh_mcp/tenancy/registry.py`
- Create: `tests/unit/test_yaml_registry.py`

- [ ] **Step 6.1: Write the failing tests**

File: `tests/unit/test_yaml_registry.py`

```python
from pathlib import Path

import pytest

from wazuh_mcp.tenancy.registry import YamlTenantRegistry


@pytest.fixture
def tenants_file(tmp_path: Path) -> Path:
    p = tmp_path / "tenants.yaml"
    p.write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.example:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: beta
    indexer_url: https://wazuh.beta.example:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    return p


def test_registry_loads_multiple_tenants(tenants_file):
    reg = YamlTenantRegistry(tenants_file)
    acme = reg.get("acme")
    assert acme.tenant_id == "acme"
    assert str(acme.indexer_url).startswith("https://wazuh.acme.example")


def test_registry_unknown_tenant_raises(tenants_file):
    reg = YamlTenantRegistry(tenants_file)
    with pytest.raises(KeyError, match="ghost"):
        reg.get("ghost")


def test_registry_rejects_duplicate_tenant_ids(tmp_path):
    p = tmp_path / "dup.yaml"
    p.write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://a:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
  - tenant_id: acme
    indexer_url: https://b:9200
    verify_tls: true
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    with pytest.raises(ValueError, match="duplicate"):
        YamlTenantRegistry(p)
```

- [ ] **Step 6.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_yaml_registry.py -v`
Expected: `ImportError: cannot import name 'YamlTenantRegistry'`.

- [ ] **Step 6.3: Implement protocol + YAML driver**

File: `src/wazuh_mcp/tenancy/registry.py`

```python
"""TenantRegistry — resolves tenant_id → TenantConfig.

M1 ships YamlTenantRegistry. M4 adds a DB-backed driver.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import yaml

from wazuh_mcp.tenancy.config import TenantConfig


class TenantRegistry(Protocol):
    def get(self, tenant_id: str) -> TenantConfig:
        """Return the config for tenant_id. Raises KeyError if unknown."""
        ...


class YamlTenantRegistry:
    def __init__(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_tenants = data.get("tenants", [])
        if not isinstance(raw_tenants, list):
            raise ValueError(f"{path}: 'tenants' must be a list")

        self._tenants: dict[str, TenantConfig] = {}
        for entry in raw_tenants:
            cfg = TenantConfig.model_validate(entry)
            if cfg.tenant_id in self._tenants:
                raise ValueError(f"duplicate tenant_id: {cfg.tenant_id}")
            self._tenants[cfg.tenant_id] = cfg

    def get(self, tenant_id: str) -> TenantConfig:
        if tenant_id not in self._tenants:
            raise KeyError(f"unknown tenant: {tenant_id}")
        return self._tenants[tenant_id]
```

- [ ] **Step 6.4: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_yaml_registry.py -v`
Expected: 3 passed.

- [ ] **Step 6.5: Commit**

```bash
git add src/wazuh_mcp/tenancy/registry.py tests/unit/test_yaml_registry.py
git commit -m "Add TenantRegistry protocol and YAML driver"
```

---

### Task 7: Alert Pydantic model

**Purpose:** Strict-validated model of Wazuh alerts. Fields chosen from the default projection; handles the 4.8+ vulnerability field rename by being lenient on optional fields but strict on `extra` at the root.

**Files:**
- Create: `src/wazuh_mcp/wazuh/__init__.py`
- Create: `src/wazuh_mcp/wazuh/models.py`
- Create: `tests/unit/test_alert_model.py`

- [ ] **Step 7.1: Write the failing tests**

File: `tests/unit/test_alert_model.py`

```python
import pytest
from pydantic import ValidationError

from wazuh_mcp.wazuh.models import Alert


SAMPLE_HIT = {
    "_id": "alert-abc-123",
    "_source": {
        "timestamp": "2026-04-20T10:00:00.000+0000",
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
    },
}


def test_alert_from_hit_parses_required_fields():
    alert = Alert.from_hit(SAMPLE_HIT)
    assert alert.id == "alert-abc-123"
    assert alert.timestamp.startswith("2026-04-20")
    assert alert.agent.id == "001"
    assert alert.agent.name == "web-01"
    assert alert.rule.id == "5710"
    assert alert.rule.level == 5
    assert alert.rule.mitre_ids == ["T1110.001"]


def test_alert_missing_source_raises():
    with pytest.raises(ValidationError):
        Alert.from_hit({"_id": "x"})


def test_alert_missing_rule_raises():
    hit = {"_id": "x", "_source": {"timestamp": "2026-04-20T10:00:00.000+0000"}}
    with pytest.raises(ValidationError):
        Alert.from_hit(hit)


def test_alert_default_agent_when_absent():
    # Some manager-generated alerts have no agent section
    hit = {
        "_id": "mgr-1",
        "_source": {
            "timestamp": "2026-04-20T10:00:00.000+0000",
            "rule": {"id": "500", "level": 3, "description": "manager event"},
        },
    }
    alert = Alert.from_hit(hit)
    assert alert.agent.id is None
    assert alert.agent.name is None
```

- [ ] **Step 7.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_alert_model.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.wazuh'`.

- [ ] **Step 7.3: Create empty `wazuh/__init__.py`**

File: `src/wazuh_mcp/wazuh/__init__.py` — empty.

- [ ] **Step 7.4: Implement `Alert` model**

File: `src/wazuh_mcp/wazuh/models.py`

```python
"""Pydantic models for Wazuh documents.

Shape is version-tolerant: required invariants (id, timestamp, rule) are
strict; optional fields that drift between Wazuh versions are nullable.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class RuleRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    level: int
    description: str
    mitre_ids: list[str] = Field(default_factory=list)

    @classmethod
    def from_source(cls, rule: dict[str, Any]) -> "RuleRef":
        mitre = rule.get("mitre") or {}
        mitre_ids = list(mitre.get("id") or [])
        return cls(
            id=str(rule["id"]),
            level=int(rule["level"]),
            description=str(rule["description"]),
            mitre_ids=mitre_ids,
        )


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    timestamp: str
    agent: AgentRef
    rule: RuleRef
    location: str | None = None

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> "Alert":
        source = hit["_source"]
        return cls(
            id=str(hit["_id"]),
            timestamp=str(source["timestamp"]),
            agent=AgentRef.model_validate(source.get("agent") or {}),
            rule=RuleRef.from_source(source["rule"]),
            location=source.get("location"),
        )
```

- [ ] **Step 7.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_alert_model.py -v`
Expected: 4 passed.

- [ ] **Step 7.6: Commit**

```bash
git add src/wazuh_mcp/wazuh/__init__.py src/wazuh_mcp/wazuh/models.py tests/unit/test_alert_model.py
git commit -m "Add Alert/RuleRef/AgentRef Pydantic models"
```

---

### Task 8: Search-alerts query builder

**Purpose:** Build OpenSearch DSL server-side from structured input. This is the invariant that makes `hunt_query` (M3) safe: no tool accepts raw DSL, ever.

**Files:**
- Create: `src/wazuh_mcp/wazuh/query.py`
- Create: `tests/unit/test_query_builder.py`

- [ ] **Step 8.1: Write the failing tests**

File: `tests/unit/test_query_builder.py`

```python
import pytest

from wazuh_mcp.wazuh.query import (
    DEFAULT_ALERT_FIELDS,
    MAX_ALERT_SIZE,
    build_search_alerts_query,
)


def test_minimal_query_is_time_bounded():
    q = build_search_alerts_query(time_range="1h")
    ranges = [c for c in q["query"]["bool"]["must"] if "range" in c]
    assert ranges
    assert ranges[0]["range"]["@timestamp"]["gte"] == "now-1h"


def test_level_filter_applied():
    q = build_search_alerts_query(time_range="1h", min_level=12)
    must = q["query"]["bool"]["must"]
    level_clause = next(c for c in must if "range" in c and "rule.level" in c["range"])
    assert level_clause["range"]["rule.level"]["gte"] == 12


def test_agent_id_filter_applied():
    q = build_search_alerts_query(time_range="1h", agent_id="001")
    must = q["query"]["bool"]["must"]
    term = next(c for c in must if "term" in c)
    assert term["term"]["agent.id"] == "001"


def test_size_is_capped():
    q = build_search_alerts_query(time_range="1h", size=1_000_000)
    assert q["size"] == MAX_ALERT_SIZE


def test_size_default():
    q = build_search_alerts_query(time_range="1h")
    assert q["size"] == 25


def test_sort_desc_timestamp():
    q = build_search_alerts_query(time_range="1h")
    assert q["sort"] == [{"@timestamp": "desc"}]


def test_source_projection_default():
    q = build_search_alerts_query(time_range="1h")
    assert q["_source"] == DEFAULT_ALERT_FIELDS


def test_search_after_cursor_applied():
    q = build_search_alerts_query(
        time_range="1h", cursor=["2026-04-20T10:00:00.000Z"]
    )
    assert q["search_after"] == ["2026-04-20T10:00:00.000Z"]


def test_terminate_after_enforced():
    q = build_search_alerts_query(time_range="1h")
    assert q["terminate_after"] == 10_000


@pytest.mark.parametrize("bad", ["", "1", "1y", "30d", "now-1h", "foo"])
def test_invalid_time_range_rejected(bad):
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range=bad)


@pytest.mark.parametrize("good", ["1m", "15m", "1h", "6h", "24h", "7d", "1d"])
def test_accepted_time_ranges(good):
    build_search_alerts_query(time_range=good)


def test_level_must_be_in_range():
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range="1h", min_level=-1)
    with pytest.raises(ValueError):
        build_search_alerts_query(time_range="1h", min_level=16)
```

- [ ] **Step 8.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_query_builder.py -v`
Expected: `ImportError: cannot import name 'build_search_alerts_query'`.

- [ ] **Step 8.3: Implement query builder**

File: `src/wazuh_mcp/wazuh/query.py`

```python
"""OpenSearch DSL builders.

No tool accepts raw DSL. Builders take structured, validated inputs and
produce clamped/capped queries. This is the single-point enforcement of
size caps, time-range limits, and `terminate_after`.
"""

from __future__ import annotations

import re
from typing import Any, Final

MAX_ALERT_SIZE: Final[int] = 100
DEFAULT_ALERT_SIZE: Final[int] = 25
TERMINATE_AFTER: Final[int] = 10_000

DEFAULT_ALERT_FIELDS: Final[list[str]] = [
    "timestamp",
    "@timestamp",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "location",
    "decoder.name",
]

# Accept durations between 1 minute and 30 days (M1 lookback cap).
_TIME_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"^([1-9][0-9]*)([mhd])$")
_UNIT_SECONDS: Final[dict[str, int]] = {"m": 60, "h": 3600, "d": 86400}
_MAX_LOOKBACK_SECONDS: Final[int] = 30 * 86400


def _validate_time_range(tr: str) -> None:
    m = _TIME_RANGE_RE.match(tr)
    if not m:
        raise ValueError(
            f"time_range must match '<int><m|h|d>' (e.g., '1h', '24h', '7d'); got {tr!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    if n * _UNIT_SECONDS[unit] >= _MAX_LOOKBACK_SECONDS:
        raise ValueError(f"time_range exceeds 30-day lookback cap: {tr!r}")


def build_search_alerts_query(
    *,
    time_range: str,
    min_level: int | None = None,
    agent_id: str | None = None,
    size: int = DEFAULT_ALERT_SIZE,
    cursor: list[Any] | None = None,
) -> dict[str, Any]:
    _validate_time_range(time_range)
    if min_level is not None and not (0 <= min_level <= 15):
        raise ValueError("min_level must be 0..15")

    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}}
    ]
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_id is not None:
        must.append({"term": {"agent.id": agent_id}})

    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": min(max(1, size), MAX_ALERT_SIZE),
        "sort": [{"@timestamp": "desc"}],
        "_source": DEFAULT_ALERT_FIELDS,
        "terminate_after": TERMINATE_AFTER,
    }
    if cursor is not None:
        query["search_after"] = cursor
    return query
```

- [ ] **Step 8.4: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_query_builder.py -v`
Expected: all tests pass (≈20 parametrized cases).

- [ ] **Step 8.5: Commit**

```bash
git add src/wazuh_mcp/wazuh/query.py tests/unit/test_query_builder.py
git commit -m "Add search_alerts query builder with clamped size and time range"
```

---

### Task 9: Error mapper

**Purpose:** Translate upstream (httpx / OpenSearch / Wazuh) exceptions to a small set of safe error codes. No internal schema, mappings, or stack traces ever leave this boundary.

**Files:**
- Create: `src/wazuh_mcp/wazuh/errors.py`
- Create: `tests/unit/test_error_mapper.py`

- [ ] **Step 9.1: Write the failing tests**

File: `tests/unit/test_error_mapper.py`

```python
import httpx
import pytest

from wazuh_mcp.wazuh.errors import WazuhError, map_http_error


def _response(status: int, body: dict | str) -> httpx.Response:
    req = httpx.Request("GET", "https://example/9200/x/_search")
    return httpx.Response(status, json=body if isinstance(body, dict) else None,
                          text=body if isinstance(body, str) else None, request=req)


def test_401_maps_to_auth_expired():
    resp = _response(401, {"error": "token expired"})
    err = map_http_error(resp)
    assert isinstance(err, WazuhError)
    assert err.code == "auth_expired"


def test_403_maps_to_forbidden():
    resp = _response(403, {"error": "no permission"})
    err = map_http_error(resp)
    assert err.code == "forbidden"


def test_429_maps_to_rate_limited():
    resp = _response(429, {"error": "too many"})
    err = map_http_error(resp)
    assert err.code == "rate_limited"


def test_400_parse_error_maps_to_invalid_query_without_details():
    body = {
        "error": {
            "type": "parse_exception",
            "reason": "failed to parse at line 1: unknown field rule.badname",
            "stack_trace": "...deep internals...",
        }
    }
    resp = _response(400, body)
    err = map_http_error(resp)
    assert err.code == "invalid_query"
    # Internal details never surface:
    assert "stack_trace" not in err.message
    assert "...deep internals..." not in err.message
    assert "parse_exception" not in err.message


def test_5xx_maps_to_upstream_error():
    resp = _response(503, "<html>gateway</html>")
    err = map_http_error(resp)
    assert err.code == "upstream_error"


def test_error_repr_does_not_leak_body():
    resp = _response(500, {"error": {"reason": "secret internal message"}})
    err = map_http_error(resp)
    assert "secret internal message" not in repr(err)
    assert "secret internal message" not in str(err)


def test_unknown_status_is_upstream_error():
    resp = _response(418, {"error": "teapot"})
    err = map_http_error(resp)
    assert err.code == "upstream_error"


def test_safe_codes_enumerated():
    # A guard against accidental expansion of the safe-code set.
    from wazuh_mcp.wazuh.errors import SAFE_CODES

    assert SAFE_CODES == frozenset(
        {"auth_expired", "forbidden", "rate_limited", "invalid_query", "upstream_error"}
    )
```

- [ ] **Step 9.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_error_mapper.py -v`
Expected: `ImportError`.

- [ ] **Step 9.3: Implement error mapper**

File: `src/wazuh_mcp/wazuh/errors.py`

```python
"""Upstream error → safe code mapping.

Any upstream response body/stacktrace/schema data is discarded at this
boundary. MCP clients only ever see the codes in SAFE_CODES.
"""

from __future__ import annotations

from typing import Final

import httpx

SAFE_CODES: Final[frozenset[str]] = frozenset(
    {"auth_expired", "forbidden", "rate_limited", "invalid_query", "upstream_error"}
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
    if status == 429:
        return WazuhError("rate_limited", "upstream rate limit exceeded", status)
    if status == 400:
        # Swallow upstream detail entirely; surface only a generic message.
        return WazuhError("invalid_query", _INVALID_QUERY_GENERIC, status)
    return WazuhError("upstream_error", "upstream returned an error", status)
```

- [ ] **Step 9.4: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_error_mapper.py -v`
Expected: 8 passed.

- [ ] **Step 9.5: Commit**

```bash
git add src/wazuh_mcp/wazuh/errors.py tests/unit/test_error_mapper.py
git commit -m "Add error mapper producing only safe MCP-visible codes"
```

---

### Task 10: Wazuh indexer async client

**Purpose:** The only upstream HTTP client in M1. Wraps basic auth, TLS verification, query execution, and error mapping. All future tools (M2+) consume this.

**Files:**
- Create: `src/wazuh_mcp/wazuh/indexer.py`
- Create: `tests/unit/test_indexer_client.py`

- [ ] **Step 10.1: Write the failing tests**

File: `tests/unit/test_indexer_client.py`

```python
import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient

BASE = "https://wazuh.test:9200"


def _credentials() -> tuple[SecretValue, SecretValue]:
    return SecretValue("admin"), SecretValue("pw")


async def test_search_builds_auth_and_hits_expected_url(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        body = await client.search(
            index="wazuh-alerts-*", query={"query": {"match_all": {}}, "size": 1}
        )
    finally:
        await client.aclose()

    assert body["hits"]["total"]["value"] == 0
    req = httpx_mock.get_request()
    assert req is not None
    assert req.headers["Authorization"].startswith("Basic ")
    assert req.headers["Content-Type"] == "application/json"


async def test_search_401_raises_auth_expired(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=401,
        json={"error": "token"},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(WazuhError) as excinfo:
            await client.search(index="wazuh-alerts-*", query={})
    finally:
        await client.aclose()
    assert excinfo.value.code == "auth_expired"


async def test_search_400_raises_invalid_query_without_leaking(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=400,
        json={"error": {"reason": "INTERNAL DETAIL"}},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(WazuhError) as excinfo:
            await client.search(index="wazuh-alerts-*", query={})
    finally:
        await client.aclose()
    assert excinfo.value.code == "invalid_query"
    assert "INTERNAL DETAIL" not in str(excinfo.value)


async def test_aclose_is_idempotent():
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    await client.aclose()
    await client.aclose()  # must not raise
```

- [ ] **Step 10.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_indexer_client.py -v`
Expected: `ImportError: cannot import name 'IndexerClient'`.

- [ ] **Step 10.3: Implement indexer client**

File: `src/wazuh_mcp/wazuh/indexer.py`

```python
"""Async HTTPX client for the Wazuh Indexer (OpenSearch REST, port 9200).

Responsibilities in M1:
- Basic auth from SecretValue (never logged)
- TLS verification (with optional CA bundle)
- POST _search
- Map upstream errors to safe codes
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import map_http_error

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


class IndexerClient:
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
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            auth=(user.expose(), password.expose()),
            verify=verify,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        self._closed = False

    async def search(self, *, index: str, query: dict[str, Any]) -> dict[str, Any]:
        resp = await self._client.post(f"/{index}/_search", json=query)
        if resp.status_code >= 400:
            raise map_http_error(resp)
        return resp.json()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()
```

- [ ] **Step 10.4: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_indexer_client.py -v`
Expected: 4 passed.

- [ ] **Step 10.5: Commit**

```bash
git add src/wazuh_mcp/wazuh/indexer.py tests/unit/test_indexer_client.py
git commit -m "Add async Wazuh indexer client with basic auth and error mapping"
```

---

### Task 11: Audit emitter

**Purpose:** One structured-JSON event per tool call, printed to stdout in M1. Args are sha256-hashed, never raw. M4 swaps the sink for an async pluggable emitter.

**Files:**
- Create: `src/wazuh_mcp/observability/__init__.py`
- Create: `src/wazuh_mcp/observability/audit.py`
- Create: `tests/unit/test_audit.py`

- [ ] **Step 11.1: Write the failing tests**

File: `tests/unit/test_audit.py`

```python
import io
import json

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter


def _session() -> Session:
    return Session(user_id="alice", tenant_id="acme",
                   rbac_role="soc_analyst", auth_method="config")


def test_emits_one_json_line_per_call():
    buf = io.StringIO()
    emitter = AuditEmitter(stream=buf)
    emitter.emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h"},
        outcome="ok",
        result_count=24,
        duration_ms=142,
    )
    lines = buf.getvalue().strip().split("\n")
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["tool"] == "search_alerts"
    assert event["user"] == "alice"
    assert event["tenant"] == "acme"
    assert event["outcome"] == "ok"
    assert event["result_count"] == 24
    assert event["duration_ms"] == 142
    assert "timestamp" in event
    assert "arg_hash" in event


def test_args_are_hashed_not_raw():
    buf = io.StringIO()
    AuditEmitter(stream=buf).emit(
        session=_session(),
        tool="search_alerts",
        args={"time_range": "1h", "agent_id": "sensitive-host-name"},
        outcome="ok",
        result_count=0,
        duration_ms=10,
    )
    payload = buf.getvalue()
    assert "sensitive-host-name" not in payload
    # arg_hash is 64 hex chars (sha256)
    event = json.loads(payload)
    assert len(event["arg_hash"]) == 64


def test_hash_is_deterministic_across_key_order():
    buf1, buf2 = io.StringIO(), io.StringIO()
    for buf, args in (
        (buf1, {"time_range": "1h", "min_level": 12}),
        (buf2, {"min_level": 12, "time_range": "1h"}),
    ):
        AuditEmitter(stream=buf).emit(
            session=_session(),
            tool="search_alerts",
            args=args,
            outcome="ok",
            result_count=0,
            duration_ms=0,
        )
    h1 = json.loads(buf1.getvalue())["arg_hash"]
    h2 = json.loads(buf2.getvalue())["arg_hash"]
    assert h1 == h2


def test_error_outcome_captures_code():
    buf = io.StringIO()
    AuditEmitter(stream=buf).emit(
        session=_session(),
        tool="search_alerts",
        args={},
        outcome="error",
        result_count=0,
        duration_ms=7,
        error_code="rate_limited",
    )
    event = json.loads(buf.getvalue())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"
```

- [ ] **Step 11.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_audit.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.observability'`.

- [ ] **Step 11.3: Create empty `observability/__init__.py`**

File: `src/wazuh_mcp/observability/__init__.py` — empty.

- [ ] **Step 11.4: Implement `AuditEmitter`**

File: `src/wazuh_mcp/observability/audit.py`

```python
"""Audit emitter — one structured JSON event per tool call.

M1 writes JSON lines to a stream (stdout by default). M4 swaps this for
pluggable sinks (file, HTTP, back-to-Wazuh) with async delivery + bounded
disk ring-buffer.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import IO, Any

from wazuh_mcp.auth.session import Session


def _hash_args(args: dict[str, Any]) -> str:
    # sort_keys so ordering changes don't shift the hash.
    payload = json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditEmitter:
    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

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
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        self._stream.write(json.dumps(event) + "\n")
        self._stream.flush()
```

- [ ] **Step 11.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_audit.py -v`
Expected: 4 passed.

- [ ] **Step 11.6: Commit**

```bash
git add src/wazuh_mcp/observability/__init__.py src/wazuh_mcp/observability/audit.py tests/unit/test_audit.py
git commit -m "Add AuditEmitter with sha256-hashed args"
```

---

### Task 12: search_alerts tool handler

**Purpose:** Wires query builder → indexer client → alert model → structured MCP response. Audits on every exit path.

**Files:**
- Create: `src/wazuh_mcp/tools/__init__.py`
- Create: `src/wazuh_mcp/tools/alerts.py`
- Create: `tests/unit/test_search_alerts_tool.py`

- [ ] **Step 12.1: Write the failing tests**

File: `tests/unit/test_search_alerts_tool.py`

```python
import io
import json

import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.indexer import IndexerClient

BASE = "https://wazuh.test:9200"


def _session():
    return Session(user_id="alice", tenant_id="acme",
                   rbac_role="soc_analyst", auth_method="config")


def _client():
    return IndexerClient(
        base_url=BASE,
        user=SecretValue("admin"),
        password=SecretValue("pw"),
        verify_tls=False,
    )


def _hit(alert_id: str, level: int = 10):
    return {
        "_id": alert_id,
        "_source": {
            "timestamp": "2026-04-20T10:00:00.000+0000",
            "@timestamp": "2026-04-20T10:00:00.000Z",
            "agent": {"id": "001", "name": "web-01"},
            "rule": {"id": "5710", "level": level,
                     "description": "ssh brute-force"},
        },
        "sort": ["2026-04-20T10:00:00.000Z"],
    }


async def test_search_alerts_returns_structured_and_text(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 2},
                       "hits": [_hit("a1"), _hit("a2")]}},
    )
    buf = io.StringIO()
    emitter = AuditEmitter(stream=buf)
    client = _client()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h"),
            session=_session(),
            indexer=client,
            audit=emitter,
        )
    finally:
        await client.aclose()

    assert result["structuredContent"]["total"] == 2
    assert len(result["structuredContent"]["alerts"]) == 2
    assert result["structuredContent"]["next_cursor"] == ["2026-04-20T10:00:00.000Z"]
    assert "2 alert" in result["text"]

    event = json.loads(buf.getvalue().strip())
    assert event["tool"] == "search_alerts"
    assert event["result_count"] == 2
    assert event["outcome"] == "ok"


async def test_search_alerts_rejects_invalid_time_range():
    client = _client()
    try:
        with pytest.raises(ValueError):
            await search_alerts(
                args=SearchAlertsArgs(time_range="bogus"),
                session=_session(),
                indexer=client,
                audit=AuditEmitter(stream=io.StringIO()),
            )
    finally:
        await client.aclose()


async def test_search_alerts_audits_on_upstream_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=429,
        json={"error": "too many"},
    )
    buf = io.StringIO()
    client = _client()
    try:
        with pytest.raises(Exception):
            await search_alerts(
                args=SearchAlertsArgs(time_range="1h"),
                session=_session(),
                indexer=client,
                audit=AuditEmitter(stream=buf),
            )
    finally:
        await client.aclose()
    event = json.loads(buf.getvalue().strip())
    assert event["outcome"] == "error"
    assert event["error_code"] == "rate_limited"


async def test_search_alerts_truncated_when_hits_equal_size(httpx_mock: HTTPXMock):
    hits = [_hit(f"a{i}") for i in range(25)]
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 500}, "hits": hits}},
    )
    client = _client()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h"),
            session=_session(),
            indexer=client,
            audit=AuditEmitter(stream=io.StringIO()),
        )
    finally:
        await client.aclose()
    assert result["structuredContent"]["truncated"] is True
```

- [ ] **Step 12.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_search_alerts_tool.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.tools'`.

- [ ] **Step 12.3: Create empty `tools/__init__.py`**

File: `src/wazuh_mcp/tools/__init__.py` — empty.

- [ ] **Step 12.4: Implement `search_alerts`**

File: `src/wazuh_mcp/tools/alerts.py`

```python
"""search_alerts tool — M1's only tool.

Establishes the pattern every M3 tool follows:
  1. Validate args (strict Pydantic).
  2. Resolve session (caller supplies it; session is session-pinned).
  3. Build server-side DSL.
  4. Call indexer.
  5. Map hits → strict Pydantic models.
  6. Emit structuredContent + short text summary.
  7. Audit every exit path.
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

    time_range: Annotated[str, Field(description="Relative lookback, e.g. '1h', '24h', '7d'")] = "1h"
    min_level: Annotated[int | None, Field(ge=0, le=15, description="Minimum rule.level")] = None
    agent_id: Annotated[str | None, Field(description="Filter to a single agent.id")] = None
    size: Annotated[int, Field(ge=1, le=100, description="Max alerts to return (hard cap 100)")] = 25
    cursor: Annotated[list[Any] | None, Field(description="Opaque search_after cursor from prior call")] = None


def _summarise(alerts: list[Alert], total: int) -> str:
    if not alerts:
        return f"0 alerts matched (total in range: {total})."
    top = {}
    for a in alerts:
        top[a.rule.description] = top.get(a.rule.description, 0) + 1
    top_sorted = sorted(top.items(), key=lambda kv: kv[1], reverse=True)[:3]
    top_str = "; ".join(f"{desc} ({n})" for desc, n in top_sorted)
    return f"{len(alerts)} alert(s) returned (total: {total}). Top rules: {top_str}."


async def search_alerts(
    *,
    args: SearchAlertsArgs,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
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
            session=session, tool="search_alerts", args=arg_dict, outcome="error",
            result_count=0, duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise
    except ValueError:
        audit.emit(
            session=session, tool="search_alerts", args=arg_dict, outcome="error",
            result_count=0, duration_ms=int((time.monotonic() - started) * 1000),
            error_code="invalid_query",
        )
        raise

    raw_hits = body.get("hits", {}).get("hits", [])
    total = body.get("hits", {}).get("total", {}).get("value", 0)
    alerts = [Alert.from_hit(h) for h in raw_hits]
    next_cursor: list[Any] | None = None
    if raw_hits and "sort" in raw_hits[-1]:
        next_cursor = raw_hits[-1]["sort"]
    truncated = len(alerts) == args.size

    audit.emit(
        session=session, tool="search_alerts", args=arg_dict, outcome="ok",
        result_count=len(alerts),
        duration_ms=int((time.monotonic() - started) * 1000),
    )

    return {
        "structuredContent": {
            "alerts": [a.model_dump() for a in alerts],
            "total": total,
            "next_cursor": next_cursor,
            "truncated": truncated,
        },
        "text": _summarise(alerts, total),
    }
```

- [ ] **Step 12.5: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_search_alerts_tool.py -v`
Expected: 4 passed.

- [ ] **Step 12.6: Commit**

```bash
git add src/wazuh_mcp/tools/__init__.py src/wazuh_mcp/tools/alerts.py tests/unit/test_search_alerts_tool.py
git commit -m "Add search_alerts tool handler"
```

---

### Task 13: Server wiring and stdio transport

**Purpose:** Bring up an MCP server over stdio that registers `search_alerts` and serves a single session against the configured tenant. This is the first moment the stack is "alive."

**Files:**
- Create: `src/wazuh_mcp/server.py`
- Create: `src/wazuh_mcp/__main__.py`
- Create: `tests/unit/test_server_wiring.py`

- [ ] **Step 13.1: Write the failing test**

File: `tests/unit/test_server_wiring.py`

```python
from pathlib import Path

import pytest

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


def test_load_config_builds_session_and_config(config_dir):
    cfg = load_config(config_dir)
    assert cfg.session.tenant_id == "acme"
    assert cfg.session.user_id == "alice"
    assert cfg.session.auth_method == "config"
    assert cfg.tenant.tenant_id == "acme"


def test_build_app_registers_search_alerts(config_dir):
    cfg = load_config(config_dir)
    app = build_app(cfg)
    # FastMCP exposes list_tools via the underlying server object
    tool_names = {t.name for t in app._tool_manager.list_tools()}
    assert "search_alerts" in tool_names
```

Note: the private-attribute access `app._tool_manager.list_tools()` tracks the official `mcp` SDK's FastMCP tool-registry layout as of spec 2025-06-18. If the SDK surfaces a public accessor, prefer that.

- [ ] **Step 13.2: Run tests — expect failure**

Run: `uv run pytest tests/unit/test_server_wiring.py -v`
Expected: `ModuleNotFoundError: No module named 'wazuh_mcp.server'`.

- [ ] **Step 13.3: Implement `server.py`**

File: `src/wazuh_mcp/server.py`

```python
"""MCP server wiring.

M1: stdio only, single session loaded from config at startup.
M2 replaces `load_config` with an OAuth/API-key entry that yields a
Session per client connection.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore
from wazuh_mcp.tenancy.config import TenantConfig
from wazuh_mcp.tenancy.registry import YamlTenantRegistry
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.indexer import IndexerClient


@dataclass(frozen=True)
class AppConfig:
    session: Session
    tenant: TenantConfig
    secrets: YamlSecretStore


def load_config(config_dir: Path) -> AppConfig:
    server_cfg = yaml.safe_load((config_dir / "server.yaml").read_text()) or {}
    registry = YamlTenantRegistry(config_dir / "tenants.yaml")
    secrets = YamlSecretStore(config_dir / "secrets.yaml")

    tenant_id = server_cfg["active_tenant"]
    user_id = server_cfg.get("user_id", "local")
    tenant = registry.get(tenant_id)
    session = Session(
        user_id=user_id,
        tenant_id=tenant_id,
        rbac_role=tenant.default_rbac_role,
        auth_method="config",
    )
    return AppConfig(session=session, tenant=tenant, secrets=secrets)


def build_app(cfg: AppConfig, audit: AuditEmitter | None = None) -> FastMCP:
    audit_emitter = audit or AuditEmitter()
    app = FastMCP(name="wazuh-mcp", version="0.1.0")

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
        indexer = await _open_indexer()
        try:
            return await search_alerts(
                args=args, session=cfg.session, indexer=indexer, audit=audit_emitter,
            )
        finally:
            await indexer.aclose()

    return app


def run_stdio(config_dir: Path) -> None:
    cfg = load_config(config_dir)
    app = build_app(cfg)
    asyncio.run(app.run_stdio_async())
```

- [ ] **Step 13.4: Run tests — expect pass**

Run: `uv run pytest tests/unit/test_server_wiring.py -v`
Expected: 2 passed.

- [ ] **Step 13.5: Implement `__main__.py`**

File: `src/wazuh_mcp/__main__.py`

```python
"""CLI entry point: `python -m wazuh_mcp` or `wazuh-mcp`.

Reads config directory from $WAZUH_MCP_CONFIG_DIR, defaulting to ./config.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from wazuh_mcp.server import run_stdio


def main() -> int:
    config_dir = Path(os.environ.get("WAZUH_MCP_CONFIG_DIR", "./config")).resolve()
    if not config_dir.is_dir():
        print(f"Config directory not found: {config_dir}", file=sys.stderr)
        return 2
    run_stdio(config_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 13.6: Commit**

```bash
git add src/wazuh_mcp/server.py src/wazuh_mcp/__main__.py tests/unit/test_server_wiring.py
git commit -m "Wire FastMCP stdio server with search_alerts tool"
```

---

### Task 14: Integration-test docker-compose Wazuh fixture

**Purpose:** Spin up a single-node Wazuh (manager + indexer) with seeded alerts. Used by the M1 integration test and inherited by every later milestone.

**Files:**
- Create: `docker/integration-compose.yml`
- Create: `docker/seed_alerts.py`
- Create: `docker/README.md`

- [ ] **Step 14.1: Create `docker/integration-compose.yml`**

File: `docker/integration-compose.yml`

```yaml
# Single-node Wazuh stack for integration tests.
# Pinned versions — bump intentionally.
services:
  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.9.0
    hostname: wazuh-indexer
    environment:
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
      - bootstrap.memory_lock=true
      - DISABLE_INSTALL_DEMO_CONFIG=false
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile: { soft: 65536, hard: 65536 }
    ports:
      - "9200:9200"
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health | grep -q status"]
      interval: 5s
      timeout: 3s
      retries: 40

  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    hostname: wazuh-manager
    depends_on:
      wazuh-indexer:
        condition: service_healthy
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - FILEBEAT_SSL_VERIFICATION_MODE=none
    ports:
      - "55000:55000"
```

- [ ] **Step 14.2: Create the seed script**

File: `docker/seed_alerts.py`

```python
"""Seed the Wazuh indexer with synthetic alerts for integration tests.

Assumes the docker-compose stack is healthy on localhost:9200 with the
default admin credentials.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

BASE = "https://localhost:9200"
AUTH = ("admin", "SecretPassword")
INDEX = f"wazuh-alerts-4.x-{datetime.now(timezone.utc):%Y.%m.%d}"


def _alert(idx: int, level: int, offset_min: int) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(minutes=offset_min)
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {
            "id": str(5700 + idx),
            "level": level,
            "description": f"synthetic rule {idx}",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]}
            if level >= 10 else {},
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
    }


def main() -> int:
    client = httpx.Client(auth=AUTH, verify=False, timeout=30)
    docs = []
    for i in range(20):
        lvl = 12 if i % 4 == 0 else 3
        docs.append(_alert(i, lvl, offset_min=i))
    # Bulk index
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
    # Refresh so docs are searchable immediately
    client.post(f"{BASE}/{INDEX}/_refresh").raise_for_status()
    print(f"Seeded {len(docs)} alerts into {INDEX}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 14.3: Create `docker/README.md`**

File: `docker/README.md`

```markdown
# Integration fixtures

## Start the stack

    docker compose -f docker/integration-compose.yml up -d
    # wait for wazuh-indexer to pass healthcheck (~60-120s on first boot)

## Seed synthetic alerts

    uv run python docker/seed_alerts.py

## Tear down

    docker compose -f docker/integration-compose.yml down -v
```

- [ ] **Step 14.4: Bring the stack up locally once to confirm it works**

Run: `docker compose -f docker/integration-compose.yml up -d`
Expected: two containers start. Run `docker compose -f docker/integration-compose.yml ps` and confirm both are `healthy` / `running`.

- [ ] **Step 14.5: Run the seed script**

Run: `uv run python docker/seed_alerts.py`
Expected: `Seeded 20 alerts into wazuh-alerts-4.x-YYYY.MM.DD`.

- [ ] **Step 14.6: Tear down**

Run: `docker compose -f docker/integration-compose.yml down -v`

- [ ] **Step 14.7: Commit**

```bash
git add docker/
git commit -m "Add integration-test docker-compose Wazuh fixture and seed script"
```

---

### Task 15: End-to-end integration test

**Purpose:** Prove `search_alerts` works against real Wazuh. This test runs only when `@integration` is requested (not in the default fast unit run).

**Files:**
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_search_alerts_e2e.py`

- [ ] **Step 15.1: Write `tests/integration/conftest.py`**

File: `tests/integration/conftest.py`

```python
"""Fixtures for integration tests.

Assumes docker/integration-compose.yml is running and seeded.
"""

from __future__ import annotations

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.indexer import IndexerClient


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="integration",
        tenant_id="local",
        rbac_role="soc_analyst",
        auth_method="config",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def indexer():
    client = IndexerClient(
        base_url="https://localhost:9200",
        user=SecretValue("admin"),
        password=SecretValue("SecretPassword"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()
```

- [ ] **Step 15.2: Write the integration test**

File: `tests/integration/test_search_alerts_e2e.py`

```python
"""End-to-end integration test for search_alerts.

Prerequisites:
  docker compose -f docker/integration-compose.yml up -d
  # wait for healthcheck
  uv run python docker/seed_alerts.py

Run:
  uv run pytest -m integration -v
"""

from __future__ import annotations

import pytest

from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts


@pytest.mark.integration
async def test_search_alerts_returns_seeded_data(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="1h"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result["structuredContent"]["total"] >= 20
    assert len(result["structuredContent"]["alerts"]) >= 1
    assert result["structuredContent"]["next_cursor"] is not None


@pytest.mark.integration
async def test_search_alerts_min_level_filters(session, audit, indexer):
    result = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", min_level=12),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    for alert in result["structuredContent"]["alerts"]:
        assert alert["rule"]["level"] >= 12


@pytest.mark.integration
async def test_search_alerts_cursor_paginates(session, audit, indexer):
    first = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", size=5),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    cursor = first["structuredContent"]["next_cursor"]
    assert cursor is not None

    second = await search_alerts(
        args=SearchAlertsArgs(time_range="1h", size=5, cursor=cursor),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    first_ids = {a["id"] for a in first["structuredContent"]["alerts"]}
    second_ids = {a["id"] for a in second["structuredContent"]["alerts"]}
    assert first_ids.isdisjoint(second_ids), "pagination returned overlapping alerts"
```

- [ ] **Step 15.3: Bring up the stack and seed**

Run:
```bash
docker compose -f docker/integration-compose.yml up -d
# wait ~60-120s for healthcheck
until docker compose -f docker/integration-compose.yml ps | grep -q 'healthy'; do sleep 3; done
uv run python docker/seed_alerts.py
```
Expected: `Seeded 20 alerts into ...`.

- [ ] **Step 15.4: Run the integration tests**

Run: `uv run pytest -m integration -v`
Expected: 3 passed.

- [ ] **Step 15.5: Tear down**

Run: `docker compose -f docker/integration-compose.yml down -v`

- [ ] **Step 15.6: Commit**

```bash
git add tests/integration/
git commit -m "Add end-to-end integration tests for search_alerts"
```

---

### Task 16: README with M1 quickstart

**Files:**
- Create: `README.md`

- [ ] **Step 16.1: Write `README.md`**

File: `README.md`

```markdown
# wazuh-mcp

Model Context Protocol server for Wazuh SIEM/XDR.

**Status:** M1 (walking skeleton). Single tenant, single tool (`search_alerts`),
stdio transport. See `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md`
for the full v1 design and `docs/superpowers/plans/` for the milestone
roadmap.

## Requirements

- Python 3.12+
- `uv` — https://docs.astral.sh/uv/
- A Wazuh Indexer endpoint (for integration tests: Docker + Docker Compose)

## Install

    uv sync

## Configure

Create a `config/` directory with three files:

**`config/tenants.yaml`**

    tenants:
      - tenant_id: local
        indexer_url: https://localhost:9200
        verify_tls: false
        ca_bundle_path: null
        default_rbac_role: soc_analyst

**`config/secrets.yaml`**

    local:
      indexer_user: admin
      indexer_password: SecretPassword

**`config/server.yaml`**

    active_tenant: local
    user_id: alice

## Run

    WAZUH_MCP_CONFIG_DIR=./config uv run wazuh-mcp

The server speaks MCP over stdio. Add it to Claude Desktop's config:

    {
      "mcpServers": {
        "wazuh": {
          "command": "uv",
          "args": ["run", "--project", "/abs/path/to/wazuh-mcp", "wazuh-mcp"],
          "env": { "WAZUH_MCP_CONFIG_DIR": "/abs/path/to/wazuh-mcp/config" }
        }
      }
    }

## Develop

Unit tests (fast, no network):

    uv run pytest

Lint + format:

    uv run ruff check .
    uv run ruff format .

Integration tests (docker compose required):

    docker compose -f docker/integration-compose.yml up -d
    # wait for wazuh-indexer healthcheck
    uv run python docker/seed_alerts.py
    uv run pytest -m integration
    docker compose -f docker/integration-compose.yml down -v

## M1 scope

One tool, `search_alerts`, with filters: `time_range` (required, `1m` to `30d`), `min_level`, `agent_id`, `size` (hard-capped at 100), `cursor` for pagination. Results include `structuredContent` (alerts, total, next_cursor, truncated) and a short text summary.

## Roadmap

See `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md` §9.
```

- [ ] **Step 16.2: Commit**

```bash
git add README.md
git commit -m "Add README with M1 quickstart"
```

---

### Task 17: CI workflow (lint + unit tests)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 17.1: Write `.github/workflows/ci.yml`**

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
      - name: Unit tests
        run: uv run pytest -m "not integration" -v
```

- [ ] **Step 17.2: Verify ruff is clean locally before committing**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: no findings.

If there are findings, run `uv run ruff check --fix . && uv run ruff format .` and re-commit the relevant files as part of this task, not as a separate "style cleanup" task.

- [ ] **Step 17.3: Verify full unit test suite passes**

Run: `uv run pytest -m "not integration" -v`
Expected: all tests pass across every `tests/unit/` file written so far (≈50+ cases).

- [ ] **Step 17.4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "Add CI workflow for lint and unit tests"
```

---

### Task 18: Manual smoke test via Claude Desktop

**Purpose:** Prove the stdio transport actually works with an MCP client. No code, just verification — but it's the only way to catch MCP-protocol-level bugs that pytest won't surface.

- [ ] **Step 18.1: Bring up Wazuh + seed**

Run:
```bash
docker compose -f docker/integration-compose.yml up -d
until docker compose -f docker/integration-compose.yml ps | grep -q 'healthy'; do sleep 3; done
uv run python docker/seed_alerts.py
```

- [ ] **Step 18.2: Create `config/` matching the seeded stack**

Create `config/tenants.yaml`, `config/secrets.yaml`, `config/server.yaml` as in the README quickstart (tenant_id: `local`, `admin` / `SecretPassword`, `https://localhost:9200`, `verify_tls: false`).

- [ ] **Step 18.3: Add server entry to Claude Desktop config**

On macOS: edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "uv",
      "args": ["run", "--project", "/abs/path/to/wazuh-mcp", "wazuh-mcp"],
      "env": { "WAZUH_MCP_CONFIG_DIR": "/abs/path/to/wazuh-mcp/config" }
    }
  }
}
```

Restart Claude Desktop.

- [ ] **Step 18.4: Smoke-test queries**

In a new Claude conversation, verify:

1. `search_alerts` appears in the tools list (click the MCP indicator).
2. Prompt: "Show me critical alerts from the last hour."
   → Expected: Claude calls `search_alerts` with `time_range="1h"` and `min_level >= 10` or similar. Returns ≥ 5 alerts with level ≥ 12.
3. Prompt: "Show me the next page."
   → Expected: Claude calls `search_alerts` again, passing the `cursor` from the prior response. Returns a disjoint set of alerts.
4. Prompt: "Look for alerts about SSH."
   → Expected: Claude calls `search_alerts` with a time range. (This tests description copy — Claude should pick `search_alerts` and not ask for a missing tool.)

- [ ] **Step 18.5: Tear down**

Run: `docker compose -f docker/integration-compose.yml down -v`

- [ ] **Step 18.6: If any smoke test fails**, file it as a follow-up task (not fixed in this plan). M1 ships only if steps 18.4.1 and 18.4.2 pass; 18.4.3 and 18.4.4 are nice-to-have.

- [ ] **Step 18.7: Commit any small fixes that arose** (e.g., description tweaks, argument renames). Commit message: `Tighten search_alerts description based on smoke test`.

---

### Task 19: Tag M1

**Purpose:** Mark the walking skeleton as shipped so M2 branches from a known-good baseline.

- [ ] **Step 19.1: Verify everything is green**

Run:
```bash
uv run ruff check . && uv run ruff format --check .
uv run pytest -m "not integration" -v
```
Expected: clean + all tests pass.

- [ ] **Step 19.2: Verify integration tests are green** (with the stack up)

Run:
```bash
docker compose -f docker/integration-compose.yml up -d
until docker compose -f docker/integration-compose.yml ps | grep -q 'healthy'; do sleep 3; done
uv run python docker/seed_alerts.py
uv run pytest -m integration -v
docker compose -f docker/integration-compose.yml down -v
```
Expected: all integration tests pass.

- [ ] **Step 19.3: Tag the commit**

Run:
```bash
git tag -a v0.1.0-m1 -m "M1: walking skeleton (stdio, 1 tenant, search_alerts)"
git log --oneline -1
```

- [ ] **Step 19.4: Push** (if a remote is configured; otherwise skip)

```bash
git push && git push --tags
```

---

## Self-Review

**Spec coverage (against `docs/superpowers/specs/2026-04-20-wazuh-mcp-design.md`):**
- §2 Decisions — MSSP / hybrid / phased / OAuth+API-key / Python / pluggable secrets / triage+hunt scope → M1 implements the Python + pluggable (YAML driver) + one triage tool slice; OAuth, Streamable HTTP, AWS SM/Vault drivers, additional tools deferred to M2-M5 per the plan header. ✅
- §3 Architecture — Session, Tool layer, Wazuh client factory, SecretStore, TenantRegistry all present. Task 2, 3, 4, 5, 6, 10, 13. ✅
- §4 Components — `auth/`, `secrets/`, `tenancy/`, `wazuh/`, `tools/`, `observability/`, `server.py` all created in M1 with the protocols and shapes the spec mandates (even where only one driver ships). ✅
- §5 Data flow — Task 12 (`search_alerts`) + Task 13 (`server.py`) exercise the full flow: session → tenant router (trivial in M1, single tenant) → secret fetch → indexer call → model → structuredContent+text → audit. ✅
- §6 Security — `SecretValue` with property-test redaction (Task 3); error scrubbing (Task 9); `extra='forbid'` everywhere user input crosses (Task 5, 12); no raw DSL accepted, server-built queries only (Task 8); TLS configurable with CA bundle (Task 10). What M1 explicitly defers: OAuth 2.1 (M2), per-tenant rate limits (M4), RBAC-aware list_tools (M4), audit sink pluggability (M4), secret-leak scanner in CI (M5). These are called out in the plan header. ✅
- §7 Testing — Unit layer present for every module. Integration layer present with docker-compose Wazuh + seed + three e2e tests. MCP-level evals and full security negative tests deferred to M5 per header. ✅
- §8 Scale/deployment — stdio only in M1. Streamable HTTP, OTel, Prometheus metrics, healthz/readyz, distroless image deferred (M2/M4). Called out in header. ✅
- §9 Roadmap — M1 sets up plumbing (protocols, boundaries) that M2-M5 fill in. v2 write-scaffolding-but-disabled is M4 scope. ✅
- §11 Wazuh gotchas — Time-range clamping (Task 8), `terminate_after` + size cap (Task 8), TLS with explicit CA bundle / no silent `verify=False` (Task 10 — note: M1 does allow `verify_tls=false` but only via explicit config, and the README/docker fixture use it honestly). JWT expiry is Server-API-specific and doesn't apply to M1 (indexer uses basic auth). Daily index rollover handled via `wazuh-alerts-*` pattern in Task 12. ✅

**Placeholder scan:** No TBD / TODO / "implement later" / "similar to Task N". Every code block is complete. Every command has expected output. ✅

**Type consistency:**
- `SearchAlertsArgs` fields (`time_range`, `min_level`, `agent_id`, `size`, `cursor`) match between Task 12 definition and Task 13 tool signature. ✅
- `build_search_alerts_query` keyword params (`time_range`, `min_level`, `agent_id`, `size`, `cursor`) match between Task 8 definition and Task 12 caller. ✅
- `IndexerClient(base_url, user, password, verify_tls, ca_bundle_path, timeout)` consistent between Task 10 definition, Task 12 tests, Task 13 `_open_indexer`, and Task 15 conftest. ✅
- `AuditEmitter.emit(session, tool, args, outcome, result_count, duration_ms, error_code)` consistent between Task 11 definition and Task 12 callers. ✅
- `Session(user_id, tenant_id, rbac_role, auth_method)` consistent across tasks 2, 11, 12, 13, 15. ✅
- `TenantConfig` fields (`tenant_id`, `indexer_url`, `verify_tls`, `ca_bundle_path`, `default_rbac_role`) consistent across tasks 5, 6, 13. ✅
- `SecretValue.expose()` called consistently (task 3 definition, task 10 consumer). ✅
- `WazuhError(code, message, status_code)` consistent (task 9 definition, task 10 caller, task 12 caller). ✅

No issues found. Plan is ready.
