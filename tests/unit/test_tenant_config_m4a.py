"""TenantConfig extensions for M4a: secret_prefix, role_tool_allowlist,
rate_limit, audit_sinks."""
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


def test_new_fields_all_optional() -> None:
    cfg = TenantConfig(**_base_kwargs())
    assert cfg.secret_prefix is None
    assert cfg.role_tool_allowlist is None
    assert cfg.rate_limit.tenant.capacity == 250
    assert cfg.rate_limit.tenant.refill_per_sec == 4.17
    assert cfg.rate_limit.session.capacity == 60
    assert cfg.rate_limit.session.refill_per_sec == 1.0
    assert cfg.audit_sinks == []


def test_secret_prefix_accepts_str() -> None:
    cfg = TenantConfig(**_base_kwargs(), secret_prefix="wazuh-mcp/")
    assert cfg.secret_prefix == "wazuh-mcp/"


def test_role_tool_allowlist() -> None:
    cfg = TenantConfig(
        **_base_kwargs(),
        role_tool_allowlist={"custom": ["alerts.*", "hunt.hunt_query"]},
    )
    assert cfg.role_tool_allowlist == {"custom": ["alerts.*", "hunt.hunt_query"]}


def test_rate_limit_override() -> None:
    cfg = TenantConfig(
        **_base_kwargs(),
        rate_limit={
            "tenant": {"capacity": 500, "refill_per_sec": 8.33},
            "session": {"capacity": 120, "refill_per_sec": 2.0},
        },
    )
    assert cfg.rate_limit.tenant.capacity == 500
    assert cfg.rate_limit.session.refill_per_sec == 2.0


def test_audit_sinks_discriminated_union() -> None:
    cfg = TenantConfig(
        **_base_kwargs(),
        audit_sinks=[
            {"kind": "stderr"},
            {"kind": "file", "path": "/var/log/wazuh-mcp/audit.log"},
            {"kind": "http", "url": "https://siem.example/ingest"},
            {"kind": "wazuh_indexer", "index_prefix": "wazuh-mcp-audit"},
        ],
    )
    assert [s.kind for s in cfg.audit_sinks] == ["stderr", "file", "http", "wazuh_indexer"]


def test_audit_sink_unknown_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        TenantConfig(**_base_kwargs(), audit_sinks=[{"kind": "syslog"}])


def test_bucket_capacity_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        TenantConfig(
            **_base_kwargs(),
            rate_limit={"tenant": {"capacity": 0, "refill_per_sec": 1.0}},
        )


def test_frozen_still_enforced() -> None:
    cfg = TenantConfig(**_base_kwargs(), secret_prefix="x/")
    with pytest.raises(ValidationError):
        cfg.__setattr__("secret_prefix", "y/")
