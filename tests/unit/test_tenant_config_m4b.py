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
    with pytest.raises(ValidationError, match=r"write\.bogus"):
        TenantConfig(**_base_kwargs(), write_allowlist=["write.bogus"])


def test_write_allowlist_rejects_non_write_namespace() -> None:
    with pytest.raises(ValidationError, match=r"must be under write\.\*"):
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
