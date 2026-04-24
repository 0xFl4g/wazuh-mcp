"""RBAC policy: global defaults + per-tenant override merge."""
from __future__ import annotations

from wazuh_mcp.rbac.policy import (
    DEFAULT_ROLE_TOOL_ALLOWLIST,
    effective_allowlist_for,
)


def test_defaults_expose_three_roles() -> None:
    assert set(DEFAULT_ROLE_TOOL_ALLOWLIST) == {"admin", "analyst", "readonly"}


def test_admin_is_wildcard() -> None:
    assert DEFAULT_ROLE_TOOL_ALLOWLIST["admin"] == ["*"]


def test_analyst_covers_every_m3_domain() -> None:
    pats = DEFAULT_ROLE_TOOL_ALLOWLIST["analyst"]
    assert {"alerts.*", "agents.*", "vulnerabilities.*", "mitre.*", "hunt.*", "fim.*"} <= set(pats)


def test_readonly_excludes_hunt() -> None:
    pats = DEFAULT_ROLE_TOOL_ALLOWLIST["readonly"]
    assert "hunt.*" not in pats
    assert "alerts.*" in pats


def test_effective_returns_default_when_no_override() -> None:
    result = effective_allowlist_for(tenant_override=None)
    assert result == DEFAULT_ROLE_TOOL_ALLOWLIST


def test_override_replaces_per_role() -> None:
    override = {"analyst": ["alerts.search_alerts"]}
    result = effective_allowlist_for(tenant_override=override)
    assert result["analyst"] == ["alerts.search_alerts"]
    assert result["admin"] == ["*"]   # unchanged
    assert result["readonly"] == DEFAULT_ROLE_TOOL_ALLOWLIST["readonly"]


def test_override_can_add_custom_role() -> None:
    override = {"auditor": ["alerts.*", "hunt.hunt_query"]}
    result = effective_allowlist_for(tenant_override=override)
    assert result["auditor"] == ["alerts.*", "hunt.hunt_query"]
    assert result["admin"] == ["*"]


def test_override_empty_list_denies_role() -> None:
    result = effective_allowlist_for(tenant_override={"analyst": []})
    assert result["analyst"] == []


def test_returned_mapping_is_copy_not_alias() -> None:
    result = effective_allowlist_for(tenant_override=None)
    result["admin"] = ["mutated"]
    # Calling again returns the pristine default, not the mutation.
    again = effective_allowlist_for(tenant_override=None)
    assert again["admin"] == ["*"]
