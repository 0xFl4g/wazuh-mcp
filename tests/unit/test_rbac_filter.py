"""RBAC matcher: prefix (`alerts.*`) + exact (`hunt.hunt_query`)."""

from __future__ import annotations

from wazuh_mcp.auth.session import Session
from wazuh_mcp.rbac.filter import is_allowed, tool_matches


def _session(role: str) -> Session:
    return Session(
        user_id="u1",
        tenant_id="t1",
        rbac_role=role,
        auth_method="config",
    )


def test_exact_match() -> None:
    assert tool_matches("hunt.hunt_query", ["hunt.hunt_query"]) is True
    assert tool_matches("hunt.pivot_by_ioc", ["hunt.hunt_query"]) is False


def test_prefix_match_requires_dot() -> None:
    assert tool_matches("alerts.search_alerts", ["alerts.*"]) is True
    assert tool_matches("alertsfoo.x", ["alerts.*"]) is False  # no dot — not a prefix match
    assert tool_matches("alerts", ["alerts.*"]) is False  # wildcard requires suffix


def test_wildcard_star_matches_any() -> None:
    assert tool_matches("anything.goes_here", ["*"]) is True


def test_empty_allowlist_denies_all() -> None:
    assert tool_matches("alerts.search_alerts", []) is False


def test_is_allowed_admin() -> None:
    assert is_allowed(_session("admin"), "hunt.hunt_query", {"admin": ["*"]}) is True


def test_is_allowed_unknown_role_denies() -> None:
    assert is_allowed(_session("intern"), "alerts.search_alerts", {"admin": ["*"]}) is False


def test_is_allowed_allowed_by_prefix() -> None:
    allowlist = {"analyst": ["alerts.*", "hunt.hunt_query"]}
    s = _session("analyst")
    assert is_allowed(s, "alerts.search_alerts", allowlist) is True
    assert is_allowed(s, "hunt.hunt_query", allowlist) is True
    assert is_allowed(s, "hunt.pivot_by_ioc", allowlist) is False


def test_is_allowed_empty_role_denies() -> None:
    assert is_allowed(_session("analyst"), "alerts.search_alerts", {"analyst": []}) is False
