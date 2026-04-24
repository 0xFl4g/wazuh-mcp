"""Role -> tool-allowlist policy.

Ships three default roles. Per-tenant overrides replace the global
default for that role. Unknown role in the effective allowlist is
treated as deny-all at match time (see rbac/filter.py).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

_DEFAULTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "admin": ("*",),
        "analyst": (
            "alerts.*",
            "agents.*",
            "vulnerabilities.*",
            "mitre.*",
            "hunt.*",
            "fim.*",
        ),
        "readonly": (
            "alerts.*",
            "agents.get_agent",
            "agents.list_agents",
            "vulnerabilities.*",
            "mitre.*",
            "fim.*",
        ),
    }
)


def _to_mutable(src: Mapping[str, tuple[str, ...]]) -> dict[str, list[str]]:
    return {role: list(pats) for role, pats in src.items()}


# Exposed as a dict of lists for config-friendliness. Callers treat as read-only.
DEFAULT_ROLE_TOOL_ALLOWLIST: dict[str, list[str]] = _to_mutable(_DEFAULTS)


def effective_allowlist_for(
    *,
    tenant_override: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    """Return the effective per-role allowlist for a tenant.

    Tenant override replaces the global default per role. Absent roles
    fall through to the global default. Overrides can also introduce
    custom role names the operator needs.
    """
    result = _to_mutable(_DEFAULTS)
    if tenant_override:
        for role, patterns in tenant_override.items():
            result[role] = list(patterns)
    return result
