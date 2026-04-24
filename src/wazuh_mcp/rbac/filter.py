"""RBAC match + is_allowed check.

Pattern language: `*` allows every tool, `<domain>.*` allows any tool
in that dotted domain, exact names match exactly. No regex. No case
folding.
"""

from __future__ import annotations

from wazuh_mcp.auth.session import Session


def tool_matches(tool_name: str, allowlist: list[str]) -> bool:
    for pattern in allowlist:
        if pattern == "*":
            return True
        if pattern == tool_name:
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]  # drop ".*" suffix
            if tool_name.startswith(prefix + "."):
                return True
    return False


def is_allowed(
    session: Session,
    tool_name: str,
    effective_allowlist: dict[str, list[str]],
) -> bool:
    """True iff session.rbac_role is in effective_allowlist AND
    tool_name matches one of its patterns."""
    patterns = effective_allowlist.get(session.rbac_role)
    if patterns is None:
        return False
    return tool_matches(tool_name, patterns)
