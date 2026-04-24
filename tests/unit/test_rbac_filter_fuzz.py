"""Hypothesis fuzz: the matcher never allows a tool outside its allowlist."""
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from wazuh_mcp.rbac.filter import tool_matches

_tool_domain = st.sampled_from(["alerts", "agents", "hunt", "fim", "mitre", "vulnerabilities"])
_tool_leaf = st.sampled_from([
    "search_alerts", "get_alert", "list_agents", "get_agent", "hunt_query",
    "pivot_by_ioc", "get_fim_state", "get_technique",
])
_tool_name = st.builds(lambda d, leaf: f"{d}.{leaf}", _tool_domain, _tool_leaf)

# allowlist patterns drawn from the same universe plus `*` and obvious distractors
_pattern = st.one_of(
    st.just("*"),
    st.builds(lambda d: f"{d}.*", _tool_domain),
    _tool_name,
    # Distractors that must NOT match on substring luck:
    st.sampled_from(["", "alertsfoo.x", "hunt", "alerts", "agents_hidden", "alerts.*x"]),
)
_allowlist = st.lists(_pattern, max_size=10)


@given(tool=_tool_name, allowlist=_allowlist)
def test_match_iff_explicit_allow(tool: str, allowlist: list[str]) -> None:
    allowed = tool_matches(tool, allowlist)
    # Reconstruct expectation from the matcher's semantics:
    # 1. any "*" allows everything
    # 2. exact tool name allows
    # 3. "<domain>.*" allows iff tool starts with "<domain>."
    # Distractors never allow.
    def _expected() -> bool:
        for p in allowlist:
            if p == "*":
                return True
            if p == tool:
                return True
            if p.endswith(".*"):
                prefix = p[:-2]   # drop ".*"
                if tool.startswith(prefix + "."):
                    return True
        return False
    assert allowed == _expected()


@given(tool=_tool_name)
def test_empty_allowlist_always_denies(tool: str) -> None:
    assert tool_matches(tool, []) is False
