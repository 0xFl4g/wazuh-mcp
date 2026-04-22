"""Smoke test: all expected tools, resources, prompts register via _register_everything."""

from __future__ import annotations

import io

from mcp.server.fastmcp import FastMCP

from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.server import _register_everything


class _StubPool:
    """Minimal async pool stub - acquire returns a sentinel."""

    def __init__(self) -> None:
        self._client = object()

    async def acquire(self, tenant_id: str):
        return self._client


def test_every_m3_tool_is_registered() -> None:
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(stream=io.StringIO())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
    )
    tools = mcp_app._tool_manager.list_tools()
    names = {t.name for t in tools}
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
    missing = expected - names
    assert not missing, f"missing tool registrations: {missing}"


def test_every_m3_resource_template_is_registered() -> None:
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(stream=io.StringIO())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
    )
    templates = mcp_app._resource_manager.list_templates()
    uris = {t.uri_template for t in templates}
    expected = {
        "wazuh://rules/{rule_id}",
        "wazuh://mitre/technique/{technique_id}",
        "wazuh://agents/{agent_id}/config",
    }
    missing = expected - uris
    assert not missing, f"missing resource templates: {missing}"


def test_every_m3_prompt_is_registered() -> None:
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(stream=io.StringIO())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
    )
    prompts = mcp_app._prompt_manager.list_prompts()
    names = {p.name for p in prompts}
    expected = {"triage_last_hour", "investigate_alert", "agent_posture"}
    missing = expected - names
    assert not missing, f"missing prompts: {missing}"


def test_all_tools_carry_toolset_meta() -> None:
    mcp_app = FastMCP(name="test")
    audit = AuditEmitter(stream=io.StringIO())
    _register_everything(
        mcp_app,
        indexer_pool=_StubPool(),
        server_api_pool=_StubPool(),
        audit_emitter=audit,
    )
    for tool in mcp_app._tool_manager.list_tools():
        meta = getattr(tool, "meta", None) or {}
        assert "toolset" in meta, f"tool {tool.name} is missing meta['toolset']"
