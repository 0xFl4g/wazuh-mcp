"""Prompt: /wazuh:agent-posture {agent_id}

Composes agent details + last-24h alerts + vulnerability count for the
agent.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.agents import GetAgentArgs, get_agent
from wazuh_mcp.tools.alerts import AlertsByAgentArgs, alerts_by_agent
from wazuh_mcp.tools.vulns import (
    ListVulnerabilitiesByAgentArgs,
    list_vulnerabilities_by_agent,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


async def handle(
    *,
    agent_id: str,
    session: Session,
    indexer: IndexerClient,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()

    try:
        agent_res = await get_agent(
            args=GetAgentArgs(agent_id=agent_id),
            session=session,
            server_api=server_api,
        )
    except WazuhError as e:
        if e.code == "not_found":
            return make_user_message(
                f"Agent {agent_id!r} not found. Ask the user for a valid agent id."
            )
        raise

    agent_block = json.dumps(agent_res.agent.model_dump(), indent=2)

    alerts_block = "(alerts unavailable)"
    try:
        alerts = await alerts_by_agent(
            args=AlertsByAgentArgs(agent_id=agent_id, time_range="24h", size=25),
            session=session,
            indexer=indexer,
        )
        alerts_block = (
            f"total_in_range={alerts.total}, showing={len(alerts.alerts)}:\n"
            + json.dumps([a.model_dump() for a in alerts.alerts], indent=2)
        )
    except WazuhError:
        pass

    vuln_block = "(vulns unavailable)"
    try:
        vulns = await list_vulnerabilities_by_agent(
            args=ListVulnerabilitiesByAgentArgs(agent_id=agent_id, size=25),
            session=session,
            indexer=indexer,
        )
        vuln_block = f"total={vulns.total}, showing={len(vulns.vulnerabilities)}:\n" + json.dumps(
            [v.model_dump() for v in vulns.vulnerabilities], indent=2
        )
    except WazuhError:
        pass

    text = (
        f"Agent posture for {agent_id}.\n"
        f"\n"
        f"AGENT:\n{agent_block}\n"
        f"\n"
        f"LAST-24H ALERTS:\n{alerts_block}\n"
        f"\n"
        f"VULNERABILITIES:\n{vuln_block}\n"
        f"\n"
        f"Summarise the security posture: recent alert patterns, unpatched "
        f"critical vulns, and any immediate follow-ups the SOC should take."
    )

    duration = int((time.monotonic() - started) * 1000)
    audit.emit(
        session=session,
        tool="prompt.agent_posture",
        args={"agent_id": agent_id},
        outcome="ok",
        result_count=1,
        duration_ms=duration,
    )
    return make_user_message(text)
