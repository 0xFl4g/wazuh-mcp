"""Prompt: /wazuh:investigate-alert {alert_id}

Fetches the alert, its agent, and last-hour neighbors on the same agent.
Returns a user-role message with all context pre-loaded.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.agents import GetAgentArgs, get_agent
from wazuh_mcp.tools.alerts import (
    AlertsByAgentArgs,
    GetAlertArgs,
    alerts_by_agent,
    get_alert,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient
from wazuh_mcp.wazuh.server_api import ServerApiClient


async def handle(
    *,
    alert_id: str,
    session: Session,
    indexer: IndexerClient,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()
    audit.emit(
        session=session,
        tool="prompt.investigate_alert",
        args={"alert_id": alert_id},
        outcome="ok",
        result_count=0,
        duration_ms=0,
    )

    try:
        alert_res = await get_alert(
            args=GetAlertArgs(alert_id=alert_id),
            session=session,
            indexer=indexer,
            audit=audit,
        )
    except WazuhError as e:
        if e.code == "not_found":
            return make_user_message(
                f"Alert {alert_id!r} not found. Ask the user for a valid alert id."
            )
        raise

    alert = alert_res.alert
    agent_id = alert.agent.id

    agent_block = "(agent lookup unavailable)"
    if agent_id:
        try:
            agent_res = await get_agent(
                args=GetAgentArgs(agent_id=agent_id),
                session=session,
                server_api=server_api,
                audit=audit,
            )
            agent_block = json.dumps(agent_res.agent.model_dump(), indent=2)
        except WazuhError:
            pass

    neighbors_block = "(no neighbors)"
    if agent_id:
        try:
            neighbors = await alerts_by_agent(
                args=AlertsByAgentArgs(agent_id=agent_id, time_range="1h", size=10),
                session=session,
                indexer=indexer,
                audit=audit,
            )
            neighbors_block = json.dumps([a.model_dump() for a in neighbors.alerts], indent=2)
        except WazuhError:
            pass

    duration = int((time.monotonic() - started) * 1000)
    text = (
        f"Investigating Wazuh alert {alert_id}.\n"
        f"\n"
        f"ALERT:\n{json.dumps(alert.model_dump(), indent=2)}\n"
        f"\n"
        f"AGENT:\n{agent_block}\n"
        f"\n"
        f"NEIGHBORS (last hour, same agent):\n{neighbors_block}\n"
        f"\n"
        f"Based on the above: summarise the alert, note any notable neighbor "
        f"patterns, and recommend the next SOC actions. Use the other "
        f"wazuh-mcp tools if you need more context."
    )
    audit.emit(
        session=session,
        tool="prompt.investigate_alert",
        args={"alert_id": alert_id},
        outcome="ok",
        result_count=1,
        duration_ms=duration,
    )
    return make_user_message(text)
