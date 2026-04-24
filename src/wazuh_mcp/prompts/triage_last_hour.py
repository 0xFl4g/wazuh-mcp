"""Prompt: /wazuh:triage-last-hour

Runs search_alerts(time_range=1h, min_level=10, size=25) and returns
the results as pre-loaded context for a triage summary.
"""

from __future__ import annotations

import json
import time
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.prompts import make_user_message
from wazuh_mcp.tools.alerts import SearchAlertsArgs, search_alerts
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient


async def handle(
    *,
    session: Session,
    indexer: IndexerClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = await search_alerts(
            args=SearchAlertsArgs(time_range="1h", min_level=10, size=25),
            session=session,
            indexer=indexer,
        )
    except WazuhError as e:
        return make_user_message(f"Triage fetch failed ({e.code}). Retry or check upstream.")

    alerts_json = json.dumps([a.model_dump() for a in result.alerts], indent=2)
    text = (
        f"Triaging the last hour (min rule level 10).\n"
        f"\n"
        f"TOTAL IN RANGE: {result.total} (showing {len(result.alerts)}).\n"
        f"\n"
        f"ALERTS:\n{alerts_json}\n"
        f"\n"
        f"Summarise: (a) how many unique rules fired, (b) top agents by "
        f"count, (c) any ATT&CK clustering, (d) which alerts warrant a "
        f"deeper investigation. Use get_alert or alerts_by_agent for "
        f"any you flag."
    )

    duration = int((time.monotonic() - started) * 1000)
    audit.emit(
        session=session,
        tool="prompt.triage_last_hour",
        args={},
        outcome="ok",
        result_count=len(result.alerts),
        duration_ms=duration,
    )
    return make_user_message(text)
