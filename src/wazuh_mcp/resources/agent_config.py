"""wazuh://agents/{id}/config - Server API-backed agent config snapshot."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_AGENT_ID_RE = re.compile(r"^[0-9]{3,10}$")


async def read_agent_config(
    *,
    agent_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError("invalid agent_id")

    try:
        body = await server_api.get(
            f"/agents/{agent_id}/config/client/client",
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.agent_config",
            args={"agent_id": agent_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    if not data:
        audit.emit(
            session=session,
            tool="resource.agent_config",
            args={"agent_id": agent_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "agent config not found", 404)

    audit.emit(
        session=session,
        tool="resource.agent_config",
        args={"agent_id": agent_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(data, ttl_seconds=300)
