"""wazuh://rules/{id} - Server API-backed rule reference."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_RULE_ID_RE = re.compile(r"^[0-9]{1,12}$")


async def read_rule(
    *,
    rule_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _RULE_ID_RE.match(rule_id):
        raise ValueError("invalid rule_id")

    try:
        body = await server_api.get(
            "/rules",
            params={"rule_ids": rule_id},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.rules",
            args={"rule_id": rule_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="resource.rules",
            args={"rule_id": rule_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "rule not found", 404)

    audit.emit(
        session=session,
        tool="resource.rules",
        args={"rule_id": rule_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(items[0], ttl_seconds=300)
