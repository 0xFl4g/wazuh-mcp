"""wazuh://mitre/technique/{id} - Server API-backed MITRE technique reference."""

from __future__ import annotations

import re
from typing import Any

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.resources import make_json_content
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient

_TECHNIQUE_ID_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


async def read_mitre_technique(
    *,
    technique_id: str,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> dict[str, Any]:
    if not _TECHNIQUE_ID_RE.match(technique_id):
        raise ValueError("invalid technique_id")

    try:
        # Wazuh stores both an internal ``id`` (UUID) and ``external_id``
        # (the human ATT&CK identifier ``T1110.001``). Query by external_id
        # — ``q=id=T1110`` matches no rows.
        body = await server_api.get(
            "/mitre/techniques",
            params={"q": f"external_id={technique_id}"},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="resource.mitre",
            args={"technique_id": technique_id},
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
            tool="resource.mitre",
            args={"technique_id": technique_id},
            outcome="error",
            result_count=0,
            duration_ms=0,
            error_code="not_found",
        )
        raise WazuhError("not_found", "technique not found", 404)

    audit.emit(
        session=session,
        tool="resource.mitre",
        args={"technique_id": technique_id},
        outcome="ok",
        result_count=1,
        duration_ms=0,
    )
    return make_json_content(items[0], ttl_seconds=86_400)
