"""mitre.* tools — MITRE ATT&CK technique reference, sourced from the
Wazuh Server API's bundled dataset.
"""

from __future__ import annotations

import re
import time
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.models import MitreTechnique
from wazuh_mcp.wazuh.server_api import ServerApiClient

_TECHNIQUE_ID_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


class GetMitreTechniqueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: Annotated[str, Field(min_length=4, max_length=16)]


class MitreTechniqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique: MitreTechnique


class SearchMitreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: Annotated[
        str | None,
        Field(description="Substring to match against technique name/description"),
    ] = None
    tactic: Annotated[str | None, Field(max_length=64)] = None
    size: Annotated[int, Field(ge=1, le=200)] = 50


class MitreSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    techniques: list[MitreTechnique]
    total: int
    truncated: bool


async def get_mitre_technique(
    *,
    args: GetMitreTechniqueArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> MitreTechniqueResult:
    """Tool name: mitre.get_mitre_technique."""
    if not _TECHNIQUE_ID_RE.match(args.technique_id):
        raise ValueError("invalid technique_id")

    started = time.monotonic()
    arg_dict = args.model_dump()
    try:
        body = await server_api.get(
            "/mitre/techniques",
            params={"q": f"id={args.technique_id}"},
            run_as=session.wazuh_user,
        )
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="mitre.get_mitre_technique",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    items = (body.get("data") or {}).get("affected_items") or []
    if not items:
        audit.emit(
            session=session,
            tool="mitre.get_mitre_technique",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code="not_found",
        )
        raise WazuhError("not_found", "technique not found", 404)

    tech = MitreTechnique.from_api(items[0])
    audit.emit(
        session=session,
        tool="mitre.get_mitre_technique",
        args=arg_dict,
        outcome="ok",
        result_count=1,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return MitreTechniqueResult(technique=tech)


async def search_mitre(
    *,
    args: SearchMitreArgs,
    session: Session,
    server_api: ServerApiClient,
    audit: AuditEmitter,
) -> MitreSearchResult:
    """Tool name: mitre.search_mitre."""
    if args.q is None and args.tactic is None:
        raise ValueError("at least one of q or tactic must be set")

    started = time.monotonic()
    arg_dict = args.model_dump(exclude_none=True)
    qclauses: list[str] = []
    if args.q:
        qclauses.append(f"name~{args.q}")
    if args.tactic:
        qclauses.append(f"tactics~{args.tactic}")
    params = {"q": ",".join(qclauses), "limit": args.size}

    try:
        body = await server_api.get("/mitre/techniques", params=params, run_as=session.wazuh_user)
    except WazuhError as e:
        audit.emit(
            session=session,
            tool="mitre.search_mitre",
            args=arg_dict,
            outcome="error",
            result_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=e.code,
        )
        raise

    data = body.get("data") or {}
    items = list(data.get("affected_items") or [])
    total = int(data.get("total_affected_items") or len(items))
    techs = [MitreTechnique.from_api(i) for i in items]

    audit.emit(
        session=session,
        tool="mitre.search_mitre",
        args=arg_dict,
        outcome="ok",
        result_count=len(techs),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return MitreSearchResult(
        techniques=techs,
        total=total,
        truncated=len(techs) == args.size,
    )
