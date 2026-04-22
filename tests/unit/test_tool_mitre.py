"""Unit tests for mitre.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.mitre import (
    GetMitreTechniqueArgs,
    SearchMitreArgs,
    get_mitre_technique,
    search_mitre,
)
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64
    import json
    import time as _t

    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    pl = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{hdr}.{pl}.sig"


@pytest.fixture
def session() -> Session:
    return Session(
        user_id="u",
        tenant_id="t",
        rbac_role="soc_analyst",
        auth_method="oauth",
    )


@pytest.fixture
def audit() -> AuditEmitter:
    return AuditEmitter(stream=io.StringIO())


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
        is_optional=True,
    )
    client = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("wazuh-wui"),
        password=SecretValue("x"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_get_mitre_technique_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=id%3DT1110.001",
        method="GET",
        json={
            "data": {
                "affected_items": [
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "tactics": ["Credential Access"],
                    }
                ]
            }
        },
    )
    result = await get_mitre_technique(
        args=GetMitreTechniqueArgs(technique_id="T1110.001"),
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result.technique.id == "T1110.001"


@pytest.mark.asyncio
async def test_get_mitre_technique_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await get_mitre_technique(
            args=GetMitreTechniqueArgs(technique_id="not-a-technique"),
            session=session,
            server_api=server_api,
            audit=audit,
        )


@pytest.mark.asyncio
async def test_get_mitre_technique_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=id%3DT9999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await get_mitre_technique(
            args=GetMitreTechniqueArgs(technique_id="T9999"),
            session=session,
            server_api=server_api,
            audit=audit,
        )
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_search_mitre_requires_a_filter(session, audit, server_api):
    with pytest.raises(ValueError):
        await search_mitre(
            args=SearchMitreArgs(),
            session=session,
            server_api=server_api,
            audit=audit,
        )
