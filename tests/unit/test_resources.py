"""Unit tests for MCP resources."""

import io
import json

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.observability.sinks.stream import StderrSink
from wazuh_mcp.resources import TEMPLATES, make_json_content
from wazuh_mcp.resources.agent_config import read_agent_config
from wazuh_mcp.resources.mitre import read_mitre_technique
from wazuh_mcp.resources.rules import read_rule
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt() -> str:
    import base64 as _b
    import json as _j
    import time as _t

    h = _b.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    p = (
        _b.urlsafe_b64encode(
            _j.dumps({"exp": int(_t.time()) + 900, "iat": int(_t.time())}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{h}.{p}.sig"


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
    return AuditEmitter(global_sinks=[StderrSink(stream=io.StringIO())])


@pytest.fixture
async def server_api(httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
        is_optional=True,
    )
    c = ServerApiClient(
        base_url="https://manager.example:55000",
        user=SecretValue("u"),
        password=SecretValue("p"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


def test_templates_list_has_three_entries():
    ids = {t.uri_template for t in TEMPLATES}
    assert ids == {
        "wazuh://rules/{id}",
        "wazuh://mitre/technique/{id}",
        "wazuh://agents/{id}/config",
    }


def test_make_json_content_has_ttl_meta():
    payload = make_json_content({"x": 1}, ttl_seconds=300)
    assert payload["_meta"]["ttl_seconds"] == 300
    assert json.loads(payload["contents"][0]["text"]) == {"x": 1}
    assert payload["contents"][0]["mimeType"] == "application/json"


@pytest.mark.asyncio
async def test_read_rule_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/rules?rule_ids=5700",
        method="GET",
        json={"data": {"affected_items": [{"id": 5700, "description": "ssh brute force"}]}},
    )
    result = await read_rule(rule_id="5700", session=session, server_api=server_api, audit=audit)
    assert result["_meta"]["ttl_seconds"] == 300
    body = json.loads(result["contents"][0]["text"])
    assert body["id"] == 5700


@pytest.mark.asyncio
async def test_read_rule_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await read_rule(rule_id="abc", session=session, server_api=server_api, audit=audit)


@pytest.mark.asyncio
async def test_read_rule_not_found(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/rules?rule_ids=9999",
        method="GET",
        json={"data": {"affected_items": []}},
    )
    with pytest.raises(WazuhError) as exc_info:
        await read_rule(rule_id="9999", session=session, server_api=server_api, audit=audit)
    assert exc_info.value.code == "not_found"


@pytest.mark.asyncio
async def test_read_mitre_technique_happy(session, audit, server_api, httpx_mock):
    httpx_mock.add_response(
        url="https://manager.example:55000/mitre/techniques?q=external_id%3DT1110.001",
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
    result = await read_mitre_technique(
        technique_id="T1110.001",
        session=session,
        server_api=server_api,
        audit=audit,
    )
    assert result["_meta"]["ttl_seconds"] == 86_400


@pytest.mark.asyncio
async def test_read_agent_config_rejects_bad_id(session, audit, server_api):
    with pytest.raises(ValueError):
        await read_agent_config(agent_id="xx", session=session, server_api=server_api, audit=audit)
