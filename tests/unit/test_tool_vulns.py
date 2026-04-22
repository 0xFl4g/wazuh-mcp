"""Unit tests for vulnerabilities.* tools."""

import io

import pytest

from wazuh_mcp.auth.session import Session
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.tools.vulns import (
    ListVulnerabilitiesByAgentArgs,
    SearchVulnerabilitiesArgs,
    list_vulnerabilities_by_agent,
    search_vulnerabilities,
)
from wazuh_mcp.wazuh.indexer import IndexerClient


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
async def indexer(httpx_mock):
    client = IndexerClient(
        base_url="https://indexer.example",
        user=SecretValue("admin"),
        password=SecretValue("admin"),
        verify_tls=False,
    )
    try:
        yield client
    finally:
        await client.aclose()


def _vuln_hit(cve: str, severity: str = "High", score: float = 7.5) -> dict:
    return {
        "_source": {
            "agent": {"id": "001"},
            "package": {"name": "openssl", "version": "3.0.0"},
            "vulnerability": {
                "id": cve,
                "severity": severity,
                "scores": {"base": {"score": score}},
                "detected_at": "2026-04-22T00:00:00Z",
                "status": "Active",
            },
        },
        "sort": [1],
    }


@pytest.mark.asyncio
async def test_list_vulns_by_agent_happy(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-states-vulnerabilities-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [_vuln_hit("CVE-2024-1234")],
            }
        },
    )
    result = await list_vulnerabilities_by_agent(
        args=ListVulnerabilitiesByAgentArgs(agent_id="001", min_severity="High"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.total == 1
    assert result.vulnerabilities[0].id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_search_vulns_requires_a_filter(session, audit, indexer):
    with pytest.raises(ValueError):
        await search_vulnerabilities(
            args=SearchVulnerabilitiesArgs(),
            session=session,
            indexer=indexer,
            audit=audit,
        )


@pytest.mark.asyncio
async def test_search_vulns_by_cve(session, audit, indexer, httpx_mock):
    httpx_mock.add_response(
        url="https://indexer.example/wazuh-states-vulnerabilities-*/_search",
        method="POST",
        json={
            "hits": {
                "total": {"value": 1},
                "hits": [_vuln_hit("CVE-2023-9999", severity="Critical", score=9.8)],
            }
        },
    )
    result = await search_vulnerabilities(
        args=SearchVulnerabilitiesArgs(cve_id="CVE-2023-9999"),
        session=session,
        indexer=indexer,
        audit=audit,
    )
    assert result.vulnerabilities[0].id == "CVE-2023-9999"
    assert result.vulnerabilities[0].severity == "Critical"
