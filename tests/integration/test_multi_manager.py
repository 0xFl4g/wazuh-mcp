"""M5b T-C1: multi-manager federation tests.

Asserts per-tenant routing into distinct Wazuh clusters. tenant `local`
points at cluster 1 (manager:55000, indexer:9200) which docker/seed_alerts.py
seeds with agent 001. tenant `tenant_b` points at cluster 2 (manager:55001,
indexer:9201) which has NO seeded agent. Both tests pin the routing:

* tenant_a sees agent 001 (proves routing succeeded into cluster 1)
* tenant_b does NOT see agent 001 (proves no cross-cluster leakage)

Requires the multi-manager docker overlay; gated behind the
`multi_manager` pytest marker so the daily integration job skips it
and the weekly multi-manager-integration.yml workflow picks it up.
"""

from __future__ import annotations

import httpx as _httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

pytestmark = [
    pytest.mark.integration,
    pytest.mark.multi_manager,
    pytest.mark.requires_manager,
]


async def _list_agent_ids(url: str, token: str) -> set[str]:
    http_client = _httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_httpx.Timeout(30.0),
    )
    try:
        async with (
            streamable_http_client(f"{url}/mcp", http_client=http_client) as (
                read,
                write,
                _gsid,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool("agents.list_agents", {"size": 50})
            assert not result.isError, f"agents.list_agents errored: {result}"
            payload = result.structuredContent
            assert payload is not None, "agents.list_agents returned no structuredContent"
            return {a.get("id") for a in payload.get("agents", []) if a.get("id")}
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_tenant_a_session_only_hits_manager_1(
    mcp_http_server_multi_manager,
    keycloak_token,
):
    """tenant `local` (cluster 1) must see agent 001 (seeded by bootstrap.sh)."""
    agent_ids = await _list_agent_ids(mcp_http_server_multi_manager, keycloak_token())
    assert "001" in agent_ids, (
        f"expected agent 001 on cluster 1 (tenant local); got: {sorted(agent_ids)}"
    )


@pytest.mark.asyncio
async def test_tenant_b_session_only_hits_manager_2(
    mcp_http_server_multi_manager,
    keycloak_token_tenant_b,
):
    """tenant_b (cluster 2) must NOT see agent 001 — proves no cross-cluster leak."""
    agent_ids = await _list_agent_ids(mcp_http_server_multi_manager, keycloak_token_tenant_b())
    assert "001" not in agent_ids, (
        f"cross-tenant leak: agent 001 (cluster 1) appeared in tenant_b call; got: {sorted(agent_ids)}"
    )
