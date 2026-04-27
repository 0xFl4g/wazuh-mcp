"""ServerApiClient cluster + restart wire-shape pinning (M4c T10)."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.server_api import ServerApiClient


def _jwt(exp_offset_s: int = 900) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_s, "sub": "mcp"}).encode()
    ).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


@pytest_asyncio.fixture
async def client(httpx_mock) -> AsyncIterator[ServerApiClient]:
    httpx_mock.add_response(
        url="https://wazuh.example:55000/security/user/authenticate",
        method="POST",
        json={"data": {"token": _jwt()}},
    )
    c = ServerApiClient(
        base_url="https://wazuh.example:55000",
        user=SecretValue("wazuh"),
        password=SecretValue("pass"),
        verify_tls=False,
    )
    try:
        yield c
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_restart_cluster_scope_cluster_puts_to_cluster_restart(client, httpx_mock) -> None:
    httpx_mock.add_response(
        method="PUT",
        url="https://wazuh.example:55000/cluster/restart",
        json={"data": {"affected_items": ["master"]}, "message": "Restart request sent"},
    )
    resp = await client.restart_cluster(scope="cluster")
    assert resp["data"]["affected_items"] == ["master"]


@pytest.mark.asyncio
async def test_restart_cluster_scope_node_puts_to_manager_restart(client, httpx_mock) -> None:
    httpx_mock.add_response(
        method="PUT",
        url="https://wazuh.example:55000/manager/restart",
        json={"data": {"affected_items": ["master"]}, "message": "Restart request sent"},
    )
    resp = await client.restart_cluster(scope="node")
    assert resp["data"]["affected_items"] == ["master"]


@pytest.mark.asyncio
async def test_cluster_status_reads_status_and_nodes(client, httpx_mock) -> None:
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example:55000/cluster/status",
        json={"data": {"enabled": "yes", "running": "yes"}},
    )
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example:55000/cluster/nodes",
        json={
            "data": {
                "affected_items": [
                    {"name": "node-master", "type": "master", "status": "running"},
                    {"name": "node-worker-1", "type": "worker", "status": "running"},
                ],
                "total_affected_items": 2,
            }
        },
    )
    status = await client.cluster_status()
    assert status["enabled"] is True
    assert status["running"] is True
    assert len(status["nodes"]) == 2
    assert status["nodes"][0]["name"] == "node-master"


@pytest.mark.asyncio
async def test_cluster_status_returns_disabled_when_clustering_off(client, httpx_mock) -> None:
    """When `/cluster/status` reports enabled=no, skip the /cluster/nodes call
    and return enabled=False with empty nodes."""
    httpx_mock.add_response(
        method="GET",
        url="https://wazuh.example:55000/cluster/status",
        json={"data": {"enabled": "no", "running": "no"}},
    )
    status = await client.cluster_status()
    assert status["enabled"] is False
    assert status["running"] is False
    assert status["nodes"] == []
