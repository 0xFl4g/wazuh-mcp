import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.wazuh.errors import WazuhError
from wazuh_mcp.wazuh.indexer import IndexerClient

BASE = "https://wazuh.test:9200"


def _credentials() -> tuple[SecretValue, SecretValue]:
    return SecretValue("admin"), SecretValue("pw")


async def test_search_builds_auth_and_hits_expected_url(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        body = await client.search(
            index="wazuh-alerts-*", query={"query": {"match_all": {}}, "size": 1}
        )
    finally:
        await client.aclose()

    assert body["hits"]["total"]["value"] == 0
    req = httpx_mock.get_request()
    assert req is not None
    assert req.headers["Authorization"].startswith("Basic ")
    assert req.headers["Content-Type"] == "application/json"


async def test_search_401_raises_auth_expired(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=401,
        json={"error": "token"},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(WazuhError) as excinfo:
            await client.search(index="wazuh-alerts-*", query={})
    finally:
        await client.aclose()
    assert excinfo.value.code == "auth_expired"


async def test_search_400_raises_invalid_query_without_leaking(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE}/wazuh-alerts-*/_search",
        method="POST",
        status_code=400,
        json={"error": {"reason": "INTERNAL DETAIL"}},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(WazuhError) as excinfo:
            await client.search(index="wazuh-alerts-*", query={})
    finally:
        await client.aclose()
    assert excinfo.value.code == "invalid_query"
    assert "INTERNAL DETAIL" not in str(excinfo.value)


async def test_aclose_is_idempotent():
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    await client.aclose()
    await client.aclose()  # must not raise
