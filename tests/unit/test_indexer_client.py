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


@pytest.mark.parametrize("bad_index", ["", "..", "../_nodes", "a/b", "wazuh/../_nodes"])
async def test_search_rejects_path_traversal_in_index(bad_index):
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(ValueError, match="invalid index name"):
            await client.search(index=bad_index, query={})
    finally:
        await client.aclose()


async def test_bulk_posts_ndjson_to_bulk_endpoint(httpx_mock: HTTPXMock):
    """Pin: ``WazuhIndexerSink`` calls ``IndexerClient.bulk(body=...)``.

    Latent regression: M4a's audit-indexer-sink test suite mocked these
    methods on a MagicMock pool client and never asserted they exist on
    the real ``IndexerClient``. Result: every audit-sink emit silently
    failed in the integration env (5 retries → drop) and the audit index
    never landed. Catching it via the integration suite that wasn't
    running means the unit suite needs the real-method check.
    """
    httpx_mock.add_response(url=f"{BASE}/_bulk", method="POST", json={"errors": False, "items": []})
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        body = '{"index":{"_index":"x"}}\n{"field":1}\n'
        result = await client.bulk(body=body)
    finally:
        await client.aclose()
    assert result == {"errors": False, "items": []}
    sent = httpx_mock.get_request(url=f"{BASE}/_bulk")
    assert sent is not None
    assert sent.headers["content-type"] == "application/x-ndjson"


async def test_put_index_template_acks(httpx_mock: HTTPXMock):
    """Pin: ``WazuhIndexerSink._ensure_template`` calls
    ``put_index_template(name=..., body=...)``."""
    httpx_mock.add_response(
        url=f"{BASE}/_index_template/wazuh-mcp-audit-template",
        method="PUT",
        json={"acknowledged": True},
    )
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        result = await client.put_index_template(
            name="wazuh-mcp-audit-template",
            body={"index_patterns": ["wazuh-mcp-audit-*"]},
        )
    finally:
        await client.aclose()
    assert result == {"acknowledged": True}


@pytest.mark.parametrize("bad_name", ["", "..", "a/b"])
async def test_put_index_template_rejects_bad_name(bad_name: str):
    user, pw = _credentials()
    client = IndexerClient(base_url=BASE, user=user, password=pw, verify_tls=False)
    try:
        with pytest.raises(ValueError, match="invalid template name"):
            await client.put_index_template(name=bad_name, body={})
    finally:
        await client.aclose()
