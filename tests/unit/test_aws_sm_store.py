"""AWSSecretsManagerStore against moto (in-process AWS SDK mock).

Adaptation note: moto 5.x wires AWS responses into botocore via a
synchronous ``AWSResponse(..., MockRawResponse(body))`` returned from its
``before-send`` event hook. aiobotocore intercepts the same hook, but its
``convert_to_response_dict`` reads urllib3-style ``raw.raw_headers`` and
awaits ``.content``/``raw.read()`` — neither of which moto's sync
``AWSResponse`` + ``BytesIO``-based ``MockRawResponse`` provide. We patch
``aiobotocore.endpoint.convert_to_response_dict`` for the duration of
these tests so it can consume moto's synchronous response shape.
"""
from __future__ import annotations

import aiobotocore.endpoint
import pytest
from moto import mock_aws
from urllib3.response import HTTPHeaderDict

from wazuh_mcp.secrets.aws_sm import AWSSecretsManagerStore


async def _sync_compatible_convert_to_response_dict(http_response, operation_model):
    """Replacement for aiobotocore.endpoint.convert_to_response_dict.

    Accepts either a native aiobotocore response (async content + urllib3
    raw with ``raw_headers``) or moto's sync-style ``AWSResponse`` whose
    ``raw`` is a ``BytesIO`` subclass.
    """
    raw = http_response.raw
    raw_headers = getattr(raw, "raw_headers", None)
    if raw_headers is not None:
        headers = HTTPHeaderDict(
            {
                k.decode("utf-8").lower(): v.decode("utf-8")
                for k, v in raw_headers
            }
        )
    else:
        headers = HTTPHeaderDict()

    response_dict = {
        "headers": headers,
        "status_code": http_response.status_code,
        "context": {"operation_name": operation_model.name},
    }

    # moto's sync AWSResponse.content is bytes; aiobotocore's is a
    # coroutine. Fall back to reading the raw BytesIO when content is
    # sync bytes and we still need a body.
    async def _body() -> bytes:
        content = http_response.content
        if hasattr(content, "__await__"):
            return await content
        if isinstance(content, bytes | bytearray):
            return bytes(content)
        # Last resort: drain the raw BytesIO-like object.
        raw.seek(0)
        return raw.read()

    if response_dict["status_code"] >= 300:
        response_dict["body"] = await _body()
    elif operation_model.has_event_stream_output:
        response_dict["body"] = raw
    elif operation_model.has_streaming_output:
        from aiobotocore.response import StreamingBody

        length = response_dict["headers"].get("content-length")
        response_dict["body"] = StreamingBody(raw, length)
    else:
        response_dict["body"] = await _body()
    return response_dict


@pytest.fixture(autouse=True)
def _patch_aiobotocore_for_moto(monkeypatch):
    monkeypatch.setattr(
        aiobotocore.endpoint,
        "convert_to_response_dict",
        _sync_compatible_convert_to_response_dict,
    )
    yield


@pytest.fixture
def mocked_aws():
    with mock_aws():
        yield


@pytest.mark.asyncio
async def test_get_existing_secret(mocked_aws) -> None:
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="wazuh-mcp/t1/indexer_password", SecretString="hunter2")

    store = AWSSecretsManagerStore(region="us-east-1", prefix="wazuh-mcp/")
    value = await store.get("t1", "indexer_password")
    assert value.expose() == "hunter2"


@pytest.mark.asyncio
async def test_missing_secret_raises_keyerror(mocked_aws) -> None:
    store = AWSSecretsManagerStore(region="us-east-1", prefix="wazuh-mcp/")
    with pytest.raises(KeyError, match="wazuh-mcp/t1/missing"):
        await store.get("t1", "missing")


@pytest.mark.asyncio
async def test_prefix_is_applied(mocked_aws) -> None:
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="custom-prefix/t1/k1", SecretString="v1")
    store = AWSSecretsManagerStore(region="us-east-1", prefix="custom-prefix/")
    v = await store.get("t1", "k1")
    assert v.expose() == "v1"


@pytest.mark.asyncio
async def test_binary_secret_rejected(mocked_aws) -> None:
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="wazuh-mcp/t1/k1", SecretBinary=b"\x00\x01\x02")
    store = AWSSecretsManagerStore(region="us-east-1", prefix="wazuh-mcp/")
    with pytest.raises(ValueError, match="binary"):
        await store.get("t1", "k1")


@pytest.mark.asyncio
async def test_default_prefix() -> None:
    store = AWSSecretsManagerStore(region="us-east-1")
    assert store._prefix == "wazuh-mcp/"
