"""VaultSecretStore — hvac KVv2 read, wrapped via asyncio.to_thread."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from wazuh_mcp.secrets.vault import VaultSecretStore


@pytest.fixture
def fake_client(monkeypatch):
    # Patch hvac.Client so we can control what read returns.
    client = MagicMock()
    client.is_authenticated.return_value = True
    created_with = {}

    def _ctor(url=None, token=None, **kw):
        created_with["url"] = url
        created_with["token"] = token
        return client

    monkeypatch.setattr("wazuh_mcp.secrets.vault.hvac.Client", _ctor)
    return client, created_with


@pytest.mark.asyncio
async def test_get_kv_v2(fake_client) -> None:
    client, _ = fake_client
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"value": "topsecret"}}
    }
    store = VaultSecretStore(address="https://vault.example", token="t", prefix="wazuh-mcp/")
    v = await store.get("tenant1", "indexer_password")
    assert v.expose() == "topsecret"
    client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="wazuh-mcp/tenant1/indexer_password", raise_on_deleted_version=True
    )


@pytest.mark.asyncio
async def test_missing_secret_raises_keyerror(fake_client) -> None:
    client, _ = fake_client
    import hvac.exceptions

    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath()
    store = VaultSecretStore(address="https://vault.example", token="t")
    with pytest.raises(KeyError, match="wazuh-mcp/t/k"):
        await store.get("t", "k")


@pytest.mark.asyncio
async def test_auth_fail_raises(fake_client) -> None:
    client, _ = fake_client
    client.is_authenticated.return_value = False
    store = VaultSecretStore(address="https://vault.example", token="bad")
    with pytest.raises(PermissionError):
        await store.get("t", "k")


@pytest.mark.asyncio
async def test_value_must_have_value_key(fake_client) -> None:
    client, _ = fake_client
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"something_else": "x"}}
    }
    store = VaultSecretStore(address="https://vault.example", token="t")
    with pytest.raises(ValueError, match="value"):
        await store.get("t", "k")
