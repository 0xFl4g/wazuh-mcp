from pathlib import Path

import pytest

from wazuh_mcp.secrets.value import SecretValue
from wazuh_mcp.secrets.yaml_driver import YamlSecretStore


@pytest.fixture
def secrets_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.yaml"
    p.write_text(
        """
acme:
  indexer_user: admin
  indexer_password: s3cret
beta:
  indexer_user: admin
  indexer_password: other
""".strip()
    )
    return p


async def test_get_returns_secret_value(secrets_file):
    store = YamlSecretStore(secrets_file)
    value = await store.get("acme", "indexer_password")
    assert isinstance(value, SecretValue)
    assert value.expose() == "s3cret"


async def test_get_is_tenant_scoped(secrets_file):
    store = YamlSecretStore(secrets_file)
    acme = await store.get("acme", "indexer_password")
    beta = await store.get("beta", "indexer_password")
    assert acme.expose() == "s3cret"
    assert beta.expose() == "other"


async def test_unknown_tenant_raises(secrets_file):
    store = YamlSecretStore(secrets_file)
    with pytest.raises(KeyError, match="ghost"):
        await store.get("ghost", "indexer_password")


async def test_unknown_key_raises(secrets_file):
    store = YamlSecretStore(secrets_file)
    with pytest.raises(KeyError, match="missing"):
        await store.get("acme", "missing")
