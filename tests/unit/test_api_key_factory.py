from pathlib import Path

import pytest
from argon2 import PasswordHasher

from wazuh_mcp.auth.api_key import ApiKeySessionFactory
from wazuh_mcp.auth.api_key_store import YamlApiKeyStore
from wazuh_mcp.auth.errors import InvalidToken

HASHER = PasswordHasher()


@pytest.fixture
def store(tmp_path: Path) -> YamlApiKeyStore:
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        f"""
api_keys:
  - key_id: wzk_acme_01
    hash: "{HASHER.hash("secret-token")}"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
""".strip()
    )
    return YamlApiKeyStore(f)


async def test_valid_key_builds_session(store):
    factory = ApiKeySessionFactory(store=store)
    ctx = {"headers": {"Authorization": "Bearer wzk_acme_01.secret-token"}}
    session = await factory.build(ctx)
    assert session.user_id == "alice"
    assert session.tenant_id == "acme"
    assert session.rbac_role == "soc_analyst"
    assert session.auth_method == "api_key"


async def test_missing_header_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {}})


async def test_malformed_prefix_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer not-a-key"}})


async def test_unknown_key_id_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer wzk_ghost_01.x"}})


async def test_bad_plaintext_rejected(store):
    factory = ApiKeySessionFactory(store=store)
    with pytest.raises(InvalidToken):
        await factory.build({"headers": {"Authorization": "Bearer wzk_acme_01.wrong"}})
