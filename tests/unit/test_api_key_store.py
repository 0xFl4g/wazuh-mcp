from pathlib import Path

import pytest
from argon2 import PasswordHasher

from wazuh_mcp.auth.api_key_store import ApiKeyRecord, YamlApiKeyStore

HASHER = PasswordHasher()


def _write(
    path: Path,
    plaintext: str,
    *,
    revoked: bool = False,
    expires_at: str | None = None,
    user: str = "alice",
    tenant: str = "acme",
    role: str = "soc_analyst",
    key_id: str = "wzk_acme_01",
) -> None:
    hashed = HASHER.hash(plaintext)
    ex = f'"{expires_at}"' if expires_at else "null"
    path.write_text(
        f"""
api_keys:
  - key_id: {key_id}
    hash: "{hashed}"
    tenant_id: {tenant}
    user_id: {user}
    rbac_role: {role}
    revoked: {str(revoked).lower()}
    expires_at: {ex}
""".strip()
    )


def test_loads_and_verifies_valid_key(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "secret-token")
    store = YamlApiKeyStore(f)
    rec = store.verify(key_id="wzk_acme_01", plaintext="secret-token")
    assert isinstance(rec, ApiKeyRecord)
    assert rec.tenant_id == "acme"
    assert rec.user_id == "alice"
    assert rec.rbac_role == "soc_analyst"


def test_unknown_key_id_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_ghost_01", plaintext="x") is None


def test_wrong_plaintext_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "right")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="wrong") is None


def test_revoked_key_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", revoked=True)
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="x") is None


def test_expired_key_returns_none(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", expires_at="2020-01-01T00:00:00Z")
    store = YamlApiKeyStore(f)
    assert store.verify(key_id="wzk_acme_01", plaintext="x") is None


def test_duplicate_key_ids_rejected(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        f"""
api_keys:
  - key_id: wzk_acme_01
    hash: "{HASHER.hash("a")}"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
  - key_id: wzk_acme_01
    hash: "{HASHER.hash("b")}"
    tenant_id: beta
    user_id: bob
    rbac_role: admin
    revoked: false
    expires_at: null
""".strip()
    )
    with pytest.raises(ValueError, match="duplicate"):
        YamlApiKeyStore(f)


def test_malformed_hash_rejected(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        """
api_keys:
  - key_id: wzk_acme_01
    hash: "not-an-argon2-hash"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
""".strip()
    )
    with pytest.raises(ValueError, match="hash"):
        YamlApiKeyStore(f)


def test_expires_at_field_absent_works_like_null(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        f"""
api_keys:
  - key_id: wzk_acme_01
    hash: "{HASHER.hash("x")}"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
""".strip()
    )
    store = YamlApiKeyStore(f)
    rec = store.verify(key_id="wzk_acme_01", plaintext="x")
    assert rec is not None


def test_future_expires_at_accepted(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", expires_at="2099-01-01T00:00:00Z")
    store = YamlApiKeyStore(f)
    rec = store.verify(key_id="wzk_acme_01", plaintext="x")
    assert rec is not None


def test_non_utc_timezone_in_expires_at(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    # Future time in +05:00 offset: still in the future.
    _write(f, "x", expires_at="2099-01-01T00:00:00+05:00")
    store = YamlApiKeyStore(f)
    rec = store.verify(key_id="wzk_acme_01", plaintext="x")
    assert rec is not None


def test_malformed_expires_at_rejected(tmp_path: Path):
    f = tmp_path / "api_keys.yaml"
    _write(f, "x", expires_at="not-an-iso-date")
    store = YamlApiKeyStore(f)
    # Malformed ISO parse fails, collapse to None.
    assert store.verify(key_id="wzk_acme_01", plaintext="x") is None


def test_argon2i_hash_rejected_at_load(tmp_path: Path):
    # Manually craft an argon2i hash string that starts with $argon2i$ not $argon2id$.
    f = tmp_path / "api_keys.yaml"
    f.write_text(
        """
api_keys:
  - key_id: wzk_acme_01
    hash: "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$somehash"
    tenant_id: acme
    user_id: alice
    rbac_role: soc_analyst
    revoked: false
    expires_at: null
""".strip()
    )
    with pytest.raises(ValueError, match="argon2id"):
        YamlApiKeyStore(f)
