"""SqliteAgeSecretStore — real pyrage + aiosqlite roundtrip against tempdir DB."""
from __future__ import annotations

from pathlib import Path

import pyrage
import pytest

from wazuh_mcp.secrets.sqlite_age import SqliteAgeSecretStore


@pytest.fixture
async def age_store(tmp_path: Path):
    identity = pyrage.x25519.Identity.generate()  # ty:ignore[unresolved-attribute]
    id_path = tmp_path / "id.txt"
    id_path.write_text(str(identity))
    db_path = tmp_path / "secrets.db"
    store = SqliteAgeSecretStore(db_path=db_path, identity_path=id_path)
    await store.init_schema()
    yield store, identity


@pytest.mark.asyncio
async def test_put_and_get_roundtrip(age_store) -> None:
    store, identity = age_store
    await store.put("t1", "k1", "hunter2", recipients=[identity.to_public()])
    val = await store.get("t1", "k1")
    assert val.expose() == "hunter2"


@pytest.mark.asyncio
async def test_missing_raises_keyerror(age_store) -> None:
    store, _ = age_store
    with pytest.raises(KeyError):
        await store.get("t1", "absent")


@pytest.mark.asyncio
async def test_unknown_tenant_raises_keyerror(age_store) -> None:
    store, _ = age_store
    with pytest.raises(KeyError):
        await store.get("ghost", "k1")


@pytest.mark.asyncio
async def test_wrong_identity_fails(tmp_path: Path, age_store) -> None:
    store, _identity = age_store
    # Encrypt to one identity, try to decrypt with another.
    other = pyrage.x25519.Identity.generate()  # ty:ignore[unresolved-attribute]
    await store.put("t1", "k1", "v1", recipients=[other.to_public()])
    with pytest.raises(pyrage.DecryptError):  # ty:ignore[unresolved-attribute]
        await store.get("t1", "k1")


@pytest.mark.asyncio
async def test_primary_key_unique(age_store) -> None:
    store, identity = age_store
    await store.put("t1", "k1", "v1", recipients=[identity.to_public()])
    await store.put("t1", "k1", "v2", recipients=[identity.to_public()])
    val = await store.get("t1", "k1")
    assert val.expose() == "v2"
