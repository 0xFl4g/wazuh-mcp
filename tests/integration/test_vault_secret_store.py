"""M5b T-D1. Real-Vault driver round-trip integration tests.

Replaces the unit-only ``hvac.Client`` mock coverage in
``tests/unit/test_vault_store.py`` with three end-to-end tests that
write secrets through Vault's HTTP API, then read them back through
``VaultSecretStore``. Catches deserialization mismatches, KV v2 path
shape regressions, and any future hvac upgrade fallout.

Requires the ``vault`` service from ``docker/integration-compose.yml``;
gated behind the ``vault`` pytest marker so daily integration runs that
don't bring up Vault skip cleanly.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from tests.integration._vault_bootstrap import (
    VAULT_TOKEN,
    VAULT_URL,
    wait_until_vault_ready,
    write_secret,
)
from wazuh_mcp.secrets.vault import VaultSecretStore

pytestmark = [pytest.mark.integration, pytest.mark.vault]

# Default VaultSecretStore prefix is "wazuh-mcp/", and the get() API takes
# (tenant_id, key) which produces the path "wazuh-mcp/<tenant>/<key>".
# We match that shape when seeding via the HTTP API.
_TENANT = "local"


@pytest.fixture(scope="module", autouse=True)
async def _vault_ready():
    await wait_until_vault_ready()


@pytest.mark.asyncio
async def test_get_existing_secret_round_trips_through_vault():
    """Seed a secret via the HTTP API, read it back via the driver."""
    await write_secret(
        f"wazuh-mcp/{_TENANT}/oauth_client_secret",
        {"value": "round-trip-secret-value"},
    )
    store = VaultSecretStore(
        address=VAULT_URL,
        token=VAULT_TOKEN,
    )
    secret = await store.get(_TENANT, "oauth_client_secret")
    assert secret.expose() == "round-trip-secret-value"
    # SecretValue must redact in repr — defensive check that we don't
    # accidentally leak plaintext through logs in the round-trip path.
    assert "round-trip-secret-value" not in repr(secret)


@pytest.mark.asyncio
async def test_get_missing_secret_raises_keyerror():
    """A missing path (never written) must surface as KeyError, not a
    generic Vault InvalidPath/HTTP 404 — ``vault.py`` is responsible for
    the translation and any regression here would break SecretStore
    callers that catch KeyError specifically.
    """
    store = VaultSecretStore(
        address=VAULT_URL,
        token=VAULT_TOKEN,
    )
    with pytest.raises(KeyError):
        await store.get(_TENANT, "definitely-does-not-exist-m5b-td1")


@pytest.mark.asyncio
async def test_token_renewal_refreshes_lease():
    """Vault dev-mode root token does not expire; this test proves the
    driver's repeated read path doesn't fail and that its per-call client
    construction (no shared session) keeps working under repeat use.

    Real periodic-token renewal exercise would require a non-dev Vault
    config — out of scope for v1.0.0 (carry-forward to v1.1).
    """
    store = VaultSecretStore(
        address=VAULT_URL,
        token=VAULT_TOKEN,
    )
    await write_secret(f"wazuh-mcp/{_TENANT}/renewal_canary", {"value": "v1"})
    s1 = await store.get(_TENANT, "renewal_canary")
    assert s1.expose() == "v1"
    await asyncio.sleep(0.1)
    s2 = await store.get(_TENANT, "renewal_canary")
    assert s2.expose() == "v1"

    # Sanity-check the dev token is still authenticated end-to-end via
    # the raw HTTP API — proves the driver's auth state matches reality.
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{VAULT_URL}/v1/auth/token/lookup-self",
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=3.0,
        )
        assert r.status_code == 200, f"vault token lookup failed: {r.status_code} {r.text}"
