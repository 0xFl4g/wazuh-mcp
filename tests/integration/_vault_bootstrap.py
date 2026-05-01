"""M5b T-D1. Vault test-fixture bootstrap helper.

Thin httpx-based shim for seeding the dev-mode Vault container with
test secrets via the KV v2 HTTP API. Used by
``tests/integration/test_vault_secret_store.py`` and any future fixture
that needs a pre-seeded Vault entry.

The dev-mode container exposes:

* address: ``http://localhost:8200``
* root token: ``test-root-token``
* KV v2 mounted at ``secret/`` (the Vault default)
"""

from __future__ import annotations

import asyncio

import httpx

VAULT_URL = "http://localhost:8200"
VAULT_TOKEN = "test-root-token"  # dev-mode fixture token, not a credential


async def wait_until_vault_ready(timeout_s: float = 30.0) -> None:
    """Poll /v1/sys/health until Vault answers 200/429 or the timeout elapses.

    Vault returns 200 when initialised + unsealed + active, 429 when it's
    a standby. Either is acceptable for our test fixture; only 5xx and
    connection errors mean Vault is still booting.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    last_exc: Exception | None = None
    async with httpx.AsyncClient() as c:
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await c.get(f"{VAULT_URL}/v1/sys/health", timeout=3.0)
                if r.status_code in (200, 429):
                    return
            except httpx.HTTPError as e:
                last_exc = e
            await asyncio.sleep(0.5)
    raise RuntimeError(f"vault not ready after {timeout_s}s: {last_exc}")


async def write_secret(path: str, data: dict[str, str]) -> None:
    """Write a KV v2 secret at ``secret/data/<path>``.

    ``data`` is the inner secret dict; the helper wraps it in the
    ``{"data": ...}`` envelope KV v2 requires.
    """
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{VAULT_URL}/v1/secret/data/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
            json={"data": data},
            timeout=5.0,
        )
        r.raise_for_status()


async def delete_secret(path: str) -> None:
    """Soft-delete the latest version of a KV v2 secret."""
    async with httpx.AsyncClient() as c:
        await c.delete(
            f"{VAULT_URL}/v1/secret/data/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=5.0,
        )
