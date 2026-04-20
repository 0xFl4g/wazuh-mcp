"""SecretStore protocol — the contract every backend implements.

M1 ships YamlSecretStore. M4 adds AwsSecretsManagerStore,
VaultSecretStore, SqliteAgeSecretStore.
"""

from __future__ import annotations

from typing import Protocol

from wazuh_mcp.secrets.value import SecretValue


class SecretStore(Protocol):
    async def get(self, tenant_id: str, key: str) -> SecretValue:
        """Return the secret for (tenant_id, key).

        Raises KeyError if tenant or key is unknown.
        Never returns or logs plaintext; the returned SecretValue is the
        only way callers can access it via .expose().
        """
        ...
