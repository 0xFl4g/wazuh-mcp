"""AWS Secrets Manager-backed SecretStore.

Secret name convention: `{prefix}{tenant_id}/{key}` (default prefix
"wazuh-mcp/"). Operators with existing hierarchies override via
TenantConfig.secret_prefix and pass it through at bootstrap.

Auth: boto3's default credential chain (env, ~/.aws, instance/container
IAM role). Explicit keys can be passed via kwargs for dev.

Errors:
  - KeyError on ResourceNotFoundException.
  - ValueError when the secret is SecretBinary (we only support string).
  - ClientError propagates for auth failures etc; callers translate to
    WazuhError.
"""

from __future__ import annotations

from typing import Any

import aioboto3
from botocore.exceptions import ClientError

from wazuh_mcp.secrets.value import SecretValue


class AWSSecretsManagerStore:
    def __init__(
        self,
        *,
        region: str,
        prefix: str = "wazuh-mcp/",
        **boto_kwargs: Any,
    ) -> None:
        self._region = region
        self._prefix = prefix
        self._boto_kwargs = boto_kwargs
        self._session = aioboto3.Session()

    def _name(self, tenant_id: str, key: str) -> str:
        return f"{self._prefix}{tenant_id}/{key}"

    async def get(self, tenant_id: str, key: str) -> SecretValue:
        name = self._name(tenant_id, key)
        async with self._session.client(
            "secretsmanager", region_name=self._region, **self._boto_kwargs
        ) as client:
            try:
                resp = await client.get_secret_value(SecretId=name)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    raise KeyError(name) from exc
                raise
        if "SecretString" not in resp:
            raise ValueError(f"secret {name!r} is binary; wazuh-mcp stores only string secrets")
        return SecretValue(resp["SecretString"])
