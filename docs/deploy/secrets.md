# Secret stores

wazuh-mcp resolves tenant secrets — indexer credentials, Server API service-account passwords, OAuth client secrets — through a `SecretStore` abstraction. Four drivers ship: YAML (dev only), AWS Secrets Manager, HashiCorp Vault, and SQLite + age. All drivers share the same secret-path convention (`{prefix}{tenant_id}/{key}`) and the same `SecretValue` return type — plaintext never appears in `repr`, `str`, logs, or serialized output.

## Pick a driver

| Driver | Deploy shape | Auth | Notes |
|---|---|---|---|
| `aws_sm` | AWS-hosted wazuh-mcp | boto3 default credential chain (instance role, IRSA, env, profile) | Wrap with `CachingSecretStore`; `GetSecretValue` is billable per call. |
| `vault` | Self-hosted multi-site, Vault already in the stack | Static token or AppRole (`role_id` + `secret_id`) | Wrap with `CachingSecretStore`; `hvac` is blocking, the driver bounces to a thread. |
| `sqlite_age` | Single-node self-hosted, air-gapped, dev boxes that need stronger than plaintext YAML | Age identity file on disk (`AGE-SECRET-KEY-...`) | No caching needed — reads are local SQLite + an in-process decrypt. |
| `yaml` | Local dev only | File permissions | Loaded from `secrets.yaml`; do not use in production. |

The path convention is `{prefix}{tenant_id}/{key}` across every driver. `prefix` defaults to `wazuh-mcp/`. Operators with an existing naming scheme override per-tenant via `TenantConfig.secret_prefix`:

```yaml
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.internal:9200
    default_rbac_role: soc_analyst
    secret_prefix: "prod/soc/wazuh-mcp/"
```

With that override, `acme/indexer_password` resolves to `prod/soc/wazuh-mcp/acme/indexer_password` in the backing store. When `secret_prefix` is unset the driver default applies.

## YAML driver (`YamlSecretStore`)

The M1 dev driver. Loads `secrets.yaml` once at boot and serves from memory.

```yaml
acme:
  indexer_user: mcp-reader
  indexer_password: "pw-1"
  oauth_client_secret: "..."
```

Path semantics: top-level key is the tenant id, second-level key is the secret key. The `secret_prefix` is ignored — the YAML structure already reflects per-tenant scoping.

`chmod 0600` and own the file as the MCP service user. Do not use this driver in production: secrets sit in plaintext on disk, there is no rotation hook, and the file format is incompatible with any KMS workflow.

See `src/wazuh_mcp/secrets/yaml.py`.

## AWS Secrets Manager driver (`AWSSecretsManagerStore`)

Required:
- IAM principal (instance role, ECS task role, EKS IRSA, or static keys in dev) with `secretsmanager:GetSecretValue` on `{prefix}{tenant_id}/*`.
- Region — the driver does not read `AWS_REGION` implicitly; pass it at construction time.

Env vars the driver reads (via boto3's default chain):
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` — explicit keys (dev only).
- `AWS_PROFILE` — profile name from `~/.aws/credentials`.
- `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` — IRSA / workload identity.

Secret payload format: the stored value must be `SecretString`. Binary secrets raise `ValueError` at read time. One value per secret — if a tenant needs `indexer_user` and `indexer_password`, create two secrets, not one JSON blob.

Bootstrap:

```python
from wazuh_mcp.secrets.aws_sm import AWSSecretsManagerStore
from wazuh_mcp.secrets.caching import CachingSecretStore

store = CachingSecretStore(
    AWSSecretsManagerStore(region="eu-west-1"),
    ttl_seconds=300,
)
```

IAM policy example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:wazuh-mcp/acme/*"
    }
  ]
}
```

See `src/wazuh_mcp/secrets/aws_sm.py`.

## HashiCorp Vault driver (`VaultSecretStore`)

Required:
- Vault address reachable from the MCP process.
- Either a static token (short-lived, renewed externally) or AppRole credentials (`role_id` + `secret_id`).
- KV v2 engine mounted at `secret/` (Vault's default) — override with `mount_point` if your deploy uses a different mount.

Construction signature:

```python
VaultSecretStore(
    address: str,
    *,
    token: str | None = None,
    role_id: str | None = None,
    secret_id: str | None = None,
    mount_point: str = "secret",
    prefix: str = "wazuh-mcp/",
)
```

Method signature: `await store.get(tenant_id: str, key: str) -> SecretValue` — two positional args. The driver composes the Vault path as `{prefix}{tenant_id}/{key}`.

Secret payload format: each path must be a KV v2 secret whose data dictionary contains a `value` key. A missing `value` key raises `ValueError`:

```
$ vault kv put secret/wazuh-mcp/acme/indexer_password value=pw-1
```

Bootstrap with AppRole:

```python
from wazuh_mcp.secrets.vault import VaultSecretStore
from wazuh_mcp.secrets.caching import CachingSecretStore

store = CachingSecretStore(
    VaultSecretStore(
        address="https://vault.example.com:8200",
        role_id="<role-id>",
        secret_id="<secret-id>",
        mount_point="secret",
    ),
    ttl_seconds=300,
)
```

Bootstrap with a static token (dev / staging):

```python
VaultSecretStore(
    address="https://vault.example.com:8200",
    token="hvs.CAESxxx",
)
```

AppRole is the recommended production path because `secret_id` is short-lived and re-issuable without restarting the MCP process. Token auth requires an external renewer (Vault Agent, or a sidecar) to refresh the token before expiry.

`hvac` is blocking; the driver calls it from `asyncio.to_thread`. Each `get` builds a fresh `hvac.Client` — cheap, but exactly why wrapping with `CachingSecretStore` matters.

### Real Vault container in integration tests (M5b T-D1)

`docker/integration-compose.yml` ships a real Vault dev container on port 8200, replacing the prior `hvac.Client` mock-only coverage. `tests/integration/test_vault_secret_store.py` exercises the full read path (bootstrap → `kv put` → `await store.get(tenant, key)` → assert `SecretValue` round-trip). The container starts in dev mode with a known root token; the test suite pins token + path conventions inside the fixture.

Operators who run the integration suite locally pick up the Vault container automatically via `docker/bootstrap.sh`. No additional config — the test container is gated to `pytest -m integration` runs and does not affect production deployments.

See `src/wazuh_mcp/secrets/vault.py` and `tests/integration/test_vault_secret_store.py`.

## SQLite + age driver (`SqliteAgeSecretStore`)

Required:
- A writable path for the SQLite DB.
- An age X25519 identity file on disk, readable only by the MCP service user (`chmod 0400`).

Generate an identity once:

```
$ age-keygen -o /etc/wazuh-mcp/age.key
Public key: age1q2...
```

The file contains `AGE-SECRET-KEY-...`. Never check it into git, never copy it off the host without re-encrypting it. The public key printed on stdout is the encryption recipient — save it for `put()` calls.

Bootstrap:

```python
from pathlib import Path
from wazuh_mcp.secrets.sqlite_age import SqliteAgeSecretStore

store = SqliteAgeSecretStore(
    db_path=Path("/var/lib/wazuh-mcp/secrets.db"),
    identity_path=Path("/etc/wazuh-mcp/age.key"),
)
await store.init_schema()
```

Writing a secret (one-time, usually from an admin CLI or fixture script):

```python
import pyrage
recipients = [pyrage.x25519.Recipient.from_str("age1q2...")]
await store.put("acme", "indexer_password", "pw-1", recipients=recipients)
```

Pass more than one recipient to keep a break-glass admin key alongside the MCP service key. Rotating the identity means re-encrypting every row — run a migration script that reads with the old identity and `put()`s with the new recipients.

No caching wrapper is needed. Reads are local SQLite + an in-process age decrypt; the cost of wrapping with `CachingSecretStore` outweighs the saving.

See `src/wazuh_mcp/secrets/sqlite_age.py`.

## CachingSecretStore wrapper

`CachingSecretStore` is a composition wrapper — it implements the same `SecretStore` protocol and delegates to the inner store. It adds:

- **TTL cache** (default 300 s) of positive results only. `KeyError` and other exceptions bypass the cache so a transient miss doesn't pin a negative for 5 minutes.
- **Single-flight** coalescing: concurrent `get` calls for the same `(tenant, key)` share one upstream call.
- **Manual invalidation**: `store.invalidate(tenant_id, key)` drops the entry immediately; use this after rotating a secret so the next call refetches.

Recommended TTL:
- AWS Secrets Manager: 300 s (matches the driver default). Longer TTLs save money; shorter TTLs shorten rotation propagation.
- Vault: 300 s.
- SQLite + age: skip the wrapper.

Invalidation on rotation — wherever your rotation job runs (Lambda, Vault rotation hook, cron), call `store.invalidate(tenant_id, key)` on the MCP process, or accept the TTL as your rotation propagation window.

See `src/wazuh_mcp/secrets/caching.py`.

## Per-tenant `secret_prefix`

`TenantConfig.secret_prefix` overrides the driver default for a single tenant:

```yaml
tenants:
  - tenant_id: acme
    secret_prefix: "prod/soc/wazuh-mcp/"
  - tenant_id: contoso
    # secret_prefix omitted -> driver default ("wazuh-mcp/") applies
```

Use this when one tenant lives in an existing secret namespace (acquired customer, separate AWS account using a shared MCP deploy via cross-account IAM) and the rest follow the default.

## Operational notes

**Token / credential renewal.**
- Vault static tokens: run Vault Agent or a sidecar renewer; the MCP process does not refresh tokens.
- Vault AppRole: re-issue `secret_id` on the operator schedule; the driver re-authenticates on every `get`, so new credentials take effect at the next call.
- AWS: lean on instance role / IRSA — STS handles rotation. Static keys are dev-only.

**KMS.** AWS Secrets Manager backs onto KMS by default; pin a CMK per tenant (or per environment) and grant `kms:Decrypt` to the MCP IAM principal alongside `secretsmanager:GetSecretValue`.

**Age key rotation.** SQLite + age key rotation is a manual migration: read every secret with the old identity, re-encrypt with the new recipient set, write back. Plan a rotation window that fits the secret count and downstream invalidation propagation.

## Error mapping

The driver itself raises Python exceptions; the callers that use the `SecretValue` to reach Wazuh translate to `WazuhError`. The mapping operators care about:

| Driver outcome | Exception from driver | `WazuhError` code at the upstream call site |
|---|---|---|
| Secret not found | `KeyError` | `not_found` (if surfaced as 404 from upstream) or `upstream_error` if the tool's upstream then rejects bad credentials |
| AWS `ResourceNotFoundException` | `KeyError` | same as above |
| AWS auth failure / expired session | `botocore.exceptions.ClientError` | `auth_expired` when the Wazuh call subsequently 401s |
| Vault auth failure | `PermissionError` | `auth_expired` at the upstream call |
| Vault transient network error | `hvac.exceptions.*` | `upstream_error` |
| Binary secret in AWS | `ValueError` | `upstream_error` (configuration bug — fix the secret payload) |
| Vault path missing `value` key | `ValueError` | `upstream_error` (configuration bug) |

`auth_expired` and `upstream_error` are the operator-visible signals in `mcp_tool_calls_total{outcome=...}` — see `observability.md` for the metric set and the per-call audit event carrying `error_code`.
