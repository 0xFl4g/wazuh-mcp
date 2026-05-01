# Vault dev-mode container

`hashicorp/vault:1.18` runs in dev mode for the integration test
fixture. Root token: `test-root-token`. KV v2 engine mounted at
`secret/` (Vault default). HTTP listener on `0.0.0.0:8200`, exposed
on host `localhost:8200`.

**Do not use this configuration in production.** Dev mode disables
sealing, runs entirely in-memory (data lost on container restart),
and uses a fixed, well-known root token.

The `tests/integration/test_vault_secret_store.py` suite writes
secrets at `secret/data/wazuh-mcp/<tenant>/<key>` (the path shape
`VaultSecretStore` derives from its `prefix` + `tenant_id` + `key`)
and reads them back through the driver. The bootstrap helper at
`tests/integration/_vault_bootstrap.py` provides the seeding shim.
