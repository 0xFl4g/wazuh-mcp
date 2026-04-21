# API keys

API keys are the fallback auth path for customers without an IdP.

## Format

```
wzk_<tenant_id>_<nnn>.<base64url-random>
```

- `wzk_<tenant_id>_<nnn>` is the `key_id` — used for store lookup.
- `.<random>` is the plaintext secret — argon2id-hashed in `api_keys.yaml`.
- `.` is the separator (never appears in either part).

Example: `wzk_acme_01.pK4n...base64url...`.

## Generating a key

```bash
python - <<'PY'
import secrets, sys
from argon2 import PasswordHasher

tenant = "acme"
seq = "01"
secret = secrets.token_urlsafe(32)      # 32 bytes → 43 chars base64url
key_id = f"wzk_{tenant}_{seq}"
full = f"{key_id}.{secret}"
hashed = PasswordHasher().hash(secret)

print(f"Full key (give to user ONCE): {full}")
print()
print(f"Add to api_keys.yaml:")
print(f"  - key_id: {key_id}")
print(f"    hash: \"{hashed}\"")
print(f"    tenant_id: {tenant}")
print(f"    user_id: alice@example.com")
print(f"    rbac_role: soc_analyst")
print(f"    revoked: false")
print(f"    expires_at: null")
PY
```

## Rotation

1. Generate a new key with an incremented sequence: `wzk_acme_02`.
2. Add the new entry to `api_keys.yaml` alongside the old one.
3. Send the new key to the user.
4. After confirming the user has switched, set `revoked: true` on the old entry.

No server restart needed — `api_keys.yaml` is re-read on every start, and reload is a planned M4 feature. For M2, a HUP to the uvicorn process is the escape hatch (forces restart + re-read).

## Revocation

Set `revoked: true` on the entry. Effective on next process start. For immediate revocation, restart the process.

## Expiry

Set `expires_at` to an ISO-8601 timestamp (e.g., `2026-12-31T23:59:59Z`). Verified per-call; expired keys fail with 401 the same as revoked ones.

## Security posture

- Plaintext is shown to the admin **once**, at generation time, and never again. Store it in the customer's secret manager.
- argon2id parameters (`m=19456, t=2, p=1`) are per-OWASP-2024 recommendation.
- The `wzk_<tenant>_` prefix is a **routing hint only** — authoritative tenant comes from the store entry. Crafted keys can't claim a tenant they weren't assigned.
- `api_keys.yaml` must be mode 0600 and owned by the MCP service user. A leak of this file exposes every key's hash — still not the plaintext, but harvestable offline if argon2 parameters are weak. Keep parameters at or above the OWASP recommendation.

## What the key does NOT grant

- Cross-tenant access. The store-entry's `tenant_id` pins the session's tenant.
- Admin / write operations. M2 is read-only.
- Bypass of RBAC — the `rbac_role` in the entry flows into the `Session`, and M4's RBAC-aware `list_tools` will gate tools accordingly.
