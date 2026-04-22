# OAuth setup — Keycloak

Keycloak 24+ (tested: 26). Use the integration-test realm export as a starting point: `docker/config/keycloak-realm.json`.

## Minimum steps

1. **Create a realm** named after your MSSP (e.g., `msp`).
2. **Create a client**:
   - Client ID: `wazuh-mcp-client`
   - Access type: Confidential
   - Direct Access Grants: on (for testing) or off (production)
   - Standard flow: on
   - Valid redirect URIs: whatever your MCP client expects (for Claude, `http://localhost:*`)
3. **Add protocol mappers** to the client:
   - **Audience mapper** — includes `wazuh-mcp-api` in the token's `aud`.
     - Type: Audience
     - Included Client Audience: `wazuh-mcp-api`
     - Add to access token: ✓
   - **Tenant mapper** — emits `tenant_id` claim from a user attribute.
     - Type: User Attribute
     - User Attribute: `wazuh_mcp_tenant`
     - Token Claim Name: `tenant_id`
     - Claim JSON Type: String
     - Add to access token: ✓
   - **Role mapper** — emits `wazuh_mcp_role` claim from a user attribute.
     - Type: User Attribute
     - User Attribute: `wazuh_mcp_role`
     - Token Claim Name: `wazuh_mcp_role`
     - Claim JSON Type: String
     - Add to access token: ✓
4. **Populate user attributes** (per-user): set `wazuh_mcp_tenant` and `wazuh_mcp_role` via the Keycloak admin UI or API.
5. **Configure wazuh-mcp** with:
   ```yaml
   oauth:
     issuer: "https://keycloak.example.com/realms/msp"
     audience: "wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery and JWKS

Keycloak exposes:
- `${issuer}/.well-known/openid-configuration`
- `${issuer}/protocol/openid-connect/certs`

wazuh-mcp auto-discovers the JWKS URL from the configuration endpoint.

## Token rotation

Default Keycloak access token lifespan is 5 minutes. Adjust under Realm → Tokens as needed. Shorter lifespan = tighter revocation story; wazuh-mcp has no introspection in M2, so short tokens are the revocation mechanism.

## Emitting the `wazuh_user` claim

For per-user attribution in Wazuh's audit log (`run_as`), the access token must carry a claim whose value is the Wazuh username the bearer maps to. The claim name is configured in `tenants.yaml` via `wazuh_user_claim` (default `wazuh_user`).

1. Realm → Users → <user> → Attributes: add `wazuh_user=<wazuh-username>`.
2. Realm → Clients → `wazuh-mcp-client` → Client scopes → `wazuh-mcp-client-dedicated` → Add mapper → By configuration → **User Attribute**.
   - Name: `wazuh_user-mapper`
   - User Attribute: `wazuh_user`
   - Token Claim Name: `wazuh_user`
   - Add to access token: **On**
   - Multivalued: **Off**

Absent claim → request runs as the tenant's Server API service account.
