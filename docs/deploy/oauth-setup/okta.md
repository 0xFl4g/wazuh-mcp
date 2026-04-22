# OAuth setup — Okta

Okta Workforce Identity Cloud. Requires an org admin account.

## Minimum steps

1. **Create an API service** (under Security → API → Authorization Servers → Default, or create a custom auth server):
   - Audience: `wazuh-mcp-api`
2. **Create an OIDC application**:
   - Applications → Create App Integration → OIDC → Native/SPA/Web (match your MCP client)
   - Client ID: record it for the MCP config
   - Allowed grant types: Authorization Code (PKCE)
3. **Add claims** to the access token:
   - `tenant_id` → Expression `user.wazuh_mcp_tenant`
   - `wazuh_mcp_role` → Expression `user.wazuh_mcp_role`
   Mark both as **Always**, include in **Access Token**.
4. **Set user profile attributes** on users or on a group.
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://<your-org>.okta.com/oauth2/<server-id>"
     audience: "wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery

Okta's well-known endpoint lives at `${issuer}/.well-known/openid-configuration`. JWKS is discovered automatically.

## Notes

- The **Default** authorization server's issuer is `https://<org>.okta.com`, but custom audiences + claims require a **custom** authorization server. Use a custom one for real deployments.
- Okta's default access-token lifetime is 1 hour. Consider shortening for sensitive environments.

## Emitting the `wazuh_user` claim

For per-user attribution in Wazuh's audit log (`run_as`), the access token must carry a claim whose value is the Wazuh username the bearer maps to. The claim name is configured in `tenants.yaml` via `wazuh_user_claim` (default `wazuh_user`).

1. Directory → Profile Editor → the Okta user profile → Add Attribute: string `wazuh_user` (custom attribute).
2. Populate the per-user value (Directory → People → <user> → Profile) or map it from your upstream directory.
3. Security → API → Authorization Servers → <server> → Claims → Add Claim:
   - Name: `wazuh_user`
   - Include in token type: **Access Token**
   - Value type: Expression → `user.wazuh_user`
   - Include in: **Any scope** (or scope-filtered if you prefer)

Absent claim → request runs as the tenant's Server API service account.
