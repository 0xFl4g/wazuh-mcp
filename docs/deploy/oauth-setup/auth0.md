# OAuth setup — Auth0

Any Auth0 tenant.

## Minimum steps

1. **Create an API**:
   - Name: `wazuh-mcp-api`
   - Identifier (audience): `https://mcp.example.com/api` (or any URI you prefer)
   - Signing algorithm: RS256
2. **Create an application**:
   - Type: Machine-to-Machine (for service-to-service) or Native (for Claude Desktop)
   - Authorize the app for the API above
3. **Add a custom claim** via an Action (post-login):
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const ns = "https://mcp.example.com/";
     if (event.user.user_metadata?.wazuh_mcp_tenant) {
       api.accessToken.setCustomClaim("tenant_id", event.user.user_metadata.wazuh_mcp_tenant);
     }
     if (event.user.user_metadata?.wazuh_mcp_role) {
       api.accessToken.setCustomClaim("wazuh_mcp_role", event.user.user_metadata.wazuh_mcp_role);
     }
   };
   ```
4. **Set user metadata**: in the Auth0 user's `user_metadata`, set `wazuh_mcp_tenant` and `wazuh_mcp_role`.
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://<your-tenant>.auth0.com/"
     audience: "https://mcp.example.com/api"
     rbac_claims: [wazuh_mcp_role, groups, roles]
   ```

## Discovery

Auth0's well-known endpoint is `${issuer}.well-known/openid-configuration` (Auth0 includes the trailing slash in issuer). wazuh-mcp auto-discovers JWKS.

## Notes

- Auth0 namespaces custom claims unless you use an allowlisted claim name. If the claim doesn't arrive, verify the Action ran (Auth0 → Actions → Logs) and the claim isn't being stripped by a namespace rule.
- Default access-token lifetime is 24h. Shorten for sensitive deployments.
