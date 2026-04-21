# OAuth setup — Microsoft Entra (Azure AD)

Entra External Identities or Workforce tenant. Requires Application Administrator.

## Minimum steps

1. **Register an application**:
   - Name: `wazuh-mcp-api`
   - Supported account types: Single tenant (production) or multi-tenant (if you want federation)
   - Redirect URI: `http://localhost` (for native clients like Claude Desktop) or your MCP client URL
2. **Expose an API**:
   - Application ID URI: `api://wazuh-mcp-api`
   - Add a scope: `mcp.read`
3. **Add an app role** for each tenant (if using roles-claim routing), e.g., `Wazuh.Acme.Analyst`.
4. **Create optional claims** in the manifest or UI:
   ```json
   "optionalClaims": {
     "accessToken": [
       { "name": "tenant_id", "source": null, "essential": false },
       { "name": "wazuh_mcp_role", "source": null, "essential": false }
     ]
   }
   ```
   For custom-claim population, use a **claims mapping policy** attached to a **service principal** (Entra's claim-customization path for access tokens).
5. **Configure wazuh-mcp**:
   ```yaml
   oauth:
     issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
     audience: "api://wazuh-mcp-api"
     rbac_claims: [wazuh_mcp_role, roles, groups]
   ```

## v1 vs v2 endpoints

Use the v2.0 issuer (`/v2.0`) and audience of the form `api://<app-id-uri>`. The v1 endpoint uses GUID audiences and is not recommended for new deployments.

## Discovery

Entra exposes `${issuer}/.well-known/openid-configuration`; auto-discovered.

## Notes

- Entra claim customization is more involved than Keycloak/Okta; simpler deployments can route via `iss` alone (the IssuerIndex path), skipping `tenant_id` claim entirely.
- Default access-token lifetime is 1 hour (configurable via Conditional Access policies).
