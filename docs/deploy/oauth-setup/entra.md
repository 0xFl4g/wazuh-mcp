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

## Emitting the `wazuh_user` claim

For per-user attribution in Wazuh's audit log (`run_as`), the access token must carry a claim whose value is the Wazuh username the bearer maps to. The claim name is configured in `tenants.yaml` via `wazuh_user_claim` (default `wazuh_user`).

Entra source this from a directory-schema extension attribute. Two equivalent paths:

1. **Manifest**: app registration → Manifest → append to `optionalClaims.accessToken`:
   ```json
   { "name": "extension_wazuh_user", "source": "user", "essential": false }
   ```
   Then populate `extension_<appid>_wazuh_user` on each user (Graph API). Configure `wazuh_user_claim: extension_wazuh_user` in `tenants.yaml`.
2. **UI**: app registration → Token configuration → Add optional claim → **Access** → pick the extension attribute. If prompted, tick "Turn on the Microsoft Graph email permission".

Absent claim → request runs as the tenant's Server API service account.
