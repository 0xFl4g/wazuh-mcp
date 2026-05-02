"""Reverse index: OAuth issuer URL → TenantConfig.

Used by OAuthSessionFactory when the JWT has no `tenant_id` claim, or
as a sanity check when a `tenant_id` claim IS present (mismatch raises).

Multiple tenants MAY share an issuer URL (e.g. multi-tenant Keycloak
realms distinguished only by claim). When a lookup is ambiguous,
``IssuerIndex.get`` returns ``None`` and the caller (OAuthSessionFactory)
falls back to claim-only routing. Tokens without a `tenant_id` claim
hitting an ambiguous issuer fail with ``MissingClaim`` at the factory
layer — fail-closed.

Independent of issuer-keyed lookup, the index also exposes
``get_by_tenant_id(tenant_id)`` so callers that already resolved a
tenant_id (via claim) can fetch that tenant's config — needed for
default_rbac_role fallback and wazuh_user_claim resolution when the
issuer-keyed path returned None.
"""

from __future__ import annotations

from collections.abc import Iterable

from wazuh_mcp.tenancy.config import TenantConfig


def _canonicalise(issuer: str) -> str:
    return issuer.rstrip("/")


class IssuerIndex:
    __slots__ = ("_by_issuer", "_by_tenant_id")
    _by_issuer: dict[str, TenantConfig | None]
    _by_tenant_id: dict[str, TenantConfig]

    def __init__(self, tenants: Iterable[TenantConfig]) -> None:
        by_issuer: dict[str, TenantConfig | None] = {}
        by_tenant_id: dict[str, TenantConfig] = {}
        for t in tenants:
            by_tenant_id[t.tenant_id] = t
            if t.oauth_issuer is None:
                continue
            key = _canonicalise(str(t.oauth_issuer))
            if key in by_issuer:
                # Ambiguous: two or more tenants share this issuer.
                # Force claim-based resolution by collapsing to None.
                by_issuer[key] = None
            else:
                by_issuer[key] = t
        object.__setattr__(self, "_by_issuer", by_issuer)
        object.__setattr__(self, "_by_tenant_id", by_tenant_id)

    def get(self, issuer: str) -> TenantConfig | None:
        """Return the tenant for this issuer.

        Returns ``None`` for unknown issuers AND for issuers shared by
        multiple tenants. Callers MUST handle the None case (typically
        by falling back to a `tenant_id` claim).
        """

        return self._by_issuer.get(_canonicalise(issuer))

    def get_by_tenant_id(self, tenant_id: str) -> TenantConfig | None:
        """Return the tenant config for a known tenant_id, or None."""

        return self._by_tenant_id.get(tenant_id)

    def known_issuers(self) -> list[str]:
        """Return the canonicalised list of all tenant-configured issuers.

        Includes ambiguous/shared issuers (those with collapsed-to-None
        TenantConfig values). v1.0.4 OAuthSessionFactory uses this to
        accept JWTs from any tenant-configured issuer, not just the
        single global ``oauth.issuer`` from server.yaml.
        """

        return list(self._by_issuer.keys())
