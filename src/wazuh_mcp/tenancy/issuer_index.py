"""Reverse index: OAuth issuer URL → TenantConfig.

Used by OAuthSessionFactory when the JWT has no `tenant_id` claim, or
as a sanity check when a `tenant_id` claim IS present (mismatch raises).

Multiple tenants MAY share an issuer URL (e.g. multi-tenant Keycloak
realms distinguished only by claim). When a lookup is ambiguous,
``IssuerIndex.get`` returns ``None`` and the caller (OAuthSessionFactory)
falls back to claim-only routing. Tokens without a `tenant_id` claim
hitting an ambiguous issuer fail with ``MissingClaim`` at the factory
layer — fail-closed.
"""

from __future__ import annotations

from collections.abc import Iterable

from wazuh_mcp.tenancy.config import TenantConfig


def _canonicalise(issuer: str) -> str:
    return issuer.rstrip("/")


class IssuerIndex:
    __slots__ = ("_by_issuer",)
    _by_issuer: dict[str, TenantConfig | None]

    def __init__(self, tenants: Iterable[TenantConfig]) -> None:
        index: dict[str, TenantConfig | None] = {}
        for t in tenants:
            if t.oauth_issuer is None:
                continue
            key = _canonicalise(str(t.oauth_issuer))
            if key in index:
                # Ambiguous: two or more tenants share this issuer.
                # Force claim-based resolution by collapsing to None.
                index[key] = None
            else:
                index[key] = t
        object.__setattr__(self, "_by_issuer", index)

    def get(self, issuer: str) -> TenantConfig | None:
        """Return the tenant for this issuer.

        Returns ``None`` for unknown issuers AND for issuers shared by
        multiple tenants. Callers MUST handle the None case (typically
        by falling back to a `tenant_id` claim).
        """

        return self._by_issuer.get(_canonicalise(issuer))
