"""Reverse index: OAuth issuer URL → TenantConfig.

Used by OAuthSessionFactory when the JWT has no `tenant_id` claim.
Duplicate issuers across tenants are rejected at construction so the
lookup is unambiguous.
"""

from __future__ import annotations

from collections.abc import Iterable

from wazuh_mcp.tenancy.config import TenantConfig


def _canonicalise(issuer: str) -> str:
    return issuer.rstrip("/")


class IssuerIndex:
    __slots__ = ("_by_issuer",)
    _by_issuer: dict[str, TenantConfig]

    def __init__(self, tenants: Iterable[TenantConfig]) -> None:
        index: dict[str, TenantConfig] = {}
        for t in tenants:
            if t.oauth_issuer is None:
                continue
            key = _canonicalise(str(t.oauth_issuer))
            if key in index:
                raise ValueError(
                    f"duplicate oauth_issuer {key!r} in tenants "
                    f"{index[key].tenant_id!r} and {t.tenant_id!r}"
                )
            index[key] = t
        object.__setattr__(self, "_by_issuer", index)

    def get(self, issuer: str) -> TenantConfig | None:
        return self._by_issuer.get(_canonicalise(issuer))
