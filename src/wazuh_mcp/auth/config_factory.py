"""ConfigSessionFactory — M1's stdio/config auth mode.

Session is built once from server.yaml at startup and returned identically
for every request. No token validation. Only valid for single-operator stdio.
"""

from __future__ import annotations

from wazuh_mcp.auth.factory import RequestContext, SessionFactory
from wazuh_mcp.auth.session import Session
from wazuh_mcp.tenancy.config import TenantConfig


class ConfigSessionFactory(SessionFactory):
    __slots__ = ("_session",)

    _session: Session

    def __init__(self, *, user_id: str, tenant: TenantConfig) -> None:
        object.__setattr__(
            self,
            "_session",
            Session(
                user_id=user_id,
                tenant_id=tenant.tenant_id,
                rbac_role=tenant.default_rbac_role,
                auth_method="config",
            ),
        )

    async def build(self, ctx: RequestContext) -> Session:
        return self._session
