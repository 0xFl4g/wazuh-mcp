"""Session value object — identity carried through every tool call.

Frozen by design: a session's tenant cannot change mid-call. This is a
structural defense against confused-deputy / cross-tenant bugs.
"""

from dataclasses import dataclass
from typing import Literal

AuthMethod = Literal["config", "oauth", "api_key"]


@dataclass(frozen=True, slots=True)
class Session:
    user_id: str
    tenant_id: str
    rbac_role: str
    auth_method: AuthMethod
    # Optional upstream-identity attribution carried through to Wazuh's own
    # audit log via the Server API's `run_as` parameter. Populated only by
    # OAuthSessionFactory when the configured claim is present. Config- and
    # API-key sessions always leave this None — `run_as=None` means the
    # Server API request runs as the tenant's service account.
    wazuh_user: str | None = None
