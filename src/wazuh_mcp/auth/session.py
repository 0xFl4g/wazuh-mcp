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
