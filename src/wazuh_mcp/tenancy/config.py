"""TenantConfig - per-tenant routing and trust configuration.

Strict Pydantic. Unknown fields rejected so config drift surfaces loudly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from wazuh_mcp.tenancy.m4_config import (
    AuditSinkConfig,
    RateLimitConfig,
)

TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: Annotated[str, Field(pattern=TENANT_ID_PATTERN.pattern)]
    indexer_url: HttpUrl
    verify_tls: bool = True
    ca_bundle_path: Path | None = None
    default_rbac_role: str
    oauth_issuer: HttpUrl | None = None
    oauth_audience: str | None = None
    # Name of the OAuth claim that carries the Wazuh user identity for
    # run_as attribution. When the claim is present in a verified bearer,
    # Session.wazuh_user is populated and the Server API calls pass run_as.
    # When absent, calls run as the tenant's service account.
    wazuh_user_claim: str = "wazuh_user"

    # M4a additions (all optional; defaults preserve M3 behaviour).
    secret_prefix: str | None = None
    role_tool_allowlist: dict[str, list[str]] | None = None
    rate_limit: RateLimitConfig = RateLimitConfig()
    audit_sinks: list[AuditSinkConfig] = Field(default_factory=list)
