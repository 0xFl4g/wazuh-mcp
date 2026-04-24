"""TenantConfig - per-tenant routing and trust configuration.

Strict Pydantic. Unknown fields rejected so config drift surfaces loudly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

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

    # M4b additions. write_allowlist: None -> no filter (all writes register).
    # Empty list -> NO writes register. List -> only those names register.
    write_allowlist: list[str] | None = None
    active_response_allowlist: list[str] = Field(default_factory=list)

    @field_validator("write_allowlist")
    @classmethod
    def _validate_writes(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        from wazuh_mcp.tenancy.m4_config import _validate_write_allowlist_entry

        return [_validate_write_allowlist_entry(name) for name in v]

    @field_validator("active_response_allowlist")
    @classmethod
    def _validate_ar(cls, v: list[str]) -> list[str]:
        from wazuh_mcp.tenancy.m4_config import _validate_ar_command_name

        return [_validate_ar_command_name(name) for name in v]
