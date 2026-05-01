"""M4a additions to TenantConfig - rate limits and audit sinks.

Kept in a sibling module so the M1 config stays small. Imported and re-exposed
by tenancy/config.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class BucketConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capacity: Annotated[int, Field(gt=0, le=100_000)]
    refill_per_sec: Annotated[float, Field(gt=0.0, le=1000.0)]


class RateLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant: BucketConfig = BucketConfig(capacity=250, refill_per_sec=4.17)
    session: BucketConfig = BucketConfig(capacity=60, refill_per_sec=1.0)


class StderrSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["stderr"] = "stderr"


class StdoutSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["stdout"] = "stdout"


class FileSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["file"] = "file"
    path: Path
    rotate_size_mb: Annotated[int, Field(gt=0, le=10_000)] = 100
    keep: Annotated[int, Field(ge=0, le=100)] = 5


class HttpSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["http"] = "http"
    url: HttpUrl
    batch: Annotated[int, Field(gt=0, le=10_000)] = 50
    flush_ms: Annotated[int, Field(gt=0, le=60_000)] = 500
    max_attempts: Annotated[int, Field(ge=1, le=20)] = 5


class WazuhIndexerSinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["wazuh_indexer"] = "wazuh_indexer"
    index_prefix: str = "wazuh-mcp-audit"
    batch: Annotated[int, Field(gt=0, le=10_000)] = 100
    flush_ms: Annotated[int, Field(gt=0, le=60_000)] = 1000
    max_attempts: Annotated[int, Field(ge=1, le=20)] = 5


AuditSinkConfig = Annotated[
    StderrSinkConfig | StdoutSinkConfig | FileSinkConfig | HttpSinkConfig | WazuhIndexerSinkConfig,
    Field(discriminator="kind"),
]


# M4b additions ------------------------------------------------------------

_WRITE_TOOL_NAMES: set[str] = {
    "write.isolate_agent",
    "write.restart_agent",
    "write.add_agent_to_group",
    "write.remove_agent_from_group",
    "write.create_rule",
    "write.update_rule",
    "write.run_active_response",
    "write.run_active_response_on_group",
}


def _validate_write_allowlist_entry(name: str) -> str:
    if not name.startswith("write."):
        raise ValueError(f"write_allowlist entries must be under write.* namespace; got {name!r}")
    if name not in _WRITE_TOOL_NAMES:
        raise ValueError(
            f"write_allowlist entry {name!r} is not a known write tool. "
            f"Valid names: {sorted(_WRITE_TOOL_NAMES)}"
        )
    return name


def _validate_ar_command_name(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("active_response_allowlist command names must be non-empty")
    return name


_AGENT_GROUP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_AGENT_GROUP_MAX = 50


def _validate_ar_group_name(name: str) -> str:
    """Wazuh agent group names: alphanumeric + dot/dash/underscore, length 1-128.
    Reject empty strings at the field-validator layer to fail fast at YAML-load.
    """
    if not isinstance(name, str) or not _AGENT_GROUP_NAME_PATTERN.match(name):
        raise ValueError(
            f"invalid agent group name: {name!r}. "
            "Expected: alphanumeric + .-_ characters, length 1-128, "
            "must start with alphanumeric."
        )
    return name
