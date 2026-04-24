"""M4a additions to TenantConfig - rate limits and audit sinks.

Kept in a sibling module so the M1 config stays small. Imported and re-exposed
by tenancy/config.py.
"""

from __future__ import annotations

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
