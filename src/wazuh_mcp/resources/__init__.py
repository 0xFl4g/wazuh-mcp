"""MCP resources — URI-addressable, cacheable reference data.

All three resources are publishable as URI templates via
resources/templates/list. resources/list returns [] — we never enumerate
rules, techniques, or agents (cardinality too large or corpus too
public-domain to be useful).

Each read returns a dict with:
  - `contents`: list of MCP content blocks (JSON body in `text`, MIME
    `application/json`).
  - `_meta.ttl_seconds`: compliant clients cache for this long.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResourceTemplate:
    uri_template: str
    name: str
    description: str
    mime_type: str
    ttl_seconds: int


TEMPLATES: tuple[ResourceTemplate, ...] = (
    ResourceTemplate(
        uri_template="wazuh://rules/{id}",
        name="Wazuh rule",
        description=(
            "Individual Wazuh detection rule - definition, groups, "
            "description. Attach this instead of calling a tool when the "
            "model just needs rule metadata."
        ),
        mime_type="application/json",
        ttl_seconds=300,
    ),
    ResourceTemplate(
        uri_template="wazuh://mitre/technique/{id}",
        name="MITRE ATT&CK technique",
        description=(
            "Individual MITRE ATT&CK technique (TXXXX or TXXXX.YYY). "
            "Stable public corpus - cache aggressively."
        ),
        mime_type="application/json",
        ttl_seconds=86_400,
    ),
    ResourceTemplate(
        uri_template="wazuh://agents/{id}/config",
        name="Agent configuration",
        description=("Current agent configuration snapshot from the Server API."),
        mime_type="application/json",
        ttl_seconds=300,
    ),
)


def make_json_content(data: Any, ttl_seconds: int) -> dict[str, Any]:
    """Shared response shape for `resources/read`."""
    return {
        "contents": [
            {
                "mimeType": "application/json",
                "text": json.dumps(data, indent=2),
            }
        ],
        "_meta": {"ttl_seconds": ttl_seconds},
    }
