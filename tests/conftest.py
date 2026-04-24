"""Root conftest — pytest collection hooks shared across unit + integration.

Hooks here:
  - requires_manager: auto-skip on arm64+darwin because wazuh-manager:4.9.0
    segfaults under QEMU on Apple Silicon. The env var
    WAZUH_MCP_FORCE_ARM64_DARWIN=1 forces the skip for local verification
    on non-arm64 machines (used by tests/unit/test_requires_manager_marker.py).
"""
from __future__ import annotations

import os
import platform

import pytest


def _is_arm64_darwin() -> bool:
    if os.environ.get("WAZUH_MCP_FORCE_ARM64_DARWIN") == "1":
        return True
    return platform.system() == "Darwin" and platform.machine() == "arm64"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if not _is_arm64_darwin():
        return
    skip_marker = pytest.mark.skip(
        reason="wazuh-manager:4.9.0 segfaults under QEMU on arm64+darwin; "
        "run on amd64 CI via .github/workflows/integration.yml"
    )
    for item in items:
        if "requires_manager" in item.keywords:
            item.add_marker(skip_marker)
