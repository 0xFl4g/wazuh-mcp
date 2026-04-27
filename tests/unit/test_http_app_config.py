"""HttpAppConfig.registry threading (M4c T5)."""

from __future__ import annotations

from wazuh_mcp.server import HttpAppConfig


def test_http_app_config_has_registry_field() -> None:
    """HttpAppConfig accepts a registry kwarg."""
    fields = {f.name for f in HttpAppConfig.__dataclass_fields__.values()}
    assert "registry" in fields


def test_http_app_config_registry_default_is_none() -> None:
    """registry defaults to None to preserve backwards compatibility for
    legacy callers that construct HttpAppConfig directly without going
    through load_http_config."""
    field = HttpAppConfig.__dataclass_fields__["registry"]
    assert field.default is None
