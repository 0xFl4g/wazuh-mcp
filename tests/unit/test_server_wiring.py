import io
from pathlib import Path

import pytest
from pytest_httpx import HTTPXMock

from wazuh_mcp.auth.config_factory import ConfigSessionFactory
from wazuh_mcp.auth.factory import SessionFactory
from wazuh_mcp.observability.audit import AuditEmitter
from wazuh_mcp.server import build_app, load_config


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "tenants.yaml").write_text(
        """
tenants:
  - tenant_id: acme
    indexer_url: https://wazuh.acme.test:9200
    verify_tls: false
    ca_bundle_path: null
    default_rbac_role: soc_analyst
""".strip()
    )
    (tmp_path / "secrets.yaml").write_text(
        """
acme:
  indexer_user: admin
  indexer_password: pw
""".strip()
    )
    (tmp_path / "server.yaml").write_text(
        """
active_tenant: acme
user_id: alice
""".strip()
    )
    return tmp_path


def test_load_config_builds_factory(config_dir):
    cfg = load_config(config_dir)
    assert isinstance(cfg.factory, SessionFactory)
    assert isinstance(cfg.factory, ConfigSessionFactory)
    assert cfg.tenant.tenant_id == "acme"


def test_build_app_registers_search_alerts(config_dir):
    cfg = load_config(config_dir)
    app = build_app(cfg)
    tool_names = {t.name for t in app._tool_manager.list_tools()}
    assert "alerts.search_alerts" in tool_names


async def test_registered_search_alerts_executes_against_mocked_indexer(
    config_dir, httpx_mock: HTTPXMock
):
    httpx_mock.add_response(
        url="https://wazuh.acme.test:9200/wazuh-alerts-*/_search",
        method="POST",
        json={"hits": {"total": {"value": 0}, "hits": []}},
    )
    cfg = load_config(config_dir)
    audit_buf = io.StringIO()
    app = build_app(cfg, audit=AuditEmitter(stream=audit_buf))
    tool = next(t for t in app._tool_manager.list_tools() if t.name == "alerts.search_alerts")
    result = await tool.fn(time_range="1h")
    assert result.total == 0
    assert result.alerts == []
    assert '"tool": "alerts.search_alerts"' in audit_buf.getvalue()
