"""M3 query-builder tests — validation + clamping + time/size caps."""

import pytest

from wazuh_mcp.wazuh.query import (
    build_alerts_by_agent_query,
    build_alerts_by_mitre_query,
    build_fim_changes_by_agent_query,
    build_fim_history_for_path_query,
    build_get_alert_query,
    build_search_vulnerabilities_query,
    build_vulnerabilities_by_agent_query,
)


def test_get_alert_rejects_path_traversal():
    with pytest.raises(ValueError):
        build_get_alert_query("../evil")


def test_get_alert_shape():
    q = build_get_alert_query("abc123")
    assert q["query"]["term"]["_id"] == "abc123"
    assert q["size"] == 1


def test_alerts_by_agent_clamps_size():
    q = build_alerts_by_agent_query(agent_id="001", time_range="1h", size=500)
    assert q["size"] == 100


def test_alerts_by_agent_rejects_bad_id():
    with pytest.raises(ValueError):
        build_alerts_by_agent_query(agent_id="0x01", time_range="1h")


def test_alerts_by_mitre_rejects_bad_technique():
    with pytest.raises(ValueError):
        build_alerts_by_mitre_query(technique_id="not-a-technique", time_range="1h")


def test_alerts_by_mitre_shape():
    q = build_alerts_by_mitre_query(technique_id="T1110.001", time_range="24h")
    must = q["query"]["bool"]["must"]
    assert {"term": {"rule.mitre.id": "T1110.001"}} in must


def test_vulns_by_agent_severity_filter_gte():
    q = build_vulnerabilities_by_agent_query(agent_id="001", min_severity="Medium")
    terms = next(c for c in q["query"]["bool"]["must"] if "terms" in c)
    assert terms["terms"]["vulnerability.severity"] == ["Medium", "High", "Critical"]


def test_vulns_by_agent_rejects_bad_severity():
    with pytest.raises(ValueError):
        build_vulnerabilities_by_agent_query(agent_id="001", min_severity="Catastrophic")


def test_search_vulns_requires_at_least_one_filter():
    with pytest.raises(ValueError):
        build_search_vulnerabilities_query()


def test_search_vulns_cve_format_enforced():
    with pytest.raises(ValueError):
        build_search_vulnerabilities_query(cve_id="2024-1234")
    q = build_search_vulnerabilities_query(cve_id="CVE-2024-1234")
    assert {"term": {"vulnerability.id": "CVE-2024-1234"}} in q["query"]["bool"]["must"]


def test_fim_history_rejects_empty_path():
    with pytest.raises(ValueError):
        build_fim_history_for_path_query(path="", time_range="24h")


def test_fim_history_rejects_huge_path():
    with pytest.raises(ValueError):
        build_fim_history_for_path_query(path="A" * 2048, time_range="24h")


def test_fim_changes_by_agent_shape():
    q = build_fim_changes_by_agent_query(agent_id="001", time_range="24h")
    must = q["query"]["bool"]["must"]
    assert any(c == {"exists": {"field": "syscheck.path"}} for c in must)
