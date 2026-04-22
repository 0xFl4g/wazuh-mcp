"""M3 Pydantic model tests - Agent, Vulnerability, FimEvent, MitreTechnique."""

import pytest
from pydantic import ValidationError

from wazuh_mcp.wazuh.models import (
    Agent,
    FimEvent,
    MitreTechnique,
    Vulnerability,
)


def test_agent_from_api_minimal():
    a = Agent.from_api({"id": "001", "name": "web-01"})
    assert a.id == "001"
    assert a.name == "web-01"
    assert a.group == []


def test_agent_from_api_full():
    a = Agent.from_api(
        {
            "id": "001",
            "name": "web-01",
            "ip": "10.0.0.5",
            "status": "active",
            "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "22.04"},
            "version": "Wazuh v4.9.0",
            "group": ["default", "linux"],
            "lastKeepAlive": "2026-04-22T00:00:00Z",
            "dateAdd": "2024-01-01T00:00:00Z",
        }
    )
    assert a.ip == "10.0.0.5"
    assert a.os_platform == "ubuntu"
    assert a.group == ["default", "linux"]


def test_agent_frozen():
    a = Agent.from_api({"id": "001", "name": "w"})
    with pytest.raises(ValidationError):
        a.id = "002"  # type: ignore[misc]


def test_vulnerability_uses_id_not_cve():
    """4.8+ field rename: vulnerability.cve -> vulnerability.id."""
    v = Vulnerability.from_hit(
        {
            "_source": {
                "agent": {"id": "001"},
                "package": {"name": "openssl", "version": "3.0.0"},
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "scores": {"base": {"score": 7.5}},
                    "published_at": "2024-06-01T00:00:00Z",
                    "status": "Active",
                },
            }
        }
    )
    assert v.id == "CVE-2024-1234"
    assert v.severity == "High"
    assert v.cvss3_score == 7.5


def test_fim_event_from_hit():
    ev = FimEvent.from_hit(
        {
            "_source": {
                "agent": {"id": "001"},
                "timestamp": "2026-04-22T00:00:00Z",
                "syscheck": {
                    "path": "/etc/passwd",
                    "event": "modified",
                    "sha256_after": "abc123",
                },
            }
        }
    )
    assert ev.path == "/etc/passwd"
    assert ev.event == "modified"
    assert ev.sha256_after == "abc123"


def test_mitre_technique_from_api():
    t = MitreTechnique.from_api(
        {
            "id": "T1110.001",
            "name": "Password Guessing",
            "description": "...",
            "tactics": ["Credential Access"],
            "url": "https://attack.mitre.org/techniques/T1110/001/",
        }
    )
    assert t.id == "T1110.001"
    assert t.tactics == ["Credential Access"]
