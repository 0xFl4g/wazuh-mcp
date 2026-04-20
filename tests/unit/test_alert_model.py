import pytest
from pydantic import ValidationError

from wazuh_mcp.wazuh.models import Alert

SAMPLE_HIT = {
    "_id": "alert-abc-123",
    "_source": {
        "timestamp": "2026-04-20T10:00:00.000+0000",
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
    },
}


def test_alert_from_hit_parses_required_fields():
    alert = Alert.from_hit(SAMPLE_HIT)
    assert alert.id == "alert-abc-123"
    assert alert.timestamp.startswith("2026-04-20")
    assert alert.agent.id == "001"
    assert alert.agent.name == "web-01"
    assert alert.rule.id == "5710"
    assert alert.rule.level == 5
    assert alert.rule.mitre_ids == ["T1110.001"]


def test_alert_missing_source_raises():
    with pytest.raises(ValidationError):
        Alert.from_hit({"_id": "x"})


def test_alert_missing_rule_raises():
    hit = {"_id": "x", "_source": {"timestamp": "2026-04-20T10:00:00.000+0000"}}
    with pytest.raises(ValidationError):
        Alert.from_hit(hit)


def test_alert_default_agent_when_absent():
    hit = {
        "_id": "mgr-1",
        "_source": {
            "timestamp": "2026-04-20T10:00:00.000+0000",
            "rule": {"id": "500", "level": 3, "description": "manager event"},
        },
    }
    alert = Alert.from_hit(hit)
    assert alert.agent.id is None
    assert alert.agent.name is None
