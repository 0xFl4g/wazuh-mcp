"""RuleDefinition model + render_rule_xml pure function."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from pydantic import ValidationError

from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml


def _parse(xml: str) -> ET.Element:
    return ET.fromstring(xml)


def _find(el: ET.Element, tag: str) -> ET.Element:
    """Find a child element by tag and assert it is present (for ty)."""
    found = el.find(tag)
    assert found is not None, f"expected child <{tag}> in <{el.tag}>"
    return found


def test_minimal_rule() -> None:
    r = RuleDefinition(id=100_100, level=5, description="Failed SSH login")
    x = render_rule_xml(r)
    root = _parse(x)
    assert root.tag == "rule"
    assert root.attrib == {"id": "100100", "level": "5"}
    assert _find(root, "description").text == "Failed SSH login"


def test_rule_with_if_sid_list() -> None:
    r = RuleDefinition(id=100_200, level=10, description="d", if_sid=[5710, 5711])
    x = render_rule_xml(r)
    root = _parse(x)
    if_sids = root.findall("if_sid")
    assert len(if_sids) == 1
    assert if_sids[0].text == "5710, 5711"


def test_rule_with_match() -> None:
    r = RuleDefinition(id=100_300, level=3, description="d", match="failed login")
    x = render_rule_xml(r)
    root = _parse(x)
    assert _find(root, "match").text == "failed login"


def test_rule_with_regex_compile_fail_rejects_at_args_parse() -> None:
    with pytest.raises(ValidationError, match="regex"):
        RuleDefinition(id=100_400, level=3, description="d", regex="(unclosed")


def test_rule_with_groups() -> None:
    r = RuleDefinition(
        id=100_500, level=7, description="d", groups=["authentication_failed", "syslog"]
    )
    x = render_rule_xml(r)
    root = _parse(x)
    assert _find(root, "group").text == "authentication_failed,syslog,"


def test_rule_with_field_dict() -> None:
    r = RuleDefinition(id=100_600, level=4, description="d", field={"user.name": "^root$"})
    x = render_rule_xml(r)
    root = _parse(x)
    fields = root.findall("field")
    assert len(fields) == 1
    assert fields[0].attrib == {"name": "user.name"}
    assert fields[0].text == "^root$"


def test_xml_escapes_user_strings_match() -> None:
    """No tool call can inject sibling elements via < or & in description/match."""
    r = RuleDefinition(
        id=100_700,
        level=3,
        description="alert for <script>alert(1)</script> & friends",
        match='password="hunter2"',
    )
    x = render_rule_xml(r)
    # The output must parse cleanly and contain escaped entities, not literal markup.
    root = _parse(x)
    assert _find(root, "description").text == "alert for <script>alert(1)</script> & friends"
    assert _find(root, "match").text == 'password="hunter2"'
    # Belt-and-braces: the raw string should contain escaped entities.
    assert "&lt;" in x or "&amp;" in x or "&quot;" in x


def test_xml_has_no_sibling_elements_outside_rule() -> None:
    """Even an attacker-style description cannot produce extra top-level elements."""
    r = RuleDefinition(
        id=100_800,
        level=3,
        description='</rule><rule id="999999" level="15"><match>x',
    )
    x = render_rule_xml(r)
    # Wrap in a root so ElementTree can parse multiple top-level elements.
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    # Exactly one <rule> child — no injection.
    rule_children = [c for c in root if c.tag == "rule"]
    assert len(rule_children) == 1
    assert rule_children[0].attrib["id"] == "100800"


def test_id_range_validation() -> None:
    # Valid custom rule range: 100_000 - 999_999
    with pytest.raises(ValidationError):
        RuleDefinition(id=99_999, level=3, description="d")
    with pytest.raises(ValidationError):
        RuleDefinition(id=1_000_000, level=3, description="d")


def test_level_range_validation() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=-1, description="d")
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=16, description="d")


def test_description_length_limit() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=3, description="x" * 513)


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition(id=100_001, level=3, description="d", unknown_field="x")
