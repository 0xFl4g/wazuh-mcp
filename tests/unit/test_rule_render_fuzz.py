"""Hypothesis fuzz: no generated RuleDefinition produces malformed XML or
XML with injected sibling elements."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from hypothesis import given
from hypothesis import strategies as st

from wazuh_mcp.wazuh.rule_render import RuleDefinition, render_rule_xml

_ids = st.integers(min_value=100_000, max_value=999_999)
_levels = st.integers(min_value=0, max_value=15)
# Characters from the XML 1.0 Char production minus surrogates, U+FFFE, U+FFFF —
# i.e. the set the validator accepts. The hypothesis text strategy by default
# emits codepoints (including C0 controls) that XML 1.0 forbids; restricting the
# alphabet lets us fuzz valid inputs without discarding 99% of cases.
_xml_safe_alphabet = st.characters(
    min_codepoint=0x20,
    max_codepoint=0xFFFD,
    blacklist_categories=("Cs",),  # drop lone surrogates
)
_short_text = st.text(alphabet=_xml_safe_alphabet, min_size=1, max_size=128)
_optional_text = st.one_of(st.none(), _short_text)
_optional_sid_list = st.one_of(
    st.none(),
    st.lists(st.integers(min_value=1, max_value=999_999), min_size=1, max_size=5),
)


@given(
    id=_ids,
    level=_levels,
    description=_short_text,
    match=_optional_text,
    if_sid=_optional_sid_list,
)
def test_every_rule_parses_and_has_single_rule_child(id, level, description, match, if_sid):
    r = RuleDefinition(id=id, level=level, description=description, match=match, if_sid=if_sid)
    x = render_rule_xml(r)
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    children = list(root)
    assert len(children) == 1
    assert children[0].tag == "rule"


# Strategy that guarantees at least one XML-unsafe char is present — avoids the
# filter-too-much health check that firing .filter() on st.text() triggers.
_unsafe_char = st.sampled_from(list("<>&\"'"))


@st.composite
def _text_with_unsafe_char(draw: st.DrawFn) -> str:
    prefix = draw(st.text(alphabet=_xml_safe_alphabet, max_size=64))
    middle = draw(_unsafe_char)
    suffix = draw(st.text(alphabet=_xml_safe_alphabet, max_size=63))
    return prefix + middle + suffix


@given(description=_text_with_unsafe_char())
def test_xml_unsafe_characters_always_escaped_in_description(description):
    r = RuleDefinition(id=100_001, level=3, description=description)
    x = render_rule_xml(r)
    wrapped = f"<root>{x}</root>"
    root = ET.fromstring(wrapped)
    rule = root.find("rule")
    assert rule is not None
    desc = rule.find("description")
    assert desc is not None
    # Must roundtrip exactly.
    assert desc.text == description
