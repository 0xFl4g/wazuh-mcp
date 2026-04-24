"""RuleDefinition model + pure XML renderer for M4b write.create_rule and
write.update_rule.

Matches M3's query-builder pattern: NO raw XML from callers. The renderer
escapes every user-controlled string via xml.sax.saxutils.escape so no
tool call can inject sibling elements or disable detection via
`<ignore>*</ignore>` tricks.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal
from xml.sax.saxutils import escape as _xml_escape
from xml.sax.saxutils import quoteattr as _xml_quoteattr

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CUSTOM_RULE_ID_MIN = 100_000
_CUSTOM_RULE_ID_MAX = 999_999


# XML 1.0 legal Char production (https://www.w3.org/TR/xml/#charsets):
#   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
# Anything outside this set (e.g. C0 controls like \x00..\x08, \x0B..\x0C,
# \x0E..\x1F) cannot appear in an XML 1.0 document even via numeric character
# reference. Reject at validation so no user-controlled string can produce
# malformed XML downstream.
_XML_ILLEGAL_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]"
)


def _reject_xml_illegal(v: str) -> str:
    m = _XML_ILLEGAL_CHARS.search(v)
    if m is not None:
        raise ValueError(
            f"value contains character U+{ord(m.group(0)):04X} that is not "
            "valid in XML 1.0"
        )
    return v


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Annotated[int, Field(ge=_CUSTOM_RULE_ID_MIN, le=_CUSTOM_RULE_ID_MAX)]
    level: Annotated[int, Field(ge=0, le=15)]
    description: Annotated[str, Field(min_length=1, max_length=512)]

    if_sid: list[int] | None = None
    if_matched_sid: int | None = None
    match: str | None = None
    regex: str | None = None
    decoded_as: str | None = None
    field: dict[str, str] | None = None
    srcip: str | None = None
    program_name: str | None = None
    groups: list[str] | None = None
    options: list[Literal["no_log", "alert_by_email"]] | None = None

    @field_validator("regex")
    @classmethod
    def _validate_regex(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"regex does not compile: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _check_xml_legal_chars(self) -> RuleDefinition:
        """Reject any string field containing an XML 1.0 illegal character.

        XML 1.0 forbids most C0 control characters (\x00..\x08, \x0B, \x0C,
        \x0E..\x1F), unpaired surrogates, and the non-characters U+FFFE /
        U+FFFF even via numeric character reference. We reject here so the
        renderer never produces output that a strict XML parser rejects.
        """
        for attr in (
            "description",
            "match",
            "regex",
            "decoded_as",
            "srcip",
            "program_name",
        ):
            v = getattr(self, attr)
            if isinstance(v, str):
                _reject_xml_illegal(v)
        if self.field is not None:
            for name, regex in self.field.items():
                _reject_xml_illegal(name)
                _reject_xml_illegal(regex)
        if self.groups is not None:
            for g in self.groups:
                _reject_xml_illegal(g)
                if "," in g:
                    raise ValueError(
                        "group names must not contain ',' (Wazuh separator)"
                    )
        return self


def _el(tag: str, text: str) -> str:
    """Open tag, escaped text, close tag — no attrs."""
    return f"<{tag}>{_xml_escape(text)}</{tag}>"


def _el_with_attr(tag: str, attr_name: str, attr_value: str, text: str) -> str:
    return f"<{tag} {attr_name}={_xml_quoteattr(attr_value)}>{_xml_escape(text)}</{tag}>"


def render_rule_xml(rule: RuleDefinition) -> str:
    """Render a RuleDefinition as a minimal well-formed <rule>...</rule> block.

    Every user-controlled string is XML-escaped. Never accepts raw XML.
    """
    parts: list[str] = [
        f"<rule id={_xml_quoteattr(str(rule.id))} "
        f"level={_xml_quoteattr(str(rule.level))}>"
    ]
    # Description is required.
    parts.append(_el("description", rule.description))
    # Optional parent-rule relationships.
    if rule.if_sid is not None:
        parts.append(_el("if_sid", ", ".join(str(s) for s in rule.if_sid)))
    if rule.if_matched_sid is not None:
        parts.append(_el("if_matched_sid", str(rule.if_matched_sid)))
    # Optional matchers.
    if rule.match is not None:
        parts.append(_el("match", rule.match))
    if rule.regex is not None:
        parts.append(_el("regex", rule.regex))
    if rule.decoded_as is not None:
        parts.append(_el("decoded_as", rule.decoded_as))
    if rule.field is not None:
        for name, regex in rule.field.items():
            parts.append(_el_with_attr("field", "name", name, regex))
    if rule.srcip is not None:
        parts.append(_el("srcip", rule.srcip))
    if rule.program_name is not None:
        parts.append(_el("program_name", rule.program_name))
    # Wazuh's <group> element takes a comma-separated list with a trailing comma.
    if rule.groups is not None:
        parts.append(_el("group", ",".join(rule.groups) + ","))
    if rule.options is not None:
        for opt in rule.options:
            parts.append(_el("options", opt))
    parts.append("</rule>")
    return "".join(parts)
