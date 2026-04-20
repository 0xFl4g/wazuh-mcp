"""Pydantic models for Wazuh documents.

Shape is version-tolerant: required invariants (id, timestamp, rule) are
strict; optional fields that drift between Wazuh versions are nullable.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class RuleRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    level: int
    description: str
    mitre_ids: list[str] = Field(default_factory=list)

    @classmethod
    def from_source(cls, rule: dict[str, Any]) -> RuleRef:
        mitre = rule.get("mitre") or {}
        mitre_ids = list(mitre.get("id") or [])
        return cls(
            id=str(rule["id"]),
            level=int(rule["level"]),
            description=str(rule["description"]),
            mitre_ids=mitre_ids,
        )


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    timestamp: str
    agent: AgentRef
    rule: RuleRef
    location: str | None = None

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> Alert:
        source = hit.get("_source") or {}
        rule_raw = source.get("rule")
        if rule_raw is None:
            # Let Pydantic raise ValidationError for the missing required field
            return cls.model_validate({"id": str(hit.get("_id", "")), **source})
        return cls(
            id=str(hit.get("_id", "")),
            timestamp=str(source.get("timestamp", "")),
            agent=AgentRef.model_validate(source.get("agent") or {}),
            rule=RuleRef.from_source(rule_raw),
            location=source.get("location"),
        )
