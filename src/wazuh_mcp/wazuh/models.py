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


class Agent(BaseModel):
    """Wazuh agent - shape aligned with Server API /agents responses."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    name: str
    ip: str | None = None
    status: str | None = None  # active | disconnected | pending | never_connected
    os_platform: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    version: str | None = None
    group: list[str] = Field(default_factory=list)
    last_keep_alive: str | None = None
    date_add: str | None = None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> Agent:
        os_info = item.get("os") or {}
        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            ip=item.get("ip"),
            status=item.get("status"),
            os_platform=os_info.get("platform"),
            os_name=os_info.get("name"),
            os_version=os_info.get("version"),
            version=item.get("version"),
            group=list(item.get("group") or []),
            last_keep_alive=item.get("lastKeepAlive"),
            date_add=item.get("dateAdd"),
        )


class Vulnerability(BaseModel):
    """Wazuh 4.8+ vulnerability - sourced from the indexer.

    Field `id` is the CVE identifier (the 4.8+ rename from `cve`).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str  # CVE, e.g. "CVE-2024-1234"
    agent_id: str
    package_name: str
    package_version: str
    severity: str | None = None  # Critical | High | Medium | Low | Unknown
    cvss3_score: float | None = None
    published: str | None = None
    detected_at: str | None = None
    status: str | None = None  # Active | Solved

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> Vulnerability:
        src = hit.get("_source") or {}
        vuln = src.get("vulnerability") or {}
        pkg = src.get("package") or {}
        agent = src.get("agent") or {}
        cvss = (vuln.get("scores") or {}).get("base", {})
        return cls(
            id=str(vuln.get("id") or ""),
            agent_id=str(agent.get("id") or ""),
            package_name=str(pkg.get("name") or ""),
            package_version=str(pkg.get("version") or ""),
            severity=vuln.get("severity"),
            cvss3_score=cvss.get("score"),
            published=vuln.get("published_at"),
            detected_at=vuln.get("detected_at"),
            status=vuln.get("status"),
        )


class FimEvent(BaseModel):
    """File-integrity-monitoring event - from `wazuh-alerts-*` (rule groups
    include `syscheck` and friends).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    agent_id: str
    timestamp: str
    path: str
    event: str | None = None  # added | modified | deleted
    sha256_after: str | None = None
    md5_after: str | None = None
    size_after: int | None = None
    uid_after: str | None = None
    gid_after: str | None = None

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> FimEvent:
        src = hit.get("_source") or {}
        syscheck = src.get("syscheck") or {}
        agent = src.get("agent") or {}
        return cls(
            agent_id=str(agent.get("id") or ""),
            timestamp=str(src.get("timestamp") or ""),
            path=str(syscheck.get("path") or ""),
            event=syscheck.get("event"),
            sha256_after=syscheck.get("sha256_after"),
            md5_after=syscheck.get("md5_after"),
            size_after=syscheck.get("size_after"),
            uid_after=syscheck.get("uid_after"),
            gid_after=syscheck.get("gid_after"),
        )


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique reference - sourced from Wazuh's bundled MITRE
    dataset via the Server API (/mitre/techniques).
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str  # e.g. "T1110.001"
    name: str
    description: str | None = None
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> MitreTechnique:
        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            description=item.get("description"),
            tactics=list(item.get("tactics") or []),
            url=item.get("url"),
        )
