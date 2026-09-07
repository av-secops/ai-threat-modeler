"""Typed canonical contract for every threat-knowledge record."""

from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


StrideCategory = Literal[
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
]
Severity = Literal["Critical", "High", "Medium", "Low"]


class ApplicabilityContract(BaseModel):
    element_types: List[str] = Field(default_factory=list)
    cloud_platforms: List[str] = Field(default_factory=list)
    cloud_services: List[str] = Field(default_factory=list)
    required_signals: List[str] = Field(default_factory=list)
    excluded_signals: List[str] = Field(default_factory=list)


class DetectionContract(BaseModel):
    auto_detectable: bool = False
    logic: Dict[str, Any] = Field(default_factory=dict)
    evidence_requirement: Literal["explicit", "configuration", "source", "candidate_only"] = "candidate_only"

    @model_validator(mode="after")
    def deterministic_rules_require_logic(self):
        if self.auto_detectable and not self.logic:
            raise ValueError("auto-detectable rules require structured detection logic")
        return self

class ControlContract(BaseModel):
    negating_controls: List[str] = Field(default_factory=list)
    remediation: str


class TaxonomyContract(BaseModel):
    cwe: List[str] = Field(default_factory=list)
    owasp_top_10: List[str] = Field(default_factory=list)
    nist_800_53: List[str] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    mitre_atlas: List[str] = Field(default_factory=list)


class CanonicalThreatRule(BaseModel):
    """One validated rule used consistently by predicates, retrieval, and reports."""

    model_config = ConfigDict(extra="allow")

    id: str
    title: str
    description: str
    attack_vector: str
    stride_category: StrideCategory
    category: StrideCategory
    severity: Severity
    likelihood: Literal["High", "Medium", "Low"]
    components: List[str]
    cloud_platform: List[str] = Field(default_factory=list)
    cloud_services: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    detection: DetectionContract
    applicability: ApplicabilityContract
    controls: ControlContract
    taxonomies: TaxonomyContract
    rule_kind: Literal["deterministic", "candidate"]
    source_module: str
    references: List[str] = Field(default_factory=list)
    framework_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    framework_mapping_issues: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def kind_matches_detection(self):
        expected = "deterministic" if self.detection.auto_detectable else "candidate"
        if self.rule_kind != expected:
            raise ValueError(f"rule_kind must be {expected}")
        if not self.components:
            raise ValueError("at least one component type is required")
        return self
