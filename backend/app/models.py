from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Component(BaseModel):
    id: str
    name: str
    type: str
    trust_level: str = "internal"
    description: Optional[str] = ""
    properties: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = "Medium"


class DataFlow(BaseModel):
    id: str = ""
    flow_number: str = ""
    description: str = ""
    source_id: str
    target_id: str
    protocol: str
    data_type: str = "application_data"
    assumed: bool = False
    properties: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = "Medium"


class TrustBoundary(BaseModel):
    id: str = ""
    parent_id: Optional[str] = None
    name: str
    boundary_type: str
    components: List[str] = Field(default_factory=list)
    description: Optional[str] = ""
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = "Medium"


class Asset(BaseModel):
    name: str
    sensitivity: str
    location: str
    asset_type: str = "data"
    related_component_id: Optional[str] = None
    related_data_flows: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = "Medium"


class SystemArchitecture(BaseModel):
    components: List[Component]
    flows: List[DataFlow]
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class Threat(BaseModel):
    id: str
    category: str
    stride_category: Optional[str] = None
    affected_stride_categories: List[str] = Field(default_factory=list)
    title: str
    description: str
    severity: str
    likelihood: Optional[str] = "Unknown"
    impact: Optional[str] = "Unknown"
    risk_score: Optional[int] = 0
    confidence: Optional[str] = "Medium"
    confidence_score: Optional[float] = None
    tier: Optional[str] = "Potential"
    status: Optional[str] = "Identified"
    review_status: str = "pending_review"
    affected_flow_refs: List[Dict[str, Any]] = Field(default_factory=list)
    flow_reference_status: str = "not_flow_specific"
    evidence: List[str] = Field(default_factory=list)
    evidence_details: List[Dict[str, Any]] = Field(default_factory=list)
    finding_type: str = "architecture"
    risk_factors: Dict[str, Any] = Field(default_factory=dict)
    preconditions: List[str] = Field(default_factory=list)
    mitigation: str
    component: Optional[str] = None
    data_flow: Optional[str] = None
    asset: Optional[str] = None
    affected_component: Optional[str] = None
    related_data_flow: Optional[str] = None
    root_cause: Optional[str] = None
    realistic_attack_scenario: Optional[str] = None
    attack_scenario: Optional[str] = None
    business_impact: Optional[str] = None
    attack_path: Optional[Dict[str, Any]] = None
    specific_control: Optional[str] = None
    implementation_detail: Optional[str] = None
    optional_config_example: Optional[str] = None
    exposure: Optional[str] = None
    data_sensitivity: Optional[str] = None
    exploit_complexity: Optional[str] = None
    privilege_required: Optional[str] = None
    # What the producing rule claimed before the risk model ran. The risk model
    # runs several times as the architecture is refined, so it needs the original
    # claim to compare against rather than the result of its own previous pass.
    reported_severity: Optional[str] = None
    # "rule" where a curated rule, taxonomy entry or analyst statement authored the
    # severity, "model" where this engine computed it. A generic formula cannot
    # rederive that a privileged pod with a mounted service account token is
    # critical, so an authored severity is a floor the model may raise but not
    # lower. A computed one carries no such authority.
    severity_source: str = "model"
    # Compliance and framework mappings
    owasp_top_10: Optional[List[str]] = Field(default_factory=list)
    cwe: Optional[List[str]] = Field(default_factory=list)
    mitre_attack: Optional[List[str]] = Field(default_factory=list)
    mitre_atlas: Optional[List[str]] = Field(default_factory=list)
    nist_800_53: Optional[List[str]] = Field(default_factory=list)
    # Aggregated and compatibility fields
    affected_components: List[str] = Field(default_factory=list)
    affected_data_flows: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    component_id: Optional[str] = None
    flow_source: Optional[str] = None
    flow_target: Optional[str] = None
    explanation: Optional[Dict[str, Any]] = Field(default_factory=dict)
    review_state: Optional[str] = "open"


class AnalysisResult(BaseModel):
    project_name: str
    summary: str
    threats: List[Threat]
    architecture: SystemArchitecture
    score: Optional[int]
    mermaid_diagram: Optional[str] = None
    diagram: Optional[str] = None
    report_markdown: Optional[str] = None
    timestamp: Optional[str] = None
    attack_chains: Optional[Dict[str, Any]] = None
    ml_enhanced: Optional[Dict[str, Any]] = None
    architecture_insights: Optional[List[Dict[str, Any]]] = None
    coverage: Optional[Dict[str, Any]] = None
    diff_summary: Optional[Dict[str, Any]] = None
    follow_up_questions: Optional[List[Dict[str, Any]]] = None
    evidence_requests: Optional[Dict[str, Any]] = None
    review_summary: Optional[Dict[str, Any]] = None
    domain_context: Optional[Dict[str, Any]] = None
    ai_security_lens: Optional[Dict[str, Any]] = None
    priority_actions: Optional[List[Dict[str, Any]]] = None
    system_model: Optional[Dict[str, Any]] = None
    # The analyzed model in the format the parser accepts, so a reviewer can
    # correct a row and re-analyze instead of rewriting the original description.
    architecture_document: Optional[str] = None
    finding_groups: Optional[Dict[str, List[Threat]]] = None
    risk_methodology: Optional[Dict[str, Any]] = None
    stride_coverage: Optional[Dict[str, Any]] = None
    engine_status: Optional[Dict[str, Any]] = None
    architecture_validation: Optional[Dict[str, Any]] = None
