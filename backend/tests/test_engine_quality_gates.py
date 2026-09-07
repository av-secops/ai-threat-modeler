from app.engine.canonical_model import canonicalize_architecture
from app.engine.analyzer import ThreatAnalyzer
from app.engine.confidence_calibration import ConfidenceCalibrator
from app.engine.deduplication_engine import deduplicate_threats
from app.engine.parser import ArchitectureParser
from app.engine.specialist_router import SpecialistRouter
from app.engine.specialist_orchestrator import SpecialistOrchestrator
from app.engine.local_challenger import LocalChallenger
from app.engine.structured_local_slm import StructuredLocalSLM
from app.engine.stride_coverage_engine import StrideCoverageEngine
from app.knowledge_base.loader import _normalize_stride
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.knowledge_base.contracts import CanonicalThreatRule
from app.models import Component, DataFlow, SystemArchitecture, Threat
from app.services.llm_analyzer import LLMAnalyzer


def _threat(threat_id="T-1", component="api", evidence=None):
    return Threat(
        id=threat_id,
        category="Tampering",
        stride_category="Tampering",
        title="Untrusted input can alter state",
        description="Input reaches a state-changing operation.",
        severity="High",
        mitigation="Validate input and authorize the operation.",
        component=component,
        affected_component=component,
        affected_components=[component] if component else [],
        root_cause="Missing integrity validation",
        cwe=["CWE-20"],
        evidence=evidence or [],
    )


def test_unknown_taxonomy_does_not_default_to_tampering():
    assert _normalize_stride("not-a-real-category") == "Unknown"


def test_unknown_control_state_surfaces_only_as_potential_architecture_threat():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API", trust_level="public")],
        flows=[],
    )
    candidates, coverage = StrideCoverageEngine().assess(architecture, [], generate_candidates=True)

    assert len(candidates) == 6
    assert all(candidate.tier == "Potential" for candidate in candidates)
    assert all(candidate.explanation["control_state"] == "unknown" for candidate in candidates)
    assert coverage["unknown_cells"] > 0
    assert all(cell["status"] != "finding" for cell in coverage["cells"] if not cell["finding_ids"])


def test_canonical_gate_rejects_duplicate_ids_and_dangling_flows():
    architecture = SystemArchitecture(
        components=[
            Component(id="api", name="API One", type="API"),
            Component(id="api", name="API Two", type="API"),
        ],
        flows=[DataFlow(source_id="api", target_id="missing", protocol="HTTPS")],
    )
    _, validation = canonicalize_architecture(architecture)

    assert validation["valid"] is False
    assert validation["quality_gate"]["status"] == "fail"
    assert {item["type"] for item in validation["issues"]} >= {
        "duplicate_component_id", "invalid_flow",
    }


def test_specialist_router_activates_only_evidenced_conditional_packs():
    architecture = SystemArchitecture(
        components=[
            Component(id="lambda", name="AWS Lambda", type="Service", properties={"cloud_provider": "aws"}),
            Component(id="agent", name="LLM Agent", type="ML Service", properties={"tool_execution": True}),
        ],
        flows=[],
        metadata={"architecture_text": "AWS Lambda invokes an LLM agent through an MCP server."},
    )
    route = SpecialistRouter().route(architecture, [
        "cloud_aws_threats.json", "cloud_azure_threats.json", "ai_agent_threats.json",
        "custom_ai_llm_threats.json", "owasp_api_top10.json",
    ])

    assert "aws_cloud" in route["active_specialists"]
    assert "ai_agent_mcp" in route["active_specialists"]
    assert "cloud_aws_threats.json" in route["active_modules"]
    assert "cloud_azure_threats.json" not in route["active_modules"]


def test_specialist_router_ignores_inactive_property_names():
    architecture = SystemArchitecture(
        components=[Component(
            id="api", name="GraphQL API", type="API",
            properties={"containerized": False, "cloud_provider": "unknown", "ml_pipeline": False},
        )],
        flows=[],
        metadata={"architecture_text": "A React portal calls a GraphQL API backed by PostgreSQL."},
    )
    route = SpecialistRouter().route(architecture, [
        "cloud_aws_threats.json", "container_k8s_threats.json", "ai_agent_threats.json",
        "owasp_api_top10.json",
    ])

    assert "aws_cloud" not in route["active_specialists"]
    assert "kubernetes_container" not in route["active_specialists"]
    assert "ai_agent_mcp" not in route["active_specialists"]


def test_short_cloud_service_names_do_not_match_ordinary_words():
    architecture = ArchitectureParser().parse(
        "A GraphQL API uses PostgreSQL to store tenant records and Redis for sessions."
    )

    databases = [item for item in architecture.components if item.type == "Database"]
    assert databases
    assert all((item.properties or {}).get("cloud_provider") is None for item in databases)


def test_every_knowledge_record_uses_the_typed_contract():
    knowledge_base = ThreatKnowledgeBase()

    assert len(knowledge_base.get_typed_rules()) == len(knowledge_base.get_all_threats())
    assert all(isinstance(item, CanonicalThreatRule) for item in knowledge_base.get_typed_rules())
    assert all(
        item.rule_kind == ("deterministic" if item.detection.auto_detectable else "candidate")
        for item in knowledge_base.get_typed_rules()
    )


def test_architecture_ir_distinguishes_explicit_and_inferred_flows():
    architecture = ArchitectureParser().parse(
        "React calls API Gateway over HTTPS. API Gateway invokes Order Service. PostgreSQL stores orders."
    )
    architecture, validation = canonicalize_architecture(architecture)
    ir = architecture.metadata["architecture_ir"]

    assert validation["valid"] is True
    assert ir["version"] == "architecture-ir-1.0"
    assert any(item["claim_status"] == "explicit" for item in ir["flows"])
    assert all(item["evidence"] for item in ir["components"])


def test_local_challenger_returns_questions_not_findings():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API", trust_level="public")],
        flows=[],
        metadata={"architecture_text": "A public API receives requests."},
    )
    retrieved = [{
        "id": "API-CANDIDATE",
        "title": "API authentication weakness",
        "stride_category": "Spoofing",
        "category": "Spoofing",
        "retrieval_score": 0.8,
        "retrieved_for": ["api:Spoofing"],
        "applicability": {"required_signals": ["authentication explicitly absent"]},
        "negating_controls": ["strong_authentication"],
    }]

    result = LocalChallenger().challenge(architecture, [], retrieved)

    assert result["finding_authority"] is False
    assert result["review_candidates"][0]["status"] == "information_required"


def test_local_challenger_uses_the_score_for_each_element_scope():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API", trust_level="public")],
        flows=[], metadata={"architecture_text": "A public API receives requests."},
    )
    retrieved = [{
        "id": "API-CANDIDATE", "title": "API authentication weakness",
        "stride_category": "Spoofing", "retrieval_score": 0.9,
        "retrieved_for": ["api:Spoofing"],
        "retrieval_scores_by_scope": {"api:Spoofing": 0.31},
    }]

    result = LocalChallenger().challenge(architecture, [], retrieved)

    assert result["review_candidates"] == []
    assert result["review_candidate_count"] == 0


def test_structured_local_slm_rejects_hallucinated_scope_and_evidence():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")], flows=[],
    )
    source = "The public API uses JWT authentication."
    unknown = [{"element_id": "api", "category": "Spoofing"}]
    accepted, rejected = StructuredLocalSLM.validate_candidates([
        {
            "element_id": "api", "stride_category": "Spoofing",
            "title": "Review token validation", "evidence": [source],
        },
        {
            "element_id": "invented", "stride_category": "Tampering",
            "title": "Invented database", "evidence": ["MySQL is public"],
        },
    ], architecture, source, unknown)

    assert len(accepted) == 1
    assert accepted[0]["status"] == "information_required"
    assert rejected == 1


def test_inline_known_issues_are_split_and_excluded_from_topology():
    description = (
        "React calls a Node.js REST API backed by PostgreSQL. "
        "Known issues: Redis does not require TLS or authentication. "
        "OAuth refresh tokens are not rotated. "
        "The FHIR partner endpoint does not require mutual TLS."
    )

    architecture = ArchitectureParser().parse(description)

    assert len(architecture.metadata["known_issues"]) == 3
    assert not any(component.name.lower() == "redis" for component in architecture.components)


def test_simple_node_keycloak_ec2_s3_architecture_returns_stride_risks():
    description = (
        "A website built with Node.js. Authentication is managed by Keycloak. "
        "The backend is hosted on AWS EC2 and uses an S3 bucket for image storage."
    )

    result = ThreatAnalyzer().analyze_from_text(
        description,
        project_name="Node Keycloak EC2 S3",
        use_local_slm=False,
        analysis_mode="deep",
    )
    components = {component.id: component for component in result.architecture.components}
    flow_pairs = {(flow.source_id, flow.target_id) for flow in result.architecture.flows}

    assert {"web_application", "node_js", "keycloak", "ec2", "s3"} <= set(components)
    assert components["node_js"].name == "Node.js Backend"
    assert components["ec2"].name == "EC2"
    assert components["s3"].properties.get("ml_pipeline") is not True
    assert components["s3"].properties.get("public_access") is None
    assert {
        ("web_application", "node_js"),
        ("node_js", "keycloak"),
        ("node_js", "s3"),
    } <= flow_pairs
    assert len(result.threats) >= 6
    assert {threat.stride_category for threat in result.threats} == {
        "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
        "Denial of Service", "Elevation of Privilege",
    }
    assert all(threat.tier == "Potential" for threat in result.threats)
    assert all((threat.explanation or {}).get("control_state") in {"unknown", "partial"} for threat in result.threats)


def test_omission_challenger_accepts_concrete_alias_representations():
    architecture = ArchitectureParser().parse(
        "A React frontend calls an Express REST API. An AI agent uses an MCP shell executor."
    )

    omitted = LocalChallenger._omitted_literal_components(architecture)

    assert not {item["technology"] for item in omitted} & {"frontend", "rest api", "shell executor"}


def test_specialist_orchestrator_reports_static_source_adapters():
    knowledge_base = ThreatKnowledgeBase()
    architecture = SystemArchitecture(
        components=[Component(id="bucket", name="S3 Bucket", type="Object Storage")],
        flows=[],
        metadata={"architecture_text": "AWS S3 bucket", "iac_findings": [{"id": "IAC-1"}]},
    )

    _, diagnostics = SpecialistOrchestrator(knowledge_base).analyze(architecture)

    assert "iac_static_analysis" in diagnostics["source_adapters"]
    assert "aws_cloud" in diagnostics["active_specialists"]


def test_confidence_calibration_requires_direct_evidence_for_confirmation():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")], flows=[],
    )
    direct = _threat(component="api", evidence=["Explicit source issue"])
    direct.evidence_details = [{
        "source_type": "architecture_input", "source_ref": "K1", "statement": "Explicit source issue",
    }]
    challenger = _threat(threat_id="T-CHALLENGER", component="api", evidence=["Model suggestion"])
    challenger.evidence_details = [{
        "source_type": "llm_challenger", "source_ref": "architecture input", "statement": "Model suggestion",
    }]

    calibrated, diagnostics = ConfidenceCalibrator().calibrate([direct, challenger], architecture)

    assert calibrated[0].tier == "Confirmed"
    assert calibrated[0].confidence_score >= 0.8
    assert calibrated[1].tier == "Potential"
    assert calibrated[1].confidence_score < 0.8
    assert diagnostics["version"] == "confidence-1.0"


def test_llm_challenger_rejects_unmapped_or_unsupported_output():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="FastAPI", type="API")],
        flows=[],
    )
    source = "A FastAPI service receives prompts from users."
    ungrounded = _threat(component="invented", evidence=["A technology that is not in the input"])
    grounded = _threat(threat_id="T-2", component="api", evidence=[source])

    validated = LLMAnalyzer.validate_llm_threats([ungrounded, grounded], architecture, source)

    assert [item.id for item in validated] == ["LLM-CHALLENGER-T-2"]
    assert validated[0].tier == "Potential"
    assert validated[0].explanation["validation_status"] == "grounded_challenger"


def test_deduplication_does_not_merge_different_components():
    left = _threat(threat_id="T-LEFT", component="api_one")
    right = _threat(threat_id="T-RIGHT", component="api_two")

    assert len(deduplicate_threats([left, right])) == 2
