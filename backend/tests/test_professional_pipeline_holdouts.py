from pathlib import Path

from app.engine.analyzer import ThreatAnalyzer
from app.engine.canonical_model import canonicalize_architecture
from app.engine.iac_parser import IaCParser
from app.engine.parser import ArchitectureParser
from app.models import Component, SystemArchitecture
from app.services.document_ingestion import _extract_structured_text


FIXTURES = Path(__file__).parent / "fixtures" / "professional_holdout"


def test_holdout_structured_yaml_preserves_exact_topology_and_issue():
    payload = (FIXTURES / "structured_architecture.yml").read_bytes()
    text, metadata = _extract_structured_text(payload, ".yml")
    architecture = ArchitectureParser().parse(text)

    assert metadata["structured_kind"] == "architecture"
    assert {item.id for item in architecture.components} == {"portal", "gateway", "claims", "database"}
    assert {(item.source_id, item.target_id) for item in architecture.flows} == {
        ("portal", "gateway"), ("gateway", "claims"), ("claims", "database"),
    }
    assert all(not item.assumed for item in architecture.flows)
    assert architecture.metadata["known_issues"][0]["suggested_threat_id"] == \
        "API-BOLA-TENANT-CONTROL-001"


def test_holdout_vulnerable_kubernetes_separates_facts_from_absence_baselines():
    architecture = IaCParser().parse(
        (FIXTURES / "vulnerable_kubernetes.yml").read_text(encoding="utf-8"), "kubernetes",
    )
    findings = architecture.metadata["iac_findings"]
    by_id = {item["rule_id"]: item for item in findings}

    assert {
        "IAC-K8S-PRIVILEGED-CONTAINER", "IAC-K8S-RUN-AS-ROOT",
        "IAC-K8S-PRIV-ESCALATION", "IAC-K8S-AUTOMOUNT-TOKEN",
        "IAC-K8S-PUBLIC-SERVICE", "IAC-K8S-MISSING-NETWORK-POLICY",
        "IAC-K8S-MISSING-RESOURCE-BOUNDS", "IAC-K8S-MISSING-READONLY-ROOTFS",
    } <= set(by_id)
    assert by_id["IAC-K8S-PRIVILEGED-CONTAINER"]["evidence_kind"] == "explicit"
    assert by_id["IAC-K8S-MISSING-NETWORK-POLICY"]["evidence_kind"] == "absence"


def test_holdout_multicloud_terraform_builds_graph_and_finds_nested_secrets():
    architecture = IaCParser().parse(
        (FIXTURES / "multi_cloud.tf").read_text(encoding="utf-8"), "terraform",
    )
    findings = {item["rule_id"] for item in architecture.metadata["iac_findings"]}
    graph = architecture.metadata["iac_resource_graph"]

    assert {
        "aws_s3_bucket.documents", "aws_lambda_function.processor", "aws_iam_role.processor",
        "azurerm_storage_account.archive", "google_sql_database_instance.analytics",
    } <= set(graph["nodes"])
    assert any(
        edge["source"] == "aws_lambda_function.processor"
        and edge["target"] == "aws_s3_bucket.documents"
        for edge in graph["edges"]
    )
    assert {
        "IAC-AWS-S3-PUBLIC-ACL", "IAC-AWS-LAMBDA-HARDCODED-SECRET",
        "IAC-AWS-IAM-PUBLIC-TRUST", "IAC-AZURE-STORAGE-LEGACY-TLS",
        "IAC-GCP-SQL-PUBLIC",
    } <= findings


def test_holdout_secure_saas_does_not_invent_confirmed_weaknesses():
    result = ThreatAnalyzer().analyze_from_text(
        (FIXTURES / "secure_saas.txt").read_text(encoding="utf-8"),
        "Secure SaaS holdout", use_local_slm=False,
    )

    assert not [item for item in result.threats if item.tier == "Confirmed"]
    assert result.engine_status["quality_gate"]["model_integrity"] == "valid"


def test_holdout_paraphrased_agent_weaknesses_survive_without_heading():
    result = ThreatAnalyzer().analyze_from_text(
        (FIXTURES / "paraphrased_agent.txt").read_text(encoding="utf-8"),
        "Agent holdout", use_local_slm=False,
    )
    confirmed = [item.id for item in result.threats if item.tier == "Confirmed"]

    expected = {
        "GENERIC-TENANT-ISOLATION-001", "GENERIC-INDIRECT-PROMPT-INJECTION-001",
        "GENERIC-AGENT-TOOL-AUTHORIZATION-001", "GENERIC-DELEGATED-CREDENTIAL-SHARING-001",
        "GENERIC-APPROVAL-BYPASS-001", "GENERIC-SENSITIVE-TELEMETRY-001",
        "GENERIC-MCP-PEER-AUTHENTICITY-001", "GENERIC-AGENT-RESOURCE-EXHAUSTION-001",
    }
    assert all(any(finding_id.startswith(rule_id) for finding_id in confirmed) for rule_id in expected)


def test_holdout_conflicting_system_sources_block_publication():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")],
        flows=[],
        metadata={"source_documents": [
            {"filename": "claims.yml", "role": "source_design", "system_name": "Claims SaaS"},
            {"filename": "inventory.yml", "role": "source_design", "system_name": "Inventory SaaS"},
        ]},
    )
    _, validation = canonicalize_architecture(architecture)

    assert validation["valid"] is False
    assert any(item["type"] == "source_conflict" for item in validation["issues"])
