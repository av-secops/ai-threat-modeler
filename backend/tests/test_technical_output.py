from app.engine.analyzer import ThreatAnalyzer
from app.engine.iac_parser import IaCParser


def test_iac_analysis_emits_a_technical_threat_model_contract():
    terraform = '''
resource "aws_db_instance" "primary" {
  publicly_accessible = true
  storage_encrypted = false
}
'''
    architecture = IaCParser().parse(terraform, format_hint="terraform")
    result = ThreatAnalyzer().analyze(architecture, "Technical Output")

    assert set(result.system_model) >= {
        "components", "assets", "data_flows", "trust_boundaries",
        "public_entry_points", "identities", "cloud_resources", "boundary_crossings",
    }
    # v4 deduplicates root risks before scoring and reports uncertainty separately.
    assert result.risk_methodology["version"] == "technical-v4"
    assert result.risk_methodology["score_breakdown"]["unique_risk_groups"] > 0
    assert result.finding_groups["iac"]

    finding = result.finding_groups["iac"][0]
    assert finding.tier == "Confirmed"
    assert finding.evidence_details[0]["source_type"] == "iac"
    assert finding.risk_factors["evidence_confidence"] == "High"
    assert finding.preconditions

    # An isolated resource is an exploit scenario, not a graph attack path.
    assert result.attack_chains["paths"] == []
    assert finding.attack_path is None
    assert finding.explanation["attack_path_reason"] in {"no_reachable_entry", "no_explicit_hop"}

    assert "## 5. Technical Findings" in result.report_markdown
    assert "## 6. Evidence-Backed Attack Paths" in result.report_markdown
    assert "## 7. Risk Calculation" in result.report_markdown
