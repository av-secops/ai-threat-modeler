"""The gate must distinguish a report that contradicts itself from a report that
may be incomplete. Only the former blocks publication."""

from app.engine.analyzer import ThreatAnalyzer
from app.models import Component, SystemArchitecture, Threat


VALID = {"valid": True}
NO_COVERAGE_CONCERN = {"unknown_cells": 0, "applicable_cells": 0}
gate = ThreatAnalyzer._runtime_quality_gate


def _threat(tier="Confirmed", component="api", evidence=True, origin=None):
    return Threat(
        id="T-1",
        category="Tampering",
        stride_category="Tampering",
        title="Finding",
        description="Description",
        severity="High",
        mitigation="Fix it.",
        component=component,
        affected_component=component,
        affected_components=[component] if component else [],
        root_cause="Cause",
        tier=tier,
        evidence_details=[{"source_ref": "K1", "statement": "Stated in input"}] if evidence else [],
        explanation={"origin": origin} if origin else {},
    )


def _architecture(known_issues=0):
    return SystemArchitecture(
        components=[Component(id="api", name="API", type="API")],
        flows=[],
        metadata={"known_issues": [{"description": f"issue {index}"} for index in range(known_issues)]},
    )


def test_a_coherent_model_is_ready_to_publish():
    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=_architecture())

    assert result["status"] == "ready"
    assert result["model_integrity"] == "valid"
    assert result["integrity_violations"] == []
    assert result["completeness_warnings"] == []


def test_status_and_publication_status_never_disagree():
    for threats in ([_threat()], [_threat(evidence=False)], [_threat(tier="Potential", component=None)]):
        result = gate(VALID, threats, NO_COVERAGE_CONCERN, architecture=_architecture())

        assert result["status"] == result["publication_status"]


def test_confirmed_finding_without_evidence_blocks_publication():
    result = gate(VALID, [_threat(evidence=False)], NO_COVERAGE_CONCERN, architecture=_architecture())

    assert result["status"] == "blocked"
    assert result["model_integrity"] == "violated"
    assert [item["check"] for item in result["integrity_violations"]] == ["confirmed_without_evidence"]


def test_confirmed_finding_without_scope_blocks_publication():
    result = gate(VALID, [_threat(component=None)], NO_COVERAGE_CONCERN, architecture=_architecture())

    assert result["status"] == "blocked"
    assert "confirmed_without_scope" in {item["check"] for item in result["integrity_violations"]}


def test_invalid_topology_blocks_publication():
    result = gate({"valid": False}, [_threat()], NO_COVERAGE_CONCERN, architecture=_architecture())

    assert result["status"] == "blocked"
    assert "invalid_topology" in {item["check"] for item in result["integrity_violations"]}


def test_a_declared_known_issue_that_no_finding_reports_blocks_publication():
    """Losing a stated fact is an integrity failure, not a coverage gap."""
    reported = _threat(origin="declared_known_issue")
    result = gate(VALID, [reported], NO_COVERAGE_CONCERN, architecture=_architecture(known_issues=3))

    assert result["status"] == "blocked"
    assert result["declared_known_issues"] == 3
    assert result["reported_known_issues"] == 1
    violation = next(
        item for item in result["integrity_violations"]
        if item["check"] == "declared_known_issue_not_reported"
    )
    assert violation["count"] == 2


def test_every_declared_known_issue_reported_satisfies_the_invariant():
    threats = [_threat(origin="declared_known_issue") for _ in range(3)]
    result = gate(VALID, threats, NO_COVERAGE_CONCERN, architecture=_architecture(known_issues=3))

    assert result["status"] == "ready"


def test_an_omitted_component_asks_for_review_rather_than_blocking():
    """One missed component must not withhold every finding in the report."""
    diagnostics = {"challenger": {"omitted_component_count": 2, "duplicate_alias_count": 1}}
    result = gate(
        VALID, [_threat()], NO_COVERAGE_CONCERN,
        local_diagnostics=diagnostics, architecture=_architecture(),
    )

    assert result["status"] == "review"
    assert result["model_integrity"] == "valid"
    assert result["integrity_violations"] == []
    assert {item["check"] for item in result["completeness_warnings"]} == {
        "omitted_named_components", "duplicate_component_aliases",
    }


def test_low_control_determination_requires_conditional_review():
    coverage = {"unknown_cells": 52, "applicable_cells": 64}
    result = gate(VALID, [_threat()], coverage, architecture=_architecture())

    assert result["status"] == "review"
    assert [item["check"] for item in result["completeness_warnings"]] == [
        "low_determined_control_coverage",
    ]
    assert result["unknown_stride_cells"] == 52
    assert result["determined_control_ratio"] == 0.188


def test_unresolved_engine_disagreement_asks_for_review():
    result = gate(
        VALID, [_threat()], NO_COVERAGE_CONCERN,
        disagreement_diagnostics={"unresolved_count": 4}, architecture=_architecture(),
    )

    assert result["status"] == "review"
    assert [item["check"] for item in result["completeness_warnings"]] == [
        "unresolved_engine_disagreements",
    ]
