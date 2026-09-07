"""Regression probes for cross-request state and evidence accounting."""

import pytest

from app.engine.analyzer import ThreatAnalyzer
from app.engine.local_intelligence import LocalIntelligence
from app.engine.parser import ArchitectureParser
from app.engine.stride_coverage_engine import StrideCoverageEngine
from app.models import Component, SystemArchitecture, Threat


DESCRIPTION = "A React frontend calls a Node.js REST API over HTTPS. The API reads PostgreSQL over TLS."


def finding(identifier, *, tier="Potential", controls=(), cwe=(), component="api", **kwargs):
    return Threat(
        id=identifier, category="Spoofing", title=identifier, description=identifier,
        severity="High", mitigation="Validate the authentication boundary.", tier=tier,
        component=component, affected_components=[component], cwe=list(cwe),
        explanation={"matched_controls": list(controls)}, **kwargs,
    )


@pytest.fixture
def isolated_analyzer(monkeypatch):
    # These tests exercise deterministic analysis, not installed model weights.
    monkeypatch.setattr(LocalIntelligence, "_initialize", lambda self: None)
    return ThreatAnalyzer()


def test_analysis_does_not_mutate_caller_architecture(isolated_analyzer):
    architecture = ArchitectureParser().parse(DESCRIPTION)
    before = architecture.model_dump()
    isolated_analyzer.analyze(architecture, use_local_slm=False)
    assert architecture.model_dump() == before


def test_result_edits_cannot_poison_parse_cache(isolated_analyzer):
    first = isolated_analyzer.analyze_from_text(DESCRIPTION, use_local_slm=False)
    first.architecture.components[0].name = "CALLER EDIT MUST NOT LEAK"
    first.architecture.metadata["known_issues"] = ["Injected by result consumer"]
    second = isolated_analyzer.analyze_from_text(DESCRIPTION, use_local_slm=False)
    assert second.architecture.components[0].name != "CALLER EDIT MUST NOT LEAK"
    assert "Injected by result consumer" not in second.architecture.metadata.get("known_issues", [])


def test_report_refresh_uses_current_finding_content(isolated_analyzer):
    result = isolated_analyzer.analyze_from_text(DESCRIPTION, use_local_slm=False)
    assert result.threats
    result.threats[0].implementation_detail = "UPDATED REMEDIATION 2026"
    report = isolated_analyzer._generate_report_markdown(result)
    assert "UPDATED REMEDIATION 2026" in report


def test_known_issue_does_not_hide_independent_control_or_scope():
    known = finding("known", tier="Confirmed", controls=["session_revocation"], cwe=["CWE-613"],
                    evidence_details=[{"source_ref": "K1", "statement": "Sessions survive password changes."}])
    auth = finding("auth", controls=["auth_type"], cwe=["CWE-306"])
    duplicate = finding("duplicate", controls=["session_revocation"], cwe=["CWE-613"])
    broader_scope = finding("broader", controls=["session_revocation"])
    broader_scope.affected_components.append("second-api")
    other_flow = finding("flow", controls=["session_revocation"], data_flow="client->api")
    threats = [known, auth, duplicate, broader_scope, other_flow]
    actual = ThreatAnalyzer._suppress_potentials_superseded_by_known_issues(threats)
    assert [t.id for t in actual] == ["known", "auth", "broader", "flow"]


def test_potential_findings_do_not_resolve_unknown_evidence():
    architecture = SystemArchitecture(components=[Component(id="api", name="API", type="API")], flows=[])
    engine = StrideCoverageEngine()
    potential = finding("maybe")
    _, before = engine.assess(architecture, [], generate_candidates=False)
    _, after = engine.assess(architecture, [potential], generate_candidates=False)
    cell = next(c for c in after["cells"] if c["element_id"] == "api" and c["category"] == "Spoofing")
    assert cell["status"] == "potential"
    assert cell["finding_ids"] == ["maybe"]
    assert cell["controls"]
    assert after["evidence_resolution_percent"] == before["evidence_resolution_percent"]


def test_one_confirmed_finding_does_not_resolve_other_controls_in_same_category():
    from app.engine.evidence_requests import build_evidence_requests
    architecture = SystemArchitecture(components=[Component(id="api", name="API", type="API", properties={"rate_limiting": False})], flows=[])
    _, coverage = StrideCoverageEngine().assess(architecture, [])
    cell = next(c for c in coverage["cells"] if c["element_id"] == "api" and c["category"] == "Denial of Service")
    assert cell["status"] == "finding"
    assert "request_size_limit" in cell["unresolved_controls"]
    requests = build_evidence_requests(coverage, architecture)
    assert requests["unresolved_cells"] > 0
    assert coverage["resolved_cells"] + coverage["unknown_cells"] == coverage["applicable_cells"]


def test_disabled_local_ai_does_not_initialize_models(monkeypatch):
    calls = []
    monkeypatch.setattr(LocalIntelligence, "_initialize", lambda self: calls.append("initialized"))
    monkeypatch.setattr("app.engine.local_intelligence.StructuredLocalSLM", lambda: calls.append("generative"))
    intelligence = LocalIntelligence(None)
    _, status = intelligence.enrich(None, [], enabled=False)
    assert status["status"] == "disabled"
    assert calls == []


def test_phase_timings_and_cache_status_are_reported(isolated_analyzer):
    first = isolated_analyzer.analyze_from_text(DESCRIPTION, use_local_slm=False)
    second = isolated_analyzer.analyze_from_text(DESCRIPTION, use_local_slm=False)
    assert first.engine_status["performance"]["parse_cache_hit"] is False
    assert second.engine_status["performance"]["parse_cache_hit"] is True
    for result in (first, second):
        performance = result.engine_status["performance"]
        assert {"parsing", "knowledge", "stride_coverage", "local_intelligence", "reporting"} <= performance["phase_ms"].keys()
        assert all(value >= 0 for value in performance["phase_ms"].values())
        assert sum(performance["phase_ms"].values()) <= performance["total_ms"] + 0.02


def test_refresh_discards_attack_paths_for_removed_findings(isolated_analyzer):
    result = isolated_analyzer.analyze_from_text(
        "React calls a Node.js API over HTTPS. The API writes PHI to PostgreSQL. "
        "PostgreSQL is not encrypted at rest.", use_local_slm=False,
    )
    assert result.attack_chains["paths"]
    result.threats = []
    isolated_analyzer.refresh_result_artifacts(result, use_local_slm=False)
    assert result.attack_chains == {"paths": [], "count": 0}
    assert result.engine_status["quality_gate"]["invalid_attack_paths"] == 0


def test_reattaching_paths_clears_obsolete_per_finding_paths(isolated_analyzer):
    threat = finding("obsolete", tier="Confirmed", attack_path={"id": "old-path"})
    isolated_analyzer._attach_attack_paths([threat], [])
    assert threat.attack_path is None


def test_concurrent_contextual_analyses_keep_their_own_assets(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from app.engine.contextual_threat_engine import ContextualThreatEngine
    from app.models import Asset

    engine = ContextualThreatEngine()
    original = engine._analyze_component
    barrier = Barrier(2)

    def interleaved(*args):
        barrier.wait(timeout=5)
        return original(*args)

    monkeypatch.setattr(engine, "_analyze_component", interleaved)
    def analyze(name):
        architecture = SystemArchitecture(
            components=[Component(id="db", name="DB", type="Database", properties={
                "data_sensitivity": "phi", "encryption_at_rest": False,
                "explicit_negations": ["encryption_at_rest"],
            })], flows=[], assets=[Asset(name=name, sensitivity="phi", location="db", related_component_id="db")],
        )
        return engine.analyze(architecture)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(analyze, ("tenant-a", "tenant-b")))
    assert {t.asset for t in first} == {"tenant-a"}
    assert {t.asset for t in second} == {"tenant-b"}
