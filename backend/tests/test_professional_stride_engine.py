import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from app.engine.analyzer import ThreatAnalyzer
from app.engine.stride_coverage_engine import STRIDE_CATEGORIES
from app.knowledge_base.loader import ThreatKnowledgeBase


SCENARIOS = json.loads(
    (Path(__file__).parent / "fixtures" / "golden_scenarios.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def analyzer():
    return ThreatAnalyzer()


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: item["id"])
def test_golden_scenario_is_exhaustive_grounded_and_actionable(analyzer, scenario):
    result = analyzer.analyze_from_text(
        scenario["description"],
        scenario["id"],
        use_local_slm=False,
        domain_profile=scenario["domain"],
    )

    coverage = result.stride_coverage
    elements = coverage["elements"]
    cells = coverage["cells"]
    assert coverage["assessment_percent"] == 100.0
    assert len(cells) == len(elements) * len(STRIDE_CATEGORIES)

    categories_by_element = defaultdict(list)
    for cell in cells:
        categories_by_element[cell["element_id"]].append(cell["category"])
        assert cell["status"] in {"finding", "potential", "control_present", "unknown", "not_applicable"}
        assert cell["rationale"]
    expected_categories = Counter(STRIDE_CATEGORIES)
    for categories in categories_by_element.values():
        assert Counter(categories) == expected_categories

    component_text = " ".join(
        f"{component.id} {component.name}" for component in result.architecture.components
    ).lower()
    for required in scenario["required_components"]:
        assert required in component_text
    for forbidden in scenario["forbidden_components"]:
        assert forbidden not in component_text

    # Every requested category must be assessed, but a vulnerability must not
    # be fabricated merely to make each category appear in the finding list.
    assessed_categories = {cell["category"] for cell in cells}
    assert set(scenario["required_categories"]).issubset(assessed_categories)
    titles = " ".join(threat.title for threat in result.threats).lower()
    for term in scenario["required_title_terms"]:
        assert term in titles

    for threat in result.threats:
        assert threat.tier in {"Confirmed", "Potential"}
        assert threat.confidence in {"High", "Medium", "Low"}
        assert threat.evidence_details
        if threat.tier == "Confirmed":
            assert any(item.get("statement") for item in threat.evidence_details)


def test_normalized_knowledge_base_has_unique_canonical_records():
    knowledge_base = ThreatKnowledgeBase()
    threats = knowledge_base.get_all_threats()
    ids = [threat["id"] for threat in threats]

    assert len(threats) >= 150
    assert len(ids) == len(set(ids))
    for threat in threats:
        assert threat["title"]
        assert threat["description"]
        assert threat["stride_category"] in STRIDE_CATEGORIES
        assert threat["severity"] in {"Critical", "High", "Medium", "Low"}
        assert isinstance(threat["components"], list)
        assert isinstance(threat["detection"], dict)


def test_runtime_status_never_claims_unavailable_local_models_are_active(analyzer):
    result = analyzer.analyze_from_text(
        "A public React frontend calls a FastAPI API backed by PostgreSQL.",
        "runtime-status",
        use_local_slm=True,
    )
    local = result.engine_status["local_intelligence"]
    assert local["status"] in {"active", "degraded", "unavailable", "disabled"}
    if local["status"] != "active":
        assert (
            local["semantic_retrieval"] != "active"
            or local["stride_classifier"] != "active"
            or local["reranker"] != "cross_encoder"
        )
