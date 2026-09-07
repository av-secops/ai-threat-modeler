"""Executable capabilities must match the loader's published rule contract."""

import pytest

from app.knowledge_base.loader import ThreatKnowledgeBase


@pytest.fixture(scope="module")
def knowledge_base():
    return ThreatKnowledgeBase()


def test_loader_does_not_advertise_unknown_operators_as_deterministic(knowledge_base):
    rule = knowledge_base._normalize_threat({
        "id": "AUDIT-UNSUPPORTED", "title": "Unsupported predicate",
        "category": "Tampering", "component": "API",
        "detection": {"auto_detectable": True, "logic": {
            "operator": "AND", "conditions": [
                {"field": "input_validation", "op": "regex", "value": ".*"},
            ],
        }},
    }, 1)
    assert rule["rule_kind"] == "candidate"


def test_loader_routes_flow_predicates_to_flow_elements(knowledge_base):
    for rule_id in ("T-001", "LAT-001", "LAT-002"):
        rule = knowledge_base.get_by_id(rule_id)
        assert rule["components"] == ["DataFlow"]
        assert rule["rule_kind"] == "deterministic"
        assert rule['predicate_support']['element_kind'] == 'flow'


def test_loader_preserves_curated_reference_taxonomies(knowledge_base):
    rule = knowledge_base.get_by_id("AWS-S3-001")
    source = rule["raw"]["references"]
    assert rule["cwe"] == source["cwe"]
    assert rule["taxonomy_mapping_quality"]["cwe"] == "curated"
    assert set(source["external_links"]) <= set(rule["references"])
