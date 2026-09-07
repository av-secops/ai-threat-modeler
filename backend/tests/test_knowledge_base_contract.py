from app.engine.retrieval_quality import rule_provenance
from app.knowledge_base.loader import ThreatKnowledgeBase


def test_every_loaded_rule_has_taxonomy_quality_and_provenance():
    knowledge_base = ThreatKnowledgeBase()
    rules = knowledge_base.get_all_threats()

    assert rules
    assert all(rule["cwe"] and rule["owasp_top_10"] and rule["nist_800_53"] for rule in rules)
    assert all(rule["version"] and rule["source"] for rule in rules)
    assert all(set(rule["taxonomy_mapping_quality"]) == {
        "cwe", "owasp_top_10", "nist_800_53",
    } for rule in rules)
    provenance = rule_provenance(rules[0])
    assert provenance["rule_version"]
    assert provenance["content_digest"]
    assert provenance["taxonomy_mapping_quality"]


def test_source_packs_have_no_duplicate_rule_ids():
    knowledge_base = ThreatKnowledgeBase()
    duplicate_issues = [
        item for item in knowledge_base.validation_issues
        if "Duplicate threat ID" in item.get("issue", "")
    ]

    assert duplicate_issues == []


def test_deterministic_rules_only_use_parser_produced_fields():
    rules = ThreatKnowledgeBase().get_all_threats()

    assert all(
        rule["predicate_support"]["status"] == "supported"
        for rule in rules if rule["rule_kind"] == "deterministic"
    )
    assert all(
        rule["rule_kind"] == "candidate"
        for rule in rules if rule["predicate_support"]["unsupported_fields"]
    )
