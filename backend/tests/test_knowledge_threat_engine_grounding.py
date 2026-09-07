"""Focused predicate regressions; no models, retrieval, or network required."""

from types import SimpleNamespace

import pytest

from app.engine.knowledge_threat_engine import KnowledgeThreatEngine, _evaluate_logic
from app.knowledge_base.contracts import CanonicalThreatRule
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Component, SystemArchitecture


def _logic(*conditions, operator="AND"):
    return {"operator": operator, "conditions": list(conditions)}


def _condition(field, value=False, op="=="):
    return {"field": field, "op": op, "value": value}


def _rule(**overrides):
    data = {
        "id": "TEST", "title": "Control gap", "description": "Explicit control gap",
        "attack_vector": "Explicit control gap", "stride_category": "Tampering",
        "category": "Tampering", "severity": "High", "likelihood": "Medium",
        "components": ["Any"], "applicability": {},
        "detection": {"auto_detectable": True, "evidence_requirement": "explicit",
                      "logic": _logic(_condition("input_validation"))},
        "controls": {"remediation": "Validate input"}, "taxonomies": {},
        "rule_kind": "deterministic", "source_module": "test.json",
    }
    data.update(overrides)
    return CanonicalThreatRule.model_validate(data)


def _kb(*rules):
    return SimpleNamespace(get_typed_rules=lambda: list(rules), get_all_threats=lambda: list(rules))


def _component(**overrides):
    data = {"id": "orders", "name": "Orders", "type": "API", "confidence": "High",
            "properties": {"input_validation": False}}
    data.update(overrides)
    return Component(**data)


def _analyze(rule, *components, **kwargs):
    return KnowledgeThreatEngine(_kb(rule)).analyze(
        SystemArchitecture(components=list(components or [_component()]), flows=[]), **kwargs,
    )


def test_applicability_element_types_narrow_legacy_components():
    rule = _rule(applicability={"element_types": ["Database"]})
    assert _analyze(rule)[0] == []
    assert len(_analyze(rule, _component(type="Database"))[0]) == 1


@pytest.mark.parametrize("provider", [None, "unknown", "azure", "gcp", "multi-cloud"])
@pytest.mark.parametrize("scope", ["cloud_platform", "applicability"])
def test_restricted_cloud_rules_require_component_local_provider(provider, scope):
    rule = _rule(**{scope: ["AWS"] if scope == "cloud_platform" else {"cloud_platforms": ["AWS"]}})
    component = _component(properties={"input_validation": False, "cloud_provider": provider})
    assert _analyze(rule, component)[0] == []


def test_cloud_scope_is_not_borrowed_from_another_component_or_architecture():
    rule = _rule(cloud_platform=["AWS"])
    architecture = SystemArchitecture(components=[
        _component(id="aws", properties={"input_validation": False, "cloud_provider": "AWS"}),
        _component(id="azure", properties={"input_validation": False, "cloud_provider": "azure"}),
        _component(id="local"),
    ], flows=[], metadata={"cloud_provider": "aws", "architecture_text": "AWS application"})
    findings, _ = KnowledgeThreatEngine(_kb(rule)).analyze(architecture)
    assert [item.component for item in findings] == ["aws"]


def test_platform_agnostic_catalog_rules_do_not_require_a_cloud_provider():
    rule = _rule(cloud_platform=["AWS", "Azure", "GCP", "On-Premise"])
    assert len(_analyze(rule)[0]) == 1


@pytest.mark.parametrize("component", [
    _component(id="a", type="Database"),
    _component(name="Rapid processing", type="Service"),
])
def test_short_ids_and_embedded_substrings_do_not_establish_component_type(component):
    assert _analyze(_rule(components=["API"]), component)[0] == []


@pytest.mark.parametrize(("expected", "actual"), [
    ("StorageBucket", "Object Storage"), ("IdentityProvider", "Identity Provider"),
    ("APIGateway", "API Gateway"), ("Cache", "Redis"), ("API", "API Gateway"),
    ("API", "APIGateway"), ("Service", "Microservice"),
])
def test_established_component_names_and_synonyms_still_match(expected, actual):
    assert len(_analyze(_rule(components=[expected]), _component(type=actual))[0]) == 1


def test_or_evidence_contains_only_successful_branches():
    logic = _logic(_condition("rate_limiting"), _condition("pagination"), operator="OR")
    assert _evaluate_logic(logic, {"rate_limiting": False, "pagination": True}) == (True, ["rate_limiting"])


def test_failed_nested_and_does_not_contribute_partial_or_evidence():
    logic = _logic(
        _logic(_condition("rate_limiting"), _condition("pagination")),
        _condition("input_validation"), operator="OR",
    )
    props = {"rate_limiting": False, "pagination": True, "input_validation": False}
    assert _evaluate_logic(logic, props) == (True, ["input_validation"])


def test_failed_logic_has_no_matched_evidence():
    assert _evaluate_logic(_logic(_condition("input_validation")), {"input_validation": True}) == (False, [])


def test_nested_evidence_and_confidence_use_the_value_actually_compared():
    rule = _rule(detection={"auto_detectable": True, "logic": _logic(_condition("security.validation"))})
    findings, _ = _analyze(rule, _component(properties={"security": {"validation": False}}))
    assert len(findings) == 1
    assert findings[0].confidence == "High"
    assert findings[0].evidence[-1] == "Matched component properties: security.validation=False"


def test_matched_controls_excludes_unsatisfied_or_branch():
    rule = _rule(detection={"auto_detectable": True, "logic": _logic(
        _condition("rate_limiting"), _condition("pagination"), operator="OR",
    )})
    findings, _ = _analyze(rule, _component(properties={"rate_limiting": False, "pagination": True}))
    assert findings[0].explanation["matched_controls"] == ["rate_limiting"]
    assert "pagination" not in findings[0].evidence[-1]


@pytest.mark.parametrize("value", [False, None, "", "false", " False ", "no", "off", "disabled", "absent", "0", "none", " UNKNOWN "])
def test_false_like_negating_controls_do_not_suppress_findings(value):
    rule = _rule(negating_controls=["waf_enabled"])
    findings, _ = _analyze(rule, _component(properties={"input_validation": False, "waf_enabled": value}))
    assert len(findings) == 1


@pytest.mark.parametrize("value", [True, "true", " YES ", "enabled", "present", "oauth2", "AES-256"])
def test_present_or_named_controls_still_suppress_findings(value):
    rule = _rule(negating_controls=["waf_enabled"])
    assert _analyze(rule, _component(properties={"input_validation": False, "waf_enabled": value}))[0] == []


def test_explicitly_absent_control_is_not_overridden_by_a_stale_presence_assertion():
    rule = _rule(negating_controls=["waf_enabled"])
    component = _component(properties={
        "input_validation": False, "waf_enabled": "false",
        "control_assertions": {"waf_enabled": "present"},
    })
    assert len(_analyze(rule, component)[0]) == 1


@pytest.mark.parametrize("op", ["!=", "not_in"])
@pytest.mark.parametrize("value", [None, "unknown", " UNKNOWN "])
def test_unknown_values_are_not_negative_predicate_evidence(op, value):
    expected = [True] if op == "not_in" else True
    logic = _logic(_condition("input_validation", value=expected, op=op))
    assert _evaluate_logic(logic, {"input_validation": value}) == (False, [])


@pytest.mark.parametrize("field", ["ai_scope", "vector_store", "agentic", "mcp_enabled"])
@pytest.mark.parametrize("value", ["false", "unknown", "off"])
def test_false_like_ai_flags_do_not_enable_ai_rules(field, value):
    rule = _rule(source_module="custom_ai_llm_threats.json")
    assert _analyze(rule, _component(properties={"input_validation": False, field: value}))[0] == []


def test_canonical_component_type_is_available_to_existing_database_predicates():
    kb = ThreatKnowledgeBase()
    rule = next(item for item in kb.get_typed_rules() if item.id == "DB-002")
    component = _component(type="Database", properties={"encryption_at_rest": False})
    findings, _ = _analyze(rule, component)
    assert len(findings) == 1
    assert "type='Database'" in findings[0].evidence[-1]
    assert component.properties == {"encryption_at_rest": False}


@pytest.mark.parametrize("logic", [
    _logic(_condition("input_validation"), operator="XOR"),
    _logic(_condition("input_validation"), {"field": "x", "op": "regex", "value": ".*"}, operator="OR"),
    _logic(_condition("input_validation"), {"op": "==", "value": True}),
    _logic(_condition("input_validation"), "not a condition"),
])
def test_unsupported_or_malformed_logic_is_not_partially_executed(logic):
    rule = _rule(detection={"auto_detectable": True, "logic": logic})
    assert _analyze(rule)[0] == []


def test_missing_requires_explicit_absence_not_omission():
    logic = _logic(_condition("rate_limiting", op="missing"))
    assert _evaluate_logic(logic, {}) == (False, [])
    assert _evaluate_logic(logic, {"explicit_negations": ["rate_limiting"]}) == (True, ["rate_limiting"])


def test_only_deterministic_rules_are_serialized_once_per_engine(monkeypatch):
    deterministic = _rule()
    candidate = _rule(id="CANDIDATE", detection={"auto_detectable": False}, rule_kind="candidate")
    calls = []
    original = CanonicalThreatRule.model_dump

    def counted(self, *args, **kwargs):
        calls.append(self.id)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(CanonicalThreatRule, "model_dump", counted)
    engine = KnowledgeThreatEngine(_kb(deterministic, candidate))
    architecture = SystemArchitecture(components=[_component(id=str(i)) for i in range(4)], flows=[])
    for _ in range(2):
        findings, diagnostics = engine.analyze(architecture)
        assert len(findings) == 4
        assert diagnostics["rules"] == 2
    assert calls == ["TEST"]


def test_routing_and_diagnostics_remain_per_component_rule_pairs():
    engine = KnowledgeThreatEngine(_kb(_rule(), _rule(
        id="CANDIDATE", detection={"auto_detectable": False}, rule_kind="candidate", source_module="other.json",
    )))
    architecture = SystemArchitecture(components=[_component(), _component(id="second")], flows=[])
    findings, diagnostics = engine.analyze(architecture, allowed_modules=["test.json"])
    assert len(findings) == 2
    assert diagnostics["predicates_evaluated"] == 2
    assert diagnostics["applicable_predicates"] == 2
    assert diagnostics["skipped_by_specialist_route"] == 2


def test_real_candidate_rules_remain_non_executable():
    kb = ThreatKnowledgeBase()
    rule = next(item for item in kb.get_typed_rules() if item.id == "AWS-S3-001")
    assert rule.rule_kind == "candidate"
    assert _analyze(rule, _component(type="Object Storage", properties={"public_access": True, "cloud_provider": "aws"}))[0] == []


@pytest.mark.parametrize(("op", "actual", "expected"), [
    ("==", False, False), ("eq", "jwt", "jwt"), ("!=", False, True), ("ne", "basic", "jwt"),
    ("in", "pii", ["pii", "credentials"]), ("not_in", "public", ["pii"]),
    ("not in", "public", ["pii"]), ("exists", False, None), ("is_set", False, None),
    ("contains", "oauth2 jwt", "jwt"), ("contains", ["HIPAA", "PCI"], "HIPAA"),
])
def test_supported_predicate_operators_keep_their_meaning(op, actual, expected):
    logic = _logic(_condition("control", value=expected, op=op))
    assert _evaluate_logic(logic, {"control": actual}) == (True, ["control"])


def test_presence_normalization_does_not_coerce_boolean_equality_predicates():
    assert _evaluate_logic(_logic(_condition("input_validation")), {"input_validation": "false"}) == (False, [])


def test_all_successful_or_branches_contribute_unique_fields():
    logic = _logic(_condition("a"), _condition("b"), _condition("a"), operator="OR")
    assert _evaluate_logic(logic, {"a": False, "b": False}) == (True, ["a", "b"])


def test_structured_negating_controls_and_presence_assertions_are_respected():
    rule = _rule(controls={"negating_controls": ["WAF Enabled"], "remediation": "Validate input"})
    component = _component(properties={"input_validation": False, "control_assertions": {"waf_enabled": "present"}})
    assert _analyze(rule, component)[0] == []


def test_explicit_absence_is_visible_in_evidence():
    rule = _rule(detection={"auto_detectable": True, "logic": _logic(_condition("rate_limiting", op="missing"))})
    findings, _ = _analyze(rule, _component(properties={"explicit_negations": ["rate_limiting"]}))
    assert findings[0].confidence == "High"
    assert findings[0].evidence[-1] == "Matched component properties: rate_limiting=None (explicitly absent)"


def test_unsupported_rules_are_identified_in_diagnostics():
    rule = _rule(detection={"auto_detectable": True, "logic": _logic(_condition("input_validation"), operator="XOR")})
    findings, diagnostics = _analyze(rule)
    assert findings == []
    assert diagnostics["compiled_predicate_rules"] == 0
    assert diagnostics["unsupported_predicate_rules"] == ["TEST"]


def test_engine_snapshot_changes_only_when_reconstructed():
    rule = _rule()
    kb = _kb(rule)
    engine = KnowledgeThreatEngine(kb)
    rule.detection.logic["conditions"][0]["value"] = True
    architecture = SystemArchitecture(components=[_component()], flows=[])
    assert len(engine.analyze(architecture)[0]) == 1
    assert KnowledgeThreatEngine(kb).analyze(architecture)[0] == []


@pytest.mark.parametrize("allowed", [None, []])
def test_empty_routes_retain_existing_unrestricted_semantics(allowed):
    assert len(_analyze(_rule(), allowed_modules=allowed)[0]) == 1


def test_conflicting_legacy_and_canonical_scopes_do_not_broaden_applicability():
    rule = _rule(components=["API"], applicability={"element_types": ["Database"]})
    assert _analyze(rule, _component(type="Database"))[0] == []
    rule = _rule(cloud_platform=["AWS"], applicability={"cloud_platforms": ["Azure"]})
    assert _analyze(rule, _component(properties={"input_validation": False, "cloud_provider": "azure"}))[0] == []


@pytest.mark.parametrize(("scope", "provider"), [("AWS", "aws"), ("Google Cloud", "gcp"), ("On-Premise", "on-prem")])
def test_explicit_cloud_aliases_match(scope, provider):
    rule = _rule(applicability={"cloud_platforms": [scope]})
    assert len(_analyze(rule, _component(properties={"input_validation": False, "cloud_provider": provider}))[0]) == 1


@pytest.mark.parametrize(("rule_id", "component_type", "props"), [
    ("K8S-001", "Service", {"privileged_container": True}),
    ("AI-005", "ML Service", {"ml_pipeline": True, "training_data_validation": False}),
])
def test_existing_platform_agnostic_catalog_checks_remain_executable(rule_id, component_type, props):
    kb = ThreatKnowledgeBase()
    rule = next(item for item in kb.get_typed_rules() if item.id == rule_id)
    assert len(_analyze(rule, _component(type=component_type, properties=props))[0]) == 1
