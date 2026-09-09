"""Execute normalized knowledge-base predicates against the canonical model."""

from __future__ import annotations

import re
from collections import Counter, OrderedDict
from threading import RLock
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from types import SimpleNamespace

from ..models import Threat
from .control_contracts import normalized_properties, control_value, boundary_dimensions


AI_RULE_MODULES = {
    "custom_ai_llm_threats.json", "ai_agent_threats.json",
    "rag_vector_store_threats.json",
}


Predicate = Callable[[Dict[str, Any], set[str]], Tuple[bool, List[str]]]


@dataclass(frozen=True)
class _CompiledRule:
    data: Dict[str, Any]
    matches: Callable[[Any], bool]
    evaluate: Predicate
    negating_controls: Tuple[str, ...]


class KnowledgeThreatEngine:
    def __init__(self, knowledge_base):
        # An engine owns a snapshot. The analyzer constructs a new engine when
        # reloading the KB, so no rule serialization belongs in the hot loop.
        self.knowledge_base = knowledge_base
        self._predicate_cache = OrderedDict()
        self._predicate_lock = RLock()
        typed_rules = knowledge_base.get_typed_rules()
        self.content_digest = hashlib.sha256(json.dumps(knowledge_base.get_all_threats(), sort_keys=True, default=str).encode()).hexdigest()
        self._rule_count = len(knowledge_base.get_all_threats())
        self._module_counts = Counter(rule.source_module for rule in typed_rules)
        self._rules: List[_CompiledRule] = []
        self._unsupported_rules: List[str] = []
        for typed_rule in typed_rules:
            if not typed_rule.detection.auto_detectable or not typed_rule.detection.logic:
                continue
            rule = typed_rule.model_dump(exclude={"raw"})
            predicate = _compile_logic(rule["detection"]["logic"])
            if predicate is None:
                self._unsupported_rules.append(rule["id"])
                continue
            self._rules.append(_CompiledRule(
                rule, _compile_applicability(rule), predicate, _control_names(rule),
            ))

    def analyze(self, architecture, allowed_modules: Optional[List[str]] = None) -> Tuple[List[Threat], Dict[str, Any]]:
        findings: List[Threat] = []
        evaluated = 0
        applicable = 0
        cache_hits = 0
        allowed = set(allowed_modules or [])
        active_rules = [item for item in self._rules if not allowed or item.data["source_module"] in allowed]
        skipped_by_route = len(architecture.components or []) * sum(
            count for module, count in self._module_counts.items() if allowed and module not in allowed
        )
        elements = list(architecture.components or [])
        components = {component.id: component for component in elements}
        for flow in architecture.flows or []:
            if flow.assumed or flow.source_id not in components or flow.target_id not in components:
                continue
            reference = f"{flow.source_id}->{flow.target_id}"
            elements.append(SimpleNamespace(
                id=f"flow:{reference}", name=reference, type="Data Flow",
                confidence=flow.confidence, trust_level="internal", evidence=flow.evidence,
                properties={**(flow.properties or {}), "protocol": (flow.protocol or "").lower(),
                    "trust_boundary_crossing": bool(boundary_dimensions(components[flow.source_id], components[flow.target_id]))},
            ))
        for component in elements:
            props = _component_properties(component)
            key = hashlib.sha256(json.dumps([props, component.evidence], sort_keys=True, default=str).encode()).hexdigest()
            explicit_negations = set(props.get("explicit_negations") or [])
            for compiled in active_rules:
                rule = compiled.data
                if component.type == "Data Flow" and not any(_squashed(str(t).lower()) == "dataflow" for t in rule.get("components", [])):
                    continue
                evaluated += 1
                if rule.get("source_module") in AI_RULE_MODULES and not _ai_rule_scope(component):
                    continue
                if not compiled.matches(component):
                    continue
                if _has_negating_control(props, compiled.negating_controls, explicit_negations):
                    continue
                applicable += 1
                with self._predicate_lock:
                    cached = self._predicate_cache.get(key, {}).get(rule['id'])
                if cached is None:
                    matched, evidence_fields = compiled.evaluate(props, explicit_negations)
                    with self._predicate_lock:
                        self._predicate_cache.setdefault(key, {})[rule['id']] = (matched, tuple(evidence_fields))
                        self._predicate_cache.move_to_end(key)
                        while len(self._predicate_cache) > 128:
                            self._predicate_cache.popitem(last=False)
                else:
                    matched, evidence_fields = cached
                    cache_hits += 1
                if not matched:
                    continue
                if any(control_value(props, field) == "conflicting" for field in evidence_fields):
                    continue
                evidence = _component_evidence(component, evidence_fields)
                confidence = "High" if _has_direct_evidence(component, evidence_fields) else "Medium"
                findings.append(_to_threat(rule, component, evidence, confidence, evidence_fields))

        diagnostics = {
            "engine": "normalized_kb_predicates",
            "rules": self._rule_count,
            "compiled_predicate_rules": len(self._rules),
            "unsupported_predicate_rules": list(self._unsupported_rules),
            "predicates_evaluated": evaluated,
            "predicate_cache_hits": cache_hits,
            "predicate_executions": applicable - cache_hits,
            "content_digest": self.content_digest,
            "predicate_cache_scope": "Source and property fingerprint; rule snapshot replaced on KB reload",
            "applicable_predicates": applicable,
            "findings": len(findings),
            "skipped_by_specialist_route": skipped_by_route,
            "active_modules": sorted(allowed),
        }
        return findings, diagnostics


# The knowledge base and the canonical model name some things differently, and
# a name that never matches disables the predicate silently: every rule about a
# bucket, including unencrypted storage and public access, skipped Object Storage
# components because "storagebucket" shares no substring with "object storage".
_RESOURCE_TYPE_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "storagebucket": ("object storage", "bucket", "blob storage", "file store", "data lake"),
    "cache": ("redis", "memcached", "elasticache"),
    "api": ("api gateway",),
    "service": ("microservice",),
}


def _component_matches(component, rule: Dict[str, Any]) -> bool:
    return _compile_applicability(rule)(component)


def _compile_component_matcher(elements: List[str]) -> Callable[[Any], bool]:
    expected = {str(item).strip().lower() for item in elements or ["Any"]}
    if "any" in expected:
        return lambda component: True
    expected |= {
        synonym
        for candidate in tuple(expected)
        for synonym in _RESOURCE_TYPE_SYNONYMS.get(_squashed(candidate), ())
    }
    exact = {_squashed(candidate) for candidate in expected if candidate}
    patterns = tuple(
        re.compile(r"(?<![a-z0-9])" + r"[\s_-]*".join(
            re.escape(part) for part in re.split(r"[\s_-]+", candidate)
        ) + r"(?![a-z0-9])")
        for candidate in sorted(expected) if candidate
    )

    def matches(component) -> bool:
        props = component.properties or {}
        tokens = (
            component.type, component.id, component.name,
            props.get("db_type"), props.get("iac_resource_type"),
        )
        # Names may contain a type, but arbitrary substrings and short IDs must
        # not establish one ("a" and "Rapid" are not evidence of an API).
        for value in tokens:
            if not value:
                continue
            token = str(value).lower()
            if _squashed(token) in exact or any(pattern.search(token) for pattern in patterns):
                return True
        return False

    return matches


def _compile_applicability(rule: Dict[str, Any]) -> Callable[[Any], bool]:
    applicability = rule.get("applicability") or {}
    element_scopes = [rule.get("components") or ["Any"]]
    if applicability.get("element_types"):
        element_scopes.append(applicability["element_types"])
    matchers = [_compile_component_matcher(list(elements)) for elements in dict.fromkeys(
        tuple(elements) for elements in element_scopes
    )]
    platform_scopes = []
    for platforms in (rule.get("cloud_platform"), applicability.get("cloud_platforms")):
        scope = {_cloud_platform(value) for value in platforms or []}
        # Existing cross-platform AI/container packs enumerate every deployment
        # family, including on-premise; these are not cloud-specific checks.
        if scope and "any" not in scope and not {"aws", "azure", "gcp", "onpremise"} <= scope:
            platform_scopes.append(scope)

    def matches(component) -> bool:
        provider = _cloud_platform((component.properties or {}).get("cloud_provider") or "")
        return all(provider in scope for scope in platform_scopes) and all(
            matcher(component) for matcher in matchers
        )

    # Service lists and prose required/excluded signals have no executable
    # contract here. Do not invent predicates from the loader's metadata.
    return matches


def _cloud_platform(value: str) -> str:
    normalized = _squashed(str(value).strip().lower())
    return {
        "amazonwebservices": "aws", "microsoftazure": "azure",
        "googlecloud": "gcp", "googlecloudplatform": "gcp", "onprem": "onpremise",
    }.get(normalized, normalized)


def _squashed(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value)


def _ai_rule_scope(component) -> bool:
    props = component.properties or {}
    return bool(
        component.type == "ML Service"
        or any(_presence_state(props.get(key)) is True for key in (
            "ai_scope", "vector_store", "agentic", "mcp_enabled",
        ))
    )


_ABSENT_STRINGS = {"none", "false", "no", "off", "disabled", "absent", "0"}
_UNKNOWN_STRINGS = {"", "unknown", "unspecified", "null", "n/a"}


def _presence_state(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _UNKNOWN_STRINGS:
            return None
        return normalized not in _ABSENT_STRINGS
    return None


def _control_names(rule: Dict[str, Any]) -> Tuple[str, ...]:
    controls = rule.get("negating_controls") or (rule.get("controls") or {}).get("negating_controls") or []
    return tuple(dict.fromkeys(
        str(control).strip().lower().replace(" ", "_").replace("-", "_") for control in controls
    ))


def _negated_by_control(props: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Suppress a candidate when the architecture explicitly states a negating control."""
    return _has_negating_control(props, _control_names(rule), set(props.get("explicit_negations") or []))


def _has_negating_control(props: Dict[str, Any], controls: Tuple[str, ...], explicit_negations: set[str]) -> bool:
    assertions = props.get("control_assertions") or {}
    for control in controls:
        state = _presence_state(props.get(control))
        if control in explicit_negations or state is False:
            continue
        if state is True or str(assertions.get(control) or "").strip().lower() == "present":
            return True
    return False


def _evaluate_logic(logic: Dict[str, Any], props: Dict[str, Any]) -> Tuple[bool, List[str]]:
    predicate = _compile_logic(logic)
    return predicate(props, set(props.get("explicit_negations") or [])) if predicate else (False, [])


def supports_detection_logic(logic: Any) -> bool:
    """The loader uses the same executable contract as the predicate engine."""
    return _compile_logic(logic) is not None


def _compile_logic(logic: Dict[str, Any]) -> Optional[Predicate]:
    if not isinstance(logic, dict):
        return None
    operator = str(logic.get("operator") or "AND").strip().upper()
    conditions = logic.get("conditions")
    if operator not in {"AND", "OR"} or not isinstance(conditions, list) or not conditions:
        return None
    predicates = []
    for condition in conditions:
        if not isinstance(condition, dict):
            return None
        if "conditions" in condition:
            predicate = _compile_logic(condition)
        else:
            predicate = _compile_condition(condition)
        # Reject the entire expression, including OR, rather than silently
        # deleting an unsupported branch or interpreting a new operator as AND.
        if predicate is None:
            return None
        predicates.append(predicate)

    def evaluate(props: Dict[str, Any], explicit_negations: set[str]) -> Tuple[bool, List[str]]:
        fields = []
        any_matched = False
        for predicate in predicates:
            matched, matched_fields = predicate(props, explicit_negations)
            if not matched and operator == "AND":
                return False, []
            if matched:
                any_matched = True
                fields.extend(matched_fields)
        return any_matched, list(dict.fromkeys(fields))

    return evaluate


def _compile_condition(condition: Dict[str, Any]) -> Optional[Predicate]:
    field = condition.get("field")
    if not isinstance(field, str) or not field or any(not part for part in field.split(".")):
        return None
    op = str(condition.get("op") or "==").strip().lower()
    unary = {"exists", "is_set", "missing", "not_set"}
    if op not in {"==", "eq", "!=", "ne", "in", "not_in", "not in", "contains"} | unary:
        return None
    if op not in unary and "value" not in condition:
        return None
    expected = condition.get("value")
    if op in {"in", "not_in", "not in"} and not isinstance(expected, (list, tuple, set, str)):
        return None
    path = tuple(field.split("."))

    def evaluate(props: Dict[str, Any], explicit_negations: set[str]) -> Tuple[bool, List[str]]:
        actual = _path_value(props, path)
        matched = _compare(actual, expected, op, explicitly_absent=field in explicit_negations)
        return matched, [field] if matched else []

    return evaluate


def _nested_value(props: Dict[str, Any], field: str) -> Any:
    return _path_value(props, tuple(field.split(".")))


def _path_value(props: Dict[str, Any], path: Tuple[str, ...]) -> Any:
    value: Any = props
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _compare(actual: Any, expected: Any, op: str, explicitly_absent: bool = False) -> bool:
    if op in {"missing", "not_set"}:
        return explicitly_absent
    if actual is None or (isinstance(actual, str) and actual.strip().lower() in _UNKNOWN_STRINGS):
        return False
    if op in {"==", "eq"}:
        return actual == expected
    if op in {"!=", "ne"}:
        return actual is not None and actual != expected
    if op == "in":
        if isinstance(expected, str) and not isinstance(actual, str):
            return False
        return actual in (expected or [])
    if op in {"not_in", "not in"}:
        if isinstance(expected, str) and not isinstance(actual, str):
            return False
        return actual is not None and actual not in (expected or [])
    if op in {"exists", "is_set"}:
        return actual is not None
    if op in {"contains"}:
        if isinstance(actual, str) and not isinstance(expected, str):
            return False
        return expected in actual if isinstance(actual, (str, list, tuple, set)) else False
    return False


def _component_properties(component) -> Dict[str, Any]:
    return {**normalized_properties(component.properties or {}), "type": component.type}


def _has_direct_evidence(component, fields: List[str]) -> bool:
    props = _component_properties(component)
    explicit_negations = set(props.get("explicit_negations") or [])
    if component.confidence != "High":
        return False
    for field in fields:
        value = _nested_value(props, field)
        if field in explicit_negations or (value is not None and not (
            isinstance(value, str) and value.strip().lower() in _UNKNOWN_STRINGS
        )):
            return True
    return False


def _component_evidence(component, fields: List[str]) -> List[Dict[str, Any]]:
    evidence = list(component.evidence or [])
    props = _component_properties(component)
    explicit_negations = set(props.get("explicit_negations") or [])
    assertions = ", ".join(
        f"{field}={_nested_value(props, field)!r}" + (" (explicitly absent)" if field in explicit_negations else "")
        for field in fields
    )
    evidence.append({
        "source_type": "rule_evaluation",
        "source_ref": component.id,
        "line": None,
        "statement": f"Matched component properties: {assertions}",
        "confidence": "High" if component.confidence == "High" else "Medium",
    })
    return evidence


def _to_threat(rule: Dict[str, Any], component, evidence: List[Dict[str, Any]], confidence: str,
               matched_controls: Optional[List[str]] = None) -> Threat:
    severity = rule.get("severity") or "Medium"
    category = rule.get("stride_category") or rule.get("category") or "Unknown"
    threat = Threat(
        id=f"KB-{rule['id']}-{component.id}",
        category=category,
        stride_category=category,
        title=rule.get("title") or rule["id"],
        description=rule.get("description") or rule.get("attack_vector") or rule["id"],
        severity=severity,
        severity_source="rule",
        likelihood=rule.get("likelihood") or "Medium",
        impact="High" if severity in {"Critical", "High"} else "Medium",
        confidence=confidence,
        tier="Confirmed" if confidence == "High" else "Potential",
        finding_type="control_gap",
        mitigation=rule.get("mitigation") or "Implement and verify the required security control.",
        component=component.id,
        affected_component=component.id,
        component_id=component.id,
        affected_components=[component.id],
        root_cause=f"Knowledge-base predicate {rule['id']} matched the canonical component properties.",
        realistic_attack_scenario=rule.get("attack_vector") or rule.get("description"),
        attack_scenario=rule.get("attack_vector") or rule.get("description"),
        evidence=[item["statement"] for item in evidence],
        evidence_details=evidence,
        preconditions=rule.get("preconditions") or [],
        owasp_top_10=rule.get("owasp_top_10") or [],
        cwe=rule.get("cwe") or [],
        mitre_attack=rule.get("mitre_attack") or [],
        mitre_atlas=rule.get("mitre_atlas") or [],
        nist_800_53=rule.get("nist_800_53") or [],
        exposure="public" if component.trust_level in {"public", "external"} else "internal",
        data_sensitivity=(component.properties or {}).get("data_sensitivity") or "internal",
        exploit_complexity="Low" if component.trust_level in {"public", "external"} else "Medium",
        privilege_required="None" if component.trust_level in {"public", "external"} else "Low",
        # Which control decided the finding, so a second route to the same
        # problem can recognise it instead of reporting it again.
        explanation={"matched_controls": sorted(set(matched_controls or ())),
            "framework_mappings": rule.get("framework_mappings") or [],
            "framework_mapping_issues": rule.get("framework_mapping_issues") or [],
            "verification": rule.get("verification") or "Validate the cited control on the affected element and repeat the negative authorization or abuse test after remediation.",
            "rule_provenance": {key: rule.get(key) for key in ("id", "version", "source", "source_module", "references", "taxonomy_mapping_quality", "review_status", "last_reviewed")}},
    )
    if component.type == "Data Flow":
        threat.component = threat.affected_component = threat.component_id = None
        threat.affected_components = []
        threat.data_flow = threat.related_data_flow = component.name
        threat.affected_data_flows = [component.name]
    return threat
