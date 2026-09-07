"""Exhaustive STRIDE applicability and coverage assessment."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..models import Threat
from . import graph
from .control_contracts import control_value, presence


STRIDE_CATEGORIES = (
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
)

CATEGORY_CODE = {
    "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
    "Information Disclosure": "I", "Denial of Service": "D",
    "Elevation of Privilege": "E",
}

ACTIVE_COMPONENTS = {
    "API", "API Gateway", "Service", "ML Service", "WebClient", "Mobile App",
    "Identity Provider", "Queue", "IoT Device", "Load Balancer", "CDN",
}
DATA_COMPONENTS = {"Database", "Object Storage", "Data Warehouse", "Secrets Manager", "Backup"}


class StrideCoverageEngine:
    def assess(self, architecture, existing_threats: List[Threat], generate_candidates: bool = True) -> Tuple[List[Threat], Dict[str, Any]]:
        elements = list(self._elements(architecture))
        existing_index = self._finding_index(existing_threats)
        unknown_candidate_targets = _select_unknown_candidate_targets(elements, existing_index)
        cells: List[Dict[str, Any]] = []
        candidates: List[Threat] = []

        for element in elements:
            for category in STRIDE_CATEGORIES:
                applicable, rationale = _applicability(element, category)
                if not applicable:
                    cells.append(_cell(element, category, "not_applicable", rationale, [], []))
                    continue

                linked = existing_index.get((element["id"], category), [])
                if linked:
                    state, controls, _ = _control_state(element, category)
                    confirmed = any(threat.tier == "Confirmed" for threat in linked)
                    status = "finding" if confirmed else "potential"
                    cells.append(_cell(
                        element, category, status,
                        "A confirmed finding is linked; other unspecified controls still require evidence." if confirmed else
                        "Potential findings are awaiting validation; they do not resolve the evidence gap.",
                        sorted({threat.id for threat in linked}), controls,
                    ))
                    continue

                control_state, controls, control_rationale = _control_state(element, category)
                status = "control_present" if control_state == "present" else "finding" if control_state == "absent" else "unknown"
                candidate: Optional[Threat] = None
                # Explicitly absent controls are findings. For architecture-only
                # input, surface one representative, high-value Potential threat
                # per unresolved STRIDE category. This gives users an actionable
                # threat model without mislabeling an unspecified control as a
                # confirmed vulnerability.
                should_surface_unknown = (
                    control_state in {"unknown", "partial", "conflicting"}
                    and (element["id"], category) in unknown_candidate_targets
                )
                if generate_candidates and (control_state == "absent" or should_surface_unknown):
                    candidate = _candidate_threat(element, category, control_state, controls)
                    candidates.append(candidate)
                    status = "finding" if control_state == "absent" else "potential"
                cells.append(_cell(
                    element, category, status, control_rationale,
                    [candidate.id] if candidate else [], controls,
                ))

        status_counts = Counter(cell["status"] for cell in cells)
        category_summary = {}
        for category in STRIDE_CATEGORIES:
            category_cells = [cell for cell in cells if cell["category"] == category]
            category_summary[category] = dict(Counter(cell["status"] for cell in category_cells))

        assessed = len(cells) - status_counts.get("not_applicable", 0)
        unresolved = sum(bool(cell["unresolved_controls"]) or cell["status"] in {"unknown", "potential"} for cell in cells)
        resolved = assessed - unresolved
        coverage = {
            "version": "stride-coverage-3.2",
            "categories": list(STRIDE_CATEGORIES),
            "elements_assessed": len(elements),
            "applicable_cells": assessed,
            "resolved_cells": resolved,
            "unknown_cells": unresolved,
            "assessment_percent": 100.0,
            "evidence_resolution_percent": round((resolved / assessed) * 100, 1) if assessed else 100.0,
            # Compatibility for existing clients. This measures evidence
            # resolution, not whether every category was assessed.
            "coverage_percent": round((resolved / assessed) * 100, 1) if assessed else 100.0,
            "status_counts": dict(status_counts),
            "category_summary": category_summary,
            "elements": elements,
            "cells": cells,
            "guarantee": (
                "Every modeled element was evaluated for every STRIDE category. Cells whose "
                "controls are unspecified are raised as Potential architecture threats, never "
                f"as confirmed vulnerabilities, and at most {UNKNOWN_CANDIDATE_BUDGET} of them "
                "are raised: the strongest candidate in each category first, then the "
                "highest-risk cells remaining. One element supplies no more than "
                f"{MAX_CATEGORIES_PER_ELEMENT} categories while another element still has a "
                "candidate to offer. Every unresolved cell left over is listed in the evidence "
                "requests."
            ),
        }
        return candidates, coverage

    @staticmethod
    def _finding_index(threats: List[Threat]) -> Dict[Tuple[str, str], List[Threat]]:
        index: Dict[Tuple[str, str], List[Threat]] = {}
        for threat in threats:
            category = threat.stride_category or threat.category
            coverage_element_id = (threat.explanation or {}).get("coverage_element_id")
            if coverage_element_id:
                index.setdefault((coverage_element_id, category), []).append(threat)
            component_ids = set(threat.affected_components or [])
            if threat.component:
                component_ids.add(threat.component)
            if threat.affected_component:
                component_ids.add(threat.affected_component)
            for component_id in component_ids:
                index.setdefault((component_id, category), []).append(threat)
            flow_refs = set((threat.affected_data_flows or []))
            if threat.data_flow:
                flow_refs.add(threat.data_flow)
            if threat.related_data_flow:
                flow_refs.add(threat.related_data_flow)
            for flow_ref in flow_refs:
                normalized = flow_ref.replace(" → ", "->")
                index.setdefault((f"flow:{normalized}", category), []).append(threat)
            for asset in threat.affected_assets or ([] if not threat.asset else [threat.asset]):
                index.setdefault((f"asset:{asset}", category), []).append(threat)
        return index

    @staticmethod
    def _elements(architecture) -> Iterable[Dict[str, Any]]:
        for component in architecture.components or []:
            yield {
                "id": component.id,
                "name": component.name,
                "kind": "component",
                "type": component.type,
                "trust_level": component.trust_level,
                "properties": component.properties or {},
                "evidence": component.evidence or [],
                "confidence": component.confidence,
            }
        for flow in architecture.flows or []:
            yield {
                "id": f"flow:{flow.source_id}->{flow.target_id}",
                "name": f"{flow.source_id} -> {flow.target_id}",
                "kind": "flow",
                "type": "Data Flow",
                "trust_level": (flow.properties or {}).get("trust_boundary", "unknown"),
                "properties": {**(flow.properties or {}), "protocol": flow.protocol, "data_type": flow.data_type, "assumed": flow.assumed},
                "evidence": flow.evidence or [],
                "confidence": flow.confidence,
            }
        for asset in architecture.assets or []:
            yield {
                "id": f"asset:{asset.name}",
                "name": asset.name,
                "kind": "asset",
                "type": asset.asset_type,
                "trust_level": "restricted" if asset.sensitivity not in {"public", "internal"} else "internal",
                "properties": {"sensitivity": asset.sensitivity, "location": asset.location},
                "evidence": asset.evidence or [],
                "confidence": asset.confidence,
            }
        for boundary in architecture.trust_boundaries or []:
            yield {
                "id": f"boundary:{boundary.name}",
                "name": boundary.name,
                "kind": "boundary",
                "type": boundary.boundary_type,
                "trust_level": boundary.boundary_type,
                "properties": {"components": boundary.components},
                "evidence": boundary.evidence or [],
                "confidence": boundary.confidence,
            }
        for actor in (architecture.metadata or {}).get("actors", []):
            yield {
                "id": f"actor:{actor['id']}",
                "name": actor["name"],
                "kind": "actor",
                "type": "Actor",
                "trust_level": "external" if actor["id"] in {"user", "customer", "partner", "vendor", "attacker"} else "internal",
                "properties": actor,
                "evidence": [],
                "confidence": "High",
            }


def _applicability(element: Dict[str, Any], category: str) -> Tuple[bool, str]:
    kind = element["kind"]
    component_type = element["type"]
    props = element["properties"]
    if kind == "component":
        if component_type in ACTIVE_COMPONENTS:
            return True, f"{category} applies to active process or identity component {element['name']}."
        if component_type in DATA_COMPONENTS:
            if category == "Spoofing" and not (props.get("db_type") == "redis" or props.get("data_sensitivity") in {"credentials", "secrets"}):
                return False, "Identity spoofing is assessed on the access process unless the store holds sessions or credentials."
            return True, f"{category} applies to protected data component {element['name']}."
        if component_type == "Compute":
            return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}, "Compute is assessed for host integrity, accountability, confidentiality, availability, and workload privilege."
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service"}, "Infrastructure elements are assessed for integrity, accountability, confidentiality, and availability."
    if kind == "flow":
        if category == "Elevation of Privilege" and props.get("data_type") not in {"credentials", "secrets", "pii", "phi", "financial"}:
            return False, "Privilege escalation is assessed on this flow only when it carries privileged or sensitive context."
        return True, f"{category} applies to data moving across this interaction."
    if kind == "asset":
        if category == "Spoofing":
            return False, "Assets do not authenticate; spoofing is assessed on actors and access processes."
        return True, f"{category} applies to the confidentiality, integrity, accountability, availability, or authorization of this asset."
    if kind == "boundary":
        if category == "Repudiation":
            return False, "Repudiation is assessed on actions and flows crossing this boundary."
        return True, f"{category} applies at this trust transition."
    if kind == "actor":
        return category in {"Spoofing", "Repudiation", "Elevation of Privilege"}, "Actors are assessed for identity, accountability, and privilege abuse."
    return False, "The category is not applicable to this element type."


def _control_details(element: Dict[str, Any], category: str) -> Dict[str, str]:
    props = element["properties"]
    kind = element["kind"]
    controls = _expected_controls(kind, category, element)
    states = {}
    for control in controls:
        if control == "transport_encryption":
            protocol = str(props.get("protocol") or "").lower()
            states[control] = "present" if protocol in {"https", "tls", "mtls", "wss", "grpcs"} else "absent" if protocol in {"http", "ws"} else "unknown"
        elif control == "authorization":
            alternatives = [control_value(props, key) for key in ("authorization", "rbac_enabled", "abac_enabled")]
            states[control] = "conflicting" if "conflicting" in alternatives else "present" if "present" in alternatives else "absent" if control_value(props, "authorization") == "absent" else "unknown"
        else:
            states[control] = control_value(props, control)
    return states


def _control_state(element: Dict[str, Any], category: str) -> Tuple[str, List[str], str]:
    states = _control_details(element, category)
    absent = [key for key, value in states.items() if value == "absent"]
    unresolved = [key for key, value in states.items() if value in {"unknown", "conflicting"}]
    if "conflicting" in states.values():
        return "conflicting", unresolved, "Conflicting control claims require source reconciliation."
    if absent:
        return "absent", absent, f"Explicitly absent controls: {', '.join(absent)}."
    if not unresolved:
        return "present", list(states), "All controls in this assessment profile are stated; effectiveness is not independently verified."
    support = category == "Denial of Service" and presence(element["properties"].get("waf_enabled")) is True
    partial = "present" in states.values() or support
    return "partial" if partial else "unknown", unresolved, f"Controls requiring evidence: {', '.join(unresolved)}."


def _expected_controls(kind: str, category: str, element: Optional[Dict[str, Any]] = None) -> List[str]:
    mapping = {
        "Spoofing": ["auth_type"],
        "Tampering": ["input_validation"],
        "Repudiation": ["audit_logging", "log_integrity"],
        "Information Disclosure": ["encryption_at_rest", "encryption_in_transit"],
        "Denial of Service": ["rate_limiting", "request_size_limit"],
        "Elevation of Privilege": ["authorization"],
    }
    controls = mapping[category]
    if kind == "flow":
        return {
            "Spoofing": ["mtls_enabled", "auth_type"],
            "Tampering": ["integrity_validation", "webhook_signature_validation"],
            "Repudiation": ["audit_logging", "logging_enabled"],
            "Information Disclosure": ["transport_encryption"],
            "Denial of Service": ["rate_limiting"],
            "Elevation of Privilege": ["authorization"],
        }[category]
    if kind == "actor":
        return {"Spoofing": ["auth_type", "mfa_enabled"], "Repudiation": ["audit_logging"], "Elevation of Privilege": ["authorization"]}.get(category, controls)
    props = (element or {}).get("properties", {})
    if category == "Spoofing" and (element or {}).get("type") == "Identity Provider":
        controls = [*controls, "mfa_enabled", "token_revocation"]
    if category == "Denial of Service" and props.get("has_graphql") is True:
        controls = [*controls, "query_depth_limiting"]
    if category == "Elevation of Privilege" and props.get("multi_tenant") is True:
        controls = [*controls, "tenant_isolation"]
    return controls


def _risk_relevant(element: Dict[str, Any], category: str) -> bool:
    props = element["properties"]
    trust = element["trust_level"]
    kind = element["kind"]
    component_type = element["type"]
    sensitive = props.get("data_sensitivity") in {"pii", "phi", "financial", "credentials", "secrets"} or props.get("sensitivity") not in {None, "public", "internal"}
    if kind == "flow":
        return not props.get("assumed") and bool(
            props.get("crosses_trust_boundary") or trust in {"internet", "external"}
            or props.get("data_type") in {"pii", "phi", "financial", "credentials", "secrets"}
        )
    if kind in {"boundary", "actor", "asset"}:
        return False
    if trust in {"public", "external"}:
        return True
    if component_type == "Identity Provider":
        return category in {"Spoofing", "Repudiation", "Denial of Service", "Elevation of Privilege"}
    if component_type == "Compute":
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if component_type == "Object Storage":
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if component_type in DATA_COMPONENTS and sensitive:
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if props.get("db_type") == "redis" and category in {"Spoofing", "Tampering", "Information Disclosure", "Denial of Service"}:
        return True
    if component_type in {"API", "API Gateway", "Service", "ML Service"}:
        return category in {"Spoofing", "Elevation of Privilege"}
    return False


#: How many unresolved cells are worth asking about. A review that asks about
#: everything is not read, and one that asks about six things chosen by category
#: alone asks five of them about whichever element happened to rank highest.
UNKNOWN_CANDIDATE_BUDGET = 12

#: How many categories one element may account for. Without this the single
#: highest-scoring flow took a slot in every category, so a report on a payments
#: architecture asked five questions about one internal hop and none about the
#: path to the card processor.
MAX_CATEGORIES_PER_ELEMENT = 2


def _select_unknown_candidate_targets(
    elements: List[Dict[str, Any]],
    existing_index: Dict[Tuple[str, str], List[Threat]],
) -> Set[Tuple[str, str]]:
    """Choose which unresolved cells are worth raising as questions.

    Every category gets its strongest candidate first, so no part of STRIDE goes
    unmentioned. The rest of the budget then goes to the highest-risk cells
    wherever they are, capped per element so one exposed hop cannot crowd out the
    rest of the architecture.

    Returns the (element id, category) pairs to surface.
    """
    ranked: List[Tuple[int, str, str]] = []
    for element in elements:
        for category in STRIDE_CATEGORIES:
            applicable, _ = _applicability(element, category)
            if not applicable or existing_index.get((element["id"], category)):
                continue
            state, _, _ = _control_state(element, category)
            if state not in {"unknown", "partial", "conflicting"} or not _risk_relevant(element, category):
                continue
            ranked.append((_unknown_candidate_priority(element, category), element["id"], category))
    # Sorted by score, then by name so the same architecture always produces the
    # same report.
    ranked.sort(key=lambda entry: (-entry[0], entry[1], entry[2]))

    selected: Set[Tuple[str, str]] = set()
    per_element: Counter = Counter()

    def take(entry: Tuple[int, str, str]) -> None:
        _, element_id, category = entry
        selected.add((element_id, category))
        per_element[element_id] += 1

    for category in STRIDE_CATEGORIES:
        in_category = [entry for entry in ranked if entry[2] == category]
        # The cap exists to stop one element speaking for the whole architecture,
        # so it gives way when no other element has anything to say in this
        # category: a single-component model must still be asked all six
        # questions.
        best = next(
            (entry for entry in in_category if per_element[entry[1]] < MAX_CATEGORIES_PER_ELEMENT),
            next(iter(in_category), None),
        )
        if best is not None:
            take(best)
    for entry in ranked:
        if len(selected) >= UNKNOWN_CANDIDATE_BUDGET:
            break
        _, element_id, category = entry
        if (element_id, category) in selected or per_element[element_id] >= MAX_CATEGORIES_PER_ELEMENT:
            continue
        take(entry)
    return selected


# A flow standing between two trust levels is as worth naming as the components
# it joins, so exposure counts the boundary names the parser actually assigns.
EXPOSED_TRUST_LEVELS = {"public", "external", "internet"}


def _unknown_candidate_priority(element: Dict[str, Any], category: str) -> int:
    component_type = element["type"]
    props = element["properties"]
    exposed = element["trust_level"] in EXPOSED_TRUST_LEVELS
    preferences = {
        "Spoofing": {"Identity Provider": 100, "API": 90, "WebClient": 85, "Service": 75, "Data Flow": 70},
        "Tampering": {"API": 100, "WebClient": 95, "Object Storage": 90, "Compute": 85, "Data Flow": 80},
        "Repudiation": {"Identity Provider": 100, "Compute": 95, "API": 90, "Object Storage": 85, "Data Flow": 60},
        "Information Disclosure": {"Object Storage": 100, "Database": 100, "API": 90, "Data Flow": 90, "WebClient": 80, "Compute": 75},
        "Denial of Service": {"WebClient": 100, "API": 100, "Compute": 95, "Identity Provider": 90, "Data Flow": 70},
        "Elevation of Privilege": {"Compute": 100, "API": 95, "Identity Provider": 90, "Object Storage": 85, "Data Flow": 75},
    }
    score = preferences.get(category, {}).get(component_type, 50) + (10 if exposed else 0)
    # Among flows, prefer the one that leaves a trust level over one that stays
    # inside it. Guessed paths are already excluded by _risk_relevant.
    score += 10 if props.get("crosses_trust_boundary") else 0
    # What the element handles decides which questions are worth the reviewer's
    # attention: an unencrypted hop carrying card data matters more than the same
    # question asked about an internal call carrying nothing in particular.
    return score + 4 * graph.rank(props.get("data_sensitivity") or props.get("data_type"))


def _candidate_threat(element: Dict[str, Any], category: str, state: str, controls: List[str]) -> Threat:
    code = CATEGORY_CODE[category]
    element_id = re.sub(r"[^A-Za-z0-9]+", "-", element["id"]).strip("-").upper()
    explicit_absence = state == "absent"
    confidence = "High" if explicit_absence and element["confidence"] == "High" else "Medium"
    title = _title(category, element)
    mitigation = _mitigation(category, controls)
    evidence_details = list(element.get("evidence") or [])
    evidence_details.append({
        "source_type": "coverage_assessment",
        "source_ref": element["id"],
        "line": None,
        "statement": (
            f"Required controls explicitly absent: {', '.join(controls)}."
            if explicit_absence else f"Required controls not specified: {', '.join(controls)}."
        ),
        "confidence": confidence,
    })
    component = element["id"] if element["kind"] == "component" else None
    flow = element["id"].removeprefix("flow:") if element["kind"] == "flow" else None
    asset = element["name"] if element["kind"] == "asset" else None
    severity = "High" if explicit_absence and (element["trust_level"] in {"public", "external"} or category in {"Information Disclosure", "Elevation of Privilege"}) else "Medium"
    return Threat(
        id=f"STRIDE-{code}-{element_id}",
        category=category,
        stride_category=category,
        title=title,
        description=f"{category} was assessed for {element['name']}; the required control set is {'explicitly absent' if explicit_absence else 'not documented'}.",
        severity=severity,
        likelihood="High" if explicit_absence else "Medium",
        impact="High" if severity == "High" else "Medium",
        confidence=confidence,
        tier="Confirmed" if confidence == "High" else "Potential",
        finding_type="control_gap" if explicit_absence else "validation_question",
        affected_stride_categories=[category],
        mitigation=mitigation,
        specific_control=", ".join(controls),
        implementation_detail=mitigation,
        component=component,
        affected_component=component,
        component_id=component,
        data_flow=flow,
        related_data_flow=flow,
        asset=asset,
        affected_components=[component] if component else [],
        affected_data_flows=[flow] if flow else [],
        affected_assets=[asset] if asset else [],
        root_cause=f"The architecture does not establish the {category} control contract for {element['name']}.",
        realistic_attack_scenario=_scenario(category, element),
        attack_scenario=_scenario(category, element),
        evidence=[item["statement"] for item in evidence_details],
        evidence_details=evidence_details,
        preconditions=[f"The attacker can interact with or reach {element['name']} under the modeled trust assumptions."],
        exposure="public" if element["trust_level"] in {"public", "external"} else "internal",
        data_sensitivity=element["properties"].get("data_sensitivity") or element["properties"].get("sensitivity") or "internal",
        exploit_complexity="Low" if explicit_absence else "Medium",
        privilege_required="None" if element["trust_level"] in {"public", "external"} else "Low",
        explanation={"coverage_element_id": element["id"], "control_state": state},
    )


def _cell(element: Dict[str, Any], category: str, status: str, rationale: str, finding_ids: List[str], controls: List[str]) -> Dict[str, Any]:
    details = _control_details(element, category) if status != "not_applicable" else {}
    return {
        "element_id": element["id"], "element_name": element["name"],
        "element_kind": element["kind"], "element_type": element["type"],
        "category": category, "status": status, "rationale": rationale,
        "finding_ids": finding_ids, "controls": controls,
        "control_assessment": {"state": _control_state(element, category)[0], "controls": details} if details else {},
        "unresolved_controls": [name for name, state in details.items() if state in {"unknown", "conflicting"}],
    }


def _title(category: str, element: Dict[str, Any]) -> str:
    component_type = element["type"]
    specialized = {
        ("Spoofing", "API"): "Backend token validation and identity enforcement require validation",
        ("Spoofing", "Identity Provider"): "Identity-provider token and session controls require validation",
        ("Tampering", "WebClient"): "Public web input and request-integrity controls require validation",
        ("Repudiation", "Identity Provider"): "Identity security audit trails require validation",
        ("Information Disclosure", "Object Storage"): "Object-storage access and encryption controls require validation",
        ("Denial of Service", "WebClient"): "Public website rate limiting and availability controls require validation",
        ("Denial of Service", "API"): "API rate limiting and resource bounds require validation",
        ("Elevation of Privilege", "Compute"): "Compute workload identity and instance-role privilege require validation",
    }
    if (category, component_type) in specialized:
        return f"{specialized[(category, component_type)]} for {element['name']}"
    titles = {
        "Spoofing": "Identity spoofing controls require validation",
        "Tampering": "Integrity and tampering controls require validation",
        "Repudiation": "Security auditability requires validation",
        "Information Disclosure": "Sensitive-data disclosure controls require validation",
        "Denial of Service": "Availability and resource-exhaustion controls require validation",
        "Elevation of Privilege": "Authorization and least-privilege controls require validation",
    }
    return f"{titles[category]} for {element['name']}"


def _mitigation(category: str, controls: List[str]) -> str:
    guidance = {
        "Spoofing": "Define strong workload or user authentication, token validation, replay protection, and MFA or mTLS where applicable.",
        "Tampering": "Validate untrusted input, authenticate messages, enforce integrity checks, and protect deployment and data modification paths.",
        "Repudiation": "Emit identity-bound, tamper-evident audit events with synchronized timestamps, protected retention, and alerting.",
        "Information Disclosure": "Enforce least-privilege data access, transport and storage encryption, data minimization, and egress controls.",
        "Denial of Service": "Define quotas, rate limits, timeouts, bounded workloads, autoscaling, redundancy, and tested recovery objectives.",
        "Elevation of Privilege": "Enforce server-side authorization, tenant and object ownership checks, scoped workload identity, and separation of duties.",
    }
    return f"Validate and implement {', '.join(controls)}. {guidance[category]}"


def _scenario(category: str, element: Dict[str, Any]) -> str:
    actions = {
        "Spoofing": "impersonates a trusted user, workload, or partner",
        "Tampering": "alters requests, messages, configuration, or stored data",
        "Repudiation": "performs a sensitive action that cannot be reliably attributed",
        "Information Disclosure": "obtains protected data through an insufficiently defined confidentiality boundary",
        "Denial of Service": "exhausts a bounded resource or disrupts a critical dependency",
        "Elevation of Privilege": "bypasses authorization or abuses an over-privileged identity",
    }
    return f"An attacker who can reach {element['name']} {actions[category]} because the required control contract is absent or unspecified."
