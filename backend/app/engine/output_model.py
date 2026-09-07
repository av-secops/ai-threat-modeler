"""Normalize analysis output into a technical threat-model contract."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List


FINDING_TYPES = ("architecture", "code", "iac", "control_gap", "validation_question")


def build_system_model(architecture) -> Dict[str, Any]:
    components = architecture.components or []
    component_map = {component.id: component for component in components}
    public_entry_points = []
    identities = []
    cloud_resources = []

    for component in components:
        props = component.properties or {}
        item = {
            "id": component.id,
            "name": component.name,
            "type": component.type,
            "trust_level": component.trust_level,
            "public_access": bool(props.get("public_access")) or component.trust_level in {"public", "external"},
            "authentication": props.get("auth_type") if props.get("auth_type") not in {None, "", "unknown"} else "unspecified",
            "authorization": _authorization_model(props),
            "data_sensitivity": props.get("data_sensitivity") or "unspecified",
        }
        if item["public_access"]:
            public_entry_points.append(item)
        if component.type in {"Identity Provider", "IAM"} or item["authentication"] != "unspecified":
            identities.append({
                "component_id": component.id,
                "component_name": component.name,
                "authentication": item["authentication"],
                "authorization": item["authorization"],
            })
        if props.get("cloud_provider") or props.get("iac_resource_type"):
            cloud_resources.append({
                "component_id": component.id,
                "resource_type": props.get("iac_resource_type") or component.type,
                "provider": props.get("cloud_provider") or "unspecified",
                "deployment": props.get("deployment") or "unspecified",
            })

    flows = []
    boundary_crossings = []
    inferred_boundary_crossings = []
    for flow in architecture.flows or []:
        source = component_map.get(flow.source_id)
        target = component_map.get(flow.target_id)
        item = {
            "id": f"{flow.source_id}->{flow.target_id}",
            "source": flow.source_id,
            "target": flow.target_id,
            "protocol": flow.protocol,
            "data_type": flow.data_type,
            "explicit": not flow.assumed,
            "crosses_trust_boundary": bool(source and target and source.trust_level != target.trust_level),
        }
        flows.append(item)
        if item["crosses_trust_boundary"]:
            if item["explicit"]:
                boundary_crossings.append(item)
            else:
                inferred_boundary_crossings.append(item)

    return {
        "components": [
            {
                "id": component.id,
                "name": component.name,
                "type": component.type,
                "trust_level": component.trust_level,
                "properties": _security_properties(component.properties or {}),
            }
            for component in components
        ],
        "assets": [
            {
                "name": asset.name,
                "type": asset.asset_type,
                "sensitivity": asset.sensitivity,
                "location": asset.location,
                "component_id": asset.related_component_id,
            }
            for asset in architecture.assets or []
        ],
        "data_flows": flows,
        "trust_boundaries": [
            {
                "name": boundary.name,
                "type": boundary.boundary_type,
                "components": boundary.components,
                "description": boundary.description,
            }
            for boundary in architecture.trust_boundaries or []
        ],
        "public_entry_points": public_entry_points,
        "identities": identities,
        "actors": (architecture.metadata or {}).get("actors", []),
        "cloud_resources": cloud_resources,
        "boundary_crossings": boundary_crossings,
        "inferred_boundary_crossings": inferred_boundary_crossings,
    }


def normalize_finding_output(threats, architecture) -> List:
    component_map = {component.id: component for component in architecture.components or []}
    for threat in threats:
        threat.finding_type = _finding_type(threat)
        threat.evidence_details = threat.evidence_details or _evidence_details(threat, component_map)
        threat.preconditions = threat.preconditions or _preconditions(threat, component_map)
        threat.explanation = threat.explanation or {}
        threat.explanation.update({
            "finding_type": threat.finding_type,
            "evidence_count": len(threat.evidence_details),
            "evidence_summary": [item["statement"] for item in threat.evidence_details[:3]],
            "preconditions": threat.preconditions,
        })
    return threats


def group_findings(threats) -> Dict[str, List]:
    groups = {name: [] for name in FINDING_TYPES}
    for threat in threats:
        groups.setdefault(threat.finding_type or "architecture", []).append(threat)
    for items in groups.values():
        items.sort(key=lambda threat: threat.risk_score or 0, reverse=True)
    return groups


def risk_methodology() -> Dict[str, Any]:
    return {
        "version": "technical-v4",
        "inputs": [
            "internet exposure",
            "asset sensitivity",
            "exploit complexity",
            "privileges required",
            "compensating controls",
            "trust boundary crossing",
            "blast radius",
        ],
        "severity_rule": (
            "Severity is derived from likelihood and impact. Exposure and required privilege "
            "describe the same reachability, so their combined contribution is capped rather "
            "than counted twice. Evidence confidence is reported alongside a finding but does "
            "not raise its likelihood. Direct code and IaC evidence keeps a finding from being "
            "scored below the severity its rule reported, and never above it."
        ),
        "likelihood_rule": (
            "Likelihood is reachability, capped, plus exploit complexity, plus one point for "
            "sitting on a trust boundary, less one point per compensating control up to two. "
            "It is recalculated in full whenever the architecture is refined, so controls and "
            "classifications found later can lower a severity as well as raise it."
        ),
        "confirmed_rule": "Confirmed findings require explicit source, IaC, or architecture evidence. Assumption-only findings remain potential.",
        "scope_rule": (
            "Blast radius is the finding's own elements plus everything reachable from them "
            "over the data flow graph, and counts toward impact once it covers about half the "
            "architecture. A component-scoped finding crosses a trust boundary when any flow "
            "into or out of it does."
        ),
        "classification_rule": (
            "Asset sensitivity is the most sensitive classification carried by the finding's "
            "components and flows. A classification stated about one component is carried along "
            "the flows that data travels, and never overrides one stated outright."
        ),
        "system_score_rule": (
            "The system score groups equivalent findings by affected scope and root control, "
            "then applies diminishing impact so large models do not mechanically saturate at zero. "
            "Potential findings are reported as a separate uncertainty penalty."
        ),
    }


def _finding_type(threat) -> str:
    # Preserve a producer's explicit contract. Known issues and direct policy
    # gaps are deliberately classified as control_gap before normalization.
    if threat.finding_type and threat.finding_type != "architecture":
        return threat.finding_type
    threat_id = (threat.id or "").upper()
    if threat_id.startswith("CODE-"):
        return "code"
    if threat_id.startswith("IAC-"):
        return "iac"
    if threat_id.startswith("CTX-") and any(token in threat_id for token in ("INPUT", "AUTH", "WAF", "DATA")):
        return "control_gap"
    return "architecture"


def _evidence_details(threat, component_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_type = "architecture"
    if threat.finding_type == "code":
        source_type = "source_code"
    elif threat.finding_type == "iac":
        source_type = "iac"

    component_id = threat.component or threat.affected_component or threat.component_id
    component = component_map.get(component_id)
    details = []
    for evidence in threat.evidence or []:
        line_match = re.search(r"\bline\s+(\d+)\b", evidence, re.IGNORECASE)
        details.append({
            "source_type": source_type,
            "source_ref": component_id or (component.name if component else "architecture input"),
            "line": int(line_match.group(1)) if line_match else None,
            "statement": evidence,
            "confidence": threat.confidence or "Medium",
        })
    if not details and component:
        details.append({
            "source_type": "architecture",
            "source_ref": component.id,
            "line": None,
            "statement": f"Component {component.name} is modeled as {component.type} with trust level {component.trust_level}.",
            "confidence": threat.confidence or "Medium",
        })
    return details


def _preconditions(threat, component_map: Dict[str, Any]) -> List[str]:
    preconditions = []
    component_id = threat.component or threat.affected_component or threat.component_id
    component = component_map.get(component_id)
    if component and (component.properties or {}).get("public_access"):
        preconditions.append("The target component is internet reachable.")
    if threat.privilege_required:
        preconditions.append(f"Required attacker privilege: {threat.privilege_required}.")
    if threat.exploit_complexity:
        preconditions.append(f"Exploit complexity: {threat.exploit_complexity}.")
    return preconditions


def _authorization_model(properties: Dict[str, Any]) -> str:
    if properties.get("abac_enabled"):
        return "ABAC"
    if properties.get("rbac_enabled"):
        return "RBAC"
    return "unspecified"


def _security_properties(properties: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "auth_type", "rbac_enabled", "abac_enabled", "input_validation", "encryption_at_rest",
        "logging_enabled", "rate_limiting", "waf_enabled", "cloud_provider", "iac_resource_type",
    )
    return {key: properties[key] for key in keys if key in properties}
