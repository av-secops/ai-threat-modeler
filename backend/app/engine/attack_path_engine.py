"""Evidence-aware attack paths over the canonical architecture graph."""

from __future__ import annotations

from collections import deque
from heapq import heappop, heappush
from itertools import count
from typing import Dict, List, Optional, Set, Tuple

from . import graph
from .control_contracts import presence, boundary_dimensions


def generate_attack_paths(system_model, threats) -> List[Dict]:
    """Model connectivity, not proof that an attacker can exercise permissions.

    Route status describes ingress to the finding. ``onward_reach`` retains all
    modeled downstream connectivity; explicit/inferred fields qualify it. Only
    wholly explicit ingress and onward routes populate ``sensitive_data_reached``.
    Even explicit connectivity remains conditional on exploit and access checks.
    """
    components = {component.id: component for component in system_model.components or []}
    adjacency: Dict[str, List[Tuple[str, object]]] = {}
    for flow in system_model.flows or []:
        if flow.source_id not in components or flow.target_id not in components:
            continue
        if _permission_state(flow, components[flow.source_id], components[flow.target_id]) == "denied":
            continue
        adjacency.setdefault(flow.source_id, []).append((flow.target_id, flow))

    entry_points = [
        component.id for component in components.values()
        if component.trust_level in {"public", "external"} or presence((component.properties or {}).get("public_access")) is True
    ]
    route_cache = {}
    onward_cache = {}
    paths: List[Dict] = []
    for threat in threats:
        # Potential control questions are not exploitable attack paths. A path
        # requires a confirmed finding, a mapped target, and a graph-reachable
        # entry point.
        if threat.tier != "Confirmed":
            continue
        target = _target_component(threat, components)
        if not target:
            _mark_without_path(threat, "unmapped_target")
            continue

        if target not in route_cache:
            route_cache[target] = _best_route(entry_points, target, adjacency)
        route = route_cache[target]
        if route is None:
            reason = "no_explicit_hop" if target in entry_points else "no_reachable_entry"
            _mark_without_path(threat, reason)
            continue

        hops = []
        steps = []
        inferred_hops = 0
        for index in range(1, len(route)):
            source_id = route[index - 1][0]
            target_id, flow = route[index]
            if flow is None:
                continue
            inferred = bool(flow.assumed)
            inferred_hops += int(inferred)
            source = components[source_id]
            destination = components[target_id]
            hop = {
                "source": source_id,
                "target": target_id,
                "protocol": flow.protocol,
                "data_type": flow.data_type,
                "evidence_status": "inferred" if inferred else "explicit",
                "evidence": list(flow.evidence or []) or [
                    {
                        "source_type": "inference" if inferred else "architecture_input",
                        "source_ref": f"{source_id}->{target_id}",
                        "statement": (flow.properties or {}).get("evidence")
                        or f"{source.name} connects to {destination.name} over {flow.protocol}.",
                        "confidence": flow.confidence,
                    }
                ],
                "crosses_trust_boundary": bool(boundary_dimensions(source, destination)),
                "source_trust": source.trust_level,
                "target_trust": destination.trust_level,
                "source_identity": _effective_identity(source),
                "target_identity": _effective_identity(destination),
                "required_permissions": _required_permissions(flow, destination),
                "identity_transition": _identity_transition(source, destination),
                "authorization_transition": _authorization_transition(source, destination),
                "permission_status": _permission_state(flow, source, destination),
                "permission_evidence": (flow.properties or {}).get("authorization_evidence") or {},
            }
            hops.append(hop)
            steps.append(
                f"{'Inferred' if inferred else 'Explicit'} flow: {source.name} -> {destination.name} over {flow.protocol}."
            )
        # A graph-local exploit scenario is not an attack path. At least one hop
        # must be supported by explicit architecture evidence.
        if not hops or not any(hop["evidence_status"] == "explicit" for hop in hops):
            _mark_without_path(threat, "no_explicit_hop")
            continue

        scenario = threat.attack_scenario or threat.realistic_attack_scenario
        if scenario:
            steps.append(scenario)
        if threat.asset:
            steps.append(f"The path affects protected asset {threat.asset}.")

        if target not in onward_cache:
            explicit = _downstream(target, adjacency, include_assumed=False)
            all_reached = _downstream(target, adjacency, include_assumed=True)
            onward_cache[target] = (all_reached, explicit)
        all_reached, explicit = onward_cache[target]
        onward = sorted(all_reached)
        inferred_onward = sorted(all_reached - explicit)
        exposed_stores = [
            components[component_id].name for component_id in [target, *onward]
            if not inferred_hops and (component_id == target or component_id in explicit)
            and graph.rank((components[component_id].properties or {}).get("data_sensitivity")) >= 3
        ]
        potential_stores = [
            components[component_id].name for component_id in [target, *onward]
            if (inferred_hops or (component_id != target and component_id not in explicit))
            and graph.rank((components[component_id].properties or {}).get("data_sensitivity")) >= 3
        ]
        if exposed_stores:
            steps.append(
                "Explicit modeled flows reach components handling sensitive data: "
                + ", ".join(exposed_stores)
                + ". Data access remains conditional on authorization and exploit preconditions."
            )
        if potential_stores:
            steps.append(
                "Sensitive data at " + ", ".join(potential_stores)
                + " is potentially reachable through inferred flows; access is not established."
            )

        entry_id = route[0][0]
        confidence = "High" if inferred_hops == 0 and threat.confidence == "High" else "Medium"
        assumptions = [
            f"Flow {hop['source']}->{hop['target']} was inferred rather than stated."
            for hop in hops if hop["evidence_status"] == "inferred"
        ]
        assumptions.extend(
            f"Onward reach from {target} to {component_id} relies on inferred flows."
            for component_id in inferred_onward
        )
        permission_chain = [
            {
                "hop": f"{hop['source']}->{hop['target']}",
                "identity": hop["source_identity"],
                "target_identity": hop["target_identity"],
                "identity_transition": hop["identity_transition"],
                "required_permissions": hop["required_permissions"],
                "transition": hop["authorization_transition"],
            }
            for hop in hops
        ]
        paths.append({
            "id": f"PATH-{threat.id}",
            "entry_point": components[entry_id].name,
            "entry_component_id": entry_id,
            "steps": steps,
            "hops": hops,
            "target_component": components[target].name,
            "target_component_id": target,
            "impact": threat.business_impact or threat.impact or "Operational impact",
            "related_threat_id": threat.id,
            "finding_type": threat.finding_type,
            "confidence": confidence,
            "severity": threat.severity,
            "preconditions": threat.preconditions,
            "evidence": threat.evidence_details or _fallback_evidence(threat),
            "path_status": "explicit" if inferred_hops == 0 else "partially_inferred",
            "inferred_hops": inferred_hops,
            "onward_reach": onward,
            "explicit_onward_reach": sorted(explicit),
            "inferred_onward_reach": inferred_onward,
            "sensitive_data_reached": exposed_stores,
            "potential_sensitive_data_reached": potential_stores,
            "identities": [
                *dict.fromkeys(
                    [_effective_identity(components[entry_id])]
                    + [hop["source_identity"] for hop in hops]
                    + [hop["target_identity"] for hop in hops]
                )
            ],
            "permission_chain": permission_chain,
            "network_route": [
                {
                    "source": hop["source"], "target": hop["target"],
                    "protocol": hop["protocol"],
                    "trust_transition": f"{hop['source_trust']}->{hop['target_trust']}",
                }
                for hop in hops
            ],
            "assumptions": assumptions,
            "exploit_status": "not_verified",
            "permission_status": "supported_by_submitted_evidence" if all(hop['permission_status'] == 'allowed' for hop in hops) else "unresolved",
            "verification_required": [f"Verify permissions for {hop['source']}->{hop['target']} using the source identity." for hop in hops if hop['permission_status'] != 'allowed'],
            "trust_boundary_crossings": [
                f"{hop['source']}->{hop['target']}" for hop in hops
                if hop["crosses_trust_boundary"]
            ],
            "controls_bypassed": [],
            "controls_implicated": list((threat.explanation or {}).get("matched_controls") or []),
        })
    return paths


def _permission_state(flow, source, destination) -> str:
    evidence = (flow.properties or {}).get('authorization_evidence') or {}
    if flow.assumed or not isinstance(evidence, dict) or not evidence.get('source_ref'):
        return 'unknown'
    if evidence.get('identity') != _effective_identity(source) or evidence.get('resource') != destination.id:
        return 'unknown'
    required = _required_permissions(flow, destination)
    if not required or required == ['not specified in architecture evidence'] or not set(required) <= set(evidence.get('actions') or []):
        return 'unknown'
    return {'allow': 'allowed', 'deny': 'denied'}.get(str(evidence.get('decision')).lower(), 'unknown')


def _effective_identity(component) -> str:
    properties = component.properties or {}
    for key in (
        "effective_identity", "iam_role", "execution_role", "managed_identity",
        "service_account", "workload_identity",
    ):
        value = properties.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if component.trust_level in {"public", "external"}:
        return "public_or_external_actor"
    return "unspecified_workload_identity"


def _required_permissions(flow, destination) -> List[str]:
    flow_properties = flow.properties or {}
    destination_properties = destination.properties or {}
    values = (
        flow_properties.get("required_permissions")
        or flow_properties.get("permissions")
        or destination_properties.get("required_permissions")
        or []
    )
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    if values:
        return list(dict.fromkeys(str(item) for item in values))
    relationship = str(flow_properties.get("relationship") or "")
    if relationship == "permission_reference":
        return ["permission declared by IaC relationship"]
    return ["not specified in architecture evidence"]


def _authorization_transition(source, destination) -> str:
    # Identity labels and permission requirements are not grants, successful
    # authorization checks, or evidence of impersonating the destination.
    return "not established by architecture evidence"


def _identity_transition(source, destination) -> str:
    source_identity = _effective_identity(source)
    target_identity = _effective_identity(destination)
    return f"source identity: {source_identity}; destination identity: {target_identity}"


def _mark_without_path(threat, reason: str) -> None:
    threat.explanation = {
        **(threat.explanation or {}),
        "attack_path_status": "not_modeled",
        "attack_path_reason": reason,
        "exploit_scenario_available": bool(
            threat.attack_scenario or threat.realistic_attack_scenario
        ),
    }


def _target_component(threat, components: Dict[str, object]) -> Optional[str]:
    for candidate in (threat.component, threat.affected_component, threat.component_id):
        if candidate in components:
            return candidate
    if threat.data_flow or threat.related_data_flow:
        flow_ref = (threat.data_flow or threat.related_data_flow).replace(" → ", "->")
        _, _, target = flow_ref.partition("->")
        if target in components:
            return target
    for candidate in threat.affected_components or []:
        if candidate in components:
            return candidate
    return None


def _best_route(entries: List[str], target: str, adjacency: Dict[str, List[Tuple[str, object]]]):
    """Minimize inferred hops, then length, across non-local entry routes.

    Multi-source Dijkstra preserves the earlier entry on equal-cost routes.
    A serial tie-breaker avoids comparing DataFlow objects on parallel edges.
    Predecessors avoid copying an entire route at every graph expansion.
    """
    queue = []
    serial = count()
    costs = {}
    predecessors = {}
    for entry_index, entry in enumerate(entries):
        if entry == target or entry in costs:
            continue
        cost = (0, 0, entry_index)
        costs[entry] = cost
        predecessors[entry] = None
        heappush(queue, (*cost, next(serial), entry))

    while queue:
        inferred, hops, entry_index, _, node = heappop(queue)
        if costs[node] != (inferred, hops, entry_index):
            continue
        if node == target:
            route = []
            while predecessors[node] is not None:
                previous, flow = predecessors[node]
                route.append((node, flow))
                node = previous
            route.append((node, None))
            return list(reversed(route))
        for next_node, flow in adjacency.get(node, []):
            cost = (inferred + int(bool(flow.assumed)), hops + 1, entry_index)
            if next_node in costs and costs[next_node] <= cost:
                continue
            costs[next_node] = cost
            predecessors[next_node] = (node, flow)
            heappush(queue, (*cost, next(serial), next_node))
    return None


def _route(source: str, target: str, adjacency: Dict[str, List[Tuple[str, object]]]):
    if source == target:
        return [(source, None)]
    return _best_route([source], target, adjacency)


def _downstream(start: str, adjacency: Dict[str, List[Tuple[str, object]]], *, include_assumed: bool) -> Set[str]:
    """Walk the already indexed graph without promoting inferred reach."""
    queue = deque([start])
    visited = {start}
    while queue:
        node = queue.popleft()
        for next_node, flow in adjacency.get(node, []):
            if next_node in visited or (flow.assumed and not include_assumed):
                continue
            visited.add(next_node)
            queue.append(next_node)
    return visited - {start}


def _component_local_path(threat, target: str, components: Dict[str, object]) -> Dict:
    component = components[target]
    scenario = threat.attack_scenario or threat.realistic_attack_scenario or threat.description
    return {
        "id": f"PATH-{threat.id}",
        "entry_point": "Unspecified prerequisite",
        "entry_component_id": None,
        "steps": [f"No graph route from a modeled external entry point to {component.name} was established.", scenario],
        "hops": [],
        "target_component": component.name,
        "target_component_id": target,
        "impact": threat.business_impact or threat.impact or "Operational impact",
        "related_threat_id": threat.id,
        "finding_type": threat.finding_type,
        "confidence": "Low" if threat.confidence != "High" else "Medium",
        "severity": threat.severity,
        "preconditions": threat.preconditions,
        "evidence": threat.evidence_details or _fallback_evidence(threat),
        "path_status": "unresolved_entry_path",
        "inferred_hops": 0,
        "onward_reach": [],
        "sensitive_data_reached": [],
    }


def _unresolved_path(threat) -> Dict:
    return {
        "id": f"PATH-{threat.id}",
        "entry_point": "Unmapped",
        "entry_component_id": None,
        "steps": ["The finding is supported, but its affected component is not mapped to the architecture graph."],
        "hops": [],
        "target_component": "Unmapped",
        "target_component_id": None,
        "impact": threat.business_impact or threat.impact or "Operational impact",
        "related_threat_id": threat.id,
        "finding_type": threat.finding_type,
        "confidence": "Low",
        "severity": threat.severity,
        "preconditions": threat.preconditions,
        "evidence": threat.evidence_details or _fallback_evidence(threat),
        "path_status": "unmapped",
        "inferred_hops": 0,
        "onward_reach": [],
        "sensitive_data_reached": [],
    }


def _fallback_evidence(threat) -> List[Dict]:
    return [{
        "source_type": "architecture",
        "source_ref": threat.component or threat.affected_component or "architecture input",
        "line": None,
        "statement": evidence,
        "confidence": threat.confidence,
    } for evidence in (threat.evidence or [])]
