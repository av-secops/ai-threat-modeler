"""Attack paths must distinguish modeled connectivity from demonstrated access."""

from random import Random

import pytest

from app.engine import attack_path_engine as engine
from app.models import Component, DataFlow, SystemArchitecture, Threat


def _component(component_id, *, public=False, sensitive=False, **properties):
    if sensitive:
        properties["data_sensitivity"] = "pii"
    return Component(
        id=component_id, name=component_id.upper(), type="Service",
        trust_level="public" if public else "internal", properties=properties,
    )


def _flow(source, target, *, assumed=False, **properties):
    return DataFlow(
        source_id=source, target_id=target, protocol="https",
        assumed=assumed, properties=properties,
    )


def _finding(target="api", **values):
    return Threat(**{
        "id": "ATTACK-1", "category": "Information Disclosure",
        "title": "Exposed records", "description": "Records may be exposed.",
        "severity": "High", "mitigation": "Restrict access.",
        "tier": "Confirmed", "confidence": "High", "component": target,
        **values,
    })


def _hop_pairs(path):
    return [(hop["source"], hop["target"]) for hop in path["hops"]]


def test_public_target_does_not_hide_an_incoming_explicit_route():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api", public=True)],
        flows=[_flow("web", "api")],
    )

    paths = engine.generate_attack_paths(architecture, [_finding()])

    assert len(paths) == 1
    assert paths[0]["entry_component_id"] == "web"
    assert _hop_pairs(paths[0]) == [("web", "api")]


@pytest.mark.parametrize("reverse_flows", [False, True])
def test_explicit_route_wins_over_an_inferred_shortcut(reverse_flows):
    flows = [
        _flow("web", "api", assumed=True), _flow("web", "gateway"),
        _flow("gateway", "service"), _flow("service", "api"),
    ]
    architecture = SystemArchitecture(
        components=[_component("web", public=True)]
        + [_component(node) for node in ("gateway", "service", "api")],
        flows=list(reversed(flows)) if reverse_flows else flows,
    )

    paths = engine.generate_attack_paths(architecture, [_finding()])

    assert len(paths) == 1
    assert _hop_pairs(paths[0]) == [
        ("web", "gateway"), ("gateway", "service"), ("service", "api"),
    ]
    assert paths[0]["path_status"] == "explicit"
    assert paths[0]["inferred_hops"] == 0
    assert paths[0]["confidence"] == "High"


def test_fewer_inferred_hops_win_before_route_length():
    architecture = SystemArchitecture(
        components=[_component("web", public=True)]
        + [_component(node) for node in ("gateway", "short", "a", "b", "api")],
        flows=[
            _flow("web", "gateway"),
            _flow("gateway", "short", assumed=True),
            _flow("short", "api", assumed=True),
            _flow("gateway", "a", assumed=True), _flow("a", "b"),
            _flow("b", "api"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert _hop_pairs(path) == [
        ("web", "gateway"), ("gateway", "a"), ("a", "b"), ("b", "api"),
    ]
    assert path["path_status"] == "partially_inferred"
    assert path["inferred_hops"] == 1
    assert path["confidence"] == "Medium"
    assert path["assumptions"] == ["Flow gateway->a was inferred rather than stated."]


def test_assumed_onward_reach_is_not_confirmed_sensitive_data_impact():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")]
        + [_component(node, sensitive=True) for node in ("db", "archive", "logs")],
        flows=[
            _flow("web", "api"), _flow("api", "db", assumed=True),
            _flow("db", "archive"), _flow("api", "logs"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert path["sensitive_data_reached"] == ["LOGS"]
    assert path["onward_reach"] == ["archive", "db", "logs"]
    assert path["explicit_onward_reach"] == ["logs"]
    assert path["inferred_onward_reach"] == ["archive", "db"]
    assert path["potential_sensitive_data_reached"] == ["ARCHIVE", "DB"]
    assert any("api" in item and "db" in item and "inferred" in item for item in path["assumptions"])
    assert not any("path reaches sensitive data held by" in step for step in path["steps"])


def test_explicit_onward_alternative_is_not_tainted_by_an_inferred_shortcut():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")]
        + [_component("worker"), _component("db", sensitive=True)],
        flows=[
            _flow("web", "api"), _flow("api", "db", assumed=True),
            _flow("api", "worker"), _flow("worker", "db"), _flow("db", "api"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert path["onward_reach"] == ["db", "worker"]
    assert path["sensitive_data_reached"] == ["DB"]
    assert path["inferred_onward_reach"] == []
    assert path["potential_sensitive_data_reached"] == []
    assert path["assumptions"] == []


def test_inferred_ingress_cannot_prove_even_explicit_downstream_impact():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("gateway")]
        + [_component("api", sensitive=True), _component("db", sensitive=True)],
        flows=[
            _flow("web", "gateway"), _flow("gateway", "api", assumed=True),
            _flow("api", "db"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert path["sensitive_data_reached"] == []
    assert path["potential_sensitive_data_reached"] == ["API", "DB"]
    assert path["explicit_onward_reach"] == ["db"]
    assert path["path_status"] == "partially_inferred"


@pytest.mark.parametrize("target_identity", ["api-role", "caller-role", None])
def test_identity_labels_and_required_permissions_do_not_prove_authorization(target_identity):
    architecture = SystemArchitecture(
        components=[
            _component("web", public=True, iam_role="caller-role"),
            _component("api", iam_role=target_identity),
        ],
        flows=[_flow("web", "api", required_permissions=["records:read"])],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])
    hop, = path["hops"]

    assert hop["source_identity"] == "caller-role"
    assert hop["target_identity"] == (target_identity or "unspecified_workload_identity")
    assert hop["authorization_transition"] == "not established by architecture evidence"
    assert path["permission_chain"][0]["transition"] == hop["authorization_transition"]
    assert path["permission_chain"][0]["required_permissions"] == ["records:read"]


def test_authentication_mechanism_is_not_a_workload_identity():
    architecture = SystemArchitecture(
        components=[
            _component("web", public=True, auth_type="customer_jwt"),
            _component("api", auth_type="oauth2"),
        ],
        flows=[_flow("web", "api")],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert path["identities"] == ["public_or_external_actor", "unspecified_workload_identity"]


@pytest.mark.parametrize("flow_ref", ["worker->api", "web->other"])
def test_flow_reference_cannot_fabricate_an_external_route_to_the_target(flow_ref):
    architecture = SystemArchitecture(
        components=[_component("web", public=True)]
        + [_component(node) for node in ("worker", "api", "other")],
        flows=[_flow("worker", "api"), _flow("web", "other")],
    )
    finding = _finding(data_flow=flow_ref)

    assert engine.generate_attack_paths(architecture, [finding]) == []
    assert finding.explanation["attack_path_reason"] == "no_reachable_entry"


def test_dangling_flows_do_not_crash_or_create_routes_through_missing_components():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")],
        flows=[
            _flow("web", "missing"), _flow("missing", "api"),
            _flow("web", "api"), _flow("api", "missing"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert _hop_pairs(path) == [("web", "api")]
    assert path["onward_reach"] == []


def test_findings_on_the_same_target_reuse_route_search(monkeypatch):
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")],
        flows=[_flow("web", "api")],
    )
    original = engine._best_route
    calls = []

    def counted(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(engine, "_best_route", counted)
    findings = [_finding(id=f"ATTACK-{index}") for index in range(20)]

    paths = engine.generate_attack_paths(architecture, findings)

    assert len(paths) == len(findings)
    assert calls == ["api"]
    assert [path["related_threat_id"] for path in paths] == [finding.id for finding in findings]


def test_repeated_targets_reuse_downstream_walks_but_not_output_lists(monkeypatch):
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api"), _component("db", sensitive=True)],
        flows=[_flow("web", "api"), _flow("api", "db", assumed=True)],
    )
    original = engine._downstream
    calls = []

    def counted(start, adjacency, *, include_assumed):
        calls.append((start, include_assumed))
        return original(start, adjacency, include_assumed=include_assumed)

    monkeypatch.setattr(engine, "_downstream", counted)
    first, second = engine.generate_attack_paths(architecture, [_finding(), _finding(id="ATTACK-2")])

    assert calls == [("api", False), ("api", True)]
    first["onward_reach"].clear()
    first["potential_sensitive_data_reached"].clear()
    first["hops"].clear()
    assert second["onward_reach"] == ["db"]
    assert second["potential_sensitive_data_reached"] == ["DB"]
    assert _hop_pairs(second) == [("web", "api")]


def test_route_cache_includes_missing_routes_and_is_local_to_one_generation(monkeypatch):
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")], flows=[],
    )
    original = engine._best_route
    calls = []

    def counted(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(engine, "_best_route", counted)
    assert engine.generate_attack_paths(architecture, [_finding(), _finding(id="ATTACK-2")]) == []
    assert calls == ["api"]

    architecture.flows.append(_flow("web", "api"))
    assert len(engine.generate_attack_paths(architecture, [_finding()])) == 1
    assert calls == ["api", "api"]


@pytest.mark.parametrize("flows,reason", [
    ([_flow("web", "api", assumed=True)], "no_explicit_hop"),
    ([_flow("api", "web")], "no_reachable_entry"),
    ([_flow("web", "missing"), _flow("missing", "api")], "no_reachable_entry"),
])
def test_unsupported_or_reverse_only_routes_remain_unmodeled(flows, reason):
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")], flows=flows,
    )
    finding = _finding(explanation={"origin": "analyst"}, attack_scenario="A conditional exploit.")

    assert engine.generate_attack_paths(architecture, [finding]) == []
    assert finding.explanation == {
        "origin": "analyst", "attack_path_status": "not_modeled",
        "attack_path_reason": reason, "exploit_scenario_available": True,
    }


@pytest.mark.parametrize("entry_properties", [
    {"trust_level": "external"},
    {"trust_level": "internal", "properties": {"public_access": True}},
])
def test_external_and_property_based_entry_points_are_supported(entry_properties):
    architecture = SystemArchitecture(
        components=[Component(id="web", name="WEB", type="Service", **entry_properties), _component("api")],
        flows=[_flow("web", "api")],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert path["entry_component_id"] == "web"


def test_nonconfirmed_and_unmapped_findings_do_not_create_paths():
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")],
        flows=[_flow("web", "api")],
    )
    potential = _finding(tier="Potential", explanation={"origin": "analyst"})
    unmapped = _finding("missing")

    assert engine.generate_attack_paths(architecture, [potential, unmapped]) == []
    assert potential.explanation == {"origin": "analyst"}
    assert unmapped.explanation["attack_path_reason"] == "unmapped_target"


@pytest.mark.parametrize("field", ["data_flow", "related_data_flow"])
def test_flow_target_mapping_still_uses_a_real_external_route(field):
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")],
        flows=[_flow("web", "api")],
    )

    path, = engine.generate_attack_paths(architecture, [_finding(None, **{field: "web->api"})])

    assert path["target_component_id"] == "api"
    assert _hop_pairs(path) == [("web", "api")]


def test_explicit_sensitive_target_and_original_evidence_are_preserved():
    flow = _flow("web", "api", permissions="records:read, records:write, records:read")
    flow.evidence = [{"source_type": "iac", "source_ref": "main.tf:12", "statement": "An API integration."}]
    finding = _finding(
        evidence_details=[{"source_type": "architecture", "statement": "A confirmed weakness."}],
        preconditions=["Attacker controls the caller."], business_impact="Records exposed.",
    )
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api", sensitive=True)], flows=[flow],
    )
    original = architecture.model_dump()

    path, = engine.generate_attack_paths(architecture, [finding])

    assert path["sensitive_data_reached"] == ["API"]
    assert path["potential_sensitive_data_reached"] == []
    assert path["hops"][0]["evidence"] == flow.evidence
    assert path["hops"][0]["required_permissions"] == ["records:read", "records:write"]
    assert path["evidence"] == finding.evidence_details
    assert path["preconditions"] == finding.preconditions
    assert path["impact"] == finding.business_impact
    assert path["trust_boundary_crossings"] == ["web->api"]
    assert architecture.model_dump() == original


def test_parallel_flows_and_cycles_preserve_the_best_actual_edge():
    explicit = _flow("web", "api")
    duplicate = _flow("web", "api")
    explicit.evidence = [{"statement": "First explicit edge"}]
    architecture = SystemArchitecture(
        components=[_component("web", public=True), _component("api")],
        flows=[_flow("web", "web"), _flow("web", "api", assumed=True), explicit, duplicate, _flow("api", "web")],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert _hop_pairs(path) == [("web", "api")]
    assert path["hops"][0]["evidence"] == explicit.evidence


def test_equal_cost_routes_keep_entry_order_and_then_flow_order():
    architecture = SystemArchitecture(
        components=[_component("z_entry", public=True), _component("a_entry", public=True)]
        + [_component(node) for node in ("z_service", "a_service", "api")],
        flows=[
            _flow("a_entry", "a_service"), _flow("z_entry", "z_service"),
            _flow("z_entry", "a_service"), _flow("z_service", "api"),
            _flow("a_service", "api"),
        ],
    )

    path, = engine.generate_attack_paths(architecture, [_finding()])

    assert _hop_pairs(path) == [("z_entry", "z_service"), ("z_service", "api")]


def test_route_search_matches_exhaustive_simple_routes_on_small_graphs():
    random = Random(719)
    nodes = ["a", "b", "c", "d", "e"]
    for _ in range(150):
        entries = random.sample(nodes, random.randint(0, len(nodes)))
        target = random.choice(nodes)
        adjacency = {}
        for source in nodes:
            for destination in nodes:
                if random.random() < 0.3:
                    flow = _flow(source, destination, assumed=random.choice([False, True]))
                    adjacency.setdefault(source, []).append((destination, flow))

        candidates = []
        for index, entry in enumerate(entries):
            if entry == target:
                continue
            pending = [(entry, {entry}, 0, 0)]
            while pending:
                node, visited, inferred, hops = pending.pop()
                for destination, flow in adjacency.get(node, []):
                    if destination in visited:
                        continue
                    cost = (inferred + int(flow.assumed), hops + 1, index)
                    if destination == target:
                        candidates.append(cost)
                    else:
                        pending.append((destination, visited | {destination}, cost[0], cost[1]))

        route = engine._best_route(entries, target, adjacency)
        if not candidates:
            assert route is None
            continue
        assert route is not None
        assert route[-1][0] == target
        assert len({node for node, _ in route}) == len(route)
        cost = (sum(int(flow.assumed) for _, flow in route[1:]), len(route) - 1, entries.index(route[0][0]))
        assert cost == min(candidates)


def test_long_routes_are_iterative_and_keep_all_hops():
    nodes = [f"node-{index}" for index in range(1200)]
    architecture = SystemArchitecture(
        components=[_component(node, public=index == 0) for index, node in enumerate(nodes)],
        flows=[_flow(source, destination) for source, destination in zip(nodes, nodes[1:])],
    )

    path, = engine.generate_attack_paths(architecture, [_finding(nodes[-1])])

    assert len(path["hops"]) == len(nodes) - 1
    assert path["entry_component_id"] == nodes[0]
    assert path["target_component_id"] == nodes[-1]
