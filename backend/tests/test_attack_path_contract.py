from app.engine.attack_path_engine import generate_attack_paths
from app.models import Component, DataFlow, SystemArchitecture, Threat


def _finding(component="database"):
    return Threat(
        id="TEST-1", category="Information Disclosure", title="Database exposure",
        description="The database is exposed through the API.", severity="High",
        mitigation="Restrict access.", component=component, affected_component=component,
        affected_components=[component], tier="Confirmed", confidence="High",
        evidence=["Direct architecture evidence"],
    )


def test_attack_path_requires_an_explicit_graph_hop():
    architecture = SystemArchitecture(
        components=[
            Component(id="web", name="Web", type="WebClient", trust_level="public", properties={"auth_type": "customer_jwt"}),
            Component(id="api", name="API", type="API", trust_level="internal", properties={"iam_role": "orders-api-role"}),
            Component(id="database", name="DB", type="Database", trust_level="restricted"),
        ],
        flows=[
            DataFlow(source_id="web", target_id="api", protocol="https", assumed=False),
            DataFlow(source_id="api", target_id="database", protocol="tls", assumed=False, properties={"required_permissions": ["orders:read"]}),
        ],
    )

    paths = generate_attack_paths(architecture, [_finding()])

    assert len(paths) == 1
    assert len(paths[0]["hops"]) == 2
    assert all(hop["evidence_status"] == "explicit" for hop in paths[0]["hops"])
    assert paths[0]["permission_chain"][1]["identity"] == "orders-api-role"
    assert paths[0]["permission_chain"][1]["required_permissions"] == ["orders:read"]
    assert paths[0]["network_route"][0]["protocol"] == "https"
    assert paths[0]["assumptions"] == []


def test_isolated_confirmed_finding_is_not_called_an_attack_path():
    architecture = SystemArchitecture(
        components=[Component(id="database", name="DB", type="Database", trust_level="public")],
        flows=[],
    )
    finding = _finding()

    assert generate_attack_paths(architecture, [finding]) == []
    assert finding.explanation["attack_path_reason"] == "no_explicit_hop"
