import re

import networkx as nx

from app.engine.mermaid_generator import diagram_coverage, generate_mermaid
from app.engine.analyzer import ThreatAnalyzer


def test_diagram_uses_standard_dfd_shapes_and_trust_boundaries():
    graph = nx.DiGraph()
    graph.add_node('browser', label='Browser', type='WebClient', external=True)
    graph.add_node('api', label='Public API', type='API Gateway')
    graph.add_edge(
        'browser',
        'api',
        protocol='https',
        crosses_trust_boundary=True,
    )

    diagram = generate_mermaid(graph, enhanced=True)

    assert 'External Entity' in diagram
    assert 'Internet / Client Boundary' in diagram
    assert 'direction LR' in diagram
    assert 'E1 Browser' in diagram
    assert '1.0 Public API' in diagram
    assert 'stroke-dasharray: 7 4' in diagram
    assert '==>|"HTTPS"|' in diagram


def test_every_modelled_component_and_flow_is_drawn():
    """A reviewer cannot threat model against a component the diagram omits."""
    graph = nx.DiGraph()
    graph.add_node('web', label='React SPA', type='WebClient')
    graph.add_node('gateway', label='API Gateway', type='API Gateway')

    for index in range(8):
        service = f'service_{index}'
        database = f'database_{index}'
        graph.add_node(service, label=f'Platform Service {index}', type='Service')
        graph.add_node(database, label=f'Data Store {index}', type='Database')
        graph.add_edge('web', 'gateway', protocol='https')
        graph.add_edge('gateway', service, protocol='https')
        graph.add_edge(service, database, protocol='tcp')

    diagram = generate_mermaid(graph, enhanced=True)
    coverage = diagram_coverage(graph)

    assert 'Application Trust Boundary' in diagram
    assert 'Data Trust Boundary' in diagram
    for index in range(8):
        assert f'Platform Service {index}' in diagram
        assert f'Data Store {index}' in diagram
    assert coverage['complete'] is True
    assert coverage['components_drawn'] == coverage['components_in_model'] == 18
    assert coverage['flows_drawn'] == coverage['flows_in_model']


def test_sibling_data_stores_are_both_drawn():
    graph = nx.DiGraph()
    graph.add_node('client', label='Client', type='WebClient', public_access=True)
    graph.add_node('api', label='API', type='API')
    graph.add_node('primary', label='Primary DB', type='Database')
    graph.add_node('cache', label='Cache', type='Database')
    graph.add_edge('client', 'api', protocol='https')
    graph.add_edge('api', 'primary', protocol='tcp')
    graph.add_edge('api', 'cache', protocol='tcp')

    diagram = generate_mermaid(graph, enhanced=True)

    assert diagram.count('-->|') + diagram.count('==>|') == 3
    assert 'Primary DB' in diagram
    assert 'Cache' in diagram


def test_observability_components_are_excluded_but_accounted_for():
    graph = nx.DiGraph()
    graph.add_node('api', label='API', type='API')
    graph.add_node('primary', label='Primary DB', type='Database')
    graph.add_node('guardduty', label='GuardDuty', type='Threat Detection')
    graph.add_edge('api', 'primary', protocol='tcp')

    diagram = generate_mermaid(graph, enhanced=True)
    coverage = diagram_coverage(graph)

    assert 'GuardDuty' not in diagram.split('classDef')[0].replace('%% Excluded', '')
    assert coverage['components_excluded_as_non_flow'] == 1
    assert coverage['excluded_component_ids'] == ['guardduty']
    assert 'Excluded as not part of a data flow: guardduty' in diagram


def test_a_graph_beyond_the_budget_states_what_it_hides():
    graph = nx.DiGraph()
    for index in range(60):
        graph.add_node(f'service_{index}', label=f'Service {index}', type='Service')
    for index in range(59):
        graph.add_edge(f'service_{index}', f'service_{index + 1}', protocol='https')

    diagram = generate_mermaid(graph, enhanced=True)
    coverage = diagram_coverage(graph)

    assert coverage['complete'] is False
    assert coverage['components_drawn'] == 40
    assert coverage['components_hidden_for_readability'] == 20
    assert 'further components in this zone' in diagram
    assert 'Coverage: 40 of 60 components' in diagram


def test_edge_labels_are_quoted_so_punctuation_cannot_break_the_render():
    """An unquoted bracket in a label is read as node syntax and kills the diagram."""
    graph = nx.DiGraph()
    graph.add_node('client', label='Mobile App (iOS)', type='WebClient', public_access=True)
    graph.add_node('api', label='API Gateway', type='API Gateway')
    graph.add_node('idp', label='Auth0', type='Identity Provider', external=True)
    graph.add_edge('client', 'api', protocol='https', data_type='financial')
    graph.add_edge('api', 'idp', protocol='https', data_type='credentials', origin='assumed')

    diagram = generate_mermaid(graph)

    edge_labels = re.findall(r'(?:-->|==>|-\.->)\|([^|]*)\|', diagram)
    assert edge_labels, 'no edges were drawn'
    for label in edge_labels:
        assert label.startswith('"') and label.endswith('"'), f'unquoted edge label: {label}'
    assert '-.->|"HTTPS / credentials (assumed)"|' in diagram


def test_a_label_carrying_a_pipe_cannot_end_the_label_early():
    graph = nx.DiGraph()
    graph.add_node('a', label='A', type='Service')
    graph.add_node('b', label='B', type='Database')
    graph.add_edge('a', 'b', protocol='tcp|raw', data_type='pii')

    diagram = generate_mermaid(graph)

    assert re.search(r'\|"[^"|]*"\|', diagram)


def test_confirmed_findings_are_outlined_on_the_diagram():
    graph = nx.DiGraph()
    graph.add_node('api', label='Payments API', type='API')
    graph.add_node('db', label='Ledger DB', type='Database')
    graph.add_edge('api', 'db', protocol='tcp')

    threats = [
        {'tier': 'Confirmed', 'affected_component': 'api', 'affected_components': ['api']},
        {'tier': 'Potential', 'affected_component': 'db', 'affected_components': ['db']},
    ]
    diagram = generate_mermaid(graph, threats=threats)

    assert 'classDef dfdFinding' in diagram
    assert 'class api dfdFinding' in diagram
    assert 'class db dfdStore' in diagram
    assert diagram_coverage(graph, threats)['components_with_confirmed_findings'] == 1


def test_healthcare_template_keeps_security_relevant_topology():
    description = """Healthcare records management system with:
- React frontend with role-based access (Doctor, Nurse, Admin)
- .NET Core REST API with OAuth2 + MFA authentication
- PostgreSQL for patient records (PHI/PII data)
- Redis for session management
- Azure Blob Storage for medical imaging (DICOM files)
- HL7 FHIR API for interoperability
- Azure AD for identity management
- Encryption at rest (AES-256) and in transit (TLS 1.3)
- Audit logging for all data access
- HIPAA-compliant infrastructure on Azure

KNOWN ISSUES:
- Break-the-glass access procedure not audited separately
- No data loss prevention (DLP) on file downloads
- Session timeout set to 8 hours (too long for PHI access)"""

    result = ThreatAnalyzer().analyze_from_text(
        description, "Healthcare System", use_local_slm=False, domain_profile="healthcare"
    )
    edges = {(flow.source_id, flow.target_id) for flow in result.architecture.flows}

    assert {
        ("react", "rest_api"),
        ("rest_api", "hl7_fhir_api"),
        ("rest_api", "postgresql"),
        ("rest_api", "redis"),
        ("rest_api", "azure_blob"),
        ("rest_api", "azure_ad"),
    }.issubset(edges)
    assert ("hl7_fhir_api", "postgresql") not in edges
    assert ("hl7_fhir_api", "redis") not in edges

    for label in ("React", "Rest Api", "HL7 FHIR API", "Postgresql", "REDIS", "Azure Blob", "Azure Ad"):
        assert label in result.mermaid_diagram
    for boundary in result.architecture.trust_boundaries:
        if boundary.components:
            assert boundary.name in result.mermaid_diagram
    assert result.engine_status['diagram_coverage']['flows_in_model'] == len(result.architecture.flows)
