from copy import deepcopy
import pytest

from app.models import Component, DataFlow, SystemArchitecture, Threat, TrustBoundary
from app.engine.canonical_diagram import render_view
from app.engine.literal_security import apply_literal_settings
from app.engine.policy_semantics import evaluate_access
from app.engine.finding_assurance import validate_evidence
from app.engine.issue_inventory import dispositions
from app.engine.workflow_checks import analyze_workflows
from app.services.release_comparison import compare_reports
from app.engine.knowledge_threat_engine import KnowledgeThreatEngine
from app.knowledge_base.loader import get_knowledge_base


def architecture(text='', properties=None):
    return SystemArchitecture(components=[Component(id='orders', name='Orders API', type='API', properties=properties or {})],
        flows=[], metadata={'source_text': text})


@pytest.mark.parametrize('text,expected', [
    ('Orders API debug_mode = true', True), ('Orders API debug_mode = false', False),
    ('Orders API should set debug_mode = false', None), ('Orders API debug_mode = maybe', None),
    ('Orders API debug_mode = true in staging', None),
    ('Orders API debug_mode = true\nOrders API debug_mode = false', None),
])
def test_literal_settings_require_typed_current_scope(text, expected):
    model = architecture(text, {'environment': 'production'})
    apply_literal_settings(model)
    assert model.components[0].properties.get('debug_mode') is expected


def test_parallel_flows_and_boundary_membership_are_not_collapsed():
    model = architecture()
    model.components.append(Component(id='db', name='Ledger', type='Database'))
    model.flows = [DataFlow(source_id='orders', target_id='db', protocol='TLS', data_type='financial') for _ in range(2)]
    model.trust_boundaries = [TrustBoundary(name='App', boundary_type='network', components=['orders']),
        TrustBoundary(name='Data', boundary_type='network', components=['db'])]
    view = render_view(model)
    assert view['coverage']['flows_drawn'] == 2
    assert view['diagram'].count('==>') == 2
    assert view['coverage']['boundary_crossings_drawn'] == 2
    assert view['coverage']['boundary_membership']['db'] == ('Data',)
    assert not render_view(model, node_limit=1)['coverage']['complete']


def test_canonical_diagram_highlights_only_confirmed_visible_components():
    model = architecture()
    threat = Threat(id='test', title='Test', description='Test', category='Tampering',
        severity='High', mitigation='Validate inputs.', tier='Confirmed', component='orders')
    assert 'stroke:#dc2626' in render_view(model, threats=[threat])['diagram']
    assert 'stroke:#dc2626' not in render_view(model, selected=[], threats=[threat])['diagram']
    threat.tier = 'Potential'
    assert 'stroke:#dc2626' not in render_view(model, threats=[threat])['diagram']


def query(**changes):
    return {'principal': 'arn:aws:iam::111111111111:user/alice', 'principal_type': 'iam_user',
        'action': 's3:GetObject', 'resource': 'arn:aws:s3:::images/a', 'policy_inventory_complete': True,
        'policy_sets': {'identity': [{'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}]}, **changes}


def test_policy_allow_deny_ceiling_and_unknown():
    assert evaluate_access(query())['decision'] == 'allowed_in_supplied_policies'
    assert evaluate_access(query(policy_inventory_complete=False))['decision'] == 'unknown'
    denied = query()
    denied['policy_sets']['identity'][0]['Statement'].append({'Effect': 'Deny', 'Action': '*', 'Resource': '*'})
    assert evaluate_access(denied)['decision'] == 'explicit_deny'
    boundary = query()
    boundary['policy_sets']['boundaries'] = [{'Statement': [{'Effect': 'Allow', 'Action': 's3:ListBucket', 'Resource': '*'}]}]
    assert evaluate_access(boundary)['decision'] == 'implicit_deny'
    boundary['policy_sets']['resource'] = query()['policy_sets']['identity']
    assert evaluate_access(boundary)['decision'] == 'unknown'
    unresolved = query()
    unresolved['policy_sets']['identity'][0]['Statement'][0]['Condition'] = {'IpAddress': {'aws:SourceIp': '10.0.0.0/8'}}
    assert evaluate_access(unresolved)['decision'] == 'unknown'


def finding(**changes):
    return Threat(id='test', title='Missing MFA', description='MFA absent', category='Spoofing', severity='High',
        mitigation='Enable MFA', affected_components=['orders'], tier='Confirmed',
        explanation={'matched_controls': ['mfa_enabled']}, **changes)


def test_unrelated_absence_cannot_override_present_control():
    model = architecture(properties={'correlated_controls': {'mfa_enabled': {'state': 'present'}},
        'correlation_evidence': [{'control': 'rate_limiting', 'state': 'absent', 'applicable': True, 'statement': 'No rate limit'}]})
    threat = finding(evidence_details=[{'statement': 'No rate limit'}])
    validate_evidence([threat], model)
    assert threat.tier == 'Potential'
    assert threat.explanation['evidence_validation']['status'] == 'requires_review'


def test_source_issue_cannot_be_accounted_by_other_component():
    model = architecture('Known issues:\n- Orders API lacks MFA')
    threat = finding(evidence_details=[{'statement': 'Orders API lacks MFA'}])
    threat.affected_components = ['billing']
    assert dispositions(model, [threat])['unaccounted'] == 1


def test_inline_issue_heading_and_explicit_runtime_alias():
    from app.engine.parser import ArchitectureParser
    parser = ArchitectureParser()
    text = 'React calls the Orders API. The Orders API is a Node.js REST API. KNOWN ISSUES:\n- Orders API has no input validation.'
    assert len(parser.parse_known_issues(text)) == 1
    model = parser.parse(text)
    assert not ({'node_js', 'orders_api'} <= {c.id for c in model.components})


def test_system_counts_match_canonical_boundaries_not_only_trust_labels():
    from app.engine.canonical_model import canonicalize_architecture
    from app.engine.output_model import build_system_model
    model = architecture()
    model.components.append(Component(id='other', name='Other API', type='API'))
    model.flows = [DataFlow(source_id='orders', target_id='other', protocol='HTTPS')]
    model.trust_boundaries = [TrustBoundary(name='Account A', boundary_type='account', components=['orders']),
        TrustBoundary(name='Account B', boundary_type='account', components=['other'])]
    model = canonicalize_architecture(model)[0]
    assert len(build_system_model(model)['boundary_crossings']) == render_view(model)['coverage']['boundary_crossings_drawn'] == 1


def test_workflow_absence_requires_control_specific_evidence():
    model = architecture()
    model.metadata['workflows'] = [{'id': 'refund', 'name': 'Refund', 'components': ['orders'],
        'invariants': {'atomic_debit': False, 'tenant_binding': False},
        'evidence': [{'control': 'atomic_debit', 'statement': 'Balance check and debit are separate transactions.'}]}]
    risks, assessed = analyze_workflows(model)
    assert len(risks) == 1 and 'atomic_debit' in risks[0].id
    assert len(assessed) == 6


def test_comparison_preserves_parallel_count_and_ignores_runtime_diagnostics():
    flow = {'source_id': 'a', 'target_id': 'b', 'protocol': 'TLS'}
    old = {'architecture': {'flows': [flow, deepcopy(flow)]}, 'engine_status': {'knowledge_base': {'content_digest': 'abc', 'findings': 9}}}
    new = deepcopy(old)
    new['architecture']['flows'].pop()
    new['engine_status']['knowledge_base']['findings'] = 8
    compared = compare_reports(old, new)
    assert len(compared['flows']['removed']) == 1 and not compared['engine_changed']
    new['engine_status']['knowledge_base']['content_digest'] = 'changed'
    assert compare_reports(old, new)['engine_changed']


def test_predicate_cache_invalidates_on_control_change_and_same_site_is_not_enough():
    engine = KnowledgeThreatEngine(get_knowledge_base())
    model = architecture(properties={'debug_mode': True})
    _, first = engine.analyze(model)
    _, cached = engine.analyze(model)
    assert first['predicate_cache_hits'] == 0 and cached['predicate_cache_hits'] > 0
    model.components[0].properties['debug_mode'] = False
    _, changed = engine.analyze(model)
    assert changed['predicate_cache_hits'] == 0
    client = Component(id='web', name='Web', type='WebClient', properties={'same_site_cookie': 'none'})
    model.components = [client]
    risks, _ = engine.analyze(model)
    assert not any((r.explanation or {}).get('rule_id') == 'S-006' for r in risks)
    client.properties.update(cookie_authentication=True, csrf_protection=False)
    risks, _ = engine.analyze(model)
    assert any('S-006' in r.id for r in risks)
