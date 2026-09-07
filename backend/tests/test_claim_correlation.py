from copy import deepcopy

import pytest

from app.engine.canonical_model import canonicalize_architecture
from app.engine.control_contracts import control_value
from app.models import Component, DataFlow, SystemArchitecture
from app.services.model_review import ModelReviewRequest, prepare_model


def model(*sources, environment='', properties=None):
    documents = []
    blocks = []
    for i, source in enumerate(sources):
        source = {'text': source} if isinstance(source, str) else source
        name = source.get('name', f'design-{i}.pdf')
        documents.append({'filename': name, 'source_id': f'source-{i}', 'role': 'source_design', **source})
        blocks.append(f'Document: {name}\nType: pdf\nRole: source_design\nContent:\n{source["text"]}')
    return SystemArchitecture(components=[
        Component(id='orders', name='Orders API', type='API', properties={'environment': environment, **(properties or {})}),
        Component(id='billing', name='Billing API', type='API')], flows=[],
        metadata={'source_text': '\n\n---\n'.join(blocks), 'source_documents': documents})


def correlate(*sources, **kwargs):
    return canonicalize_architecture(model(*sources, **kwargs))[0]


def test_prompt_silence_does_not_override_documented_control():
    result = correlate('Orders API accepts customer requests.', '[Page 3]\nOrders API enforces rate limiting.')
    orders, billing = result.components
    assert control_value(orders.properties, 'rate_limiting') == 'present'
    assert control_value(billing.properties, 'rate_limiting') == 'unknown'
    claim = orders.properties['correlation_evidence'][0]
    assert claim['source_id'] == 'source-1' and claim['locator'] == 'page 3'
    assert claim['statement'] == 'Orders API enforces rate limiting.'


def test_conflicting_claims_keep_both_citations_without_absent_verdict():
    result = correlate('Orders API has no rate limiting.', 'Orders API enforces rate limiting.')
    props = result.components[0].properties
    assert control_value(props, 'rate_limiting') == 'conflicting'
    assert 'rate_limiting' not in props
    assert {f['source_id'] for f in props['correlation_evidence']} == {'source-0', 'source-1'}
    assert result.metadata['source_correlation']['conflicts']


@pytest.mark.parametrize('statement', ['Orders API will implement rate limiting.',
    'Orders API should enforce rate limiting.', 'Orders API rate limiting is planned.',
    'Orders API rate limiting is not documented.'])
def test_planned_or_unknown_controls_do_not_become_protection(statement):
    result = correlate(statement)
    assert control_value(result.components[0].properties, 'rate_limiting') == 'unknown'
    assert not result.components[0].properties.get('rate_limiting')


def test_endpoint_control_does_not_protect_every_endpoint():
    result = correlate('Orders API enforces rate limiting only on /login.')
    props = result.components[0].properties
    assert props['correlated_controls']['rate_limiting']['state'] == 'partial'
    assert control_value(props, 'rate_limiting') == 'unknown'
    assert props['correlation_evidence'][0]['scope']['endpoints'] == ['/login']


def test_staging_evidence_does_not_protect_production():
    result = correlate({'text': 'Orders API enforces rate limiting.', 'environment': 'staging'}, environment='prod')
    assert control_value(result.components[0].properties, 'rate_limiting') == 'unknown'
    assert result.components[0].properties['correlation_evidence'][0]['scope_status'] == 'scope_unconfirmed'


def test_equivalent_environment_names_match_and_releases_remain_scoped():
    result = correlate({'text': 'Orders API enforces rate limiting.', 'environment': 'prod', 'deployment_version': '26.02'},
                       environment='production', properties={'deployment_version': '26.02'})
    assert control_value(result.components[0].properties, 'rate_limiting') == 'present'
    other = correlate({'text': 'Orders API enforces rate limiting.', 'deployment_version': '26.01'}, properties={'deployment_version': '26.02'})
    assert control_value(other.components[0].properties, 'rate_limiting') == 'unknown'


def test_explicit_alias_and_ambiguous_subject_resolution():
    result = correlate('order-service enforces rate limiting.', properties={'aliases': ['order-service']})
    assert control_value(result.components[0].properties, 'rate_limiting') == 'present'
    ambiguous = correlate('The API enforces rate limiting.')
    assert ambiguous.metadata['source_correlation']['unresolved_claims']
    assert all(control_value(c.properties, 'rate_limiting') == 'unknown' for c in ambiguous.components)


def test_waf_does_not_imply_sql_or_all_components_protected():
    result = correlate('Orders API is protected by a WAF.')
    assert control_value(result.components[0].properties, 'waf_enabled') == 'present'
    assert control_value(result.components[0].properties, 'parameterized_queries') == 'unknown'
    assert control_value(result.components[1].properties, 'waf_enabled') == 'unknown'


def test_reconciliation_is_idempotent_including_iac_contradictions():
    result = correlate('Orders API enforces rate limiting.', properties={'resource_type': 'aws_api_gateway_rest_api', 'rate_limiting': False})
    again, _ = canonicalize_architecture(result.model_copy(deep=True))
    assert result.model_dump() == again.model_dump()
    assert control_value(again.components[0].properties, 'rate_limiting') == 'conflicting'


def test_repeated_passages_stay_attributed_to_each_document():
    result = correlate('Orders API enforces rate limiting.', 'Orders API enforces rate limiting.')
    assert len({f['source_id'] for f in result.components[0].properties['correlation_evidence']}) == 2


def request():
    return ModelReviewRequest(project_name='Correlation', sources=[{'id': 'design', 'name': 'Design',
        'text': 'React calls a Node.js API over HTTPS. PostgreSQL stores customer data.'}], use_local_slm=False)


def test_review_cache_returns_isolated_models_and_retains_version_contract():
    payload = request()
    payload.sources[0].version = 'document-3'
    payload.sources[0].metadata['deployment_version'] = '26.02'
    first = prepare_model(payload)
    first['architecture']['components'][0]['name'] = 'Corrupted by caller'
    second = prepare_model(payload)
    assert second['performance']['parse_cache_hit'] is True
    assert all(c['name'] != 'Corrupted by caller' for c in second['architecture']['components'])
    decision = second['architecture']['metadata']['source_reconciliation']['decisions'][0]
    assert decision['document_version'] == 'document-3' and decision['deployment_version'] == '26.02'


def test_new_answers_survive_unrelated_source_changes_but_not_control_changes():
    payload = request()
    first = prepare_model(payload)
    question = next(q for q in first['questions'] if q['control'] == 'rate_limiting' and q['element_id'] == 'node_js')
    data = payload.model_dump()
    data['answers'] = [{'element_id': question['element_id'], 'control': question['control'],
        'state': 'present', 'note': 'The owner confirmed application rate limiting.',
        'source_digest': first['source_digest'], 'evidence_digest': question['evidence_digest']}]
    data['sources'].append({'id': 'docs', 'name': 'Email notes', 'text': 'SendGrid sends transactional email.'})
    second = prepare_model(ModelReviewRequest.model_validate(data))
    assert not any(w['type'] == 'stale_answer' for w in second['warnings'])
    data['sources'][0]['text'] += ' Node.js API has no rate limiting.'
    third = prepare_model(ModelReviewRequest.model_validate(data))
    assert any(w['type'] == 'stale_answer' for w in third['warnings'])


def test_assumed_diagram_paths_remain_assumed_and_do_not_derive_transport():
    architecture = model('Orders API and Billing API exchange requests.')
    architecture.flows = [DataFlow(source_id='orders', target_id='billing', assumed=True, protocol='TLS')]
    result, _ = canonicalize_architecture(architecture)
    assert result.flows[0].assumed and 'transport_encryption' not in result.flows[0].properties
    assert result.metadata['source_correlation']['flow_gaps'][0]['assumed']


def test_alias_identifies_component_existence_with_source_evidence():
    result = correlate('order-service processes requests.', properties={'aliases': ['order-service']})
    assert result.components[0].properties['evidence_status'] == 'explicit'
    assert result.components[0].evidence[0]['document'] == 'design-0.pdf'
    assert all(e['source_type'] != 'inference' for e in result.components[0].evidence)


def test_known_issue_conflicts_are_not_reported_as_confirmed_absence():
    from app.engine.analyzer import ThreatAnalyzer
    payload = ModelReviewRequest(project_name='Conflict', use_local_slm=False, sources=[
        {'id': 'prompt', 'name': 'Prompt', 'text': 'Node.js API receives requests.\nKNOWN ISSUES:\n- Node.js API has no rate limiting.'},
        {'id': 'doc', 'name': 'Controls', 'text': 'Node.js API enforces rate limiting.'},
    ])
    prepared = prepare_model(payload)
    result = ThreatAnalyzer().analyze(SystemArchitecture.model_validate(prepared['architecture']), use_local_slm=False)
    findings = [t for t in result.threats if 'rate_limiting' in t.explanation.get('matched_controls', [])]
    assert findings and all(t.tier == 'Potential' for t in findings)
    assert any(t.explanation.get('correlated_evidence') for t in findings)


def test_replacing_an_explicitly_cited_source_invalidates_answer():
    payload = request()
    first = prepare_model(payload)
    question = next(q for q in first['questions'] if q['control'] == 'rate_limiting' and q['element_id'] == 'node_js')
    data = payload.model_dump()
    data['answers'] = [{'element_id': question['element_id'], 'control': question['control'], 'state': 'present',
        'note': 'Owner cites the source for this control.', 'source_ids': ['design'],
        'source_digests': {'design': first['source_digests']['design']}, 'evidence_digest': question['evidence_digest']}]
    assert not any(w['type'] == 'stale_answer' for w in prepare_model(ModelReviewRequest.model_validate(data))['warnings'])
    data['sources'][0]['text'] += ' The source document was revised.'
    assert any(w['type'] == 'stale_answer' for w in prepare_model(ModelReviewRequest.model_validate(data))['warnings'])
