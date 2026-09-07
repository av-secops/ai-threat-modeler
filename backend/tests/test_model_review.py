"""Review is a source-preserving stage, not a second threat detection engine."""

from copy import deepcopy
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Component, DataFlow, SystemArchitecture
from app.services.model_review import ModelReviewRequest, ReviewAnswer, prepare_model


def payload(**changes):
    return ModelReviewRequest.model_validate({
        'project_name': 'Guided review', 'use_local_slm': False, 'sources': [],
        'baseline': SystemArchitecture(components=[
            Component(id='api', name='API', type='API', trust_level='public'),
            Component(id='db', name='Database', type='Database', properties={'data_sensitivity': 'pii'}),
        ], flows=[DataFlow(source_id='api', target_id='db', protocol='TCP', assumed=False)]).model_dump(),
        **changes,
    })


def answer(request, **changes):
    return {'element_id': 'api', 'control': 'input_validation', 'state': 'present',
        'note': 'API validates request bodies using a schema.', 'reviewer': 'Architecture owner',
        'source_digest': prepare_model(request)['source_digest'], **changes}


def component(prepared, identifier):
    return next(c for c in prepared['architecture']['components'] if c['id'] == identifier)


def test_prepare_has_no_findings_or_security_score_and_does_not_mutate_input():
    request = payload()
    before = request.model_dump()
    prepared = prepare_model(request)
    assert request.model_dump() == before
    assert prepared['questions']
    assert 'threats' not in prepared and 'score' not in prepared
    assert prepared['readiness']['is_security_score'] is False


@pytest.mark.parametrize('state,value', [('present', True), ('absent', False), ('unknown', None), ('not_applicable', None)])
def test_answers_only_change_named_target(state, value):
    request = payload()
    request = request.model_copy(update={'answers': []})
    record = answer(request, state=state)
    reviewed = payload(answers=[record])
    result = prepare_model(reviewed)
    assert component(result, 'api')['properties'].get('input_validation') is value
    assert 'input_validation' not in component(result, 'db')['properties']
    if state == 'not_applicable':
        assert any(w['type'] == 'scope_exception' for w in result['warnings'])


def test_conflicting_answer_preserves_old_evidence():
    request = payload()
    request.baseline.components[0].properties['input_validation'] = False
    request.answers = [ReviewAnswer.model_validate(answer(request))]
    result = prepare_model(request)
    props = component(result, 'api')['properties']
    assert props['control_assertions']['input_validation'] == 'conflicting'
    assert {r['state'] for r in props['control_evidence']['input_validation']} == {'present', 'absent'}


def test_replaced_sources_invalidate_previous_answers():
    request = payload()
    record = answer(request)
    changed = payload(answers=[record], sources=[{'id': 'addition', 'name': 'Clarification', 'text': 'Redis stores API sessions.'}])
    result = prepare_model(changed)
    assert 'input_validation' not in component(result, 'api')['properties']
    assert any(w['type'] == 'stale_answer' for w in result['warnings'])


def test_flow_protocol_uses_existing_transport_derivation():
    request = payload()
    flow = prepare_model(request)['flows'][0]
    record = answer(request, element_id=flow['review_id'], control='protocol', value='TLS')
    result = prepare_model(payload(answers=[record]))
    actual = result['architecture']['flows'][0]
    assert actual['protocol'] == 'TLS'
    assert 'transport_encryption' not in actual['properties']
    assert not any(q['element_id'] == flow['review_id'] and q['control'] == 'protocol' for q in result['questions'])


def test_flow_edits_keep_stable_review_identity():
    request = payload()
    identifier = prepare_model(request)['flows'][0]['review_id']
    edits = [{'element_id': identifier, 'field': 'protocol', 'value': 'TLS', 'reason': 'Corrected protocol.'}]
    updated = prepare_model(payload(edits=edits))
    assert updated['flows'][0]['review_id'] == identifier
    edits.append({'element_id': identifier, 'field': 'data_type', 'value': 'phi', 'reason': 'Patient records flow here.'})
    assert prepare_model(payload(edits=edits))['flows'][0]['data_type'] == 'phi'


def test_added_flow_can_be_corrected_and_removed():
    edits = [{'element_id': 'new-flow', 'field': 'add_flow', 'value': {'source_id': 'db', 'target_id': 'api', 'protocol': 'unknown'}, 'reason': 'Database returns records.'},
        {'element_id': 'new-flow', 'field': 'protocol', 'value': 'TLS', 'reason': 'TLS is required.'}]
    result = prepare_model(payload(edits=edits))
    assert next(f for f in result['flows'] if f['review_id'] == 'new-flow')['protocol'] == 'TLS'


def test_removed_component_does_not_leave_dangling_flows():
    result = prepare_model(payload(edits=[{'element_id': 'db', 'field': 'remove', 'value': True, 'reason': 'Database is out of scope.'}]))
    assert len(result['architecture']['components']) == 1
    assert result['flows'] == []
    assert any(w['type'] == 'removed_flow' for w in result['warnings'])


def test_reference_reports_do_not_create_architecture():
    request = payload(baseline=None, sources=[
        {'id': 'notes', 'name': 'Design', 'text': 'React calls a Node.js API over HTTPS.'},
        {'id': 'report', 'name': 'Old report', 'text': 'Azure OpenAI and Pinecone host an AI chatbot.', 'metadata': {'role': 'reference_report'}},
    ])
    result = prepare_model(request)
    assert not any(c['type'] == 'ML Service' for c in result['architecture']['components'])


def test_mixed_environments_and_incomplete_extraction_stay_visible():
    request = payload(sources=[
        {'id': 'one', 'name': 'Production.pdf', 'text': 'Node.js API', 'environment': 'production', 'metadata': {'extraction_quality': 'partial', 'warning': 'Page 2 was unreadable.'}},
        {'id': 'two', 'name': 'Staging', 'text': 'Redis sessions', 'environment': 'staging'},
    ])
    warnings = prepare_model(request)['warnings']
    assert any('Page 2' in w['message'] for w in warnings)
    assert any(w['type'] == 'mixed_environments' for w in warnings)


@pytest.fixture(scope='module')
def client():
    with TestClient(app) as value:
        yield value


def test_scoped_review_api_analysis_and_prepare_agree(client):
    request = payload()
    record = answer(request, state='absent')
    body = payload(answers=[record]).model_dump()
    prepared = client.post('/model-review/prepare', json=body)
    result = client.post('/model-review/analyze', json=body)
    assert prepared.status_code == result.status_code == 200, result.text
    architecture = result.json()['architecture']
    assert architecture['components'] == prepared.json()['architecture']['components']
    assert architecture['flows'] == prepared.json()['architecture']['flows']
    assert result.json()['diff_summary'] is None
    assert result.json()['engine_status']['input_review']['is_security_score'] is False


def test_pdf_and_yaml_sources_survive_review_revisions(client):
    import pymupdf

    with pymupdf.open() as doc:
        page = doc.new_page()
        page.insert_text((40, 40), 'React calls a Node.js API over HTTPS. PostgreSQL stores patient records.')
        pdf = doc.tobytes()
    extracted = client.post('/model-review/sources', files=[
        ('files', ('design.pdf', pdf, 'application/pdf')),
        ('files', ('docker-compose.yml', b'services:\n  db:\n    image: postgres:16\n    ports: ["5432:5432"]\n', 'application/yaml')),
    ])
    assert extracted.status_code == 200, extracted.text
    sources = extracted.json()['sources']
    assert len(sources) == 2 and all(s['text'].strip() for s in sources)
    original = deepcopy(sources)
    body = payload(baseline=None, sources=sources).model_dump()
    first = client.post('/model-review/analyze', json=body)
    assert first.status_code == 200, first.text
    assert any(t['id'].startswith('IAC-') for t in first.json()['threats'])
    body['sources'].append({'id': 'redis', 'name': 'Session update', 'text': 'Redis stores Node.js API sessions.'})
    second = client.post('/model-review/analyze', json=body)
    assert second.status_code == 200, second.text
    assert body['sources'][:2] == original
    assert any(t['id'].startswith('IAC-') for t in second.json()['threats'])


def test_iac_plan_preview_warns_about_unresolved_values(client):
    plan = {'planned_values': {'root_module': {'resources': [{'address': 'aws_db_instance.db', 'type': 'aws_db_instance', 'name': 'db', 'values': {'storage_encrypted': False}}]}},
        'resource_changes': [{'address': 'aws_db_instance.db', 'change': {'after_unknown': {'publicly_accessible': True}}}]}
    body = payload(baseline=None, input_kind='iac', sources=[{'id': 'plan', 'name': 'plan.json', 'kind': 'json', 'text': json.dumps(plan)}]).model_dump()
    result = client.post('/model-review/prepare', json=body)
    assert result.status_code == 200, result.text
    assert any(w['type'] == 'unresolved_iac' for w in result.json()['warnings'])


@pytest.mark.parametrize('body', [
    {'project_name': 'Empty', 'sources': []},
    {'project_name': 'Invalid', 'sources': [{'id': 'one', 'name': 'x\nInjected', 'text': 'Node.js API'}]},
])
def test_invalid_input_is_an_actionable_client_error(client, body):
    assert client.post('/model-review/prepare', json=body).status_code in {400, 422}


def test_busy_review_is_not_an_internal_error(client, monkeypatch):
    from fastapi import HTTPException

    async def busy(*args, **kwargs):
        raise HTTPException(503, 'Analysis capacity is busy', headers={'Retry-After': '5'})

    monkeypatch.setattr('app.main._run_analysis', busy)
    response = client.post('/model-review/analyze', json=payload().model_dump())
    assert response.status_code == 503
    assert response.headers['retry-after'] == '5'


def test_flow_endpoint_changes_invalidate_scoped_answers():
    request = payload()
    flow = prepare_model(request)['flows'][0]
    request.answers = [ReviewAnswer.model_validate(answer(request, element_id=flow['review_id'], control='protocol', value='TLS'))]
    changed = request.model_dump()
    changed['edits'] = [
        {'element_id': flow['review_id'], 'field': 'source_id', 'value': 'db', 'reason': 'This is the return flow.'},
        {'element_id': flow['review_id'], 'field': 'target_id', 'value': 'api', 'reason': 'The API receives records.'},
    ]
    result = prepare_model(ModelReviewRequest.model_validate(changed))
    assert (result['flows'][0]['source_id'], result['flows'][0]['target_id']) == ('db', 'api')
    assert result['flows'][0]['review_id'] == flow['review_id']
    assert result['flows'][0]['protocol'] == 'TCP'
    assert any(w['type'] == 'stale_answer' for w in result['warnings'])
    changed['edits'][0]['value'] = 'missing'
    with pytest.raises(ValueError, match='endpoint'):
        prepare_model(ModelReviewRequest.model_validate(changed))


def test_encrypted_protocol_answer_does_not_erase_stated_plaintext():
    request = payload()
    request.baseline.flows[0].protocol = 'HTTP'
    flow = prepare_model(request)['flows'][0]
    request.answers = [ReviewAnswer.model_validate(answer(request, element_id=flow['review_id'], control='protocol', value='TLS'))]
    result = prepare_model(request)
    assert result['flows'][0]['protocol'] == 'HTTP'
    assert any(w['type'] == 'conflicting_answer' for w in result['warnings'])


def test_iac_context_keeps_findings_known_issues_and_file_evidence(client):
    sources = [
        {'id': 'tf', 'name': 'main.tf', 'kind': 'tf', 'text': 'resource "aws_db_instance" "records" {\n storage_encrypted = false\n publicly_accessible = true\n}'},
        {'id': 'notes', 'name': 'Follow-up context', 'kind': 'text', 'text': 'React calls a Node.js REST API. KNOWN ISSUES:\n- Node.js API has no input validation.'},
        {'id': 'pdf', 'name': 'design.pdf', 'kind': 'pdf', 'text': 'Redis stores API sessions.', 'metadata': {'extraction_quality': 'partial', 'warning': 'An unreadable page remains.'}},
        {'id': 'ref', 'name': 'old.pdf', 'kind': 'pdf', 'text': 'Azure OpenAI processes prompts.', 'metadata': {'role': 'reference_report'}},
    ]
    request = payload(baseline=None, input_kind='iac', sources=sources)
    prepared = prepare_model(request)
    metadata = prepared['architecture']['metadata']
    assert metadata['iac_findings'] and metadata['known_issues']
    assert all(f['source_file'] == 'main.tf' for f in metadata['iac_findings'])
    assert any('unreadable page' in w['message'] for w in prepared['warnings'])
    result = client.post('/model-review/analyze', json=request.model_dump())
    assert result.status_code == 200, result.text
    assert any(t['id'].startswith('IAC-') for t in result.json()['threats'])
    assert not any(c['type'] == 'ML Service' for c in prepared['architecture']['components'])


def test_excluded_iac_resource_keeps_evidence_without_reassigning_findings(client):
    sources = [{'id': name, 'name': name, 'kind': 'yml', 'text': 'services:\n  db:\n    image: postgres:16\n    ports: ["5432:5432"]\n'} for name in ('one.yml', 'two.yml')]
    request = payload(baseline=None, input_kind='iac', sources=sources)
    initial = prepare_model(request)
    components = initial['architecture']['components']
    assert len(components) == 2
    findings = initial['architecture']['metadata']['iac_findings']
    assert {f['resource_id'] for f in findings} == {c['id'] for c in components}
    excluded = components[1]['id']
    body = request.model_dump()
    body['edits'] = [{'element_id': excluded, 'field': 'remove', 'value': True, 'reason': 'Second environment is out of scope.'}]
    prepared = prepare_model(ModelReviewRequest.model_validate(body))
    metadata = prepared['architecture']['metadata']
    assert metadata['review_exclusions']
    assert all(f['resource_id'] != excluded for f in metadata['iac_findings'])
    assert metadata['iac_findings_count'] == len(metadata['iac_findings'])
    result = client.post('/model-review/analyze', json=body)
    assert result.status_code == 200, result.text
    static = [t for t in result.json()['threats'] if t['id'].startswith('IAC-')]
    assert static and all(t['component_id'] == components[0]['id'] for t in static)


def test_iac_review_honors_explicit_format_for_pasted_source():
    request = payload(baseline=None, input_kind='iac', sources=[{
        'id': 'paste', 'name': 'infrastructure.yml', 'kind': 'yml',
        'text': "param adminPassword string = 'qa-literal-password'\nresource db 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {}",
        'metadata': {'iac_format': 'bicep'},
    }])
    result = prepare_model(request)
    assert any(f['rule_id'] == 'IAC-BICEP-HARDCODED-SECRET' for f in result['architecture']['metadata']['iac_findings'])
