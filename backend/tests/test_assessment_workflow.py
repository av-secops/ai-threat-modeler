import io
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.models import Component, DataFlow, SystemArchitecture, TrustBoundary
from app.services.assessment_store import AssessmentStore
from app.services.product_store import ProductStore, StoreConflict
from app.services.model_review import ModelReviewRequest, ReviewEdit, prepare_model
from app.services.diagram_import import extract_diagram
from app.services.security_report_import import parse_report
from app.services.questionnaires import TemplateInput


ADMIN = {'name': 'architect', 'role': 'admin'}
EDITOR = {'name': 'product-engineer', 'role': 'editor'}


@pytest.fixture
def store(tmp_path):
    return AssessmentStore(ProductStore(tmp_path / 'workspaces.sqlite3'))


@pytest.fixture
def payload():
    return ModelReviewRequest(project_name='Test product', assessment_id='test-assessment', application_types=['web'],
        baseline=SystemArchitecture(components=[Component(id='ui', name='React', type='WebClient'),
            Component(id='api', name='Orders API', type='API'), Component(id='db', name='PostgreSQL', type='Database')],
            flows=[DataFlow(source_id='ui', target_id='api', protocol='HTTPS'), DataFlow(source_id='api', target_id='db', protocol='TLS')]))


def answered(store, payload, value='unknown'):
    preview = store.prepare(payload, ADMIN)
    answers = [{'question_id': q['id'], 'value': value, 'note': 'Architecture owner is investigating the configuration.',
        'evidence_digest': q['evidence_digest'], 'source_ids': []} for q in preview['questionnaire']['questions']]
    return payload.model_copy(update={'questionnaire_answers': answers, 'generate_dfd': True})


def test_questionnaire_gates_diagram_and_analysis(store, payload):
    before = store.prepare(payload.model_copy(update={'generate_dfd': True}), ADMIN)
    assert not before['diagram']
    assert before['questionnaire']['missing']
    with pytest.raises(ValueError, match='Complete'):
        store.prepare(payload, ADMIN, require_ready=True)
    complete = store.prepare(answered(store, payload), ADMIN, require_ready=True)
    assert complete['diagram'].startswith('flowchart')
    assert complete['questionnaire']['complete']
    api = next(c for c in complete['architecture']['components'] if c['id'] == 'api')
    assert api['properties'].get('authenticated') is None
    assert all(a['reviewer'] == 'architect' for a in complete['questionnaire']['answers'])


def test_changed_scope_invalidates_answers(store, payload):
    filled = answered(store, payload)
    changed = filled.model_copy(update={'environment': 'different-environment'})
    assert not store.prepare(changed, ADMIN)['questionnaire']['complete']


def test_not_applicable_needs_admin_and_rationale(store, payload):
    filled = answered(store, payload, 'not_applicable')
    with pytest.raises(ValueError, match='administrator'):
        store.prepare(filled, EDITOR)
    assert store.prepare(filled, ADMIN)['questionnaire']['complete']


def test_flow_numbers_survive_edits_and_deleted_numbers_are_not_reused(store, payload):
    preview = store.prepare(payload, ADMIN)
    first, second = preview['flows']
    edited = payload.model_copy(update={'edits': [ReviewEdit(element_id=first['id'], field='description', value='Send order intent', reason='Describe the same interaction.') ]})
    updated = store.prepare(edited, ADMIN)
    assert updated['flows'][0]['flow_number'] == first['flow_number']
    removed = payload.model_copy(update={'edits': [ReviewEdit(element_id=first['id'], field='remove', value=True, reason='Remove obsolete workflow.'),
        ReviewEdit(element_id='flow:new', field='add_flow', value={'source_id': 'ui', 'target_id': 'db', 'protocol': 'unknown'}, reason='Review proposed new path.')]})
    after = store.prepare(removed, ADMIN)
    assert [f['flow_number'] for f in after['flows']] == [second['flow_number'], 'F-003']


def test_parallel_flows_and_concurrent_number_assignment(store, payload):
    store.pin_template(payload.assessment_id, ADMIN['name'])
    def add(index):
        arch = SystemArchitecture(components=payload.baseline.components, flows=[DataFlow(id=f'flow:{index}', source_id='ui', target_id='api', protocol='HTTPS')])
        store.number_flows(payload.assessment_id, arch)
        return arch.flows[0].flow_number
    with ThreadPoolExecutor(max_workers=4) as pool:
        numbers = list(pool.map(add, range(12)))
    assert len(set(numbers)) == 12
    parallel = payload.baseline.model_copy(deep=True)
    parallel.flows.append(parallel.flows[0].model_copy(deep=True))
    result = prepare_model(payload.model_copy(update={'baseline': parallel}), render=False)
    assert len(result['flows']) == 3
    assert len({f['id'] for f in result['flows']}) == 3


def test_boundary_crud_and_cycle_rejection(payload):
    edits = [ReviewEdit(element_id='boundary:a', field='add_boundary', value={'name': 'Application', 'boundary_type': 'explicit', 'components': ['api']}, reason='Define application authority.'),
        ReviewEdit(element_id='boundary:b', field='add_boundary', value={'name': 'Data', 'boundary_type': 'explicit', 'components': ['db']}, reason='Define data authority.')]
    result = prepare_model(payload.model_copy(update={'edits': edits}), render=False)
    assert len(result['architecture']['trust_boundaries']) == 2
    with pytest.raises(ValueError, match='acyclic'):
        prepare_model(payload.model_copy(update={'edits': [*edits,
            ReviewEdit(element_id='boundary:a', field='parent_id', value='boundary:b', reason='Proposed nesting.'),
            ReviewEdit(element_id='boundary:b', field='parent_id', value='boundary:a', reason='Contradictory nesting.')]}))


def test_template_versions_pin_existing_assessments(store, payload):
    original = store.prepare(payload, ADMIN)['questionnaire']['template_version']
    template = store.templates()[0]
    with pytest.raises(StoreConflict):
        store.save_template({'name': template['name'], 'questions': template['questions'], 'expected_revision': template['revision']}, ADMIN['name'], original)
    draft = store.save_template({'name': 'Next questionnaire', 'questions': [{'key': 'new-question', 'text': 'Who owns this system?', 'answer_type': 'text'}]}, ADMIN['name'])
    store.transition_template(draft['version'], 'published', draft['revision'], ADMIN['name'])
    assert store.prepare(payload, ADMIN)['questionnaire']['template_version'] == original
    assert store.prepare(payload.model_copy(update={'assessment_id': 'new-assessment'}), ADMIN)['questionnaire']['template_version'] == draft['version']


def test_question_schema_rejects_executable_applicability():
    with pytest.raises(ValueError):
        TemplateInput(name='Unsafe', questions=[{'key': 'q', 'text': 'Who owns this?', 'expression': 'eval()'}])


def test_drawio_import_preserves_connectors_and_rejects_entities():
    raw = b'''<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>
    <mxCell id="a" vertex="1" value="Frontend" parent="1"/><mxCell id="b" vertex="1" value="Orders API" parent="1"/>
    <mxCell id="e" edge="1" source="a" target="b" value="HTTPS order request" style="endArrow=classic;"/>
    </root></mxGraphModel>'''
    _, _, meta = extract_diagram('architecture.drawio', raw)
    assert len(meta['diagram_model']['components']) == 2
    assert meta['diagram_model']['flows'][0]['protocol'] == 'HTTPS'
    assert meta['diagram_model']['flows'][0]['assumed'] is False
    with pytest.raises(Exception):
        extract_diagram('unsafe.xml', b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>')


def test_mermaid_import_does_not_execute_and_reports_unsupported_lines():
    _, _, meta = extract_diagram('system.mmd', b'flowchart LR\nA[React] -->|Request| B[API]\nclick A "javascript:alert(1)"')
    assert len(meta['diagram_model']['flows']) == 1
    assert 'Unsupported' in meta['warning']


def test_external_report_import_and_secret_masking():
    metadata = {'category': 'sast', 'title': 'Scan', 'source': 'Test scanner', 'report_date': '2026-09-19', 'environment': 'test', 'deployment_version': '26.09'}
    report = parse_report(json.dumps({'version': '2.1.0', 'runs': [{'results': [{'ruleId': 'X', 'level': 'warning', 'message': {'text': 'Review input validation'}}]}]}).encode(), 'scan.sarif', metadata)
    assert report['findings'][0]['severity'] == 'Medium'
    assert report['link_status'] == 'unlinked_pending_review'
    secret = parse_report(b'[{"file":"app.py","secret":"sensitive-value","message":"sensitive-value"}]', 'scan.json', {**metadata, 'category': 'secret_detection'})
    assert 'sensitive-value' not in json.dumps(secret)
    inventory = parse_report(b'{"bomFormat":"CycloneDX","components":[{"name":"pkg","version":"1"}]}', 'bom.json', {**metadata, 'category': 'sca'})
    assert not inventory['findings'] and len(inventory['inventory']) == 1


def test_review_history_concurrency_and_verification(store, payload):
    store.pin_template(payload.assessment_id, ADMIN['name'])
    with store.store.connect() as db:
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', ('report', payload.assessment_id, json.dumps({'threats': [{'id': 'risk'}]}), 'qa', 1))
    row = store.review('report', 'risk', {'status': 'in_review', 'remarks': 'Architect is reviewing.', 'expected_version': 0}, EDITOR)
    assert row['latest']['risk']['author'] == EDITOR['name']
    with pytest.raises(StoreConflict):
        store.review('report', 'risk', {'status': 'in_review', 'remarks': 'Stale update.', 'expected_version': 0}, EDITOR)
    with pytest.raises(ValueError, match='verification'):
        store.review('report', 'risk', {'status': 'verified_fixed', 'remarks': 'Claim without proof.'}, ADMIN)
    version = row['latest']['risk']['version']
    updated = store.review('report', 'risk', {'status': 'verified_fixed', 'remarks': 'Verified in test deployment.',
        'owner': 'product-team', 'acceptance_criteria': ['Unauthorized PHI access is rejected.'],
        'verification': [{'method': 'test', 'reference': 'Negative test report build 34.', 'result': 'passed',
                          'checked_at': '2026-01-01T00:00:00Z'}], 'expected_version': version}, ADMIN)
    assert len(updated['events']) == 2


def test_release_change_invalidates_answers_but_layout_does_not(store, payload):
    filled = answered(store, payload)
    assert store.prepare(filled.model_copy(update={'diagram_layout': {'api': {'x': 20., 'y': 90.}}}), ADMIN)['questionnaire']['complete']
    assert not store.prepare(filled.model_copy(update={'deployment_version': '26.10'}), ADMIN)['questionnaire']['complete']
    with pytest.raises(ValueError, match='duplicate responses'):
        store.prepare(filled.model_copy(update={'questionnaire_answers': filled.questionnaire_answers * 2}), ADMIN)


def test_explicit_flow_reference_does_not_expand_to_parallel_paths(store, payload):
    from app.engine.analyzer import ThreatAnalyzer
    from app.models import Threat
    architecture = SystemArchitecture.model_validate(store.prepare(payload, ADMIN)['architecture'])
    first = architecture.flows[0]
    architecture.flows.append(first.model_copy(update={'id': 'another', 'flow_number': 'F-099'}))
    finding = Threat(id='test', category='Tampering', title='Flow risk', description='Test flow-specific risk',
        severity='High', mitigation='Validate this interaction', affected_components=['api'], affected_data_flows=['ui->api'])
    incident = ThreatAnalyzer._flows_by_component(architecture)
    ThreatAnalyzer._describe_flow_context(finding, architecture, incident)
    assert finding.flow_reference_status == 'unresolved' and not finding.affected_flow_refs
    finding.affected_data_flows = [first.id]
    ThreatAnalyzer._describe_flow_context(finding, architecture, incident)
    assert [ref['number'] for ref in finding.affected_flow_refs] == [first.flow_number]
    finding.affected_data_flows = []
    ThreatAnalyzer._describe_flow_context(finding, architecture, incident)
    assert finding.flow_reference_status == 'not_flow_specific' and not finding.affected_flow_refs


def test_nested_boundaries_preserve_effective_membership(payload):
    from app.engine.canonical_diagram import render_view
    from app.engine.control_contracts import boundary_members
    architecture = payload.baseline.model_copy(deep=True)
    architecture.trust_boundaries = [TrustBoundary(id='outer', name='Private network', boundary_type='explicit', components=['api']),
        TrustBoundary(id='inner', name='Data zone', boundary_type='explicit', components=['db'], parent_id='outer')]
    members = boundary_members(architecture)
    assert members == [{'api', 'db'}, {'db'}]
    view = render_view(architecture)
    assert view['diagram'].index('Private network') < view['diagram'].index('Data zone')
    assert view['coverage']['boundary_membership']['db'] == ('Private network', 'Data zone')


@pytest.mark.parametrize('raw', [b'{"runs":[null],"version":"2.1.0"}', b'{"findings":"not a list"}',
    b'{"runs":[{"results":[{"message":"wrong"}]}],"version":"2.1.0"}', b'{"bomFormat":"CycloneDX","components":[null]}',
    b'{"runs":[{"results":[{"level":{}}]}],"version":"2.1.0"}'])
def test_malformed_scanner_reports_fail_as_validation_errors(raw):
    with pytest.raises(ValueError):
        parse_report(raw, 'scan.json', {'category': 'sast', 'report_date': '2026-09-19'})


def test_external_report_review_links_preserve_origins_and_reject_stale_writes(store, payload):
    preview = store.prepare(payload, ADMIN)
    with store.store.connect() as db:
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', ('model', payload.assessment_id,
            json.dumps({'architecture': preview['architecture'], 'engine_status': {'assessment': {'id': payload.assessment_id}}}), 'qa', 1))
    raw = b'{"findings":[{"id":"same-rule","title":"Risk one"},{"id":"same-rule","title":"Risk two"}]}'
    report = parse_report(raw, 'scan.json', {'category': 'sast', 'title': 'Imported scan', 'source': 'QA scanner',
        'report_date': '2026-09-19', 'environment': 'test', 'deployment_version': '26.09'})
    imported = store.import_report(payload.assessment_id, report, ADMIN['name'])
    assert store.import_report(payload.assessment_id, report, ADMIN['name'])['id'] == imported['id']
    assert len({f['import_id'] for f in imported['findings']}) == 2
    review = {'expected_revision': 1, 'status': 'under_review', 'remarks': 'Validated affected API scope.', 'model_report_id': 'model',
        'links': [{'finding_id': imported['findings'][0]['import_id'], 'component_ids': ['api'], 'flow_ids': [preview['flows'][0]['id']], 'reason': 'Source endpoint matches the modeled API.'}]}
    saved = store.review_security_report(payload.assessment_id, imported['id'], review, EDITOR)
    assert saved['review_history'][0]['author'] == EDITOR['name']
    assert saved['artifact_hash'] == imported['artifact_hash']
    with pytest.raises(StoreConflict):
        store.review_security_report(payload.assessment_id, imported['id'], review, EDITOR)
    review['expected_revision'] = 2
    review['links'][0]['component_ids'] = ['nonexistent']
    with pytest.raises(ValueError, match='unknown'):
        store.review_security_report(payload.assessment_id, imported['id'], review, EDITOR)


def test_questionnaire_and_report_routes_enforce_roles_and_job_gate(store, payload, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.services.assessment_api import router
    from app.services.enterprise_api import router as jobs_router
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({f'{role}-token': {'name': role, 'role': role} for role in ['viewer', 'editor', 'admin']}))
    app = FastAPI()
    app.state.assessment_store = store
    app.state.product_store = store.store
    app.include_router(router)
    app.include_router(jobs_router)
    headers = lambda role: {'Authorization': f'Bearer {role}-token'}
    value = {'name': 'Test', 'questions': [{'key': 'actors', 'text': 'Who are the actors?', 'answer_type': 'text'}]}
    with TestClient(app) as client:
        assert client.get('/enterprise/questionnaires').status_code == 401
        assert client.post('/enterprise/questionnaires', json=value, headers=headers('viewer')).status_code == 403
        assert client.post('/enterprise/questionnaires', json=value, headers=headers('editor')).status_code == 403
        assert client.post('/enterprise/questionnaires', json=value, headers=headers('admin')).status_code == 200
        assert client.post('/enterprise/jobs', json=payload.model_dump(), headers=headers('editor')).status_code == 400
        assert client.post('/enterprise/jobs', json=payload.model_dump(), headers=headers('viewer')).status_code == 403
        body = {'expected_revision': 1, 'status': 'reviewed', 'remarks': 'Review completed.', 'model_report_id': 'missing', 'links': []}
        assert client.post('/enterprise/assessments/test/security-reports/nope/review', json=body, headers=headers('viewer')).status_code == 403


@pytest.mark.parametrize('address', ['127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', 'fd00::1'])
def test_document_import_blocks_private_dns_before_connecting(address, monkeypatch):
    from app.services.source_import import import_url
    monkeypatch.setenv('AEGIS_DOCUMENT_IMPORT_HOSTS', 'docs.example.com')
    monkeypatch.setattr('socket.getaddrinfo', lambda *a, **kw: [(None, None, None, None, (address, 443))])
    with pytest.raises(ValueError, match='Private'):
        import_url('https://docs.example.com/architecture.pdf')


def test_pdf_diagram_import_is_bounded_and_has_page_evidence(monkeypatch):
    import pymupdf
    from app.services.diagram_import import extract_pdf_diagram
    monkeypatch.setattr('app.services.diagram_import._image', lambda raw, filename, **kwargs: (SystemArchitecture(
        components=[Component(id=filename, name='API', type='API', evidence=[{'document': filename}])], flows=[]), ['Confirm topology.']))
    with pymupdf.open() as pdf:
        pdf.new_page()
        pdf.new_page()
        raw = pdf.tobytes()
    text, kind, meta = extract_pdf_diagram('architecture.pdf', raw)
    assert kind == '.pdf' and text.count('API') == 2
    assert len(meta['diagram_model']['components']) == 2
    assert 'Page 2' in meta['warning']
    assert meta['diagram_pages'][0]['page'] == 1


def test_component_merge_keeps_flow_identity_boundary_membership_and_conflicts(store, payload):
    baseline = payload.baseline.model_copy(deep=True)
    baseline.components[1].properties['rate_limiting'] = True
    baseline.components.append(Component(id='duplicate', name='Orders API duplicate', type='API', properties={'rate_limiting': False}))
    baseline.flows.append(DataFlow(id='stated-flow', source_id='duplicate', target_id='db', protocol='TLS'))
    baseline.trust_boundaries.append(TrustBoundary(id='app', name='Application', boundary_type='explicit', components=['duplicate']))
    merged = store.prepare(payload.model_copy(update={'baseline': baseline, 'edits': [ReviewEdit(element_id='duplicate', field='merge_into', value='api', reason='Architect confirms these represent the same API deployment.')]}), ADMIN)
    assert len(merged['architecture']['components']) == 3
    assert next(f for f in merged['flows'] if f['id'] == 'stated-flow')['source_id'] == 'api'
    api = next(c for c in merged['architecture']['components'] if c['id'] == 'api')
    assert api['properties']['control_assertions']['rate_limiting'] == 'conflicting'
    assert merged['architecture']['trust_boundaries'][0]['components'] == ['api']
    assert merged['architecture']['metadata']['component_lineage'][0]['predecessor_id'] == 'duplicate'


def test_same_named_uploads_keep_distinct_evidence_and_identical_bytes_deduplicate():
    import asyncio
    from fastapi import UploadFile
    from app.services.document_ingestion import extract_documents
    uploads = [UploadFile(file=io.BytesIO(raw), filename='design.txt') for raw in [b'API calls PostgreSQL.', b'React calls API.', b'API calls PostgreSQL.']]
    text, documents = asyncio.run(extract_documents(uploads))
    assert len(documents) == 2
    assert len({d['filename'] for d in documents}) == 2
    assert text.count('API calls PostgreSQL.') == 1


def test_additive_migration_leaves_existing_workspaces_unchanged_and_backup_restores(tmp_path):
    import sqlite3
    original = ProductStore(tmp_path / 'legacy.sqlite3')
    product = original.create('products', 'Existing product', 'owner')
    release = original.create('releases', '26.09', 'owner', product['id'])
    workspace = {'id': 'old-model', 'projectName': 'Existing product', 'revisions': [{'number': 1, 'data': {'threats': []}}],
        'draft': {'payload': {'domain_profile': 'healthcare', 'sources': []}}}
    original.save_workspace(release['id'], workspace, None, 'production', 0, 'owner')
    before = original.workspace(workspace['id'])
    backup = tmp_path / 'backup.sqlite3'
    with sqlite3.connect(original.path) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    AssessmentStore(original)
    AssessmentStore(original)
    assert original.workspace(workspace['id']) == before
    assert ProductStore(backup).workspace(workspace['id']) == before
