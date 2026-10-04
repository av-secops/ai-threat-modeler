from copy import deepcopy
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.comparison_engine import compare_reports, match_components
from app.services.enterprise_api import router
from app.services.product_store import ProductStore


def report(component_id='api', severity='High'):
    return {
        'architecture': {'components': [{'id': component_id, 'name': 'Billing API', 'type': 'api',
            'properties': {'account_id': '111', 'authentication': False}}], 'flows': [], 'trust_boundaries': []},
        'threats': [{'id': 'risk', 'rule_id': 'S-009', 'title': 'Missing authentication',
            'severity': severity, 'tier': 'Confirmed', 'affected_components': [component_id],
            'stride_category': 'Spoofing', 'evidence': ['architecture:1']}],
        'engine_status': {'engine_version': '2.3.2', 'knowledge_base': {'content_digest': 'one'}},
        'diagram': 'flowchart LR\napi[Billing API]',
    }


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.delenv('AEGIS_WORKSPACE_TOKENS', raising=False)
    monkeypatch.delenv('ENVIRONMENT', raising=False)
    store = ProductStore(tmp_path / 'comparison.sqlite3')
    product = store.create('products', 'Comparison product', 'tester')
    for number in (1, 2):
        release = store.create('releases', str(number), 'tester', product['id'])
        model = {'id': f'model-{number}', 'projectName': 'Billing', 'revisions': [
            {'number': 1, 'data': report(severity='High' if number == 1 else 'Critical')}],
            'reviewAnnotations': {f'workspace:model-{number}:revision:1': {'notes': {'risk': f'Reviewer note {number}'}}}}
        store.save_workspace(release['id'], model, None, 'production', 0, 'tester')
    app = FastAPI()
    app.state.product_store = store
    app.include_router(router)
    with TestClient(app) as client:
        yield client, store, product


def request():
    return {'before_workspace': 'model-1', 'after_workspace': 'model-2', 'before_revision': 1, 'after_revision': 1}


def test_active_api_uses_rich_engine_and_snapshot_annotations(api):
    client, _, product = api
    response = client.post('/enterprise/compare', json=request())
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['schema_version'] == '3'
    finding = next(c for c in result['changes'] if c['kind'] == 'finding')
    assert finding['status'] == 'worsened' and finding['review_changed']
    assert result['snapshots'][0]['product_id'] == product['id']
    assert len(result['snapshots'][0]['report_digest']) == 64
    assert len(result['diagrams']) == 2
    catalog = client.get(f"/enterprise/products/{product['id']}/comparison-catalog").json()
    assert len(catalog['models']) == 2
    assert catalog['models'][0]['revisions'][0]['number'] == 1


def test_saved_comparison_review_evidence_and_conflict(api):
    client, store, product = api
    response = client.post(f"/enterprise/products/{product['id']}/comparisons", json={'name': 'Release review', 'comparison': request()})
    assert response.status_code == 200, response.text
    saved = response.json()
    change = next(c for c in saved['result']['changes'] if c['kind'] == 'finding')
    path = f"/enterprise/comparisons/{saved['id']}/reviews/{change['id']}"
    review = {'expected_version': 1, 'status': 'verified_fixed', 'remarks': 'Verified in test deployment', 'evidence': ''}
    assert client.patch(path, json=review).status_code == 400
    review['evidence'] = 'Test run SECURITY-19, deployment digest 9876'
    updated = client.patch(path, json=review)
    assert updated.status_code == 200, updated.text
    assert updated.json()['version'] == 2
    assert client.patch(path, json=review).status_code == 409
    assert client.get(f"/enterprise/comparisons/{saved['id']}").json()['result'] == saved['result']
    assert store.workspace('model-2')['workspace']['revisions'][0]['data']['threats'][0]['severity'] == 'Critical'


def test_comparison_cannot_cross_products_or_scope(api):
    client, store, product = api
    other = store.create('products', 'Another product', 'tester')
    assert client.post(f"/enterprise/products/{other['id']}/comparisons", json={'name': 'Incorrect scope', 'comparison': request()}).status_code == 400
    release = store.create('releases', 'new', 'tester', other['id'])
    store.save_workspace(release['id'], {'id': 'foreign', 'revisions': [{'number': 1, 'data': report()}]}, None, 'production', 0, 'tester')
    assert client.post('/enterprise/compare', json=request() | {'after_workspace': 'foreign'}).status_code == 400
    assert client.post('/enterprise/compare', json=request() | {'after_workspace': 'model-1'}).status_code == 400


def test_automatic_identity_does_not_merge_accounts_or_reused_ids():
    a = report()['architecture']['components']
    b = deepcopy(a)
    b[0]['properties']['account_id'] = '222'
    assert match_components(a, b)[0] == {}
    b[0]['id'] = 'new-id'
    assert match_components(a, b)[0] == {}
    assert match_components(a, b, {'api': 'new-id'})[0] == {'api': 'new-id'}


def test_rename_mapping_and_evidence_only_changes_are_not_new_risks():
    before, after = report(), report('new-api')
    after['architecture']['components'][0]['name'] = 'Billing service'
    after['threats'][0]['evidence'] = ['architecture:19']
    result = compare_reports(before, after, component_mappings={'api': 'new-api'})
    assert not result['findings']['added']
    finding = next(c for c in result['changes'] if c['kind'] == 'finding')
    assert finding['status'] == 'evidence_changed'
    after['threats'] = []
    result = compare_reports(before, after, component_mappings={'api': 'new-api'})
    assert result['findings']['no_longer_reported']
    assert not any(c['status'] == 'verified_fixed' for c in result['changes'])


def test_compare_preserves_parallel_flows_and_input_snapshots():
    before, after = report(), report()
    for value in (before, after):
        value['architecture']['components'].append({'id': 'db', 'name': 'Billing database', 'type': 'database'})
    flows = [{'id': f'f{i}', 'source_id': 'api', 'target_id': 'db', 'protocol': 'https'} for i in range(2)]
    before['architecture']['flows'] = flows
    after['architecture']['flows'] = flows[:1]
    original = deepcopy(before)
    result = compare_reports(before, after)
    assert len(result['flows']['removed']) == 1
    assert before == original


def test_many_occurrences_are_matched_exactly_before_changes():
    from app.services.comparison_engine import pair_rows
    old = [{'id': str(i), 'operation': i % 7} for i in range(1500)]
    new = deepcopy(old[:-1])
    paired, removed, added = pair_rows(old, new, lambda row, side: 'parallel', lambda row, side: row['operation'])
    assert len(paired) == 1499 and len(removed) == 1 and not added


def test_finding_identity_uses_rule_even_if_generated_id_changes():
    before, after = report(), report()
    after['threats'][0]['id'] = 'regenerated-id'
    result = compare_reports(before, after)
    assert len(result['findings']['unchanged']) == 1
    assert not result['findings']['added']


def test_governed_catalog_digest_is_part_of_comparison_provenance():
    from app.services.comparison_engine import engine_identity, report_provenance
    before, after = report(), report()
    before['engine_status'] = {'knowledge_base': {'threats': 276, 'release': {'content_digest': 'a' * 64}}}
    after['engine_status'] = {'knowledge_base': {'threats': 276, 'release': {'content_digest': 'b' * 64}}}
    assert report_provenance(before)['knowledge_base']['content_digest'] == 'a' * 64
    assert engine_identity(before) != engine_identity(after)


def test_comparison_reads_authoritative_report_and_review_events(api):
    from app.services.assessment_store import AssessmentStore
    client, store, _ = api
    AssessmentStore(store)
    body = report(severity='Low')
    with store.connect() as db:
        db.execute('INSERT INTO assessment_sessions VALUES(?,1,?,?)', ('model-2', 'tester', time.time()))
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', ('native-2', 'model-2', json.dumps(body), 'tester', time.time()))
        db.execute("UPDATE workspaces SET payload=json_set(payload,'$.revisions[0].data.engine_status.assessment.report_id','native-2') WHERE id='model-2'")
        db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
            ('native-2', 'risk', json.dumps({'status': 'in_review', 'remarks': 'Authoritative note', 'owner': 'Security team'}), 'tester', time.time()))
    result = client.post('/enterprise/compare', json=request()).json()
    finding = next(row for row in result['changes'] if row['kind'] == 'finding')
    assert finding['after']['severity'] == 'Low'
    assert finding['review']['after']['notes'] == 'Authoritative note'
    assert result['snapshots'][1]['report_source'] == 'authoritative_assessment_result'
    # A reference to a different workspace must not become a cross-scope read.
    with store.connect() as db:
        db.execute("UPDATE workspaces SET payload=json_set(payload,'$.revisions[0].data.engine_status.assessment.report_id','native-2') WHERE id='model-1'")
    assert client.post('/enterprise/compare', json=request()).status_code == 400
