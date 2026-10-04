from copy import deepcopy

import pytest

from app.models import Component, DataFlow, SystemArchitecture, TrustBoundary
from app.services.assessment_store import AssessmentStore
from app.services.model_review import ModelReviewRequest, ReviewSource
from app.services.product_store import ProductStore
from app.services.questionnaires import build_questions, default_template, TemplateInput


ADMIN = {'name': 'Architect', 'role': 'admin'}
EDITOR = {'name': 'Engineer', 'role': 'editor'}
AUTH = {'key': 'authentication', 'text': 'Is authentication enforced?', 'component_types': ['API'], 'control': 'authenticated'}


@pytest.fixture
def store(tmp_path):
    return AssessmentStore(ProductStore(tmp_path / 'adaptive.sqlite3'))


@pytest.fixture
def payload():
    return ModelReviewRequest(project_name='Order platform', assessment_id='assessment', application_types=['api'],
        environment='production', deployment_version='26.09', baseline=SystemArchitecture(components=[
            Component(id='orders', name='Orders API', type='API'), Component(id='billing', name='Billing API', type='API')],
            flows=[DataFlow(source_id='orders', target_id='billing', protocol='HTTPS')]))


def template(*definitions):
    return {'version': 1, **TemplateInput(name='Adaptive', questions=list(definitions)).model_dump()}


def rows(payload, definitions=None, previous=None):
    return build_questions(definitions or template(AUTH), payload.baseline, payload, previous)


def manual(q, value='unknown', **extra):
    return {'question_id': q['id'], 'value': value, 'note': 'Awaiting component owner confirmation.',
            'evidence_digest': q['evidence_digest'], **extra}


def confirmation(q, **extra):
    p = q['proposal']
    return {'question_id': q['id'], 'value': p['value'], 'note': '', 'basis': p['basis'],
        'source_ids': p['source_ids'], 'proposal_digest': p['digest'], 'evidence_digest': q['evidence_digest'], **extra}


def cited(payload, state='present'):
    value = payload.model_copy(deep=True)
    statement = f'Orders API {"requires" if state == "present" else "does not require"} authentication.'
    value.sources = [ReviewSource(id='design', name='Design.md', text=statement)]
    record = {'kind': 'control', 'control': 'authenticated', 'state': state, 'source_id': 'design',
        'document': 'Design.md', 'line': 1, 'statement': statement, 'element_id': 'orders', 'applicable': True, 'scope': {}}
    value.baseline.components[0].properties.update({'authenticated': state == 'present', 'control_assertions': {'authenticated': state},
        'control_evidence': {'authenticated': [record]}, 'correlation_evidence': [record]})
    return value


def test_many_services_keep_component_records_but_share_control_groups(payload):
    payload.baseline.components = [Component(id=f'api-{i}', name=f'Service {i}', type='Service') for i in range(12)]
    questions = rows(payload, {'version': 1, **default_template()})
    assert len(questions) == 88
    assert len({q['group_key'] for q in questions}) == 11
    assert all(q['status'] == 'unanswered' for q in questions)


@pytest.mark.parametrize('field', ['environment', 'cloud_account', 'tenant_id'])
def test_group_scope_separates_security_authorities(payload, field):
    assert len({q['group_key'] for q in rows(payload)}) == 1
    payload.baseline.components[1].properties[field] = 'different'
    assert len({q['group_key'] for q in rows(payload)}) == 2


def test_group_scope_separates_boundaries_and_trust(payload):
    payload.baseline.trust_boundaries = [TrustBoundary(id='zone', name='Private', boundary_type='explicit', components=['orders'])]
    assert len({q['group_key'] for q in rows(payload)}) == 2
    payload.baseline.trust_boundaries = []
    payload.baseline.components[1].trust_level = 'external'
    assert len({q['group_key'] for q in rows(payload)}) == 2


@pytest.mark.parametrize('state', ['present', 'absent'])
def test_cited_suggestions_require_explicit_confirmation(payload, state):
    payload = cited(payload, state)
    q, other = rows(payload)
    assert q['proposal']['value'] == state and q['status'] == 'unanswered'
    assert not other['proposal']
    payload.questionnaire_answers = [confirmation(q)]
    q, other = rows(payload)
    assert q['status'] == 'answered' and q['response']['note'].startswith('Design.md:1:')
    assert other['status'] == 'unanswered'


@pytest.mark.parametrize('issue', ['inferred', 'conflicting', 'planned', 'partial', 'endpoint', 'workflow', 'scope', 'wrong_text', 'wrong_control', 'wrong_component', 'excluded', 'reference', 'environment', 'release'])
def test_unsafe_or_unscoped_suggestions_are_not_bulk_confirmable(payload, issue):
    payload = cited(payload)
    props = payload.baseline.components[0].properties
    record = props['control_evidence']['authenticated'][0]
    if issue == 'inferred':
        props.pop('control_evidence')
    elif issue in {'conflicting', 'planned', 'partial'}:
        props['control_assertions']['authenticated'] = issue
    elif issue == 'endpoint':
        record['scope']['endpoints'] = ['/login']
    elif issue == 'workflow':
        record['scope']['workflow_restricted'] = True
    elif issue == 'scope':
        record['applicable'] = False
    elif issue == 'wrong_text':
        payload.sources[0].text = 'The design does not specify authentication.'
    elif issue == 'wrong_control':
        record['control'] = 'rate_limiting'
    elif issue == 'wrong_component':
        record['element_id'] = 'billing'
    elif issue == 'excluded':
        payload.sources[0].included = False
    elif issue == 'reference':
        payload.sources[0].metadata['role'] = 'reference_report'
    elif issue == 'environment':
        payload.sources[0].environment = 'test'
    else:
        payload.sources[0].metadata['deployment_version'] = '26.08'
    q = rows(payload)[0]
    assert q['proposal'] is None
    if issue in {'conflicting', 'endpoint', 'workflow', 'scope'}:
        assert q['requires_individual_review']


@pytest.mark.parametrize('field,value', [('value', 'absent'), ('proposal_digest', 'a' * 64), ('source_ids', []), ('basis', 'carry_forward')])
def test_tampered_proposal_confirmation_is_rejected(payload, field, value):
    payload = cited(payload)
    payload.questionnaire_answers = [confirmation(rows(payload)[0], **{field: value})]
    with pytest.raises(ValueError, match='suggested answer changed'):
        rows(payload)


def test_changed_claim_invalidates_existing_confirmation(payload):
    original = cited(payload)
    updated = cited(payload, 'absent')
    updated.questionnaire_answers = [confirmation(rows(original)[0])]
    assert rows(updated)[0]['status'] == 'stale'


def test_conditions_keep_unknown_and_partial_followups_visible(payload):
    definitions = template(AUTH, {'key': 'session', 'text': 'Are tokens revoked?', 'component_types': ['API'],
        'control': 'token_revocation', 'when': {'question_key': 'authentication', 'values': ['present'], 'scope': 'same_component'}})
    for state, status in [('absent', 'not_triggered'), ('present', 'unanswered'), ('unknown', 'unanswered'), ('partial', 'unanswered')]:
        payload.questionnaire_answers = [manual(rows(payload, definitions)[0], state)]
        result = {q['id']: q for q in rows(payload, definitions)}
        assert result['session:orders']['status'] == status
        assert result['session:billing']['status'] == 'unanswered'
    payload.questionnaire_answers = []
    qs = rows(payload, definitions)
    payload.questionnaire_answers = [manual(qs[0], 'present')]
    session = next(q for q in rows(payload, definitions) if q['id'] == 'session:orders')
    payload.questionnaire_answers = [manual(qs[0], 'partial'), manual(session)]
    assert next(q for q in rows(payload, definitions) if q['id'] == 'session:orders')['status'] == 'stale'


@pytest.mark.parametrize('bad', [
    {'question_key': 'later', 'values': ['present']},
    {'question_key': 'authentication', 'values': ['present'], 'scope': 'assessment'},
    {'question_key': 'authentication', 'values': ['invalid'], 'scope': 'same_component'},
])
def test_invalid_dependencies_rejected(bad):
    with pytest.raises(ValueError):
        template(AUTH, {**AUTH, 'key': 'later', 'when': bad})


def test_technology_filters_are_literal_and_admin_priority_preserved(payload):
    payload.baseline.components[0].properties['technology'] = 'Node.js'
    assert len(rows(payload, template({**AUTH, 'technologies': ['Node.js']}))) == 1
    assert not rows(payload, template({**AUTH, 'technologies': ['NodeXjs']}))
    assert rows(payload, template({**AUTH, 'priority': 'low'}))[0]['priority'] == 'low'
    assert rows(payload, template({**AUTH, 'priority': 'normal'}))[0]['priority'] == 'normal'


def test_manual_unknown_needs_reason_and_never_adds_protective_property(store, payload):
    initial = store.prepare(payload, ADMIN)
    payload.questionnaire_answers = [manual(q, owner='Identity team') for q in initial['questionnaire']['questions']]
    result = store.prepare(payload, EDITOR, require_ready=True)
    assert result['questionnaire']['complete']
    assert all(a['owner'] == 'Identity team' and a['reviewer'] == 'Engineer' for a in result['questionnaire']['answers'])
    assert all(c['properties'].get('authenticated') is None for c in result['architecture']['components'])
    payload.questionnaire_answers[0]['note'] = ' '
    with pytest.raises(ValueError, match='explanation'):
        store.prepare(payload, EDITOR)


def test_mixed_batch_is_atomic_and_required_gate_remains(store, payload):
    qs = store.prepare(payload, ADMIN)['questionnaire']['questions']
    payload.questionnaire_answers = [manual(qs[0]), manual(qs[1], 'not_applicable')]
    with pytest.raises(ValueError, match='administrator'):
        store.prepare(payload, EDITOR)
    with store.store.read_snapshot() as db:
        assert db.execute('SELECT COUNT(*) FROM assessment_answer_events').fetchone()[0] == 0
    payload.questionnaire_answers = [manual(qs[0])]
    assert not store.prepare(payload, EDITOR)['questionnaire']['complete']
    with pytest.raises(ValueError, match='Complete'):
        store.prepare(payload, EDITOR, require_ready=True)


def test_real_document_correlation_generates_cited_control_proposal(store, payload):
    payload.baseline = None
    payload.sources = [ReviewSource(id='design', name='Design.md', text='Orders API has rate limiting enabled.\nBilling API has no rate limiting.')]
    result = store.prepare(payload, ADMIN)
    qs = result['questionnaire']['questions']
    auth = next(q for q in qs if q['id'] == 'rate-limiting:orders_api')
    assert auth['proposal']['value'] == 'present'
    assert auth['proposal']['evidence'][0]['source_id'] == 'design'
    payload.questionnaire_answers = [confirmation(auth)]
    recorded = store.prepare(payload, EDITOR)['questionnaire']['answers'][0]
    assert recorded['confirmation_basis'] == 'source'
    assert recorded['proposal_evidence'] and recorded['source_fingerprints']
    assert recorded['reviewer'] == 'Engineer'


def clone_fixture(store, payload):
    p = store.store.create('products', 'Test platform', 'Architect')
    r = store.store.create('releases', '26.09', 'Architect', p['id'])
    initial = store.prepare(payload, ADMIN)
    payload.questionnaire_answers = [manual(q) for q in initial['questionnaire']['questions']]
    store.prepare(payload, ADMIN)
    workspace = {'id': payload.assessment_id, 'revisions': [], 'draft': {'payload': payload.model_dump()}}
    store.store.save_workspace(r['id'], workspace, None, 'production', 0, 'Architect')
    release = store.store.clone_release(r['id'], '26.10', 'Architect')
    copied_id = store.store.release(release['id'])['workspaces'][0]['id']
    copied = store.store.workspace(copied_id)['workspace']
    return ModelReviewRequest.model_validate(copied['draft']['payload'])


def test_clone_proposes_unchanged_answers_without_auto_confirmation(store, payload):
    copied = clone_fixture(store, payload)
    first = store.prepare(copied, EDITOR)['questionnaire']
    assert not first['complete'] and not first['answers']
    assert all(q['proposal'] and q['proposal']['basis'] == 'carry_forward' for q in first['questions'])
    copied.questionnaire_answers = [confirmation(q) for q in first['questions']]
    second = store.prepare(copied, EDITOR, require_ready=True)['questionnaire']
    assert second['complete']
    assert all(a['reviewer'] == 'Engineer' and a['inherited_from']['reviewer'] == 'Architect' for a in second['answers'])
    assert store.prepare(copied, {'name': 'worker', 'role': 'editor'}, record=False)['questionnaire']['complete']


@pytest.mark.parametrize('change', ['flow', 'environment', 'control', 'boundary', 'lineage'])
def test_clone_reopens_changed_scope_and_cannot_use_unrelated_history(store, payload, change):
    copied = clone_fixture(store, payload)
    if change == 'flow':
        copied.baseline.flows[0].protocol = 'HTTP'
    elif change == 'environment':
        copied.environment = 'test'
    elif change == 'control':
        copied.baseline.components[0].properties['authenticated'] = False
    elif change == 'boundary':
        copied.baseline.trust_boundaries = [TrustBoundary(id='new', name='New zone', boundary_type='explicit', components=['orders'])]
    else:
        copied.assessment_id = 'unrelated-assessment'
    auth = next(q for q in store.prepare(copied, EDITOR)['questionnaire']['questions'] if q['id'] == 'authentication:orders')
    assert auth['proposal'] is None and auth['status'] == 'unanswered'


def test_clone_ignores_answers_changed_after_cloning(store, payload):
    copied = clone_fixture(store, payload)
    payload.questionnaire_answers = [{**a, 'value': 'present', 'note': 'New statement after the clone.'} for a in payload.questionnaire_answers]
    store.prepare(payload, ADMIN)
    qs = store.prepare(copied, EDITOR)['questionnaire']['questions']
    assert all(q['proposal']['value'] == 'unknown' for q in qs)


def test_legacy_answers_without_reuse_digest_are_not_inherited(payload):
    q = rows(payload)[0]
    old = {**manual(q), 'reviewer': 'Previous owner', 'answered_at': '2026-09-20', 'assessment_id': 'old'}
    assert rows(payload, previous={q['id']: old})[0]['proposal'] is None


def test_changed_supporting_source_reopens_manual_carry_forward(payload):
    payload.sources = [ReviewSource(id='doc', name='Architecture.md', text='Network design v1')]
    q = rows(payload)[0]
    old = {**manual(q), 'reuse_digest': q['reuse_digest'], 'source_ids': ['doc'], 'source_fingerprints': {'doc': 'old'},
        'reviewer': 'Previous owner', 'answered_at': '2026-09-20', 'assessment_id': 'old'}
    assert rows(payload, previous={q['id']: deepcopy(old)})[0]['proposal'] is None
