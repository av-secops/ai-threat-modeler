import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import Component, DataFlow, SystemArchitecture
from app.services.assessment_store import AssessmentStore
from app.services.enterprise_api import router
from app.services.model_review import ModelReviewRequest
from app.services.product_store import ProductStore
from app.services.workspace_access import ENV_KEYS


@pytest.mark.parametrize(
    'product_role,answer_value,expected_status',
    [
        ('editor', 'not_applicable', 400),
        ('editor', 'unknown', 200),
        ('admin', 'not_applicable', 200),
    ],
)
def test_job_preparation_uses_product_role(
    tmp_path, monkeypatch, product_role, answer_value, expected_status
):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    products = ProductStore(tmp_path / 'jobs.sqlite3')
    product = products.create('products', 'Orders', 'fixture')
    release = products.create('releases', '1', 'fixture', product['id'])
    products.save_workspace(
        release['id'], {'id': 'assessment', 'revisions': []},
        None, 'production', 0, 'fixture',
    )
    assessments = AssessmentStore(products)
    payload = ModelReviewRequest(
        project_name='Orders', assessment_id='assessment', application_types=['web'],
        baseline=SystemArchitecture(
            components=[
                Component(id='ui', name='React', type='WebClient'),
                Component(id='api', name='Orders API', type='API'),
                Component(id='db', name='PostgreSQL', type='Database'),
            ],
            flows=[
                DataFlow(source_id='ui', target_id='api', protocol='HTTPS'),
                DataFlow(source_id='api', target_id='db', protocol='TLS'),
            ],
        ),
    )
    preview = assessments.prepare(payload, {'name': 'fixture', 'role': 'admin'})
    answers = [
        {
            'question_id': question['id'], 'value': answer_value,
            'note': 'Architecture owner has reviewed the control applicability.',
            'evidence_digest': question['evidence_digest'], 'source_ids': [],
        }
        for question in preview['questionnaire']['questions']
    ]
    assert answers
    body = payload.model_dump(mode='json')
    body['questionnaire_answers'] = answers
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'global-admin-token': {
            'name': 'architect', 'role': 'admin',
            'products': {product['id']: product_role},
        },
    }))
    submit = Mock(return_value={'id': 'queued-job'})
    app = FastAPI()
    app.state.product_store = products
    app.state.assessment_store = assessments
    app.state.job_runner = SimpleNamespace(submit=submit)
    app.include_router(router)

    with TestClient(app) as client:
        response = client.post(
            '/enterprise/jobs', json=body,
            headers={'Authorization': 'Bearer global-admin-token'},
        )

    assert response.status_code == expected_status, response.text
    with products.read_snapshot() as db:
        evidence = [
            json.loads(row['body']) for row in db.execute(
                'SELECT body FROM assessment_answer_events WHERE assessment_id=?',
                ('assessment',),
            ).fetchall()
        ]
    if expected_status == 400:
        assert 'administrator' in response.json()['detail']
        submit.assert_not_called()
        assert evidence == []
    else:
        submit.assert_called_once_with(body, 'architect')
        assert evidence
        assert {answer['reviewer_role'] for answer in evidence} == {product_role}
        assert {answer['reviewer'] for answer in evidence} == {'architect'}
