"""Ephemeral UI-test server; never connects to a user's workspace database."""
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI

from app.services.assessment_api import router as assessment_router
from app.services.assessment_store import AssessmentStore
from app.services.enterprise_api import router
from app.services.product_store import ProductStore
from test_product_dashboard import model, finding, review


@asynccontextmanager
async def lifespan(app):
    os.environ['AEGIS_WORKSPACE_TOKENS'] = json.dumps({'dashboard-test-editor': {'name': 'QA', 'role': 'editor'},
        'dashboard-test-viewer': {'name': 'QA viewer', 'role': 'viewer'}})
    with TemporaryDirectory(prefix='aegis-dashboard-') as directory:
        store = ProductStore(Path(directory) / 'qa.sqlite3')
        app.state.product_store = store
        app.state.assessment_store = AssessmentStore(store)
        p = store.create('products', 'Atlas Product', 'QA')
        r = store.create('releases', '26.09', 'QA', p['id'])
        a = store.release_application(r['id'], 'Customer Portal', 'QA')
        for app_name in ['Billing', 'Identity', 'Notifications']:
            store.release_application(r['id'], app_name, 'QA')
        threats = [finding(str(i), ['Critical', 'High', 'Medium', 'Low'][i % 4],
            title=['Cross-tenant order access', 'Unrestricted service identity', 'Missing audit event verification', 'Session lifetime requires review'][i % 4] + f' ({i})',
            description='Synthetic dashboard acceptance-test finding.', mitigation='Verify scoped access controls and record the test evidence.',
            tier='Confirmed' if i % 3 else 'Potential', affected_components=['Order API'], explanation={},
            finding_type='validation_question' if i == 34 else 'architecture') for i in range(35)]
        _, report = model((store, p, r, a), threats)
        for id, state in [('1', 'accepted'), ('2', 'verified_fixed'), ('3', 'false_positive')]:
            review(store, report, id, state, verification_evidence='Synthetic test proof', remarks='Synthetic review', author_role='admin')
        store.clone_release(r['id'], '26.10', 'QA')
        store.create('products', 'Unassessed Product', 'QA')
        yield


app = FastAPI(lifespan=lifespan)
app.include_router(router)
app.include_router(assessment_router)
