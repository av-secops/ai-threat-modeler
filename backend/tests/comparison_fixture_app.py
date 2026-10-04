"""Disposable browser-test workspace, isolated from saved user assessments."""

from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.enterprise_api import router
from app.services.product_store import ProductStore


@asynccontextmanager
async def lifespan(app):
    with TemporaryDirectory(prefix='aegis-comparison-') as directory:
        store = ProductStore(Path(directory) / 'qa.sqlite3')
        app.state.product_store = store
        product = store.create('products', 'Comparison QA', 'QA')
        base = {'architecture': {'components': [
            {'id': 'api', 'name': 'Order API', 'type': 'api', 'trust_level': 'public', 'properties': {'tenant_isolation': False}},
            {'id': 'db', 'name': 'Orders', 'type': 'database', 'trust_level': 'internal', 'properties': {}}],
            'flows': [{'id': 'f1', 'source_id': 'api', 'target_id': 'db', 'protocol': 'https', 'data_type': 'orders'}],
            'trust_boundaries': []},
            'threats': [{'id': 'risk-1', 'title': 'Cross-tenant order access', 'description': 'Synthetic fixture: tenant scoping is absent.',
                'severity': 'High', 'tier': 'Confirmed', 'category': 'Information Disclosure', 'affected_components': ['api'],
                'specific_control': 'tenant_isolation', 'evidence': ['fixture.txt:5'], 'mitigation': 'Bind each order query to the authenticated tenant.'}],
            'engine_status': {'engine_version': '2.3.2', 'knowledge_base': {'content_digest': 'fixture-kb'}},
            'score': 60, 'diagram': 'flowchart LR\napi[Order API] -->|HTTPS| db[(Orders)]'}
        for index in (1, 2):
            release = store.create('releases', f'26.0{index}', 'QA', product['id'])
            data = deepcopy(base)
            if index == 2:
                data['threats'][0]['severity'] = 'Critical'
                data['threats'][0]['evidence'].append('review.txt:8')
                data['architecture']['flows'][0]['protocol'] = 'http'
                data['diagram'] = 'flowchart LR\napi[Order API] -->|HTTP| db[(Orders)]'
                data['score'] = 40
            model = {'id': f'qa-model-{index}', 'projectName': 'Order platform', 'revisions': [
                {'number': 1, 'createdAt': f'2026-0{index}-01T12:00:00Z', 'data': data}]}
            store.save_workspace(release['id'], model, None, 'production', 0, 'QA')
        yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:5194', 'http://localhost:5194'],
                   allow_methods=['*'], allow_headers=['*'])
app.include_router(router)
