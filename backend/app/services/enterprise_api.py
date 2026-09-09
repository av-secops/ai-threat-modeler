"""Role-protected local enterprise registry. Tokens are supplied by the operator."""

import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .product_store import ProductStore, StoreConflict
from .durable_jobs import JobRunner
from .release_comparison import compare_reports
from .model_review import ModelReviewRequest, prepare_model
from ..models import SystemArchitecture

router = APIRouter(prefix='/enterprise')


def principal(request: Request):
    try:
        configured = json.loads(os.getenv('AEGIS_WORKSPACE_TOKENS', '{}'))
        if not isinstance(configured, dict) or any(not isinstance(v, dict) for v in configured.values()):
            raise ValueError('Invalid identity map')
    except (ValueError, TypeError):
        raise HTTPException(503, 'Workspace identity configuration is invalid.') from None
    token = request.headers.get('authorization', '').removeprefix('Bearer ')
    for secret, identity in configured.items():
        if secret and hmac.compare_digest(secret, token):
            if identity.get('role') not in {'viewer', 'editor', 'admin'} or not identity.get('name'):
                raise HTTPException(503, 'Workspace identity configuration is invalid.')
            return identity
    if configured or os.getenv('ENVIRONMENT', '').lower() == 'production':
        raise HTTPException(401, 'A workspace access token is required.')
    origin = request.headers.get('origin')
    if request.client.host not in {'127.0.0.1', '::1', 'testclient'} or (origin and urlparse(origin).hostname not in {'localhost', '127.0.0.1', '::1'}):
        raise HTTPException(403, 'Unconfigured workspace access is restricted to local clients.')
    return {'name': 'local-user', 'role': 'admin'}


def editor(identity=Depends(principal)):
    if identity['role'] not in {'editor', 'admin'}:
        raise HTTPException(403, 'Editor access is required.')
    return identity


def administrator(identity=Depends(principal)):
    if identity['role'] != 'admin':
        raise HTTPException(403, 'Administrator access is required.')
    return identity


def store(request: Request):
    return request.app.state.product_store


def invoke(work):
    try:
        return work()
    except StoreConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def start_enterprise(app):
    path = os.getenv('AEGIS_WORKSPACE_DB') or str(Path(__file__).resolve().parents[2] / 'data' / 'workspaces.sqlite3')
    app.state.product_store = ProductStore(path)

    def analyze(value):
        payload = ModelReviewRequest.model_validate(value)
        prepared = prepare_model(payload)
        architecture = SystemArchitecture.model_validate(prepared['architecture'])
        if not architecture.components:
            raise ValueError('No components were modeled.')
        result = app.state.threat_analyzer.analyze(architecture, payload.project_name,
            use_local_slm=payload.use_local_slm, analysis_mode=payload.analysis_mode, domain_profile=payload.domain_profile)
        result.engine_status['input_review'] = prepared['readiness']
        return result.model_dump(mode='json')

    app.state.job_runner = JobRunner(app.state.product_store, analyze)


class Name(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class ProductUpdate(Name):
    archived: bool = False


class WorkspaceSave(BaseModel):
    workspace: dict
    application_id: str | None = None
    environment: str = Field(default='production', min_length=1, max_length=100)
    expected_version: int = Field(default=0, ge=0)


class Compare(BaseModel):
    before_workspace: str
    after_workspace: str
    before_revision: int = Field(ge=1)
    after_revision: int = Field(ge=1)


@router.get('/identity')
def identity(value=Depends(principal)):
    return value


@router.get('/products')
def products(db=Depends(store), user=Depends(principal)):
    return db.list_products()


@router.post('/products')
def create_product(payload: Name, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.create('products', payload.name, user['name']))


@router.get('/products/{identifier}')
def product(identifier: str, db=Depends(store), user=Depends(principal)):
    return invoke(lambda: db.product(identifier))


@router.patch('/products/{identifier}')
def update_product(identifier: str, payload: ProductUpdate, db=Depends(store), user=Depends(administrator)):
    return invoke(lambda: db.update_product(identifier, payload.name, payload.archived, user['name']))


@router.post('/products/{identifier}/releases')
def create_release(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.create('releases', payload.name, user['name'], identifier))


@router.post('/products/{identifier}/applications')
def create_application(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.create('applications', payload.name, user['name'], identifier))


@router.get('/releases/{identifier}')
def release(identifier: str, db=Depends(store), user=Depends(principal)):
    return invoke(lambda: db.release(identifier))


@router.post('/releases/{identifier}/applications')
def release_application(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.release_application(identifier, payload.name, user['name']))


@router.post('/releases/{identifier}/clone')
def clone(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.clone_release(identifier, payload.name, user['name']))


@router.get('/workspaces/{identifier}')
def workspace(identifier: str, db=Depends(store), user=Depends(principal)):
    return invoke(lambda: db.workspace(identifier))


@router.put('/releases/{identifier}/workspaces')
def save_workspace(identifier: str, payload: WorkspaceSave, db=Depends(store), user=Depends(editor)):
    return invoke(lambda: db.save_workspace(identifier, payload.workspace, payload.application_id,
        payload.environment, payload.expected_version, user['name']))


@router.post('/compare')
def compare(payload: Compare, db=Depends(store), user=Depends(principal)):
    def execute():
        before, after = db.workspace(payload.before_workspace), db.workspace(payload.after_workspace)
        left, right = db.release(before['release_id']), db.release(after['release_id'])
        if left['product_id'] != right['product_id'] or before['application_id'] != after['application_id'] or before['environment'] != after['environment']:
            raise ValueError('Compare the same product, application scope and environment.')
        def revision(row, number):
            matches = [r for r in row['workspace'].get('revisions', []) if r.get('number') == number]
            if not matches:
                raise LookupError('Report revision not found')
            return matches[0]['data']
        return compare_reports(revision(before, payload.before_revision), revision(after, payload.after_revision))
    return invoke(execute)


@router.get('/audit')
def audit(db=Depends(store), user=Depends(administrator)):
    return db.audit_log()


@router.post('/jobs')
def create_job(request: Request, payload: ModelReviewRequest, user=Depends(editor)):
    return invoke(lambda: request.app.state.job_runner.submit(payload.model_dump(mode='json'), user['name']))


@router.get('/jobs/{identifier}')
def job(identifier: str, request: Request, user=Depends(principal)):
    return invoke(lambda: request.app.state.job_runner.get(identifier, user['name']))


@router.post('/jobs/{identifier}/retry')
def retry_job(identifier: str, request: Request, user=Depends(editor)):
    return invoke(lambda: request.app.state.job_runner.retry(identifier, user['name']))
