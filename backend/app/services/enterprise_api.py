"""Role-protected local enterprise registry. Tokens are supplied by the operator."""

import json
import os
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Response
from pydantic import BaseModel, Field

from .product_store import ProductStore, StoreConflict
from .durable_jobs import JobRunner
from .comparison_engine import compare_reports, digest
from .model_review import ModelReviewRequest, prepare_model
from ..models import SystemArchitecture
from .product_dashboard import DashboardFilters, dashboard, portfolio, history, observe, finding_detail
from .workspace_access import (authenticate_request, require_role, require_platform_admin,
    require_product, require_resource, require_comparison_inputs, require_workspace_save,
    require_model_review, filter_products, can_access_product)

router = APIRouter(prefix='/enterprise')


def principal(request: Request):
    return authenticate_request(request)


def editor(identity=Depends(principal)):
    return require_role(identity, 'editor')


def administrator(identity=Depends(principal)):
    return require_role(identity, 'admin')


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
    from .assessment_store import AssessmentStore
    from .workspace_access import WorkspaceAccess, identity_for_product
    import time
    import uuid
    app.state.assessment_store = AssessmentStore(app.state.product_store)

    def authorize(actor, value):
        # The actor was authenticated at submission. Resolve CURRENT operator
        # grants, not a token, claimed role or authorization snapshot in payload.
        configured = WorkspaceAccess.from_env()
        candidates = []
        if configured.oidc:
            candidates.extend(configured._identity(grant, subject, configured.oidc.issuer, 'oidc')
                              for subject, grant in configured._principals.items())
        if configured._allow_tokens:
            candidates.extend(configured._identity(grant, grant.name, 'workspace-token', 'token')
                              for grant in configured._tokens.values())
        if (not configured.oidc and not configured._tokens and not configured._production
                and configured._local is not None):
            candidates.append(configured._identity(configured._local, configured._local.name,
                                                   'local-workspace', 'local'))
        matches = {identity for identity in candidates if identity.name == actor}
        if len(matches) != 1:
            raise PermissionError('Job actor was removed or has ambiguous current grants.')
        identity = matches.pop()
        payload = ModelReviewRequest.model_validate(value)
        product_id = require_model_review(app.state.product_store, identity, payload)
        return identity_for_product(identity, product_id) if product_id else identity

    def analyze(value, *, identity):
        payload = ModelReviewRequest.model_validate(value)
        prepared = app.state.assessment_store.prepare(payload, identity, require_ready=True, record=False)
        architecture = SystemArchitecture.model_validate(prepared['architecture'])
        if not architecture.components:
            raise ValueError('No components were modeled.')
        result = app.state.threat_analyzer.analyze(architecture, payload.project_name,
            use_local_slm=payload.use_local_slm, analysis_mode=payload.analysis_mode, domain_profile=payload.domain_profile)
        if (result.architecture.metadata or {}).get('assessment', {}).get('id') != payload.assessment_id:
            raise ValueError('Analysis result does not belong to the authorized assessment.')
        result.engine_status['input_review'] = prepared['readiness']
        return result

    def publish(result, *, identity, db):
        # Same governed-report contract as AssessmentStore.save_result, using
        # the runner's transaction so report and job publication are atomic.
        state = (result.architecture.metadata or {}).get('assessment', {})
        if not state.get('complete'):
            raise ValueError('A governed report requires a completed questionnaire.')
        report_id = str(uuid.uuid4())
        result.engine_status['assessment'] = {**state, 'report_id': report_id}
        result.engine_status['assessment_mode'] = 'governed'
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)',
                   (report_id, state['id'], result.model_dump_json(), identity.name, time.time()))
        return result.model_dump(mode='json')

    app.state.job_runner = JobRunner(app.state.product_store, analyze, authorize=authorize, publish=publish)


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
    component_mappings: dict[str, str] = Field(default_factory=dict, max_length=2000)


class SaveComparison(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    comparison: Compare


class ComparisonReview(BaseModel):
    expected_version: int = Field(ge=1)
    status: Literal['pending_review', 'acknowledged', 'accepted_risk', 'verified_fixed', 'needs_investigation']
    remarks: str = Field(min_length=3, max_length=10000)
    evidence: str = Field(default='', max_length=20000)


@router.get('/identity')
def identity(value=Depends(principal)):
    return value


@router.get('/products')
def products(db=Depends(store), user=Depends(principal)):
    return filter_products(user, db.list_products())


@router.get('/security-dashboard')
def portfolio_dashboard(archived: bool = False, db=Depends(store), user=Depends(principal)):
    permitted = {row['id'] for row in filter_products(user, db.list_products())}
    return invoke(lambda: portfolio(db, archived, allowed_product_ids=permitted))


@router.get('/products/{identifier}/security-dashboard')
@router.get('/products/{identifier}/security-dashboard/findings')
def product_dashboard(identifier: str, filters: DashboardFilters = Depends(),
                      snapshot: str = Query(default='', max_length=64),
                      page: int = Query(default=1, ge=1), page_size: int = Query(default=25, ge=1, le=100),
                      db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: dashboard(db, identifier, filters, snapshot, page, page_size))


@router.get('/products/{identifier}/security-dashboard/export')
def export_product_dashboard(identifier: str, filters: DashboardFilters = Depends(),
                             snapshot: str = Query(min_length=64, max_length=64),
                             db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    content = invoke(lambda: dashboard(db, identifier, filters, snapshot, export=True))
    return Response('\ufeff' + content, media_type='text/csv', headers={
        'Content-Disposition': 'attachment; filename="product-risk-register.csv"', 'Cache-Control': 'no-store'})


@router.get('/products/{identifier}/security-dashboard/finding')
def dashboard_finding(identifier: str, workspace_id: str = Query(max_length=100),
                      report_id: str = Query(max_length=100), finding_id: str = Query(max_length=500),
                      db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: finding_detail(db, identifier, workspace_id, report_id, finding_id))


@router.get('/products/{identifier}/security-dashboard/history')
def dashboard_history(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: history(db, identifier))


@router.post('/products/{identifier}/security-dashboard/history')
def record_dashboard_history(identifier: str, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'product', identifier, 'editor')
    return invoke(lambda: observe(db, identifier, user['name']))


@router.post('/products')
def create_product(payload: Name, db=Depends(store), user=Depends(editor)):
    if dict(user.products).get('*') not in {'editor', 'admin'}:
        raise HTTPException(403, 'Catalog-wide editor access is required to create products.')
    return invoke(lambda: db.create('products', payload.name, user['name']))


@router.get('/products/{identifier}')
def product(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: db.product(identifier) | {'permissions': {
        'edit': can_access_product(user, identifier, 'editor'), 'admin': can_access_product(user, identifier, 'admin')}})


@router.patch('/products/{identifier}')
def update_product(identifier: str, payload: ProductUpdate, db=Depends(store), user=Depends(administrator)):
    require_resource(db, user, 'product', identifier, 'admin')
    return invoke(lambda: db.update_product(identifier, payload.name, payload.archived, user['name']))


@router.post('/products/{identifier}/releases')
def create_release(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'product', identifier, 'editor')
    return invoke(lambda: db.create('releases', payload.name, user['name'], identifier))


@router.post('/products/{identifier}/applications')
def create_application(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'product', identifier, 'editor')
    return invoke(lambda: db.create('applications', payload.name, user['name'], identifier))


@router.get('/releases/{identifier}')
def release(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'release', identifier)
    return invoke(lambda: db.release(identifier))


@router.post('/releases/{identifier}/applications')
def release_application(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'release', identifier, 'editor')
    return invoke(lambda: db.release_application(identifier, payload.name, user['name']))


@router.post('/releases/{identifier}/clone')
def clone(identifier: str, payload: Name, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'release', identifier, 'editor')
    return invoke(lambda: db.clone_release(identifier, payload.name, user['name']))


@router.get('/workspaces/{identifier}')
def workspace(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'workspace', identifier)
    return invoke(lambda: db.workspace(identifier))


@router.put('/releases/{identifier}/workspaces')
def save_workspace(identifier: str, payload: WorkspaceSave, db=Depends(store), user=Depends(editor)):
    require_workspace_save(db, user, identifier, application_id=payload.application_id, workspace_id=payload.workspace.get('id'))
    return invoke(lambda: db.save_workspace(identifier, payload.workspace, payload.application_id,
        payload.environment, payload.expected_version, user['name']))


@router.post('/compare')
def compare(payload: Compare, db=Depends(store), user=Depends(principal)):
    require_comparison_inputs(db, user, [payload.before_workspace, payload.after_workspace])
    return invoke(lambda: run_comparison(db, payload)[1])


def run_comparison(db, payload):
    before, after = db.comparison_snapshots([
        {'workspace_id': payload.before_workspace, 'revision': payload.before_revision},
        {'workspace_id': payload.after_workspace, 'revision': payload.after_revision},
    ])
    if any(before[key] != after[key] for key in ('product_id', 'application_id', 'environment')):
        raise ValueError('Compare the same product, application scope and environment.')
    if payload.before_workspace == payload.after_workspace and payload.before_revision == payload.after_revision:
        raise ValueError('Select two different report revisions.')
    reports = [row['revision']['data'] for row in (before, after)]
    result = compare_reports(*reports, component_mappings=payload.component_mappings,
        before_annotations=before['annotations'], after_annotations=after['annotations'])
    result['diagrams'] = [r.get('diagram') for r in reports]
    result['snapshots'] = [{key: row[key] for key in ('workspace_id', 'release_id', 'product_id', 'application_id', 'environment')} |
        {'revision': row['revision']['number'], 'report_digest': digest(report), 'report_source': row['report_source']} for row, report in zip((before, after), reports)]
    if any(row['report_source'] == 'legacy_workspace_snapshot' for row in (before, after)):
        result['warnings'].append('A legacy workspace snapshot has no authoritative server assessment record. Its analysis provenance requires review.')
    return before['product_id'], result


@router.get('/products/{identifier}/comparison-catalog')
def comparison_catalog(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: db.comparison_catalog(identifier))


@router.get('/products/{identifier}/comparisons')
def comparisons(identifier: str, offset: int = Query(default=0, ge=0), limit: int = Query(default=30, ge=1, le=100),
                db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'product', identifier)
    return invoke(lambda: db.list_comparisons(identifier, offset, limit))


@router.post('/products/{identifier}/comparisons')
def save_comparison(identifier: str, payload: SaveComparison, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'product', identifier, 'editor')
    require_comparison_inputs(db, user, [payload.comparison.before_workspace, payload.comparison.after_workspace], 'editor')
    def execute():
        product_id, result = run_comparison(db, payload.comparison)
        if product_id != identifier:
            raise ValueError('The comparison belongs to another product.')
        return db.save_comparison(product_id, payload.name, payload.comparison.model_dump(), result, user['name'])
    return invoke(execute)


@router.get('/comparisons/{identifier}')
def saved_comparison(identifier: str, db=Depends(store), user=Depends(principal)):
    require_resource(db, user, 'comparison', identifier)
    return invoke(lambda: db.comparison(identifier))


@router.patch('/comparisons/{identifier}/reviews/{change_id}')
def review_comparison(identifier: str, change_id: str, payload: ComparisonReview, db=Depends(store), user=Depends(editor)):
    require_resource(db, user, 'comparison', identifier, 'admin' if payload.status == 'accepted_risk' else 'editor')
    return invoke(lambda: db.review_comparison(identifier, change_id,
        payload.model_dump(exclude={'expected_version'}), payload.expected_version, user['name']))


@router.get('/audit')
def audit(db=Depends(store), user=Depends(administrator)):
    require_platform_admin(user)
    return db.audit_log()


@router.post('/jobs')
def create_job(request: Request, payload: ModelReviewRequest, user=Depends(editor)):
    from .workspace_access import identity_for_product
    product_id = require_model_review(request.app.state.product_store, user, payload)
    reviewer = identity_for_product(user, product_id) if product_id else user
    def execute():
        request.app.state.assessment_store.prepare(payload, reviewer, require_ready=True)
        return request.app.state.job_runner.submit(payload.model_dump(mode='json'), user['name'])
    return invoke(execute)


@router.get('/jobs/{identifier}')
def job(identifier: str, request: Request, user=Depends(principal)):
    authorize_job(request.app.state.product_store, user, identifier)
    return invoke(lambda: request.app.state.job_runner.get(identifier, user['name']))


@router.post('/jobs/{identifier}/retry')
def retry_job(identifier: str, request: Request, user=Depends(editor)):
    authorize_job(request.app.state.product_store, user, identifier, write=True)
    return invoke(lambda: request.app.state.job_runner.retry(identifier, user['name']))


def authorize_job(db, user, identifier, *, write=False):
    with db.read_snapshot() as connection:
        row = connection.execute('SELECT actor,payload FROM jobs WHERE id=?', (identifier,)).fetchone()
    if row is None or row['actor'] != user['name']:
        raise HTTPException(404, 'Job not found.')
    from .workspace_access import require_assessment
    payload = json.loads(row['payload'])
    if payload.get('assessment_id'):
        require_assessment(db, user, payload['assessment_id'], 'editor' if write else 'viewer')
    elif user.scopes_configured:
        raise HTTPException(404, 'Job not found.')
