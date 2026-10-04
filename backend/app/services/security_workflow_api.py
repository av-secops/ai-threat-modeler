"""Product-scoped workflow routes; install after enterprise ProductStore startup.

The parent application supplies a product/workspace access policy at startup.
Missing policy fails closed except for unconfigured, loopback-only local mode.
"""

import os
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field

from .security_workflows import (SecurityWorkflows, JiraConnections, Input, PatternInput, PatternTransition,
                                 InheritanceInput, RiskReview, RiskComment, TicketLink, TicketSync)


router = APIRouter(prefix='/enterprise/products/{product_id}/security-workflows', tags=['Security workflows'])
SCOPE = '/workspaces/{workspace_id}/revisions/{revision}'
RISK = SCOPE + '/risks/{finding_id}'


def start_security_workflows(app, *, access: Callable | None = None):
    """access(*, store, identity, product_id, workspace_id, write) must return True.

    Raising HTTPException is also supported. Wrap the central access policy in
    this signature. No network requests or ticket processing occur at startup.
    """
    app.state.security_workflows = SecurityWorkflows(app.state.product_store)
    app.state.security_workflow_access = access


def principal(request: Request):
    from .enterprise_api import principal as resolve
    return resolve(request)


def service(request: Request):
    result = getattr(request.app.state, 'security_workflows', None)
    if result is None:
        raise HTTPException(503, 'Security workflows have not been initialized.')
    return result


def access(request, db, user, product_id, workspace_id=None, *, write=False, admin=False):
    if admin and user['role'] != 'admin':
        raise HTTPException(403, 'Administrator approval is required.')
    if write and user['role'] not in {'editor', 'admin'}:
        raise HTTPException(403, 'Editor access is required.')
    from .workspace_access import VerifiedIdentity, require_product, require_resource
    if isinstance(user, VerifiedIdentity):
        minimum = 'admin' if admin else 'editor' if write else 'viewer'
        require_product(user, product_id, minimum)
        if workspace_id and require_resource(db.store, user, 'workspace', workspace_id, minimum) != product_id:
            raise HTTPException(404, 'Workspace not found in this product.')
        return
    policy = getattr(request.app.state, 'security_workflow_access', None)
    if policy:
        if policy(store=db.store, identity=user, product_id=product_id, workspace_id=workspace_id, write=write) is not True:
            raise HTTPException(403, 'Access to this product or workspace is denied.')
    elif (user.get('name') != 'local-user' or user.get('role') != 'admin'
          or os.getenv('ENVIRONMENT', '').lower() == 'production'
          or os.getenv('AEGIS_WORKSPACE_TOKENS', '{}').strip() not in {'', '{}'}):
        raise HTTPException(503, 'Configure the security workflow product access policy before using authenticated workspaces.')


def invoke(work):
    from .enterprise_api import invoke as existing_invoke
    try:
        return existing_invoke(work)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


def connections():
    try:
        return JiraConnections.from_environment()
    except ValueError:
        raise HTTPException(503, 'Jira connection configuration is invalid.') from None


class Dispatch(Input):
    limit: int = Field(default=5, ge=1, le=10)


@router.get('/patterns')
def patterns(product_id: str, request: Request, offset: int = Query(default=0, ge=0, le=1_000_000),
             limit: int = Query(default=50, ge=1, le=100), db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id)
    return invoke(lambda: db.patterns(product_id, offset=offset, limit=limit))


@router.post('/patterns')
def create_pattern(product_id: str, payload: PatternInput, request: Request, db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, write=True)
    return invoke(lambda: db.create_pattern_version(product_id, payload, user))


@router.post('/patterns/{pattern_id}/versions')
def create_version(product_id: str, pattern_id: str, payload: PatternInput, request: Request,
                   db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, write=True)
    return invoke(lambda: db.create_pattern_version(product_id, payload, user, pattern_id))


@router.post('/patterns/{pattern_id}/versions/{version}/transition')
def transition_pattern(product_id: str, pattern_id: str, version: int, payload: PatternTransition, request: Request,
                       db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, write=True, admin=True)
    return invoke(lambda: db.transition_pattern(product_id, pattern_id, version, payload, user))


@router.get(SCOPE + '/pattern-evidence')
def inherited_patterns(product_id: str, workspace_id: str, revision: int, request: Request,
                       offset: int = Query(default=0, ge=0, le=1_000_000), limit: int = Query(default=50, ge=1, le=100),
                       db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id)
    return invoke(lambda: db.inherited_evidence(product_id, workspace_id, revision, offset=offset, limit=limit))


@router.post(SCOPE + '/pattern-evidence')
def inherit_pattern(product_id: str, workspace_id: str, revision: int, payload: InheritanceInput, request: Request,
                    db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id, write=True)
    return invoke(lambda: db.inherit_pattern(product_id, workspace_id, revision, payload, user))


@router.get(SCOPE + '/risks')
def risks(product_id: str, workspace_id: str, revision: int, request: Request,
          offset: int = Query(default=0, ge=0, le=1_000_000), limit: int = Query(default=50, ge=1, le=100),
          db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id)
    return invoke(lambda: db.risk_register(product_id, workspace_id, revision, offset=offset, limit=limit))


@router.put(RISK)
def review_risk(product_id: str, workspace_id: str, revision: int, finding_id: str, payload: RiskReview, request: Request,
                db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id, write=True,
           admin=payload.status in {'accepted', 'verified_fixed', 'false_positive'})
    return invoke(lambda: db.review_risk(product_id, workspace_id, revision, finding_id, payload, user))


@router.post(RISK + '/comments')
def comment_risk(product_id: str, workspace_id: str, revision: int, finding_id: str, payload: RiskComment, request: Request,
                 db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id, write=True)
    return invoke(lambda: db.comment_risk(product_id, workspace_id, revision, finding_id, payload, user))


@router.get(RISK + '/events')
def risk_events(product_id: str, workspace_id: str, revision: int, finding_id: str, request: Request,
                offset: int = Query(default=0, ge=0, le=1_000_000), limit: int = Query(default=50, ge=1, le=100),
                db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id)

    def read():
        with db.store.read_snapshot() as connection:
            identifier, _, _, _ = db._risk_ref(connection, product_id, workspace_id, revision, finding_id)
        return db.events(product_id, identifier, offset=offset, limit=limit)
    return invoke(read)


@router.get(RISK + '/tickets')
def ticket_links(product_id: str, workspace_id: str, revision: int, finding_id: str, request: Request,
                 db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id)
    return invoke(lambda: db.ticket_links(product_id, workspace_id, revision, finding_id))


@router.post(RISK + '/tickets')
def link_ticket(product_id: str, workspace_id: str, revision: int, finding_id: str, payload: TicketLink, request: Request,
                db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, workspace_id, write=True)
    return invoke(lambda: db.link_ticket(product_id, workspace_id, revision, finding_id, payload, user, connections()))


@router.get('/outbox')
def outbox(product_id: str, request: Request, offset: int = Query(default=0, ge=0, le=1_000_000),
           limit: int = Query(default=50, ge=1, le=100), db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, admin=True)
    return invoke(lambda: db.outbox(product_id, offset=offset, limit=limit))


@router.post('/tickets/{link_id}/sync')
def enqueue_ticket(product_id: str, link_id: str, payload: TicketSync, request: Request,
                   db=Depends(service), user=Depends(principal)):
    # Resolve the workspace from the server-owned link, not from client input.
    def enqueue():
        with db.store.read_snapshot() as connection:
            link = db._link(connection, product_id, link_id)
            risk = db._require_risk(connection, product_id, link['risk_id'])
        access(request, db, user, product_id, risk['workspace_id'], write=True)
        return db.enqueue_ticket(product_id, link_id, payload, user, connections())
    access(request, db, user, product_id, write=True)
    return invoke(enqueue)


@router.post('/outbox/dispatch')
def dispatch(product_id: str, payload: Dispatch, request: Request, db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, write=True, admin=True)
    if os.getenv('AEGIS_JIRA_SYNC_ENABLED', '').lower() != 'true':
        raise HTTPException(409, 'Jira synchronization is disabled. An operator must enable it server-side.')
    return invoke(lambda: db.dispatch(product_id, user, connections(), limit=payload.limit))


@router.post('/risks/expire-acceptances')
def expire_acceptances(product_id: str, request: Request, db=Depends(service), user=Depends(principal)):
    access(request, db, user, product_id, write=True, admin=True)
    return invoke(lambda: db.expire_acceptances(product_id, user))
