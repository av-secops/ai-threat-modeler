"""Installation-admin KB release operations. Publication never swaps a live engine."""

import os
import json
import sqlite3
from pathlib import Path
from typing import Literal, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Path as PathParameter
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enterprise_api import principal
from .workspace_access import require_platform_admin
from ..knowledge_base.loader import ThreatKnowledgeBase
from ..knowledge_base.releases import KnowledgeReleaseStore, ReleaseConflict, ReleaseGateError

router = APIRouter(prefix='/enterprise/knowledge', tags=['Knowledge governance'])


def administrator(identity=Depends(principal)):
    return require_platform_admin(identity)


def release_store(user=Depends(administrator)):
    # Authorize before opening/creating an installation-wide database.
    path = os.getenv('AEGIS_KB_RELEASE_DB', '').strip() or str(Path(__file__).resolve().parents[2] / 'data' / 'knowledge-releases.sqlite3')
    return invoke(lambda: KnowledgeReleaseStore(path))


def invoke(work):
    try:
        return work()
    except ReleaseConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ReleaseGateError as exc:
        raise HTTPException(422, {'message': 'Knowledge release gates failed.', 'blockers': exc.blockers}) from exc
    except KeyError as exc:
        raise HTTPException(404, 'Knowledge release not found.') from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (sqlite3.DatabaseError, OSError) as exc:
        raise HTTPException(503, 'Knowledge governance storage is unavailable.') from exc


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Waiver(Input):
    rule_id: str = Field(min_length=1, max_length=300)
    code: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=3, max_length=6000)
    tracking_reference: str = Field(min_length=1, max_length=1000)
    expires_at: str = Field(min_length=1, max_length=50)


class Approval(Input):
    reason: str = Field(min_length=3, max_length=6000)
    expected_assessment_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    valid_until: str = Field(max_length=50)
    baseline_digest: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    waivers: list[Waiver] = Field(default_factory=list, max_length=2000)


class Activation(Input):
    reason: str = Field(min_length=3, max_length=6000)
    approval_id: int = Field(ge=1, le=9223372036854775807)
    expected_revision: int = Field(ge=0, le=9223372036854775807)


class Revoke(Input):
    reason: str = Field(min_length=3, max_length=6000)


class Reassessment(Input):
    baseline_digest: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    report_ids: list[Annotated[str, Field(min_length=1, max_length=100)]] = Field(default_factory=list, max_length=100)
    after_report_id: str = Field(default='', max_length=100)
    limit: int = Field(default=50, ge=1, le=100)

    @model_validator(mode='after')
    def selection_is_unambiguous(self):
        if len(set(self.report_ids)) != len(self.report_ids):
            raise ValueError('Report IDs must be unique.')
        if self.report_ids and self.after_report_id:
            raise ValueError('Select report IDs or use pagination, not both.')
        if len(self.report_ids) > self.limit:
            raise ValueError('The report selection exceeds the requested page limit.')
        return self


def _stored_reports(request, payload):
    """Read only immutable server report provenance, never browser workspace JSON."""
    assessment_store = getattr(request.app.state, 'assessment_store', None)
    if assessment_store is None:
        raise HTTPException(503, 'Assessment storage is unavailable.')
    # Project only the needed JSON fields; large finding/evidence bodies are not
    # returned to Python or the caller. Unknown provenance requires reassessment.
    projection = '''SELECT id, assessment_id, created,
        CASE WHEN json_valid(body) THEN json_extract(body,
            '$.engine_status.knowledge_base.release.content_digest') END AS kb_digest,
        CASE WHEN json_valid(body) THEN substr(json_extract(body,
            '$.engine_status.knowledge_base.evaluated_rule_ids'), 1, 200000) END AS evaluated
        FROM assessment_results'''
    with assessment_store.store.read_snapshot() as connection:
        if payload.report_ids:
            marks = ','.join('?' for _ in payload.report_ids)
            rows = connection.execute(projection + f' WHERE id IN ({marks}) ORDER BY id', payload.report_ids).fetchall()
            if len(rows) != len(payload.report_ids):
                raise HTTPException(404, 'One or more saved assessment reports were not found.')
            has_more = False
        else:
            rows = connection.execute(projection + ' WHERE id > ? ORDER BY id LIMIT ?',
                (payload.after_report_id, payload.limit + 1)).fetchall()
            has_more = len(rows) > payload.limit
            rows = rows[:payload.limit]
    reports, metadata = [], {}
    for row in rows:
        try:
            evaluated = json.loads(row['evaluated']) if isinstance(row['evaluated'], str) else None
        except (ValueError, TypeError):
            evaluated = None
        if not isinstance(evaluated, list) or len(evaluated) > 10000 or any(not isinstance(value, str) for value in evaluated):
            evaluated = None
        reports.append({'id': row['id'], 'knowledge_provenance': {
            'content_digest': row['kb_digest'], 'evaluated_rule_ids': evaluated}})
        metadata[row['id']] = {'assessment_id': row['assessment_id'], 'created_at': row['created']}
    return reports, metadata, rows[-1]['id'] if has_more and rows else None


@router.get('/status')
def status(request: Request, history_limit: int = Query(default=20, ge=1, le=100),
           db=Depends(release_store), user=Depends(administrator)):
    def execute():
        pointer = db.active()
        runtime = getattr(getattr(request.app.state, 'threat_analyzer', None), 'knowledge_base', None)
        effective = getattr(runtime, 'release_provenance', {})
        if not isinstance(effective, dict):
            effective = {}
        return {'configured': bool(os.getenv('AEGIS_KB_RELEASE_DB', '').strip()),
            'requested': {k: pointer[k] for k in ('digest', 'revision')}, 'effective': effective,
            'restart_required': bool(pointer['digest'] and (pointer['digest'] != effective.get('content_digest') or
                pointer['revision'] != effective.get('activation_revision'))),
            'history': db.history(limit=history_limit), 'independent_accuracy_established': False}
    return invoke(execute)


@router.post('/stage')
def stage(db=Depends(release_store), user=Depends(administrator)):
    def execute():
        artifact = db.stage(ThreatKnowledgeBase(), actor=user['name'])
        return {'content_digest': artifact['digest'], 'created_by': artifact['created_by'],
            'created_at': artifact['created_at'], 'assessment': db.assess(artifact['digest'], baseline_digest=db.active()['digest'])}
    return invoke(execute)


@router.get('/releases/{digest}/assessment')
def assess(digest: str, db=Depends(release_store), user=Depends(administrator)):
    return invoke(lambda: db.assess(digest, baseline_digest=db.active()['digest']))


@router.post('/releases/{digest}/approve')
def approve(digest: str, payload: Approval, db=Depends(release_store), user=Depends(administrator)):
    def execute():
        baseline = db.active()['digest']
        if 'baseline_digest' in payload.model_fields_set and payload.baseline_digest != baseline:
            raise ReleaseConflict('The active baseline changed; refresh the release assessment.')
        return db.approve(digest, reviewer=user['name'],
            **{**payload.model_dump(), 'baseline_digest': baseline})
    return invoke(execute)


@router.post('/approvals/{identifier}/revoke')
def revoke(identifier: Annotated[int, PathParameter(ge=1, le=9223372036854775807)], payload: Revoke,
           db=Depends(release_store), user=Depends(administrator)):
    def execute():
        db.revoke_approval(identifier, actor=user['name'], reason=payload.reason)
        return {'revoked': True, 'approval_id': identifier}
    return invoke(execute)


@router.post('/releases/{digest}/reassessment')
def reassessment(digest: str, payload: Reassessment, request: Request,
                 db=Depends(release_store), user=Depends(administrator)):
    def execute():
        baseline = payload.baseline_digest if 'baseline_digest' in payload.model_fields_set else db.active()['digest']
        # Validate both release identities even when there are no stored reports.
        db.artifact(digest)
        if baseline:
            db.artifact(baseline)
        reports, metadata, cursor = _stored_reports(request, payload)
        plan = db.reassessment_plan(baseline, digest, reports)
        for decision in plan['reports']:
            decision.update(metadata[decision['report_id']])
            affected = decision['affected_rule_ids']
            decision['affected_rule_count'] = len(affected)
            decision['affected_rule_ids'] = affected[:100]
            decision['affected_rule_ids_truncated'] = len(affected) > 100
        change_counts = {kind: len(values) for kind, values in plan['changes'].items()}
        plan['changes'] = {kind: values[:100] for kind, values in plan['changes'].items()}
        return {**plan, 'source': 'authoritative_assessment_results', 'page_count': len(reports),
            'change_counts': change_counts, 'changes_truncated': any(count > 100 for count in change_counts.values()),
            'next_after_report_id': cursor, 'has_more': cursor is not None,
            'notice': 'This is a reassessment plan, not a rerun or a declaration that any risk is fixed.'}
    return invoke(execute)


@router.post('/releases/{digest}/{action}')
def activate(digest: str, action: Literal['publish', 'rollback'], payload: Activation,
             db=Depends(release_store), user=Depends(administrator)):
    def execute():
        result = getattr(db, action)(digest, actor=user['name'], **payload.model_dump())
        return {**result, 'restart_required': True,
            'runtime_notice': 'Set AEGIS_KB_RELEASE_DB to this release database and restart workers to load the approved catalog.'}
    return invoke(execute)
