"""Authenticated questionnaire administration and assessment review APIs."""

import csv
import io
import json
import os
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .enterprise_api import principal, editor, administrator, invoke
from .questionnaires import APPLICATION_TYPES, TemplateInput
from .assessment_store import REPORT_TYPES, REVIEW_STATES
from .security_report_import import parse_report
from .source_import import import_url, allowed_hosts
from .workspace_access import require_assessment, require_assessment_report, require_platform_admin
from .security_workflows import Verification, Text

router = APIRouter(prefix='/enterprise')


def assessment_store(request: Request):
    return request.app.state.assessment_store


class Transition(BaseModel):
    expected_revision: int = Field(ge=1)


class URLImport(BaseModel):
    url: str = Field(min_length=8, max_length=2000)


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_version: int = Field(default=0, ge=0)
    status: str = Field(default='pending_review', max_length=40)
    remarks: str = Field(min_length=3, max_length=6000)
    owner: str = Field(default='', max_length=200)
    target_date: str = Field(default='', max_length=20)
    acceptance_expires_at: str = Field(default='', max_length=50)
    verification_evidence: str = Field(default='', max_length=6000)
    acceptance_criteria: list[Text] = Field(default_factory=list, max_length=20)
    verification: list[Verification] = Field(default_factory=list, max_length=20)


class ReportLink(BaseModel):
    model_config = ConfigDict(extra='forbid')
    finding_id: str = Field(max_length=200)
    component_ids: list[str] = Field(default_factory=list, max_length=100)
    flow_ids: list[str] = Field(default_factory=list, max_length=100)
    reason: str = Field(min_length=3, max_length=1000)


class ReportReviewInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1)
    status: str = Field(max_length=30)
    remarks: str = Field(min_length=3, max_length=3000)
    model_report_id: str = Field(min_length=1, max_length=100)
    links: list[ReportLink] = Field(default_factory=list, max_length=2000)


@router.get('/assessment-settings')
def settings(user=Depends(principal)):
    return {'application_types': APPLICATION_TYPES, 'report_types': REPORT_TYPES, 'review_states': REVIEW_STATES,
        'can_manage_questionnaires': user['role'] == 'admin' and dict(user.get('products', ())).get('*') == 'admin', 'identity': user,
        'document_import_hosts': sorted(allowed_hosts()),
        'vision_configured': bool(os.getenv('AEGIS_DIAGRAM_VISION_URL') and os.getenv('AEGIS_DIAGRAM_VISION_MODEL')),
        'remote_diagram_processing': os.getenv('AEGIS_ALLOW_REMOTE_DIAGRAMS') == 'true'}


@router.get('/questionnaires')
def templates(db=Depends(assessment_store), user=Depends(principal)):
    return db.templates()


@router.post('/questionnaires')
def create_template(payload: TemplateInput, db=Depends(assessment_store), user=Depends(administrator)):
    require_platform_admin(user)
    return invoke(lambda: db.save_template(payload.model_dump(), user['name']))


@router.put('/questionnaires/{version}')
def amend_template(version: int, payload: TemplateInput, db=Depends(assessment_store), user=Depends(administrator)):
    require_platform_admin(user)
    return invoke(lambda: db.save_template(payload.model_dump(), user['name'], version))


@router.post('/questionnaires/{version}/{status}')
def transition_template(version: int, status: str, payload: Transition, db=Depends(assessment_store), user=Depends(administrator)):
    require_platform_admin(user)
    return invoke(lambda: db.transition_template(version, status, payload.expected_revision, user['name']))


@router.post('/sources/import')
async def source_import(payload: URLImport, user=Depends(editor)):
    return await run_in_threadpool(lambda: invoke(lambda: import_url(payload.url)))


@router.get('/assessment-reports/{report_id}/reviews')
def reviews(report_id: str, db=Depends(assessment_store), user=Depends(principal)):
    require_assessment_report(db.store, user, report_id)
    return invoke(lambda: db.reviews(report_id))


@router.post('/assessment-reports/{report_id}/reviews/{finding_id}')
def review(report_id: str, finding_id: str, payload: ReviewInput, db=Depends(assessment_store), user=Depends(editor)):
    require_assessment_report(db.store, user, report_id, 'editor')
    if payload.status in {'accepted', 'verified_fixed', 'false_positive'}:
        try:
            require_assessment_report(db.store, user, report_id, 'admin')
        except HTTPException as exc:
            if exc.status_code not in {403, 404}:
                raise
            raise HTTPException(403, 'Product administrator approval is required for final risk decisions.') from None
    return invoke(lambda: db.review(report_id, finding_id, payload.model_dump(), user))


@router.get('/assessments/{assessment_id}/security-reports')
def reports(assessment_id: str, db=Depends(assessment_store), user=Depends(principal)):
    require_assessment(db.store, user, assessment_id)
    return db.security_reports(assessment_id)


@router.post('/assessments/{assessment_id}/security-reports')
async def import_security_report(assessment_id: str, file: UploadFile = File(...), metadata: str = Form(...),
        db=Depends(assessment_store), user=Depends(editor)):
    require_assessment(db.store, user, assessment_id, 'editor')
    raw = await file.read(8_000_001)
    def execute():
        if len(metadata) > 5000:
            raise ValueError('Report metadata is too large.')
        value = json.loads(metadata)
        permitted = {'category', 'title', 'source', 'report_date', 'environment', 'deployment_version', 'image_digest'}
        if not isinstance(value, dict) or set(value) - permitted or any(not isinstance(v, str) or len(v) > 500 for v in value.values()):
            raise ValueError('Invalid report metadata.')
        for key in permitted - {'image_digest'}:
            if not value.get(key, '').strip():
                raise ValueError(f'{key} is required.')
        if value['category'] == 'container_security' and not value.get('image_digest', '').strip():
            raise ValueError('Container reports require an image digest or tag.')
        parsed = parse_report(raw, (file.filename or 'report.txt')[:200], value)
        return db.import_report(assessment_id, parsed, user['name'])
    return await run_in_threadpool(lambda: invoke(execute))


@router.get('/assessment-reports/{report_id}/register/{format}')
def export_register(report_id: str, format: str, db=Depends(assessment_store), user=Depends(principal)):
    require_assessment_report(db.store, user, report_id)
    def execute():
        report, reviews = db.result(report_id), db.reviews(report_id)
        rows = []
        for finding in report['threats']:
            decision = reviews['latest'].get(finding['id'], {})
            remarks = [event for event in reviews['events'] if event['finding_id'] == finding['id']]
            rows.append({'risk_id': finding['id'], 'risk_name': finding['title'], 'description': finding['description'],
                'source': finding.get('finding_type'), 'flows': finding.get('affected_flow_refs', []),
                'flow_reference_status': finding.get('flow_reference_status'), 'evidence': finding.get('evidence_details', []),
                'affected_components': finding.get('affected_components', []), 'affected_stride': finding.get('affected_stride_categories', []),
                'security_controls': finding.get('specific_control') or finding.get('mapped_controls') or finding.get('explanation', {}).get('matched_controls', []),
                'severity': finding['severity'], 'priority': finding.get('risk_score'), 'review_status': decision.get('status', 'pending_review'),
                'owner': decision.get('owner', ''), 'target_date': decision.get('target_date', ''), 'remarks': remarks, 'remediation': finding.get('mitigation')})
        if format == 'json':
            return Response(json.dumps({'assessment': report['engine_status']['assessment'], 'risks': rows}), media_type='application/json',
                headers={'Content-Disposition': 'attachment; filename="risk-register.json"'})
        if format != 'csv':
            raise ValueError('Register export supports CSV and JSON.')
        output = io.StringIO(newline='')
        fields = list(rows[0]) if rows else ['risk_id', 'risk_name', 'description', 'source', 'flows', 'evidence', 'security_controls', 'severity', 'review_status', 'remarks']
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            cells = {key: json.dumps(value) if isinstance(value, (dict, list)) else str(value or '') for key, value in row.items()}
            writer.writerow({key: "'" + value if value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else value for key, value in cells.items()})
        return Response(output.getvalue(), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename="risk-register.csv"'})
    return invoke(execute)


@router.post('/assessments/{assessment_id}/security-reports/{report_id}/review')
def review_external_report(assessment_id: str, report_id: str, payload: ReportReviewInput,
        db=Depends(assessment_store), user=Depends(editor)):
    require_assessment_report(db.store, user, report_id, 'editor', external=True, assessment_id=assessment_id)
    require_assessment_report(db.store, user, payload.model_report_id, 'editor', assessment_id=assessment_id)
    return invoke(lambda: db.review_security_report(assessment_id, report_id, payload.model_dump(), user))
