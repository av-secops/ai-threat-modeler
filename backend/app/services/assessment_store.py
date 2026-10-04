"""Governed assessment evidence, numbering and review history in the workspace DB."""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated

from pydantic import Field, TypeAdapter

from ..models import SystemArchitecture
from ..engine.canonical_diagram import render_view, identifier as diagram_id
from .model_review import prepare_model, flow_id, ReviewAnswer, _apply_answers, STRING_CONTROLS
from .product_store import StoreConflict
from .security_workflows import effective_workflow_review, Verification, Text
from .questionnaires import APPLICATION_TYPES, TemplateInput, build_questions, default_template, fingerprint


REVIEW_STATES = ('pending_review', 'in_review', 'action_required', 'accepted', 'false_positive', 'mitigation_proposed', 'verified_fixed')
REPORT_TYPES = ('threat_modeling', 'sast', 'penetration_testing', 'sca', 'foss', 'container_security', 'secret_detection', 'other')
_REVIEW_CRITERIA = TypeAdapter(Annotated[list[Text], Field(max_length=20)])
_REVIEW_VERIFICATION = TypeAdapter(Annotated[list[Verification], Field(max_length=20)])


class AssessmentStore:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS questionnaire_templates(
                    version INTEGER PRIMARY KEY AUTOINCREMENT, revision INTEGER NOT NULL,
                    status TEXT NOT NULL, body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS assessment_sessions(
                    id TEXT PRIMARY KEY, template_version INTEGER NOT NULL REFERENCES questionnaire_templates(version),
                    actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS assessment_answer_events(
                    id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessment_sessions(id),
                    question_id TEXT NOT NULL, body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS assessment_flow_numbers(
                    assessment_id TEXT NOT NULL REFERENCES assessment_sessions(id), flow_id TEXT NOT NULL,
                    number INTEGER NOT NULL, PRIMARY KEY(assessment_id,flow_id), UNIQUE(assessment_id,number));
                CREATE TABLE IF NOT EXISTS assessment_results(
                    id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessment_sessions(id),
                    body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS finding_review_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL REFERENCES assessment_results(id),
                    finding_id TEXT NOT NULL, body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS reviews_by_finding ON finding_review_events(report_id,finding_id,id);
                CREATE TABLE IF NOT EXISTS security_reports(
                    id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessment_sessions(id),
                    body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM questionnaire_templates LIMIT 1').fetchone():
                db.execute('INSERT INTO questionnaire_templates(revision,status,body,actor,created) VALUES(1,?,?,?,?)',
                    ('published', json.dumps(default_template()), 'system', time.time()))

    @staticmethod
    def _template(row):
        return {**json.loads(row['body']), **{key: row[key] for key in ('version', 'revision', 'status', 'actor', 'created')}}

    def templates(self):
        with self.store.connect() as db:
            return [self._template(row) for row in db.execute('SELECT * FROM questionnaire_templates ORDER BY version DESC')]

    def save_template(self, payload, actor, version=None):
        value = TemplateInput.model_validate(payload)
        body = json.dumps(value.model_dump(exclude={'expected_revision'}))
        with self.store.connect() as db:
            if version is None:
                cursor = db.execute('INSERT INTO questionnaire_templates(revision,status,body,actor,created) VALUES(1,?,?,?,?)',
                    ('draft', body, actor, time.time()))
                version = cursor.lastrowid
            else:
                row = db.execute('SELECT * FROM questionnaire_templates WHERE version=?', (version,)).fetchone()
                if not row:
                    raise LookupError('Questionnaire version not found.')
                if row['status'] != 'draft' or row['revision'] != value.expected_revision:
                    raise StoreConflict('Only the latest draft can be edited. Clone a published template to amend it.')
                db.execute('UPDATE questionnaire_templates SET body=?,revision=revision+1,actor=? WHERE version=?', (body, actor, version))
            self.store.audit(db, actor, 'save_questionnaire', str(version))
            return self._template(db.execute('SELECT * FROM questionnaire_templates WHERE version=?', (version,)).fetchone())

    def transition_template(self, version, status, revision, actor):
        with self.store.connect() as db:
            row = db.execute('SELECT * FROM questionnaire_templates WHERE version=?', (version,)).fetchone()
            if not row:
                raise LookupError('Questionnaire version not found.')
            if row['revision'] != revision or (row['status'], status) not in {('draft', 'published'), ('published', 'retired')}:
                raise StoreConflict('Invalid or stale template transition.')
            if status == 'retired' and db.execute("SELECT count(*) FROM questionnaire_templates WHERE status='published'").fetchone()[0] <= 1:
                raise ValueError('Publish a replacement before retiring the last active questionnaire.')
            db.execute('UPDATE questionnaire_templates SET status=?,revision=revision+1 WHERE version=?', (status, version))
            self.store.audit(db, actor, status + '_questionnaire', str(version))
        return next(row for row in self.templates() if row['version'] == version)

    def pin_template(self, identifier, actor):
        if not identifier:
            raise ValueError('A saved assessment ID is required. Start or reopen an assessment.')
        with self.store.connect() as db:
            session = db.execute('SELECT * FROM assessment_sessions WHERE id=?', (identifier,)).fetchone()
            if not session:
                row = db.execute("SELECT * FROM questionnaire_templates WHERE status='published' ORDER BY version DESC LIMIT 1").fetchone()
                if not row:
                    raise ValueError('No published questionnaire is available.')
                db.execute('INSERT INTO assessment_sessions VALUES(?,?,?,?)', (identifier, row['version'], actor, time.time()))
            else:
                row = db.execute('SELECT * FROM questionnaire_templates WHERE version=?', (session['template_version'],)).fetchone()
            return self._template(row)

    def number_flows(self, assessment_id, architecture):
        with self.store.connect() as db:
            numbers = {row['flow_id']: row['number'] for row in db.execute('SELECT flow_id,number FROM assessment_flow_numbers WHERE assessment_id=?', (assessment_id,))}
            next_number = max(numbers.values(), default=0) + 1
            for flow in architecture.flows:
                flow.id = flow_id(flow)
                if flow.id not in numbers:
                    numbers[flow.id] = next_number
                    db.execute('INSERT INTO assessment_flow_numbers VALUES(?,?,?)', (assessment_id, flow.id, next_number))
                    next_number += 1
                flow.flow_number = f'F-{numbers[flow.id]:03d}'
                flow.properties['review_id'] = flow.id

    def prepare(self, payload, identity, *, require_ready=False, record=True):
        template = self.pin_template(payload.assessment_id, identity['name'])
        preview = prepare_model(payload, render=False)
        architecture = SystemArchitecture.model_validate(preview['architecture'])
        questions = build_questions(template, architecture, payload, self._previous_answers(payload.assessment_id))
        missing = [q['id'] for q in questions if q['required'] and q['status'] not in {'answered', 'not_triggered'}]
        scope_errors = []
        if not payload.application_types:
            scope_errors.append('Select an application type.')
        if 'other' in payload.application_types and not payload.other_application_type.strip():
            scope_errors.append('Describe the other application type.')
        records = []
        with self.store.connect() as db:
            for q in questions:
                if q['status'] != 'answered':
                    continue
                answer = q['response']
                event_id = fingerprint([payload.assessment_id, template['version'], answer])
                existing = db.execute('SELECT body FROM assessment_answer_events WHERE id=?', (event_id,)).fetchone()
                if existing:
                    evidence = json.loads(existing['body'])
                else:
                    if not record:
                        raise ValueError('Questionnaire evidence must be saved before analysis.')
                    if answer['value'] == 'not_applicable' and identity['role'] != 'admin':
                        raise ValueError('An administrator must approve a not-applicable answer.')
                    evidence = {**answer, 'question': q['text'], 'question_key': q['key'], 'template_version': template['version'],
                        'reuse_digest': q['reuse_digest'], 'group_key': q['group_key'],
                        'source_fingerprints': {s.id: fingerprint(s.text) for s in payload.sources if s.id in answer['source_ids']},
                        'confirmation_basis': answer.get('basis', 'manual'),
                        'proposal_evidence': q['proposal']['evidence'] if q['proposal'] and answer.get('basis') != 'manual' else [],
                        'inherited_from': q['proposal'].get('previous') if q['proposal'] and answer.get('basis') == 'carry_forward' else None,
                        'reviewer': identity['name'], 'reviewer_role': identity['role'], 'answered_at': datetime.now(timezone.utc).isoformat()}
                    db.execute('INSERT INTO assessment_answer_events VALUES(?,?,?,?,?,?)',
                        (event_id, payload.assessment_id, q['id'], json.dumps(evidence), identity['name'], time.time()))
                q['recorded_by'] = evidence['reviewer']
                q['answered_at'] = evidence['answered_at']
                records.append(evidence)
        ready = not missing and not scope_errors
        if require_ready and (not ready or not architecture.components):
            raise ValueError('Complete the current questionnaire and application scope before generating or analyzing the DFD.')
        applied = []
        for q in questions:
            response = q['response']
            if q['status'] != 'answered' or not q['control'] or q['control'] in STRING_CONTROLS or response['value'] not in {'present', 'absent'}:
                continue
            applied.append(ReviewAnswer(element_id=q['element_id'], control=q['control'], state=response['value'],
                note=response['note'], reviewer=q['recorded_by'], answered_at=q['answered_at'],
                source_ids=response['source_ids'], source_digest=preview['source_digest']))
        _apply_answers(architecture, payload.model_copy(update={'answers': applied}), preview['source_digest'], preview['warnings'])
        self.number_flows(payload.assessment_id, architecture)
        state = {'id': payload.assessment_id, 'template_version': template['version'], 'template_name': template['name'],
            'application_types': payload.application_types, 'other_application_type': payload.other_application_type,
            'environment': payload.environment, 'deployment_version': payload.deployment_version,
            'complete': ready, 'missing': missing, 'scope_errors': scope_errors, 'answers': records,
            'verification_status': 'owner_reviewed_not_runtime_verified'}
        state['questionnaire_summary'] = {
            'checks': len(questions), 'answered': sum(q['status'] == 'answered' for q in questions),
            'not_triggered': sum(q['status'] == 'not_triggered' for q in questions),
            'required_remaining': len(missing),
            'suggested_answers': sum(bool(q['proposal']) and q['status'] not in {'answered', 'not_triggered'} for q in questions),
            'clarification_groups': len({q['id'] if q['requires_individual_review'] else q['group_key'] for q in questions if not q['proposal'] and q['status'] not in {'answered', 'not_triggered'}}),
        }
        architecture.metadata['assessment'] = state
        view = render_view(architecture) if ready and (payload.generate_dfd or require_ready) else None
        preview.update({'architecture': architecture.model_dump(), 'flows': [{**f.model_dump(), 'review_id': f.id} for f in architecture.flows],
            'questionnaire': {**state, 'questions': questions}, 'diagram': view['diagram'] if view else ''})
        if view:
            preview['diagram_coverage'] = view['coverage']
            preview['diagram_bindings']['flows'] = [{'source': diagram_id(architecture.flows[i].source_id),
                'target': diagram_id(architecture.flows[i].target_id), 'element_id': architecture.flows[i].id}
                for i in view['coverage']['flow_indexes']]
        preview['readiness']['questionnaire_complete'] = ready
        preview['readiness']['dfd_generated'] = bool(preview['diagram'])
        return preview

    def _previous_answers(self, assessment_id):
        """Only a server-created clone lineage may propose another release's answers."""
        with self.store.read_snapshot() as db:
            origin = db.execute('''SELECT source.id,l.created FROM assessment_lineage l
                JOIN workspaces target ON target.id=l.target_id
                JOIN workspaces source ON source.id=l.source_id
                JOIN releases tr ON tr.id=target.release_id JOIN releases sr ON sr.id=source.release_id
                WHERE l.target_id=? AND tr.product_id=sr.product_id
                AND target.application_id IS source.application_id AND target.environment=source.environment''', (assessment_id,)).fetchone()
            if not origin:
                return {}
            rows = db.execute('SELECT body FROM assessment_answer_events WHERE assessment_id=? AND created<=? ORDER BY created,id', (origin['id'], origin['created'])).fetchall()
        return {row['question_id']: {**row, 'assessment_id': origin['id']}
                for item in rows if (row := json.loads(item['body']))}

    def save_result(self, result, actor):
        state = (result.architecture.metadata or {}).get('assessment', {})
        if not state.get('complete'):
            raise ValueError('A governed report requires a completed questionnaire.')
        report_id = str(uuid.uuid4())
        result.engine_status['assessment'] = {**state, 'report_id': report_id}
        result.engine_status['assessment_mode'] = 'governed'
        with self.store.connect() as db:
            db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)',
                (report_id, state['id'], result.model_dump_json(), actor, time.time()))
        return result

    def result(self, report_id):
        with self.store.connect() as db:
            row = db.execute('SELECT * FROM assessment_results WHERE id=?', (report_id,)).fetchone()
            if not row:
                raise LookupError('Assessment report not found.')
            return json.loads(row['body'])

    def reviews(self, report_id):
        self.result(report_id)
        with self.store.connect() as db:
            events = [{**json.loads(r['body']), 'version': r['id'], 'author': r['actor'], 'created_at': r['created'], 'finding_id': r['finding_id']}
                for r in db.execute('SELECT * FROM finding_review_events WHERE report_id=? ORDER BY id', (report_id,))]
        now = time.time()
        latest = {event['finding_id']: effective_workflow_review(event, now=now)
                  if event.get('security_workflow') else event for event in events}
        return {'latest': latest, 'events': events}

    def review(self, report_id, finding_id, value, identity):
        result = self.result(report_id)
        if finding_id not in {f['id'] for f in result['threats']}:
            raise LookupError('Finding not present in this report revision.')
        status = value.get('status', 'pending_review')
        if status not in REVIEW_STATES:
            raise ValueError('Invalid review status.')
        if status in {'accepted', 'verified_fixed', 'false_positive'}:
            if identity['role'] != 'admin':
                raise ValueError('Product administrator approval is required for final risk decisions.')
            from .workspace_access import VerifiedIdentity, require_assessment_report
            if isinstance(identity, VerifiedIdentity):
                require_assessment_report(self.store, identity, report_id, 'admin')
        if status == 'accepted':
            if not str(value.get('owner') or '').strip():
                raise ValueError('Risk acceptance requires an accountable owner.')
            try:
                expiry = datetime.fromisoformat(value.get('acceptance_expires_at') or '')
                if expiry.tzinfo is None or not time.time() < expiry.timestamp() <= time.time() + 366 * 86400:
                    raise ValueError()
            except (TypeError, ValueError, OverflowError):
                raise ValueError('Risk acceptance requires a future expiry with a timezone, within 366 days.') from None
        if not isinstance(value.get('remarks'), str) or len(value['remarks'].strip()) < 3:
            raise ValueError('Record the reason or product-team remarks for this review.')
        criteria = _REVIEW_CRITERIA.validate_python(value.get('acceptance_criteria', []))
        verification = _REVIEW_VERIFICATION.validate_python(value.get('verification', []))
        for check in verification:
            if check.checked_at.tzinfo is None or check.checked_at.utcoffset() is None:
                raise ValueError('Verification dates must include a timezone.')
            if check.checked_at.timestamp() > time.time() + 300:
                raise ValueError('Verification cannot be dated in the future.')
        if status == 'verified_fixed' and (not criteria or not verification or any(check.result != 'passed' for check in verification)):
            raise ValueError('Verified fixed requires acceptance criteria and passing structured verification evidence.')
        if status == 'verified_fixed' and (not isinstance(value.get('owner'), str) or not value['owner'].strip()):
            raise ValueError('Verified fixed requires an accountable owner.')
        body = {k: value.get(k, '') for k in ('status', 'remarks', 'owner', 'target_date', 'verification_evidence', 'acceptance_expires_at')}
        body['author_role'] = identity['role']
        if any(not isinstance(v, str) or len(v) > 6000 for v in body.values()):
            raise ValueError('Review fields must be text of at most 6000 characters.')
        body['acceptance_criteria'] = criteria
        body['verification'] = [check.model_dump(mode='json') for check in verification]
        if status == 'verified_fixed':
            # Existing register/export readers still consume this summary field.
            # Full references and test results remain in the structured records.
            body['verification_evidence'] = (
                f'Reviewer-attested: {len(verification)} passing verification check(s). '
                f'First reference: {verification[0].reference}. See structured verification records for all evidence.')
            body['verification_status'] = 'reviewer_attested_not_automatically_tested'
        body['security_workflow'] = True
        with self.store.connect() as db:
            last = db.execute('SELECT MAX(id) FROM finding_review_events WHERE report_id=? AND finding_id=?', (report_id, finding_id)).fetchone()[0] or 0
            if last != value.get('expected_version', 0):
                raise StoreConflict('This finding was reviewed elsewhere. Reload its remarks before saving.')
            db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
                (report_id, finding_id, json.dumps(body), identity['name'], time.time()))
            self.store.audit(db, identity['name'], 'review_finding', report_id + ':' + finding_id)
        return self.reviews(report_id)

    def security_reports(self, assessment_id):
        with self.store.connect() as db:
            native = [{'id': r['id'], 'category': 'threat_modeling', 'title': 'Threat Modeling', 'status': 'pending_review',
                'created_at': r['created'], 'source': 'Aegis', 'native': True} for r in db.execute(
                'SELECT id,created FROM assessment_results WHERE assessment_id=? ORDER BY created DESC', (assessment_id,))]
            imported = [{**json.loads(r['body']), 'id': r['id'], 'created_at': r['created'], 'imported_by': r['actor']}
                for r in db.execute('SELECT * FROM security_reports WHERE assessment_id=? ORDER BY created DESC', (assessment_id,))]
        return {'categories': list(REPORT_TYPES), 'reports': native + imported}

    def import_report(self, assessment_id, report, actor):
        if report.get('category') not in REPORT_TYPES or report['category'] == 'threat_modeling':
            raise ValueError('Select an external security assessment category.')
        for field in ('title', 'source', 'report_date', 'environment', 'deployment_version'):
            if not str(report.get(field, '')).strip():
                raise ValueError(f'{field.replace("_", " ")} is required for report scope.')
        identifier = str(uuid.uuid4())
        body = {**report, 'status': 'imported', 'revision': 1, 'review_history': [], 'links': [],
            'verification_status': 'external_report_not_independently_verified'}
        with self.store.connect() as db:
            if not db.execute('SELECT 1 FROM assessment_sessions WHERE id=?', (assessment_id,)).fetchone():
                raise LookupError('Assessment not found.')
            for row in db.execute('SELECT id,body FROM security_reports WHERE assessment_id=?', (assessment_id,)):
                old = json.loads(row['body'])
                if all(old.get(key) == body.get(key) for key in ('artifact_hash', 'category', 'environment', 'deployment_version', 'image_digest', 'report_date', 'source')):
                    return {**old, 'id': row['id']}
            db.execute('INSERT INTO security_reports VALUES(?,?,?,?,?)', (identifier, assessment_id, json.dumps(body), actor, time.time()))
            self.store.audit(db, actor, 'import_security_report', identifier)
        return {**body, 'id': identifier}

    def review_security_report(self, assessment_id, report_id, value, identity):
        from .security_report_import import redact
        if value.get('status') not in {'imported', 'under_review', 'reviewed'}:
            raise ValueError('Invalid external report review status.')
        if len(value.get('remarks', '').strip()) < 3:
            raise ValueError('A report review needs attributable remarks.')
        target = self.result(value['model_report_id'])
        if target.get('engine_status', {}).get('assessment', {}).get('id') != assessment_id:
            raise ValueError('Links must reference a model revision in this assessment.')
        components = {c['id'] for c in target['architecture']['components']}
        flows = {f['id'] for f in target['architecture']['flows']}
        with self.store.connect() as db:
            row = db.execute('SELECT * FROM security_reports WHERE id=? AND assessment_id=?', (report_id, assessment_id)).fetchone()
            if not row:
                raise LookupError('Security report not found.')
            body = json.loads(row['body'])
            if value['expected_revision'] != body.get('revision', 1):
                raise StoreConflict('This report was reviewed elsewhere. Refresh reports before editing.')
            findings = {f['import_id'] for f in body.get('findings', [])}
            links = value.get('links', [])
            for link in links:
                if link['finding_id'] not in findings or not set(link['component_ids']) <= components or not set(link['flow_ids']) <= flows:
                    raise ValueError('A report link references an unknown finding, component or flow.')
                if not link['component_ids'] and not link['flow_ids']:
                    raise ValueError('Select a component or flow for each link.')
                if len(link['reason'].strip()) < 3:
                    raise ValueError('Explain the evidence supporting each link.')
            if len({link['finding_id'] for link in links}) != len(links):
                raise ValueError('Use one link record per imported finding.')
            revision = body.get('revision', 1) + 1
            event = redact({'version': revision, 'status': value['status'], 'remarks': value['remarks'],
                'links': links, 'model_report_id': value['model_report_id'], 'author': identity['name'],
                'author_role': identity['role'], 'created_at': time.time()})
            body.update({'revision': revision, 'status': event['status'], 'links': event['links'],
                'model_report_id': value['model_report_id'], 'link_status': 'reviewer_linked' if links else 'unlinked_pending_review',
                'review_history': [*body.get('review_history', []), event]})
            db.execute('UPDATE security_reports SET body=? WHERE id=?', (json.dumps(body), report_id))
            self.store.audit(db, identity['name'], 'review_security_report', report_id)
        return {**body, 'id': report_id, 'created_at': row['created'], 'imported_by': row['actor']}
