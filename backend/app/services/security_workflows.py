"""Scoped organizational evidence, risk decisions and an opt-in Jira outbox.

This service never changes an analysis result or treats ticket status as proof of
remediation. It owns only sw_* tables in the existing ProductStore database.
"""

from copy import deepcopy
from collections.abc import Mapping
from datetime import datetime, timezone
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from typing import Annotated, Literal
from urllib.parse import urlsplit
import uuid

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
import urllib3

from ..engine.control_contracts import control_value
from .product_store import StoreConflict, normalize_name


Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=3000)]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
STATES = ('pending_review', 'in_review', 'action_required', 'mitigation_proposed',
          'accepted', 'false_positive', 'verified_fixed')
MAX_ATTEMPTS = 5
LEASE_SECONDS = 120


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _timestamp(value):
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Dates must include a timezone.')
    return value.timestamp()


def _deadline(value, now):
    stamp = _timestamp(value)
    if stamp is None or not now < stamp <= now + 366 * 86400:
        raise ValueError('Expiry must be in the future and no more than 366 days away.')
    return stamp


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class PatternControl(Input):
    control: str = Field(pattern=r'^[a-z][a-z0-9_]{1,99}$')
    state: Literal['present', 'absent', 'partial', 'planned', 'unknown']
    statement: Text
    source_references: list[Text] = Field(min_length=1, max_length=20)


class PatternInput(Input):
    name: ShortText
    owner: ShortText
    description: Text
    environment: ShortText
    application_id: Identifier | None = None
    release_id: Identifier | None = None
    component_types: list[ShortText] = Field(min_length=1, max_length=30)
    controls: list[PatternControl] = Field(min_length=1, max_length=64)
    expires_at: datetime
    expected_version: int = Field(default=0, ge=0)

    @field_validator('controls')
    @classmethod
    def unique_controls(cls, controls):
        if len({c.control for c in controls}) != len(controls):
            raise ValueError('Each control may be declared once per pattern version.')
        return controls


class PatternTransition(Input):
    status: Literal['published', 'retired']
    expected_revision: int = Field(ge=1)
    reason: Text


class InheritanceInput(Input):
    pattern_id: Identifier
    pattern_version: int = Field(ge=1)
    component_ids: list[Identifier] = Field(min_length=1, max_length=100)
    reason: Text


class Verification(Input):
    method: Literal['test', 'configuration_review', 'code_review', 'independent_report']
    reference: Text
    result: Literal['passed', 'failed', 'inconclusive']
    checked_at: datetime


class RiskReview(Input):
    expected_version: int = Field(default=0, ge=0)
    expected_canonical_version: int | None = Field(default=None, ge=0)
    status: Literal['pending_review', 'in_review', 'action_required', 'mitigation_proposed',
                    'accepted', 'false_positive', 'verified_fixed'] = 'pending_review'
    owner: str = Field(default='', max_length=200)
    remarks: Text
    target_date: datetime | None = None
    acceptance_expires_at: datetime | None = None
    acceptance_criteria: list[Text] = Field(default_factory=list, max_length=20)
    verification: list[Verification] = Field(default_factory=list, max_length=20)


class RiskComment(Input):
    expected_version: int = Field(ge=1)
    expected_canonical_version: int | None = Field(default=None, ge=0)
    comment: Text


class TicketLink(Input):
    connection: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    issue_key: str = Field(pattern=r'^[A-Z][A-Z0-9_]{1,30}-[1-9][0-9]{0,14}$')


class TicketSync(Input):
    operation: Literal['pull', 'push']
    idempotency_key: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{8,100}$')


def _has_table(db, name):
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def _canonical_review(db, report_id, finding_id):
    if not _has_table(db, 'finding_review_events'):
        return None
    return db.execute('SELECT * FROM finding_review_events WHERE report_id=? AND finding_id=? ORDER BY id DESC LIMIT 1',
                      (report_id, finding_id)).fetchone()


def _mirror_review(db, report_id, finding_id, body, actor, now):
    if not _has_table(db, 'finding_review_events'):
        return 0
    value = {**body, 'security_workflow': True,
             'verification_evidence': '\n'.join(v['reference'] for v in body.get('verification', []) if v['result'] == 'passed')}
    value.pop('canonical_event_id', None)
    cursor = db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
                        (report_id, finding_id, _json(value), actor, now))
    return cursor.lastrowid


def effective_workflow_review(body, *, now=None):
    """Pure read projection shared by the register and dashboard; no DB writes.

    External callers should apply only to decisions marked security_workflow.
    Original acceptance/verification records stay immutable in the event log.
    """
    now = time.time() if now is None else now
    value = deepcopy(body)
    expires = value.get('acceptance_expires_at')
    expired = False
    if value.get('status') == 'accepted':
        try:
            expired = not expires or _timestamp(datetime.fromisoformat(expires)) <= now
        except (ValueError, TypeError, AttributeError):
            expired = True
    value['acceptance_expired'] = bool(expired)
    if expired:
        value['recorded_status'] = value['status']
        value['status'] = 'pending_review'
    value['overdue'] = False
    if value.get('target_date') and value.get('status') not in {'verified_fixed', 'false_positive'}:
        try:
            target = datetime.fromisoformat(value['target_date'])
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            value['overdue'] = target.timestamp() <= now
        except (ValueError, TypeError, AttributeError):
            value['due_date_invalid'] = True
    return value


def workflow_review_overlays(db, product_id=None, *, now=None):
    """Dashboard-compatible latest canonical decisions, with live expiry states.

    Merge this mapping into product_dashboard._load's reviews before _build.
    Synthetic read IDs include effective state so expiry invalidates export/page
    fingerprints without changing the canonical optimistic-lock version.
    """
    if not _has_table(db, 'finding_review_events'):
        return {}
    query = '''SELECT e.* FROM finding_review_events e JOIN assessment_results a ON a.id=e.report_id
        JOIN workspaces w ON w.id=a.assessment_id JOIN releases r ON r.id=w.release_id
        WHERE json_extract(e.body,'$.security_workflow')=1
        AND a.id=json_extract(w.payload,'$.revisions[#-1].data.engine_status.assessment.report_id')
        AND e.id=(SELECT MAX(last.id) FROM finding_review_events last
                  WHERE last.report_id=e.report_id AND last.finding_id=e.finding_id)'''
    params = ()
    if product_id:
        query += ' AND r.product_id=?'
        params = (product_id,)
    result = {}
    for row in db.execute(query, params):
        body = effective_workflow_review(json.loads(row['body']), now=now)
        item = {**dict(row), 'body': _json(body), 'canonical_version': row['id']}
        item['id'] = f"workflow:{row['id']}:{body['status']}:{int(body['acceptance_expired'])}:{int(body['overdue'])}"
        result[(row['report_id'], row['finding_id'])] = item
    return result


class SecurityWorkflows:
    def __init__(self, store, *, clock=time.time):
        self.store, self.clock = store, clock
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS sw_patterns(
                    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
                    name TEXT NOT NULL, name_key TEXT NOT NULL, UNIQUE(product_id,name_key));
                CREATE TABLE IF NOT EXISTS sw_pattern_versions(
                    pattern_id TEXT NOT NULL REFERENCES sw_patterns(id), version INTEGER NOT NULL,
                    revision INTEGER NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL,
                    actor TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(pattern_id,version));
                CREATE TABLE IF NOT EXISTS sw_inheritances(
                    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id), report_revision INTEGER NOT NULL,
                    pattern_id TEXT NOT NULL, pattern_version INTEGER NOT NULL,
                    body TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL,
                    FOREIGN KEY(pattern_id,pattern_version) REFERENCES sw_pattern_versions(pattern_id,version));
                CREATE TABLE IF NOT EXISTS sw_risks(
                    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id), report_revision INTEGER NOT NULL,
                    finding_id TEXT NOT NULL, version INTEGER NOT NULL, body TEXT NOT NULL,
                    actor TEXT NOT NULL, updated REAL NOT NULL,
                    UNIQUE(workspace_id,report_revision,finding_id));
                CREATE TABLE IF NOT EXISTS sw_ticket_links(
                    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
                    risk_id TEXT NOT NULL REFERENCES sw_risks(id), connection TEXT NOT NULL,
                    config_digest TEXT NOT NULL, issue_key TEXT NOT NULL, body TEXT NOT NULL,
                    actor TEXT NOT NULL, created REAL NOT NULL,
                    UNIQUE(risk_id,connection), UNIQUE(connection,issue_key));
                CREATE TABLE IF NOT EXISTS sw_outbox(
                    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
                    link_id TEXT NOT NULL REFERENCES sw_ticket_links(id), operation TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
                    attempts INTEGER NOT NULL, due REAL NOT NULL, lease_until REAL,
                    lease_token TEXT, error TEXT, actor TEXT NOT NULL, created REAL NOT NULL,
                    updated REAL NOT NULL, UNIQUE(product_id,idempotency_key));
                CREATE TABLE IF NOT EXISTS sw_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT NOT NULL REFERENCES products(id),
                    target TEXT NOT NULL, action TEXT NOT NULL, body TEXT NOT NULL,
                    actor TEXT NOT NULL, created REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS sw_events_target ON sw_events(product_id,target,id);
                CREATE INDEX IF NOT EXISTS sw_risks_workspace ON sw_risks(workspace_id,report_revision);
                CREATE INDEX IF NOT EXISTS sw_outbox_due ON sw_outbox(product_id,state,due);
                CREATE INDEX IF NOT EXISTS sw_inherited_workspace ON sw_inheritances(workspace_id,report_revision);
            ''')

    @staticmethod
    def _role(identity, admin=False, product_id=None):
        if not isinstance(identity, Mapping) or not identity.get('name'):
            raise PermissionError('An authenticated identity is required.')
        if identity.get('role') not in ({'admin'} if admin else {'editor', 'admin'}):
            raise PermissionError('Administrator approval is required.' if admin else 'Editor access is required.')
        if product_id:
            from .workspace_access import VerifiedIdentity, require_product
            if isinstance(identity, VerifiedIdentity):
                require_product(identity, product_id, 'admin' if admin else 'editor')

    def _event(self, db, product_id, target, action, body, actor):
        db.execute('INSERT INTO sw_events(product_id,target,action,body,actor,created) VALUES(?,?,?,?,?,?)',
                   (product_id, target, action, _json(body), actor, self.clock()))
        self.store.audit(db, actor, 'security_workflows.' + action, target)

    def _product(self, db, product_id, write=False):
        product = self.store.require(db, 'products', product_id)
        if write and product['archived']:
            raise StoreConflict('Restore the product before changing security workflows.')
        return product

    def _report(self, db, product_id, workspace_id, revision, *, write=False):
        self._product(db, product_id, write)
        workspace = self.store.require(db, 'workspaces', workspace_id)
        release = self.store.require(db, 'releases', workspace['release_id'])
        if release['product_id'] != product_id:
            raise LookupError('Workspace not found in this product.')
        if write and release['archived']:
            raise StoreConflict('Restore the release before changing security workflows.')
        snapshot = next((r for r in json.loads(workspace['payload']).get('revisions', [])
                         if r.get('number') == revision), None)
        if not snapshot:
            raise LookupError('Published report revision not found.')
        report = snapshot.get('data', {})
        report_id = report.get('engine_status', {}).get('assessment', {}).get('report_id')
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='assessment_results'").fetchone()
        authoritative = db.execute('SELECT * FROM assessment_results WHERE id=?', (report_id,)).fetchone() if exists and report_id else None
        if not authoritative or authoritative['assessment_id'] != workspace_id:
            raise ValueError('A server-recorded assessment report belonging to this workspace is required.')
        return workspace, json.loads(authoritative['body'])

    def _risk_ref(self, db, product_id, workspace_id, revision, finding_id, *, write=False):
        workspace, report = self._report(db, product_id, workspace_id, revision, write=write)
        matches = [f for f in report.get('threats', []) if f.get('id') == finding_id]
        if len(matches) != 1:
            raise LookupError('A unique finding was not found in this report revision.')
        identifier = _digest([product_id, workspace_id, revision, finding_id])
        return identifier, workspace, report, matches[0]

    @staticmethod
    def _pattern(db, product_id, pattern_id, version):
        row = db.execute('''SELECT v.*,p.product_id,p.name FROM sw_pattern_versions v
            JOIN sw_patterns p ON p.id=v.pattern_id WHERE p.product_id=? AND p.id=? AND v.version=?''',
                         (product_id, pattern_id, version)).fetchone()
        if not row:
            raise LookupError('Pattern version not found in this product.')
        return {**dict(row), 'body': json.loads(row['body'])}

    def create_pattern_version(self, product_id, payload, identity, pattern_id=None):
        self._role(identity, product_id=product_id)
        value = PatternInput.model_validate(payload)
        _deadline(value.expires_at, self.clock())
        name, key = normalize_name(value.name)
        body = value.model_dump(mode='json', exclude={'expected_version'})
        if len(_json(body).encode()) > 64_000:
            raise ValueError('Pattern content exceeds the 64 KB limit.')
        with self.store.connect() as db:
            self._product(db, product_id, True)
            for table, identifier in [('applications', value.application_id), ('releases', value.release_id)]:
                if identifier and self.store.require(db, table, identifier)['product_id'] != product_id:
                    raise ValueError('Pattern scope belongs to another product.')
            if pattern_id is None:
                if value.expected_version != 0:
                    raise StoreConflict('A new pattern starts at version zero.')
                pattern_id = str(uuid.uuid4())
                db.execute('INSERT INTO sw_patterns VALUES(?,?,?,?)', (pattern_id, product_id, name, key))
                latest = 0
            else:
                pattern = db.execute('SELECT * FROM sw_patterns WHERE id=? AND product_id=?', (pattern_id, product_id)).fetchone()
                if not pattern:
                    raise LookupError('Pattern not found in this product.')
                if pattern['name_key'] != key:
                    raise ValueError('Versioned patterns retain their identity and name.')
                latest = db.execute('SELECT MAX(version) FROM sw_pattern_versions WHERE pattern_id=?', (pattern_id,)).fetchone()[0]
            if latest != value.expected_version:
                raise StoreConflict('The pattern changed. Reload before creating a version.')
            version = latest + 1
            db.execute('INSERT INTO sw_pattern_versions VALUES(?,?,1,?,?,?,?)',
                       (pattern_id, version, 'draft', _json(body), identity['name'], self.clock()))
            self._event(db, product_id, pattern_id, 'pattern_version_created', {'version': version, 'body': body}, identity['name'])
            return self._pattern(db, product_id, pattern_id, version)

    def patterns(self, product_id, *, offset=0, limit=50):
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            self._product(db, product_id)
            rows = db.execute('''SELECT v.*,p.product_id,p.name FROM sw_pattern_versions v JOIN sw_patterns p
                ON p.id=v.pattern_id WHERE p.product_id=? ORDER BY p.name_key,v.version DESC LIMIT ? OFFSET ?''',
                              (product_id, limit + 1, offset)).fetchall()
            return self._page_result([{**dict(r), 'body': json.loads(r['body']),
                'expired': _timestamp(datetime.fromisoformat(json.loads(r['body'])['expires_at'])) <= self.clock()} for r in rows], offset, limit)

    def transition_pattern(self, product_id, pattern_id, version, payload, identity):
        self._role(identity, admin=True, product_id=product_id)
        value = PatternTransition.model_validate(payload)
        with self.store.connect() as db:
            self._product(db, product_id, True)
            row = self._pattern(db, product_id, pattern_id, version)
            if row['revision'] != value.expected_revision or (row['status'], value.status) not in {('draft', 'published'), ('published', 'retired')}:
                raise StoreConflict('Invalid or stale pattern transition.')
            if value.status == 'published':
                _deadline(datetime.fromisoformat(row['body']['expires_at']), self.clock())
            db.execute('UPDATE sw_pattern_versions SET status=?,revision=revision+1 WHERE pattern_id=? AND version=?',
                       (value.status, pattern_id, version))
            self._event(db, product_id, pattern_id, 'pattern_' + value.status,
                        {'version': version, 'reason': value.reason}, identity['name'])
            return self._pattern(db, product_id, pattern_id, version)

    def inherit_pattern(self, product_id, workspace_id, revision, payload, identity):
        self._role(identity, product_id=product_id)
        value = InheritanceInput.model_validate(payload)
        with self.store.connect() as db:
            workspace, report = self._report(db, product_id, workspace_id, revision, write=True)
            pattern = self._pattern(db, product_id, value.pattern_id, value.pattern_version)
            body = pattern['body']
            if pattern['status'] != 'published' or _timestamp(datetime.fromisoformat(body['expires_at'])) <= self.clock():
                raise StoreConflict('Only a published, unexpired pattern version can be inherited.')
            if (body['environment'] != workspace['environment'] or body['application_id'] != workspace['application_id']
                    or body['release_id'] not in {None, workspace['release_id']}):
                raise ValueError('Pattern and workspace application, release or environment scope do not match.')
            components = {c['id']: c for c in report.get('architecture', {}).get('components', [])}
            claims = []
            for component_id in sorted(set(value.component_ids)):
                component = components.get(component_id)
                if not component or component.get('type') not in body['component_types']:
                    raise ValueError('Each selected component must exist and have an allowed component type.')
                for control in body['controls']:
                    observed = control_value(component.get('properties') or {}, control['control'])
                    conflict = observed == 'conflicting' or {observed, control['state']} == {'present', 'absent'}
                    claims.append({**deepcopy(control), 'component_id': component_id, 'observed_state': observed,
                                   'state': 'conflicting' if conflict else 'unverified', 'declared_state': control['state'],
                                   'verification_status': 'requires_validation', 'suppresses_finding': False})
            identifier = _digest([product_id, workspace_id, revision, value.pattern_id, value.pattern_version,
                                  sorted(set(value.component_ids))])
            evidence = {'id': identifier, 'pattern_id': value.pattern_id, 'pattern_version': value.pattern_version,
                'pattern_digest': _digest(body), 'report_digest': _digest(report), 'product_id': product_id,
                'workspace_id': workspace_id, 'report_revision': revision, 'release_id': workspace['release_id'],
                'application_id': workspace['application_id'], 'environment': workspace['environment'],
                'owner': body['owner'], 'expires_at': body['expires_at'], 'reason': value.reason, 'claims': claims}
            if len(_json(evidence).encode()) > 512_000:
                raise ValueError('Inherited evidence exceeds 512 KB. Select fewer components or a smaller pattern.')
            old = db.execute('SELECT body FROM sw_inheritances WHERE id=?', (identifier,)).fetchone()
            if old:
                return json.loads(old['body'])
            db.execute('INSERT INTO sw_inheritances VALUES(?,?,?,?,?,?,?,?,?)', (identifier, product_id, workspace_id,
                revision, value.pattern_id, value.pattern_version, _json(evidence), identity['name'], self.clock()))
            self._event(db, product_id, identifier, 'pattern_inherited', evidence, identity['name'])
            return evidence

    def inherited_evidence(self, product_id, workspace_id, revision, *, offset=0, limit=50):
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            _, report = self._report(db, product_id, workspace_id, revision)
            rows = db.execute('''SELECT i.body,v.status FROM sw_inheritances i JOIN sw_pattern_versions v
                ON v.pattern_id=i.pattern_id AND v.version=i.pattern_version
                WHERE i.product_id=? AND i.workspace_id=? AND i.report_revision=? ORDER BY i.created,i.id LIMIT ? OFFSET ?''',
                              (product_id, workspace_id, revision, limit + 1, offset)).fetchall()
            result = []
            for row in rows:
                body = json.loads(row['body'])
                body['stale'] = (row['status'] != 'published' or _timestamp(datetime.fromisoformat(body['expires_at'])) <= self.clock()
                                 or body['report_digest'] != _digest(report))
                body['pattern_status'] = row['status']
                result.append(body)
            return self._page_result(result, offset, limit)

    def _risk_view(self, row):
        result = {**dict(row), 'body': json.loads(row['body'])}
        effective = effective_workflow_review(result['body'], now=self.clock())
        result['effective_status'] = effective['status']
        result['acceptance_expired'] = effective['acceptance_expired']
        result['closed'] = result['effective_status'] in {'verified_fixed', 'false_positive'}
        result['overdue'] = effective['overdue']
        result['canonical_version'] = result['body'].get('canonical_event_id', 0)
        return result

    def expire_acceptances(self, product_id, identity, *, limit=100):
        """Persist expiry transitions for audit/notifications; reads expire immediately."""
        self._role(identity, admin=True, product_id=product_id)
        self._page(0, limit)
        result = []
        with self.store.connect() as db:
            self._product(db, product_id, True)
            rows = db.execute('''SELECT * FROM sw_risks WHERE product_id=?
                AND json_extract(body,'$.status')='accepted'
                AND julianday(json_extract(body,'$.acceptance_expires_at'))<=julianday(?,'unixepoch')
                ORDER BY updated,id LIMIT ?''', (product_id, self.clock(), limit)).fetchall()
            for row in rows:
                view = self._risk_view(row)
                if not view['acceptance_expired']:
                    continue
                body = view['body']
                _, report = self._report(db, product_id, row['workspace_id'], row['report_revision'])
                report_id = report['engine_status']['assessment']['report_id']
                canonical = _canonical_review(db, report_id, row['finding_id'])
                if (canonical['id'] if canonical else 0) != body.get('canonical_event_id', 0):
                    continue
                expiry = body.pop('acceptance_expires_at')
                body.update({'status': 'pending_review', 'acceptance_expires_at': None,
                             'previous_acceptance_expired_at': expiry})
                body['canonical_event_id'] = _mirror_review(db, report_id, row['finding_id'], body, identity['name'], self.clock())
                db.execute('UPDATE sw_risks SET version=version+1,body=?,updated=? WHERE id=?',
                           (_json(body), self.clock(), row['id']))
                self._event(db, product_id, row['id'], 'risk_acceptance_expired',
                            {'version': row['version'] + 1, 'owner': body['owner'], 'expired_at': expiry}, identity['name'])
                result.append(self._risk_view(db.execute('SELECT * FROM sw_risks WHERE id=?', (row['id'],)).fetchone()))
        return result

    def review_risk(self, product_id, workspace_id, revision, finding_id, payload, identity):
        self._role(identity, product_id=product_id)
        value = RiskReview.model_validate(payload)
        now = self.clock()
        if value.status != 'pending_review' and not value.owner:
            raise ValueError('Assign a risk owner before starting a review or decision.')
        if value.status in {'accepted', 'verified_fixed', 'false_positive'}:
            self._role(identity, admin=True, product_id=product_id)
        if value.status == 'accepted':
            _deadline(value.acceptance_expires_at, now)
        elif value.acceptance_expires_at is not None:
            raise ValueError('Acceptance expiry is only valid for accepted risk.')
        if value.target_date:
            _timestamp(value.target_date)
        for check in value.verification:
            if _timestamp(check.checked_at) > now + 300:
                raise ValueError('Verification cannot be dated in the future.')
        if value.status == 'verified_fixed' and (not value.acceptance_criteria or not value.verification
                                                 or any(v.result != 'passed' for v in value.verification)):
            raise ValueError('Verified fixed requires acceptance criteria and passing verification evidence.')
        body = value.model_dump(mode='json', exclude={'expected_version', 'expected_canonical_version'})
        with self.store.connect() as db:
            identifier, _, report, _ = self._risk_ref(db, product_id, workspace_id, revision, finding_id, write=True)
            canonical = _canonical_review(db, report['engine_status']['assessment']['report_id'], finding_id)
            canonical_version = canonical['id'] if canonical else 0
            row = db.execute('SELECT * FROM sw_risks WHERE id=?', (identifier,)).fetchone()
            expected_canonical = value.expected_canonical_version
            if expected_canonical is None:
                expected_canonical = json.loads(row['body']).get('canonical_event_id', 0) if row else 0
            if canonical_version != expected_canonical:
                raise StoreConflict('The finding was reviewed in another risk register. Reload before saving.')
            version = row['version'] if row else 0
            if version != value.expected_version:
                raise StoreConflict('This risk changed. Reload before saving your review.')
            current_status = (json.loads(canonical['body']).get('status') if canonical else
                              self._risk_view(row)['effective_status'] if row else 'pending_review')
            if current_status in {'verified_fixed', 'false_positive'} and value.status not in {'pending_review', 'in_review', 'action_required'}:
                raise StoreConflict('Reopen a closed risk before making another decision.')
            body.update({'report_digest': _digest(report), 'reviewer': identity['name'], 'reviewed_at': now, 'security_workflow': True,
                         'canonical_event_id': canonical_version,
                         'verification_status': 'reviewer_attested_not_automatically_tested'})
            body['canonical_event_id'] = _mirror_review(db, report['engine_status']['assessment']['report_id'], finding_id,
                                                       body, identity['name'], now)
            if row:
                db.execute('UPDATE sw_risks SET version=?,body=?,actor=?,updated=? WHERE id=?',
                           (version + 1, _json(body), identity['name'], now, identifier))
            else:
                db.execute('INSERT INTO sw_risks VALUES(?,?,?,?,?,?,?,?,?)',
                           (identifier, product_id, workspace_id, revision, finding_id, 1, _json(body), identity['name'], now))
            self._event(db, product_id, identifier, 'risk_reviewed', {'version': version + 1, **body}, identity['name'])
            return self._risk_view(db.execute('SELECT * FROM sw_risks WHERE id=?', (identifier,)).fetchone())

    def comment_risk(self, product_id, workspace_id, revision, finding_id, payload, identity):
        self._role(identity, product_id=product_id)
        value = RiskComment.model_validate(payload)
        with self.store.connect() as db:
            identifier, _, report, _ = self._risk_ref(db, product_id, workspace_id, revision, finding_id, write=True)
            canonical = _canonical_review(db, report['engine_status']['assessment']['report_id'], finding_id)
            row = self._require_risk(db, product_id, identifier)
            expected_canonical = value.expected_canonical_version
            if expected_canonical is None:
                expected_canonical = json.loads(row['body']).get('canonical_event_id', 0)
            if (canonical['id'] if canonical else 0) != expected_canonical:
                raise StoreConflict('The finding was reviewed in another risk register. Reload before commenting.')
            if row['version'] != value.expected_version:
                raise StoreConflict('This risk changed. Reload before adding a comment.')
            db.execute('UPDATE sw_risks SET version=version+1,updated=? WHERE id=?', (self.clock(), identifier))
            self._event(db, product_id, identifier, 'risk_comment',
                        {'version': row['version'] + 1, 'comment': value.comment}, identity['name'])
            return self._risk_view(db.execute('SELECT * FROM sw_risks WHERE id=?', (identifier,)).fetchone())

    @staticmethod
    def _require_risk(db, product_id, identifier):
        row = db.execute('SELECT * FROM sw_risks WHERE id=? AND product_id=?', (identifier, product_id)).fetchone()
        if not row:
            raise LookupError('Review and assign this finding before linking a ticket or adding comments.')
        return row

    def risks(self, product_id, workspace_id, revision, *, offset=0, limit=50):
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            self._report(db, product_id, workspace_id, revision)
            rows = db.execute('''SELECT * FROM sw_risks WHERE product_id=? AND workspace_id=? AND report_revision=?
                ORDER BY updated DESC,id LIMIT ? OFFSET ?''', (product_id, workspace_id, revision, limit + 1, offset)).fetchall()
            return self._page_result([self._risk_view(r) for r in rows], offset, limit)

    def risk_register(self, product_id, workspace_id, revision, *, offset=0, limit=50):
        """All authoritative findings, including those not yet assigned/reviewed."""
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            _, report = self._report(db, product_id, workspace_id, revision)
            findings = report.get('threats', [])
            report_id = report['engine_status']['assessment']['report_id']
            ids = [finding.get('id') for finding in findings]
            if any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids)):
                raise ValueError('The report has missing or duplicate finding identifiers; regenerate it before review.')
            reviews = {r['finding_id']: self._risk_view(r) for r in db.execute('''SELECT * FROM sw_risks
                WHERE product_id=? AND workspace_id=? AND report_revision=?''', (product_id, workspace_id, revision))}
            result = []
            for finding in findings[offset:offset + limit + 1]:
                identifier = _digest([product_id, workspace_id, revision, finding['id']])
                review = reviews.get(finding['id'], {'id': identifier, 'version': 0, 'effective_status': 'pending_review',
                    'acceptance_expired': False, 'closed': False,
                    'body': {'status': 'pending_review', 'owner': '', 'remarks': '', 'verification': [], 'acceptance_criteria': []}})
                canonical = _canonical_review(db, report_id, finding['id'])
                review['canonical_version'] = canonical['id'] if canonical else 0
                if canonical and canonical['id'] != review['body'].get('canonical_event_id', 0):
                    canonical_body = json.loads(canonical['body'])
                    if canonical_body.get('security_workflow'):
                        canonical_body = effective_workflow_review(canonical_body, now=self.clock())
                    review.update({'canonical_review': canonical_body, 'superseded_by_risk_register': True,
                                   'body': canonical_body, 'effective_status': canonical_body.get('status', 'pending_review'),
                                   'acceptance_expired': canonical_body.get('acceptance_expired', False),
                                   'overdue': canonical_body.get('overdue', False)})
                    review['closed'] = review['effective_status'] in {'verified_fixed', 'false_positive'}
                result.append({'finding': deepcopy(finding), 'review': review})
            response = self._page_result(result, offset, limit)
            response['total'] = len(findings)
            response['report_id'] = report.get('engine_status', {}).get('assessment', {}).get('report_id')
            return response

    @staticmethod
    def _page(offset, limit):
        if not isinstance(offset, int) or not isinstance(limit, int) or not 0 <= offset <= 1_000_000 or not 1 <= limit <= 100:
            raise ValueError('Use an offset from 0 to 1000000 and a limit from 1 to 100.')

    @staticmethod
    def _page_result(rows, offset, limit):
        return {'items': rows[:limit], 'next_offset': offset + limit if len(rows) > limit else None}

    def events(self, product_id, target, *, offset=0, limit=50):
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            self._product(db, product_id)
            rows = db.execute('''SELECT * FROM sw_events WHERE product_id=? AND target=?
                ORDER BY id DESC LIMIT ? OFFSET ?''', (product_id, target, limit + 1, offset)).fetchall()
            return self._page_result([{**dict(r), 'body': json.loads(r['body'])} for r in rows], offset, limit)

    def link_ticket(self, product_id, workspace_id, revision, finding_id, payload, identity, connections):
        self._role(identity, product_id=product_id)
        value = TicketLink.model_validate(payload)
        config = connections.get(value.connection, product_id)
        config.check_key(value.issue_key)
        with self.store.connect() as db:
            risk_id, _, _, _ = self._risk_ref(db, product_id, workspace_id, revision, finding_id, write=True)
            self._require_risk(db, product_id, risk_id)
            row = db.execute('SELECT * FROM sw_ticket_links WHERE risk_id=? AND connection=?', (risk_id, value.connection)).fetchone()
            if row:
                if row['issue_key'] != value.issue_key or row['config_digest'] != config.digest:
                    raise StoreConflict('This risk already has a different ticket or connector binding.')
                return self._link_view(row)
            identifier = str(uuid.uuid4())
            body = {'verified_link': False, 'remote_status': None, 'last_synced_at': None,
                    'remote_done_is_not_verified_fixed': True}
            db.execute('INSERT INTO sw_ticket_links VALUES(?,?,?,?,?,?,?,?,?)', (identifier, product_id, risk_id,
                value.connection, config.digest, value.issue_key, _json(body), identity['name'], self.clock()))
            self._event(db, product_id, risk_id, 'ticket_linked', {'link_id': identifier, **value.model_dump()}, identity['name'])
            self._enqueue(db, product_id, identifier, 'pull', 'link:' + identifier, {}, identity['name'])
            return self._link_view(db.execute('SELECT * FROM sw_ticket_links WHERE id=?', (identifier,)).fetchone())

    @staticmethod
    def _link_view(row):
        return {k: (json.loads(row[k]) if k == 'body' else row[k]) for k in row.keys() if k != 'config_digest'}

    def ticket_links(self, product_id, workspace_id, revision, finding_id):
        with self.store.read_snapshot() as db:
            risk_id, _, _, _ = self._risk_ref(db, product_id, workspace_id, revision, finding_id)
            return [self._link_view(r) for r in db.execute('SELECT * FROM sw_ticket_links WHERE risk_id=? ORDER BY created,id', (risk_id,))]

    def _enqueue(self, db, product_id, link_id, operation, key, payload, actor):
        old = db.execute('SELECT * FROM sw_outbox WHERE product_id=? AND idempotency_key=?', (product_id, key)).fetchone()
        if old:
            if old['link_id'] != link_id or old['operation'] != operation or old['payload'] != _json(payload):
                raise StoreConflict('An idempotency key cannot be reused for a different operation or risk version.')
            return self._job_view(old)
        pending = db.execute("SELECT COUNT(*) FROM sw_outbox WHERE product_id=? AND state IN ('queued','retry_wait','processing')", (product_id,)).fetchone()[0]
        if pending >= 1000:
            raise StoreConflict('The product ticket queue is full. Drain existing requests before adding more.')
        identifier, now = str(uuid.uuid4()), self.clock()
        db.execute('''INSERT INTO sw_outbox(id,product_id,link_id,operation,idempotency_key,payload,state,attempts,
            due,actor,created,updated) VALUES(?,?,?,?,?,?,'queued',0,?,?,?,?)''',
                   (identifier, product_id, link_id, operation, key, _json(payload), now, actor, now, now))
        self._event(db, product_id, link_id, 'ticket_sync_queued', {'job_id': identifier, 'operation': operation}, actor)
        return self._job_view(db.execute('SELECT * FROM sw_outbox WHERE id=?', (identifier,)).fetchone())

    def enqueue_ticket(self, product_id, link_id, payload, identity, connections):
        self._role(identity, product_id=product_id)
        value = TicketSync.model_validate(payload)
        with self.store.connect() as db:
            self._product(db, product_id, True)
            link = self._link(db, product_id, link_id)
            config = connections.get(link['connection'], product_id)
            if config.digest != link['config_digest']:
                raise StoreConflict('Ticket connection scope changed; administrator reconciliation is required.')
            risk = self._require_risk(db, product_id, link['risk_id'])
            _, _, report, finding = self._risk_ref(db, product_id, risk['workspace_id'], risk['report_revision'], risk['finding_id'], write=True)
            if value.operation == 'push' and not json.loads(link['body'])['verified_link']:
                raise StoreConflict('Read and verify the ticket before exporting risk details.')
            canonical = _canonical_review(db, report['engine_status']['assessment']['report_id'], risk['finding_id'])
            if value.operation == 'push' and (canonical['id'] if canonical else 0) != json.loads(risk['body']).get('canonical_event_id', 0):
                raise StoreConflict('A newer risk register decision exists. Reconcile the workflow review before exporting.')
            body = {}
            if value.operation == 'push':
                review = self._risk_view(risk)
                body = {'risk_version': risk['version'], 'property': {
                    'schema_version': 1, 'risk_id': risk['id'], 'product_id': product_id,
                    'workspace_id': risk['workspace_id'], 'report_revision': risk['report_revision'],
                    'finding_id': risk['finding_id'], 'title': str(finding.get('title', ''))[:500],
                    'severity': str(finding.get('severity') or '')[:40], 'review_status': review['effective_status'],
                    'owner': review['body']['owner'], 'remarks': review['body']['remarks'],
                    'acceptance_expires_at': review['body'].get('acceptance_expires_at'),
                    'verification_status': review['body']['verification_status']}}
                if len(_json(body['property']).encode()) > 24_000:
                    raise ValueError('Ticket summary exceeds the 24 KB export limit.')
            return self._enqueue(db, product_id, link_id, value.operation, value.idempotency_key, body, identity['name'])

    @staticmethod
    def _link(db, product_id, link_id):
        row = db.execute('SELECT * FROM sw_ticket_links WHERE id=? AND product_id=?', (link_id, product_id)).fetchone()
        if not row:
            raise LookupError('Ticket link not found in this product.')
        return row

    @staticmethod
    def _job_view(row):
        return {key: row[key] for key in ('id', 'product_id', 'link_id', 'operation', 'state', 'attempts',
                                          'due', 'error', 'actor', 'created', 'updated')}

    def outbox(self, product_id, *, offset=0, limit=50):
        self._page(offset, limit)
        with self.store.read_snapshot() as db:
            self._product(db, product_id)
            rows = db.execute('SELECT * FROM sw_outbox WHERE product_id=? ORDER BY created DESC,id LIMIT ? OFFSET ?',
                              (product_id, limit + 1, offset)).fetchall()
            return self._page_result([self._job_view(r) for r in rows], offset, limit)

    def _claim(self, product_id, actor):
        now = self.clock()
        with self.store.connect() as db:
            self._product(db, product_id, True)
            # A crashed worker may have completed the remote PUT. Repeating the
            # same issue-property replacement is safe; appending comments is not.
            expired = db.execute("""UPDATE sw_outbox SET state=CASE WHEN attempts>=? THEN 'failed' ELSE 'retry_wait' END,
                lease_token=NULL,lease_until=NULL,error='Worker lease expired',updated=?
                WHERE product_id=? AND state='processing' AND lease_until<=?
                RETURNING id,link_id,state,attempts""", (MAX_ATTEMPTS, now, product_id, now)).fetchall()
            for recovered in expired:
                self._event(db, product_id, recovered['link_id'], 'ticket_sync_lease_expired',
                            {'job_id': recovered['id'], 'state': recovered['state'], 'attempts': recovered['attempts']}, actor)
            row = db.execute('''SELECT j.* FROM sw_outbox j WHERE j.product_id=?
                AND j.state IN ('queued','retry_wait') AND j.due<=? AND j.attempts<?
                AND NOT EXISTS (SELECT 1 FROM sw_outbox active WHERE active.link_id=j.link_id AND active.state='processing')
                ORDER BY j.created,j.id LIMIT 1''', (product_id, now, MAX_ATTEMPTS)).fetchone()
            if not row:
                return None
            token = str(uuid.uuid4())
            db.execute("UPDATE sw_outbox SET state='processing',attempts=attempts+1,lease_token=?,lease_until=?,updated=? WHERE id=?",
                       (token, now + LEASE_SECONDS, now, row['id']))
            self._event(db, product_id, row['link_id'], 'ticket_sync_claimed', {'job_id': row['id'], 'attempt': row['attempts'] + 1}, actor)
            return {**dict(row), 'attempts': row['attempts'] + 1, 'lease_token': token,
                    'payload': json.loads(row['payload'])}

    def dispatch(self, product_id, identity, connections, *, limit=5, adapter_factory=None):
        """Explicit worker entrypoint. Call only after administrator opt-in.

        adapter_factory is a dependency-injection hook for hermetic tests; callers
        cannot provide it over HTTP. Network IO occurs outside the SQLite lock.
        """
        self._role(identity, admin=True, product_id=product_id)
        if not 1 <= limit <= 10:
            raise ValueError('Dispatch between 1 and 10 jobs at a time.')
        results = []
        for _ in range(limit):
            job = self._claim(product_id, identity['name'])
            if not job:
                break
            result, failure, state = None, None, 'succeeded'
            try:
                with self.store.read_snapshot() as db:
                    link = dict(self._link(db, product_id, job['link_id']))
                    risk = self._require_risk(db, product_id, link['risk_id'])
                    _, _, report, _ = self._risk_ref(db, product_id, risk['workspace_id'], risk['report_revision'], risk['finding_id'], write=True)
                    view = self._risk_view(risk)
                    canonical = _canonical_review(db, report['engine_status']['assessment']['report_id'], risk['finding_id'])
                    canonical_changed = (canonical['id'] if canonical else 0) != view['body'].get('canonical_event_id', 0)
                config = connections.get(link['connection'], product_id)
                if config.digest != link['config_digest']:
                    raise JiraFailure('Ticket connection scope changed; reconcile the link before syncing.', retryable=False)
                if job['operation'] == 'push' and (job['payload']['risk_version'] != risk['version']
                        or job['payload']['property']['review_status'] != view['effective_status'] or canonical_changed):
                    state = 'superseded'
                else:
                    adapter = (adapter_factory or JiraAdapter)(config)
                    result = adapter.read_issue(link['issue_key'])
                    config.check_key(result['key'])
                    if result['key'] != link['issue_key'] or result['project_key'] != config.project_key:
                        raise JiraFailure('Ticket identity or project no longer matches the approved link.', retryable=False)
                    if job['operation'] == 'push':
                        adapter.update_property(link['issue_key'], job['payload']['property'])
            except JiraFailure as exc:
                failure = exc
            except (LookupError, ValueError, PermissionError):
                failure = JiraFailure('Ticket configuration or assessment scope is no longer valid.', retryable=False)
            except Exception:
                # Never persist raw upstream exceptions, URLs, tokens or bodies.
                failure = JiraFailure('Ticket service unavailable.', retryable=True)
            with self.store.connect() as db:
                current = db.execute('SELECT * FROM sw_outbox WHERE id=?', (job['id'],)).fetchone()
                if current['state'] != 'processing' or current['lease_token'] != job['lease_token']:
                    results.append({'id': job['id'], 'state': 'lease_lost'})
                    continue
                now = self.clock()
                if failure:
                    state = 'retry_wait' if failure.retryable and job['attempts'] < MAX_ATTEMPTS else 'failed'
                due = now + max(min(3600, 30 * 2 ** (job['attempts'] - 1)), failure.retry_after or 0) if failure else now
                db.execute('''UPDATE sw_outbox SET state=?,due=?,lease_token=NULL,lease_until=NULL,error=?,updated=? WHERE id=?''',
                           (state, due, str(failure) if failure else None, now, job['id']))
                if not failure and result and state == 'succeeded':
                    body = json.loads(self._link(db, product_id, job['link_id'])['body'])
                    body.update({'verified_link': True, 'remote_status': result['status'], 'remote_updated': result.get('updated'),
                                 'last_synced_at': now, 'remote_done_is_not_verified_fixed': True})
                    db.execute('UPDATE sw_ticket_links SET body=? WHERE id=?', (_json(body), job['link_id']))
                self._event(db, product_id, job['link_id'], 'ticket_sync_' + state,
                            {'job_id': job['id'], 'attempt': job['attempts']}, identity['name'])
                results.append(self._job_view(db.execute('SELECT * FROM sw_outbox WHERE id=?', (job['id'],)).fetchone()))
        return results


class JiraFailure(Exception):
    def __init__(self, message, *, retryable=False, retry_after=None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = min(3600, max(0, retry_after or 0))


class JiraConnection(Input):
    base_url: str = Field(max_length=300)
    project_key: str = Field(pattern=r'^[A-Z][A-Z0-9_]{1,30}$')
    product_ids: list[Identifier] = Field(min_length=1, max_length=500)
    username_env: str = Field(pattern=r'^[A-Z][A-Z0-9_]{1,100}$')
    token_env: str = Field(pattern=r'^[A-Z][A-Z0-9_]{1,100}$')

    @field_validator('base_url')
    @classmethod
    def safe_origin(cls, value):
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.port not in {None, 443}
                or url.path not in {'', '/'} or url.query or url.fragment
                or not re.fullmatch(r'[a-zA-Z0-9.-]+', url.hostname)):
            raise ValueError('Jira must use an operator-configured HTTPS origin on port 443, without a path or credentials.')
        return 'https://' + url.hostname.lower()

    @property
    def digest(self):
        return _digest({'origin': self.base_url, 'project_key': self.project_key, 'product_ids': sorted(self.product_ids)})

    def check_key(self, key):
        if not isinstance(key, str) or not re.fullmatch(re.escape(self.project_key) + r'-[1-9][0-9]{0,14}', key):
            raise ValueError('Ticket must belong to the configured Jira project.')


class JiraConnections:
    def __init__(self, values):
        if not isinstance(values, dict) or len(values) > 100:
            raise ValueError('Invalid Jira connection configuration.')
        self._connections = {}
        for name, value in values.items():
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', name):
                raise ValueError('Invalid Jira connection name.')
            self._connections[name] = JiraConnection.model_validate(value)

    @classmethod
    def from_environment(cls):
        try:
            raw = os.getenv('AEGIS_JIRA_CONNECTIONS', '{}')
            if len(raw) > 100_000:
                raise ValueError('Configuration is too large.')
            return cls(json.loads(raw))
        except (ValueError, TypeError):
            raise ValueError('Jira connection configuration is invalid.') from None

    def get(self, name, product_id):
        result = self._connections.get(name)
        if result is None or product_id not in result.product_ids:
            raise ValueError('Jira connection is not configured for this product.')
        return result


class JiraAdapter:
    """Bounded Jira Cloud v3 GET and issue-property PUT; no create/close calls."""
    def __init__(self, config):
        self.config = config

    def _request(self, method, path, body=None):
        host = urlsplit(self.config.base_url).hostname
        username, token = os.getenv(self.config.username_env, ''), os.getenv(self.config.token_env, '')
        if not username or not token or ':' in username or any(c in username + token for c in '\r\n'):
            raise JiraFailure('Jira server-side credentials are not configured.')
        if len(username) > 500 or len(token) > 4096:
            raise JiraFailure('Jira credentials exceed supported limits.')
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
            if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
                raise JiraFailure('Jira destination must resolve only to public addresses.')
            headers = {'Host': host, 'Accept': 'application/json', 'Accept-Encoding': 'identity',
                       'Authorization': 'Basic ' + base64.b64encode((username + ':' + token).encode()).decode()}
            serialized = None if body is None else _json(body).encode()
            if serialized is not None:
                if len(serialized) > 24_000:
                    raise JiraFailure('Jira export exceeds the 24 KB limit.')
                headers['Content-Type'] = 'application/json'
            # Pin the validated IP for this request while validating the original
            # TLS hostname. Disable redirects, implicit retries and proxy env vars.
            with urllib3.HTTPSConnectionPool(sorted(addresses)[0], port=443, server_hostname=host,
                    assert_hostname=host, cert_reqs='CERT_REQUIRED', timeout=urllib3.Timeout(total=20, connect=5, read=15)) as pool:
                response = pool.request(method, path, body=serialized, headers=headers,
                                        redirect=False, retries=False, preload_content=False)
                try:
                    if response.status not in {200, 201, 204}:
                        delay = response.headers.get('Retry-After', '')
                        delay = int(delay) if delay.isdigit() else None
                        raise JiraFailure('Jira rejected the request (HTTP %s).' % response.status,
                                          retryable=response.status == 429 or response.status >= 500, retry_after=delay)
                    if response.headers.get('Content-Encoding', 'identity').lower() not in {'', 'identity'}:
                        raise JiraFailure('Compressed Jira responses are not supported.')
                    raw = response.read(256_001, decode_content=False)
                    if len(raw) > 256_000:
                        raise JiraFailure('Jira response exceeds the 256 KB limit.')
                    return json.loads(raw) if raw else {}
                finally:
                    response.close()
        except JiraFailure:
            raise
        except (OSError, urllib3.exceptions.HTTPError):
            raise JiraFailure('Jira connection failed.', retryable=True) from None
        except (ValueError, TypeError):
            raise JiraFailure('Jira returned an invalid response.') from None

    def read_issue(self, issue_key):
        self.config.check_key(issue_key)
        data = self._request('GET', '/rest/api/3/issue/' + issue_key + '?fields=status,project,updated')
        try:
            fields = data['fields']
            result = {'key': data['key'], 'project_key': fields['project']['key'],
                      'status': fields['status']['name'], 'updated': fields.get('updated')}
            if any(not isinstance(result[key], str) or len(result[key]) > 200 for key in ('key', 'project_key', 'status')):
                raise ValueError('Invalid ticket fields')
            if result['updated'] is not None and (not isinstance(result['updated'], str) or len(result['updated']) > 100):
                raise ValueError('Invalid update date')
            return result
        except (KeyError, TypeError, ValueError):
            raise JiraFailure('Jira returned invalid issue metadata.') from None

    def update_property(self, issue_key, value):
        self.config.check_key(issue_key)
        return self._request('PUT', '/rest/api/3/issue/' + issue_key + '/properties/com.aegis.threat-model', value)
