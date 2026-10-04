"""Content-addressed KB releases with explicit review, regression and activation gates.

The caller supplies authenticated identities and enforces administrator access.
SQLite is an atomic local release ledger, not a tamper-proof enterprise audit sink.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .evaluation import evaluate_contracts
from .frameworks import registry
from .governance import audit_contracts
from .loader import ThreatKnowledgeBase


SCHEMA_VERSION = 'aegis-kb-release-1'
WAIVABLE_GAPS = frozenset({
    'missing_primary_reference', 'missing_verification', 'missing_counterexamples',
    'missing_executable_test_contract', 'unversioned_source', 'independent_review_not_recorded',
    'category_fallback_mapping', 'unsupported_predicate', 'removed_rule',
})


class ReleaseConflict(ValueError):
    """The release pointer or reviewed assessment changed since the caller read it."""


class ReleaseGateError(ValueError):
    def __init__(self, blockers):
        self.blockers = blockers
        super().__init__('Knowledge release gates failed: ' + ', '.join(sorted({b['code'] for b in blockers})))


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def content_digest(value):
    return hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{field} must be a non-empty string.')
    return value.strip()


def _date(value):
    parsed = datetime.fromisoformat(_text(value, 'date').replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Review and expiry timestamps must include a timezone.')
    return parsed.astimezone(timezone.utc)


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
        raise ValueError('Expected a SHA-256 content digest.')
    return value


def release_changes(before, after):
    old = {rule['id']: rule for rule in before or []}
    new = {rule['id']: rule for rule in after or []}
    return {'added': sorted(new.keys() - old.keys()), 'removed': sorted(old.keys() - new.keys()),
        'modified': sorted(key for key in old.keys() & new.keys() if content_digest(old[key]) != content_digest(new[key])),
        'unchanged': sorted(key for key in old.keys() & new.keys() if content_digest(old[key]) == content_digest(new[key]))}


class KnowledgeReleaseStore:
    """Immutable artifacts and approvals; only the active pointer can be updated."""

    def __init__(self, database):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS kb_artifacts (
                    digest TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    created_by TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_approvals (
                    id INTEGER PRIMARY KEY, digest TEXT NOT NULL REFERENCES kb_artifacts(digest),
                    reviewer TEXT NOT NULL, reviewed_at TEXT NOT NULL, valid_until TEXT NOT NULL,
                    assessment_digest TEXT NOT NULL, waivers TEXT NOT NULL, reason TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_revocations (
                    approval_id INTEGER PRIMARY KEY REFERENCES kb_approvals(id),
                    actor TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_release_events (
                    id INTEGER PRIMARY KEY, action TEXT NOT NULL, actor TEXT NOT NULL,
                    before_digest TEXT, after_digest TEXT NOT NULL,
                    approval_id INTEGER REFERENCES kb_approvals(id), revision INTEGER NOT NULL,
                    reason TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_active (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1), digest TEXT,
                    revision INTEGER NOT NULL);
                INSERT OR IGNORE INTO kb_active VALUES (1, NULL, 0);
            ''')
            for table in ('kb_artifacts', 'kb_approvals', 'kb_revocations', 'kb_release_events'):
                for operation in ('UPDATE', 'DELETE'):
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                        BEFORE {operation} ON {table} BEGIN
                        SELECT RAISE(ABORT, 'Knowledge release records are immutable'); END''')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def stage(self, knowledge_base, *, actor):
        """Freeze the loaded catalog and its diagnostics; this never activates it."""
        actor = _text(actor, 'actor')
        rules = sorted(deepcopy(knowledge_base.get_all_threats()), key=lambda rule: rule['id'])
        ThreatKnowledgeBase.from_canonical_rules(rules)
        payload = {'schema_version': SCHEMA_VERSION, 'rules': rules,
            'framework_registry': deepcopy(registry()),
            'validation_issues': deepcopy(knowledge_base.validation_issues),
            'quarantined_rules': deepcopy(knowledge_base.quarantined_rules)}
        digest = content_digest(payload)
        with self._db() as db:
            db.execute('INSERT OR IGNORE INTO kb_artifacts VALUES (?, ?, ?, ?)',
                (digest, canonical_json(payload), actor, _now()))
        return self.artifact(digest)

    @staticmethod
    def _artifact(db, digest):
        row = db.execute('SELECT * FROM kb_artifacts WHERE digest = ?', (_digest(digest),)).fetchone()
        if row is None:
            raise KeyError('Knowledge release not found.')
        record = dict(row)
        record['payload'] = json.loads(record['payload'])
        if content_digest(record['payload']) != digest or record['payload'].get('schema_version') != SCHEMA_VERSION:
            raise ValueError('Knowledge release integrity check failed.')
        return record

    def artifact(self, digest):
        with self._db() as db:
            return self._artifact(db, digest)

    def active(self):
        with self._db() as db:
            pointer = dict(db.execute('SELECT digest, revision FROM kb_active WHERE singleton = 1').fetchone())
            if pointer['digest']:
                pointer['artifact'] = self._artifact(db, pointer['digest'])
            return pointer

    def load_active(self):
        # Read pointer, artifact and approval from one snapshot. Expired/revoked
        # reviews block the next process load; no unapproved bundled fallback.
        with self._db() as db:
            db.execute('BEGIN')
            active = dict(db.execute('SELECT digest, revision FROM kb_active WHERE singleton = 1').fetchone())
            if not active['digest']:
                raise KeyError('No knowledge release has been published.')
            artifact = self._artifact(db, active['digest'])
            event = db.execute('SELECT * FROM kb_release_events WHERE revision = ? AND after_digest = ?',
                (active['revision'], active['digest'])).fetchone()
            approval = db.execute('SELECT * FROM kb_approvals WHERE id = ?',
                (event['approval_id'],)).fetchone() if event else None
            if (approval is None or approval['digest'] != active['digest'] or
                    db.execute('SELECT 1 FROM kb_revocations WHERE approval_id = ?', (approval['id'],)).fetchone()):
                raise ReleaseGateError([{'code': 'active_approval_missing_or_revoked'}])
            if _date(approval['valid_until']) <= datetime.now(timezone.utc):
                raise ReleaseGateError([{'code': 'active_approval_expired'}])
            waivers = json.loads(approval['waivers'])['items']
            if any(_date(item['expires_at']) <= datetime.now(timezone.utc) for item in waivers):
                raise ReleaseGateError([{'code': 'active_exception_expired'}])
        kb = ThreatKnowledgeBase.from_canonical_rules(artifact['payload']['rules'])
        kb.release_provenance = {'mode': 'published_release', 'content_digest': active['digest'],
            'activation_revision': active['revision'], 'approval_id': approval['id'],
            'reviewer': approval['reviewer'], 'review_valid_until': approval['valid_until'],
            'waived_gaps': waivers, 'loaded_at': _now(), 'published_at': event['created_at'],
            'schema_version': SCHEMA_VERSION, 'independent_accuracy_established': False}
        return kb

    def history(self, limit=None):
        with self._db() as db:
            if limit is None:
                return [dict(row) for row in db.execute('SELECT * FROM kb_release_events ORDER BY id DESC')]
            if type(limit) is not int or not 1 <= limit <= 100:
                raise ValueError('History limit must be between 1 and 100.')
            return [dict(row) for row in db.execute('SELECT * FROM kb_release_events ORDER BY id DESC LIMIT ?', (limit,))]

    def assess(self, digest, *, baseline_digest=None):
        artifact = self.artifact(digest)
        payload = artifact['payload']
        kb = ThreatKnowledgeBase.from_canonical_rules(payload['rules'])
        audit = audit_contracts(kb.threats)
        contracts = evaluate_contracts(kb)
        before = self.artifact(baseline_digest)['payload']['rules'] if baseline_digest else []
        changes = release_changes(before, kb.threats)
        blockers = [{'rule_id': issue['rule_id'], 'code': gap, 'waivable': gap in WAIVABLE_GAPS}
            for issue in audit['issues'] for gap in issue['gaps']]
        blockers.extend({'rule_id': identifier, 'code': 'removed_rule', 'waivable': True} for identifier in changes['removed'])
        if not kb.threats:
            blockers.append({'rule_id': None, 'code': 'empty_catalog', 'waivable': False})
        if payload['validation_issues']:
            blockers.append({'rule_id': None, 'code': 'loader_validation_issues', 'waivable': False})
        if payload['quarantined_rules']:
            blockers.append({'rule_id': None, 'code': 'quarantined_rules_in_source', 'waivable': False})
        if contracts['failures']:
            blockers.append({'rule_id': None, 'code': 'regression_failed', 'waivable': False})
        # Timing is diagnostic, not review identity. Runtime results and skipped
        # rule IDs are included so a changed engine cannot reuse stale approval.
        stable_contracts = {key: value for key, value in contracts.items() if key != 'elapsed_ms'}
        assessment_digest = content_digest({'release': digest, 'baseline': baseline_digest,
            'audit': audit, 'contracts': stable_contracts, 'changes': changes, 'blockers': blockers})
        return {'content_digest': digest, 'baseline_digest': baseline_digest, 'assessment_digest': assessment_digest,
            'governance': audit, 'contracts': contracts, 'changes': changes, 'blockers': blockers,
            'publishable_without_exceptions': not blockers, 'independent_accuracy_established': False}

    @staticmethod
    def _check_waivers(assessment, waivers):
        if not isinstance(waivers, list):
            raise ValueError('Waivers must be a list.')
        blockers = {(item['rule_id'], item['code']): item for item in assessment['blockers']}
        waived = set()
        for waiver in waivers:
            if not isinstance(waiver, dict):
                raise ValueError('Each waiver must be an object.')
            key = (waiver.get('rule_id'), waiver.get('code'))
            if key in waived or key not in blockers or not blockers[key]['waivable']:
                raise ValueError('Waivers must match unique, waivable findings in this release assessment.')
            _text(waiver.get('reason'), 'waiver reason')
            _text(waiver.get('tracking_reference'), 'waiver tracking reference')
            if _date(waiver.get('expires_at')) <= datetime.now(timezone.utc):
                raise ValueError('Waiver has expired.')
            waived.add(key)
        remaining = [item for key, item in blockers.items() if key not in waived]
        if remaining:
            raise ReleaseGateError(remaining)

    def approve(self, digest, *, reviewer, reason, expected_assessment_digest, valid_until,
                waivers=None, baseline_digest=None):
        """Record a review attestation, not inferred approval or measured accuracy."""
        reviewer = _text(reviewer, 'reviewer')
        reason = _text(reason, 'reason')
        if _date(valid_until) <= datetime.now(timezone.utc):
            raise ValueError('Approval must expire in the future.')
        artifact = self.artifact(digest)
        if reviewer.casefold() == artifact['created_by'].casefold():
            raise ValueError('The release author cannot approve their own release.')
        assessment = self.assess(digest, baseline_digest=baseline_digest)
        if assessment['assessment_digest'] != expected_assessment_digest:
            raise ReleaseConflict('Assessment changed; review the current regression and audit report.')
        waivers = deepcopy(waivers or [])
        self._check_waivers(assessment, waivers)
        # Baseline is bound into the record because removing rules needs separate
        # review even when the candidate artifact itself has not changed.
        envelope = {'baseline_digest': baseline_digest, 'items': waivers}
        with self._db() as db:
            cursor = db.execute('''INSERT INTO kb_approvals
                (digest, reviewer, reviewed_at, valid_until, assessment_digest, waivers, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)''', (digest, reviewer, _now(), valid_until,
                    assessment['assessment_digest'], canonical_json(envelope), reason))
            return {'approval_id': cursor.lastrowid, 'content_digest': digest,
                'assessment_digest': assessment['assessment_digest'], 'reviewer': reviewer,
                'waived_gaps': waivers, 'independent_accuracy_established': False}

    def revoke_approval(self, approval_id, *, actor, reason):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM kb_approvals WHERE id = ?', (approval_id,)).fetchone():
                raise KeyError('Knowledge release approval not found.')
            if db.execute('SELECT 1 FROM kb_revocations WHERE approval_id = ?', (approval_id,)).fetchone():
                raise ReleaseConflict('This approval was already revoked.')
            db.execute('INSERT INTO kb_revocations VALUES (?, ?, ?, ?)',
                (approval_id, _text(actor, 'actor'), _text(reason, 'reason'), _now()))

    def publish(self, digest, *, approval_id, actor, reason, expected_revision):
        return self._activate('publish', digest, approval_id, actor, reason, expected_revision)

    def rollback(self, digest, *, approval_id, actor, reason, expected_revision):
        """Re-select a previously published snapshot; never modify/delete history."""
        return self._activate('rollback', digest, approval_id, actor, reason, expected_revision)

    def _activate(self, action, digest, approval_id, actor, reason, expected_revision):
        actor, reason = _text(actor, 'actor'), _text(reason, 'reason')
        active = self.active()
        if isinstance(expected_revision, bool) or expected_revision != active['revision']:
            raise ReleaseConflict('Active release changed; refresh before publishing.')
        assessment = self.assess(digest, baseline_digest=active['digest'])
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            pointer = db.execute('SELECT * FROM kb_active WHERE singleton = 1').fetchone()
            if pointer['revision'] != expected_revision:
                raise ReleaseConflict('Another publisher changed the active release.')
            artifact = self._artifact(db, digest)
            row = db.execute('SELECT * FROM kb_approvals WHERE id = ? AND digest = ?', (approval_id, digest)).fetchone()
            if row is None or db.execute('SELECT 1 FROM kb_revocations WHERE approval_id = ?', (approval_id,)).fetchone():
                raise ReleaseGateError([{'code': 'approval_missing_or_revoked'}])
            approval = dict(row)
            if _date(approval['valid_until']) <= datetime.now(timezone.utc):
                raise ReleaseGateError([{'code': 'approval_expired'}])
            if approval['reviewer'].casefold() == artifact['created_by'].casefold():
                raise ReleaseGateError([{'code': 'reviewer_not_independent_of_author'}])
            envelope = json.loads(approval['waivers'])
            if (envelope['baseline_digest'] != pointer['digest'] or
                    approval['assessment_digest'] != assessment['assessment_digest']):
                raise ReleaseConflict('The reviewed baseline or regression results changed; a new approval is required.')
            self._check_waivers(assessment, envelope['items'])
            if action == 'rollback' and not db.execute(
                    'SELECT 1 FROM kb_release_events WHERE after_digest = ?', (digest,)).fetchone():
                raise ValueError('Rollback target must have been published previously.')
            if action == 'rollback' and pointer['digest'] == digest:
                raise ReleaseConflict('This knowledge release is already active.')
            revision = pointer['revision'] + 1
            db.execute('UPDATE kb_active SET digest = ?, revision = ? WHERE singleton = 1', (digest, revision))
            db.execute('''INSERT INTO kb_release_events
                (action, actor, before_digest, after_digest, approval_id, revision, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (action, actor, pointer['digest'], digest, approval_id, revision, reason, _now()))
        return {'content_digest': digest, 'previous_digest': active['digest'], 'revision': revision,
            'action': action, 'changes': assessment['changes'], 'reassessment_required': True,
            'restart_required': True, 'runtime_applied': False,
            'waived_gaps': envelope['items'], 'independent_accuracy_established': False}

    def reassessment_plan(self, before_digest, after_digest, reports):
        """Flag impacted saved reports conservatively without rerunning or mutating them."""
        before = self.artifact(before_digest)['payload']['rules'] if before_digest else []
        after = self.artifact(after_digest)['payload']['rules']
        changes = release_changes(before, after)
        changed = set(changes['modified'] + changes['removed'])
        decisions = []
        for report in reports:
            provenance = report.get('knowledge_provenance') or {}
            evaluated = provenance.get('evaluated_rule_ids')
            matching = sorted(changed & set(evaluated or []))
            incomplete = not isinstance(evaluated, list) or provenance.get('content_digest') != before_digest
            already_current = provenance.get('content_digest') == after_digest
            # Additions may find a previously unreported risk in any model.
            required = not already_current and bool(changes['added'] or matching or incomplete)
            decisions.append({'report_id': report.get('id'), 'reassessment_required': required,
                'affected_rule_ids': [] if already_current else matching,
                'reason': 'already_on_target_release' if already_current else 'unknown_previous_coverage' if incomplete else
                'new_rules' if changes['added'] else 'changed_evaluated_rules' if matching else 'no_rule_change_in_evaluated_scope'})
        return {'before_digest': before_digest, 'after_digest': after_digest, 'changes': changes,
            'reports': decisions, 'automatic_rerun': False}
