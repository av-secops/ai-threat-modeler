"""Transactional local product registry and immutable report snapshots."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import time
import unicodedata
import uuid


_RELEASE_SUMMARY = '''
    SELECT r.*, COUNT(w.id) AS model_count,
        SUM(CASE WHEN w.id IS NOT NULL AND w.application_id IS NULL THEN 1 ELSE 0 END) AS release_models,
        SUM(CASE WHEN w.application_id IS NOT NULL THEN 1 ELSE 0 END) AS application_models,
        SUM(CASE WHEN COALESCE(json_array_length(w.payload,'$.revisions'),0)>0 THEN 1 ELSE 0 END) AS reported_models,
        SUM(CASE WHEN w.id IS NOT NULL AND COALESCE(json_array_length(w.payload,'$.revisions'),0)=0 THEN 1 ELSE 0 END) AS draft_models,
        MAX(json_extract(w.payload,'$.revisions[#-1].createdAt')) AS last_modeled_at
    FROM releases r LEFT JOIN workspaces w ON w.release_id=r.id
'''


class StoreConflict(ValueError):
    pass


def normalize_name(value):
    name = ' '.join(unicodedata.normalize('NFKC', str(value)).split())
    if not name or len(name) > 200:
        raise ValueError('A name between 1 and 200 characters is required.')
    return name, name.casefold()


class ProductStore:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY,name TEXT NOT NULL,name_key TEXT NOT NULL UNIQUE,archived INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,product_id TEXT NOT NULL REFERENCES products(id),name TEXT NOT NULL,name_key TEXT NOT NULL,UNIQUE(product_id,name_key));
                CREATE TABLE IF NOT EXISTS releases(id TEXT PRIMARY KEY,product_id TEXT NOT NULL REFERENCES products(id),name TEXT NOT NULL,name_key TEXT NOT NULL,archived INTEGER NOT NULL DEFAULT 0,UNIQUE(product_id,name_key));
                CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,release_id TEXT NOT NULL REFERENCES releases(id),application_id TEXT REFERENCES applications(id),environment TEXT NOT NULL,version INTEGER NOT NULL,payload TEXT NOT NULL,updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at REAL NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,actor TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,result TEXT,error TEXT,updated REAL NOT NULL,owner TEXT);
                CREATE INDEX IF NOT EXISTS workspaces_by_release ON workspaces(release_id,updated);
                CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs(state,updated);
                CREATE TABLE IF NOT EXISTS comparisons(id TEXT PRIMARY KEY,product_id TEXT NOT NULL REFERENCES products(id),
                    name TEXT NOT NULL,request TEXT NOT NULL,payload TEXT NOT NULL,review TEXT NOT NULL,
                    version INTEGER NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS comparisons_by_product ON comparisons(product_id,created);
                CREATE TABLE IF NOT EXISTS dashboard_observations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id TEXT NOT NULL REFERENCES products(id),
                    fingerprint TEXT NOT NULL, policy TEXT NOT NULL, body TEXT NOT NULL,
                    observed REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS dashboard_history ON dashboard_observations(product_id,id);
                CREATE TABLE IF NOT EXISTS assessment_lineage(
                    target_id TEXT PRIMARY KEY REFERENCES workspaces(id),
                    source_id TEXT NOT NULL REFERENCES workspaces(id), created REAL NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            columns = {row['name'] for row in db.execute('PRAGMA table_info(releases)')}
            if 'created_at' not in columns:
                db.execute('ALTER TABLE releases ADD COLUMN created_at REAL')
            # Recover historical dates from the audit trail, never from a report edit.
            db.execute('''UPDATE releases SET created_at=(
                SELECT MIN(at) FROM audit WHERE target=releases.id
                AND action IN ('create_releases','clone_release')
            ) WHERE created_at IS NULL''')

    @contextmanager
    def read_snapshot(self):
        """Read without taking the writer reservation used by mutation transactions."""
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            yield db
        finally:
            db.rollback()
            db.close()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA journal_mode=WAL')
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise StoreConflict('That name is reserved or the referenced record does not exist.') from exc
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def audit(db, actor, action, target):
        db.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)', (time.time(), actor, action, target))

    @staticmethod
    def require(db, table, identifier):
        if table not in {'products', 'applications', 'releases', 'workspaces', 'jobs', 'comparisons'}:
            raise ValueError('Invalid record type')
        row = db.execute(f'SELECT * FROM {table} WHERE id=?', (identifier,)).fetchone()
        if not row:
            raise LookupError('Record not found')
        return dict(row)

    def list_products(self):
        with self.read_snapshot() as db:
            return [dict(r) for r in db.execute('''SELECT p.*,
                COUNT(DISTINCT r.id) AS release_count,
                COUNT(DISTINCT CASE WHEN COALESCE(json_array_length(w.payload,'$.revisions'),0)>0 THEN w.application_id END) AS assessed_applications,
                MAX(json_extract(w.payload,'$.revisions[#-1].createdAt')) AS last_modeled_at
                FROM products p LEFT JOIN releases r ON r.product_id=p.id
                LEFT JOIN workspaces w ON w.release_id=r.id
                GROUP BY p.id ORDER BY p.name_key''')]

    def product(self, identifier):
        with self.read_snapshot() as db:
            product = self.require(db, 'products', identifier)
            product['releases'] = [dict(r) for r in db.execute(
                _RELEASE_SUMMARY + ' WHERE r.product_id=? GROUP BY r.id ORDER BY r.name_key DESC', (identifier,))]
            product['applications'] = [dict(r) for r in db.execute('SELECT * FROM applications WHERE product_id=? ORDER BY name_key', (identifier,))]
            return product

    def create(self, kind, name, actor, product_id=None):
        if kind not in {'products', 'applications', 'releases'}:
            raise ValueError('Invalid record type')
        name, key = normalize_name(name)
        identifier = str(uuid.uuid4())
        with self.connect() as db:
            if kind == 'products':
                db.execute('INSERT INTO products(id,name,name_key) VALUES(?,?,?)', (identifier, name, key))
            else:
                product = self.require(db, 'products', product_id)
                if product['archived']:
                    raise StoreConflict('Restore the product before adding items.')
                db.execute(f'INSERT INTO {kind}(id,product_id,name,name_key) VALUES(?,?,?,?)', (identifier, product_id, name, key))
                if kind == 'releases':
                    db.execute('UPDATE releases SET created_at=? WHERE id=?', (time.time(), identifier))
            self.audit(db, actor, f'create_{kind}', identifier)
            return self.require(db, kind, identifier)

    def update_product(self, identifier, name, archived, actor):
        name, key = normalize_name(name)
        with self.connect() as db:
            self.require(db, 'products', identifier)
            db.execute('UPDATE products SET name=?,name_key=?,archived=? WHERE id=?', (name, key, int(archived), identifier))
            self.audit(db, actor, 'update_product', identifier)
            return self.require(db, 'products', identifier)

    def release(self, identifier):
        with self.read_snapshot() as db:
            release = self.require(db, 'releases', identifier)
            release['workspaces'] = [dict(r) for r in db.execute('''
                SELECT w.id,w.release_id,w.application_id,w.environment,w.version,w.updated,
                    a.name AS application_name,
                    CASE WHEN w.application_id IS NULL THEN 'release' ELSE 'application' END AS model_scope,
                    json_extract(w.payload,'$.projectName') AS name,
                    COALESCE(json_array_length(w.payload,'$.revisions'),0) AS revisions,
                    json_extract(w.payload,'$.revisions[#-1].createdAt') AS last_modeled_at
                FROM workspaces w LEFT JOIN applications a ON a.id=w.application_id
                WHERE w.release_id=? ORDER BY w.updated DESC,w.id
            ''', (identifier,))]
            return release

    def release_application(self, release_id, name, actor):
        """Resolve an ad hoc model's identity only after its release is selected."""
        name, key = normalize_name(name)
        with self.connect() as db:
            release = self.require(db, 'releases', release_id)
            product = self.require(db, 'products', release['product_id'])
            if product['archived'] or release['archived']:
                raise StoreConflict('Restore the product and release before adding models.')
            existing = db.execute('SELECT * FROM applications WHERE product_id=? AND name_key=?',
                (product['id'], key)).fetchone()
            if existing:
                return dict(existing)
            identifier = str(uuid.uuid4())
            db.execute('INSERT INTO applications(id,product_id,name,name_key) VALUES(?,?,?,?)',
                (identifier, product['id'], name, key))
            self.audit(db, actor, 'create_applications', identifier)
            return self.require(db, 'applications', identifier)

    def workspace(self, identifier):
        with self.read_snapshot() as db:
            return self.unpack(self.require(db, 'workspaces', identifier))

    def comparison_catalog(self, product_id):
        """Read compact revision metadata in one query, without loading report bodies."""
        with self.read_snapshot() as db:
            product = self.require(db, 'products', product_id)
            rows = [dict(row) for row in db.execute('''
                SELECT w.id,w.release_id,w.application_id,w.environment,a.name AS application_name,
                    json_extract(w.payload,'$.projectName') AS name,
                    COALESCE(json_array_length(w.payload,'$.revisions'),0) AS revision_count,
                    COALESCE((SELECT json_group_array(json_object('number',json_extract(j.value,'$.number'),
                        'created_at',json_extract(j.value,'$.createdAt')))
                        FROM json_each(w.payload,'$.revisions') j),'[]') AS revision_options
                FROM workspaces w JOIN releases r ON r.id=w.release_id LEFT JOIN applications a ON a.id=w.application_id
                WHERE r.product_id=? ORDER BY a.name,w.environment,w.id
            ''', (product_id,))]
            for row in rows:
                row['revisions'] = json.loads(row.pop('revision_options'))
            return {'product': product, 'releases': [dict(r) for r in db.execute(
                'SELECT * FROM releases WHERE product_id=? ORDER BY created_at DESC,name_key DESC', (product_id,))], 'models': rows}

    def comparison_snapshots(self, selections):
        """Read both sides under one transaction so annotations cannot change halfway."""
        with self.read_snapshot() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            result = []
            for selection in selections:
                row = self.unpack(self.require(db, 'workspaces', selection['workspace_id']))
                release = self.require(db, 'releases', row['release_id'])
                revision = next((r for r in row['workspace'].get('revisions', []) if r['number'] == selection['revision']), None)
                if revision is None:
                    raise LookupError('Report revision not found')
                revision = deepcopy(revision)
                annotations = deepcopy(row['workspace'].get('reviewAnnotations', {}).get(
                    f"workspace:{row['id']}:revision:{revision['number']}", revision.get('annotations', {})))
                report_id = (revision.get('data', {}).get('engine_status') or {}).get('assessment', {}).get('report_id')
                source = 'legacy_workspace_snapshot'
                if report_id:
                    report = db.execute('SELECT assessment_id,body FROM assessment_results WHERE id=?', (report_id,)).fetchone() if 'assessment_results' in tables else None
                    if not report or report['assessment_id'] != row['id']:
                        raise ValueError('Report is not bound to the selected workspace.')
                    revision['data'] = json.loads(report['body'])
                    source = 'authoritative_assessment_result'
                    if 'finding_review_events' in tables:
                        from .security_workflows import effective_workflow_review
                        fields = {'owners': 'owner', 'notes': 'remarks', 'reviewStates': 'status',
                            'dueDates': 'target_date', 'verification': 'verification_evidence',
                            'acceptanceExpiry': 'acceptance_expires_at'}
                        for event in db.execute('''SELECT e.* FROM finding_review_events e WHERE e.report_id=?
                            AND e.id=(SELECT MAX(last.id) FROM finding_review_events last
                                WHERE last.report_id=e.report_id AND last.finding_id=e.finding_id)''', (report_id,)):
                            decision = json.loads(event['body'])
                            if decision.get('security_workflow'):
                                decision = effective_workflow_review(decision)
                            for field, key in fields.items():
                                annotations.setdefault(field, {})[event['finding_id']] = decision.get(key)
                result.append({'workspace_id': row['id'], 'release_id': row['release_id'], 'product_id': release['product_id'], 'application_id': row['application_id'],
                    'environment': row['environment'], 'name': row['workspace'].get('projectName'), 'revision': revision,
                    'annotations': annotations, 'report_source': source})
            return result

    def save_comparison(self, product_id, name, request, result, actor):
        name, _ = normalize_name(name)
        if len(json.dumps(result).encode()) > 64_000_000:
            raise ValueError('Comparison exceeds the 64 MB storage limit. Compare fewer application scopes.')
        identifier, now = str(uuid.uuid4()), time.time()
        with self.connect() as db:
            self.require(db, 'products', product_id)
            db.execute('INSERT INTO comparisons VALUES(?,?,?,?,?,?,?,?,?,?)',
                (identifier, product_id, name, json.dumps(request), json.dumps(result), '{}', 1, actor, now, now))
            self.audit(db, actor, 'save_comparison', identifier)
        return self.comparison(identifier)

    def comparison(self, identifier):
        with self.read_snapshot() as db:
            row = self.require(db, 'comparisons', identifier)
            row['result'] = json.loads(row.pop('payload'))
            row['request'] = json.loads(row['request'])
            row['review'] = json.loads(row['review'])
            return row

    def list_comparisons(self, product_id, offset=0, limit=30):
        with self.read_snapshot() as db:
            self.require(db, 'products', product_id)
            rows = db.execute('SELECT id,name,actor,created,updated,version FROM comparisons WHERE product_id=? ORDER BY created DESC,id LIMIT ? OFFSET ?',
                              (product_id, limit + 1, offset)).fetchall()
            return {'items': [dict(row) for row in rows[:limit]], 'next_offset': offset + limit if len(rows) > limit else None}

    def review_comparison(self, identifier, change_id, review, expected_version, actor):
        if review.get('status') not in {'pending_review', 'acknowledged', 'accepted_risk', 'verified_fixed', 'needs_investigation'}:
            raise ValueError('Unsupported comparison review status.')
        if len(review.get('remarks', '').strip()) < 3:
            raise ValueError('Review remarks are required.')
        with self.connect() as db:
            row = self.require(db, 'comparisons', identifier)
            if row['version'] != expected_version:
                raise StoreConflict('This comparison was reviewed elsewhere. Reload it before saving.')
            changes = json.loads(row['payload']).get('changes', [])
            change = next((c for c in changes if c['id'] == change_id), None)
            if not change:
                raise LookupError('Comparison change not found')
            if review['status'] == 'verified_fixed' and (change['kind'] != 'finding' or not review.get('evidence', '').strip()):
                raise ValueError('Verified fixed requires a finding and verification evidence.')
            reviews = json.loads(row['review'])
            reviews[change_id] = {**review, 'reviewer': actor, 'reviewed_at': time.time()}
            db.execute('UPDATE comparisons SET review=?,version=version+1,updated=? WHERE id=?', (json.dumps(reviews), time.time(), identifier))
            self.audit(db, actor, 'review_comparison', identifier)
        return self.comparison(identifier)

    @staticmethod
    def unpack(row):
        row['workspace'] = json.loads(row.pop('payload'))
        return row

    def save_workspace(self, release_id, workspace, application_id, environment, expected_version, actor):
        identifier = workspace.get('id')
        if not isinstance(identifier, str) or not identifier or len(identifier) > 100:
            raise ValueError('A workspace ID is required.')
        payload = deepcopy(workspace)
        payload.pop('server', None)
        payload.pop('readOnly', None)
        revisions = payload.get('revisions', [])
        if not isinstance(revisions, list) or any(not isinstance(r, dict) or r.get('number') != i for i, r in enumerate(revisions, 1)):
            raise ValueError('Report revision numbers must be consecutive, starting at one.')
        serialized = json.dumps(payload)
        if len(serialized.encode()) > 16_000_000:
            raise ValueError('Workspace exceeds the 16 MB server storage limit.')
        with self.connect() as db:
            release = self.require(db, 'releases', release_id)
            if self.require(db, 'products', release['product_id'])['archived']:
                raise StoreConflict('Restore the product before editing its workspaces.')
            if application_id and self.require(db, 'applications', application_id)['product_id'] != release['product_id']:
                raise ValueError('Application belongs to another product.')
            old = db.execute('SELECT * FROM workspaces WHERE id=?', (identifier,)).fetchone()
            if old:
                if old['release_id'] != release_id or old['application_id'] != application_id or old['environment'] != environment:
                    raise StoreConflict('Workspace scope cannot change in place. Create a new workspace.')
                if old['version'] != expected_version:
                    raise StoreConflict('A newer workspace exists. Reload it before saving.')
                previous = json.loads(old['payload']).get('revisions', [])
                if payload.get('revisions', [])[:len(previous)] != previous:
                    raise StoreConflict('Published report revisions are immutable.')
                version = old['version'] + 1
                db.execute('UPDATE workspaces SET version=?,payload=?,updated=? WHERE id=?', (version, serialized, time.time(), identifier))
            else:
                if expected_version != 0:
                    raise StoreConflict('Workspace version is stale.')
                version = 1
                db.execute('INSERT INTO workspaces VALUES(?,?,?,?,?,?,?)', (identifier, release_id, application_id, environment, version, serialized, time.time()))
            self.audit(db, actor, 'save_workspace', identifier)
            return {'version': version, 'release_id': release_id, 'application_id': application_id, 'environment': environment}

    def clone_release(self, identifier, name, actor):
        name, key = normalize_name(name)
        with self.connect() as db:
            original = self.require(db, 'releases', identifier)
            product = self.require(db, 'products', original['product_id'])
            if product['archived']:
                raise StoreConflict('Restore the product first.')
            target = str(uuid.uuid4())
            db.execute('INSERT INTO releases(id,product_id,name,name_key,created_at) VALUES(?,?,?,?,?)', (target, original['product_id'], name, key, time.time()))
            for row in db.execute('SELECT * FROM workspaces WHERE release_id=?', (identifier,)).fetchall():
                workspace = json.loads(row['payload'])
                workspace['id'] = str(uuid.uuid4())
                workspace['revisions'] = []
                workspace.pop('activeJob', None)
                draft = workspace.setdefault('draft', {})
                draft.update({'preview': None, 'preparedSignature': None})
                draft.setdefault('payload', {}).update({'deployment_version': name, 'answers': [],
                    'assessment_id': workspace['id'], 'questionnaire_answers': [], 'generate_dfd': False})
                db.execute('INSERT INTO workspaces VALUES(?,?,?,?,?,?,?)', (workspace['id'], target, row['application_id'], row['environment'], 1, json.dumps(workspace), time.time()))
                db.execute('INSERT INTO assessment_lineage VALUES(?,?,?)', (workspace['id'], row['id'], time.time()))
            self.audit(db, actor, 'clone_release', target)
            return self.require(db, 'releases', target)

    def audit_log(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')]
