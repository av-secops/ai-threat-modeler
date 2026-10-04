"""Persistent analysis jobs, bounded admission, polling and explicit crash retry."""

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import threading
import time
import uuid

from .analysis_workers import analysis_workers, AnalysisBusy

logger = logging.getLogger(__name__)
_IDENTITY_BINDING = '_aegis_job_identity'
_MISSING_BINDING = object()


class JobAuthorizationDenied(PermissionError):
    """No access details or credentials are retained in the persisted failure."""


class JobRunner:
    def __init__(self, store, analyze, *, authorize=None, publish=None):
        """Legacy analyze(payload) callers remain unchanged.

        Guarded jobs use authorize(actor, payload) -> identity and
        analyze(payload, identity=identity), with no persistence during analysis.
        Optional publish(result, identity=identity, db=db) runs after a second
        authorization check inside the job completion transaction. It must use
        the provided connection, not open another write transaction.
        """
        self.store, self.analyze = store, analyze
        self.authorize, self.publish = authorize, publish
        self.owner = str(uuid.uuid4())
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def submit(self, payload, actor):
        if self.authorize:
            payload = {key: value for key, value in payload.items() if key != _IDENTITY_BINDING}
            try:
                identity = self._authorize(actor, payload)
            except JobAuthorizationDenied:
                raise ValueError('Job access is not authorized under the current grants.') from None
            binding = self._identity_binding(identity)
            if binding is not None:
                payload = {**payload, _IDENTITY_BINDING: binding}
        identifier = str(uuid.uuid4())
        with self.store.connect() as db:
            if db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0] >= 20:
                raise ValueError('Analysis queue is full. Retry after a job completes.')
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)', (identifier, actor, 'queued', json.dumps(payload), None, None, time.time(), None))
            self.store.audit(db, actor, 'submit_analysis', identifier)
        return {'id': identifier, 'state': 'queued'}

    def get(self, identifier, actor):
        with self.store.connect() as db:
            row = self.store.require(db, 'jobs', identifier)
            if row['actor'] != actor:
                raise LookupError('Job not found')
            return {'id': row['id'], 'state': row['state'], 'error': row['error'],
                'result': json.loads(row['result']) if row['result'] else None}

    def retry(self, identifier, actor):
        with self.store.connect() as db:
            row = self.store.require(db, 'jobs', identifier)
            if row['actor'] != actor:
                raise LookupError('Job not found')
            if row['state'] not in {'failed', 'interrupted'}:
                raise ValueError('Only failed or interrupted jobs can be retried.')
            if db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0] >= 20:
                raise ValueError('Analysis queue is full. Retry after a job completes.')
            db.execute("UPDATE jobs SET state='queued',error=NULL,updated=? WHERE id=?", (time.time(), identifier))
            self.store.audit(db, actor, 'retry_analysis', identifier)
        return {'id': identifier, 'state': 'queued'}

    def execute(self, row):
        try:
            payload = json.loads(row['payload'])
            binding = payload.pop(_IDENTITY_BINDING, _MISSING_BINDING)

            def work():
                identity = self._authorize(row['actor'], payload, binding=binding)
                return self.analyze(payload, identity=identity) if self.authorize else self.analyze(payload)

            result = analysis_workers.run_sync(work)
            with self.store.connect() as db:
                current = db.execute('SELECT state,owner FROM jobs WHERE id=?', (row['id'],)).fetchone()
                if current is None or current['state'] != 'running' or current['owner'] != self.owner:
                    return
                original = json.loads(row['payload'])
                original.pop(_IDENTITY_BINDING, None)
                identity = self._authorize(row['actor'], original, binding=binding)
                if self.publish:
                    result = self.publish(result, identity=identity, db=db)
                db.execute("UPDATE jobs SET state='completed',error=NULL,result=?,updated=? WHERE id=? AND owner=?",
                           (json.dumps(result), time.time(), row['id'], self.owner))
            return
        except AnalysisBusy:
            state, error, output = 'queued', None, None
        except JobAuthorizationDenied:
            logger.warning('Persistent analysis job access denied: %s', row['id'])
            state, error, output = ('failed',
                'Job access is no longer authorized. Check current access grants before retrying.', None)
        except Exception:
            logger.exception('Persistent analysis job failed: %s', row['id'])
            state, error, output = 'failed', 'Analysis failed. The input and prior report were preserved; inspect backend logs.', None
        with self.store.connect() as db:
            db.execute('UPDATE jobs SET state=?,error=?,result=?,updated=? WHERE id=? AND owner=?', (state, error, output, time.time(), row['id'], self.owner))

    @staticmethod
    def _identity_binding(identity):
        from .workspace_access import VerifiedIdentity
        if isinstance(identity, VerifiedIdentity):
            return {'issuer': identity.issuer, 'subject': identity.subject, 'auth_method': identity.auth_method}
        return None

    def _authorize(self, actor, payload, *, binding=None):
        if self.authorize is None:
            return None
        try:
            identity = self.authorize(actor, payload)
            current = self._identity_binding(identity)
            # A revoked static actor named local-user must never become the
            # anonymous local administrator when the token configuration clears.
            if binding is not None and current is not None and current != binding:
                raise JobAuthorizationDenied()
            return identity
        except Exception:
            raise JobAuthorizationDenied() from None

    def loop(self):
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix='aegis-job') as pool:
            current, identifier = None, None
            while not self.stop_event.wait(1):
                try:
                    with self.store.connect() as db:
                        db.execute("UPDATE jobs SET state='interrupted',error='Worker stopped; retry the saved analysis.' WHERE state='running' AND updated<?", (time.time() - 60,))
                        if current and not current.done():
                            db.execute('UPDATE jobs SET updated=? WHERE id=? AND owner=?', (time.time(), identifier, self.owner))
                            continue
                        row = db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY updated LIMIT 1").fetchone()
                        if row:
                            row = dict(row)
                            identifier = row['id']
                            db.execute("UPDATE jobs SET state='running',owner=?,updated=? WHERE id=? AND state='queued'", (self.owner, time.time(), identifier))
                            current = pool.submit(self.execute, row)
                except Exception:
                    logger.exception('Persistent job dispatch failed')

    def stop(self):
        self.stop_event.set()
