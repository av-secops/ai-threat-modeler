"""Persistent analysis jobs, bounded admission, polling and explicit crash retry."""

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import threading
import time
import uuid

from .analysis_workers import analysis_workers, AnalysisBusy

logger = logging.getLogger(__name__)


class JobRunner:
    def __init__(self, store, analyze):
        self.store, self.analyze = store, analyze
        self.owner = str(uuid.uuid4())
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def submit(self, payload, actor):
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
            result = analysis_workers.run_sync(lambda: self.analyze(json.loads(row['payload'])))
            state, error, output = 'completed', None, json.dumps(result)
        except AnalysisBusy:
            state, error, output = 'queued', None, None
        except Exception:
            logger.exception('Persistent analysis job failed: %s', row['id'])
            state, error, output = 'failed', 'Analysis failed. The input and prior report were preserved; inspect backend logs.', None
        with self.store.connect() as db:
            db.execute('UPDATE jobs SET state=?,error=?,result=?,updated=? WHERE id=? AND owner=?', (state, error, output, time.time(), row['id'], self.owner))

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
