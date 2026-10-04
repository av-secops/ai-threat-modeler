import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from app.engine.retrieval_quality import RetrievalMonitor


def test_metrics_survive_restart_without_prompt_or_double_counting(tmp_path):
    path = tmp_path / 'metrics.sqlite3'
    first = RetrievalMonitor(path)
    first.record(latency_ms=12, results=3, fallback=True, cache='miss')
    first.snapshot()
    first.snapshot()
    second = RetrievalMonitor(path)
    second.record(latency_ms=5, results=2, fallback=False, cache='hit')
    summary = second.snapshot()
    assert summary['queries'] == 1
    assert summary['persistence']['counters']['queries'] == 2
    assert summary['persistence']['retained_runs'] == 2
    with sqlite3.connect(path) as db:
        values = [json.loads(row[0]) for row in db.execute('SELECT payload FROM retrieval_runs')]
    assert all(set(value) == {'counters', 'latencies'} for value in values)


def test_monitor_bounds_samples_labels_and_handles_unavailable_storage(tmp_path):
    monitor = RetrievalMonitor(tmp_path / 'metrics.sqlite3')
    for i in range(5010):
        monitor.record(latency_ms=i, results=1, fallback=False, cache=f'private-query-{i}')
    result = monitor.snapshot()
    assert result['latency_samples'] == 5000
    assert result['cache:other'] == 5010
    assert not any('private-query' in key for key in result)
    unavailable = RetrievalMonitor(tmp_path)
    unavailable.record(latency_ms=1, results=1, fallback=False, cache='hit')
    assert unavailable.snapshot()['persistence']['status'] == 'unavailable'


def test_concurrent_record_and_checkpoints_do_not_lose_counts(tmp_path):
    monitor = RetrievalMonitor(tmp_path / 'metrics.sqlite3')
    def record(_):
        monitor.record(latency_ms=1, results=1, fallback=False, cache='hit')
        monitor.flush()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, range(20)))
    assert monitor.snapshot()['persistence']['counters']['queries'] == 20
