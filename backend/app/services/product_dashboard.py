"""Stored-report analytics. No analyzer calls or client-authored risk totals."""

from collections import Counter
import csv
import hashlib
import io
import json
import time
from typing import Literal

from pydantic import BaseModel, Field

from .product_store import StoreConflict
from .security_workflows import effective_workflow_review

POLICY = 'product-dashboard-v2'
SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Unknown')
STATUSES = ('pending_review', 'in_review', 'action_required', 'mitigation_proposed',
            'verified_fixed', 'accepted', 'false_positive', 'unknown')
OPEN = frozenset(STATUSES[:4])


class DashboardFilters(BaseModel):
    release_id: str = Field(default='', max_length=100)
    application_id: str = Field(default='', max_length=100)
    environment: str = Field(default='', max_length=100)
    scope: Literal['all', 'release', 'application'] = 'all'
    archived: bool = False
    tier: Literal['all', 'Confirmed', 'Potential', 'Unknown'] = 'all'
    quality: Literal['all', 'ready', 'review', 'blocked', 'unknown'] = 'all'
    severity: Literal['all', 'Critical', 'High', 'Medium', 'Low', 'Unknown'] = 'all'
    status: Literal['all', 'open', 'pending_review', 'in_review', 'action_required',
                    'mitigation_proposed', 'verified_fixed', 'accepted', 'false_positive', 'unknown'] = 'all'
    kind: Literal['all', 'risk', 'question'] = 'all'
    search: str = Field(default='', max_length=200)
    sort: Literal['severity', 'title', 'release', 'status'] = 'severity'


def _json(value, default):
    try:
        return json.loads(value) if value else default
    except (ValueError, TypeError):
        return default


def _quality(gate):
    value = gate.get('publication_status') or gate.get('status')
    if value in {'blocked', 'failed'}:
        return 'blocked'
    if value == 'ready':
        return 'ready'
    if value in {'review', 'review_required', 'technical_review', 'warning', 'passed', 'pass'}:
        return 'review'
    return 'unknown'


def _load(db, product_id=None):
    """A bounded number of queries independent of product/release/model count."""
    args = (product_id,) if product_id else ()
    where = ' WHERE product_id=?' if product_id else ''
    products = [dict(r) for r in db.execute('SELECT * FROM products' + (' WHERE id=?' if product_id else ''), args)]
    if product_id and not products:
        raise LookupError('Product not found.')
    releases = [dict(r) for r in db.execute('SELECT * FROM releases' + where, args)]
    applications = [dict(r) for r in db.execute('SELECT * FROM applications' + where, args)]
    # Extract only selected-revision metadata, not the workspace's entire history.
    models = [dict(r) for r in db.execute('''
        SELECT w.id,w.release_id,w.application_id,w.environment,w.version,w.updated,
            r.product_id,r.name AS release_name,r.archived,a.name AS application_name,
            json_extract(w.payload,'$.projectName') AS name,
            j.state AS latest_attempt,
            json_extract(w.payload,'$.revisions[#-1].number') AS revision,
            json_extract(w.payload,'$.revisions[#-1].data.engine_status.assessment.report_id') AS report_id
        FROM workspaces w JOIN releases r ON r.id=w.release_id
        LEFT JOIN applications a ON a.id=w.application_id
        LEFT JOIN jobs j ON j.id=json_extract(w.payload,'$.activeJob.id')
    ''' + (' WHERE r.product_id=?' if product_id else ''), args)]
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    results, reviews = {}, {}
    if 'assessment_results' in tables:
        for r in db.execute('''
            SELECT ar.id,ar.assessment_id,ar.created,
                json_extract(ar.body,'$.threats') AS threats,
                json_extract(ar.body,'$.engine_status.quality_gate') AS quality_gate
            FROM assessment_results ar JOIN workspaces w ON ar.assessment_id=w.id
            JOIN releases r ON r.id=w.release_id
            WHERE ar.id=json_extract(w.payload,'$.revisions[#-1].data.engine_status.assessment.report_id')
        ''' + (' AND r.product_id=?' if product_id else ''), args):
            results[r['id']] = dict(r)
    if 'finding_review_events' in tables:
        for r in db.execute('''
            SELECT e.* FROM finding_review_events e
            JOIN assessment_results ar ON ar.id=e.report_id
            JOIN workspaces w ON ar.assessment_id=w.id
            JOIN releases r ON r.id=w.release_id
            WHERE ar.id=json_extract(w.payload,'$.revisions[#-1].data.engine_status.assessment.report_id')
            AND e.id=(SELECT MAX(x.id) FROM finding_review_events x
                WHERE x.report_id=e.report_id AND x.finding_id=e.finding_id)
        ''' + (' AND r.product_id=?' if product_id else ''), args):
            reviews[(r['report_id'], r['finding_id'])] = dict(r)
    return products, releases, applications, models, results, reviews


def _build(data, product_id, filters):
    products, releases, applications, models, results, reviews = data
    product = next(p for p in products if p['id'] == product_id)
    releases = [r for r in releases if r['product_id'] == product_id]
    applications = [a for a in applications if a['product_id'] == product_id]
    if filters.release_id and not any(r['id'] == filters.release_id for r in releases):
        raise ValueError('Release does not belong to this product.')
    if filters.application_id and not any(a['id'] == filters.application_id for a in applications):
        raise ValueError('Application does not belong to this product.')
    all_models = [m for m in models if m['product_id'] == product_id]
    selected_releases = {r['id'] for r in releases if (filters.archived or not r['archived'])
                         and (not filters.release_id or r['id'] == filters.release_id)}
    selected = [m for m in all_models if m['release_id'] in selected_releases
                and (not filters.application_id or m['application_id'] == filters.application_id)
                and (not filters.environment or m['environment'] == filters.environment)
                and (filters.scope == 'all' or bool(m['application_id']) == (filters.scope == 'application'))]
    coverage, findings, versions = [], [], []
    for model in selected:
        report = results.get(model['report_id'])
        valid = bool(report and report['assessment_id'] == model['id'])
        quality = _quality(_json(report['quality_gate'], {})) if valid else 'unknown'
        if filters.quality != 'all' and quality != filters.quality:
            continue
        item = {**model, 'model_scope': 'application' if model['application_id'] else 'release',
                'quality': quality, 'completed': valid, 'last_analyzed': report['created'] if valid else None,
                'assessment_status': 'completed' if valid else 'legacy_unverified' if model['revision'] else 'draft'}
        coverage.append(item)
        versions.append((model['id'], model['version'], model['report_id'], model['latest_attempt']))
        if not valid:
            continue
        for threat in _json(report['threats'], []):
            review = reviews.get((report['id'], threat.get('id')))
            decision = _json(review['body'], {}) if review else {}
            if decision.get('security_workflow'):
                decision = effective_workflow_review(decision)
            state = decision.get('status', 'pending_review')
            if state not in STATUSES or (state == 'verified_fixed' and not str(decision.get('verification_evidence', '')).strip()):
                state = 'unknown'
            severity = str(threat.get('severity') or '').title()
            severity = severity if severity in SEVERITIES else 'Unknown'
            tier = threat.get('tier') if threat.get('tier') in {'Confirmed', 'Potential'} else 'Unknown'
            finding = {k: item[k] for k in ('release_id', 'release_name', 'application_id', 'application_name',
                        'environment', 'model_scope', 'revision', 'report_id', 'quality', 'last_analyzed')}
            finding.update({'workspace_id': model['id'], 'finding_id': threat.get('id', ''),
                'occurrence_id': f"{model['id']}:{report['id']}:{threat.get('id', '')}",
                'title': threat.get('title') or 'Untitled finding', 'severity': severity, 'tier': tier,
                'status': state, 'owner': decision.get('owner', ''),
                'acceptance_expired': bool(decision.get('acceptance_expired')),
                'overdue': bool(decision.get('overdue')),
                'kind': 'question' if threat.get('finding_type') == 'validation_question' else 'risk',
                'stride': threat.get('affected_stride_categories') or [threat.get('stride_category') or threat.get('category') or 'Unknown'],
                'flow_refs': threat.get('affected_flow_refs') or [],
                'review_version': review['id'] if review else 0})
            versions.append((report['id'], finding['finding_id'], finding['review_version'], state,
                             finding['acceptance_expired'], finding['overdue']))
            findings.append(finding)
    def matches(f):
        return ((filters.tier == 'all' or f['tier'] == filters.tier)
                and (filters.severity == 'all' or f['severity'] == filters.severity)
                and (filters.status == 'all' or f['status'] == filters.status or (filters.status == 'open' and f['status'] in OPEN))
                and (filters.kind == 'all' or f['kind'] == filters.kind)
                and (not filters.search or filters.search.casefold() in ' '.join(str(f[k] or '') for k in
                    ('title', 'finding_id', 'application_name', 'release_name', 'owner')).casefold()))
    rows = [f for f in findings if matches(f)]
    open_risks = [f for f in rows if f['kind'] == 'risk' and f['status'] in OPEN]
    risks = [f for f in rows if f['kind'] == 'risk']
    severity = Counter(f['severity'] for f in open_risks)
    states = Counter(f['status'] for f in rows)
    completed = [m for m in coverage if m['completed']]
    overlap = {m['release_id'] for m in completed if m['model_scope'] == 'release'} & {m['release_id'] for m in completed if m['model_scope'] == 'application'}
    fingerprint = hashlib.sha256(json.dumps([POLICY, filters.model_dump(), sorted(versions, key=str),
        [(r['id'], r['name'], r['archived']) for r in releases], [(a['id'], a['name']) for a in applications],
        product['name'], product['archived']], sort_keys=True).encode()).hexdigest()
    result = {'product': product, 'policy': POLICY, 'snapshot': fingerprint, 'generated_at': time.time(),
        'counting_unit': 'finding_occurrences', 'filters': filters.model_dump(),
        'options': {'releases': releases, 'applications': applications, 'environments': sorted({m['environment'] for m in all_models})},
        'coverage': {'applications_registered': len(applications), 'applications_assessed': len({m['application_id'] for m in completed if m['application_id']}),
            'releases_registered': len(selected_releases), 'releases_assessed': len({m['release_id'] for m in completed}),
            'models_completed': len(completed), 'models_total': len(coverage),
            'full_release_models': sum(m['model_scope'] == 'release' for m in completed),
            'application_models': sum(m['model_scope'] == 'application' for m in completed),
            'legacy_unverified': sum(m['assessment_status'] == 'legacy_unverified' for m in coverage),
            'drafts': sum(m['assessment_status'] == 'draft' for m in coverage),
            'quality': dict(Counter(m['quality'] for m in completed)), 'overlapping_releases': len(overlap),
            'last_analyzed': max((m['last_analyzed'] for m in completed), default=None)},
        'metrics': {'reported_findings': len(rows), 'open_risks': len(open_risks),
            'verified_fixed': sum(f['status'] == 'verified_fixed' for f in risks),
            'accepted_risks': sum(f['status'] == 'accepted' for f in risks),
            'false_positives': states['false_positive'], 'validation_questions': sum(f['kind'] == 'question' for f in rows),
            'confirmed_open': sum(f['tier'] == 'Confirmed' for f in open_risks),
            'potential_open': sum(f['tier'] == 'Potential' for f in open_risks)},
        'severity': [{'name': s, 'count': severity[s], 'percent': round(100 * severity[s] / len(open_risks), 1) if open_risks else None} for s in SEVERITIES],
        'statuses': [{'name': s, 'count': states[s], 'percent': round(100 * states[s] / len(rows), 1) if rows else None} for s in STATUSES],
        'models': sorted(coverage, key=lambda m: (m['release_name'], m['name'] or '', m['id']))}
    keys = {'severity': lambda f: (SEVERITIES.index(f['severity']), f['title'].casefold(), f['occurrence_id']),
            'title': lambda f: (f['title'].casefold(), f['occurrence_id']),
            'release': lambda f: (f['release_name'].casefold(), f['occurrence_id']),
            'status': lambda f: (STATUSES.index(f['status']), f['occurrence_id'])}
    rows.sort(key=keys[filters.sort])
    return result, rows


def dashboard(store, product_id, filters, snapshot='', page=1, page_size=25, export=False):
    with store.read_snapshot() as db:
        result, rows = _build(_load(db, product_id), product_id, filters)
    if snapshot and snapshot != result['snapshot']:
        raise StoreConflict('Dashboard data changed. Refresh before paging or exporting.')
    if export:
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        columns = ['product', 'release_name', 'application_name', 'model_scope', 'environment', 'title',
                   'severity', 'tier', 'status', 'kind', 'stride', 'workspace_id', 'report_id', 'revision', 'finding_id', 'quality']
        writer.writerow(columns)
        for row in rows:
            values = {**row, 'product': result['product']['name'], 'stride': ', '.join(row['stride'])}
            writer.writerow([_csv_cell(values.get(key)) for key in columns])
        return output.getvalue()
    result['findings'] = {'total': len(rows), 'page': page, 'page_size': page_size, 'rows': rows[(page-1)*page_size:page*page_size]}
    return result


def _csv_cell(value):
    text = str(value if value is not None else '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')) or text.startswith(('\t', '\r', '\n')) else text


def finding_detail(store, product_id, workspace_id, report_id, finding_id):
    with store.read_snapshot() as db:
        row = db.execute('''SELECT ar.body FROM assessment_results ar
            JOIN workspaces w ON w.id=ar.assessment_id JOIN releases r ON r.id=w.release_id
            WHERE r.product_id=? AND w.id=? AND ar.id=?
            AND EXISTS(SELECT 1 FROM json_each(w.payload,'$.revisions') j
                WHERE json_extract(j.value,'$.data.engine_status.assessment.report_id')=ar.id)
        ''', (product_id, workspace_id, report_id)).fetchone()
        if not row:
            raise LookupError('Report is not associated with this product and model.')
        report = _json(row['body'], {})
        threat = next((t for t in report.get('threats', []) if t.get('id') == finding_id), None)
        if not threat:
            raise LookupError('Finding not present in this report.')
        events = [{**_json(e['body'], {}), 'version': e['id'], 'author': e['actor'],
                   'created_at': e['created'], 'finding_id': e['finding_id']} for e in db.execute(
                       'SELECT * FROM finding_review_events WHERE report_id=? AND finding_id=? ORDER BY id', (report_id, finding_id))]
    latest = events[-1] if events else None
    if latest and latest.get('security_workflow'):
        latest = effective_workflow_review(latest)
    return {'threat': threat, 'reviews': {'events': events, 'latest': {finding_id: latest} if latest else {}}}


def observe(store, product_id, actor):
    """Explicitly record a current overview; never fabricate past status snapshots."""
    filters = DashboardFilters()
    with store.connect() as db:
        result, _ = _build(_load(db, product_id), product_id, filters)
        latest = db.execute('SELECT fingerprint FROM dashboard_observations WHERE product_id=? ORDER BY id DESC LIMIT 1', (product_id,)).fetchone()
        if not latest or latest['fingerprint'] != result['snapshot']:
            body = {key: result[key] for key in ('coverage', 'metrics', 'severity', 'statuses')}
            db.execute('INSERT INTO dashboard_observations(product_id,fingerprint,policy,body,observed) VALUES(?,?,?,?,?)',
                       (product_id, result['snapshot'], POLICY, json.dumps(body), time.time()))
            store.audit(db, actor, 'record_dashboard_observation', product_id)
    return history(store, product_id)


def history(store, product_id):
    with store.read_snapshot() as db:
        store.require(db, 'products', product_id)
        rows = [dict(r) for r in db.execute('SELECT id,policy,body,observed FROM dashboard_observations WHERE product_id=? ORDER BY id DESC LIMIT 100', (product_id,))]
    return {'scope': 'All active releases; latest completed report per model at observation time',
            'kind': 'recorded_observations_not_continuous_history',
            'observations': [{**r, 'body': _json(r['body'], {})} for r in rows]}


def portfolio(store, archived=False, *, allowed_product_ids=None):
    with store.read_snapshot() as db:
        data = _load(db)
        summaries = [_build(data, p['id'], DashboardFilters())[0] for p in data[0]
            if (allowed_product_ids is None or p['id'] in allowed_product_ids) and (archived or not p['archived'])]
    return {'generated_at': time.time(), 'policy': POLICY, 'products_total': len(summaries),
            'products_assessed': sum(s['coverage']['models_completed'] > 0 for s in summaries),
            'products': [{key: s[key] for key in ('product', 'coverage', 'metrics')} for s in summaries]}
