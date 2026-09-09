"""Compare explicit immutable report revisions without treating disappearance as repair."""

import json
from collections import defaultdict


def fingerprint(value):
    return json.dumps(value, sort_keys=True, default=str)


def compare_reports(before, after):
    def delta(left, right, key):
        def index(rows):
            grouped = defaultdict(list)
            for row in rows:
                grouped[key(row)].append(row)
            return {(k, i): row for k, values in grouped.items() for i, row in enumerate(sorted(values, key=fingerprint))}
        a, b = index(left), index(right)
        return {'added': [b[k] for k in b.keys() - a.keys()], 'removed': [a[k] for k in a.keys() - b.keys()],
            'changed': [{'before': a[k], 'after': b[k]} for k in a.keys() & b.keys() if a[k] != b[k]]}
    old, new = before.get('architecture', {}), after.get('architecture', {})
    def risk_key(r):
        explanation = r.get('explanation') or {}
        return fingerprint([explanation.get('rule_id') or r.get('id'), sorted(r.get('affected_components') or []),
            sorted(r.get('affected_data_flows') or []), sorted(explanation.get('matched_controls') or [])])
    findings = delta(before.get('threats', []), after.get('threats', []), risk_key)
    findings['no_longer_reported'] = findings.pop('removed')
    return {'components': delta(old.get('components', []), new.get('components', []), lambda r: r['id']),
        'flows': delta(old.get('flows', []), new.get('flows', []), lambda r: fingerprint([r['source_id'], r['target_id'], r.get('protocol'), r.get('data_type'), r.get('properties', {}).get('workflow')])),
        'boundaries': delta(old.get('trust_boundaries', []), new.get('trust_boundaries', []), lambda r: r['name']),
        'findings': findings,
        'engine_changed': engine_identity(before) != engine_identity(after),
        'notice': 'No longer reported is not verified remediation. Review changed scope, source evidence, engine and rule versions.'}


def engine_identity(report):
    status = report.get('engine_status') or {}
    kb = status.get('knowledge_base') or {}
    return fingerprint({key: kb.get(key) for key in ('schema_version', 'content_digest', 'threats', 'typed_rules', 'deterministic_rules')})
