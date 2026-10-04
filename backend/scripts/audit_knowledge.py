"""Read-only KB audit: python scripts/audit_knowledge.py [--contracts]."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.knowledge_base.loader import ThreatKnowledgeBase
from app.knowledge_base.evaluation import evaluate_contracts
from app.knowledge_base.governance import review_digest, quarantine_reason, audit_contracts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contracts', action='store_true')
    parser.add_argument('--strict', action='store_true', help='Fail on unresolved curation gaps, not only loader or test errors.')
    parser.add_argument('--directory', type=Path, help='Inspect this KB directory without changing the active catalog.')
    parser.add_argument('--candidate', type=Path, help='Inspect a proposed pack without installing or activating it.')
    args = parser.parse_args()
    kb = ThreatKnowledgeBase(args.directory)
    report = {'rules': len(kb.threats), 'validation_issues': kb.validation_issues,
        'governance': kb.governance_audit}
    if args.candidate:
        content = json.loads(args.candidate.read_text(encoding='utf-8'))
        rules = content.get('threats') if isinstance(content, dict) else content
        if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
            parser.error('Candidate must contain a list of rule objects.')
        report['candidate'] = []
        for rule in rules:
            rule['origin'] = 'external'
            report['candidate'].append({'id': rule.get('id'), 'content_digest': review_digest(rule),
                'quarantine_reason': quarantine_reason(rule), 'installed': False})
        # Validation for a proposed pack is separate from activation approval.
        candidate = ThreatKnowledgeBase.from_canonical_rules([])
        preview = []
        for rule in rules:
            draft = {**rule, 'origin': 'preview', 'lifecycle': 'active'}
            preview.extend(candidate._normalize_and_merge([draft]))
        identifiers = [r['id'] for r in preview]
        report['candidate_audit'] = {**audit_contracts(preview), 'validation_issues': candidate.validation_issues,
            'duplicate_ids': sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1}),
            'activation_authorized': False}
    if args.contracts:
        report['contracts'] = evaluate_contracts(kb)
    print(json.dumps(report, indent=2))
    invalid_candidate = bool(report.get('candidate_audit', {}).get('validation_issues') or
        report.get('candidate_audit', {}).get('duplicate_ids'))
    return int(bool(kb.validation_issues or report.get('contracts', {}).get('failures') or invalid_candidate or
        (args.strict and (kb.governance_audit['issues'] or kb.quarantined_rules or
                         report.get('candidate_audit', {}).get('issues')))))


if __name__ == '__main__':
    raise SystemExit(main())
