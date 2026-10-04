"""Local KB release operator tool. Caller-provided identities are attestations, not SSO."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.knowledge_base.loader import ThreatKnowledgeBase
from app.knowledge_base.releases import KnowledgeReleaseStore, ReleaseGateError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    stage = sub.add_parser('stage')
    stage.add_argument('--directory', type=Path)
    stage.add_argument('--actor', required=True)
    assess = sub.add_parser('assess')
    assess.add_argument('digest')
    approve = sub.add_parser('approve')
    approve.add_argument('digest')
    approve.add_argument('--reviewer', required=True)
    approve.add_argument('--reason', required=True)
    approve.add_argument('--assessment-digest', required=True)
    approve.add_argument('--valid-until', required=True)
    approve.add_argument('--waivers', type=Path)
    for command in ('publish', 'rollback'):
        operation = sub.add_parser(command)
        operation.add_argument('digest')
        operation.add_argument('--approval-id', type=int, required=True)
        operation.add_argument('--actor', required=True)
        operation.add_argument('--reason', required=True)
        operation.add_argument('--expected-revision', type=int, required=True)
    sub.add_parser('active')
    sub.add_parser('history')
    export = sub.add_parser('export')
    export.add_argument('digest')
    args = parser.parse_args()
    store = KnowledgeReleaseStore(args.database)
    try:
        if args.command == 'stage':
            result = store.stage(ThreatKnowledgeBase(args.directory), actor=args.actor)
            result = {k: v for k, v in result.items() if k != 'payload'}
        elif args.command == 'assess':
            result = store.assess(args.digest, baseline_digest=store.active()['digest'])
        elif args.command == 'approve':
            result = store.approve(args.digest, reviewer=args.reviewer, reason=args.reason,
                expected_assessment_digest=args.assessment_digest, valid_until=args.valid_until,
                waivers=json.loads(args.waivers.read_text(encoding='utf-8')) if args.waivers else [],
                baseline_digest=store.active()['digest'])
        elif args.command in ('publish', 'rollback'):
            result = getattr(store, args.command)(args.digest, approval_id=args.approval_id,
                actor=args.actor, reason=args.reason, expected_revision=args.expected_revision)
        elif args.command == 'export':
            result = store.artifact(args.digest)
        else:
            result = getattr(store, args.command)()
    except (ValueError, KeyError) as exc:
        print(json.dumps({'error': str(exc), 'blockers': exc.blockers if isinstance(exc, ReleaseGateError) else []}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
