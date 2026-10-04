"""Validate a reviewed holdout or score its separately reviewed prediction matches."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.knowledge_base.holdout import DOMAINS, STRIDE, score_holdout, validate_holdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('--training', type=Path, required=True, help='Actual training/validation query and family inventory.')
    parser.add_argument('--minimum-scenarios', type=int, default=100)
    parser.add_argument('--predictions', type=Path)
    parser.add_argument('--judgments', type=Path)
    args = parser.parse_args()
    if bool(args.predictions) != bool(args.judgments):
        parser.error('--predictions and --judgments must be supplied together.')
    try:
        records = json.loads(args.corpus.read_text(encoding='utf-8'))
        training = json.loads(args.training.read_text(encoding='utf-8'))
        options = {'training': training, 'minimum_scenarios': args.minimum_scenarios,
            'required_domains': DOMAINS, 'required_stride': STRIDE}
        if args.predictions:
            report = score_holdout(records, json.loads(args.predictions.read_text(encoding='utf-8')),
                json.loads(args.judgments.read_text(encoding='utf-8')), **options)
        else:
            report = validate_holdout(records, **options)
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({'eligible': False, 'error': str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return int(not report['eligible'])


if __name__ == '__main__':
    raise SystemExit(main())
