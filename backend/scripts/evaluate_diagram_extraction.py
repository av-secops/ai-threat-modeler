"""Score extraction separately from threat detection against annotated local diagrams.

Usage: python scripts/evaluate_diagram_extraction.py manifest.json --output report.json
Manifest rows: {file, components: [labels], flows: [[from,to]], boundaries: [labels]}.
No LLM is needed for structured imports. Raster evaluation uses configured local
OCR/vision; missing providers are reported, never silently scored as a success.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.diagram_import import extract_diagram, extract_pdf_diagram
from app.services.diagram_vision import label


def metrics(expected, actual):
    expected, actual = Counter(expected), Counter(actual)
    correct = sum((expected & actual).values())
    predicted, total = sum(actual.values()), sum(expected.values())
    return {'expected': total, 'extracted': predicted, 'correct': correct,
        'precision': correct/predicted if predicted else (1.0 if not total else 0.0),
        'recall': correct/total if total else 1.0,
        'missed': total-correct, 'unsupported': predicted-correct}


def score(expected, model):
    names = {c['id']: label(c['name']) for c in model['components']}
    actual_flows = [(names.get(f['source_id'], '?'), names.get(f['target_id'], '?')) for f in model['flows']]
    wanted = [(label(a), label(b)) for a, b in expected.get('flows', [])]
    result = {'components': metrics([label(v) for v in expected['components']], names.values()),
        'directed_flows': metrics(wanted, actual_flows),
        'trust_boundaries': metrics([label(v) for v in expected.get('boundaries', [])], [label(b['name']) for b in model.get('trust_boundaries', [])]),
        'direction_errors': sum(1 for a, b in actual_flows if (a, b) not in wanted and (b, a) in wanted),
        'unconfirmed_flows': sum(f.get('assumed', False) for f in model['flows']),
        'region_coverage': sum(any(e.get('bbox') for e in c.get('evidence', [])) for c in model['components']) / max(1, len(model['components']))}
    if expected.get('instances'):
        instances = {c['id']: next((expected['instances'][e['source_key']] for e in c.get('evidence', []) if e.get('source_key') in expected['instances']), '?') for c in model['components']}
        result['instance_flows'] = metrics([tuple(pair) for pair in expected.get('instance_flows', [])],
            [(instances.get(f['source_id'], '?'), instances.get(f['target_id'], '?')) for f in model['flows']])
        result['boundary_membership'] = metrics([(label(b), member) for b, members in expected.get('boundary_membership', {}).items() for member in members],
            [(label(b['name']), instances.get(member, '?')) for b in model.get('trust_boundaries', []) for member in b['components']])
    return result


def run(manifest):
    entries = json.loads(manifest.read_text(encoding='utf-8'))
    if not isinstance(entries, list) or len(entries) > 1000:
        raise ValueError('Manifest must contain at most 1000 reviewed cases.')
    results = []
    for case in entries:
        path = (manifest.parent / case['file']).resolve()
        if not path.is_relative_to(manifest.parent.resolve()):
            raise ValueError('Evaluation fixtures must remain inside the manifest directory.')
        started = time.monotonic()
        try:
            if path.stat().st_size > 8_000_000:
                raise ValueError('Fixture exceeds the upload limit.')
            extractor = extract_pdf_diagram if path.suffix.lower() == '.pdf' else extract_diagram
            _, _, meta = extractor(path.name, path.read_bytes())
            result = {'file': case['file'], 'scores': score(case, meta['diagram_model']),
                'extraction': {k: v for k, v in meta['diagram_model'].get('metadata', {}).get('diagram_extraction', {}).items() if k != 'connector_segments'}, 'warnings': meta.get('warning', '')}
        except Exception as exc:
            result = {'file': case['file'], 'error': f'{type(exc).__name__}: {exc}'}
        results.append({**result, 'elapsed_ms': round((time.monotonic()-started)*1000)})
    return {'schema_version': 1, 'purpose': 'diagram_extraction_not_threat_detection',
        'independent_accuracy_claim': False, 'cases': results,
        'reviewer_corrections': 'Not measured by batch extraction; compare reviewed model revisions separately.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'cases': len(report['cases']), 'errors': sum('error' in row for row in report['cases']), 'output': str(args.output)}))
