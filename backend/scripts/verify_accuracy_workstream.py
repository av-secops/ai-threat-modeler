"""Offline end-to-end probes. Output stays local and is not a production benchmark."""

import argparse
import json
import os
from pathlib import Path
import sys

os.environ.setdefault('AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD', '0')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.engine.analyzer import ThreatAnalyzer
from app.services.diagram_vision import extract_raster

SCENARIOS = {
    'saas': ('React calls Orders API over HTTPS. Orders API stores tenant orders in PostgreSQL. '
        'Orders API has no row level tenant scope. Orders API has no async job budget.',
        {'row_level_tenant_scope', 'async_job_budget'}),
    'cloud': ('An AWS Lambda processes uploaded files in Amazon S3. '
        'AWS Lambda has no lambda invocation restriction.', {'lambda_invocation_restriction'}),
    'agent': ('An MCP Server provides tools for an AI agent. '
        'MCP Server has no mcp token passthrough blocking.', {'mcp_token_passthrough_blocking'}),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    analyzer = ThreatAnalyzer()
    rows = []
    for name, (text, expected) in SCENARIOS.items():
        result = analyzer.analyze_from_text(text, name, use_local_slm=False)
        controls = {c for t in result.threats if t.tier == 'Confirmed' for c in t.explanation.get('matched_controls', [])}
        rows.append({'scenario': name, 'expected': sorted(expected), 'observed': sorted(controls),
            'missing': sorted(expected - controls), 'findings': len(result.threats), 'score': result.score})
        (args.output / f'{name}.json').write_text(result.model_dump_json(indent=2), encoding='utf-8')
    if args.image:
        from PIL import Image
        model, warnings = extract_raster(Image.open(args.image), args.image.name)
        result = analyzer.analyze(model, 'Image extraction review', use_local_slm=False)
        assert result.score is None, 'Unreviewed image extraction must not receive an assessed score.'
        assert not [t for t in result.threats if t.tier == 'Confirmed'], 'Image labels cannot prove control weaknesses.'
        (args.output / 'image.json').write_text(result.model_dump_json(indent=2), encoding='utf-8')
        rows.append({'scenario': 'image', 'components': [c.name for c in model.components],
            'groups': [g['name'] for g in model.metadata.get('diagram_groups', [])],
            'unknown_relationships': len(model.metadata.get('diagram_relationships', [])),
            'unresolved_networks': len(model.metadata.get('diagram_unresolved_networks', [])),
            'confirmed': 0, 'score': result.score, 'warnings': warnings})
    report = {'independent_accuracy': False, 'local_ai_enabled': False, 'scenarios': rows}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return int(any(r.get('missing') for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
