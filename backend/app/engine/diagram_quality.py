"""One extraction checkpoint for model review, scoring and report publication."""


def diagram_quality(architecture):
    metadata = architecture.metadata or {}
    tasks = metadata.get('diagram_review_tasks', [])
    pending = [t for t in tasks if t.get('status') == 'pending']
    candidates = [c.id for c in architecture.components if c.properties.get('diagram_review_required')]
    visual = any(c.id.startswith(('diagram:ocr:', 'diagram:visual:')) for c in architecture.components)
    extractions = [*metadata.get('diagram_extractions', [])]
    if metadata.get('diagram_extraction'):
        extractions.append(metadata['diagram_extraction'])
    outdated = any(e.get('method') in {'ocr_only', 'ocr_vision'} and e.get('version', 1) < 2 for e in extractions)
    raster = [e for e in extractions if e.get('method') in {'ocr_only', 'ocr_vision'}]
    reviewed = {t.get('source_id') for t in tasks if t.get('kind') == 'topology' and t.get('status') == 'reviewed'}
    unreviewed_sources = [e for e in raster if e.get('source_id') not in reviewed]
    missing_topology = bool(unreviewed_sources) or (visual and len(architecture.components) > 1 and not architecture.flows and not reviewed)
    reasons = []
    if candidates:
        reasons.append(f'{len(candidates)} image-derived components still need identification review.')
    if pending:
        reasons.append(f'{len(pending)} diagram interpretations remain unresolved.')
    if missing_topology:
        reasons.append('Image topology has not been reviewed for every source. Review connector direction, missing paths and deployment groups before treating this as a complete assessment.')
    if outdated:
        reasons.append('This report used an older image extractor. Re-import the original image to rebuild its component candidates.')
    return {'status': 'incomplete' if reasons else 'reviewed' if visual or extractions else 'not_applicable',
        'score_available': not reasons, 'reasons': reasons, 'pending_components': candidates,
        'pending_interpretations': len(pending), 'runtime_flow_count': len(architecture.flows),
        'connection_candidates': sum(r.get('kind') == 'unknown' for r in metadata.get('diagram_relationships', [])),
        'outdated_extraction': outdated}
