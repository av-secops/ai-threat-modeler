export function diagramQuality(data) {
  if (data?.engine_status?.diagram_quality) return data.engine_status.diagram_quality;
  const architecture = data?.architecture || {};
  const metadata = architecture.metadata || {};
  const components = architecture.components || [];
  const pending = components.filter(c => c.properties?.diagram_review_required);
  const tasks = metadata.diagram_review_tasks || [];
  const unresolved = tasks.filter(t => t.status === 'pending');
  const visual = components.some(c => /^diagram:(ocr|visual):/.test(c.id));
  const extractions = [...(metadata.diagram_extractions || []), ...(metadata.diagram_extraction ? [metadata.diagram_extraction] : [])];
  const raster = extractions.filter(e => ['ocr_only', 'ocr_vision'].includes(e.method));
  const outdated = raster.some(e => (e.version || 1) < 2);
  const reviewed = new Set(tasks.filter(t => t.kind === 'topology' && t.status === 'reviewed').map(t => t.source_id));
  const missing = raster.some(e => !reviewed.has(e.source_id)) ||
    (visual && components.length > 1 && !architecture.flows?.length && !reviewed.size);
  const reasons = [pending.length && `${pending.length} image-derived components need identification review.`,
    unresolved.length && `${unresolved.length} diagram interpretations remain unresolved.`,
    missing && 'Review the topology and original connectors for every uploaded image.',
    outdated && 'Re-import the original image using the updated extractor.'].filter(Boolean);
  return { status: reasons.length ? 'incomplete' : 'not_applicable', score_available: !reasons.length, reasons, outdated_extraction: outdated };
}
