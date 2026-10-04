const normalize = value => String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
const sourceKey = item => item.evidence?.find(e => e.source_key)?.source_key || item.properties?.diagram_key;
const shape = (item, kind) => JSON.stringify(kind === 'components'
  ? [item.name, item.type, item.trust_level]
  : kind === 'flows' ? [item.source_id, item.target_id, item.description, item.protocol, item.assumed]
    : [item.name, [...(item.components || [])].sort(), item.parent_id]);

export function replaceDiagramSource(previous, replacement, edits = []) {
  const next = structuredClone(replacement);
  next.id = previous.id;
  const before = previous.metadata?.diagram_model;
  const after = next.metadata?.diagram_model;
  if (!before || !after) return { source: next, edits, suspended: [] };
  const remap = new Map();
  const used = new Set();
  for (const kind of ['components', 'flows', 'trust_boundaries']) {
    for (const item of after[kind] || []) {
      if (kind === 'flows') {
        item.source_id = remap.get(item.source_id) || item.source_id;
        item.target_id = remap.get(item.target_id) || item.target_id;
      }
      if (kind === 'trust_boundaries') item.components = item.components.map(id => remap.get(id) || id);
      const old = before[kind] || [];
      let matches = old.filter(c => sourceKey(c) && sourceKey(c) === sourceKey(item));
      if (!matches.length && kind === 'components') {
        const uniqueNew = after.components.filter(c => normalize(c.name) === normalize(item.name)).length === 1;
        if (uniqueNew) matches = old.filter(c => normalize(c.name) === normalize(item.name) && c.type === item.type);
      }
      if (!matches.length && kind === 'flows') matches = old.filter(c => c.source_id === item.source_id && c.target_id === item.target_id && c.description === item.description && c.protocol === item.protocol);
      if (!matches.length && kind === 'trust_boundaries') matches = old.filter(c => c.name === item.name && JSON.stringify([...c.components].sort()) === JSON.stringify([...item.components].sort()));
      if (matches.length === 1 && !used.has(matches[0].id)) {
        remap.set(item.id, matches[0].id);
        used.add(matches[0].id);
        item.id = matches[0].id;
      }
    }
  }
  for (const boundary of after.trust_boundaries || []) boundary.parent_id = remap.get(boundary.parent_id) || boundary.parent_id;
  for (const relation of after.metadata?.diagram_relationships || []) {
    relation.source_id = remap.get(relation.source_id) || relation.source_id;
    relation.target_id = remap.get(relation.target_id) || relation.target_id;
  }
  for (const issue of after.metadata?.diagram_issues || []) issue.element_id = remap.get(issue.element_id) || issue.element_id;
  const changed = new Set(), removed = new Set(), added = [];
  for (const kind of ['components', 'flows', 'trust_boundaries']) {
    const current = new Map((after[kind] || []).map(c => [c.id, c]));
    const old = new Map((before[kind] || []).map(c => [c.id, c]));
    for (const [id, item] of old) {
      if (!current.has(id)) removed.add(id);
      else if (shape(item, kind) !== shape(current.get(id), kind)) changed.add(id);
    }
    for (const [id, item] of current) if (!old.has(id)) added.push(item.name || item.description || id);
  }
  const suspended = edits.filter(e => changed.has(e.element_id) || removed.has(e.element_id)
    || ['source_id', 'target_id', 'merge_into'].includes(e.field) && (changed.has(e.value) || removed.has(e.value))
    || e.field === 'add_flow' && [e.value?.source_id, e.value?.target_id].some(id => changed.has(id) || removed.has(id))
    || e.field === 'components' && Array.isArray(e.value) && e.value.some(id => changed.has(id) || removed.has(id)));
  next.metadata.diagram_revision = { added, changed: [...changed], removed: [...removed],
    previous_artifact_hash: previous.metadata.artifact_hash, suspended_corrections: suspended.length };
  return { source: next, edits: edits.filter(e => !suspended.includes(e)), suspended };
}

export function diagramRegions(architecture, source, page) {
  const elements = [...(architecture?.trust_boundaries || []), ...(architecture?.flows || []), ...(architecture?.components || [])];
  return elements.flatMap(element => (element.evidence || []).filter(e => (e.source_id === source.id || source.name && e.document === source.name) && (e.page || 1) === page
    && Array.isArray(e.bbox) && e.bbox.length === 4 && e.bbox.every(Number.isFinite)
    && e.bbox[0] >= 0 && e.bbox[1] >= 0 && e.bbox[2] > 0 && e.bbox[3] > 0 && e.bbox[0] + e.bbox[2] <= 1.001 && e.bbox[1] + e.bbox[3] <= 1.001)
    .map(e => ({ elementId: element.id, name: element.name || element.description || 'Data flow', ...e })));
}
