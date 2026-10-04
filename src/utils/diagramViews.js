export const MIN_DIAGRAM_ZOOM = 0.005;
export const MAX_DIAGRAM_ZOOM = 4;
export const clampDiagramZoom = value => Math.max(MIN_DIAGRAM_ZOOM, Math.min(MAX_DIAGRAM_ZOOM, Number.isNaN(value) ? 1 : value));
export const fitDiagramZoom = (width, height, availableWidth, availableHeight) =>
  clampDiagramZoom(Math.min(Math.max(1, availableWidth) / Math.max(1, width), Math.max(1, availableHeight) / Math.max(1, height), 1));

export const isAssumedFlow = flow => flow.assumed === true || flow.properties?.assumed === true;
export const flowKey = (flow, index) => flow.id || flow.properties?.review_id || `flow-index:${index}`;
const label = value => String(value || '').slice(0, 160).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', "'").replaceAll('|', '/').replace(/[\r\n]/g, ' ');

export async function canonicalDiagramId(id) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id));
  return 'n_' + [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

/** A display-only slice of existing model edges. Never infer a connection. */
export function focusedDiagram(architecture, { flowId = '', componentId = '', threats = [] } = {}) {
  if (!flowId && !componentId) return null;
  const components = architecture?.components || [];
  const flows = architecture?.flows || [];
  const relationships = (architecture?.metadata?.diagram_relationships || []).filter(r => r.kind === 'unknown');
  const ids = new Set(components.map(c => c.id));
  const indexes = flows.map((f, i) => ({ f, i })).filter(({ f, i }) =>
    (flowId ? flowKey(f, i) === flowId : f.source_id === componentId || f.target_id === componentId)
    && ids.has(f.source_id) && ids.has(f.target_id));
  const wanted = new Set(componentId && ids.has(componentId) ? [componentId] : []);
  for (const { f } of indexes) { wanted.add(f.source_id); wanted.add(f.target_id); }
  const related = componentId ? relationships.filter(r => r.source_id === componentId || r.target_id === componentId) : [];
  for (const r of related) {
    if (ids.has(r.source_id) && ids.has(r.target_id)) { wanted.add(r.source_id); wanted.add(r.target_id); }
  }
  const selected = components.filter(c => wanted.has(c.id)).sort((a, b) =>
    Number(b.id === componentId) - Number(a.id === componentId) || a.id.localeCompare(b.id)).slice(0, 80);
  const visible = new Set(selected.map(c => c.id));
  const shown = indexes.filter(({ f }) => visible.has(f.source_id) && visible.has(f.target_id)).slice(0, 120);
  const nodes = selected.map((c, i) => ({ diagram_id: `focus_n${i}`, element_id: c.id }));
  const nodeIds = new Map(nodes.map(n => [n.element_id, n.diagram_id]));
  const boundaries = [...(architecture?.trust_boundaries || []),
    ...(architecture?.metadata?.diagram_groups || []).map(b => ({ ...b, kind: 'deployment', name: `${b.name} (deployment)` }))]
    .map((b, i) => ({ ...b, key: b.id || `boundary-index:${i}` }));
  const byBoundary = new Map(boundaries.map(b => [b.key, b]));
  const ancestors = key => {
    const seen = new Set([key]); const result = [];
    let parent = byBoundary.get(key)?.parent_id;
    while (byBoundary.has(parent) && !seen.has(parent)) {
      result.push(parent); seen.add(parent); parent = byBoundary.get(parent)?.parent_id;
    }
    return result;
  };
  const membership = new Map(components.map(c => {
    const matching = boundaries.filter(b => (b.components || []).includes(c.id));
    const trust = matching.filter(b => b.kind !== 'deployment');
    const own = (trust.length ? trust : matching).map(b => b.key);
    return [c.id, [...new Set(own.flatMap(key => [key, ...ancestors(key)]))].sort()];
  }));
  const groups = new Map();
  const nodeGroups = new Map();
  for (const c of selected) {
    const belongs = membership.get(c.id);
    const parents = new Set(belongs.flatMap(ancestors));
    const leaves = belongs.filter(key => !parents.has(key));
    // Overlapping zones are explicitly named, not collapsed into a false parent.
    const key = leaves.length === 1 ? leaves[0] : leaves.length ? `overlap:${JSON.stringify(leaves)}` : 'unassigned';
    if (!groups.has(key)) groups.set(key, { name: leaves.length === 1 ? byBoundary.get(key).name :
      leaves.length ? 'Overlapping boundaries: ' + leaves.map(id => byBoundary.get(id).name).join(' / ') : 'Unassigned boundary',
    parent: leaves.length === 1 ? byBoundary.get(key).parent_id : null,
    deployment: leaves.length === 1 && byBoundary.get(key).kind === 'deployment' });
    nodeGroups.set(c.id, key);
    for (const ancestor of (leaves.length === 1 ? ancestors(leaves[0]) : [])) if (!groups.has(ancestor)) {
      const b = byBoundary.get(ancestor); groups.set(ancestor, { name: b.name, parent: b.parent_id, deployment: b.kind === 'deployment' });
    }
  }
  const lines = ['flowchart LR', '%% Focused view of modeled components and flows; omitted items are not deleted.'];
  const emitted = new Set();
  const groupIds = new Map([...groups.keys()].map((key, i) => [key, `focus_b${i}`]));
  const emit = key => {
    if (emitted.has(key)) return;
    emitted.add(key);
    lines.push(`subgraph ${groupIds.get(key)}["${label(groups.get(key).name)}"]`);
    for (const [child, group] of groups) if (group.parent === key) emit(child);
    for (const c of selected.filter(c => nodeGroups.get(c.id) === key)) {
      const kind = c.type?.toLowerCase() || '';
      const external = ['external', 'third_party'].includes(c.trust_level) || /external|identity provider/.test(kind);
      const shape = external ? ['[', ']'] : /database|storage|cache|queue/.test(kind) ? ['[(', ')]'] : ['((', '))'];
      lines.push(`${nodeIds.get(c.id)}${shape[0]}"${label(c.name)}"${shape[1]}`);
    }
    lines.push('end', `style ${groupIds.get(key)} fill:transparent,stroke:#64748b${groups.get(key).deployment ? '' : ',stroke-dasharray:5 5'}`);
  };
  for (const [key, group] of groups) if (!groups.has(group.parent)) emit(key);
  for (const key of groups.keys()) emit(key);
  for (const { f } of shown) {
    const source = components.find(c => c.id === f.source_id);
    const target = components.find(c => c.id === f.target_id);
    const left = source.properties || {}; const right = target.properties || {};
    const trustKeys = id => membership.get(id).filter(key => byBoundary.get(key)?.kind !== 'deployment');
    const crossing = JSON.stringify(trustKeys(f.source_id)) !== JSON.stringify(trustKeys(f.target_id)) ||
      source.trust_level !== target.trust_level ||
      (Array.isArray(left.canonical_boundaries) && Array.isArray(right.canonical_boundaries) &&
        JSON.stringify([...new Set(left.canonical_boundaries)].sort()) !== JSON.stringify([...new Set(right.canonical_boundaries)].sort())) ||
      ['trust_boundary', 'cloud_account', 'tenant_id', 'environment'].some(key => left[key] && right[key] && left[key] !== right[key]);
    const arrow = isAssumedFlow(f) ? '-.->' : crossing ? '==>' : '-->';
    lines.push(`${nodeIds.get(f.source_id)} ${arrow}|"${label(`${f.flow_number ? f.flow_number + ': ' : ''}${f.description || `${f.protocol || 'Unknown protocol'} / ${f.data_type || 'Unspecified data'}`}${isAssumedFlow(f) ? ' (assumed)' : ''}`)}"| ${nodeIds.get(f.target_id)}`);
  }
  const shownRelationships = related.filter(r => visible.has(r.source_id) && visible.has(r.target_id)).slice(0, 120);
  for (const r of shownRelationships) lines.push(`${nodeIds.get(r.source_id)} -.-|"Connection needs review"| ${nodeIds.get(r.target_id)}`);
  const confirmed = new Set(threats.filter(t => t.tier === 'Confirmed').flatMap(t => [t.component, ...(t.affected_components || [])]));
  for (const c of selected) if (confirmed.has(c.id)) lines.push(`style ${nodeIds.get(c.id)} stroke:#dc2626,stroke-width:3px`);
  if (!selected.length) lines.push('empty["No modeled elements match this selection"]');
  return { diagram: lines.join('\n'), nodes, flows: shown.map(({ f }) => f), indexes: shown.map(({ i }) => i),
    coverage: { components_in_model: components.length, components_drawn: selected.length,
      flows_in_model: flows.length, flows_drawn: shown.length, component_ids: selected.map(c => c.id),
      relationships_drawn: shownRelationships.length, deployment_groups_drawn: [...groups.values()].filter(g => g.deployment).length,
      flow_indexes: shown.map(({ i }) => i), components_hidden_for_readability: wanted.size - selected.length,
      flows_hidden_for_readability: indexes.length - shown.length, complete: selected.length === components.length && shown.length === flows.length } };
}
