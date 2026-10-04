import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import { Move, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';

export default function DiagramLayoutEditor({ architecture, layout = {}, onChange, darkMode, onSelect }) {
  const container = useRef(null);
  const graph = useRef(null);
  const callbacks = useRef({ onChange, onSelect, layout });
  useEffect(() => { callbacks.current = { onChange, onSelect, layout }; }, [onChange, onSelect, layout]);
  const topology = JSON.stringify({ components: architecture.components.map(c => ({ id: c.id, name: c.name, type: c.type })),
    flows: architecture.flows.map(f => ({ id: f.id, source: f.source_id, target: f.target_id, label: `${f.flow_number}: ${f.description || f.protocol}`, assumed: f.assumed })),
    boundaries: architecture.trust_boundaries });
  useEffect(() => {
    const model = JSON.parse(topology);
    const boundaries = new Map(model.boundaries.map(b => [b.id, b]));
    const ancestors = id => {
      const values = new Set(); let parent = boundaries.get(id)?.parent_id;
      while (parent && !values.has(parent)) { values.add(parent); parent = boundaries.get(parent)?.parent_id; }
      return values;
    };
    const nodes = model.components.map(c => {
      const memberOf = model.boundaries.filter(b => b.components.includes(c.id));
      const leaves = memberOf.filter(b => !memberOf.some(other => ancestors(other.id).has(b.id)));
      return { data: { id: c.id, label: c.name, parent: leaves.length === 1 ? `group:${leaves[0].id}` : undefined, kind: c.type },
        position: callbacks.current.layout[c.id] };
    });
    const parents = new Set(nodes.map(n => n.data.parent).filter(Boolean));
    for (const parent of [...parents]) for (const id of ancestors(parent.slice(6))) parents.add(`group:${id}`);
    const groups = model.boundaries.filter(b => parents.has(`group:${b.id}`)).map(b => ({ data: { id: `group:${b.id}`, label: b.name,
      parent: parents.has(`group:${b.parent_id}`) ? `group:${b.parent_id}` : undefined } }));
    const instance = cytoscape({ container: container.current, elements: [...groups, ...nodes, ...model.flows.map(f => ({
      data: { id: `edge:${f.id}`, source: f.source, target: f.target, label: f.label, flowId: f.id, assumed: f.assumed ? 1 : 0 } }))],
      minZoom: .2, maxZoom: 3, wheelSensitivity: .2,
      style: [
        { selector: 'node', style: { label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': 100, 'font-size': 12, color: darkMode ? '#f1f5f9' : '#17212e', 'background-color': darkMode ? '#263442' : '#ffffff', 'border-width': 1.5, 'border-color': darkMode ? '#cbd5e1' : '#334155', width: 95, height: 95, 'text-valign': 'center' } },
        { selector: 'node[kind = "Database"], node[kind = "Object Storage"]', style: { shape: 'barrel', width: 110, height: 65 } },
        { selector: 'node[kind = "External Entity"], node[kind = "Identity Provider"]', style: { shape: 'rectangle', width: 110, height: 60 } },
        { selector: ':parent', style: { shape: 'rectangle', 'background-opacity': 0, 'border-style': 'dashed', 'border-color': '#8291a3', padding: 32, 'text-valign': 'top', 'font-size': 13 } },
        { selector: 'edge', style: { label: 'data(label)', 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', width: 2, 'line-color': darkMode ? '#d3dce7' : '#526173', 'target-arrow-color': darkMode ? '#d3dce7' : '#526173', color: darkMode ? '#f1f5f9' : '#17212e', 'font-size': 10, 'text-wrap': 'wrap', 'text-max-width': 100, 'text-background-color': darkMode ? '#111827' : '#ffffff', 'text-background-opacity': 1, 'text-background-padding': 3 } },
        { selector: ':selected', style: { 'border-color': '#0d9488', 'line-color': '#0d9488', 'target-arrow-color': '#0d9488' } },
        { selector: 'edge[assumed = 1]', style: { 'line-style': 'dashed' } },
      ],
      layout: { name: nodes.every(n => n.position) ? 'preset' : 'breadthfirst', directed: true, spacingFactor: 1.8, padding: 35 },
    });
    graph.current = instance;
    instance.on('dragfree', 'node', () => callbacks.current.onChange?.(Object.fromEntries(instance.nodes().filter(n => !n.isParent()).map(n => [n.id(), n.position()]))));
    instance.on('tap', 'node', event => { if (!event.target.isParent()) callbacks.current.onSelect?.([event.target.id()]); });
    instance.on('tap', 'edge', event => callbacks.current.onSelect?.([event.target.data('flowId')]));
    const observer = new ResizeObserver(() => instance.resize()); observer.observe(container.current);
    return () => { observer.disconnect(); instance.destroy(); graph.current = null; };
  }, [topology, darkMode]);
  return <section aria-label="Editable DFD layout">
    <div className="flex items-center justify-between gap-3 py-2"><span className="flex items-center gap-2 text-sm"><Move size={16} />Layout</span><div className="flex gap-2">
      <button type="button" className="ui-button-secondary" title="Zoom out layout" aria-label="Zoom out layout" onClick={() => graph.current?.zoom(graph.current.zoom() / 1.2)}><ZoomOut size={16} /></button>
      <button type="button" className="ui-button-secondary" title="Zoom in layout" aria-label="Zoom in layout" onClick={() => graph.current?.zoom(graph.current.zoom() * 1.2)}><ZoomIn size={16} /></button>
      <button type="button" className="ui-button-secondary" title="Fit layout" aria-label="Fit layout" onClick={() => graph.current?.fit(undefined, 35)}><RotateCcw size={16} /></button>
      <button type="button" className="ui-button-secondary" onClick={() => { graph.current?.layout({ name: 'breadthfirst', directed: true, padding: 35, spacingFactor: 1.8 }).run(); callbacks.current.onChange?.(Object.fromEntries(graph.current.nodes().filter(n => !n.isParent()).map(n => [n.id(), n.position()]))); }}>Reset layout</button>
    </div></div>
    <div ref={container} className="h-[480px] w-full bg-white dark:bg-brand-900" aria-label="Drag component layout" />
  </section>;
}
