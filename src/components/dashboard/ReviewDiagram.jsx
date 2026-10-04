import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, Focus } from 'lucide-react';
import { clampDiagramZoom, fitDiagramZoom, MIN_DIAGRAM_ZOOM, MAX_DIAGRAM_ZOOM } from '../../utils/diagramViews';

const DiagramLayoutEditor = lazy(() => import('./DiagramLayoutEditor'));

export default function ReviewDiagram({ code, darkMode, bindings, onSelect, architecture, layout, onLayoutChange, selectedIds = [] }) {
  const canvas = useRef(null);
  const viewport = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('dfd');
  const zoomRef = useRef(1);
  const anchor = useRef(null);
  const selection = useRef({ bindings, onSelect });
  useEffect(() => { selection.current = { bindings, onSelect }; }, [bindings, onSelect]);
  const selected = useRef(selectedIds);
  useEffect(() => {
    selected.current = selectedIds;
    canvas.current?.querySelectorAll('[data-element-ids]').forEach(node => {
      node.style.outline = JSON.parse(node.dataset.elementIds).some(id => selectedIds.includes(id)) ? '2px solid #0891b2' : '';
      node.style.outlineOffset = '3px';
    });
  }, [selectedIds]);
  useEffect(() => {
    let cancelled = false;
    async function render() {
      try {
        const { default: mermaid } = await import('mermaid');
        if (cancelled) return;
        mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', theme: darkMode ? 'dark' : 'default' });
        const renderId = `review-${crypto.randomUUID()}`;
        const { svg } = await mermaid.render(renderId, code);
        if (cancelled || !canvas.current) return;
        canvas.current.innerHTML = svg;
        const root = canvas.current.querySelector('svg');
        const wire = (node, ids, label) => {
          if (!ids.length) return;
          node.setAttribute('tabindex', '0');
          node.setAttribute('role', 'button');
          node.setAttribute('aria-label', label);
          node.dataset.elementIds = JSON.stringify(ids);
          node.style.outline = ids.some(id => selected.current.includes(id)) ? '2px solid #0891b2' : '';
          node.style.outlineOffset = '3px';
          node.style.cursor = 'pointer';
          node.addEventListener('click', (event) => { event.stopPropagation(); selection.current.onSelect?.(ids); });
          node.addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); selection.current.onSelect?.(ids); } });
        };
        root.querySelectorAll('.node').forEach((node) => {
          const id = node.id.replace(`${renderId}-`, '');
          const matches = (selection.current.bindings?.nodes || []).filter((item) => id.startsWith(`flowchart-${item.diagram_id}-`));
          if (matches.length === 1) wire(node, [matches[0].element_id], `Inspect component ${node.textContent.replace(/\s+/g, ' ').trim()}`);
        });
        root.querySelectorAll('.flowchart-link').forEach((node, index) => {
          const id = node.id.replace(`${renderId}-`, '');
          const matches = (selection.current.bindings?.flows || []).filter((item) => id.startsWith(`L_${item.source}_${item.target}_`));
          const ordered = selection.current.bindings?.flows?.[index];
          const ids = ordered && matches.includes(ordered) ? [ordered.element_id] : matches.length === 1 ? [matches[0].element_id] : [];
          wire(node, ids, 'Inspect data flow evidence');
        });
        root.dataset.theme = darkMode ? 'dark' : 'light';
        const box = root.viewBox.baseVal;
        root.style.maxWidth = 'none';
        root.style.display = 'block';
        root.style.margin = '0 auto';
        root.dataset.baseWidth = String(box.width || 900);
        root.dataset.baseHeight = String(box.height || 420);
        root.style.width = `${root.dataset.baseWidth}px`;
        root.style.height = `${root.dataset.baseHeight}px`;
        root.style.maxHeight = 'none';
        anchor.current = null;
        const fitted = viewport.current ? Math.min(1, fitDiagramZoom(Number(root.dataset.baseWidth), Number(root.dataset.baseHeight), viewport.current.clientWidth - 32, viewport.current.clientHeight - 32)) : 1;
        zoomRef.current = fitted;
        root.style.width = `${Number(root.dataset.baseWidth) * fitted}px`;
        root.style.height = `${Number(root.dataset.baseHeight) * fitted}px`;
        setZoom(fitted);
        viewport.current?.scrollTo(0, 0);
        if (darkMode) {
          root.querySelectorAll('.cluster rect').forEach((n) => {
            n.style.setProperty('fill', '#18202c', 'important');
            n.style.setProperty('stroke', '#8897aa', 'important');
          });
          root.querySelectorAll('.node rect, .node circle, .node ellipse, .node path, .node polygon').forEach((n) => {
            n.style.setProperty('fill', '#252f3d', 'important');
            n.style.setProperty('stroke', '#cbd5e1', 'important');
          });
          root.querySelectorAll('text, .nodeLabel, .nodeLabel *, .cluster-label *, .edgeLabel *').forEach((n) => {
            n.style.setProperty('color', '#f1f5f9', 'important');
            n.style.setProperty('fill', '#f1f5f9', 'important');
          });
          root.querySelectorAll('.flowchart-link, .edgePath path').forEach((n) => {
            n.style.setProperty('stroke', '#d4dee9', 'important');
          });
          root.querySelectorAll('marker path, .arrowMarkerPath').forEach((n) => {
            n.style.setProperty('stroke', '#d4dee9', 'important');
            n.style.setProperty('fill', '#d4dee9', 'important');
          });
          root.querySelectorAll('.edgeLabel, .edgeLabel p, .edgeLabel span').forEach((n) => {
            n.style.setProperty('background-color', '#18202c', 'important');
          });
        }
        setError('');
      } catch {
        if (!cancelled) setError('Diagram unavailable. The component and flow tables remain available.');
      }
    }
    if (code && mode === 'dfd') render();
    return () => { cancelled = true; };
  }, [code, darkMode, mode]);
  useEffect(() => {
    zoomRef.current = zoom;
    const root = canvas.current?.querySelector('svg');
    if (root) {
      root.style.width = `${Number(root.dataset.baseWidth) * zoom}px`;
      root.style.height = `${Number(root.dataset.baseHeight) * zoom}px`;
    }
    if (anchor.current && viewport.current) {
      const point = anchor.current;
      viewport.current.scrollLeft = point.left * zoom / point.zoom - point.x;
      viewport.current.scrollTop = point.top * zoom / point.zoom - point.y;
      anchor.current = null;
    }
  }, [zoom]);
  useEffect(() => {
    const node = viewport.current;
    const wheel = (event) => {
      event.preventDefault();
      const rect = node.getBoundingClientRect();
      const x = event.clientX - rect.left; const y = event.clientY - rect.top;
      anchor.current = { left: node.scrollLeft + x, top: node.scrollTop + y, x, y, zoom: zoomRef.current };
      setZoom(z => clampDiagramZoom(z * (event.deltaY < 0 ? 1.15 : 1 / 1.15)));
    };
    node.addEventListener('wheel', wheel, { passive: false });
    let drag;
    const down = (event) => { if (event.button === 0 && !event.target.closest('[role="button"]')) { drag = [event.clientX, event.clientY, node.scrollLeft, node.scrollTop]; node.setPointerCapture(event.pointerId); } };
    const move = (event) => { if (drag) { node.scrollLeft = drag[2] + drag[0] - event.clientX; node.scrollTop = drag[3] + drag[1] - event.clientY; } };
    const up = () => { drag = null; };
    node.addEventListener('pointerdown', down);
    node.addEventListener('pointermove', move);
    node.addEventListener('pointerup', up);
    node.addEventListener('pointercancel', up);
    return () => { node.removeEventListener('wheel', wheel); node.removeEventListener('pointerdown', down); node.removeEventListener('pointermove', move); node.removeEventListener('pointerup', up); node.removeEventListener('pointercancel', up); };
  }, []);
  const fit = () => {
    const root = canvas.current?.querySelector('svg'); const node = viewport.current;
    if (!root || !node) return;
    anchor.current = null;
    setZoom(fitDiagramZoom(Number(root.dataset.baseWidth), Number(root.dataset.baseHeight), node.clientWidth - 32, node.clientHeight - 32));
    node.scrollTo(0, 0);
  };
  return <div className="my-5 border-y border-brand-200 dark:border-brand-700">
    <div className="flex flex-wrap items-center justify-between gap-3 py-2">
      <h3 className="text-sm font-semibold">Draft data flow</h3>
      {architecture && <div className="flex gap-1" aria-label="Diagram mode">{[['dfd', 'DFD'], ['layout', 'Layout']].map(([id, name]) => <button type="button" key={id} className={`border-b-2 px-3 py-2 text-sm ${mode === id ? 'border-brand-primary' : 'border-transparent'}`} aria-pressed={mode === id} onClick={() => setMode(id)}>{name}</button>)}</div>}
      {mode === 'dfd' && <div className="flex items-center gap-2">
        <button type="button" className="ui-button-secondary p-2" title="Zoom out draft diagram" aria-label="Zoom out draft diagram" disabled={zoom <= MIN_DIAGRAM_ZOOM} onClick={() => { anchor.current = null; setZoom(z => clampDiagramZoom(z * .8)); }}><ZoomOut size={16} /></button>
        <output aria-label="Draft diagram zoom" className="w-12 text-center text-xs tabular-nums">{zoom < .1 ? (zoom * 100).toFixed(1) : Math.round(zoom * 100)}%</output>
        <button type="button" className="ui-button-secondary p-2" title="Zoom in draft diagram" aria-label="Zoom in draft diagram" disabled={zoom >= MAX_DIAGRAM_ZOOM} onClick={() => { anchor.current = null; setZoom(z => clampDiagramZoom(z * 1.25)); }}><ZoomIn size={16} /></button>
        <button type="button" className="ui-button-secondary p-2" title="Fit draft diagram" aria-label="Fit draft diagram" onClick={fit}><RotateCcw size={16} /></button>
        <button type="button" className="ui-button-secondary p-2" title="Actual draft diagram size" aria-label="Actual draft diagram size" onClick={() => { anchor.current = null; setZoom(1); }}><Focus size={16} /></button>
      </div>}
    </div>
    <div ref={viewport} hidden={mode !== 'dfd'} className="h-[420px] overflow-auto bg-brand-50 p-4 dark:bg-brand-900 cursor-grab" aria-label="Draft architecture diagram">
      {error && <p role="status" className="text-sm">{error}</p>}
      <div ref={canvas} hidden={!!error} style={{ width: 'max-content', minWidth: '100%' }} />
    </div>
    {mode === 'layout' && architecture && <Suspense fallback={<p role="status" className="py-5 text-sm">Loading layout...</p>}><DiagramLayoutEditor architecture={architecture} layout={layout} onChange={onLayoutChange} darkMode={darkMode} onSelect={onSelect} /></Suspense>}
  </div>;
}
