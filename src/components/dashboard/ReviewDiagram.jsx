import { useEffect, useRef, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';

export default function ReviewDiagram({ code, darkMode, bindings, onSelect }) {
  const canvas = useRef(null);
  const viewport = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [error, setError] = useState('');
  const selection = useRef({ bindings, onSelect });
  useEffect(() => { selection.current = { bindings, onSelect }; }, [bindings, onSelect]);
  useEffect(() => {
    let cancelled = false;
    let observer;
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
          node.style.cursor = 'pointer';
          node.addEventListener('click', (event) => { event.stopPropagation(); selection.current.onSelect?.(ids); });
          node.addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); selection.current.onSelect?.(ids); } });
        };
        root.querySelectorAll('.node').forEach((node) => {
          const id = node.id.replace(`${renderId}-`, '');
          const matches = (selection.current.bindings?.nodes || []).filter((item) => id.startsWith(`flowchart-${item.diagram_id}-`));
          if (matches.length === 1) wire(node, [matches[0].element_id], `Inspect component ${node.textContent.replace(/\s+/g, ' ').trim()}`);
        });
        root.querySelectorAll('.flowchart-link').forEach((node) => {
          const id = node.id.replace(`${renderId}-`, '');
          const matches = (selection.current.bindings?.flows || []).filter((item) => id.startsWith(`L_${item.source}_${item.target}_`));
          wire(node, matches.map((item) => item.element_id), 'Inspect data flow evidence');
        });
        root.dataset.theme = darkMode ? 'dark' : 'light';
        const box = root.viewBox.baseVal;
        root.style.maxWidth = 'none';
        root.style.display = 'block';
        root.style.margin = '0 auto';
        const fitDiagram = () => {
          if (!viewport.current || !box.width || !box.height) return;
          const fit = Math.min((viewport.current.clientWidth - 32) / box.width, (viewport.current.clientHeight - 32) / box.height, 1);
          root.style.width = `${box.width * fit}px`;
          root.style.height = `${box.height * fit}px`;
        };
        fitDiagram();
        observer = new ResizeObserver(fitDiagram);
        observer.observe(viewport.current);
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
    if (code) render();
    return () => { cancelled = true; observer?.disconnect(); };
  }, [code, darkMode]);
  useEffect(() => {
    const node = viewport.current;
    const wheel = (event) => { event.preventDefault(); setZoom((z) => Math.max(0.5, Math.min(3, z + (event.deltaY < 0 ? 0.1 : -0.1)))); };
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
  return <div className="my-5 border-y border-brand-200 dark:border-brand-700">
    <div className="flex items-center justify-between py-2">
      <h3 className="text-sm font-semibold">Draft data flow</h3>
      <div className="flex items-center gap-2">
        <button type="button" className="ui-button-secondary p-2" title="Zoom out draft diagram" aria-label="Zoom out draft diagram" onClick={() => setZoom((z) => Math.max(.5, z - .1))}><ZoomOut size={16} /></button>
        <span className="w-12 text-center text-xs tabular-nums">{Math.round(zoom * 100)}%</span>
        <button type="button" className="ui-button-secondary p-2" title="Zoom in draft diagram" aria-label="Zoom in draft diagram" onClick={() => setZoom((z) => Math.min(3, z + .1))}><ZoomIn size={16} /></button>
        <button type="button" className="ui-button-secondary p-2" title="Fit draft diagram" aria-label="Fit draft diagram" onClick={() => setZoom(1)}><RotateCcw size={16} /></button>
      </div>
    </div>
    <div ref={viewport} className="h-[420px] overflow-auto bg-brand-50 p-4 dark:bg-brand-900 cursor-grab" aria-label="Draft architecture diagram">
      {error && <p role="status" className="text-sm">{error}</p>}
      <div ref={canvas} hidden={!!error} style={{ zoom, width: 'max-content', minWidth: '100%' }} />
    </div>
  </div>;
}
