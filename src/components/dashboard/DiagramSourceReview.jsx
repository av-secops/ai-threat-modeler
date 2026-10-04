import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Check, Eye, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import { diagramRegions } from '../../utils/diagramRevision';

export function DiagramSourceReview({ sources, architecture, selection = [], onSelect, onEvidence }) {
  const [choice, setChoice] = useState('');
  const [zoom, setZoom] = useState(1);
  const viewport = useRef(null);
  useEffect(() => {
    const node = viewport.current;
    if (!node) return undefined;
    const wheel = event => {
      if (!event.ctrlKey) return;
      event.preventDefault();
      setZoom(z => Math.min(4, Math.max(1, z * (event.deltaY < 0 ? 1.15 : 1 / 1.15))));
    };
    node.addEventListener('wheel', wheel, { passive: false });
    return () => node.removeEventListener('wheel', wheel);
  }, []);
  const images = sources.filter(s => s.included).flatMap(source => [
    ...(source.metadata?.source_preview ? [{ page: 1, image: source.metadata.source_preview }] : []),
    ...(source.metadata?.diagram_pages || []),
  ].filter(p => /^data:image\/(png|jpeg);base64,/.test(p.image)).map(p => ({ ...p, source, id: `${source.id}:${p.page}` })));
  const selectedImage = images.find(p => diagramRegions(architecture, p.source, p.page).some(r => selection.includes(r.elementId)));
  const current = images.find(p => p.id === choice.id && choice.selection === JSON.stringify(selection)) || selectedImage || images[0];
  if (!current) return null;
  const regions = diagramRegions(architecture, current.source, current.page);
  const unique = [...new Map(regions.map(r => [`${r.elementId}:${r.bbox.join(',')}`, r])).values()];
  return <section aria-label="Original architecture image" className="min-w-0 border border-brand-200 dark:border-brand-700 rounded-md overflow-hidden">
    <header className="flex flex-wrap items-center gap-2 border-b border-brand-200 p-3 dark:border-brand-700">
      <select aria-label="Diagram source page" className="input-brand min-w-0 flex-1 text-xs" value={current.id} onChange={e => { setChoice({ id: e.target.value, selection: JSON.stringify(selection) }); setZoom(1); }}>
        {images.map(p => <option key={p.id} value={p.id}>{p.source.name} - page {p.page}</option>)}
      </select>
      <button type="button" className="ui-button-secondary p-2" aria-label="Zoom out original image" title="Zoom out" disabled={zoom <= 1} onClick={() => setZoom(z => Math.max(1, z / 1.25))}><ZoomOut size={16} /></button>
      <button type="button" className="ui-button-secondary p-2" aria-label="Zoom in original image" title="Zoom in" disabled={zoom >= 4} onClick={() => setZoom(z => Math.min(4, z * 1.25))}><ZoomIn size={16} /></button>
      <button type="button" className="ui-button-secondary p-2" aria-label="Fit original image" title="Fit image" onClick={() => setZoom(1)}><RotateCcw size={16} /></button>
    </header>
    <div ref={viewport} className="h-[420px] overflow-auto bg-white p-2">
      <div className="relative" style={{ width: `${zoom * 100}%` }}>
        <img src={current.image} alt={`${current.source.name}, page ${current.page}`} className="block w-full h-auto" />
        {unique.map((r, i) => <button key={`${r.elementId}:${i}`} type="button" aria-label={`Source region: ${r.name}`} title={`${r.name}: ${r.extraction_method || 'diagram'}${r.region_alignment ? ' (approximate region)' : ''}`}
          onClick={() => { setChoice(''); onSelect([r.elementId]); }} className={`absolute border-2 ${selection.includes(r.elementId) ? 'border-cyan-700 bg-cyan-300/30' : 'border-transparent hover:border-cyan-700 hover:bg-cyan-200/20'} focus:border-cyan-700 focus:outline-none`}
          style={{ left: `${r.bbox[0]*100}%`, top: `${r.bbox[1]*100}%`, width: `${r.bbox[2]*100}%`, height: `${r.bbox[3]*100}%` }} />)}
      </div>
    </div>
    <footer className="flex flex-wrap items-center justify-between gap-2 p-3 text-xs border-t border-brand-200 dark:border-brand-700">
      <span>{selection.length ? unique.find(r => selection.includes(r.elementId))?.name || 'Selected element has no region on this page' : 'Source evidence'}{unique.some(r => r.region_alignment) ? ' | Approximate region alignment' : ''}</span>
      {!!selection.length && <button type="button" className="ui-button-secondary text-xs" onClick={() => onEvidence(selection)}><Eye size={14} />Evidence</button>}
    </footer>
  </section>;
}

const ACTIONS = { confirm: 'Confirm interpretation', exclude: 'Exclude from model', reverse: 'Reverse flow direction', dependency: 'Dependency only', forward_flow: 'Runtime flow: forward', reverse_flow: 'Runtime flow: reverse' };

function Decision({ task, onDecision, onSelect }) {
  const [action, setAction] = useState('');
  const [note, setNote] = useState('');
  return <form className="border-t border-brand-200 py-3 dark:border-brand-700" onSubmit={e => { e.preventDefault(); onDecision({ task_id: task.id, artifact_hash: task.artifact_hash, action, note: note.trim() }); }}>
    <div className="flex items-start justify-between gap-2"><h4 className="text-sm font-medium break-words">{task.question}</h4><button type="button" className="ui-button-secondary p-2 shrink-0" title="Locate in source image" aria-label={`Locate: ${task.question}`} onClick={() => onSelect([task.element_id])}><Eye size={15} /></button></div>
    <div className="mt-2 grid gap-2 sm:grid-cols-2"><select className="input-brand text-sm min-w-0" aria-label={`Interpretation: ${task.id}`} value={action} onChange={e => setAction(e.target.value)} required><option value="">Select interpretation</option>{task.actions.map(a => <option key={a} value={a}>{ACTIONS[a]}</option>)}</select>
      <input className="input-brand text-sm min-w-0" aria-label={`Review note: ${task.id}`} value={note} onChange={e => setNote(e.target.value)} placeholder="Reason for this decision" required minLength={3} maxLength={2000} /></div>
    <button className="ui-button-secondary mt-2 text-xs" type="submit" disabled={!action || note.trim().length < 3}><Check size={14} />Record decision</button>
  </form>;
}

export function DiagramQuestions({ tasks = [], onDecision, onSelect }) {
  const [page, setPage] = useState(0);
  const pending = tasks.filter(t => t.status === 'pending');
  const pages = Math.max(1, Math.ceil(pending.length / 5)), current = Math.min(page, pages - 1);
  if (!tasks.length) return null;
  return <section aria-label="Diagram interpretation review" className="my-4 border-y border-brand-200 py-4 dark:border-brand-700">
    <header className="flex flex-wrap justify-between gap-2"><h3 className="text-sm font-semibold">Diagram review</h3><span className="text-xs">{pending.length} pending | {tasks.filter(t => t.status === 'reviewed').length} reviewed</span></header>
    {pending.slice(current * 5, current * 5 + 5).map(task => <Decision key={`${task.id}:${task.artifact_hash}`} task={task} onDecision={onDecision} onSelect={onSelect} />)}
    {pages > 1 && <div className="flex items-center justify-end gap-2 mt-2"><button type="button" className="ui-button-secondary p-2" title="Previous diagram questions" aria-label="Previous diagram questions" disabled={!current} onClick={() => setPage(current - 1)}><ArrowLeft size={14} /></button><span className="text-xs">{current+1} / {pages}</span><button type="button" className="ui-button-secondary p-2" title="Next diagram questions" aria-label="Next diagram questions" disabled={current === pages-1} onClick={() => setPage(current+1)}><ArrowRight size={14} /></button></div>}
  </section>;
}
