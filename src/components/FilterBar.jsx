import { useId, useRef, useState } from 'react';
import { Filter, RotateCcw, Search, X } from 'lucide-react';

/** Collapsing the controls never clears the active filters. */
export default function FilterBar({ label = 'Filters', resetLabel = 'Reset filters', active = [], onReset, search, children }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const trigger = useRef(null);
  const close = () => { setOpen(false); trigger.current?.focus(); };
  return <div className="min-w-0 space-y-3">
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      {search && <label className="relative min-w-0 flex-[1_1_220px] sm:max-w-md">
        <span className="sr-only">{search.label}</span><Search size={16} aria-hidden="true" className="pointer-events-none absolute left-3 top-3 text-brand-500 dark:text-brand-300" />
        <input type="search" className="input-brand w-full text-sm [&::-webkit-search-cancel-button]:hidden" style={{ paddingLeft: '2.25rem', paddingRight: '2.25rem' }} aria-label={search.label} placeholder={search.placeholder || search.label} value={search.value} onChange={event => search.onChange(event.target.value)} />
        {search.value && <button type="button" aria-label={`Clear ${search.label.toLowerCase()}`} title="Clear search" className="absolute right-1 top-1 rounded p-2 text-brand-600 hover:bg-brand-100 dark:text-brand-300 dark:hover:bg-brand-700" onClick={() => search.onChange('')}><X size={14} /></button>}
      </label>}
      <button ref={trigger} type="button" title={label} aria-label={label} aria-expanded={open} aria-controls={id} className={`ui-button-secondary h-10 gap-2 ${active.length ? 'border-brand-primary text-brand-primary dark:text-indigo-300' : ''}`} onClick={() => setOpen(value => !value)}>
        <Filter size={16} /><span className="text-sm">Filters</span>{active.length > 0 && <span className="min-w-5 text-xs font-semibold tabular-nums" aria-label={`${active.length} active filters`}>{active.length}</span>}
      </button>
      {active.length > 0 && <button type="button" className="ui-button-secondary h-10 p-2" aria-label={resetLabel} title={resetLabel} onClick={onReset}><RotateCcw size={16} /></button>}
    </div>
    {active.length > 0 && <ul aria-label={`Active ${label.toLowerCase()}`} className="flex min-w-0 flex-wrap gap-2">
      {active.map(item => <li key={item.key} className="flex max-w-full items-start gap-1 rounded border border-brand-200 bg-brand-50 pl-2 text-xs dark:border-brand-700 dark:bg-brand-800">
        <span className="min-w-0 break-words py-1.5">{item.label}</span><button type="button" title={`Remove ${item.label}`} aria-label={`Remove ${item.label}`} className="shrink-0 rounded p-1.5 hover:bg-brand-100 dark:hover:bg-brand-700" onClick={item.onRemove}><X size={14} /></button>
      </li>)}
    </ul>}
    <div id={id} hidden={!open} onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); close(); } }}>
      <section aria-label={label} className="border-y border-brand-200 py-4 dark:border-brand-700">
        <div className="mb-3 flex items-center justify-between gap-3"><h3 className="text-sm font-semibold">{label}</h3><button type="button" title="Close filters" aria-label={`Close ${label.toLowerCase()}`} className="ui-button-secondary p-2" onClick={close}><X size={16} /></button></div>
        {children}
      </section>
    </div>
  </div>;
}
