import { useState } from 'react';
import { ChevronLeft, ChevronRight, Eye } from 'lucide-react';
import { flowKey, isAssumedFlow } from '../../utils/diagramViews';
import FilterBar from '../FilterBar';

export default function ArchitectureFlowTable({ architecture, onSelect }) {
  const [search, setSearch] = useState('');
  const [basis, setBasis] = useState('all');
  const [page, setPage] = useState(0);
  const names = new Map((architecture?.components || []).map(c => [c.id, c.name]));
  const all = architecture?.flows || [];
  const flows = all.map((f, i) => ({ ...f, key: flowKey(f, i) })).filter(f =>
    (basis === 'all' || isAssumedFlow(f) === (basis === 'assumed')) &&
    [f.flow_number, f.description, names.get(f.source_id), names.get(f.target_id), f.source_id, f.target_id, f.protocol, f.data_type]
      .join(' ').toLowerCase().includes(search.trim().toLowerCase()));
  const pages = Math.max(1, Math.ceil(flows.length / 15));
  const current = Math.min(page, pages - 1);
  const active = [];
  if (basis !== 'all') active.push({ key: 'basis', label: `Basis: ${basis === 'assumed' ? 'Assumed' : 'Not marked assumed'}`, onRemove: () => { setBasis('all'); setPage(0); } });
  if (search) active.push({ key: 'search', label: `Search: ${search}`, onRemove: () => { setSearch(''); setPage(0); } });
  return <section aria-label="Modeled data flows" className="min-w-0 py-3">
    <FilterBar label="Flow filters" resetLabel="Reset flow filters" active={active} onReset={() => { setSearch(''); setBasis('all'); setPage(0); }} search={{ label: 'Search modeled flows', placeholder: 'Flow number, component or protocol', value: search, onChange: value => { setSearch(value); setPage(0); } }}>
    <div className="max-w-xs">
      <label className="min-w-0 text-xs">Flow basis<select aria-label="Flow basis" className="input-brand mt-1 block w-full" value={basis} onChange={e => { setBasis(e.target.value); setPage(0); }}><option value="all">All flows</option><option value="not-assumed">Not marked assumed</option><option value="assumed">Assumed</option></select></label>
    </div></FilterBar>
    <p role="status" className="py-3 text-xs">{flows.length} of {all.length} flows</p>
    <div className="overflow-x-auto"><table aria-label="Data flow register" className="w-full min-w-[700px] table-fixed text-left text-sm">
      <thead className="border-b border-brand-200 text-xs dark:border-brand-700"><tr>{[['Flow', 'w-20'], ['From', ''], ['To', ''], ['Protocol / data', ''], ['Basis', 'w-28'], ['Trace', 'w-16']].map(([name, width]) => <th key={name} className={`p-2 ${width}`}>{name}</th>)}</tr></thead>
      <tbody>{flows.slice(current * 15, current * 15 + 15).map(f => <tr key={f.key} className="border-b border-brand-200 align-top dark:border-brand-700">
        <td className="break-words p-2 font-medium">{f.flow_number || 'Unnumbered'}</td><td className="break-words p-2">{names.get(f.source_id) || f.source_id}</td><td className="break-words p-2">{names.get(f.target_id) || f.target_id}</td>
        <td className="break-words p-2">{f.protocol || 'Unknown'} / {f.data_type || 'Unspecified'}{f.description && <p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{f.description}</p>}</td><td className="p-2 text-xs">{isAssumedFlow(f) ? 'Assumed' : 'Not marked assumed'}</td>
        <td className="p-2"><button type="button" className="ui-button-secondary p-2" title={`Trace ${f.flow_number || 'flow'}`} aria-label={`Trace ${f.flow_number || f.key}`} onClick={() => onSelect(f.key)}><Eye size={16} /></button></td>
      </tr>)}</tbody>
    </table></div>
    {!flows.length && <p className="py-5 text-sm">No flows match the current filters.</p>}
    <div className="mt-3 flex items-center justify-end gap-3 text-xs"><button type="button" className="ui-button-secondary p-2" aria-label="Previous flows" title="Previous flows" disabled={!current} onClick={() => setPage(current - 1)}><ChevronLeft size={16} /></button><span>Page {current + 1} of {pages}</span><button type="button" className="ui-button-secondary p-2" aria-label="Next flows" title="Next flows" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}><ChevronRight size={16} /></button></div>
  </section>;
}
