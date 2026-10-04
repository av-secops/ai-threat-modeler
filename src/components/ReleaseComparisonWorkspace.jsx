import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, GitCompareArrows, Save, FolderOpen, Download, Eye, X, RotateCcw, LoaderCircle, AlertTriangle, Link2, Check } from 'lucide-react';
import { enterprise } from '../services/enterprise';
import ReviewDiagram from './dashboard/ReviewDiagram';
import FilterBar from './FilterBar';
import WorkspaceNameDialog from './WorkspaceNameDialog';
import {
  CHANGE_LABELS, KIND_LABELS, REVIEW_LABELS, DEFAULT_FILTERS, revisionOptions, modelLabel, selectionError,
  scopeWarnings, comparisonCounts, filterChanges, reviewState, mappingError, sameMappings, reviewError,
  requestError, readableValue, readableField, comparisonDate, productPermissions,
} from '../utils/releaseComparison';

const input = 'input-brand w-full min-w-0 text-sm';
const muted = 'text-sm text-brand-600 dark:text-brand-300';
const border = 'border-brand-200 dark:border-brand-700';
const emptyRequest = { before_workspace: '', after_workspace: '', before_revision: 0, after_revision: 0 };
const tabs = [{ id: 'changes', name: 'Changes' }, { id: 'architecture', name: 'Architecture' },
  { id: 'matches', name: 'Component matches' }, { id: 'evidence', name: 'Evidence & analysis' }];
const noop = () => {};

export default function ReleaseComparisonWorkspace({ product, identity, darkMode, onClose }) {
  const [catalog, setCatalog] = useState(null);
  const [catalogError, setCatalogError] = useState('');
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogReload, setCatalogReload] = useState(0);
  const [request, setRequest] = useState(emptyRequest);
  const [computed, setComputed] = useState(null);
  const [saved, setSaved] = useState(null);
  const [savedList, setSavedList] = useState({ items: [], next_offset: null });
  const [listError, setListError] = useState('');
  const [savedChoice, setSavedChoice] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [tab, setTab] = useState('changes');
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState('');
  const [mappingDraft, setMappingDraft] = useState({});
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveError, setSaveError] = useState('');
  const action = useRef(null);
  const viewId = useId();
  const permissions = productPermissions(product, identity);
  const editable = permissions.edit && !product.archived;
  const reviewRole = !editable ? 'viewer' : permissions.admin ? 'admin' : 'editor';
  const result = computed?.result;
  const changes = result?.changes || [];
  const reviews = saved?.review || {};
  const selected = changes.find(row => row.id === selectedId);
  const counts = comparisonCounts(changes, reviews);
  const filtered = useMemo(() => filterChanges(computed?.result?.changes || [], filters, saved?.review || {}), [computed, filters, saved]);
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / 30)));
  const visible = filtered.slice((currentPage - 1) * 30, currentPage * 30);
  const invalidSelection = selectionError(request, catalog);
  const invalidMapping = mappingError(mappingDraft, result?.architectures);
  const mappingChanged = !sameMappings(mappingDraft, computed?.request?.component_mappings);
  const warnings = [...new Set([...(result?.warnings || []), ...scopeWarnings(computed?.request || request, catalog)])];

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      setCatalogLoading(true); setCatalogError('');
      try { const value = await enterprise(`/products/${product.id}/comparison-catalog`, 'GET', undefined, { signal: controller.signal }); if (!controller.signal.aborted) setCatalog(value); }
      catch (e) { if (!controller.signal.aborted) setCatalogError(requestError(e)); }
      finally { if (!controller.signal.aborted) setCatalogLoading(false); }
    };
    const loadSaved = async () => {
      try { const list = await enterprise(`/products/${product.id}/comparisons`, 'GET', undefined, { signal: controller.signal }); if (!controller.signal.aborted) { setSavedList(list); setListError(''); } }
      catch (e) { if (!controller.signal.aborted) setListError(requestError(e)); }
    };
    load(); loadSaved();
    return () => controller.abort();
  }, [product.id, catalogReload]);
  useEffect(() => () => action.current?.abort(), []);

  const perform = async (name, work, onError = e => setError(requestError(e))) => {
    if (action.current) return false;
    const controller = new AbortController();
    action.current = controller; setBusy(name); setError(''); setNotice('');
    try { await work(controller.signal); return true; }
    catch (e) { if (!controller.signal.aborted) onError(e); return false; }
    finally { if (!controller.signal.aborted) { action.current = null; setBusy(''); } }
  };
  const clearResult = () => { setComputed(null); setSaved(null); setSelectedId(''); setMappingDraft({}); setError(''); setNotice(''); };
  const chooseModel = (side, id) => {
    const model = catalog?.models?.find(row => row.id === id);
    setRequest(current => ({ ...current, [`${side}_workspace`]: id, [`${side}_revision`]: revisionOptions(model)[0]?.number || 0 }));
    clearResult();
  };
  const chooseRevision = (side, value) => { setRequest(current => ({ ...current, [`${side}_revision`]: Number(value) })); clearResult(); };
  const resetFilters = () => { setFilters(DEFAULT_FILTERS); setPage(1); };
  const updateFilter = (key, value) => { setFilters(current => ({ ...current, [key]: value })); setPage(1); };
  const compare = (mappings = {}) => {
    if (invalidSelection) { setError(invalidSelection); return; }
    const nextRequest = { before_workspace: request.before_workspace, after_workspace: request.after_workspace,
      before_revision: request.before_revision, after_revision: request.after_revision,
      ...(Object.keys(mappings).length ? { component_mappings: { ...mappings } } : {}) };
    perform('compare', async signal => {
      const nextResult = await enterprise('/compare', 'POST', nextRequest, { signal });
      if (signal.aborted) return;
      setComputed({ result: nextResult, request: nextRequest }); setSaved(null); setMappingDraft(mappings);
      setSelectedId(''); resetFilters(); setTab('changes'); setNotice('Comparison ready.');
    });
  };
  const acceptSnapshot = snapshot => {
    setSaved(snapshot); setComputed({ request: snapshot.request, result: snapshot.result });
    setRequest({ ...emptyRequest, ...snapshot.request }); setMappingDraft(snapshot.request.component_mappings || {});
    setSavedChoice(snapshot.id);
  };
  const openSaved = id => perform('open', async signal => {
    const snapshot = await enterprise(`/comparisons/${id}`, 'GET', undefined, { signal });
    if (signal.aborted) return;
    acceptSnapshot(snapshot); setSelectedId(''); resetFilters(); setTab('changes'); setNotice('Saved comparison opened.');
  });
  const reloadReview = onError => perform('reload', async signal => {
    const snapshot = await enterprise(`/comparisons/${saved.id}`, 'GET', undefined, { signal });
    if (!signal.aborted) { acceptSnapshot(snapshot); setNotice('Latest review loaded. Unsaved remarks are retained.'); }
  }, onError);
  const loadMore = () => perform('list', async signal => {
    const list = await enterprise(`/products/${product.id}/comparisons?offset=${savedList.next_offset}`, 'GET', undefined, { signal });
    if (!signal.aborted) { setSavedList(current => ({ ...list, items: [...new Map([...current.items, ...list.items].map(row => [row.id, row])).values()] })); setListError(''); }
  }, e => setListError(requestError(e)));
  const beginSave = () => {
    setSelectedId(''); setSaveError('');
    const name = side => catalog?.releases?.find(row => row.id === catalog?.models?.find(model => model.id === computed.request[`${side}_workspace`])?.release_id)?.name;
    setSaveName(saved?.name ? `${saved.name} (copy)` : `${name('before') || 'Baseline'} to ${name('after') || 'Target'}`);
    setSaveOpen(true);
  };
  const saveSnapshot = event => {
    event.preventDefault();
    if (!editable || !computed || mappingChanged) return;
    perform('save', async signal => {
      const snapshot = await enterprise(`/products/${product.id}/comparisons`, 'POST', { name: saveName.trim(), comparison: computed.request }, { signal });
      if (signal.aborted) return;
      acceptSnapshot(snapshot); setSaveOpen(false); setNotice('Comparison snapshot saved.');
      setSavedList(current => ({ ...current, items: [{ id: snapshot.id, name: snapshot.name, created: snapshot.created, version: snapshot.version }, ...current.items] }));
    }, e => setSaveError(requestError(e)));
  };
  const saveReview = (change, review, onError) => perform('review', async signal => {
    const snapshot = await enterprise(`/comparisons/${saved.id}/reviews/${change.id}`, 'PATCH', { ...review, expected_version: saved.version }, { signal });
    if (signal.aborted) return;
    acceptSnapshot(snapshot); setNotice('Review decision saved.'); setSelectedId('');
  }, onError);
  const exportComparison = () => {
    const data = saved || { request: computed.request, result };
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'release-comparison.json';
    document.body.appendChild(anchor); anchor.click(); anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const activeFilters = Object.entries(filters).filter(([key, value]) => key !== 'query' && value !== DEFAULT_FILTERS[key])
    .map(([key, value]) => ({ key, label: `${readableField(key)}: ${CHANGE_LABELS[value] || KIND_LABELS[value] || REVIEW_LABELS[value] || readableField(value)}`,
      onRemove: () => updateFilter(key, DEFAULT_FILTERS[key]) }));

  return <section className="min-w-0 space-y-6 text-brand-950 dark:text-white" aria-labelledby={`${viewId}-title`} aria-busy={!!busy}>
    <header className={`space-y-4 border-b pb-5 ${border}`}>
      <button className="inline-flex min-h-9 items-center gap-2 text-sm hover:underline" disabled={!!busy} onClick={onClose}><ArrowLeft size={16} />Back to releases</button>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0"><p className={`${muted} break-words`}>{product.name}</p><h1 id={`${viewId}-title`} className="mt-1 text-2xl font-semibold">Release comparison</h1></div>
        <button className="ui-button-secondary" title="Refresh available reports" disabled={!!busy || catalogLoading} onClick={() => setCatalogReload(value => value + 1)}><RotateCcw size={16} />Refresh reports</button>
      </div>
    </header>
    {catalogLoading && <p role="status" className="flex items-center gap-2 text-sm"><LoaderCircle size={16} className="animate-spin" />Loading available reports...</p>}
    {catalogError && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{catalogError}</p>}
    <details className={`border-b pb-4 ${border}`}>
      <summary className="min-h-9 cursor-pointer text-sm font-semibold">Saved comparisons ({savedList.items.length}{savedList.next_offset !== null ? '+' : ''})</summary>
      <div className="mt-3 flex min-w-0 flex-wrap items-end gap-3">
        <label className="grid min-w-0 flex-[1_1_240px] gap-2 text-sm sm:max-w-2xl">Saved comparison
          <select className={input} aria-label="Saved comparison" value={savedChoice} disabled={!!busy} onChange={event => setSavedChoice(event.target.value)}>
            <option value="">Select a saved comparison</option>{savedList.items.map(row => <option key={row.id} value={row.id}>{row.name} / {comparisonDate(row.created)}</option>)}
          </select>
        </label>
        <button className="ui-button-secondary" disabled={!!busy || !savedChoice} onClick={() => openSaved(savedChoice)}><FolderOpen size={16} />{busy === 'open' ? 'Opening...' : 'Open comparison'}</button>
        {savedList.next_offset !== null && <button className="ui-button-secondary" disabled={!!busy} onClick={loadMore}>Load more</button>}
      </div>
      {!savedList.items.length && !listError && <p className={`mt-3 ${muted}`}>No saved comparisons.</p>}
      {listError && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{listError}</p>}
    </details>
    <div className="grid min-w-0 items-end gap-5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      {['before', 'after'].map(side => {
        const title = side === 'before' ? 'Baseline report' : 'Target report';
        const model = catalog?.models?.find(row => row.id === request[`${side}_workspace`]);
        const options = revisionOptions(model);
        return <fieldset key={side} disabled={!!busy || catalogLoading} className="grid min-w-0 gap-3">
          <legend className="mb-3 text-sm font-semibold">{title}</legend>
          <label className="grid min-w-0 gap-2 text-sm">Threat model<select className={input} aria-label={title} value={request[`${side}_workspace`]} onChange={event => chooseModel(side, event.target.value)}>
            <option value="">Select a threat model</option>
            {request[`${side}_workspace`] && !model && <option value={request[`${side}_workspace`]}>Saved model (not in current catalog)</option>}
            {(catalog?.models || []).filter(row => revisionOptions(row).length).map(row => <option key={row.id} value={row.id}>{modelLabel(row, catalog)}</option>)}
          </select></label>
          <label className="grid gap-2 text-sm">Report version<select className={input} aria-label={`${title} version`} disabled={!model || !options.length} value={request[`${side}_revision`]} onChange={event => chooseRevision(side, event.target.value)}>
            {!options.some(row => row.number === request[`${side}_revision`]) && <option value={request[`${side}_revision`]}>{request[`${side}_revision`] ? `Saved version ${request[`${side}_revision`]}` : 'Select a version'}</option>}
            {options.map(row => <option key={row.number} value={row.number}>Version {row.number} / {comparisonDate(row.created_at)}</option>)}
          </select></label>
        </fieldset>;
      })}
    </div>
    <div className="flex flex-wrap items-center gap-3">
      <button className="btn-brand gap-2" disabled={!!busy || catalogLoading || !!invalidSelection} onClick={() => compare()}><GitCompareArrows size={17} />{busy === 'compare' ? 'Comparing...' : saved ? 'Run new comparison' : 'Compare reports'}</button>
      {catalog && !catalog.models?.some(model => revisionOptions(model).length) && <p className={muted}>No completed reports are available for this product.</p>}
      {!!request.before_workspace && !!request.after_workspace && invalidSelection && <p className={muted}>{invalidSelection}</p>}
    </div>
    {error && <p role="alert" className="border-l-4 border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950/30 dark:text-red-200">{error}</p>}
    {notice && <p role="status" className="text-sm text-emerald-800 dark:text-emerald-300">{notice}</p>}
    {!!warnings.length && <div className="flex items-start gap-3 border-l-4 border-amber-500 bg-amber-50 p-3 dark:bg-amber-950/20"><AlertTriangle size={18} aria-hidden="true" className="mt-0.5 shrink-0 text-amber-700 dark:text-amber-300" /><ul className="min-w-0 space-y-1 text-sm text-amber-900 dark:text-amber-200">{warnings.map(message => <li className="break-words" key={message}>{message}</li>)}</ul></div>}
    {result && <>
      <div className={`flex flex-wrap items-center justify-between gap-3 border-t pt-5 ${border}`}>
        <div className="min-w-0"><h2 className="break-words text-lg font-semibold">{saved?.name || 'Comparison results'}</h2><p className={`mt-1 ${muted}`}>{saved ? `Saved ${comparisonDate(saved.created)} / Review version ${saved.version}` : 'Unsaved comparison'}</p></div>
        <div className="flex flex-wrap gap-2">
          <button className="ui-button-secondary" title="Export comparison JSON" aria-label="Export comparison JSON" onClick={exportComparison}><Download size={16} /></button>
          {editable && <button className="ui-button-secondary" disabled={!!busy || mappingChanged} title={mappingChanged ? 'Apply or reset component mappings before saving' : undefined} onClick={beginSave}><Save size={16} />{saved ? 'Save as new comparison' : 'Save comparison'}</button>}
        </div>
      </div>
      <p className={muted}>{result.notice || 'No longer reported is not verified remediation. Review source evidence, scope and analysis provenance.'}</p>
      <dl className={`grid grid-cols-2 gap-x-6 gap-y-4 border-y py-4 sm:grid-cols-3 xl:grid-cols-6 ${border}`}>
        {[['New risks', counts.new, 'text-red-700 dark:text-red-300'], ['Worsened risks', counts.worsened, 'text-orange-700 dark:text-orange-300'],
          ['Improved risks', counts.improved, 'text-emerald-700 dark:text-emerald-300'], ['No longer reported', counts.no_longer_reported, ''],
          ['Architecture changes', counts.architecture, ''], ['Changes pending review', counts.pending_review, '']].map(([label, value, color]) => <div className="min-w-0" key={label}><dt className="break-words text-xs text-brand-600 dark:text-brand-300">{label}</dt><dd className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</dd></div>)}
      </dl>
      <div role="tablist" aria-label="Comparison views" className={`flex flex-wrap gap-x-6 gap-y-2 border-b ${border}`}>
        {tabs.map(item => <button key={item.id} id={`${viewId}-${item.id}`} type="button" role="tab" aria-selected={tab === item.id} aria-controls={`${viewId}-panel`} tabIndex={tab === item.id ? 0 : -1}
          onKeyDown={event => { const direction = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0; if (!direction && !['Home', 'End'].includes(event.key)) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (tabs.findIndex(t => t.id === tab) + direction + tabs.length) % tabs.length; setTab(tabs[next].id); document.getElementById(`${viewId}-${tabs[next].id}`)?.focus(); }}
          className={`min-h-11 border-b-2 pb-2 text-sm ${tab === item.id ? 'border-brand-primary font-semibold text-brand-950 dark:text-white' : 'border-transparent text-brand-600 hover:text-brand-950 dark:text-brand-300 dark:hover:text-white'}`} onClick={() => setTab(item.id)}>{item.name}</button>)}
      </div>
      <div id={`${viewId}-panel`} role="tabpanel" aria-labelledby={`${viewId}-${tab}`} className="min-w-0 space-y-5">
        {tab === 'changes' && <>
          <FilterBar label="Comparison filters" active={activeFilters} onReset={resetFilters} search={{ label: 'Search changes', value: filters.query, onChange: value => updateFilter('query', value) }}>
            <div className="grid min-w-0 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <FilterSelect label="Element" value={filters.kind} onChange={value => updateFilter('kind', value)} options={{ all: 'All elements', ...KIND_LABELS }} />
              <FilterSelect label="Change" value={filters.status} onChange={value => updateFilter('status', value)} options={{ changes: 'Exclude unchanged', all: 'All changes', ...CHANGE_LABELS }} />
              <FilterSelect label="Severity" value={filters.severity} onChange={value => updateFilter('severity', value)} options={{ all: 'All severities', Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low' }} />
              <FilterSelect label="Review" value={filters.review} onChange={value => updateFilter('review', value)} options={{ all: 'All review statuses', ...REVIEW_LABELS }} />
            </div>
          </FilterBar>
          <div className="flex flex-wrap justify-between gap-2 text-xs text-brand-600 dark:text-brand-300"><span>{filtered.length} of {changes.length} items</span><span>{counts.new_critical_high} new Critical / High risks / {counts.verified_fixed} verified fixed</span></div>
          {visible.length ? <div className="min-w-0 overflow-x-auto"><table aria-label="Release comparison changes" className="w-full min-w-[700px] table-fixed text-left text-sm">
            <thead className={`border-y bg-brand-50 text-xs text-brand-600 dark:bg-brand-800 dark:text-brand-300 ${border}`}><tr><th className="w-[35%] p-3" scope="col">Change</th><th className="w-[17%] p-3" scope="col">Outcome</th><th className="w-[13%] p-3" scope="col">Severity</th><th className="w-[25%] p-3" scope="col">Review</th><th className="w-[10%] p-3 text-right" scope="col">Details</th></tr></thead>
            <tbody>{visible.map(row => <tr key={row.id} className={`border-b hover:bg-brand-50 dark:hover:bg-brand-800/50 ${border}`}>
              <td className="break-words p-3"><button className="text-left font-medium hover:underline" onClick={() => setSelectedId(row.id)}>{row.title}</button><p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{KIND_LABELS[row.kind] || row.kind}{row.stride?.filter(Boolean).length ? ` / ${row.stride.filter(Boolean).join(', ')}` : ''}</p></td>
              <td className="break-words p-3"><ChangeStatus status={row.status} /></td><td className="p-3"><Severity value={row.severity} /></td>
              <td className="break-words p-3"><span>{REVIEW_LABELS[reviewState(row, reviews)] || reviewState(row, reviews)}</span>{reviews[row.id]?.reviewer && <p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{reviews[row.id].reviewer}</p>}</td>
              <td className="p-3 text-right"><button title="View change details" aria-label={`View details: ${row.title}`} className="ui-button-secondary p-2" onClick={() => setSelectedId(row.id)}><Eye size={16} /></button></td>
            </tr>)}</tbody>
          </table></div> : <div className={`border-y py-10 text-center ${border}`}><p className="text-sm">{changes.length ? 'No changes match these filters.' : 'No comparable elements were returned.'}</p>{changes.length > 0 && <button className="ui-button-secondary mt-3" onClick={() => { resetFilters(); updateFilter('status', 'all'); }}><RotateCcw size={16} />Show all items</button>}</div>}
          {filtered.length > 30 && <div className="flex items-center justify-end gap-3 text-sm"><button className="ui-button-secondary p-2" title="Previous changes" aria-label="Previous changes" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}><ArrowLeft size={16} /></button><span className="tabular-nums">{currentPage} / {Math.ceil(filtered.length / 30)}</span><button className="ui-button-secondary p-2" title="Next changes" aria-label="Next changes" disabled={currentPage * 30 >= filtered.length} onClick={() => setPage(currentPage + 1)}><ArrowRight size={16} /></button></div>}
        </>}
        {tab === 'architecture' && <>
          <div className="grid min-w-0 gap-6 xl:grid-cols-2">{['before', 'after'].map((side, index) => <section className="min-w-0 space-y-3" key={side}><h3 className="text-sm font-semibold">{index ? 'Target architecture' : 'Baseline architecture'}</h3><p className={`${muted} break-words`}>{snapshotLabel(computed.request, side, catalog)}</p>
            {result.diagrams?.[index] ? <ReviewDiagram code={result.diagrams[index]} darkMode={darkMode} bindings={{ nodes: [], flows: [] }} onSelect={noop} /> : <p className={`border-y py-8 ${border} ${muted}`}>No diagram was saved in this report.</p>}
            <p className={muted}>{result.architectures?.[side]?.components?.length || 0} components / {result.architectures?.[side]?.flows?.length || 0} flows</p>
          </section>)}</div>
          <section className={`space-y-3 border-t pt-4 ${border}`}><h3 className="text-sm font-semibold">Exposure and reachability changes</h3><p className={muted}>{result.impact?.notice || 'Modeled reachability does not prove exploitability.'}</p>
            {['added', 'removed'].map(kind => <div key={kind}><h4 className="text-xs font-semibold">{kind === 'added' ? 'Added paths or entry points' : 'Removed paths or entry points'}</h4><ul className={`mt-2 space-y-2 ${muted}`}>{result.impact?.[kind]?.length ? result.impact[kind].map((path, index) => <li key={index} className="break-words">{path.description}</li>) : <li>None reported</li>}</ul></div>)}
          </section>
        </>}
        {tab === 'matches' && <>
          <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-sm font-semibold">Component identity</h3><p className={muted}>{result.matches?.length || 0} matched / {result.mapping_suggestions?.length || 0} unmatched baseline components</p></div>
          <div className="min-w-0 overflow-x-auto"><table className="w-full min-w-[700px] table-fixed text-left text-sm" aria-label="Component mappings">
            <thead className={`border-y text-xs ${border}`}><tr><th className="w-[27%] p-3" scope="col">Baseline component</th><th className="w-[27%] p-3" scope="col">Current match</th><th className="w-[16%] p-3" scope="col">Match basis</th><th className="w-[30%] p-3" scope="col">Reviewer mapping</th></tr></thead>
            <tbody>{(result.architectures?.before?.components || []).map(row => {
              const match = result.matches?.find(item => item.before_id === row.id);
              const target = result.architectures?.after?.components?.find(item => item.id === match?.after_id);
              const suggestion = result.mapping_suggestions?.find(item => item.before_id === row.id);
              return <tr key={row.id} className={`border-b ${border}`}><td className="break-words p-3"><p className="font-medium">{row.name || row.id}</p><p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{row.type} / {row.id}</p></td><td className="break-words p-3">{target?.name || target?.id || 'Unmatched'}</td><td className="break-words p-3">{match ? readableField(match.method) : 'No match'}</td><td className="p-3"><select className={input} aria-label={`Map ${row.name || row.id}`} disabled={!!busy} value={mappingDraft[row.id] || ''} onChange={event => setMappingDraft(current => { const next = { ...current }; if (event.target.value) next[row.id] = event.target.value; else delete next[row.id]; return next; })}>
                <option value="">Automatic matching</option>{(result.architectures?.after?.components || []).map(item => <option key={item.id} value={item.id}>{item.name || item.id} / {item.type} / {item.id}</option>)}
              </select>{!!suggestion?.candidates?.length && <p className="mt-2 break-words text-xs text-brand-600 dark:text-brand-300">Candidate names: {suggestion.candidates.map(item => item.name || item.id).join(', ')}. Not automatically accepted.</p>}</td></tr>;
            })}</tbody>
          </table></div>
          {!(result.architectures?.before?.components || []).length && <p className={muted}>No baseline components are available to map.</p>}
          {invalidMapping && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{invalidMapping}</p>}
          {mappingChanged && <p role="status" className={muted}>Unapplied mappings. Existing saved results and reviews will remain unchanged.</p>}
          <div className="flex flex-wrap gap-3"><button className="btn-brand gap-2" disabled={!!busy || !mappingChanged || !!invalidMapping || !!invalidSelection} onClick={() => compare(mappingDraft)}><Link2 size={16} />Compare with mappings</button><button className="ui-button-secondary" disabled={!!busy || !mappingChanged} onClick={() => setMappingDraft(computed.request.component_mappings || {})}><RotateCcw size={16} />Reset mappings</button></div>
        </>}
        {tab === 'evidence' && <>
          <p className={muted}>{result.engine_changed ? 'Analysis configuration or knowledge changed between reports. Design changes alone may not explain the risk difference.' : 'Recorded analysis provenance matches. Missing metadata is not evidence of an identical analysis.'}</p>
          <div className="grid min-w-0 gap-6 lg:grid-cols-2">{['before', 'after'].map((side, index) => <section className="min-w-0 space-y-3" key={side}><h3 className="text-sm font-semibold">{side === 'before' ? 'Baseline analysis' : 'Target analysis'}</h3><p className={`${muted} break-words`}>{snapshotLabel(computed.request, side, catalog)}</p><Evidence value={{ ...result.provenance?.[side], ...(result.snapshots?.[index] ? { snapshot: result.snapshots[index] } : {}) }} /></section>)}</div>
          {!!result.revision_summary?.score_delta_explanation?.length && <ul className={`space-y-2 border-t pt-4 ${border} ${muted}`}>{result.revision_summary.score_delta_explanation.map((message, index) => <li key={index}>{message}</li>)}</ul>}
          <p className={muted}>{result.revision_summary?.revalidation_required?.length || 0} target findings require revalidation.</p>
        </>}
      </div>
    </>}
    {selected && <ChangeDetails key={`${saved?.id || 'draft'}-${selected.id}`} change={selected} result={result} snapshot={saved} role={reviewRole} busy={!!busy} onClose={() => setSelectedId('')} onSave={saveReview} onReload={reloadReview} onSaveSnapshot={beginSave} mappingChanged={mappingChanged} />}
    {saveOpen && <WorkspaceNameDialog title="Save comparison" label="Comparison name" value={saveName} onChange={value => { setSaveName(value); setSaveError(''); }} onSubmit={saveSnapshot} onClose={() => setSaveOpen(false)} busy={!!busy} error={saveError} action="Save snapshot" context="A new snapshot will be created. Previous saved comparisons will not be overwritten." />}
  </section>;
}

function snapshotLabel(request, side, catalog) {
  const model = catalog?.models?.find(row => row.id === request?.[`${side}_workspace`]);
  return `${model ? modelLabel(model, catalog) : request?.[`${side}_workspace`] || 'Saved model'} / Version ${request?.[`${side}_revision`] || '?'}`;
}

function FilterSelect({ label, value, options, onChange }) {
  return <label className="grid min-w-0 gap-2 text-sm">{label}<select aria-label={`Filter by ${label.toLowerCase()}`} className={input} value={value} onChange={event => onChange(event.target.value)}>{Object.entries(options).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></label>;
}

function ChangeStatus({ status }) {
  const color = { new: 'text-sky-800 dark:text-sky-300', improved: 'text-emerald-800 dark:text-emerald-300', worsened: 'text-red-800 dark:text-red-300' };
  return <span className={`text-xs font-medium ${color[status] || 'text-brand-700 dark:text-brand-200'}`}>{CHANGE_LABELS[status] || readableField(status)}</span>;
}

function Severity({ value }) {
  const color = { Critical: 'bg-red-50 text-red-800 dark:bg-red-950/60 dark:text-red-200', High: 'bg-orange-50 text-orange-800 dark:bg-orange-950/60 dark:text-orange-200', Medium: 'bg-amber-50 text-amber-800 dark:bg-amber-950/60 dark:text-amber-200', Low: 'bg-sky-50 text-sky-800 dark:bg-sky-950/60 dark:text-sky-200' };
  return value ? <span className={`inline-block rounded px-2 py-1 text-xs font-medium ${color[value] || ''}`}>{value}</span> : <span className="text-xs text-brand-500 dark:text-brand-400">Not applicable</span>;
}

function Evidence({ value, depth = 0 }) {
  if (Array.isArray(value)) {
    if (!value.length) return <span className={muted}>Not recorded</span>;
    if (value.every(item => item === null || typeof item !== 'object')) return <span className="whitespace-pre-wrap break-words">{value.map(readableValue).join(', ')}</span>;
    if (depth < 3) return <ul className="space-y-3">{value.map((item, index) => <li key={index}><Evidence value={item} depth={depth + 1} /></li>)}</ul>;
  }
  const entries = value && typeof value === 'object' && !Array.isArray(value) ? Object.entries(value) : [];
  if (!entries.length) return <p className={`${muted} whitespace-pre-wrap break-words`}>{value && typeof value === 'object' && !Array.isArray(value) ? 'Not recorded' : readableValue(value)}</p>;
  return <dl className={`divide-y text-sm ${border}`}>{entries.map(([key, content]) => <div key={key} className="min-w-0 py-2"><dt className="mb-1 text-xs font-medium text-brand-600 dark:text-brand-300">{readableField(key)}</dt><dd className="max-h-64 overflow-auto whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{content && typeof content === 'object' && depth < 3 ? <Evidence value={content} depth={depth + 1} /> : readableValue(content)}</dd></div>)}</dl>;
}

function ChangeDetails({ change, result, snapshot, role, busy, onClose, onSave, onReload, onSaveSnapshot, mappingChanged }) {
  const initial = snapshot?.review?.[change.id];
  const [draft, setDraft] = useState({ status: initial?.status || 'pending_review', remarks: initial?.remarks || '', evidence: initial?.evidence || '' });
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [reloaded, setReloaded] = useState(false);
  const dialog = useRef(null);
  const id = useId();
  const editable = ['editor', 'admin'].includes(role);
  const currentReview = snapshot?.review?.[change.id];
  useEffect(() => {
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden'; dialog.current?.focus();
    return () => { document.body.style.overflow = overflow; if (previous?.isConnected) previous.focus(); };
  }, []);
  const keys = event => {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); onClose(); }
    if (event.key !== 'Tab') return;
    const nodes = [...dialog.current.querySelectorAll('button, input, select, textarea, summary, [tabindex="0"]')].filter(node => !node.disabled && !node.closest('details:not([open]) > :not(summary)'));
    if (!nodes.length) { event.preventDefault(); return; }
    if (event.shiftKey && (document.activeElement === nodes[0] || document.activeElement === dialog.current)) { event.preventDefault(); nodes.at(-1).focus(); }
    else if (!event.shiftKey && document.activeElement === nodes.at(-1)) { event.preventDefault(); nodes[0].focus(); }
  };
  const submit = event => {
    event.preventDefault();
    const invalid = reviewError(draft, change, role);
    if (invalid) { setError(invalid); return; }
    onSave(change, draft, e => { setError(requestError(e)); setConflict(e.status === 409); });
  };
  const reload = async () => { if (await onReload(e => setError(requestError(e)))) { setConflict(false); setError(''); setReloaded(true); } };
  return <div className="fixed inset-0 z-[90] flex items-center justify-center bg-black/45 p-3 sm:p-6">
    <section ref={dialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} aria-busy={busy} onKeyDown={keys} className={`max-h-[calc(100dvh-3rem)] w-full max-w-5xl overflow-y-auto rounded-lg border bg-white text-brand-950 shadow-xl outline-none dark:bg-brand-900 dark:text-white ${border}`}>
      <header className={`sticky top-0 z-10 flex items-start justify-between gap-4 border-b bg-white p-5 dark:bg-brand-900 ${border}`}><div className="min-w-0"><p className="mb-2 text-xs text-brand-600 dark:text-brand-300">{KIND_LABELS[change.kind]} / <ChangeStatus status={change.status} /></p><h2 id={`${id}-title`} className="break-words text-lg font-semibold">{change.title}</h2></div><button type="button" title="Close details" aria-label="Close change details" className="ui-button-secondary shrink-0 p-2" disabled={busy} onClick={onClose}><X size={17} /></button></header>
      <div className="min-w-0 space-y-6 p-5">
        <p className="break-words text-sm">{change.reason}</p>
        {change.provenance_changed && <p className="text-sm text-amber-800 dark:text-amber-200">Analysis provenance changed. Revalidate this finding against the target evidence.</p>}
        <div className="grid min-w-0 gap-6 md:grid-cols-2">{['before', 'after'].map(side => {
          const row = change[side];
          const componentNames = (row?.affected_components || []).map(cid => result.architectures?.[side]?.components?.find(item => item.id === cid)?.name || cid);
          return <section className="min-w-0 space-y-3" key={side}><h3 className="text-sm font-semibold">{side === 'before' ? 'Baseline' : 'Target'}</h3>{row ? <>
            {change.kind === 'finding' && <Severity value={row.severity} />}
            <Evidence value={{ ...(row.description ? { description: row.description } : {}), ...(componentNames.length ? { affected_components: componentNames } : {}),
              ...(row.affected_data_flows?.length ? { data_flows: row.affected_data_flows } : {}), ...(row.specific_control ? { security_control: row.specific_control } : {}),
              ...(row.mitigation || row.remediation ? { remediation: row.mitigation || row.remediation } : {}), ...(row.tier ? { finding_status: row.tier } : {}),
              ...(change.kind !== 'finding' ? { name: row.name || row.id, type: row.type || change.kind, properties: row.properties } : {}) }} />
          </> : <p className={muted}>Not present in this report.</p>}</section>;
        })}</div>
        {!!change.fields?.length && <section className="space-y-3"><h3 className="text-sm font-semibold">Changed fields</h3><div className="min-w-0 overflow-x-auto"><table className="w-full min-w-[520px] table-fixed text-left text-sm" aria-label="Changed fields"><thead className={`border-y text-xs ${border}`}><tr><th className="w-1/3 p-2" scope="col">Field</th><th className="w-1/3 p-2" scope="col">Baseline</th><th className="w-1/3 p-2" scope="col">Target</th></tr></thead><tbody>{change.fields.map(field => <tr key={field.field} className={`border-b ${border}`}><th scope="row" className="break-words p-2 align-top font-medium">{readableField(field.field)}</th>{['before', 'after'].map(side => <td className="whitespace-pre-wrap break-words p-2 align-top [overflow-wrap:anywhere]" key={side}>{readableValue(field[side])}</td>)}</tr>)}</tbody></table></div></section>}
        <details className={`border-t pt-4 ${border}`}><summary className="cursor-pointer text-sm font-semibold">Supporting evidence{change.evidence_changed ? ' (changed)' : ''}</summary><div className="mt-3 grid min-w-0 gap-6 md:grid-cols-2">{['before', 'after'].map(side => <section className="min-w-0" key={side}><h4 className="mb-2 text-sm font-semibold">{side === 'before' ? 'Baseline evidence' : 'Target evidence'}</h4><Evidence value={change[`${side}_evidence`]} /></section>)}</div></details>
        {change.review && <details className={`border-t pt-4 ${border}`}><summary className="cursor-pointer text-sm font-semibold">Original report review</summary><div className="mt-3 grid min-w-0 gap-6 md:grid-cols-2">{['before', 'after'].map(side => <section key={side} className="min-w-0"><h4 className="mb-2 text-sm font-semibold">{side === 'before' ? 'Baseline' : 'Target'}</h4><Evidence value={change.review[side]} /></section>)}</div></details>}
        <section className={`space-y-4 border-t pt-4 ${border}`}><h3 className="text-sm font-semibold">Comparison review</h3>
          {currentReview && <div className="space-y-1 text-sm"><p>{REVIEW_LABELS[currentReview.status]} / {currentReview.reviewer} / {comparisonDate(currentReview.reviewed_at)}</p><p className="whitespace-pre-wrap break-words">{currentReview.remarks}</p>{currentReview.evidence && <p className={`whitespace-pre-wrap break-words ${muted}`}>Evidence: {currentReview.evidence}</p>}</div>}
          {!editable ? <p className={muted}>Read-only access.</p> : !snapshot ? <div className="space-y-3"><p className={muted}>Save this comparison before recording review decisions.</p><button className="ui-button-secondary" disabled={busy || mappingChanged} onClick={onSaveSnapshot}><Save size={16} />Save comparison to review</button></div> : <form className="space-y-4" onSubmit={submit}>
            <label className="grid max-w-md gap-2 text-sm">Review decision<select className={input} value={draft.status} disabled={busy || conflict} onChange={event => { setDraft(current => ({ ...current, status: event.target.value })); setError(''); }}>{Object.entries(REVIEW_LABELS).map(([value, label]) => <option key={value} value={value} disabled={(value === 'accepted_risk' && role !== 'admin') || (value === 'verified_fixed' && change.kind !== 'finding')}>{label}{value === 'accepted_risk' && role !== 'admin' ? ' (administrator only)' : ''}</option>)}</select></label>
            <label className="grid gap-2 text-sm">Review remarks<textarea className={input} rows={3} maxLength={10000} disabled={busy} value={draft.remarks} onChange={event => setDraft(current => ({ ...current, remarks: event.target.value }))} /></label>
            <label className="grid gap-2 text-sm">Verification evidence{draft.status === 'verified_fixed' ? ' (required)' : ' (optional)'}<textarea className={input} rows={2} maxLength={20000} disabled={busy} value={draft.evidence} onChange={event => setDraft(current => ({ ...current, evidence: event.target.value }))} /></label>
            {draft.status === 'verified_fixed' && <p className={muted}>A missing finding alone is not verification. Record the test result or validated control evidence.</p>}
            {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
            {reloaded && <p role="status" className={muted}>Latest saved review is shown above. Reconcile it with your retained draft before saving.</p>}
            <div className="flex flex-wrap gap-3"><button className="btn-brand gap-2" disabled={busy || conflict} type="submit"><Check size={16} />{busy ? 'Saving...' : 'Save review'}</button>{conflict && <button className="ui-button-secondary" disabled={busy} type="button" onClick={reload}><RotateCcw size={16} />Reload latest review</button>}{reloaded && currentReview && <button type="button" className="ui-button-secondary" disabled={busy} onClick={() => { setDraft({ status: currentReview.status, remarks: currentReview.remarks || '', evidence: currentReview.evidence || '' }); setReloaded(false); }}>Use latest review</button>}</div>
          </form>}
        </section>
        <details className={`border-t pt-4 ${border}`}><summary className="cursor-pointer text-sm font-semibold">Raw change record</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs [overflow-wrap:anywhere]">{JSON.stringify(change, null, 2)}</pre></details>
      </div>
    </section>
  </div>;
}
