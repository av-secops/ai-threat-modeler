import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowUpRight, ChevronLeft, ChevronRight, Download, Eye, RefreshCw, Save, LayoutDashboard, ShieldAlert, Layers, History } from 'lucide-react';
import { enterprise } from '../services/enterprise';
import { dashboardQuery, downloadCsv, filterDefaults, statusLabels } from '../utils/productDashboard';
import { RiskDetailsModal } from './dashboard/RiskRegister';
import RiskReviewForm from './dashboard/RiskReviewForm';
import { SeverityBadge as KnownSeverityBadge } from './dashboard/InsightCards';
import FilterBar from './FilterBar';

const muted = 'text-brand-600 dark:text-brand-300';
const divider = 'border-brand-200 dark:border-brand-700';
const colors = { Critical: 'bg-red-600 dark:bg-red-400', High: 'bg-orange-600 dark:bg-orange-400', Medium: 'bg-amber-500 dark:bg-amber-400', Low: 'bg-teal-600 dark:bg-teal-400', Unknown: 'bg-zinc-500 dark:bg-zinc-400' };
const date = value => value ? new Date(value * 1000).toLocaleString() : 'Not yet';
const SeverityBadge = ({ severity }) => severity === 'Unknown'
  ? <span className="rounded border border-zinc-300 px-2 py-1 text-xs text-zinc-700 dark:border-zinc-600 dark:text-zinc-200">Unrated</span>
  : <KnownSeverityBadge severity={severity} />;

function Select({ label, value, options, onChange }) {
  return <label className={`grid min-w-0 gap-1 text-xs ${muted}`}>{label}<select className="input-brand w-full text-sm" value={value} onChange={e => onChange(e.target.value)}>{options.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>;
}

function Metric({ label, value, onClick, detail, disabled }) {
  const content = <><span className={`block text-xs ${muted}`}>{label}</span><span className="mt-1 block text-2xl font-semibold tabular-nums">{value}</span>{detail && <span className={`mt-1 block text-xs ${muted}`}>{detail}</span>}</>;
  return onClick ? <button disabled={disabled} onClick={onClick} className="min-w-0 break-words py-3 text-left hover:underline disabled:opacity-50">{content}</button> : <div className="min-w-0 break-words py-3">{content}</div>;
}

export default function ProductSecurityDashboard({ productId, filters, onFilters, onBack, onOpenModel, editable }) {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [modelPage, setModelPage] = useState(1);
  const [view, setView] = useState('overview');
  const previousSearch = useRef(filters.search);
  const snapshot = useRef('');
  const detailRequest = useRef(null);
  const lastScope = useRef('');
  const key = JSON.stringify(filters);
  const base = `/products/${encodeURIComponent(productId)}/security-dashboard`;
  useEffect(() => {
    if (lastScope.current !== base + key) {
      lastScope.current = base + key;
      snapshot.current = '';
      if (page !== 1) { setPage(1); return undefined; }
    }
    const controller = new AbortController();
    setBusy(true); setError('');
    const query = dashboardQuery(JSON.parse(key), { page, ...(page > 1 && snapshot.current ? { snapshot: snapshot.current } : {}) });
    const delay = previousSearch.current === filters.search ? 0 : 250;
    previousSearch.current = filters.search;
    const timer = setTimeout(() => enterprise(`${base}?${query}`, 'GET', undefined, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) { snapshot.current = value.snapshot; setData(value); }
    }).catch(e => { if (!controller.signal.aborted && e.name !== 'AbortError') { setError(e.message); setData(null); } }).finally(() => { if (!controller.signal.aborted) setBusy(false); }), delay);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [base, key, page, refresh, filters.search]);
  useEffect(() => {
    const controller = new AbortController();
    enterprise(`${base}/history`, 'GET', undefined, { signal: controller.signal }).then(setTimeline).catch(e => { if (e.name !== 'AbortError') setError(e.message); });
    return () => { controller.abort(); detailRequest.current?.abort(); };
  }, [base]);
  const reload = () => { snapshot.current = ''; setPage(1); setRefresh(n => n + 1); };
  const change = (values) => { snapshot.current = ''; setPage(1); setModelPage(1); onFilters({ ...filters, ...values }); };
  const closeDetail = useCallback(() => setDetail(null), []);
  const run = async action => { setActionBusy(true); setError(''); try { await action(); } catch (e) { if (e.name !== 'AbortError') setError(e.message); } finally { setActionBusy(false); } };
  const openDetail = row => run(async () => {
    detailRequest.current?.abort();
    const controller = new AbortController(); detailRequest.current = controller;
    const value = await enterprise(`${base}/finding?${new URLSearchParams({ workspace_id: row.workspace_id, report_id: row.report_id, finding_id: row.finding_id })}`, 'GET', undefined, { signal: controller.signal });
    setDetail({ ...value, row });
  });
  const metrics = data?.metrics, coverage = data?.coverage;
  const models = data?.models || [];
  const modelPages = Math.max(1, Math.ceil(models.length / 10));
  const currentModelPage = Math.min(modelPage, modelPages);
  const drill = values => { change(values); setView('risks'); };
  const activeFilters = Object.entries(filters).filter(([name, value]) => name in filterDefaults && name !== 'sort' && value !== filterDefaults[name]).map(([name, value]) => {
    const names = { release_id: 'Release', application_id: 'Application', environment: 'Environment', scope: 'Scope', tier: 'Evidence', quality: 'Quality', severity: 'Severity', status: 'Status', kind: 'Type', search: 'Search', archived: 'Archived releases' };
    const display = name === 'release_id' ? data?.options.releases.find(r => r.id === value)?.name || value
      : name === 'application_id' ? data?.options.applications.find(a => a.id === value)?.name || value
        : name === 'status' ? statusLabels[value] || value
          : name === 'scope' ? value === 'release' ? 'Complete release' : 'Application only'
            : name === 'kind' ? value === 'risk' ? 'Risks' : 'Validation questions' : name === 'archived' ? 'Included' : value;
    return { key: name, label: `${names[name]}: ${display}`, onRemove: () => change({ [name]: filterDefaults[name] }) };
  });
  const views = [['overview', 'Overview', LayoutDashboard], ['risks', 'Risks', ShieldAlert], ['coverage', 'Coverage', Layers], ['history', 'History', History]];
  return <section className="min-w-0 space-y-6" aria-label="Product security dashboard">
    <div className={`flex flex-wrap items-center justify-between gap-3 border-b pb-4 ${divider}`}>
      <div><p className={`text-sm ${muted}`}>Products / {data?.product.name || 'Product'}</p><h1 className="mt-1 text-xl font-semibold">Security dashboard</h1></div>
      <div className="flex flex-wrap gap-2"><button className="ui-button-secondary" onClick={onBack}><ArrowLeft size={16} />Back to releases</button><button title="Refresh dashboard" aria-label="Refresh dashboard" className="ui-button-secondary" onClick={reload} disabled={busy}><RefreshCw size={16} /></button><button title="Export filtered risk register" aria-label="Export filtered risk register" className="ui-button-secondary" disabled={!data || busy || actionBusy} onClick={() => run(async () => downloadCsv(await enterprise(`${base}/export?${dashboardQuery(filters, { snapshot: data.snapshot })}`, 'GET', undefined, { text: true })))}><Download size={16} /></button></div>
    </div>
    {error && <p role="alert" className="border-l-4 border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">{error}</p>}
    <nav aria-label="Security dashboard views" className={`flex flex-wrap gap-1 border-b ${divider}`}>{views.map(([id, name, icon]) => {
      const Icon = icon;
      return <button type="button" key={id} aria-current={view === id ? 'page' : undefined} className={`inline-flex min-h-11 items-center gap-2 border-b-2 px-3 text-sm font-medium ${view === id ? 'border-brand-primary text-brand-primary dark:text-indigo-300' : 'border-transparent text-brand-600 dark:text-brand-300'}`} onClick={() => setView(id)}><Icon size={16} />{name}{id === 'risks' && data && <span className="text-xs tabular-nums">{data.findings.total}</span>}</button>;
    })}</nav>
    {view !== 'history' && <FilterBar label="Dashboard filters" resetLabel="Reset dashboard filters" active={activeFilters} onReset={() => change(filterDefaults)} search={{ label: 'Search product findings', placeholder: 'Risk, application or release', value: filters.search, onChange: search => change({ search }) }}>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Select label="Release" value={filters.release_id} options={[[ '', 'All active releases'], ...(data?.options.releases || []).map(r => [r.id, r.name + (r.archived ? ' (archived)' : '')])]} onChange={release_id => change({ release_id })} />
      <Select label="Application" value={filters.application_id} options={[[ '', 'All applications'], ...(data?.options.applications || []).map(a => [a.id, a.name])]} onChange={application_id => change({ application_id })} />
      <Select label="Environment" value={filters.environment} options={[[ '', 'All environments'], ...(data?.options.environments || []).map(e => [e, e])]} onChange={environment => change({ environment })} />
      <Select label="Model scope" value={filters.scope} options={[['all', 'All scopes'], ['release', 'Complete release'], ['application', 'Application only']]} onChange={scope => change({ scope })} />
      <Select label="Evidence tier" value={filters.tier} options={['all', 'Confirmed', 'Potential', 'Unknown'].map(v => [v, v === 'all' ? 'All evidence tiers' : v])} onChange={tier => change({ tier })} />
      <Select label="Report quality" value={filters.quality} options={[[ 'all', 'All quality states'], ['ready', 'Ready for publication'], ['review', 'Needs review'], ['blocked', 'Blocked'], ['unknown', 'Unknown']]} onChange={quality => change({ quality })} />
      <label className={`flex items-center gap-2 text-sm ${muted}`}><input type="checkbox" checked={filters.archived} onChange={e => change({ archived: e.target.checked })} />Include archived releases</label>
      <Select label="Severity" value={filters.severity} options={['all', ...Object.keys(colors)].map(v => [v, v === 'all' ? 'All severities' : v])} onChange={severity => change({ severity })} />
      <Select label="Review status" value={filters.status} options={[[ 'all', 'All statuses'], ...Object.entries(statusLabels)]} onChange={status => change({ status })} />
      <Select label="Finding type" value={filters.kind} options={[[ 'all', 'All findings'], ['risk', 'Risks'], ['question', 'Validation questions']]} onChange={kind => change({ kind })} />
    </div></FilterBar>}
    {busy && <p role="status" className={`text-sm ${muted}`}>Loading dashboard...</p>}
    {data && <div className="space-y-6" aria-busy={busy}>
      {view !== 'history' && <div className={`flex flex-wrap justify-between gap-2 text-xs ${muted}`}><span>Latest completed reports · Finding occurrences{activeFilters.length > 0 ? ' · Filtered view' : ''}</span><span>Refreshed {date(data.generated_at)}</span></div>}
      {view === 'coverage' && <div className={`grid grid-cols-2 gap-x-6 border-y py-1 lg:grid-cols-4 ${divider}`}>
        <Metric label="Applications assessed" value={coverage.applications_registered ? `${coverage.applications_assessed} / ${coverage.applications_registered}` : 'Not defined'} detail="Registered product applications" />
        <Metric label="Releases with assessments" value={`${coverage.releases_assessed} / ${coverage.releases_registered}`} detail="At least one completed model" />
        <Metric label="Completed models" value={coverage.models_completed} detail={`${coverage.full_release_models} full release / ${coverage.application_models} application`} />
        <Metric label="Quality-ready models" value={coverage.quality.ready || 0} detail={`${coverage.quality.blocked || 0} blocked / ${coverage.drafts} draft / ${coverage.legacy_unverified} legacy`} />
      </div>}
      {view === 'overview' && <div className={`grid grid-cols-2 gap-x-6 border-b pb-2 sm:grid-cols-3 lg:grid-cols-6 ${divider}`}>
        <Metric disabled={busy} label="Open risks" value={metrics.open_risks} onClick={() => drill({ status: 'open', kind: 'risk', severity: 'all' })} detail={`${metrics.confirmed_open} confirmed / ${metrics.potential_open} potential`} />
        {['Critical', 'High'].map(s => <Metric disabled={busy} key={s} label={`${s} open`} value={data.severity.find(v => v.name === s)?.count || 0} onClick={() => drill({ severity: s, status: 'open', kind: 'risk' })} />)}
        <Metric disabled={busy} label="Verified fixed" value={metrics.verified_fixed} onClick={() => drill({ status: 'verified_fixed', kind: 'risk', severity: 'all' })} />
        <Metric disabled={busy} label="Accepted risks" value={metrics.accepted_risks} onClick={() => drill({ status: 'accepted', kind: 'risk', severity: 'all' })} />
        <Metric disabled={busy} label="Validation questions" value={metrics.validation_questions} onClick={() => drill({ kind: 'question', status: 'all', severity: 'all' })} />
      </div>}
      {view !== 'history' && (coverage.legacy_unverified > 0 || coverage.overlapping_releases > 0 || coverage.quality.blocked > 0) && <div className="space-y-1 border-l-4 border-amber-500 pl-3 text-sm text-amber-900 dark:text-amber-200" role="note">
        {coverage.legacy_unverified > 0 && <p>{coverage.legacy_unverified} legacy/unverified models are excluded from risk totals.</p>}
        {coverage.overlapping_releases > 0 && <p>Full-release and application assessments overlap in {coverage.overlapping_releases} releases. Totals represent occurrences, not unique vulnerabilities.</p>}
        {coverage.quality.blocked > 0 && <p>{coverage.quality.blocked} quality-blocked reports contribute preliminary findings.</p>}
      </div>}
      {view === 'coverage' && models.some(m => m.latest_attempt) && <div className={`text-sm ${muted}`}><h2 className="font-semibold">Latest analysis attempts</h2><ul>{models.filter(m => m.latest_attempt).map(m => <li key={m.id}>{m.release_name} / {m.name}: {m.latest_attempt}</li>)}</ul></div>}
      {view === 'overview' && <div className="grid gap-8 lg:grid-cols-2">
        <section aria-label="Open risks by severity"><h2 className="font-semibold">Open risks by severity</h2><p className={`mb-4 mt-1 text-xs ${muted}`}>{metrics.open_risks} open-risk occurrences in selected filters</p><div className="space-y-3">{data.severity.map(s => <button disabled={busy} key={s.name} className="grid w-full grid-cols-[64px_minmax(0,1fr)_86px] items-center gap-2 rounded py-1 text-left text-sm hover:bg-brand-50 disabled:opacity-50 dark:hover:bg-brand-800" aria-label={`${s.name}: ${s.count} open risks`} onClick={() => drill({ severity: s.name, status: 'open', kind: 'risk' })}><span>{s.name}</span><span className="h-3 overflow-hidden rounded-sm bg-brand-100 dark:bg-brand-800"><span className={`block h-full transition-[width] motion-reduce:transition-none ${colors[s.name]}`} style={{ width: `${s.percent || 0}%` }} /></span><span className="text-right tabular-nums">{s.count} <span className={muted}>({s.percent == null ? 'N/A' : `${s.percent}%`})</span></span></button>)}</div></section>
        <section aria-label="Finding review status"><h2 className="font-semibold">Finding review status</h2><p className={`mb-4 mt-1 text-xs ${muted}`}>{metrics.reported_findings} findings, including validation questions</p><div className="grid gap-2">{data.statuses.filter(s => s.count > 0).map(s => <button disabled={busy} key={s.name} className={`min-w-0 border-b py-2 text-left text-sm hover:bg-brand-50 disabled:opacity-50 dark:hover:bg-brand-800 ${divider}`} onClick={() => drill({ status: s.name, severity: 'all', kind: 'all' })}><span className="flex justify-between gap-2"><span>{statusLabels[s.name]}</span><span className="tabular-nums">{s.count}</span></span><span className="mt-2 block h-1.5 bg-brand-100 dark:bg-brand-800"><span className={`block h-full transition-[width] motion-reduce:transition-none ${s.name === 'verified_fixed' ? 'bg-teal-600 dark:bg-teal-400' : s.name === 'accepted' ? 'bg-amber-500' : 'bg-sky-600 dark:bg-sky-400'}`} style={{ width: `${s.percent || 0}%` }} /></span><span className={`mt-1 block text-right text-xs ${muted}`}>{s.percent == null ? 'N/A' : `${s.percent}%`}</span></button>)}</div>{!metrics.reported_findings && <p className={`py-6 text-sm ${muted}`}>No findings match the current scope.</p>}</section>
      </div>}
      {view === 'coverage' && <section className={`space-y-4 border-t pt-5 ${divider}`}><h2 className="font-semibold">Application and release coverage</h2><p className={`text-xs ${muted}`}>Last analyzed: {date(coverage.last_analyzed)}. Assessed counts do not establish complete release coverage.</p>
        <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm" aria-label="Assessment coverage"><thead><tr>{['Release', 'Application / scope', 'Environment', 'Assessment', 'Last analyzed', 'Open'].map(v => <th className={`border-b py-3 pr-4 ${divider}`} key={v}>{v}</th>)}</tr></thead><tbody>{models.slice((currentModelPage-1)*10, currentModelPage*10).map(m => <tr key={m.id}><td className={`border-b py-3 pr-4 ${divider}`}>{m.release_name}</td><td className={`border-b py-3 pr-4 ${divider}`}>{m.application_name || 'Complete release'}<p className={`text-xs ${muted}`}>{m.name}</p></td><td className={`border-b py-3 pr-4 ${divider}`}>{m.environment}</td><td className={`border-b py-3 pr-4 ${divider}`}>{m.assessment_status.replaceAll('_', ' ')}{m.completed && <span className={`block text-xs ${muted}`}>{m.quality}</span>}{m.active_job && <span className="block text-xs">Analysis job recorded</span>}</td><td className={`border-b py-3 pr-4 ${divider}`}>{date(m.last_analyzed)}</td><td className={`border-b py-3 ${divider}`}><button title="Open model" aria-label={`Open model ${m.name}`} className="ui-button-secondary" disabled={actionBusy} onClick={() => run(() => onOpenModel(m))}><ArrowUpRight size={16} /></button></td></tr>)}</tbody></table></div>
        {!models.length && <p className={`text-sm ${muted}`}>No models match this scope.</p>}
        <div className="flex items-center justify-end gap-3 text-sm"><span>Models {currentModelPage} / {modelPages}</span><button title="Previous models" aria-label="Previous models" className="ui-button-secondary" disabled={currentModelPage === 1} onClick={() => setModelPage(currentModelPage-1)}><ChevronLeft size={16} /></button><button title="Next models" aria-label="Next models" className="ui-button-secondary" disabled={currentModelPage === modelPages} onClick={() => setModelPage(currentModelPage+1)}><ChevronRight size={16} /></button></div>
      </section>}
      {view === 'risks' && <section className={`space-y-4 border-t pt-5 ${divider}`}><div className="flex flex-wrap items-end justify-between gap-3"><h2 className="font-semibold">Product risk register</h2><Select label="Sort findings" value={filters.sort} options={['severity', 'title', 'release', 'status'].map(v => [v, v[0].toUpperCase() + v.slice(1)])} onChange={sort => change({ sort })} /></div>
        <p role="status" className={`text-sm ${muted}`}>{data.findings.total} finding occurrences</p>
        <div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left text-sm" aria-label="Product risk register"><thead><tr>{['Risk', 'Severity', 'STRIDE', 'Application / release', 'Review status', 'Details'].map(v => <th className={`border-b py-3 pr-4 ${divider}`} key={v}>{v}</th>)}</tr></thead><tbody>{data.findings.rows.map(f => <tr key={f.occurrence_id}><td className={`max-w-sm break-words border-b py-3 pr-4 ${divider}`}><span className="font-medium">{f.title}</span><p className={`mt-1 text-xs ${muted}`}>{f.tier} / {f.kind === 'question' ? 'Validation question' : 'Risk'} / revision {f.revision}</p></td><td className={`border-b py-3 pr-4 ${divider}`}><SeverityBadge severity={f.severity} /></td><td className={`max-w-40 border-b py-3 pr-4 ${divider}`}>{f.stride.join(', ')}</td><td className={`border-b py-3 pr-4 ${divider}`}>{f.application_name || 'Complete release'}<p className={`text-xs ${muted}`}>{f.release_name} / {f.environment}</p></td><td className={`border-b py-3 pr-4 ${divider}`}>{statusLabels[f.status]}</td><td className={`border-b py-3 ${divider}`}><button title="View risk details" aria-label={`View details for ${f.title}`} className="ui-button-secondary" disabled={actionBusy} onClick={() => openDetail(f)}><Eye size={16} /></button></td></tr>)}</tbody></table></div>
        {!data.findings.total && <p className={`text-sm ${muted}`}>No findings match these filters. This does not establish that the product is secure.</p>}
        <div className="flex items-center justify-end gap-3 text-sm"><span>Page {page} / {Math.max(1, Math.ceil(data.findings.total / data.findings.page_size))}</span><button title="Previous findings" aria-label="Previous product findings" className="ui-button-secondary" disabled={busy || page === 1} onClick={() => setPage(page-1)}><ChevronLeft size={16} /></button><button title="Next findings" aria-label="Next product findings" className="ui-button-secondary" disabled={busy || page * data.findings.page_size >= data.findings.total} onClick={() => setPage(page+1)}><ChevronRight size={16} /></button></div>
      </section>}
      {view === 'history' && <section className={`space-y-3 border-t pt-5 ${divider}`}><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">Recorded overview history</h2>{editable && <button className="ui-button-secondary" disabled={actionBusy} onClick={() => run(async () => setTimeline(await enterprise(`${base}/history`, 'POST')))}><Save size={16} />Record overview</button>}</div><p className={`text-xs ${muted}`}>All active releases, independent of current filters. Recorded observations only; missing dates are not reconstructed.</p>
        <div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left text-sm" aria-label="Dashboard observations"><thead><tr>{['Observed', 'Open', 'Verified fixed', 'Accepted', 'Assessed models'].map(v => <th className={`border-b py-2 pr-3 ${divider}`} key={v}>{v}</th>)}</tr></thead><tbody>{timeline?.observations.map(o => <tr key={o.id}><td className={`border-b py-2 pr-3 ${divider}`}>{date(o.observed)}</td>{[o.body.metrics.open_risks, o.body.metrics.verified_fixed, o.body.metrics.accepted_risks, o.body.coverage.models_completed].map((v, i) => <td className={`border-b py-2 pr-3 tabular-nums ${divider}`} key={i}>{v}</td>)}</tr>)}</tbody></table></div>{!timeline?.observations.length && <p className={`text-sm ${muted}`}>No overview observations recorded.</p>}
      </section>}
    </div>}
    <RiskDetailsModal threat={detail?.threat} reviewState={detail?.reviews.latest[detail.threat.id]?.status || 'pending_review'} onClose={closeDetail}>
      {detail && <><div className={`px-7 py-3 text-xs ${muted}`}>{detail.row.release_name} / {detail.row.application_name || 'Complete release'} / {detail.row.environment} / revision {detail.row.revision}</div><RiskReviewForm key={`${detail.row.report_id}:${detail.threat.id}:${detail.reviews.latest[detail.threat.id]?.version || 0}`} reportId={detail.row.report_id} threat={detail.threat} review={detail.reviews.latest[detail.threat.id]} events={detail.reviews.events} readOnly={!editable} onSaved={reviews => { setDetail(current => ({ ...current, reviews })); reload(); }} /><div className="px-7 pb-5"><button className="ui-button-secondary" onClick={() => run(() => onOpenModel({ ...detail.row, id: detail.row.workspace_id }))}><ArrowUpRight size={16} />Open report revision</button></div></>}
    </RiskDetailsModal>
  </section>;
}

export function SecurityPortfolio({ onBack, onProduct }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [archived, setArchived] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    enterprise(`/security-dashboard?archived=${archived}`, 'GET', undefined, { signal: controller.signal }).then(setData).catch(e => { if (e.name !== 'AbortError') setError(e.message); });
    return () => controller.abort();
  }, [archived]);
  return <section className="space-y-5">
    <div className="flex flex-wrap justify-between gap-3"><h1 className="text-xl font-semibold">Product security portfolio</h1><button className="ui-button-secondary" onClick={onBack}><ArrowLeft size={16} />Back to products</button></div>
    {error && <p role="alert">{error}</p>}
    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={archived} onChange={e => { setData(null); setError(''); setArchived(e.target.checked); }} />Include archived products</label>
    {data ? <>
      <div className={`grid grid-cols-2 gap-5 border-y ${divider}`}><Metric label="Products" value={data.products_total} /><Metric label="Products assessed" value={data.products_assessed} detail="At least one verified report association" /></div>
      {data.products.some(p => p.coverage.legacy_unverified > 0) && <p role="note" className="border-l-4 border-amber-500 pl-3 text-sm text-amber-900 dark:text-amber-200">Legacy/unverified reports are listed separately below and excluded from assessed counts and risk totals. Zero counted risks does not establish an absence of findings.</p>}
      <div className="overflow-x-auto"><table className="w-full min-w-[600px] text-left text-sm">
        <thead><tr>{['Product', 'Applications assessed', 'Releases assessed', 'Open risks', 'Verified fixed', 'Details'].map(v => <th className={`border-b py-3 pr-4 ${divider}`} key={v}>{v}</th>)}</tr></thead>
        <tbody>{data.products.map(p => <tr key={p.product.id}>
          <td className={`border-b py-3 pr-4 ${divider}`}>{p.product.name}{p.product.archived ? ' (archived)' : ''}{p.coverage.legacy_unverified > 0 && <p className={`text-xs ${muted}`}>{p.coverage.legacy_unverified} legacy/unverified models</p>}</td>
          <td className={`border-b py-3 pr-4 ${divider}`}>{p.coverage.applications_assessed} / {p.coverage.applications_registered}</td>
          <td className={`border-b py-3 pr-4 ${divider}`}>{p.coverage.releases_assessed} / {p.coverage.releases_registered}</td>
          <td className={`border-b py-3 pr-4 ${divider}`}>{p.metrics.open_risks}</td>
          <td className={`border-b py-3 pr-4 ${divider}`}>{p.metrics.verified_fixed}</td>
          <td className={`border-b py-3 ${divider}`}><button className="ui-button-secondary" title="Open product dashboard" aria-label={`Dashboard for ${p.product.name}`} onClick={() => onProduct(p.product.id)}><ArrowUpRight size={16} /></button></td>
        </tr>)}</tbody>
      </table></div>
      <p className={`text-xs ${muted}`}>Latest completed models in active releases. Counts are occurrences, not unique vulnerabilities. Refreshed {date(data.generated_at)}.</p>
    </> : !error && <p role="status">Loading portfolio...</p>}
  </section>;
}
