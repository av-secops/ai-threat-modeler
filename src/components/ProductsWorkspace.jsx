import { useCallback, useEffect, useState } from 'react';
import { Plus, ArrowLeft, ArrowRight, Copy, Download, KeyRound, Archive, RotateCcw, X, Eye } from 'lucide-react';
import { enterprise, setWorkspaceToken } from '../services/enterprise';
import ReviewDiagram from './dashboard/ReviewDiagram';
import { formatWorkspaceDate, releaseScopes, releaseStatus } from '../utils/releasePresentation';

const input = 'input-brand min-w-0 text-sm';
function download(value) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'release-comparison.json'; anchor.click(); URL.revokeObjectURL(url);
}

export default function ProductsWorkspace({ onStart, onOpen: handleOpen, onHistory, darkMode, initialLocation = null, onLocationChange }) {
  // Restore the release only on entry; subsequent navigation belongs to this view.
  const [entryLocation] = useState(initialLocation);
  const [restoring, setRestoring] = useState(!!initialLocation?.product_id);
  const [products, setProducts] = useState([]);
  const [product, setProduct] = useState(null);
  const [release, setRelease] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState('');
  const [modal, setModal] = useState(null);
  const [name, setName] = useState('');
  const [modelScope, setModelScope] = useState('');
  const [showScope, setShowScope] = useState(false);
  const [applicationName, setApplicationName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [comparison, setComparison] = useState(null);
  const [options, setOptions] = useState([]);
  const [pair, setPair] = useState(['', '']);
  const [versions, setVersions] = useState([1, 1]);
  const [comparisonTab, setComparisonTab] = useState('summary');
  useEffect(() => { window.scrollTo(0, 0); }, [product?.id, release?.id]);
  const editable = identity?.role === 'editor' || identity?.role === 'admin';
  const onOpen = row => handleOpen({ ...row, readOnly: !editable, productScope: {
    product_id: product.id, product_name: product.name, release_id: release.id, release_name: release.name,
    application_id: row.application_id, application_name: product.applications?.find(a => a.id === row.application_id)?.name || null,
    model_scope: row.application_id ? 'application' : 'release', environment: row.environment,
  } });
  const load = useCallback(async () => {
    try { setIdentity(await enterprise('/identity')); setProducts(await enterprise('/products')); setError(''); }
    catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!entryLocation?.product_id) return undefined;
    let cancelled = false;
    const restore = async () => {
      setBusy(true);
      try {
        const savedProduct = await enterprise(`/products/${entryLocation.product_id}`);
        const savedRelease = entryLocation.release_id ? await enterprise(`/releases/${entryLocation.release_id}`) : null;
        if (cancelled) return;
        if (savedRelease && savedRelease.product_id !== savedProduct.id) throw new Error('The release does not belong to this product.');
        setProduct(savedProduct); setRelease(savedRelease);
        setModelScope(entryLocation.newModelScope || '');
        setShowScope(!!savedRelease && (!savedRelease.workspaces.length || !!entryLocation.newModelScope));
        onLocationChange?.({ product_id: savedProduct.id, release_id: savedRelease?.id });
      } catch (e) { if (!cancelled) setError(e.message); }
      finally { if (!cancelled) { setBusy(false); setRestoring(false); } }
    };
    restore();
    return () => { cancelled = true; };
  }, [entryLocation, onLocationChange]);
  const run = async work => { setBusy(true); setError(''); try { await work(); } catch (e) { setError(e.message); } finally { setBusy(false); } };
  const openProducts = () => { setProduct(null); setRelease(null); setComparison(null); onLocationChange?.(null); load(); };
  const openProduct = id => run(async () => { setProduct(await enterprise(`/products/${id}`)); setRelease(null); setComparison(null); setOptions([]); onLocationChange?.({ product_id: id }); });
  const resetScope = () => { setModelScope(''); setApplicationName(''); setEnvironment('production'); };
  const openRelease = id => run(async () => {
    const next = await enterprise(`/releases/${id}`);
    setRelease(next); resetScope(); setShowScope(!next.workspaces.length); setComparison(null);
    onLocationChange?.({ product_id: next.product_id, release_id: id });
  });
  const showModal = type => { setModal(type); setName(type === 'rename' ? product.name : ''); };
  const submit = event => {
    event.preventDefault();
    run(async () => {
      if (modal === 'token') { setWorkspaceToken(name.trim()); await load(); }
      else if (modal === 'product') { await enterprise('/products', 'POST', { name }); await load(); }
      else if (modal === 'rename') { setProduct(await enterprise(`/products/${product.id}`, 'PATCH', { name, archived: !!product.archived })); await openProduct(product.id); }
      else {
        const path = modal === 'clone' ? `/releases/${release.id}/clone` : `/products/${product.id}/releases`;
        const created = await enterprise(path, 'POST', { name });
        setProduct(await enterprise(`/products/${product.id}`));
        setRelease(await enterprise(`/releases/${created.id}`));
        resetScope(); setShowScope(true);
        onLocationChange?.({ product_id: product.id, release_id: created.id });
      }
      setModal(null);
    });
  };
  const startModel = event => {
    event.preventDefault();
    if (!editable || !modelScope || !environment.trim() || (modelScope === 'application' && !applicationName.trim())) return;
    run(async () => {
      const application = modelScope === 'application'
        ? await enterprise(`/releases/${release.id}/applications`, 'POST', { name: applicationName }) : null;
      await onStart({ product_id: product.id, release_id: release.id, application_id: application?.id || null,
        application_name: application?.name || null, model_scope: modelScope,
        environment: environment.trim(), release_name: release.name, product_name: product.name });
    });
  };
  const compareOptions = () => run(async () => {
    const rows = [];
    for (const item of product.releases) {
      const detail = await enterprise(`/releases/${item.id}`);
      rows.push(...detail.workspaces.filter(w => w.revisions > 0).map(w => ({ ...w, label: `${item.name} / ${w.name} / ${w.environment}` })));
    }
    setOptions(rows); setPair(['', '']);
  });
  const compare = () => run(async () => {
    const result = await enterprise('/compare', 'POST', { before_workspace: pair[0], after_workspace: pair[1], before_revision: versions[0], after_revision: versions[1] });
    const before = await enterprise(`/workspaces/${pair[0]}`), after = await enterprise(`/workspaces/${pair[1]}`);
    result.diagrams = [before, after].map((row, index) => row.workspace.revisions.find(r => r.number === versions[index])?.data?.diagram);
    setComparison(result);
  });
  if (restoring) return <p role="status" className="py-8 text-sm">Opening release workspace...</p>;
  return <div className="min-w-0 space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-brand-200 pb-4 dark:border-brand-700">
      <nav className="flex min-w-0 flex-wrap items-center gap-2 text-sm"><button disabled={busy} onClick={openProducts}>Products</button>{product && <><span>/</span><button disabled={busy} onClick={() => openProduct(product.id)}>{product.name}</button></>}{release && <><span>/</span><span>{release.name}</span></>}</nav>
      <div className="flex gap-2"><button className="ui-button-secondary" onClick={onHistory}>Unassigned / history</button><button aria-label="Workspace access" title="Workspace access" className="ui-button-secondary" onClick={() => showModal('token')}><KeyRound size={16} /></button></div>
    </div>
    {error && <p role="alert" className="border-l-4 border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">{error}</p>}
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-xl font-semibold">{release ? `Release ${release.name}` : product?.name || 'Products'}</h1><div className="flex flex-wrap gap-2">
      {product && !release && <button className="ui-button-secondary" disabled={busy} onClick={compareOptions}>Compare releases</button>}
      {release && <button className="ui-button-secondary" disabled={!editable || busy || !!product.archived} onClick={() => showModal('clone')}><Copy size={16} />Clone release</button>}
      {release && !showScope && <button className="btn-brand gap-2" disabled={!editable || busy || !!product.archived || !!release.archived} onClick={() => { resetScope(); setShowScope(true); }}><Plus size={16} />Add threat model</button>}
      {!release && <button className="btn-brand gap-2" disabled={!editable || busy || !!product?.archived} onClick={() => showModal(product ? 'release' : 'product')}><Plus size={16} />{product ? 'Release' : 'Product'}</button>}
    </div></div>
    {!product && <><input aria-label="Search products" className={input} placeholder="Search products" value={query} onChange={e => setQuery(e.target.value)} /><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr className="border-b border-brand-200 dark:border-brand-700"><th className="py-3">Product</th><th>Status</th><th className="w-12"><span className="sr-only">Open</span></th></tr></thead><tbody>{products.filter(p => p.name.toLowerCase().includes(query.toLowerCase())).map(p => <tr key={p.id} className="border-b border-brand-200 dark:border-brand-700"><td className="py-4"><button className="font-medium" onClick={() => openProduct(p.id)}>{p.name}</button></td><td>{p.archived ? 'Archived' : 'Active'}</td><td><button title="Open product" aria-label={`Open ${p.name}`} onClick={() => openProduct(p.id)}><ArrowRight size={18} /></button></td></tr>)}</tbody></table>{!products.length && !error && <p className="py-8 text-sm text-brand-500">No products yet.</p>}</div></>}
    {product && !release && <>
      {identity?.role === 'admin' && <div className="flex flex-wrap items-center gap-3 text-sm">
        <button disabled={busy} onClick={() => showModal('rename')}>Rename</button>
        <button disabled={busy} className="inline-flex items-center gap-1" onClick={() => run(async () => {
          await enterprise(`/products/${product.id}`, 'PATCH', { name: product.name, archived: !product.archived });
          await openProduct(product.id);
        })}>{product.archived ? <RotateCcw size={15} /> : <Archive size={15} />}{product.archived ? 'Restore' : 'Archive'}</button>
      </div>}
      <div className="overflow-x-auto">
        <table aria-label="Product releases" className="w-full min-w-[760px] text-left text-sm">
          <thead><tr className="border-y border-brand-200 bg-brand-50 dark:border-brand-700 dark:bg-brand-800">
            {['Release', 'Created', 'Threat model status', 'Model scope', 'Last modeled', 'Details'].map(label => <th key={label} className="px-3 py-3 font-semibold">{label}</th>)}
          </tr></thead>
          <tbody>{product.releases?.map(r => <tr key={r.id} className="border-b border-brand-200 dark:border-brand-700">
            <td className="px-3 py-4"><button className="font-medium hover:underline" disabled={busy} onClick={() => openRelease(r.id)}>{r.name}</button></td>
            <td className="px-3 py-4 whitespace-nowrap">{formatWorkspaceDate(r.created_at)}</td>
            <td className="px-3 py-4"><span>{releaseStatus(r)}</span>{r.model_count > 0 && <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{r.reported_models} with reports / {r.draft_models} draft{r.draft_models === 1 ? '' : 's'}</p>}</td>
            <td className="px-3 py-4">{releaseScopes(r).map(scope => <p key={scope}>{scope}</p>)}{!releaseScopes(r).length && <span className="text-brand-500 dark:text-brand-400">Not selected</span>}</td>
            <td className="px-3 py-4 whitespace-nowrap">{r.reported_models ? formatWorkspaceDate(r.last_modeled_at) : 'Not yet'}</td>
            <td className="px-3 py-4"><button className="ui-button-secondary" title="Open release" aria-label={`Open release ${r.name}`} disabled={busy} onClick={() => openRelease(r.id)}><ArrowRight size={17} /></button></td>
          </tr>)}</tbody>
        </table>
        {!product.releases?.length && <p className="py-8 text-sm">No releases yet.</p>}
      </div>
    </>}
    {release && <>
      {showScope && <form onSubmit={startModel} className="space-y-4 border-y border-brand-200 py-5 dark:border-brand-700">
        <fieldset disabled={!editable || busy || !!product.archived || !!release.archived} className="min-w-0 space-y-4">
          <legend className="mb-3 font-semibold">Threat model scope</legend>
          <div className="flex flex-wrap gap-x-8 gap-y-3">
            <label className="flex cursor-pointer items-center gap-2 text-sm"><input type="radio" name="model-scope" value="release" checked={modelScope === 'release'} onChange={() => setModelScope('release')} />Complete release product</label>
            <label className="flex cursor-pointer items-center gap-2 text-sm"><input type="radio" name="model-scope" value="application" checked={modelScope === 'application'} onChange={() => setModelScope('application')} />Ad hoc standalone application</label>
          </div>
          {modelScope && <div className="flex flex-wrap items-end gap-4">
            {modelScope === 'application' && <label className="grid w-full min-w-0 gap-1 text-sm sm:w-72">Application name<input className={input} required maxLength={200} value={applicationName} onChange={e => setApplicationName(e.target.value)} /></label>}
            <label className="grid w-full min-w-0 gap-1 text-sm sm:w-52">Environment<input required maxLength={100} className={input} value={environment} onChange={e => setEnvironment(e.target.value)} /></label>
          </div>}
          <div className="flex flex-wrap gap-3"><button type="submit" className="btn-brand gap-2" disabled={!modelScope || !environment.trim() || (modelScope === 'application' && !applicationName.trim())}><ArrowRight size={16} />Continue to threat model</button>{release.workspaces.length > 0 && <button type="button" className="ui-button-secondary" onClick={() => { resetScope(); setShowScope(false); }}><X size={16} />Cancel</button>}</div>
        </fieldset>
      </form>}
      <section className="space-y-3">
        <h2 className="font-semibold">Threat models</h2>
        <div className="overflow-x-auto"><table aria-label="Release threat models" className="w-full min-w-[700px] text-left text-sm">
          <thead><tr className="border-b border-brand-200 dark:border-brand-700">{['Model', 'Model scope', 'Environment', 'Status', 'Last modeled', 'Details'].map(label => <th key={label} className="px-3 py-3">{label}</th>)}</tr></thead>
          <tbody>{release.workspaces.map(w => <tr key={w.id} className="border-b border-brand-200 dark:border-brand-700">
            <td className="max-w-xs break-words px-3 py-4">{w.name}</td>
            <td className="px-3 py-4">{w.application_id ? 'Ad hoc application' : 'Complete release product'}{w.application_id && <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{w.application_name || product.applications?.find(a => a.id === w.application_id)?.name || 'Unnamed application'}</p>}</td>
            <td className="px-3 py-4">{w.environment}</td>
            <td className="px-3 py-4">{w.revisions ? 'Report available' : 'Draft'}{w.revisions > 0 && <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{w.revisions} report revision{w.revisions === 1 ? '' : 's'}</p>}</td>
            <td className="px-3 py-4 whitespace-nowrap">{w.revisions ? formatWorkspaceDate(w.last_modeled_at) : 'Not yet'}</td>
            <td className="px-3 py-4"><button className="ui-button-secondary" title="Open model" disabled={busy} aria-label={`Open ${w.name}`} onClick={() => run(async () => onOpen(await enterprise(`/workspaces/${w.id}`)))}><Eye size={17} /></button></td>
          </tr>)}</tbody>
        </table>{!release.workspaces.length && <p className="py-6 text-sm text-brand-500 dark:text-brand-400">No threat models for this release yet.</p>}</div>
      </section>
    </>}
    {!!options.length && !release && <section className="space-y-4 border-t border-brand-200 pt-5 dark:border-brand-700"><h2 className="font-semibold">Compare report revisions</h2><div className="flex flex-wrap gap-3">{['Baseline', 'Target'].map((title, index) => <label key={title} className="grid min-w-0 flex-1 gap-1 text-sm">{title}<select aria-label={title} className={input} value={pair[index]} onChange={e => { setPair(pair.map((v, i) => i === index ? e.target.value : v)); setVersions(versions.map((v, i) => i === index ? options.find(o => o.id === e.target.value)?.revisions || 1 : v)); }}><option value="">Select model</option>{options.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}</select><input aria-label={`${title} revision`} type="number" min="1" max={options.find(o => o.id === pair[index])?.revisions || 1} className={input} value={versions[index]} onChange={e => setVersions(versions.map((v, i) => i === index ? Number(e.target.value) : v))} /></label>)}<button className="ui-button-secondary self-end" disabled={busy || pair.some(v => !v)} onClick={compare}>Compare</button></div></section>}
    {comparison && <section className="space-y-4 border-t border-brand-200 pt-5 dark:border-brand-700"><div className="flex flex-wrap gap-3" role="tablist">{['summary', 'architecture', 'findings', 'evidence'].map(tab => <button role="tab" aria-selected={comparisonTab === tab} className={comparisonTab === tab ? 'border-b-2 border-brand-primary pb-2 font-semibold capitalize' : 'pb-2 capitalize'} key={tab} onClick={() => setComparisonTab(tab)}>{tab}</button>)}<button title="Export comparison" aria-label="Export comparison" onClick={() => download(comparison)}><Download size={17} /></button></div><p className="text-sm text-brand-500 dark:text-brand-300">{comparison.notice}</p>{comparisonTab === 'summary' && <div className="grid gap-4 sm:grid-cols-3">{['components', 'flows', 'findings'].map(key => <div key={key}><h3 className="font-semibold capitalize">{key}</h3><p className="text-sm">{comparison[key].added.length} added, {comparison[key].changed.length} changed, {(comparison[key].removed || comparison[key].no_longer_reported).length} no longer present</p></div>)}</div>}{comparisonTab === 'architecture' && <div className="grid min-w-0 gap-5 lg:grid-cols-2">{comparison.diagrams.map((code, i) => <section className="min-w-0" key={i}><h3 className="mb-3 font-semibold">{i ? 'Target' : 'Baseline'}</h3>{code && <ReviewDiagram code={code} darkMode={darkMode} bindings={{ nodes: [], flows: [] }} onSelect={() => {}} />}</section>)}</div>}{comparisonTab === 'findings' && <div className="divide-y divide-brand-200 dark:divide-brand-700">{[...comparison.findings.added.map(r => [r, 'New']), ...comparison.findings.changed.map(r => [r.after, 'Changed']), ...comparison.findings.no_longer_reported.map(r => [r, 'No longer reported'])].map(([r, state]) => <details className="py-3 text-sm" key={`${state}-${r.id}`}><summary>{state}: {r.title} ({r.severity})</summary><p className="mt-2">{r.description}</p><p className="mt-2">{r.mitigation}</p></details>)}</div>}{comparisonTab === 'evidence' && <p className="text-sm">{comparison.engine_changed ? 'Engine or knowledge diagnostics differ; review their contribution to finding changes.' : 'Engine and knowledge diagnostics match.'} Evidence changes are included in each changed component and finding in the comparison export.</p>}</section>}
    {product && <button className="inline-flex items-center gap-2 text-sm" disabled={busy} onClick={() => release ? openProduct(product.id) : openProducts()}><ArrowLeft size={16} />Back</button>}
    {modal && <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/45 p-4" onClick={() => setModal(null)}><form role="dialog" aria-modal="true" aria-label={modal === 'token' ? 'Workspace access' : `Create ${modal}`} onClick={e => e.stopPropagation()} onSubmit={submit} className="w-full max-w-md space-y-5 rounded-lg border border-brand-200 bg-white p-6 dark:border-brand-700 dark:bg-brand-900"><div className="flex justify-between"><h2 className="font-semibold capitalize">{modal === 'token' ? 'Workspace access' : modal === 'rename' ? 'Rename product' : `${modal} name`}</h2><button type="button" aria-label="Close" onClick={() => setModal(null)}><X size={18} /></button></div><label className="grid gap-2 text-sm">{modal === 'token' ? 'Access token' : 'Name'}<input autoFocus required maxLength={modal === 'token' ? 500 : 200} type={modal === 'token' ? 'password' : 'text'} className={`${input} w-full`} value={name} onChange={e => setName(e.target.value)} /></label><button disabled={busy || !name.trim()} className="btn-brand gap-2" type="submit">{busy ? 'Saving...' : modal === 'token' ? 'Connect' : 'Save'}</button></form></div>}
  </div>;
}
