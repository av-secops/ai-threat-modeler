import { useCallback, useEffect, useEffectEvent, useRef, useState } from 'react';
import { Plus, ArrowLeft, ArrowRight, Copy, KeyRound, Archive, RotateCcw, X, Eye, ChartColumn, MoreHorizontal, Pencil, History, FolderOpen, Layers3, Files, GitCompareArrows, LoaderCircle, ChevronRight } from 'lucide-react';
import { enterprise, setWorkspaceToken } from '../services/enterprise';
import ReleaseComparisonWorkspace from './ReleaseComparisonWorkspace';
import { productPermissions } from '../utils/releaseComparison';
import { formatWorkspaceDate, releaseScopes, releaseStatus } from '../utils/releasePresentation';
import ProductSecurityDashboard, { SecurityPortfolio } from './ProductSecurityDashboard';
import { dashboardHash, dashboardLocation } from '../utils/productDashboard';
import { normalizedName, readListState, saveListState, workspaceHash, workspaceLocation } from '../utils/productWorkspace';
import FilterBar from './FilterBar';
import WorkspaceNameDialog from './WorkspaceNameDialog';
import ReleaseModelForm from './ReleaseModelForm';

const input = 'input-brand min-w-0 text-sm';
const countLabel = (count, noun) => `${count} ${noun}${count === 1 ? '' : 's'}`;
const modelCounts = release => `${release.reported_models || 0} with reports / ${countLabel(release.draft_models || 0, 'draft')}`;

export default function ProductsWorkspace({ onStart, onOpen: handleOpen, onHistory, darkMode, initialLocation = null, onLocationChange }) {
  const [location, setLocation] = useState(() => ({ ...(workspaceLocation(window.location.hash) || initialLocation || {}), newModelScope: initialLocation?.newModelScope }));
  const [restoring, setRestoring] = useState(!!location?.product_id);
  const [products, setProducts] = useState([]);
  const [product, setProduct] = useState(null);
  const [release, setRelease] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [loadingProducts, setLoadingProducts] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [listStates, setListStates] = useState({});
  const listKey = location.release_id || location.product_id || 'products';
  const listState = listStates[listKey] || readListState(listKey);
  const query = listState.query || '';
  const statusFilter = listState.status || 'all';
  const page = listState.page || 1;
  const updateList = patch => setListStates(current => {
    const next = { ...(current[listKey] || readListState(listKey)), page: 1, ...patch };
    saveListState(listKey, next);
    return { ...current, [listKey]: next };
  });
  const setQuery = value => updateList({ query: value });
  const [modal, setModal] = useState(null);
  const [name, setName] = useState('');
  const [formError, setFormError] = useState('');
  const [notice, setNotice] = useState('');
  const [modelScope, setModelScope] = useState('');
  const [showScope, setShowScope] = useState(false);
  const [modelError, setModelError] = useState('');
  const [showComparison, setShowComparison] = useState(false);
  const [dashboardView, setDashboardView] = useState(() => dashboardLocation(window.location.hash));
  useEffect(() => {
    const changed = () => {
      setDashboardView(dashboardLocation(window.location.hash));
      const next = workspaceLocation(window.location.hash);
      if (next) setLocation(next);
    };
    window.addEventListener('hashchange', changed);
    window.addEventListener('popstate', changed);
    return () => { window.removeEventListener('hashchange', changed); window.removeEventListener('popstate', changed); };
  }, []);
  const navigateDashboard = (hash, replace = false) => {
    window.history[replace ? 'replaceState' : 'pushState'](null, '', window.location.pathname + window.location.search + hash);
    setDashboardView(dashboardLocation(hash));
  };
  const listPosition = useRef(0);
  useEffect(() => {
    const remember = () => { listPosition.current = window.scrollY; };
    window.addEventListener('scroll', remember, { passive: true });
    return () => { window.removeEventListener('scroll', remember); };
  }, []);
  const permissions = productPermissions(product, identity);
  const editable = permissions.edit;
  const onOpen = row => {
    saveListState(listKey, { ...listState, scroll: listPosition.current });
    handleOpen({ ...row, readOnly: !editable || !!product.archived || !!release.archived, productScope: {
    product_id: product.id, product_name: product.name, release_id: release.id, release_name: release.name,
    application_id: row.application_id, application_name: product.applications?.find(a => a.id === row.application_id)?.name || null,
    model_scope: row.application_id ? 'application' : 'release', environment: row.environment,
    } });
  };
  const load = useCallback(async () => {
    setLoadingProducts(true);
    try { setIdentity(await enterprise('/identity')); setProducts(await enterprise('/products')); setError(''); }
    catch (e) { setError(e.message); }
    finally { setLoadingProducts(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!location?.product_id) { setProduct(null); setRelease(null); setRestoring(false); return undefined; }
    let cancelled = false;
    const controller = new AbortController();
    const restore = async () => {
      setRestoring(true); setError(''); setShowComparison(false);
      try {
        const savedProduct = await enterprise(`/products/${location.product_id}`, 'GET', undefined, { signal: controller.signal });
        const savedRelease = location.release_id ? await enterprise(`/releases/${location.release_id}`, 'GET', undefined, { signal: controller.signal }) : null;
        if (cancelled) return;
        if (savedRelease && savedRelease.product_id !== savedProduct.id) throw new Error('The release does not belong to this product.');
        setProduct(savedProduct); setRelease(savedRelease);
        resetScope(); setModelScope(location.newModelScope || '');
        setShowScope(!!savedRelease && (!savedRelease.workspaces.length || !!location.newModelScope));
        onLocationChange?.({ product_id: savedProduct.id, ...(savedRelease ? { release_id: savedRelease.id } : {}) });
        if (location.model_id) {
          const row = await enterprise(`/workspaces/${location.model_id}`, 'GET', undefined, { signal: controller.signal });
          const access = await enterprise('/identity', 'GET', undefined, { signal: controller.signal });
          if (row.release_id !== savedRelease?.id) throw new Error('The threat model does not belong to this release.');
          if (!cancelled) restoreModel(row, savedProduct, savedRelease, access);
        }
      } catch (e) { if (!cancelled) { setProduct(null); setRelease(null); setError(e.message); } }
      finally { if (!cancelled) setRestoring(false); }
    };
    restore();
    return () => { cancelled = true; controller.abort(); };
  }, [location, onLocationChange]);
  const restoreModel = useEffectEvent((row, savedProduct, savedRelease, access) => handleOpen({ ...row,
    readOnly: !productPermissions(savedProduct, access).edit || !!savedProduct.archived || !!savedRelease.archived, productScope: { product_id: savedProduct.id,
      product_name: savedProduct.name, release_id: savedRelease.id, release_name: savedRelease.name,
      application_id: row.application_id, application_name: savedProduct.applications?.find(a => a.id === row.application_id)?.name,
      model_scope: row.application_id ? 'application' : 'release', environment: row.environment } }));
  useEffect(() => {
    if (!restoring) window.scrollTo(0, readListState(listKey).scroll || 0);
  }, [restoring, listKey]);
  const saving = useRef(false);
  const run = async work => {
    if (saving.current) return;
    saving.current = true; setBusy(true); setError(''); setFormError(''); setModelError('');
    try { await work(); } catch (e) { if (modal) setFormError(e.message); else if (showScope) setModelError(e.message); else setError(e.message); }
    finally { saving.current = false; setBusy(false); }
  };
  const navigateWorkspace = next => {
    saveListState(listKey, { ...listState, scroll: listPosition.current });
    const hash = workspaceHash(next);
    if (window.location.hash !== hash) window.history.pushState(null, '', hash);
    setLocation(next || {}); setShowComparison(false); setNotice(''); onLocationChange?.(next?.product_id ? next : null);
  };
  const openProducts = () => { navigateWorkspace({}); load(); };
  const openProduct = id => navigateWorkspace({ product_id: id });
  const resetScope = () => { setModelScope(''); setModelError(''); };
  const closeScope = () => { resetScope(); setShowScope(false); };
  const openRelease = id => navigateWorkspace({ product_id: product.id, release_id: id });
  const showModal = type => { setModal(type); setFormError(''); setName(type === 'rename' ? product.name : ''); };
  const submit = event => {
    event.preventDefault();
    run(async () => {
      if (modal === 'token') { setWorkspaceToken(name.trim()); await load(); }
      else if (modal === 'product') {
        const existing = products.find(p => normalizedName(p.name) === normalizedName(name));
        if (existing) throw new Error(`A product named ${existing.name} already exists${existing.archived ? ' and is archived' : ''}. Open that product instead.`);
        const created = await enterprise('/products', 'POST', { name }); await load(); openProduct(created.id);
        setNotice(`Product ${created.name} created.`);
      }
      else if (modal === 'rename') { await enterprise(`/products/${product.id}`, 'PATCH', { name, archived: !!product.archived }); setProduct(await enterprise(`/products/${product.id}`)); }
      else if (modal === 'archive') {
        await enterprise(`/products/${product.id}`, 'PATCH', { name: product.name, archived: !product.archived });
        setProduct(await enterprise(`/products/${product.id}`));
        setNotice(product.archived ? 'Product restored.' : 'Product archived. Releases and reports are retained.');
      }
      else {
        if ((product.releases || []).some(r => normalizedName(r.name) === normalizedName(name))) throw new Error(`Release ${name.trim()} already exists in ${product.name}.`);
        const path = modal === 'clone' ? `/releases/${release.id}/clone` : `/products/${product.id}/releases`;
        const created = await enterprise(path, 'POST', { name });
        openRelease(created.id); setNotice(`Release ${created.name} created.`);
      }
      setModal(null);
    });
  };
  const startModel = ({ modelScope, applicationChoice, applicationName, environment }) => {
    if (!editable || !modelScope || !environment?.trim() || (modelScope === 'application' && !applicationName?.trim())) return;
    run(async () => {
      const application = modelScope === 'application'
        ? applicationChoice !== 'new' ? product.applications.find(a => a.id === applicationChoice)
          : await enterprise(`/releases/${release.id}/applications`, 'POST', { name: applicationName }) : null;
      if (modelScope === 'application' && !application) throw new Error('Select an application belonging to this product.');
      await onStart({ product_id: product.id, release_id: release.id, application_id: application?.id || null,
        application_name: application?.name || null, model_scope: modelScope,
        environment: environment.trim(), release_name: release.name, product_name: product.name });
    });
  };
  if (dashboardView?.portfolio) return <SecurityPortfolio onBack={() => { navigateDashboard(''); openProducts(); }} onProduct={id => navigateDashboard(dashboardHash(id))} />;
  if (dashboardView?.productId) return <ProductSecurityDashboard key={dashboardView.productId} productId={dashboardView.productId} filters={dashboardView.filters} editable={productPermissions(product?.id === dashboardView.productId ? product : { id: dashboardView.productId }, identity).edit}
    onFilters={filters => navigateDashboard(dashboardHash(dashboardView.productId, filters), true)}
    onBack={() => { navigateDashboard(''); openProduct(dashboardView.productId); }}
    onOpenModel={async model => {
      const row = await enterprise(`/workspaces/${model.id}`);
      const selectedProduct = product?.id === dashboardView.productId ? product : await enterprise(`/products/${dashboardView.productId}`);
      handleOpen({ ...row, selectedRevision: model.revision, dashboardReturn: window.location.hash, readOnly: !productPermissions(selectedProduct, identity).edit || !!selectedProduct.archived,
        productScope: { product_id: selectedProduct.id, product_name: selectedProduct.name, release_id: model.release_id,
          release_name: model.release_name, application_id: model.application_id, application_name: model.application_name,
          model_scope: model.model_scope, environment: model.environment } });
    }} />;
  const rows = release ? release.workspaces : product ? product.releases || [] : products;
  const filteredRows = rows.filter(row => {
    const matchesQuery = `${row.name || ''} ${row.application_name || ''} ${row.environment || ''}`.toLowerCase().includes(query.toLowerCase());
    const matchesStatus = statusFilter === 'all' || (release ? (statusFilter === 'reports' ? row.revisions > 0 : !row.revisions) : (statusFilter === 'archived' ? row.archived : !row.archived));
    return matchesQuery && matchesStatus;
  });
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filteredRows.length / 25)));
  const pageRows = filteredRows.slice((currentPage - 1) * 25, currentPage * 25);
  const filterLabels = { reports: 'Report available', drafts: 'Draft', active: 'Active', archived: 'Archived' };
  const activeFilters = [statusFilter !== 'all' && { key: 'status', label: `Status: ${filterLabels[statusFilter] || statusFilter}`, onRemove: () => updateList({ status: 'all' }) }].filter(Boolean);
  const canCreate = editable && !product?.archived && !release?.archived;
  const modalTitle = { product: 'New product', release: 'New release', clone: 'Copy to a new release', rename: 'Rename product', token: 'Access settings', archive: product?.archived ? 'Restore product?' : 'Archive product?' }[modal];
  const modalContext = modal === 'release' ? `Product: ${product.name}`
    : modal === 'clone' ? `Copy ${product.name} / ${release.name} as new drafts. Existing reports are not copied.`
    : modal === 'archive' ? `${product.name}. ${product.archived ? 'Editing will be available again.' : 'Releases and reports will be retained. Editing will be disabled until the product is restored.'}`
    : undefined;
  const listTitle = release ? 'Threat models' : product ? 'Releases' : 'Products';
  const listNoun = release ? 'threat model' : product ? 'release' : 'product';
  const createAction = () => release ? (resetScope(), setShowScope(true)) : showModal(product ? 'release' : 'product');
  const createLabel = release ? 'New threat model' : product ? 'New release' : 'New product';
  const back = () => showScope ? closeScope() : release ? openProduct(product.id) : openProducts();
  const backLabel = showScope ? 'Back to threat models' : release ? 'Back to releases' : 'Back to products';
  const tableClass = 'w-full table-fixed text-left text-sm';
  const headClass = 'border-y border-brand-200 bg-white text-xs text-brand-600 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-300';
  const rowClass = 'border-b border-brand-200 bg-white/50 hover:bg-white dark:border-brand-700 dark:bg-transparent dark:hover:bg-brand-800/60';
  const cellClass = 'min-w-0 break-words px-3 py-4';
  if (restoring || (!product && loadingProducts)) return <div className="flex items-center gap-3 py-12 text-sm" role="status"><LoaderCircle className="animate-spin" size={18} />{restoring ? 'Opening product...' : 'Loading products...'}</div>;
  if (showComparison && product && !release) return <ReleaseComparisonWorkspace key={product.id} product={product} identity={identity} darkMode={darkMode} onClose={() => setShowComparison(false)} />;
  return <div className="product-workspace min-w-0 space-y-6" aria-busy={busy}>
    <div className="flex flex-wrap items-center justify-between gap-x-5 gap-y-3 border-b border-brand-200 pb-4 dark:border-brand-700">
      <nav aria-label="Product navigation" className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
        {product ? <button disabled={busy} className="hover:underline" onClick={openProducts}>Products</button> : <span aria-current="page">Products</span>}
        {product && <><ChevronRight size={14} aria-hidden="true" className="shrink-0 text-brand-400" />{release
          ? <button className="min-w-0 break-words text-left hover:underline" disabled={busy} onClick={() => openProduct(product.id)}>{product.name}</button>
          : <span aria-current="page" className="min-w-0 break-words">{product.name}</span>}</>}
        {release && <><ChevronRight size={14} aria-hidden="true" className="shrink-0 text-brand-400" /><span aria-current="page" className="min-w-0 break-words">Release {release.name}</span></>}
      </nav>
      <div className="flex flex-wrap items-center gap-4 text-xs text-brand-600 dark:text-brand-300">
        {!product && <button className="inline-flex min-h-9 items-center gap-2 hover:underline" onClick={onHistory}><History size={15} />Analysis history</button>}
        <button title="Workspace access settings" className="inline-flex min-h-9 items-center gap-2 hover:underline" onClick={() => showModal('token')}><KeyRound size={15} />Access settings</button>
      </div>
    </div>
    {error && <div role="alert" className="flex flex-wrap items-center justify-between gap-3 border-l-4 border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950/30 dark:text-red-200"><span>{error}</span>{!product && <button className="ui-button-secondary" onClick={load}><RotateCcw size={15} />Try again</button>}</div>}
    {notice && <p role="status" className="flex items-center justify-between gap-3 text-sm text-emerald-800 dark:text-emerald-300">{notice}<button type="button" title="Dismiss" aria-label="Dismiss confirmation" onClick={() => setNotice('')}><X size={15} /></button></p>}
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {product && <button className="mb-3 inline-flex min-h-8 items-center gap-2 text-sm text-brand-600 hover:text-brand-950 dark:text-brand-300 dark:hover:text-white" disabled={busy} onClick={back}><ArrowLeft size={16} />{backLabel}</button>}
        <h1 className="max-w-full break-words text-2xl font-semibold text-brand-950 dark:text-white">{release ? `Release ${release.name}` : product?.name || 'Products'}</h1>
        {!showScope && <p className="mt-2 text-sm text-brand-600 dark:text-brand-300">{countLabel(rows.length, listNoun)}{product?.archived || release?.archived ? ' / Archived' : ''}</p>}
      </div>
      {!showScope && <div className="flex flex-wrap items-center gap-2 self-end">
        <button className="ui-button-secondary" disabled={busy} onClick={() => navigateDashboard(product ? dashboardHash(product.id, release ? { release_id: release.id } : {}) : '#security-portfolio')}><ChartColumn size={17} />Security dashboard</button>
        {product && !release && <button className="ui-button-secondary" disabled={busy} onClick={() => { setShowComparison(true); window.scrollTo(0, 0); }}><GitCompareArrows size={17} />Compare releases</button>}
        {product && (permissions.admin || release) && <details className="relative" onKeyDown={event => { if (event.key === 'Escape') { event.currentTarget.open = false; event.currentTarget.querySelector('summary')?.focus(); } }}>
          <summary aria-label={release ? 'Release actions' : 'Product actions'} title={release ? 'Release actions' : 'Product actions'} className="ui-button-secondary cursor-pointer list-none p-2.5"><MoreHorizontal size={18} /></summary>
          <div className="absolute right-0 z-20 mt-2 grid w-52 gap-1 rounded-md border border-brand-200 bg-white p-2 shadow-lg dark:border-brand-600 dark:bg-brand-900">
            {release ? <button className="flex items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-brand-50 dark:hover:bg-brand-800" disabled={!canCreate || busy} onClick={event => { event.currentTarget.closest('details').open = false; showModal('clone'); }}><Copy size={15} />Copy to new release</button> : <>
              <button className="flex items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-brand-50 dark:hover:bg-brand-800" disabled={busy} onClick={event => { event.currentTarget.closest('details').open = false; showModal('rename'); }}><Pencil size={15} />Rename product</button>
              <button className="flex items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-brand-50 dark:hover:bg-brand-800" disabled={busy} onClick={event => { event.currentTarget.closest('details').open = false; showModal('archive'); }}>{product.archived ? <RotateCcw size={15} /> : <Archive size={15} />}{product.archived ? 'Restore product' : 'Archive product'}</button>
            </>}
          </div>
        </details>}
        <button className="btn-brand gap-2" disabled={!canCreate || busy} onClick={createAction}><Plus size={16} />{createLabel}</button>
      </div>}
    </div>
    {identity && !canCreate && <p className="border-l-2 border-brand-300 pl-3 text-sm text-brand-600 dark:text-brand-300">{product?.archived || release?.archived ? 'Archived. Editing is unavailable.' : 'Read-only access'}</p>}
    {showScope && release ? <ReleaseModelForm key={release.id} product={product} release={release} initialScope={modelScope} busy={busy} disabled={!canCreate} error={modelError} onSubmit={startModel} onCancel={closeScope} /> : <>
      {!!rows.length && <FilterBar label={`${listTitle} filters`} active={activeFilters} onReset={() => updateList({ status: 'all', query: '' })} search={{ label: `Search ${listTitle.toLowerCase()}`, value: query, onChange: setQuery }}>
        <label className="grid max-w-xs gap-2 text-sm">Status<select className={input} value={statusFilter} onChange={event => updateList({ status: event.target.value })}><option value="all">All statuses</option>{release ? <><option value="reports">Report available</option><option value="drafts">Draft</option></> : <><option value="active">Active</option><option value="archived">Archived</option></>}</select></label>
      </FilterBar>}
      {!!pageRows.length && !product && <table aria-label="Products" className={tableClass}>
        <thead className={headClass}><tr><th scope="col" className="px-3 py-3 text-left">Product</th><th scope="col" className="hidden w-28 px-3 py-3 md:table-cell">Status</th><th scope="col" className="hidden w-24 px-3 py-3 sm:table-cell">Releases</th><th scope="col" className="hidden w-40 px-3 py-3 lg:table-cell">Last assessment</th><th scope="col" className="w-14"><span className="sr-only">Open product</span></th></tr></thead>
        <tbody>{pageRows.map(p => <tr key={p.id} className={rowClass}>
          <td className={cellClass}><button disabled={busy} className="inline-flex min-h-9 max-w-full items-center gap-3 text-left font-semibold hover:underline" onClick={() => openProduct(p.id)}><FolderOpen size={18} className="hidden shrink-0 text-brand-500 sm:block" /><span className="min-w-0 break-words">{p.name}</span></button><p className="mt-1 text-xs text-brand-600 dark:text-brand-300 sm:hidden">{countLabel(p.release_count ?? 0, 'release')} / {p.archived ? 'Archived' : 'Active'}</p></td>
          <td className={`${cellClass} hidden md:table-cell`}><WorkspaceStatus label={p.archived ? 'Archived' : 'Active'} tone={p.archived ? 'muted' : 'neutral'} /></td>
          <td className={`${cellClass} hidden tabular-nums sm:table-cell`}>{p.release_count ?? 0}</td>
          <td className={`${cellClass} hidden lg:table-cell`}>{p.last_modeled_at ? formatWorkspaceDate(p.last_modeled_at) : 'No report yet'}</td>
          <td className="px-2 py-4"><button className="ui-button-secondary p-2" title="Open product" aria-label={`Open ${p.name}`} disabled={busy} onClick={() => openProduct(p.id)}><ChevronRight size={17} /></button></td>
        </tr>)}</tbody>
      </table>}
      {!!pageRows.length && product && !release && <table aria-label="Product releases" className={tableClass}>
        <thead className={headClass}><tr><th scope="col" className="px-3 py-3">Release</th><th scope="col" className="hidden w-40 px-3 py-3 md:table-cell">Threat models</th><th scope="col" className="hidden w-40 px-3 py-3 lg:table-cell">Coverage</th><th scope="col" className="hidden w-36 px-3 py-3 lg:table-cell">Last report</th><th scope="col" className="w-14"><span className="sr-only">Open release</span></th></tr></thead>
        <tbody>{pageRows.map(r => <tr key={r.id} className={rowClass}>
          <td className={cellClass}><button className="inline-flex min-h-9 max-w-full items-center gap-3 text-left font-semibold hover:underline" disabled={busy} onClick={() => openRelease(r.id)}><Layers3 size={18} className="hidden shrink-0 text-brand-500 sm:block" /><span className="min-w-0 break-words">{r.name}</span></button><p className="mt-1 text-xs text-brand-600 dark:text-brand-300">Created {formatWorkspaceDate(r.created_at)}</p><p className="mt-2 text-xs md:hidden">{r.archived ? 'Archived' : releaseStatus(r)}{r.model_count > 0 ? ` / ${modelCounts(r)}` : ''}</p></td>
          <td className={`${cellClass} hidden md:table-cell`}><WorkspaceStatus label={r.archived ? 'Archived' : releaseStatus(r)} tone={r.archived ? 'muted' : r.reported_models ? 'success' : r.model_count ? 'warning' : 'muted'} />{r.model_count > 0 && <p className="mt-2 text-xs text-brand-600 dark:text-brand-300">{modelCounts(r)}</p>}</td>
          <td className={`${cellClass} hidden lg:table-cell`}>{releaseScopes(r).map(scope => <p key={scope}>{scope}</p>)}{!releaseScopes(r).length && <span className="text-brand-500">Not started</span>}</td>
          <td className={`${cellClass} hidden lg:table-cell`}>{r.reported_models ? formatWorkspaceDate(r.last_modeled_at) : 'No report yet'}</td>
          <td className="px-2 py-4"><button className="ui-button-secondary p-2" title="Open release" aria-label={`Open release ${r.name}`} disabled={busy} onClick={() => openRelease(r.id)}><ChevronRight size={17} /></button></td>
        </tr>)}</tbody>
      </table>}
      {!!pageRows.length && release && <table aria-label="Release threat models" className={tableClass}>
        <thead className={headClass}><tr><th scope="col" className="px-3 py-3">Threat model</th><th scope="col" className="hidden w-36 px-3 py-3 lg:table-cell">Environment</th><th scope="col" className="hidden w-36 px-3 py-3 md:table-cell">Status</th><th scope="col" className="hidden w-36 px-3 py-3 xl:table-cell">Last report</th><th scope="col" className="w-36 px-3 py-3 sm:w-44"><span className="sr-only">Open threat model</span></th></tr></thead>
        <tbody>{pageRows.map(w => <tr key={w.id} className={rowClass}>
          <td className={cellClass}><span className="font-semibold">{w.name}</span><p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{w.application_id ? `Application: ${w.application_name || product.applications?.find(a => a.id === w.application_id)?.name || 'Unnamed application'}` : 'Full release'}</p><p className="mt-1 text-xs capitalize text-brand-600 dark:text-brand-300 lg:hidden">{w.environment}{!w.revisions ? ' / Draft' : ''}</p></td>
          <td className={`${cellClass} hidden capitalize lg:table-cell`}>{w.environment}</td>
          <td className={`${cellClass} hidden md:table-cell`}><WorkspaceStatus label={w.revisions ? 'Report available' : 'Draft'} tone={w.revisions ? 'success' : 'warning'} />{w.revisions > 0 && <p className="mt-1 text-xs text-brand-600 dark:text-brand-300">{w.revisions} report version{w.revisions === 1 ? '' : 's'}</p>}</td>
          <td className={`${cellClass} hidden xl:table-cell`}>{w.revisions ? formatWorkspaceDate(w.last_modeled_at) : 'No report yet'}</td>
          <td className="px-2 py-4 text-right"><button className="ui-button-secondary model-open-action w-full" title={w.revisions ? 'View report' : 'Continue draft'} disabled={busy} aria-label={`${w.revisions ? 'View report' : 'Continue draft'}: ${w.name}`} onClick={() => run(async () => onOpen(await enterprise(`/workspaces/${w.id}`)))}>{w.revisions ? <Eye className="hidden shrink-0 sm:block" size={16} /> : <Pencil className="hidden shrink-0 sm:block" size={16} />}<span className="whitespace-nowrap">{w.revisions ? 'View report' : 'Continue draft'}</span></button></td>
        </tr>)}</tbody>
      </table>}
      {!filteredRows.length && !error && <div role="status" className="flex flex-col items-center gap-3 border-y border-brand-200 py-12 text-center dark:border-brand-700">
        {release ? <Files className="text-brand-400" size={28} /> : <FolderOpen className="text-brand-400" size={28} />}
        <h2 className="text-base font-semibold">{rows.length ? 'No matching results' : release ? 'No threat models yet' : product ? 'No releases yet' : 'No products yet'}</h2>
        {rows.length ? <button className="ui-button-secondary" onClick={() => updateList({ status: 'all', query: '' })}><RotateCcw size={15} />Clear search and filters</button> : <button className="ui-button-secondary" disabled={!canCreate || busy} onClick={createAction}><Plus size={15} />{release ? 'Create first threat model' : product ? 'Create first release' : 'Create first product'}</button>}
      </div>}
      {!!filteredRows.length && (filteredRows.length > 25 || filteredRows.length !== rows.length) && <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-brand-600 dark:text-brand-300"><span>{filteredRows.length <= 25 ? `${filteredRows.length} of ${countLabel(rows.length, listNoun)}` : `${(currentPage - 1) * 25 + 1}-${Math.min(currentPage * 25, filteredRows.length)} of ${filteredRows.length}`}</span>{filteredRows.length > 25 && <div className="flex items-center gap-2"><button className="ui-button-secondary p-2" title="Previous page" aria-label="Previous page" disabled={currentPage <= 1} onClick={() => updateList({ page: currentPage - 1 })}><ArrowLeft size={16} /></button><span className="tabular-nums">{currentPage} / {Math.max(1, Math.ceil(filteredRows.length / 25))}</span><button className="ui-button-secondary p-2" title="Next page" aria-label="Next page" disabled={currentPage * 25 >= filteredRows.length} onClick={() => updateList({ page: currentPage + 1 })}><ArrowRight size={16} /></button></div>}</div>}
    </>}
    {modal && <WorkspaceNameDialog title={modalTitle} context={modalContext} label={modal === 'token' ? 'Access token' : `${modal === 'rename' ? 'Product' : modal === 'clone' ? 'New release' : modal[0].toUpperCase() + modal.slice(1)} name`} placeholder={modal === 'product' || modal === 'rename' ? 'e.g. OPTIMA' : modal === 'release' || modal === 'clone' ? 'e.g. 26.10' : undefined} value={name} onChange={value => { setName(value); setFormError(''); }} onSubmit={submit} onClose={() => setModal(null)} busy={busy} error={formError} password={modal === 'token'} confirmOnly={modal === 'archive'} action={modal === 'token' ? 'Connect' : modal === 'rename' ? 'Save name' : modal === 'archive' ? product.archived ? 'Restore product' : 'Archive product' : modal === 'clone' ? 'Create release from copy' : `Create ${modal}`} />}
  </div>;
}

function WorkspaceStatus({ label, tone = 'muted' }) {
  const colors = { success: 'bg-emerald-600 dark:bg-emerald-400', warning: 'bg-amber-600 dark:bg-amber-400', neutral: 'bg-sky-600 dark:bg-sky-400', muted: 'bg-brand-400' };
  return <span className="inline-flex items-center gap-2 text-xs font-medium"><span aria-hidden="true" className={`h-1.5 w-1.5 shrink-0 rounded-full ${colors[tone]}`} />{label}</span>;
}
