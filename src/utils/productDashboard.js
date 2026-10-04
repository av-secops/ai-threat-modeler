export const statusLabels = {
  open: 'Open risks', pending_review: 'Pending review', in_review: 'In review', action_required: 'Action required',
  mitigation_proposed: 'Mitigation proposed', verified_fixed: 'Verified fixed', accepted: 'Accepted risk',
  false_positive: 'False positive', unknown: 'Unverified status',
};
export const filterDefaults = {
  release_id: '', application_id: '', environment: '', scope: 'all', archived: false, tier: 'all',
  quality: 'all', severity: 'all', status: 'all', kind: 'all', search: '', sort: 'severity',
};
export function dashboardLocation(hash) {
  if (hash === '#security-portfolio') return { portfolio: true };
  if (!hash.startsWith('#product-dashboard?')) return null;
  const params = new URLSearchParams(hash.split('?')[1]);
  const productId = params.get('product');
  if (!productId) return null;
  const filters = { ...filterDefaults };
  for (const key of Object.keys(filters)) if (params.has(key)) filters[key] = key === 'archived' ? params.get(key) === 'true' : params.get(key);
  return { productId, filters };
}
export function dashboardHash(productId, filters = {}) {
  const params = new URLSearchParams({ product: productId });
  for (const [key, value] of Object.entries(filters)) if (key in filterDefaults && value !== filterDefaults[key]) params.set(key, String(value));
  return `#product-dashboard?${params}`;
}
export function dashboardQuery(filters, extra = {}) {
  return new URLSearchParams({ ...filterDefaults, ...filters, ...extra }).toString();
}
export function downloadCsv(content) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/csv;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = 'product-risk-register.csv'; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
