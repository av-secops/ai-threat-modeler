export function workspaceLocation(hash) {
  if (hash !== '#products' && !hash.startsWith('#products?')) return null;
  const params = new URLSearchParams(hash.split('?')[1]);
  const product_id = params.get('product') || null;
  return { product_id, release_id: product_id ? params.get('release') || null : null,
    model_id: product_id && params.get('release') ? params.get('model') || null : null };
}

export function workspaceHash(location = {}) {
  const params = new URLSearchParams();
  if (location?.product_id) params.set('product', location.product_id);
  if (location?.product_id && location.release_id) params.set('release', location.release_id);
  if (location?.product_id && location.release_id && location.model_id) params.set('model', location.model_id);
  return `#products${params.size ? `?${params}` : ''}`;
}

export function normalizedName(name) {
  return String(name || '').normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
}

export function readListState(key) {
  try { return JSON.parse(sessionStorage.getItem(`aegis-product-list:${key}`) || '{}'); }
  catch { return {}; }
}

export function saveListState(key, state) {
  try { sessionStorage.setItem(`aegis-product-list:${key}`, JSON.stringify(state)); }
  catch { /* Navigation remains available when storage is disabled. */ }
}
