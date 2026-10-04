export const CHANGE_LABELS = {
  new: 'New', removed: 'Removed', no_longer_reported: 'No longer reported', changed: 'Changed',
  improved: 'Improved', worsened: 'Worsened', review_changed: 'Review changed',
  evidence_changed: 'Evidence changed', unchanged: 'Unchanged',
};
export const KIND_LABELS = { finding: 'Risk', component: 'Component', flow: 'Data flow', boundary: 'Trust boundary' };
export const REVIEW_LABELS = {
  pending_review: 'Pending review', acknowledged: 'Acknowledged', accepted_risk: 'Accepted risk',
  verified_fixed: 'Verified fixed', needs_investigation: 'Needs investigation',
};
export const DEFAULT_FILTERS = { query: '', kind: 'all', status: 'changes', severity: 'all', review: 'all' };

export function productPermissions(product, identity) {
  const levels = { viewer: 1, editor: 2, admin: 3 };
  let level = levels[identity?.role] || 0;
  if (identity?.scopes_configured) {
    const grants = new Map((identity.products || []).filter(pair => Array.isArray(pair) && pair.length === 2));
    const scope = product?.id && grants.has(product.id) ? grants.get(product.id) : grants.get('*');
    level = Math.min(level, levels[scope] || 0);
  }
  return {
    edit: typeof product?.permissions?.edit === 'boolean' ? product.permissions.edit : level >= 2,
    admin: typeof product?.permissions?.admin === 'boolean' ? product.permissions.admin : level >= 3,
  };
}

export function revisionOptions(model) {
  return [...new Map((model?.revisions || []).filter(row => Number.isInteger(row.number) && row.number > 0)
    .map(row => [row.number, row])).values()].sort((a, b) => b.number - a.number);
}

export function modelLabel(model, catalog) {
  const release = catalog?.releases?.find(row => row.id === model?.release_id);
  return [release?.name || model?.release_id, model?.application_name || (model?.application_id ? 'Application' : 'Full release'),
    model?.name, model?.environment].filter(Boolean).join(' / ');
}

export function selectionError(request, catalog) {
  for (const side of ['before', 'after']) {
    const model = catalog?.models?.find(row => row.id === request[`${side}_workspace`]);
    if (!model) return `Select the ${side === 'before' ? 'baseline' : 'target'} threat model.`;
    if (!revisionOptions(model).some(row => row.number === request[`${side}_revision`])) return 'Select an available report version for each model.';
  }
  if (request.before_workspace === request.after_workspace && request.before_revision === request.after_revision) {
    return 'Choose different report versions or different threat models.';
  }
  const before = catalog.models.find(row => row.id === request.before_workspace);
  const after = catalog.models.find(row => row.id === request.after_workspace);
  if ((before.application_id || null) !== (after.application_id || null) || before.environment !== after.environment) {
    return 'Choose reports for the same application scope and environment.';
  }
  return '';
}

export function scopeWarnings(request, catalog) {
  const before = catalog?.models?.find(row => row.id === request?.before_workspace);
  const after = catalog?.models?.find(row => row.id === request?.after_workspace);
  if (!before || !after) return [];
  return [(before.application_id || null) !== (after.application_id || null) && 'Application scopes differ. Select the same application or full-release scope on both sides.',
    before.environment !== after.environment && 'Environments differ. Select the same environment on both sides.'].filter(Boolean);
}

export function reviewState(change, reviews = {}) {
  return reviews[change.id]?.status || 'pending_review';
}

export function comparisonCounts(changes = [], reviews = {}) {
  const findings = changes.filter(row => row.kind === 'finding');
  const material = new Set(['new', 'removed', 'changed', 'improved', 'worsened']);
  return {
    new: findings.filter(row => row.status === 'new').length,
    worsened: findings.filter(row => row.status === 'worsened').length,
    improved: findings.filter(row => row.status === 'improved').length,
    no_longer_reported: findings.filter(row => row.status === 'no_longer_reported').length,
    architecture: changes.filter(row => row.kind !== 'finding' && material.has(row.status)).length,
    pending_review: changes.filter(row => row.status !== 'unchanged' && reviewState(row, reviews) === 'pending_review').length,
    new_critical_high: findings.filter(row => row.status === 'new' && ['Critical', 'High'].includes(row.severity)).length,
    verified_fixed: findings.filter(row => reviewState(row, reviews) === 'verified_fixed').length,
  };
}

export function filterChanges(changes = [], filters = DEFAULT_FILTERS, reviews = {}) {
  const query = (filters.query || '').trim().toLowerCase();
  return changes.filter(row => {
    const search = [row.title, row.reason, row.kind, row.severity, ...(row.stride || []),
      row.before?.name, row.after?.name, row.before?.id, row.after?.id,
      ...(row.before?.affected_components || []), ...(row.after?.affected_components || [])].filter(Boolean).join(' ').toLowerCase();
    return (!query || search.includes(query)) &&
      (filters.kind === 'all' || row.kind === filters.kind) &&
      (filters.status === 'all' || (filters.status === 'changes' ? row.status !== 'unchanged' : row.status === filters.status)) &&
      (filters.severity === 'all' || row.severity === filters.severity) &&
      (filters.review === 'all' || reviewState(row, reviews) === filters.review);
  });
}

export function mappingError(mappings, architectures) {
  const before = new Set((architectures?.before?.components || []).map(row => row.id));
  const after = new Set((architectures?.after?.components || []).map(row => row.id));
  const used = new Set();
  for (const [oldId, newId] of Object.entries(mappings || {})) {
    if (!before.has(oldId) || !after.has(newId)) return 'Mappings must use components from these two report snapshots.';
    if (used.has(newId)) return 'Each target component can be mapped to only one baseline component.';
    used.add(newId);
  }
  return '';
}

export function sameMappings(left = {}, right = {}) {
  return Object.keys(left).length === Object.keys(right).length && Object.entries(left).every(([key, value]) => right[key] === value);
}

export function reviewError({ status, remarks, evidence }, change, role) {
  if (!['editor', 'admin'].includes(role)) return 'Your access is read-only.';
  if (!Object.hasOwn(REVIEW_LABELS, status)) return 'Select a review decision.';
  if (status === 'accepted_risk' && role !== 'admin') return 'Only an administrator can accept risk.';
  if (status === 'verified_fixed' && change.kind !== 'finding') return 'Only a risk can be marked verified fixed.';
  if (status === 'verified_fixed' && !(evidence || '').trim()) return 'Verification evidence is required before marking a risk fixed.';
  if ((remarks || '').trim().length < 3) return 'Add a remark explaining this decision.';
  return '';
}

export function requestError(error) {
  if (error?.status === 409) return 'Another reviewer updated this comparison. Reload the latest review, reconcile your remarks, and save again. Your draft has been retained.';
  if (error?.status === 403) return 'You do not have permission for this action. Check your product access or contact an administrator.';
  if (error?.status === 404) return 'This comparison or report is no longer available to your account. Refresh the available reports.';
  return error?.message || 'The comparison request failed. Try again.';
}

export function readableValue(value) {
  if (value === null || value === undefined || value === '') return 'Not recorded';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

export function readableField(value) {
  const label = String(value).replace(/^properties\./, '').replaceAll('_', ' ').replaceAll('.', ' / ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

export function comparisonDate(value) {
  if (!value) return 'Date not recorded';
  const date = new Date(typeof value === 'number' ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? 'Date not recorded' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
