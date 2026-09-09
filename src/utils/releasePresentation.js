export function releaseStatus(release) {
  if (!release.model_count) return 'Not started';
  if (!release.reported_models) return 'Draft only';
  return release.draft_models ? 'Reports and drafts' : 'Report available';
}

export function releaseScopes(release) {
  return [release.release_models > 0 && 'Complete release product',
    release.application_models > 0 && 'Ad hoc application'].filter(Boolean);
}

export function formatWorkspaceDate(value) {
  if (!value) return 'Not recorded';
  const date = new Date(typeof value === 'number' ? value * 1000 : value);
  return Number.isNaN(date.valueOf()) ? 'Not recorded'
    : date.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' });
}
