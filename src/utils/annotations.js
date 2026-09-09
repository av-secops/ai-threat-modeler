// What the reviewer wrote, kept separately from what the engine produced.
//
// Owners, notes and review states are the analyst's work, and an analysis is
// re-run often: after amending the model, after a design change, after a fresh
// upload of the same system. Holding them in component state meant they were
// gone by the next render, so a second run silently discarded the human half of
// the review, which is the half that cannot be regenerated.
//
// They are keyed by finding id, which is derived from the rule and the
// component it concerns rather than from position, so a note written about an
// unencrypted bucket reattaches to that same finding on the next run.

const STORAGE_KEY = 'findingAnnotations';

const EMPTY = { owners: {}, notes: {}, componentNotes: {}, reviewStates: {} };

function readAll() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch (error) {
    console.error('Failed to read annotations:', error);
    return {};
  }
}

export function loadAnnotations(projectName) {
  if (!projectName) return { ...EMPTY };
  return { ...EMPTY, ...(readAll()[projectName] || {}) };
}

export function saveAnnotations(projectName, annotations) {
  if (!projectName) return;
  try {
    const all = readAll();
    all[projectName] = { ...EMPTY, ...(all[projectName] || {}), ...annotations };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
    if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('aegis-review-saved', { detail: { key: projectName, annotations: all[projectName] } }));
  } catch (error) {
    console.error('Failed to save annotations:', error);
  }
}

/**
 * Annotations whose finding is no longer reported.
 *
 * A note that loses its finding is not deleted. The finding may come back on
 * the next run, and more importantly the reviewer should be told that the thing
 * they were tracking has gone away rather than having the record vanish with it.
 */
export function orphanedAnnotations(annotations, currentIds) {
  const present = new Set(currentIds);
  const orphans = [];
  for (const field of ['owners', 'notes']) {
    for (const [id, value] of Object.entries(annotations[field] || {})) {
      if (value && !present.has(id) && !orphans.includes(id)) {
        orphans.push(id);
      }
    }
  }
  return orphans;
}
