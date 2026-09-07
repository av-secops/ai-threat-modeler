// Keep extracted documents and immutable revisions out of localStorage's small quota.
const DATABASE = 'aegis-model-workspaces';
const STORE = 'workspaces';

function transaction(mode, work) {
  return new Promise((resolve, reject) => {
    const opening = indexedDB.open(DATABASE, 1);
    opening.onupgradeneeded = () => opening.result.createObjectStore(STORE, { keyPath: 'id' });
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
      const database = opening.result;
      const tx = database.transaction(STORE, mode);
      const request = work(tx.objectStore(STORE));
      tx.oncomplete = () => { database.close(); resolve(request.result); };
      tx.onerror = () => { database.close(); reject(tx.error || request.error); };
      tx.onabort = () => { database.close(); reject(tx.error || new Error('Workspace save was interrupted.')); };
    };
  });
}

export const saveWorkspace = (workspace) => transaction('readwrite', (store) => store.put(structuredClone(workspace)));
export const loadWorkspace = (id) => transaction('readonly', (store) => store.get(id));
export const loadWorkspaces = () => transaction('readonly', (store) => store.getAll());
export const deleteWorkspace = (id) => transaction('readwrite', (store) => store.delete(id));
export const clearWorkspaces = () => transaction('readwrite', (store) => store.clear());
export const annotationKey = (id, revision) => `workspace:${id}:revision:${revision}`;

export function newWorkspace(projectName, payload, legacyId = null) {
  return { id: crypto.randomUUID(), projectName, legacyId, updatedAt: new Date().toISOString(),
    revisions: [], draft: { payload, preview: null, preparedSignature: null }, schemaVersion: 1 };
}

export function draftSignature(payload) {
  return JSON.stringify(payload);
}

export function applyPreparedPreview(workspace, workspaceId, signature, preview) {
  if (!workspace || workspace.id !== workspaceId || draftSignature(workspace.draft.payload) !== signature) return workspace;
  return { ...workspace, draft: { ...workspace.draft, preview, preparedSignature: signature } };
}

function findingFingerprint(finding) {
  return JSON.stringify([finding.severity, finding.tier, finding.risk_score, finding.root_cause,
    finding.affected_components, finding.affected_data_flows, finding.evidence_details,
    finding.explanation?.matched_controls, finding.explanation?.control_state]);
}

export function revisionDiff(previous, current, sourcesChanged = false) {
  if (!previous) return null;
  const before = new Map((previous.threats || []).map((item) => [item.id, item]));
  const after = new Map((current.threats || []).map((item) => [item.id, item]));
  const oldComponents = new Map((previous.architecture?.components || []).map((c) => [c.id, c.name]));
  const newComponents = new Map((current.architecture?.components || []).map((c) => [c.id, c.name]));
  const newThreats = [...after.values()].filter((t) => !before.has(t.id));
  const absent = [...before.values()].filter((t) => !after.has(t.id)).map((t) => ({ ...t,
    reason: (t.affected_components || []).some((id) => !newComponents.has(id))
      ? 'Affected component is no longer in scope. Remediation was not verified.'
      : 'No longer produced from the current evidence. Remediation was not verified.' }));
  const changed = [...after.values()].filter((t) => before.has(t.id) && findingFingerprint(t) !== findingFingerprint(before.get(t.id)));
  const revalidation = [...after.values()].filter((t) => before.has(t.id) && (sourcesChanged || changed.some((c) => c.id === t.id)));
  return { changed: !!(newThreats.length || absent.length || changed.length || sourcesChanged),
    new_threats: newThreats, resolved_threats: absent, no_longer_reported: absent,
    severity_changes: changed.filter((t) => t.severity !== before.get(t.id).severity || t.tier !== before.get(t.id).tier).map((t) => ({
      id: t.id, title: t.title, from_severity: before.get(t.id).severity, to_severity: t.severity,
      from_tier: before.get(t.id).tier, to_tier: t.tier,
    })),
    revalidation_required: revalidation.map((t) => t.id),
    added_components: [...newComponents].filter(([id]) => !oldComponents.has(id)).map(([, name]) => name),
    removed_components: [...oldComponents].filter(([id]) => !newComponents.has(id)).map(([, name]) => name),
    score_delta: (current.score || 0) - (previous.score || 0),
    score_delta_explanation: sourcesChanged ? ['Source material changed; previous review decisions need revalidation.'] : [],
  };
}

export function carryAnnotations(annotations, diff) {
  const next = structuredClone(annotations);
  const reviewAgain = new Set([...(diff?.revalidation_required || []), ...(diff?.new_threats || []).map((t) => t.id)]);
  for (const id of reviewAgain) {
    if (next.reviewStates?.[id]) next.reviewStates[id] = 'open';
  }
  return next;
}

export function commitRevision(workspace, data, annotations) {
  const previous = workspace.revisions.at(-1);
  const sourceDigest = workspace.draft.preview.source_digest;
  const diff = revisionDiff(previous?.data, data, !!previous && previous.sourceDigest !== sourceDigest);
  const number = (previous?.number || 0) + 1;
  const revision = { number, createdAt: new Date().toISOString(), sourceDigest,
    payload: structuredClone(workspace.draft.payload), preview: structuredClone(workspace.draft.preview),
    data: { ...data, diff_summary: diff }, annotations: carryAnnotations(annotations, diff) };
  return { ...workspace, updatedAt: revision.createdAt, revisions: [...workspace.revisions, revision] };
}
