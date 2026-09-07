import assert from 'node:assert/strict';
import test from 'node:test';
import { revisionDiff, carryAnnotations, commitRevision, applyPreparedPreview, draftSignature } from '../src/utils/modelWorkspace.js';

const data = { score: 70, architecture: { components: [{ id: 'api', name: 'API' }] },
  threats: [{ id: 'T1', title: 'Risk', severity: 'High', tier: 'Confirmed', affected_components: ['api'] }] };

test('previews update only the matching draft, preserving sources and revisions', () => {
  const payload = { edits: [{ element_id: 'service', field: 'add_component' }], sources: [{ text: 'Design' }] };
  const workspace = { id: 'current', revisions: [data], draft: { payload, preview: null } };
  const preview = { architecture: { components: [{ id: 'service' }] } };
  const next = applyPreparedPreview(workspace, 'current', draftSignature(payload), preview);
  assert.equal(next.draft.preview, preview);
  assert.equal(next.draft.payload, payload);
  assert.equal(next.revisions, workspace.revisions);
  assert.equal(next.draft.preparedSignature, draftSignature(payload));
  assert.equal(workspace.draft.preview, null);
});

test('late responses cannot overwrite newer edits or a different workspace', () => {
  const payload = { edits: [{ element_id: 'newer', field: 'add_component' }] };
  const workspace = { id: 'current', draft: { payload } };
  assert.equal(applyPreparedPreview(workspace, 'current', draftSignature({ edits: [] }), {}), workspace);
  assert.equal(applyPreparedPreview(workspace, 'other', draftSignature(payload), {}), workspace);
  assert.equal(applyPreparedPreview(null, 'current', draftSignature(payload), {}), null);
});

test('disappearing findings are not called verified fixes', () => {
  const diff = revisionDiff(data, { threats: [], architecture: { components: [] } });
  assert.match(diff.no_longer_reported[0].reason, /not verified/);
  assert.deepEqual(diff.removed_components, ['API']);
});

test('source changes reopen decisions, preserving notes and prior revisions', () => {
  const annotations = { notes: { T1: 'Investigate' }, owners: { T1: 'Owner' }, reviewStates: { T1: 'accepted' } };
  const diff = revisionDiff(data, data, true);
  assert.equal(carryAnnotations(annotations, diff).reviewStates.T1, 'open');
  assert.equal(annotations.reviewStates.T1, 'accepted');
  const workspace = { revisions: [{ number: 1, sourceDigest: 'old', data, annotations }],
    draft: { payload: { sources: [] }, preview: { source_digest: 'new' } } };
  const next = commitRevision(workspace, data, annotations);
  assert.equal(next.revisions.length, 2);
  assert.equal(workspace.revisions.length, 1);
  assert.equal(next.revisions[1].annotations.notes.T1, 'Investigate');
});

test('unchanged findings keep reviewer decisions', () => {
  const diff = revisionDiff(data, structuredClone(data));
  assert.equal(diff.changed, false);
  assert.deepEqual(diff.revalidation_required, []);
  assert.equal(carryAnnotations({ reviewStates: { T1: 'false_positive' } }, diff).reviewStates.T1, 'false_positive');
});

test('a finding that returns must not inherit an obsolete false-positive decision', () => {
  const previous = { ...data, threats: [] };
  const annotations = { notes: { T1: 'Excluded in the old scope' }, reviewStates: { T1: 'false_positive' } };
  const next = carryAnnotations(annotations, revisionDiff(previous, data));
  assert.equal(next.reviewStates.T1, 'open');
  assert.equal(next.notes.T1, annotations.notes.T1);
  assert.equal(annotations.reviewStates.T1, 'false_positive');
});
