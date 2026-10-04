import assert from 'node:assert/strict';
import test from 'node:test';
import { diagramRegions, replaceDiagramSource } from '../src/utils/diagramRevision.js';

const component = (id, name, cell) => ({ id, name, type: 'API', trust_level: 'unknown', properties: { diagram_key: cell }, evidence: [{ source_key: cell }] });
const makeSource = (components, flows = []) => ({ id: 'source', name: 'drawing.png', metadata: { artifact_hash: 'old', diagram_model: { components, flows, trust_boundaries: [], metadata: {} } } });

test('replacement retains stable diagram identities and unaffected corrections', () => {
  const before = makeSource([component('old', 'Orders API', '0:a')]);
  const replacement = makeSource([component('new', 'Orders API', '0:a')]);
  replacement.metadata.artifact_hash = 'new';
  const edits = [{ element_id: 'old', field: 'trust_level', value: 'internal' }];
  const result = replaceDiagramSource(before, replacement, edits);
  assert.equal(result.source.metadata.diagram_model.components[0].id, 'old');
  assert.deepEqual(result.edits, edits);
  assert.equal(result.suspended.length, 0);
  assert.equal(replacement.metadata.diagram_model.components[0].id, 'new', 'does not mutate upload');
});

test('changed and removed targets suspend corrections without deleting them', () => {
  const before = makeSource([component('a', 'Orders API', '0:a'), component('b', 'Billing API', '0:b')]);
  const replacement = makeSource([component('n', 'Payments API', '0:a')]);
  const edits = [{ element_id: 'a', field: 'name', value: 'Old label' }, { element_id: 'b', field: 'trust_level', value: 'internal' }];
  const result = replaceDiagramSource(before, replacement, edits);
  assert.equal(result.edits.length, 0);
  assert.equal(result.suspended.length, 2);
  assert.deepEqual(result.source.metadata.diagram_revision.changed, ['a']);
  assert.deepEqual(result.source.metadata.diagram_revision.removed, ['b']);
});

test('same-named repeated services never inherit arbitrary old identities', () => {
  const before = makeSource([component('a', 'API', 'a'), component('b', 'API', 'b')]);
  const replacement = makeSource([component('c', 'API', 'c'), component('d', 'API', 'd')]);
  const result = replaceDiagramSource(before, replacement);
  assert.deepEqual(result.source.metadata.diagram_model.components.map(c => c.id), ['c', 'd']);
});

test('flow endpoint changes are detected after component identity remapping', () => {
  const flow = { id: 'flow', source_id: 'a', target_id: 'b', protocol: 'TLS', description: 'query', properties: { diagram_key: '0:edge' } };
  const before = makeSource([component('a', 'Orders', 'a'), component('b', 'Billing', 'b')], [flow]);
  const next = makeSource([component('x', 'Orders', 'a'), component('y', 'Billing', 'b')], [{ ...flow, id: 'newflow', source_id: 'y', target_id: 'x' }]);
  const result = replaceDiagramSource(before, next, [{ element_id: 'flow', field: 'assumed', value: false }]);
  assert.equal(result.suspended.length, 1);
  assert.equal(result.source.metadata.diagram_model.flows[0].source_id, 'b');
});

test('source overlays are page-scoped and reject invalid coordinates', () => {
  const architecture = { components: [{ id: 'api', name: 'API', evidence: [
    { source_id: 's', page: 2, bbox: [.1, .1, .2, .2] },
    { source_id: 's', page: 2, bbox: [-1, 0, 2, 1] },
    { source_id: 's', page: 1, bbox: [.1, .1, .2, .2] },
  ] }] };
  assert.equal(diagramRegions(architecture, { id: 's' }, 2).length, 1);
  assert.equal(diagramRegions(architecture, { id: 'other' }, 2).length, 0);
});
