import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { JSDOM } from 'jsdom';
import { canonicalDiagramId, clampDiagramZoom, fitDiagramZoom, flowKey, focusedDiagram, isAssumedFlow } from '../src/utils/diagramViews.js';
import { diagramQuality } from '../src/utils/diagramQuality.js';

test('focused image candidates retain deployment groups and undirected connectors', () => {
  const view = focusedDiagram({ components: [component('api'), component('db')], flows: [],
    metadata: { diagram_groups: [{ id: 'vpc', name: 'VPC', components: ['api', 'db'] }],
      diagram_relationships: [{ id: 'r', kind: 'unknown', source_id: 'api', target_id: 'db' }] } }, { componentId: 'api' });
  assert.equal(view.coverage.components_drawn, 2);
  assert.equal(view.coverage.flows_drawn, 0);
  assert.equal(view.coverage.relationships_drawn, 1);
  assert.match(view.diagram, /VPC \(deployment\)/);
  assert.match(view.diagram, /-\.\-\|"Connection needs review"/);
  assert.equal(view.diagram.includes('-->'), false);
  assert.equal(view.diagram.includes('stroke-dasharray'), false);
});

test('legacy reports cannot show an assessed score when an image source is unreviewed', () => {
  const architecture = { components: [], metadata: {
    diagram_extractions: ['one', 'two'].map(source_id => ({ source_id, method: 'ocr_only', version: 2 })),
    diagram_review_tasks: [{ source_id: 'one', kind: 'topology', status: 'reviewed' }],
  } };
  assert.equal(diagramQuality({ architecture }).score_available, false);
});

const component = (id, extra = {}) => ({ id, name: id.toUpperCase(), type: 'Service', trust_level: 'internal', ...extra });
const edge = (id, source_id, target_id, extra = {}) => ({ id, source_id, target_id, flow_number: `F-${id}`, protocol: 'https', data_type: 'pii', ...extra });
const model = () => ({ components: ['a', 'b', 'c', 'd'].map(id => component(id)), flows: [
  edge('001', 'a', 'b'), edge('002', 'a', 'b', { assumed: true }), edge('003', 'b', 'a'),
  edge('004', 'b', 'c'), edge('005', 'c', 'd'),
], trust_boundaries: [{ id: 'outer', name: 'Cloud account', components: [] },
  { id: 'inner', name: 'Private subnet', parent_id: 'outer', components: ['a', 'b'] },
  { id: 'partner', name: 'Partner', components: ['c', 'd'] }] });

test('zoom uses intrinsic dimensions and can fit very large diagrams', () => {
  assert.equal(fitDiagramZoom(2400, 20000, 1000, 500), .025);
  assert.equal(fitDiagramZoom(100, 100, 1000, 500), 1);
  assert.equal(clampDiagramZoom(0), .005);
  assert.equal(clampDiagramZoom(20), 4);
  assert.equal(clampDiagramZoom(NaN), 1);
});

test('canonical IDs match the backend SHA256 contract', async () => {
  const id = 'api/customer-v2';
  assert.equal(await canonicalDiagramId(id), 'n_' + createHash('sha256').update(id).digest('hex').slice(0, 16));
});

test('a trace selects exactly one parallel edge, with original direction, number and basis', () => {
  const architecture = model(); const original = structuredClone(architecture);
  const view = focusedDiagram(architecture, { flowId: '002' });
  assert.deepEqual(view.indexes, [1]);
  assert.deepEqual(view.coverage.component_ids, ['a', 'b']);
  assert.match(view.diagram, /focus_n0 -.->\|"F-002: https \/ pii \(assumed\)"\| focus_n1/);
  assert.deepEqual(architecture, original);
  const reversed = focusedDiagram(architecture, { flowId: '003' });
  assert.match(reversed.diagram, /focus_n1 -->.*focus_n0/);
});

test('component focus shows only incident edges and retains isolated components', () => {
  const view = focusedDiagram(model(), { componentId: 'b' });
  assert.deepEqual(view.indexes, [0, 1, 2, 3]);
  assert.deepEqual(new Set(view.coverage.component_ids), new Set(['a', 'b', 'c']));
  assert.equal(view.nodes[0].element_id, 'b');
  assert.equal(view.diagram.includes('F-005'), false);
  const isolated = focusedDiagram({ components: [component('only')], flows: [] }, { componentId: 'only' });
  assert.equal(isolated.coverage.components_drawn, 1);
  assert.equal(isolated.coverage.flows_drawn, 0);
  assert.equal(focusedDiagram(model()), null);
});

test('boundary parents and overlaps remain explicit without empty ancestor boxes', () => {
  const architecture = model();
  assert.match(focusedDiagram(architecture, { flowId: '001' }).diagram, /\["Cloud account"\]\nsubgraph .*\["Private subnet"\]/);
  architecture.trust_boundaries.push({ id: 'tenant', name: 'Tenant', components: ['a', 'b'] });
  const overlap = focusedDiagram(architecture, { flowId: '001' });
  assert.match(overlap.diagram, /Overlapping boundaries: Private subnet \/ Tenant/);
  assert.equal(overlap.diagram.includes('["Cloud account"]'), false);
  architecture.trust_boundaries[0].parent_id = 'inner';
  assert.ok(focusedDiagram(architecture, { flowId: '001' }).diagram.length < 2000);
});

test('cloud-account and tenant crossings retain the canonical thick-arrow meaning', () => {
  const architecture = model();
  architecture.components[0].properties = { cloud_account: 'account-a' };
  architecture.components[1].properties = { cloud_account: 'account-b' };
  assert.match(focusedDiagram(architecture, { flowId: '001' }).diagram, /focus_n0 ==>.*focus_n1/);
  architecture.components[1].properties = { cloud_account: 'account-a' };
  assert.match(focusedDiagram(architecture, { flowId: '001' }).diagram, /focus_n0 -->.*focus_n1/);
});

test('legacy flow identity and assumed flags are not upgraded into verified evidence', () => {
  assert.equal(flowKey({ properties: { review_id: 'review-flow' } }, 4), 'review-flow');
  assert.equal(flowKey({}, 4), 'flow-index:4');
  assert.equal(isAssumedFlow({ properties: { assumed: true } }), true);
  assert.equal(isAssumedFlow({ properties: { assumed: 'false' } }), false);
  const architecture = model(); delete architecture.flows[0].id;
  assert.deepEqual(focusedDiagram(architecture, { flowId: 'flow-index:0' }).indexes, [0]);
});

test('invalid endpoints are not fabricated and rendering limits report omitted items', () => {
  const architecture = model(); architecture.flows.push(edge('bad', 'a', 'missing'));
  assert.equal(focusedDiagram(architecture, { flowId: 'bad' }).coverage.flows_drawn, 0);
  const large = { components: Array.from({ length: 130 }, (_, i) => component(`node-${i}`)),
    flows: Array.from({ length: 129 }, (_, i) => edge(`${i}`, 'node-0', `node-${i + 1}`)) };
  const view = focusedDiagram(large, { componentId: 'node-0' });
  assert.equal(view.coverage.components_drawn, 80);
  assert.equal(view.coverage.components_hidden_for_readability, 50);
  assert.equal(view.coverage.flows_drawn, 79);
  assert.equal(view.coverage.flows_hidden_for_readability, 50);
  assert.equal(view.coverage.complete, false);
  large.flows = Array.from({ length: 130 }, (_, i) => edge(`${i}`, 'node-0', 'node-1'));
  assert.equal(focusedDiagram(large, { componentId: 'node-0' }).coverage.flows_hidden_for_readability, 10);
});

test('generated Mermaid parses; label content cannot introduce nodes; confirmed outlines stay scoped', async () => {
  const dom = new JSDOM('<!doctype html><html><body></body></html>');
  const oldWindow = globalThis.window; const oldDocument = globalThis.document;
  globalThis.window = dom.window; globalThis.document = dom.window.document;
  try {
    const { default: mermaid } = await import('mermaid');
    mermaid.initialize({ securityLevel: 'strict', startOnLoad: false });
    const architecture = model();
    architecture.components[0].name = 'API "test" <label> | end\nphantom["fake"]';
    const view = focusedDiagram(architecture, { componentId: 'a', threats: [
      { component: 'a', tier: 'Confirmed' }, { component: 'b', tier: 'Potential' },
    ] });
    assert.ok(await mermaid.parse(view.diagram));
    assert.match(view.diagram, /&lt;label&gt;/);
    assert.equal(view.nodes.length, 2);
    assert.match(view.diagram, /style focus_n0 stroke:#dc2626/);
    assert.equal(view.diagram.includes('style focus_n1 stroke:#dc2626'), false);
  } finally {
    globalThis.window = oldWindow; globalThis.document = oldDocument; dom.window.close();
  }
});
