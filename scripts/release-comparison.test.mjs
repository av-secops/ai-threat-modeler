import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DEFAULT_FILTERS, revisionOptions, modelLabel, selectionError, scopeWarnings, comparisonCounts,
  filterChanges, mappingError, sameMappings, reviewError, requestError, readableValue, readableField, comparisonDate, productPermissions,
} from '../src/utils/releaseComparison.js';

const catalog = {
  product: { id: 'product', name: 'Test product' },
  releases: [{ id: 'r1', name: '26.09' }, { id: 'r2', name: '26.10' }],
  models: [
    { id: 'm1', name: 'Product model', release_id: 'r1', application_id: null, environment: 'production', revision_count: 2, revisions: [{ number: 1 }, { number: 4 }] },
    { id: 'm2', name: 'Product model', release_id: 'r2', application_id: null, environment: 'production', revision_count: 2, revisions: [{ number: 2 }, { number: 5 }] },
  ],
};
const request = { before_workspace: 'm1', after_workspace: 'm2', before_revision: 4, after_revision: 5 };
const changes = [
  { id: 'new-risk', kind: 'finding', title: 'Unsigned events', status: 'new', severity: 'High', reason: 'Event validation is absent.', stride: ['Tampering'], after: { id: 'f1', severity: 'High', affected_components: ['api-v2'] }, fields: [] },
  { id: 'absent-risk', kind: 'finding', title: 'Public data store', status: 'no_longer_reported', severity: 'Critical', reason: 'Remediation is not verified.', before: { id: 'f2', severity: 'Critical' }, fields: [] },
  { id: 'worse-risk', kind: 'finding', title: 'Overprivileged identity', status: 'worsened', severity: 'Critical', before: { severity: 'High' }, after: { severity: 'Critical' }, fields: [{ field: 'severity', before: 'High', after: 'Critical' }] },
  { id: 'better-risk', kind: 'finding', title: 'Token lifetime', status: 'improved', severity: 'Low' },
  { id: 'evidence-risk', kind: 'finding', title: 'Source update', status: 'evidence_changed', severity: 'Medium' },
  { id: 'review-risk', kind: 'finding', title: 'Owner reassigned', status: 'review_changed', severity: 'Medium' },
  { id: 'same-risk', kind: 'finding', title: 'Unchanged finding', status: 'unchanged', severity: 'Low' },
  { id: 'component', kind: 'component', title: 'API v2', status: 'changed', before: { id: 'api', name: 'API' }, after: { id: 'api-v2', name: 'API v2' }, fields: [{ field: 'name', before: 'API', after: 'API v2' }] },
  { id: 'flow', kind: 'flow', title: 'API to store', status: 'improved', fields: [{ field: 'protocol', before: 'http', after: 'https' }] },
  { id: 'boundary', kind: 'boundary', title: 'Private network', status: 'new' },
];
const architectures = { before: { components: [{ id: 'api', name: 'API', type: 'service' }, { id: 'old-store', name: 'Storage', type: 'database' }] },
  after: { components: [{ id: 'api-v2', name: 'API v2', type: 'service' }, { id: 'new-store', name: 'Storage v2', type: 'database' }] } };

test('revision choices use actual metadata, not contiguous revision counts', () => {
  assert.deepEqual(revisionOptions(catalog.models[0]).map(row => row.number), [4, 1]);
  assert.deepEqual(revisionOptions({ revisions: [{ number: 3 }, { number: 3 }, { number: 0 }, { number: '6' }, { number: -2 }] }), [{ number: 3 }]);
  assert.deepEqual(revisionOptions(), []);
});

test('product authority honors server flags and scoped grants instead of global roles', () => {
  const identity = { role: 'admin', scopes_configured: true, products: [['product', 'editor'], ['restricted', 'viewer']] };
  assert.deepEqual(productPermissions({ id: 'product' }, identity), { edit: true, admin: false });
  assert.deepEqual(productPermissions({ id: 'restricted' }, identity), { edit: false, admin: false });
  assert.deepEqual(productPermissions({ id: 'foreign' }, identity), { edit: false, admin: false });
  assert.deepEqual(productPermissions(null, identity), { edit: false, admin: false });
  assert.deepEqual(productPermissions(null, { ...identity, products: [['*', 'editor']] }), { edit: true, admin: false });
  assert.deepEqual(productPermissions({ id: 'product', permissions: { edit: false, admin: false } }, { role: 'admin' }), { edit: false, admin: false });
  assert.deepEqual(productPermissions({ id: 'product' }, { role: 'editor' }), { edit: true, admin: false });
  assert.deepEqual(productPermissions({ id: 'product' }, { role: 'viewer', scopes_configured: true, products: [['*', 'admin']] }), { edit: false, admin: false });
  assert.deepEqual(productPermissions({ id: 'product' }, { ...identity, products: [['*', 'admin'], ['product', 'viewer']] }), { edit: false, admin: false });
});

test('selection validates model membership, revision membership, and identical snapshots', () => {
  assert.equal(selectionError(request, catalog), '');
  assert.match(selectionError({ ...request, before_revision: 3 }, catalog), /available report version/);
  assert.match(selectionError({ ...request, after_workspace: 'another-product' }, catalog), /target threat model/);
  assert.match(selectionError({ ...request, after_workspace: 'm1', after_revision: 4 }, catalog), /different/);
  assert.equal(selectionError({ ...request, after_workspace: 'm1', after_revision: 1 }, catalog), '');
});

test('labels and scope warnings distinguish release, application and environment', () => {
  assert.equal(modelLabel(catalog.models[0], catalog), '26.09 / Full release / Product model / production');
  assert.deepEqual(scopeWarnings(request, catalog), []);
  const changed = { ...catalog, models: [catalog.models[0], { ...catalog.models[1], application_id: 'billing', application_name: 'Billing', environment: 'staging' }] };
  assert.equal(scopeWarnings(request, changed).length, 2);
  assert.match(selectionError(request, changed), /same application scope and environment/);
  assert.match(modelLabel(changed.models[1], changed), /Billing/);
});

test('risk and architecture counts never treat an absent finding as verified remediation', () => {
  assert.deepEqual(comparisonCounts(changes), { new: 1, worsened: 1, improved: 1, no_longer_reported: 1, architecture: 3, pending_review: 9, new_critical_high: 1, verified_fixed: 0 });
  const reviewed = comparisonCounts(changes, { 'absent-risk': { status: 'verified_fixed' }, 'component': { status: 'acknowledged' } });
  assert.equal(reviewed.verified_fixed, 1);
  assert.equal(reviewed.pending_review, 7);
  assert.equal(reviewed.no_longer_reported, 1);
});

test('filters combine search, kind, outcome, severity, and independent review status', () => {
  assert.equal(filterChanges(changes).length, 9);
  assert.equal(filterChanges(changes, { ...DEFAULT_FILTERS, status: 'all' }).length, 10);
  assert.deepEqual(filterChanges(changes, { ...DEFAULT_FILTERS, query: ' tampering ', kind: 'finding', severity: 'High' }).map(row => row.id), ['new-risk']);
  assert.deepEqual(filterChanges(changes, { ...DEFAULT_FILTERS, status: 'no_longer_reported' }).map(row => row.id), ['absent-risk']);
  assert.deepEqual(filterChanges(changes, { ...DEFAULT_FILTERS, review: 'verified_fixed' }).map(row => row.id), []);
  assert.deepEqual(filterChanges(changes, { ...DEFAULT_FILTERS, review: 'verified_fixed' }, { 'absent-risk': { status: 'verified_fixed' } }).map(row => row.id), ['absent-risk']);
  assert.equal(filterChanges(changes, { ...DEFAULT_FILTERS, query: 'api-v2', kind: 'finding' }).length, 1);
  assert.equal(filterChanges(changes, { ...DEFAULT_FILTERS, kind: 'component', severity: 'High' }).length, 0);
});

test('explicit mappings are one-to-one and limited to the two snapshots', () => {
  assert.equal(mappingError({ api: 'api-v2' }, architectures), '');
  assert.match(mappingError({ api: 'api-v2', 'old-store': 'api-v2' }, architectures), /only one/);
  assert.match(mappingError({ foreign: 'api-v2' }, architectures), /snapshots/);
  assert.match(mappingError({ api: 'foreign' }, architectures), /snapshots/);
  assert.equal(mappingError({}, architectures), '');
  assert.equal(sameMappings({ a: 'x', b: 'y' }, { b: 'y', a: 'x' }), true);
  assert.equal(sameMappings({ a: 'x' }, { a: 'z' }), false);
  assert.equal(sameMappings({ a: 'x' }, {}), false);
});

test('review decisions enforce roles, finding-only verification, evidence and remarks', () => {
  const review = { status: 'acknowledged', remarks: 'Reviewed', evidence: '' };
  assert.equal(reviewError(review, changes[0], 'editor'), '');
  assert.match(reviewError(review, changes[0], 'viewer'), /read-only/);
  assert.match(reviewError({ ...review, status: 'accepted_risk' }, changes[0], 'editor'), /administrator/);
  assert.equal(reviewError({ ...review, status: 'accepted_risk' }, changes[0], 'admin'), '');
  assert.match(reviewError({ ...review, status: 'verified_fixed' }, changes[1], 'editor'), /evidence/);
  assert.equal(reviewError({ ...review, status: 'verified_fixed', evidence: 'Test result ABC' }, changes[1], 'editor'), '');
  assert.match(reviewError({ ...review, status: 'verified_fixed', evidence: 'Test' }, changes[7], 'admin'), /Only a risk/);
  assert.match(reviewError({ ...review, status: 'pending_review', remarks: ' ' }, changes[0], 'editor'), /remark/);
  assert.match(reviewError({ ...review, status: 'invalid' }, changes[0], 'admin'), /decision/);
});

test('error text differentiates conflicts from access and removed records', () => {
  assert.match(requestError({ status: 409 }), /draft has been retained/);
  assert.match(requestError({ status: 403 }), /permission/);
  assert.match(requestError({ status: 404 }), /no longer available/);
  assert.equal(requestError(new Error('Network unavailable')), 'Network unavailable');
});

test('presentation preserves unknown values and serializes structured evidence', () => {
  assert.equal(readableValue(null), 'Not recorded');
  assert.equal(readableValue(false), 'No');
  assert.equal(readableValue(0), '0');
  assert.match(readableValue({ control: true }), /"control": true/);
  assert.equal(readableField('properties.encryption_at_rest'), 'Encryption at rest');
  assert.equal(comparisonDate('not a date'), 'Date not recorded');
  assert.equal(comparisonDate(1770000000), comparisonDate(new Date(1770000000000).toISOString()));
});

test('comparison UI uses the catalog, immutable snapshots and optimistic reviews', async t => {
  const { JSDOM } = await import('jsdom');
  const { createServer } = await import('vite');
  const React = await import('react');
  const { act } = React;
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost:5173/' });
  const globals = new Map();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document,
    sessionStorage: dom.window.sessionStorage, IS_REACT_ACT_ENVIRONMENT: true })) {
    globals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const originalFetch = globalThis.fetch;
  const server = await createServer({ server: { middlewareMode: true, hmr: false }, appType: 'custom', logLevel: 'error' });
  let root;
  const calls = [];
  let conflict = true;
  let snapshot;
  const result = { changes, architectures, diagrams: [null, null], notice: 'No longer reported is not verified remediation.',
    matches: [{ before_id: 'api', after_id: 'api-v2', method: 'resource_identity' }],
    mapping_suggestions: [{ before_id: 'old-store', before_name: 'Storage', candidates: [{ id: 'new-store', name: 'Storage v2', similarity: 0.5 }] }],
    warnings: ['Engine or knowledge provenance is incomplete in at least one report.'],
    provenance: { before: { engine_versions: ['1'] }, after: { engine_versions: ['2'] } }, engine_changed: true };
  try {
    const { createRoot } = await import('react-dom/client');
    const { default: Workspace } = await server.ssrLoadModule('/src/components/ReleaseComparisonWorkspace.jsx');
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname.replace('/enterprise', '');
      const body = options.body && JSON.parse(options.body);
      calls.push({ path, method: options.method, body });
      let value;
      if (path === '/products/product/comparison-catalog') value = catalog;
      else if (path === '/products/product/comparisons' && options.method === 'GET') value = { items: [], next_offset: null };
      else if (path === '/compare') value = result;
      else if (path === '/products/product/comparisons' && options.method === 'POST') {
        snapshot = { id: 'saved-1', version: 1, result, request: body.comparison, review: {}, name: body.name, created: 1770000000 };
        value = snapshot;
      } else if (path === '/comparisons/saved-1' && options.method === 'GET') value = snapshot;
      else if (path === '/comparisons/saved-1/reviews/absent-risk' && options.method === 'PATCH') {
        if (conflict) {
          conflict = false;
          snapshot = { ...snapshot, version: 2, review: { 'absent-risk': { status: 'needs_investigation', remarks: 'Other review', reviewer: 'Architect' } } };
          return new Response(JSON.stringify({ detail: 'Conflict' }), { status: 409 });
        }
        assert.equal(body.expected_version, 2);
        snapshot = { ...snapshot, version: 3, review: { 'absent-risk': { ...body, reviewer: 'Test reviewer' } } };
        value = snapshot;
      } else throw new Error(`Unexpected API request: ${options.method} ${path}`);
      return new Response(JSON.stringify(value), { status: 200 });
    };
    const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 15)); });
    const button = name => [...document.querySelectorAll('button')].find(node => (node.getAttribute('aria-label') || node.textContent).trim() === name);
    const click = async node => { assert.ok(node, 'Expected button is present'); await act(async () => node.click()); await settle(); };
    const change = async (node, value) => {
      assert.ok(node, 'Expected input is present');
      await act(async () => {
        const prototype = node.tagName === 'SELECT' ? dom.window.HTMLSelectElement.prototype : node.tagName === 'TEXTAREA' ? dom.window.HTMLTextAreaElement.prototype : dom.window.HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype, 'value').set.call(node, value);
        node.dispatchEvent(new dom.window.Event(node.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
      });
    };
    root = createRoot(document.getElementById('root'));
    await act(async () => root.render(React.createElement(Workspace, { product: catalog.product, identity: { role: 'editor' }, darkMode: false, onClose() {} })));
    await settle();

    await t.test('explicit selection uses non-contiguous version numbers and clears stale results', async () => {
      assert.equal(button('Compare reports').disabled, true);
      await change(document.querySelector('select[aria-label="Baseline report"]'), 'm1');
      await change(document.querySelector('select[aria-label="Target report"]'), 'm2');
      await click(button('Compare reports'));
      assert.deepEqual(calls.find(call => call.path === '/compare').body, request);
      assert.equal(document.querySelectorAll('table[aria-label="Release comparison changes"] tbody tr').length, 9);
      assert.match(document.body.textContent, /0 verified fixed/);
      await change(document.querySelector('select[aria-label="Target report version"]'), '2');
      assert.equal(document.querySelector('table[aria-label="Release comparison changes"]'), null);
      await change(document.querySelector('select[aria-label="Target report version"]'), '5');
      await click(button('Compare reports'));
    });

    await t.test('mapping review understands backend match IDs and rejects duplicate targets', async () => {
      await click(button('Component matches'));
      const rows = document.querySelectorAll('table[aria-label="Component mappings"] tbody tr');
      assert.match(rows[0].cells[1].textContent, /API v2/);
      assert.match(rows[0].textContent, /Resource identity/);
      await change(document.querySelector('select[aria-label="Map API"]'), 'api-v2');
      await change(document.querySelector('select[aria-label="Map Storage"]'), 'api-v2');
      assert.equal(button('Compare with mappings').disabled, true);
      assert.match(document.body.textContent, /only one baseline component/);
      await change(document.querySelector('select[aria-label="Map Storage"]'), 'new-store');
      await click(button('Compare with mappings'));
      assert.deepEqual(calls.filter(call => call.path === '/compare').at(-1).body.component_mappings, { api: 'api-v2', 'old-store': 'new-store' });
    });

    await t.test('save creates a new snapshot and never overwrites a report', async () => {
      await click(button('Save comparison'));
      await click(button('Save snapshot'));
      assert.ok(snapshot.id);
      assert.match(document.body.textContent, /Review version 1/);
      assert.equal(calls.some(call => ['PUT', 'DELETE'].includes(call.method)), false);
      assert.equal(calls.some(call => call.path.startsWith('/workspaces/')), false);
    });

    await t.test('verification needs evidence and conflicts retain drafts until explicitly reloaded', async () => {
      await click(button('View details: Public data store'));
      const reviewSelect = document.querySelector('[role="dialog"] select');
      assert.equal(reviewSelect.querySelector('option[value="accepted_risk"]').disabled, true);
      await change(reviewSelect, 'verified_fixed');
      await change(document.querySelectorAll('[role="dialog"] textarea')[0], 'Re-tested access restrictions');
      await click(button('Save review'));
      assert.match(document.querySelector('[role="dialog"]').textContent, /Verification evidence is required/);
      assert.equal(calls.some(call => call.method === 'PATCH'), false);
      await change(document.querySelectorAll('[role="dialog"] textarea')[1], 'Access test SEC-42 passed');
      await click(button('Save review'));
      assert.match(document.querySelector('[role="dialog"]').textContent, /draft has been retained/);
      assert.equal(button('Save review').disabled, true);
      await click(button('Reload latest review'));
      assert.match(document.querySelector('[role="dialog"]').textContent, /Other review/);
      assert.equal(document.querySelectorAll('[role="dialog"] textarea')[0].value, 'Re-tested access restrictions');
      assert.equal(button('Save review').disabled, false);
      await click(button('Save review'));
      assert.equal(document.querySelector('[role="dialog"]'), null);
      assert.match(document.body.textContent, /1 verified fixed/);
      assert.equal(snapshot.review['absent-risk'].evidence, 'Access test SEC-42 passed');
    });

    await t.test('reopening uses the immutable saved response rather than recomparing', async () => {
      const beforeCount = calls.filter(call => call.path === '/compare').length;
      await click(button('Open comparison'));
      assert.equal(calls.filter(call => call.path === '/compare').length, beforeCount);
      assert.match(document.body.textContent, /Review version 3/);
      assert.ok(document.querySelector('button[aria-label="Export comparison JSON"]'));
    });

    await t.test('viewer has no write commands and detail modal restores focus on escape', async () => {
      await act(async () => root.render(React.createElement(Workspace, { product: catalog.product, identity: { role: 'viewer' }, darkMode: true, onClose() {} })));
      assert.equal(button('Save as new comparison'), undefined);
      const trigger = button('View details: Public data store'); trigger.focus();
      await click(trigger);
      assert.match(document.querySelector('[role="dialog"]').textContent, /Read-only access/);
      assert.equal(button('Save review'), undefined);
      await act(async () => document.querySelector('[role="dialog"]').dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
      assert.equal(document.querySelector('[role="dialog"]'), null);
      assert.equal(document.activeElement, trigger);
    });
    await t.test('global administrator with product read-only permission cannot review or save', async () => {
      await act(async () => root.render(React.createElement(Workspace, { product: { ...catalog.product, permissions: { edit: false, admin: false } }, identity: { role: 'admin' }, onClose() {} })));
      assert.equal(button('Save as new comparison'), undefined);
      await click(button('View details: Public data store'));
      assert.match(document.querySelector('[role="dialog"]').textContent, /Read-only access/);
      assert.equal(button('Save review'), undefined);
      await click(button('Close change details'));
    });
    await t.test('rerunning a saved comparison starts a new result without carrying old overrides', async () => {
      await act(async () => root.render(React.createElement(Workspace, { product: catalog.product, identity: { role: 'editor' }, onClose() {} })));
      const oldSnapshot = structuredClone(snapshot);
      await click(button('Run new comparison'));
      assert.deepEqual(calls.filter(call => call.path === '/compare').at(-1).body, request);
      assert.deepEqual(snapshot, oldSnapshot);
      assert.match(document.body.textContent, /Unsaved comparison/);
    });
  } finally {
    if (root) await act(async () => root.unmount());
    await server.close(); globalThis.fetch = originalFetch;
    for (const [key, descriptor] of globals) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; }
    dom.window.close();
  }
});
