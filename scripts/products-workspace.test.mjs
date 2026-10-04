import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import React, { act } from 'react';
import { workspaceHash, workspaceLocation, normalizedName } from '../src/utils/productWorkspace.js';

test('workspace URLs retain stable IDs and reject orphan context', () => {
  const location = { product_id: 'a & b', release_id: '26/09', model_id: 'm#2' };
  assert.deepEqual(workspaceLocation(workspaceHash(location)), location);
  assert.deepEqual(workspaceLocation('#products?release=x&model=y'), { product_id: null, release_id: null, model_id: null });
  assert.equal(workspaceLocation('#security-portfolio'), null);
  assert.equal(normalizedName('  OPTIMA  Portal '), 'optima portal');
});

test('product workspace creation, application reuse and navigation', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost:5173/#products' });
  dom.window.scrollTo = () => {};
  const saved = new Map();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document,
    sessionStorage: dom.window.sessionStorage, IS_REACT_ACT_ENVIRONMENT: true })) {
    saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const originalFetch = globalThis.fetch;
  const server = await createServer({ server: { middlewareMode: true, hmr: false, ws: false, watch: null }, appType: 'custom', logLevel: 'error' });
  let root;
  try {
    const { createRoot } = await import('react-dom/client');
    const { default: Workspace } = await server.ssrLoadModule('/src/components/ProductsWorkspace.jsx');
    const products = [{ id: 'p1', name: 'OPTIMA', archived: false, release_count: 1 }];
    const applications = [{ id: 'a1', name: 'Billing' }];
    const releases = [{ id: 'r1', product_id: 'p1', name: '26.09', workspaces: [], model_count: 0 }];
    const requests = [], started = [];
    let role = 'admin', failApplication = false;
    let comparisonModels = [];
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname.replace('/enterprise', '');
      const method = options.method || 'GET';
      const body = options.body ? JSON.parse(options.body) : {};
      requests.push({ path, method, body });
      let result;
      if (path === '/identity') result = { role };
      else if (path === '/products' && method === 'GET') result = products;
      else if (path === '/products' && method === 'POST') { result = { id: 'p2', name: body.name, archived: false }; products.push(result); }
      else if (/^\/products\/[^/]+$/.test(path)) {
        const product = products.find(p => p.id === path.split('/')[2]);
        if (method === 'PATCH') Object.assign(product, body);
        result = { ...product, applications, releases: releases.filter(r => r.product_id === path.split('/')[2]) };
      }
      else if (path === '/products/p1/comparison-catalog' && method === 'GET') result = {
        product: products.find(p => p.id === 'p1'),
        releases: releases.filter(r => r.product_id === 'p1').map(({ id, name }) => ({ id, name })),
        models: comparisonModels,
      };
      else if (path === '/products/p1/comparisons' && method === 'GET') result = { items: [], next_offset: null };
      else if (path === '/compare' && method === 'POST') result = {
        schema_version: '3', changes: [{ id: 'change-1', kind: 'finding', title: 'Missing event validation', status: 'new', severity: 'High',
          reason: 'A new finding in the target report.', after: { id: 'risk-1', title: 'Missing event validation', severity: 'High' }, fields: [], stride: ['Tampering'] }],
        architectures: { before: { components: [], flows: [] }, after: { components: [], flows: [] } },
        diagrams: [null, null], matches: [], mapping_suggestions: [], warnings: [], engine_changed: false,
        notice: 'No longer reported is not verified remediation.',
      };
      else if (/\/products\/[^/]+\/releases$/.test(path)) { result = { id: 'r2', product_id: path.split('/')[2], name: body.name, workspaces: [], model_count: 0 }; releases.push(result); }
      else if (/\/releases\/[^/]+\/applications$/.test(path)) {
        if (failApplication) return new Response(JSON.stringify({ detail: 'Could not save application. Try again.' }), { status: 503 });
        result = { id: 'a2', name: body.name }; applications.push(result);
      }
      else if (/^\/releases\/[^/]+$/.test(path)) result = releases.find(r => r.id === path.split('/')[2]);
      else return new Response(JSON.stringify({ detail: `Unhandled ${path}` }), { status: 404 });
      return new Response(JSON.stringify(result));
    };
    const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 25)); });
    const render = async (hash = '#products') => {
      if (root) await act(async () => root.unmount());
      window.history.replaceState(null, '', hash);
      root = createRoot(document.getElementById('root'));
      await act(async () => root.render(React.createElement(Workspace, { onStart: scope => started.push(scope), onOpen: () => {}, onHistory: () => {} })));
      await settle();
    };
    const button = name => [...document.querySelectorAll('button')].find(n => (n.getAttribute('aria-label') || n.textContent).trim() === name);
    const click = async node => { assert.ok(node, 'Expected control'); await act(async () => { node.focus(); node.click(); }); await settle(); };
    const fill = async (field, value) => {
      assert.ok(field, 'Expected field');
      await act(async () => {
        Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, 'value').set.call(field, value);
        field.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
      });
    };
    const select = async (field, value) => act(async () => {
      field.value = value; field.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
    });
    await t.test('create product and release enters their context immediately', async () => {
      await render();
      await click(button('New product'));
      assert.equal(document.activeElement === document.querySelector('[role="dialog"] input'), true);
      await fill(document.querySelector('[role="dialog"] input'), 'Platform');
      await click(button('Create product'));
      assert.equal(document.querySelector('h1').textContent, 'Platform');
      assert.equal(workspaceLocation(window.location.hash).product_id, 'p2');
      await click(button('New release'));
      await fill(document.querySelector('[role="dialog"] input'), '26.10');
      await click(button('Create release'));
      assert.equal(document.querySelector('h1').textContent, 'Release 26.10');
      assert.ok(document.querySelector('input[value="release"]'));
      assert.equal(document.querySelector('[role="dialog"]'), null);
    });
    await t.test('duplicate product shows an inline error and does not submit', async () => {
      await render();
      await click(button('New product'));
      await fill(document.querySelector('[role="dialog"] input'), '  optima  ');
      const before = requests.filter(r => r.method === 'POST').length;
      await click(button('Create product'));
      assert.match(document.querySelector('[role="dialog"] [role="alert"]').textContent, /already exists/);
      assert.equal(requests.filter(r => r.method === 'POST').length, before);
      await act(async () => document.querySelector('[role="dialog"] input').dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
      assert.equal(document.querySelector('[role="dialog"]'), null);
      assert.equal(document.activeElement === button('New product'), true);
    });
    await t.test('reuse an application or add another under the same release', async () => {
      await render('#products?product=p1&release=r1');
      await click(document.querySelector('input[value="application"]'));
      const select = document.querySelector('select[aria-label="Application"]');
      await act(async () => { select.value = 'a1'; select.dispatchEvent(new dom.window.Event('change', { bubbles: true })); });
      await click(button('Continue to architecture'));
      assert.equal(started.at(-1).application_id, 'a1');
      assert.equal(started.at(-1).release_id, 'r1');
      assert.equal(requests.filter(r => r.path.endsWith('/applications')).length, 0);
      await click(button('Cancel')); await click(button('New threat model'));
      await click(document.querySelector('input[value="application"]'));
      await fill(document.querySelector('input[aria-label="Application name"]'), 'Orders');
      await click(button('Continue to architecture'));
      assert.equal(started.at(-1).application_id, 'a2');
      assert.equal(started.at(-1).release_id, 'r1');
    });
    await t.test('browser navigation restores the parent and search survives a round trip', async () => {
      await render();
      await fill(document.querySelector('input[aria-label="Search products"]'), 'OPTIMA');
      await click(button('Open OPTIMA'));
      await click(button('Open release 26.09'));
      await act(async () => { window.history.replaceState(null, '', '#products?product=p1'); window.dispatchEvent(new dom.window.PopStateEvent('popstate')); });
      await settle();
      assert.equal(document.querySelector('h1').textContent, 'OPTIMA');
      await click(button('Back to products'));
      assert.equal(document.querySelector('input[aria-label="Search products"]').value, 'OPTIMA');
    });
    await t.test('full release uses a custom environment without creating an application', async () => {
      await render('#products?product=p1&release=r1');
      assert.equal(document.activeElement.id, 'new-model-title');
      await click(document.querySelector('input[value="release"]'));
      await select(document.querySelector('select[aria-label="Environment"]'), 'other');
      assert.equal(button('Continue to architecture').disabled, true);
      await fill(document.querySelector('input[maxlength="100"]'), 'Customer UAT');
      const before = requests.filter(r => r.path.endsWith('/applications')).length;
      await click(button('Continue to architecture'));
      assert.equal(started.at(-1).application_id, null);
      assert.equal(started.at(-1).environment, 'Customer UAT');
      assert.equal(requests.filter(r => r.path.endsWith('/applications')).length, before);
    });
    await t.test('duplicate application name offers explicit reuse, not a second create', async () => {
      await render('#products?product=p1&release=r1');
      await click(document.querySelector('input[value="application"]'));
      await fill(document.querySelector('input[aria-label="Application name"]'), ' billing ');
      assert.equal(button('Continue to architecture').disabled, true);
      await click(button('Use existing application'));
      assert.equal(document.querySelector('select[aria-label="Application"]').value, 'a1');
      const before = requests.filter(r => r.path.endsWith('/applications')).length;
      await click(button('Continue to architecture'));
      assert.equal(started.at(-1).application_id, 'a1');
      assert.equal(requests.filter(r => r.path.endsWith('/applications')).length, before);
    });
    await t.test('failed creation preserves the form and can be retried', async () => {
      await render('#products?product=p1&release=r1');
      await click(document.querySelector('input[value="application"]'));
      await fill(document.querySelector('input[aria-label="Application name"]'), 'Provisioning');
      failApplication = true;
      await click(button('Continue to architecture'));
      assert.match(document.querySelector('form [role="alert"]').textContent, /Try again/);
      assert.equal(document.querySelector('input[aria-label="Application name"]').value, 'Provisioning');
      assert.equal(button('Continue to architecture').disabled, false);
      failApplication = false;
      await click(button('Continue to architecture'));
      assert.equal(started.at(-1).application_name, 'Provisioning');
    });
    await t.test('duplicate release is rejected before posting and dialog focus is contained', async () => {
      await render('#products?product=p1');
      await click(button('New release'));
      assert.match(document.querySelector('#workspace-dialog-context').textContent, /OPTIMA/);
      assert.equal(document.body.style.overflow, 'hidden');
      await fill(document.querySelector('[role="dialog"] input'), '26.09');
      const before = requests.filter(r => r.method === 'POST').length;
      await click(button('Create release'));
      assert.match(document.querySelector('[role="alert"]').textContent, /already exists/);
      assert.equal(requests.filter(r => r.method === 'POST').length, before);
      await act(async () => {
        button('Create release').focus();
        button('Create release').dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }));
      });
      assert.equal(document.activeElement.getAttribute('aria-label'), 'Close dialog');
      await click(button('Cancel'));
      assert.equal(document.body.style.overflow, '');
    });
    await t.test('archiving requires confirmation and retains release navigation', async () => {
      await render('#products?product=p1');
      const details = document.querySelector('details'); details.open = true;
      const before = requests.filter(r => r.method === 'PATCH').length;
      await click(button('Archive product'));
      assert.equal(requests.filter(r => r.method === 'PATCH').length, before);
      await click(button('Cancel'));
      details.open = true; await click(button('Archive product'));
      await click(document.querySelector('[role="dialog"] button[type="submit"]'));
      assert.equal(button('New release').disabled, true);
      assert.ok(button('Open release 26.09'));
      products.find(p => p.id === 'p1').archived = false;
    });
    await t.test('empty search can be cleared without losing products', async () => {
      await render();
      await fill(document.querySelector('input[aria-label="Search products"]'), 'Unknown product');
      assert.match(document.querySelector('[role="status"]').textContent, /No matching results/);
      await click(button('Clear search and filters'));
      assert.equal(document.querySelector('input[aria-label="Search products"]').value, '');
      assert.ok(button('Open OPTIMA'));
    });
    await t.test('comparison handles missing reports and allows two versions of one model', async () => {
      await render('#products?product=p1');
      const before = requests.length;
      await click(button('Compare releases'));
      assert.equal(document.querySelector('h1').textContent, 'Release comparison');
      assert.match(document.body.textContent, /No completed reports are available for this product/);
      assert.equal(button('Compare reports').disabled, true);
      assert.deepEqual(requests.slice(before).map(({ path, method }) => ({ path, method })), [
        { path: '/products/p1/comparison-catalog', method: 'GET' },
        { path: '/products/p1/comparisons', method: 'GET' },
      ]);
      await click(button('Back to releases'));
      assert.equal(document.querySelector('h1').textContent, 'OPTIMA');
      assert.ok(document.querySelector('table[aria-label="Product releases"]'));
      comparisonModels = [{ id: 'm1', release_id: 'r1', name: 'Billing', application_id: 'a1', application_name: 'Billing', environment: 'production',
        revision_count: 2, revisions: [{ number: 1, created_at: '2026-09-01T10:00:00Z' }, { number: 4, created_at: '2026-09-15T10:00:00Z' }] }];
      await click(button('Compare releases'));
      await select(document.querySelector('select[aria-label="Baseline report"]'), 'm1');
      await select(document.querySelector('select[aria-label="Target report"]'), 'm1');
      assert.equal(button('Compare reports').disabled, true);
      assert.match(document.body.textContent, /Choose different report versions or different threat models/);
      assert.deepEqual([...document.querySelector('select[aria-label="Baseline report version"]').options].map(option => option.value), ['4', '1']);
      await select(document.querySelector('select[aria-label="Baseline report version"]'), '1');
      assert.equal(button('Compare reports').disabled, false);
      await click(button('Compare reports'));
      assert.deepEqual(requests.filter(row => row.path === '/compare').at(-1).body, {
        before_workspace: 'm1', after_workspace: 'm1', before_revision: 1, after_revision: 4,
      });
      assert.match(document.querySelector('table[aria-label="Release comparison changes"]').textContent, /Missing event validation/);
      await click(button('Back to releases'));
      assert.ok(button('Open release 26.09'));
      comparisonModels = [];
    });
    await t.test('comparison blocks different applications, full-release scope and environments before posting', async () => {
      const model = { id: 'baseline', release_id: 'r1', name: 'Billing', application_id: 'a1', application_name: 'Billing', environment: 'production',
        revision_count: 1, revisions: [{ number: 1, created_at: '2026-09-01T10:00:00Z' }] };
      comparisonModels = [model,
        { ...model, id: 'other-app', application_id: 'a2', application_name: 'Orders' },
        { ...model, id: 'full-release', application_id: null, application_name: null, name: 'Full release' },
        { ...model, id: 'staging', environment: 'staging' },
        { ...model, id: 'compatible' },
      ];
      await render('#products?product=p1');
      await click(button('Compare releases'));
      await select(document.querySelector('select[aria-label="Baseline report"]'), 'baseline');
      const before = requests.filter(row => row.path === '/compare').length;
      for (const id of ['other-app', 'full-release', 'staging']) {
        await select(document.querySelector('select[aria-label="Target report"]'), id);
        assert.equal(button('Compare reports').disabled, true);
        assert.match(document.body.textContent, /Choose reports for the same application scope and environment/);
        assert.match(document.body.textContent, id === 'staging' ? /Environments differ/ : /Application scopes differ/);
        await click(button('Compare reports'));
      }
      assert.equal(requests.filter(row => row.path === '/compare').length, before);
      await select(document.querySelector('select[aria-label="Target report"]'), 'compatible');
      assert.equal(button('Compare reports').disabled, false);
      assert.doesNotMatch(document.body.textContent, /Application scopes differ|Environments differ/);
      await click(button('Compare reports'));
      assert.equal(requests.filter(row => row.path === '/compare').length, before + 1);
      comparisonModels = [];
    });
    await t.test('viewer cannot create models or products', async () => {
      role = 'viewer'; await render();
      assert.equal(button('New product').disabled, true);
      await render('#products?product=p1&release=r1');
      assert.equal(document.querySelector('fieldset').disabled, true);
    });
  } finally {
    if (root) await act(async () => root.unmount());
    await server.close(); globalThis.fetch = originalFetch;
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
    dom.window.close();
  }
});
