import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import React, { act } from 'react';

test('release navigation keeps additional applications inside the selected release', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost:5173/' });
  dom.window.scrollTo = () => {};
  const savedGlobals = new Map();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document,
    sessionStorage: dom.window.sessionStorage, IS_REACT_ACT_ENVIRONMENT: true })) {
    savedGlobals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const originalFetch = globalThis.fetch;
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' });
  let root;
  try {
    const { createRoot } = await import('react-dom/client');
    const { default: ProductsWorkspace } = await server.ssrLoadModule('/src/components/ProductsWorkspace.jsx');
    let role = 'editor';
    const calls = [];
    const product = { id: 'product-one', name: 'Product one', applications: [{ id: 'app-one', name: 'Portal' }], releases: [] };
    const release = { id: 'release-one', product_id: product.id, name: '26.09', workspaces: [
      { id: 'model-one', name: 'Portal model', application_id: 'app-one', application_name: 'Portal', environment: 'production', revisions: 1 },
      { id: 'full-model', name: 'Complete product model', application_id: null, environment: 'production', revisions: 1 },
    ] };
    product.releases = [release];
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname.replace('/enterprise', '');
      calls.push({ path, method: options.method, body: options.body && JSON.parse(options.body) });
      let value;
      if (path === '/identity') value = { role };
      else if (path === '/products') value = [product];
      else if (path === '/products/product-one') value = product;
      else if (path === '/releases/release-one') value = release;
      else if (path === '/releases/release-one/applications') value = { id: 'app-two', name: 'Billing' };
      else if (path === '/workspaces/model-one') value = { id: 'model-one', application_id: 'app-one', environment: 'production', workspace: {} };
      else throw new Error(`Unexpected request: ${path}`);
      return new Response(JSON.stringify(value), { status: 200 });
    };
    const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    const render = async props => {
      if (root) await act(async () => root.unmount());
      root = createRoot(document.getElementById('root'));
      await act(async () => root.render(React.createElement(ProductsWorkspace, {
        initialLocation: { product_id: product.id, release_id: release.id }, ...props,
      })));
      await settle();
    };
    const button = name => [...document.querySelectorAll('button')].find(node => (node.getAttribute('aria-label') || node.textContent).trim() === name);
    const click = async node => { assert.ok(node, 'Expected control exists'); await act(async () => node.click()); await settle(); };

    await t.test('add model opens a fresh scope choice without removing existing reports', async () => {
      let started;
      await render({ onStart: scope => { started = scope; } });
      assert.equal(document.querySelectorAll('table[aria-label="Release threat models"] tbody tr').length, 2);
      assert.equal(document.querySelector('input[name="model-scope"]'), null);
      await click(button('Add threat model'));
      assert.equal(document.querySelectorAll('input[name="model-scope"]:checked').length, 0);
      await click(document.querySelector('input[value="application"]'));
      const name = [...document.querySelectorAll('label')].find(node => node.textContent === 'Application name').querySelector('input');
      await act(async () => {
        Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, 'value').set.call(name, 'Billing');
        name.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
      });
      await click(button('Continue to threat model'));
      assert.equal(started?.release_id, release.id);
      assert.equal(started?.product_id, product.id);
      assert.equal(started?.application_id, 'app-two');
      assert.equal(started?.application_name, 'Billing');
      assert.equal(document.querySelectorAll('table[aria-label="Release threat models"] tbody tr').length, 2);
      assert.equal(calls.some(call => call.method === 'PUT' || call.method === 'DELETE'), false);
    });

    await t.test('report add-another shortcut preselects application but never reuses the old name', async () => {
      await render({ initialLocation: { product_id: product.id, release_id: release.id, newModelScope: 'application' } });
      assert.equal(document.querySelector('input[value="application"]').checked, true);
      assert.equal(button('Continue to threat model').disabled, true);
      await click(button('Cancel'));
      assert.ok(button('Add threat model'));
    });

    await t.test('opening an existing report carries release breadcrumbs and application identity', async () => {
      let opened;
      await render({ onOpen: row => { opened = row; } });
      await click(button('Open Portal model'));
      assert.equal(opened.productScope.product_id, product.id);
      assert.equal(opened.productScope.release_id, release.id);
      assert.equal(opened.productScope.application_name, 'Portal');
      assert.equal(opened.readOnly, false);
    });

    await t.test('back moves from release to product and then to the catalog', async () => {
      const locations = [];
      await render({ onLocationChange: location => locations.push(location) });
      await click(button('Back'));
      assert.ok(document.querySelector('table[aria-label="Product releases"]'));
      assert.deepEqual(locations.at(-1), { product_id: product.id });
      await click(button('Back'));
      assert.equal(locations.at(-1), null);
      assert.ok(document.querySelector('input[aria-label="Search products"]'));
    });

    await t.test('viewers cannot create another model', async () => {
      role = 'viewer';
      await render({});
      assert.equal(button('Add threat model').disabled, true);
    });
  } finally {
    if (root) await act(async () => root.unmount());
    await server.close();
    globalThis.fetch = originalFetch;
    for (const [key, descriptor] of savedGlobals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
    dom.window.close();
  }
});
