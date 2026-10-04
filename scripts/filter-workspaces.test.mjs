import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import React, { act, useState } from 'react';
import { filterDefaults } from '../src/utils/productDashboard.js';

test('filter workspaces preserve scope, navigation and review semantics', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost:5173/' });
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
    const { default: FilterBar } = await server.ssrLoadModule('/src/components/FilterBar.jsx');
    const { default: Dashboard } = await server.ssrLoadModule('/src/components/ProductSecurityDashboard.jsx');
    const { default: Findings } = await server.ssrLoadModule('/src/components/dashboard/FindingsWorkspace.jsx');
    const { default: Flows } = await server.ssrLoadModule('/src/components/dashboard/ArchitectureFlowTable.jsx');
    const requests = [];
    const rows = Array.from({ length: 30 }, (_, i) => ({ occurrence_id: `o${i}`, finding_id: `f${i}`, workspace_id: 'm', report_id: 'r',
      title: i === 0 ? 'Critical access failure' : `High risk ${i}`, severity: i === 0 ? 'Critical' : 'High', tier: 'Confirmed', kind: 'risk',
      revision: 1, stride: ['Spoofing'], application_name: 'Portal', release_name: '26.09', environment: 'production', status: 'pending_review' }));
    globalThis.fetch = async (url, options = {}) => {
      const parsed = new URL(url); requests.push({ url: parsed, method: options.method || 'GET' });
      if (parsed.pathname.endsWith('/history')) return new Response(JSON.stringify({ observations: [] }));
      const params = parsed.searchParams;
      const selected = rows.filter(row => (params.get('severity') === 'all' || params.get('severity') === row.severity)
        && row.title.toLowerCase().includes((params.get('search') || '').toLowerCase()));
      const page = Number(params.get('page') || 1);
      return new Response(JSON.stringify({ product: { name: 'Test product' }, snapshot: 'snapshot', generated_at: 1750000000,
        options: { releases: [{ id: 'release', name: '26.09' }], applications: [{ id: 'app', name: 'Portal' }], environments: ['production'] },
        coverage: { applications_registered: 1, applications_assessed: 1, releases_registered: 1, releases_assessed: 1,
          models_completed: 1, full_release_models: 0, application_models: 1, quality: { ready: 1 }, drafts: 0, legacy_unverified: 0, overlapping_releases: 0 },
        metrics: { open_risks: selected.length, confirmed_open: selected.length, potential_open: 0, verified_fixed: 0, accepted_risks: 0, validation_questions: 0, reported_findings: selected.length },
        severity: ['Critical', 'High', 'Medium', 'Low', 'Unknown'].map(name => ({ name, count: selected.filter(r => r.severity === name).length, percent: 0 })),
        statuses: [{ name: 'pending_review', count: selected.length, percent: 100 }], models: [],
        findings: { total: selected.length, page_size: 25, rows: selected.slice((page - 1) * 25, page * 25) },
      }));
    };
    const settle = (ms = 30) => act(async () => { await new Promise(resolve => setTimeout(resolve, ms)); });
    const render = async element => {
      if (root) await act(async () => root.unmount());
      root = createRoot(document.getElementById('root'));
      await act(async () => root.render(element)); await settle();
    };
    const button = name => [...document.querySelectorAll('button')].find(node => (node.getAttribute('aria-label') || node.textContent).trim() === name);
    const click = async node => { assert.ok(node, 'Expected button'); await act(async () => node.click()); await settle(); };
    const select = async (name, value) => {
      const field = [...document.querySelectorAll('label')].find(node => node.firstChild?.textContent === name)?.querySelector('select');
      assert.ok(field, name); await act(async () => { field.value = value; field.dispatchEvent(new dom.window.Event('change', { bubbles: true })); }); await settle();
    };
    const fill = async (label, value) => {
      const input = document.querySelector(`input[aria-label="${label}"]`);
      await act(async () => { Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, 'value').set.call(input, value); input.dispatchEvent(new dom.window.Event('input', { bubbles: true })); });
    };
    function ProductHarness({ initial = {} }) {
      const [filters, setFilters] = useState({ ...filterDefaults, ...initial });
      return React.createElement(Dashboard, { productId: 'product', filters, onFilters: setFilters, editable: false });
    }
    await t.test('filter controls collapse without losing selections and Escape returns focus', async () => {
      let removed = false;
      await render(React.createElement(FilterBar, { label: 'Test filters', active: [{ key: 'severity', label: 'Severity: Critical', onRemove: () => { removed = true; } }], onReset: () => {} }, React.createElement('input', { 'aria-label': 'Test field' })));
      const panel = document.querySelector('section[aria-label="Test filters"]').parentElement;
      assert.equal(panel.hidden, true);
      assert.ok(button('Remove Severity: Critical'));
      await click(button('Test filters'));
      assert.equal(panel.hidden, false);
      await act(async () => document.querySelector('input').dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
      assert.equal(panel.hidden, true);
      assert.equal(document.activeElement, button('Test filters'));
      await click(button('Remove Severity: Critical')); assert.equal(removed, true);
    });
    await t.test('dashboard defaults to an overview; drilldown opens matching risks with removable filters', async () => {
      await render(React.createElement(ProductHarness));
      assert.equal(document.querySelector('table[aria-label="Product risk register"]'), null);
      assert.equal(button('Dashboard filters').getAttribute('aria-expanded'), 'false');
      await click(button('Critical: 1 open risks'));
      assert.equal(document.querySelectorAll('table[aria-label="Product risk register"] tbody tr').length, 1);
      assert.ok(button('Remove Severity: Critical'));
      assert.equal(requests.at(-1).url.searchParams.get('status'), 'open');
      await click(button('Dashboard filters')); await select('Environment', 'production');
      await click(button('Close dashboard filters'));
      await click(button('Remove Severity: Critical'));
      assert.ok(button('Remove Environment: production'));
      assert.equal(document.querySelectorAll('table[aria-label="Product risk register"] tbody tr').length, 25);
      await click(button('Reset dashboard filters'));
      assert.equal(document.querySelector('[aria-label="Active dashboard filters"]'), null);
    });
    await t.test('pagination resets on filter changes; search coalesces rapid keystrokes', async () => {
      await render(React.createElement(ProductHarness));
      await click(button('Risks30')); await click(button('Next product findings'));
      assert.equal(requests.at(-1).url.searchParams.get('page'), '2');
      const before = requests.length;
      await fill('Search product findings', 'C'); await fill('Search product findings', 'Critical'); await settle(320);
      assert.equal(requests.length, before + 1);
      assert.equal(requests.at(-1).url.searchParams.get('page'), '1');
      assert.equal(document.querySelectorAll('table[aria-label="Product risk register"] tbody tr').length, 1);
      await click(button('Clear search product findings')); await settle(280);
      assert.equal(document.querySelectorAll('table[aria-label="Product risk register"] tbody tr').length, 25);
    });
    await t.test('scope survives view changes and history remains read-only for viewers', async () => {
      await render(React.createElement(ProductHarness, { initial: { release_id: 'release' } }));
      assert.ok(button('Remove Release: 26.09'));
      await click(button('Coverage')); assert.ok(document.querySelector('table[aria-label="Assessment coverage"]'));
      await click(button('History')); assert.ok(document.querySelector('table[aria-label="Dashboard observations"]'));
      assert.equal(button('Record overview'), undefined);
      assert.equal(button('Dashboard filters'), undefined);
      await click(button('Overview')); assert.ok(button('Remove Release: 26.09'));
      assert.equal(requests.some(request => request.method !== 'GET'), false);
    });
    await t.test('report register exposes externally selected evidence and matrix filters', async () => {
      function Harness() {
        const [filters, setFilters] = useState({ severity: 'all', category: 'all', tier: 'Confirmed', search: '', impact: 'High', likelihood: 'High' });
        return React.createElement(Findings, { threats: [], filters, onFiltersChange: setFilters, reviewStates: {}, onSelectThreat: () => {} });
      }
      await render(React.createElement(Harness));
      assert.ok(button('Remove Evidence: Confirmed'));
      await click(button('Remove Matrix: High impact / High likelihood'));
      assert.ok(button('Remove Evidence: Confirmed'));
      await click(button('Reset finding filters')); assert.equal(document.querySelector('[aria-label="Active finding filters"]'), null);
    });
    await t.test('flow filtering retains exact trace identity and reset restores all flows', async () => {
      let traced;
      await render(React.createElement(Flows, { onSelect: id => { traced = id; }, architecture: { components: [{ id: 'a', name: 'API' }, { id: 'b', name: 'Database' }],
        flows: [{ id: 'flow-1', flow_number: 'F-001', source_id: 'a', target_id: 'b', assumed: true }, { id: 'flow-2', flow_number: 'F-002', source_id: 'a', target_id: 'b' }] } }));
      await click(button('Flow filters')); await select('Flow basis', 'assumed'); await click(button('Close flow filters'));
      assert.equal(document.querySelectorAll('table[aria-label="Data flow register"] tbody tr').length, 1);
      await click(button('Trace F-001')); assert.equal(traced, 'flow-1');
      await click(button('Reset flow filters'));
      assert.equal(document.querySelectorAll('table[aria-label="Data flow register"] tbody tr').length, 2);
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
