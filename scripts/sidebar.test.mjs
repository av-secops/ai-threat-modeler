import assert from 'node:assert/strict';
import test from 'node:test';
import React, { act, useState } from 'react';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';

test('sidebar header toggle preserves navigation and keyboard focus', async () => {
  const dom = new JSDOM('<div id="root"></div>');
  const saved = new Map();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, IS_REACT_ACT_ENVIRONMENT: true })) {
    saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const server = await createServer({ server: { middlewareMode: true, hmr: false, ws: false, watch: null }, appType: 'custom', logLevel: 'error' });
  let root;
  try {
    const { createRoot } = await import('react-dom/client');
    const { default: Sidebar } = await server.ssrLoadModule('/src/components/Sidebar.jsx');
    const selected = [];
    function Harness() {
      const [collapsed, setCollapsed] = useState(false);
      return React.createElement(Sidebar, { activeTab: 'products', onTabChange: tab => selected.push(tab),
        collapsed, onCollapsedChange: setCollapsed, darkMode: false, onToggleDarkMode: () => {} });
    }
    root = createRoot(document.getElementById('root'));
    await act(async () => root.render(React.createElement(Harness)));
    const toggle = document.querySelector('button[aria-controls="main-navigation"]');
    const navigation = document.getElementById('main-navigation');
    assert.ok(toggle.compareDocumentPosition(navigation) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);
    assert.equal(toggle.getAttribute('aria-label'), 'Collapse sidebar');
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(document.querySelectorAll('button[aria-controls="main-navigation"]').length, 1);
    await act(async () => { toggle.focus(); toggle.click(); });
    assert.equal(toggle.getAttribute('aria-label'), 'Expand sidebar');
    assert.equal(toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(document.activeElement, toggle);
    assert.equal(document.querySelector('aside').classList.contains('w-[68px]'), true);
    assert.equal(document.querySelector('button[aria-label="Products"]').title, 'Products');
    assert.equal(document.querySelector('button[aria-label="Products"]').getAttribute('aria-current'), 'page');
    assert.equal(navigation.querySelectorAll('button').length, 6);
    await act(async () => document.querySelector('button[aria-label="History"]').click());
    assert.deepEqual(selected, ['history']);
    await act(async () => toggle.click());
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(document.activeElement, toggle);
    await act(async () => toggle.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
    assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  } finally {
    if (root) await act(async () => root.unmount());
    await server.close();
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
    dom.window.close();
  }
});
