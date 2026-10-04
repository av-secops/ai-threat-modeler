import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import React, { act } from 'react';

function localInput(date) {
  const pad = value => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

test('product risk review expiry and structured verification', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost:5173/' });
  const globals = new Map();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document,
    sessionStorage: dom.window.sessionStorage, IS_REACT_ACT_ENVIRONMENT: true })) {
    globals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const originalFetch = globalThis.fetch;
  const server = await createServer({ server: { middlewareMode: true, hmr: false, ws: false, watch: null }, appType: 'custom', logLevel: 'error' });
  const reportId = 'report-1';
  const threat = { id: 'risk/aws:1 ?', title: 'Cross-tenant access' };
  const reviewPath = `/assessment-reports/${reportId}/reviews/${encodeURIComponent(threat.id)}`;
  const requests = [], saved = [];
  let root, nextFailure = null;
  let returnedReviews = { latest: { [threat.id]: { version: 6, status: 'pending_review' } }, events: [] };
  try {
    const { createRoot } = await import('react-dom/client');
    const { default: RiskReviewForm } = await server.ssrLoadModule('/src/components/dashboard/RiskReviewForm.jsx');
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname.replace('/enterprise', '');
      const method = options.method || 'GET';
      assert.ok((method === 'POST' && path === reviewPath) || (method === 'GET' && path === `/assessment-reports/${reportId}/reviews`), `Unexpected ${method} ${path}`);
      requests.push({ path, method, body: options.body ? JSON.parse(options.body) : undefined });
      if (nextFailure) {
        const failure = nextFailure; nextFailure = null;
        return new Response(JSON.stringify({ detail: failure.message }), { status: failure.status });
      }
      return new Response(JSON.stringify(returnedReviews), { status: 200 });
    };
    const render = async props => {
      if (root) await act(async () => root.unmount());
      requests.length = 0; saved.length = 0; nextFailure = null;
      root = createRoot(document.getElementById('root'));
      await act(async () => root.render(React.createElement(RiskReviewForm, { reportId, threat, events: [], onSaved: value => saved.push(value), ...props })));
    };
    const byLabel = name => {
      const explicit = document.querySelector(`[aria-label="${name}"]`);
      if (explicit) return explicit;
      return [...document.querySelectorAll('label')].find(label => label.firstChild?.textContent.trim() === name)?.querySelector('input, select, textarea');
    };
    const button = name => [...document.querySelectorAll('button')].find(node => node.textContent.trim() === name);
    const change = async (label, value) => {
      const node = byLabel(label);
      assert.ok(node, `${label} control is present`);
      await act(async () => {
        const prototype = node.tagName === 'SELECT' ? dom.window.HTMLSelectElement.prototype : node.tagName === 'TEXTAREA' ? dom.window.HTMLTextAreaElement.prototype : dom.window.HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype, 'value').set.call(node, value);
        node.dispatchEvent(new dom.window.Event(node.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
      });
    };
    const click = async name => {
      const node = button(name); assert.ok(node, `${name} button is present`);
      await act(async () => node.click());
    };
    const form = () => document.querySelector('form');

    await t.test('expired acceptance is visibly pending review and history stays finding-scoped', async () => {
      await render({ review: { version: 5, status: 'pending_review', owner: 'Architect', acceptance_expired: true, overdue: true }, events: [
        { version: 1, finding_id: threat.id, status: 'accepted', author: 'Architect', author_role: 'admin', created_at: 1770000000, remarks: 'Prior acceptance expired' },
        { version: 2, finding_id: 'another-risk', status: 'verified_fixed', author: 'Other reviewer', author_role: 'editor', created_at: 1770000000, remarks: 'Unrelated review must not appear' },
      ] });
      assert.match(document.querySelector('[role="status"]').textContent, /Risk acceptance expired.*pending review again/);
      assert.match(document.body.textContent, /target date has passed/);
      assert.equal(byLabel('Product review status').value, 'pending_review');
      assert.equal(byLabel('Acceptance expires'), undefined);
      assert.equal(byLabel('Owner').required, false);
      assert.match(document.querySelector('ol').textContent, /Prior acceptance expired/);
      assert.doesNotMatch(document.querySelector('ol').textContent, /Unrelated review/);
      assert.equal(requests.length, 0);
    });

    await t.test('accepted risks require owner and a bounded future expiry before submitting', async () => {
      await render();
      await change('Product review status', 'accepted');
      await change('Product team remarks', 'Approved with compensating controls');
      assert.equal(byLabel('Owner').required, true);
      assert.equal(byLabel('Acceptance expires').required, true);
      assert.equal(form().checkValidity(), false);
      await click('Record review'); assert.equal(requests.length, 0);
      await change('Owner', 'Product Architect');
      assert.equal(form().checkValidity(), false);
      await click('Record review'); assert.equal(requests.length, 0);
      await change('Acceptance expires', localInput(new Date(Date.now() - 86400000)));
      assert.equal(byLabel('Acceptance expires').validity.rangeUnderflow, true);
      await click('Record review'); assert.equal(requests.length, 0);
      await change('Acceptance expires', localInput(new Date(Date.now() + 367 * 86400000)));
      assert.equal(byLabel('Acceptance expires').validity.rangeOverflow, true);
      await click('Record review'); assert.equal(requests.length, 0);
      await change('Acceptance expires', localInput(new Date(Date.now() + 7 * 86400000)));
      assert.equal(form().checkValidity(), true);
    });

    await t.test('acceptance posts a timezone-qualified expiry, owner and optimistic review version', async () => {
      const expiry = localInput(new Date(Date.now() + 7 * 86400000));
      await render({ review: { version: 5, status: 'accepted', owner: 'Product Architect', acceptance_expires_at: new Date(expiry).toISOString() } });
      assert.equal(byLabel('Acceptance expires').value, expiry);
      await change('Product team remarks', 'Time-limited approval by product security');
      await click('Record review');
      assert.deepEqual(requests, [{ path: reviewPath, method: 'POST', body: {
        expected_version: 5, status: 'accepted', remarks: 'Time-limited approval by product security', owner: 'Product Architect', target_date: '',
        verification_evidence: '', acceptance_expires_at: new Date(expiry).toISOString(), acceptance_criteria: [], verification: [],
      } }]);
      assert.deepEqual(saved, [returnedReviews]);
      assert.equal(byLabel('Product team remarks').value, '');
    });

    await t.test('verified fixes require owner, checked time, criterion and passing evidence', async () => {
      await render();
      await change('Product review status', 'verified_fixed');
      await change('Product team remarks', 'Remediation independently checked');
      assert.equal(byLabel('Acceptance expires'), undefined);
      for (const label of ['Owner', 'Verified on', 'Acceptance criterion satisfied', 'Verification evidence']) {
        assert.equal(byLabel(label).required, true, label);
      }
      for (const [label, value] of [
        ['Owner', 'Security reviewer'], ['Verified on', localInput(new Date(Date.now() - 86400000))],
        ['Acceptance criterion satisfied', 'Cross-tenant requests receive HTTP 403'], ['Verification evidence', 'SEC-123 execution report'],
      ]) {
        assert.equal(form().checkValidity(), false);
        await click('Record review'); assert.equal(requests.length, 0);
        await change(label, value);
      }
      assert.equal(form().checkValidity(), true);
      await change('Verified on', localInput(new Date(Date.now() + 86400000)));
      assert.equal(byLabel('Verified on').validity.rangeOverflow, true);
      await click('Record review'); assert.equal(requests.length, 0);
    });

    for (const method of ['test', 'configuration_review', 'code_review', 'independent_report']) {
      await t.test(`verified fix serializes ${method} with checked_at and its criterion`, async () => {
        const checked = localInput(new Date(Date.now() - 86400000));
        await render({ review: { version: 8, status: 'action_required', owner: 'Security reviewer' } });
        await change('Product review status', 'verified_fixed');
        await change('Product team remarks', 'Retest passed for the target release');
        await change('Verification method', method);
        await change('Verified on', checked);
        await change('Acceptance criterion satisfied', 'Cross-tenant requests receive HTTP 403');
        await change('Verification evidence', 'SEC-123 execution report');
        assert.equal(form().checkValidity(), true);
        await click('Record review');
        assert.deepEqual(requests, [{ path: reviewPath, method: 'POST', body: {
          expected_version: 8, status: 'verified_fixed', remarks: 'Retest passed for the target release', owner: 'Security reviewer', target_date: '',
          verification_evidence: 'SEC-123 execution report', acceptance_expires_at: '',
          acceptance_criteria: ['Cross-tenant requests receive HTTP 403'],
          verification: [{ method, reference: 'SEC-123 execution report', result: 'passed', checked_at: new Date(checked).toISOString() }],
        } }]);
        assert.deepEqual(saved, [returnedReviews]);
        assert.equal(byLabel('Product team remarks').value, '');
        assert.equal(byLabel('Verification evidence').value, '');
      });
    }

    await t.test('returning to ordinary review removes expiry and structured verification requirements', async () => {
      await render();
      await change('Product review status', 'accepted');
      await change('Acceptance expires', localInput(new Date(Date.now() + 7 * 86400000)));
      await change('Product review status', 'verified_fixed');
      await change('Acceptance criterion satisfied', 'No cross-tenant access');
      await change('Product review status', 'in_review');
      await change('Product team remarks', 'Awaiting product team evidence');
      assert.equal(byLabel('Owner').required, false);
      assert.equal(byLabel('Acceptance expires'), undefined);
      assert.equal(byLabel('Verified on'), undefined);
      assert.equal(byLabel('Acceptance criterion satisfied'), undefined);
      assert.equal(form().checkValidity(), true);
      await click('Record review');
      assert.equal(requests[0].body.status, 'in_review');
      assert.equal(requests[0].body.acceptance_expires_at, '');
      assert.deepEqual(requests[0].body.acceptance_criteria, []);
      assert.deepEqual(requests[0].body.verification, []);
    });

    await t.test('a server rejection preserves the draft and supports reloading review history', async () => {
      await render({ review: { status: 'in_review', version: 1, owner: 'Architect' } });
      await change('Product team remarks', 'Review notes to retain after a conflict');
      nextFailure = { status: 409, message: 'Review changed. Reload before recording another decision.' };
      await click('Record review');
      assert.match(document.querySelector('[role="alert"]').textContent, /Review changed/);
      assert.equal(byLabel('Product team remarks').value, 'Review notes to retain after a conflict');
      assert.equal(byLabel('Owner').value, 'Architect');
      assert.equal(saved.length, 0);
      returnedReviews = { latest: { [threat.id]: { version: 2, status: 'action_required' } }, events: [] };
      await click('Reload review history');
      assert.equal(requests.at(-1).method, 'GET');
      assert.equal(requests.at(-1).path, `/assessment-reports/${reportId}/reviews`);
      assert.deepEqual(saved, [returnedReviews]);
      assert.equal(document.querySelector('[role="alert"]'), null);
    });

    await t.test('read-only review disables all form controls and never submits', async () => {
      await render({ readOnly: true, review: { status: 'accepted', owner: 'Architect', acceptance_expired: true } });
      assert.equal(document.querySelector('fieldset').disabled, true);
      for (const field of document.querySelectorAll('fieldset input, fieldset select, fieldset textarea, fieldset button')) {
        assert.equal(field.matches(':disabled'), true);
      }
      await click('Record review');
      assert.equal(requests.length, 0);
      assert.equal(saved.length, 0);
      assert.match(document.querySelector('[role="status"]').textContent, /acceptance expired/);
    });
  } finally {
    if (root) await act(async () => root.unmount());
    await server.close(); globalThis.fetch = originalFetch;
    for (const [key, descriptor] of globals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
    dom.window.close();
  }
});
