import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/live-review-ui');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
const errors = [], requests = [];
page.on('pageerror', (error) => errors.push(error.message));
page.on('request', (request) => {
  if (request.url().includes('/model-review/')) requests.push({ url: request.url(), body: request.postDataJSON() });
});
const diagram = page.locator('[aria-label="Draft architecture diagram"] svg');
const report = {};
const responseFor = (predicate = () => true) => page.waitForResponse((response) => response.url().endsWith('/model-review/prepare') && predicate(response.request().postDataJSON()));
const ready = () => page.waitForFunction(() => {
  const button = [...document.querySelectorAll('button')].find((item) => item.textContent === 'Analyze reviewed model');
  return button && !button.disabled;
});
async function update(action, predicate) {
  const pending = responseFor(predicate);
  await action();
  const response = await pending;
  assert.equal(response.status(), 200, await response.text());
  const preview = await response.json();
  await ready();
  return preview;
}
async function diagramHas(name) {
  await page.waitForFunction((text) => document.querySelector('[aria-label="Draft architecture diagram"] svg')?.textContent.includes(text), name);
}
async function waitForSavedDraft() {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const saved = await page.evaluate(async () => {
      const { loadWorkspaces, draftSignature } = await import('/src/utils/modelWorkspace.js');
      const workspace = (await loadWorkspaces())[0];
      return workspace && workspace.draft.preparedSignature === draftSignature(workspace.draft.payload)
        && workspace.draft.preview.architecture.components.some((item) => item.name === 'Retained Worker')
        && !workspace.draft.preview.architecture.components.some((item) => item.name === 'Current Worker');
    });
    if (saved) return;
    await page.waitForTimeout(100);
  }
  assert.fail('The latest architecture preview was not saved.');
}

try {
  await page.goto('http://127.0.0.1:5173/');
  await page.getByPlaceholder('e.g. Payment Gateway V2').fill('Live architecture review QA');
  await page.getByLabel('Architecture description').fill('React calls a Node.js API over HTTPS. Node.js reads PostgreSQL over TLS.');
  await page.locator('#useLocalSlm').uncheck();
  let preview = await update(() => page.getByRole('button', { name: 'Review architecture', exact: true }).click());
  const initialComponents = preview.architecture.components.length;
  const initialFlows = preview.flows.length;
  const api = preview.architecture.components.find((item) => item.type === 'API');
  assert.ok(api);

  await page.getByLabel('New component name', { exact: true }).fill('Review Worker');
  preview = await update(() => page.getByRole('button', { name: 'Add component', exact: true }).click());
  const worker = preview.architecture.components.find((item) => item.name === 'Review Worker');
  assert.ok(worker);
  assert.equal(preview.architecture.components.length, initialComponents + 1);
  await page.getByLabel(`Name: ${worker.id}`, { exact: true }).waitFor();
  await diagramHas('Review Worker');
  assert.equal(await page.getByRole('button', { name: 'Refresh preview', exact: true }).count(), 0);
  report.componentAutoAdded = true;

  await page.getByLabel('Source component', { exact: true }).selectOption(api.id);
  await page.getByLabel('Target component', { exact: true }).selectOption(worker.id);
  preview = await update(() => page.getByRole('button', { name: 'Add flow', exact: true }).click());
  assert.equal(preview.flows.length, initialFlows + 1);
  const flow = preview.flows.find((item) => item.target_id === worker.id);
  await page.getByLabel(`Protocol: ${flow.review_id}`, { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Add flow', exact: true }).isDisabled(), true);
  preview = await update(() => page.getByLabel(`Protocol: ${flow.review_id}`, { exact: true }).selectOption('mTLS'));
  assert.equal(preview.flows.find((item) => item.review_id === flow.review_id).protocol, 'mTLS');
  await diagramHas('MTLS');
  report.flowAutoAdded = true;

  await page.getByRole('button', { name: 'Zoom in draft diagram', exact: true }).click();
  const countBeforeTyping = requests.length;
  const nameInput = page.getByLabel(`Name: ${worker.id}`, { exact: true });
  const renamed = 'Review Worker Revised';
  preview = await update(async () => {
    await nameInput.press('End');
    await nameInput.pressSequentially(' Revised', { delay: 15 });
  });
  assert.equal(requests.length - countBeforeTyping, 1);
  await diagramHas(renamed);
  assert.equal(await page.getByText('110%', { exact: true }).count(), 1);
  report.typingDebouncedAndZoomPreserved = true;

  // Let an older request finish after a newer edit. It must never win.
  let signalHeld, releaseHeld, signalReleased;
  const held = new Promise((resolve) => { signalHeld = resolve; });
  const release = new Promise((resolve) => { releaseHeld = resolve; });
  const released = new Promise((resolve) => { signalReleased = resolve; });
  await page.route('**/model-review/prepare', async (route) => {
    if (route.request().postDataJSON().edits.some((item) => item.field === 'name' && item.value === 'Older Worker')) {
      const response = await route.fetch();
      signalHeld();
      await release;
      try { await route.fulfill({ response }); } catch { /* The browser may already have cancelled it. */ }
      signalReleased();
    } else await route.continue();
  });
  await nameInput.fill('Older Worker');
  await held;
  assert.equal(await nameInput.isEnabled(), true);
  assert.equal(await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).isDisabled(), true);
  preview = await update(() => nameInput.fill('Current Worker'));
  releaseHeld();
  await released;
  await page.unroute('**/model-review/prepare');
  await diagramHas('Current Worker');
  assert.equal(await nameInput.inputValue(), 'Current Worker');
  assert.equal(await diagram.getByText('Older Worker', { exact: false }).count(), 0);
  report.staleResponseIgnored = true;

  await page.route('**/model-review/prepare', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ detail: 'Controlled preview failure' }) }));
  await page.getByLabel('New component name', { exact: true }).fill('Retained Worker');
  const failed = responseFor();
  await page.getByRole('button', { name: 'Add component', exact: true }).click();
  assert.equal((await failed).status(), 500);
  await page.getByRole('alert').filter({ hasText: 'Controlled preview failure' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).isDisabled(), true);
  assert.equal(await nameInput.isEnabled(), true);
  await page.unroute('**/model-review/prepare');
  preview = await update(() => page.getByRole('button', { name: 'Retry update', exact: true }).click());
  assert.ok(preview.architecture.components.some((item) => item.name === 'Retained Worker'));
  await diagramHas('Retained Worker');
  report.failureRetainsDraftAndRetryWorks = true;
  await page.screenshot({ path: path.join(output, 'desktop-live-review.png'), fullPage: true });

  preview = await update(() => page.getByRole('button', { name: 'Exclude Current Worker', exact: true }).click());
  assert.ok(!preview.architecture.components.some((item) => item.id === worker.id));
  assert.ok(!preview.flows.some((item) => item.target_id === worker.id || item.source_id === worker.id));
  assert.equal(await page.getByLabel(`Name: ${worker.id}`, { exact: true }).count(), 0);
  report.deletionUpdatesIncidentFlows = true;

  await waitForSavedDraft();
  await page.reload();
  await page.getByTitle('History', { exact: true }).click();
  await page.getByTitle('Load analysis', { exact: true }).click();
  await ready();
  await diagramHas('Retained Worker');
  report.draftSurvivesReload = true;
  await page.getByTitle('Dark mode', { exact: true }).click();
  await page.locator('[aria-label="Draft architecture diagram"] svg[data-theme="dark"]').waitFor();
  await page.screenshot({ path: path.join(output, 'desktop-live-review-dark.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
  await page.screenshot({ path: path.join(output, 'mobile-live-review.png'), fullPage: true });
  assert.equal(requests.filter((item) => item.url.endsWith('/model-review/analyze')).length, 0);
  assert.deepEqual(errors, []);
  report.mobileFits = true;
  report.noAutomaticThreatAnalysis = true;
  report.errors = errors;
  report.passed = true;
  await writeFile(path.join(output, 'result.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.failure = error.message;
  report.errors = errors;
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
  await writeFile(path.join(output, 'result.json'), JSON.stringify(report, null, 2));
  throw error;
} finally { await browser.close(); }
