import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/model-review-ui');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
const page = await context.newPage();
await page.route('**/feedback/findings', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
const errors = [];
const report = {};
page.on('pageerror', (error) => errors.push(error.message));
const responseFor = (endpoint) => page.waitForResponse((response) => response.url().endsWith(endpoint) && response.request().method() === 'POST');
async function updatePreview(action) {
  const response = responseFor('/model-review/prepare');
  await action();
  const result = await response;
  assert.equal(result.status(), 200, await result.text());
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some((button) => button.textContent === 'Analyze reviewed model' && !button.disabled));
  return result.json();
}

try {
  await page.goto('http://127.0.0.1:5173/');
  await page.getByPlaceholder('e.g. Payment Gateway V2').fill('Guided review QA');
  await page.getByLabel('Architecture description').fill('React calls a Node.js REST API over HTTPS. The Node.js REST API reads PostgreSQL over TLS. PostgreSQL stores customer personal information.');
  await page.locator('#useLocalSlm').uncheck();
  const preflightResponse = responseFor('/model-review/prepare');
  await page.getByRole('button', { name: 'Review architecture', exact: true }).click();
  const preflight = await preflightResponse;
  assert.equal(preflight.status(), 200, await preflight.text());
  let preview = await preflight.json();
  assert.equal('threats' in preview, false);
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).waitFor();
  await page.locator('[aria-label="Draft architecture diagram"] svg').waitFor();
  await page.screenshot({ path: path.join(output, 'review-desktop.png'), fullPage: true });
  const api = preview.architecture.components.find((c) => c.type === 'API');
  assert.ok(api);

  // Review-only preparation must be resumable before a report exists.
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await page.reload();
  await page.getByTitle('History', { exact: true }).click();
  await page.getByText('Saved architecture draft', { exact: true }).waitFor();
  await page.getByTitle('Load analysis', { exact: true }).click();
  await page.getByRole('region', { name: 'Model review workspace' }).waitFor();
  report.draftResumed = true;

  const dbFlow = preview.flows.find((f) => f.source_id === 'postgresql' || f.target_id === 'postgresql');
  assert.ok(dbFlow);
  await updatePreview(() => page.getByLabel(`Flow source: ${dbFlow.review_id}`, { exact: true }).selectOption(api.id));
  preview = await updatePreview(() => page.getByLabel(`Flow target: ${dbFlow.review_id}`, { exact: true }).selectOption('postgresql'));
  const correctedFlow = preview.flows.find((f) => f.review_id === dbFlow.review_id);
  assert.equal(correctedFlow.source_id, api.id);
  assert.equal(correctedFlow.target_id, 'postgresql');
  report.flowEndpointsEditable = true;

  const question = preview.questions.find((q) => q.element_id === api.id && q.control === 'input_validation');
  assert.ok(question);
  await page.getByRole('navigation', { name: 'Model review sections' }).getByRole('button', { name: 'Clarifications' }).click();
  for (let i = 0; i < Math.floor(preview.questions.indexOf(question) / 5); i++) await page.getByRole('button', { name: 'Next clarification page' }).click();
  await page.getByLabel(`State: ${question.id}`, { exact: true }).selectOption('absent');
  await page.getByLabel(`Explanation: ${question.id}`, { exact: true }).fill('The API accepts request bodies without schema validation.');
  const form = page.locator('form').filter({ has: page.getByLabel(`State: ${question.id}`, { exact: true }) });
  preview = await updatePreview(() => form.getByRole('button', { name: 'Record answer', exact: true }).click());
  const target = preview.architecture.components.find((c) => c.id === api.id);
  assert.equal(target.properties.input_validation, false);
  assert.equal(preview.architecture.components.find((c) => c.id === 'postgresql').properties.input_validation, undefined);
  await page.screenshot({ path: path.join(output, 'clarifications-desktop.png'), fullPage: true });
  const analysisResponse = responseFor('/model-review/analyze');
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).click();
  const result = await analysisResponse;
  assert.equal(result.status(), 200, await result.text());
  const first = await result.json();
  assert.ok(first.threats.some((t) => t.tier === 'Confirmed'));
  await page.getByRole('navigation', { name: 'Analysis result views' }).waitFor();
  await page.getByRole('navigation', { name: 'Analysis result views' }).getByRole('button', { name: 'Report', exact: true }).click();
  await page.getByRole('heading', { name: 'Final report', exact: true }).waitFor();
  report.firstFindings = first.threats.length;

  const reviewedFinding = first.threats.find((t) => t.tier === 'Confirmed');
  await page.getByRole('button').filter({ hasText: reviewedFinding.title }).last().click();
  await page.getByRole('dialog').getByRole('combobox', { name: 'Finding review status' }).selectOption('false_positive');
  await page.keyboard.press('Escape');
  await page.getByRole('navigation', { name: 'Analysis result views' }).getByRole('button', { name: /Overview/ }).click();
  const pdfDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export PDF', exact: true }).click();
  await (await pdfDownload).saveAs(path.join(output, 'reviewed-report.pdf'));
  report.pdfExpectedConfirmed = first.threats.filter((t) => t.tier === 'Confirmed').length - 1;
  report.pdfExpectedPotential = first.threats.filter((t) => t.tier !== 'Confirmed').length;
  report.pdfExcludedTitle = reviewedFinding.title;

  await page.getByRole('button', { name: 'Update this model', exact: true }).click();
  await page.getByRole('navigation', { name: 'Model review sections' }).getByRole('button', { name: 'Sources', exact: true }).click();
  await page.getByLabel('Additional architecture context').fill('Redis stores API sessions. The Node.js API reads Redis over TLS.');
  preview = await updatePreview(() => page.getByRole('button', { name: 'Add context to draft', exact: true }).click());
  assert.ok(preview.architecture.components.some((c) => /redis/i.test(c.name)));
  assert.ok(preview.warnings.some((w) => w.type === 'stale_answer'));
  assert.ok(preview.architecture.components.find((c) => c.id === api.id).properties.input_validation == null);
  report.staleAnswerFlagged = true;

  const uploadResponse = responseFor('/model-review/sources');
  preview = await updatePreview(() => page.getByLabel('Add review files', { exact: true }).setInputFiles({ name: 'docker-compose.yml', mimeType: 'application/yaml', buffer: Buffer.from('services:\n  audit:\n    image: redis:7\n    ports: ["6379:6379"]\n') }));
  assert.equal((await uploadResponse).status(), 200);
  await page.getByText('docker-compose.yml', { exact: false }).first().waitFor();
  const updatedResponse = responseFor('/model-review/analyze');
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).click();
  const updated = await updatedResponse;
  assert.equal(updated.status(), 200, await updated.text());
  const second = await updated.json();
  assert.ok(second.threats.some((t) => t.id.startsWith('IAC-')));
  await page.getByRole('navigation', { name: 'Analysis result views' }).waitFor();
  assert.equal(await page.getByLabel('Report revision', { exact: true }).inputValue(), '2');
  await page.getByLabel('Report revision', { exact: true }).selectOption('1');
  await page.getByText('Historical report', { exact: true }).waitFor();
  await page.getByLabel('Report revision', { exact: true }).selectOption('2');
  report.revisionsPassed = true;
  const annotations = await page.evaluate(async (findingId) => {
    const { loadWorkspaces, annotationKey } = await import('/src/utils/modelWorkspace.js');
    const { loadAnnotations } = await import('/src/utils/annotations.js');
    const workspace = (await loadWorkspaces())[0];
    return { first: loadAnnotations(annotationKey(workspace.id, 1)).reviewStates[findingId],
      second: loadAnnotations(annotationKey(workspace.id, 2)).reviewStates[findingId] };
  }, reviewedFinding.id);
  assert.equal(annotations.first, 'false_positive');
  if (second.threats.some((t) => t.id === reviewedFinding.id)) assert.equal(annotations.second, 'open');
  report.reviewerDecisionPreserved = true;

  // Failed analysis must preserve both the draft and the last successful report.
  await page.getByRole('button', { name: 'Update this model', exact: true }).click();
  await page.route('**/model-review/analyze', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ detail: 'Controlled QA failure' }) }));
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).click();
  await page.getByText('Controlled QA failure', { exact: true }).waitFor();
  await page.unroute('**/model-review/analyze');
  assert.equal(await page.getByRole('region', { name: 'Model review workspace' }).count(), 1);
  await page.getByRole('button', { name: 'Back to report', exact: true }).click();
  assert.equal(await page.getByLabel('Report revision', { exact: true }).locator('option').count(), 2);
  report.failurePreservesReport = true;

  await page.getByRole('button', { name: 'Update this model', exact: true }).click();
  await page.getByTitle('Dark mode', { exact: true }).click();
  await page.getByRole('navigation', { name: 'Model review sections' }).getByRole('button', { name: 'Architecture', exact: true }).click();
  const draftDiagram = page.locator('[aria-label="Draft architecture diagram"] svg[data-theme="dark"]');
  await draftDiagram.waitFor();
  const edges = await draftDiagram.locator('.flowchart-link').evaluateAll((nodes) => nodes.map((n) => getComputedStyle(n).stroke));
  assert.ok(edges.length && edges.every((color) => color === 'rgb(212, 222, 233)'));
  const arrows = await draftDiagram.locator('marker path').evaluateAll((nodes) => nodes.map((n) => getComputedStyle(n).fill));
  assert.ok(arrows.length && arrows.every((color) => color === 'rgb(212, 222, 233)'));
  const centered = await draftDiagram.evaluate((svg) => {
    const rect = svg.getBoundingClientRect();
    const frame = svg.closest('[aria-label]').getBoundingClientRect();
    return Math.abs((rect.left + rect.right) / 2 - (frame.left + frame.right) / 2) < 10;
  });
  assert.equal(centered, true);
  const initialWidth = await draftDiagram.evaluate((n) => n.getBoundingClientRect().width);
  await page.getByRole('button', { name: 'Zoom in draft diagram', exact: true }).click();
  await page.waitForFunction((width) => document.querySelector('svg[data-theme="dark"]').getBoundingClientRect().width > width, initialWidth);
  await page.getByRole('button', { name: 'Fit draft diagram', exact: true }).click();
  report.darkDiagramPassed = true;
  await page.screenshot({ path: path.join(output, 'review-desktop-dark.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'review-mobile-dark.png'), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
  report.mobileOverflow = false;
  await page.getByRole('button', { name: 'Back to report', exact: true }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export workspace', exact: true }).click();
  await (await download).saveAs(path.join(output, 'workspace.json'));
  await page.reload();
  await page.getByTitle('History', { exact: true }).click();
  await page.getByText('2 report revisions and a saved draft', { exact: true }).waitFor();
  assert.equal(await page.getByTitle('Load analysis', { exact: true }).count(), 1);
  await page.getByTitle('Load analysis', { exact: true }).click();
  await page.getByRole('navigation', { name: 'Analysis result views' }).waitFor();
  assert.equal(await page.getByLabel('Report revision', { exact: true }).inputValue(), '2');
  assert.equal(await page.getByText('Something went wrong', { exact: true }).count(), 0);
  report.persistedSingleWorkspace = true;
  report.errors = errors;
  assert.deepEqual(errors, []);
  report.passed = true;
} catch (error) {
  report.failure = error.message;
  report.errors = errors;
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
  throw error;
} finally {
  await writeFile(path.join(output, 'verification.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(JSON.stringify(report, null, 2));
