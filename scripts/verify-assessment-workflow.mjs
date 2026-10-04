import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/assessment-workflow');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
const page = await context.newPage();
if (process.env.AEGIS_TEST_API_URL) await page.route('http://127.0.0.1:8000/**', async route => {
  const response = await route.fetch({ url: route.request().url().replace('http://127.0.0.1:8000', process.env.AEGIS_TEST_API_URL), timeout: 180000 });
  await route.fulfill({ response });
});
const errors = [];
page.on('pageerror', error => errors.push(error.message));
page.setDefaultTimeout(45000);
const prepared = () => page.waitForResponse(response => response.url().endsWith('/model-review/prepare'));
let preview;

async function update(action) {
  const pending = prepared();
  await action();
  const response = await pending;
  assert.equal(response.status(), 200, await response.text());
  preview = await response.json();
  await page.getByText('Updating architecture...', { exact: true }).waitFor({ state: 'hidden' });
}

try {
  await page.goto(process.env.AEGIS_UI_URL || 'http://127.0.0.1:5173/');
  await page.getByTitle('Static Analysis', { exact: true }).click();
  await page.getByPlaceholder('e.g. Payment Gateway V2').fill('Assessment workflow QA');
  await page.getByLabel('Select Application Type').selectOption('web');
  await page.getByLabel('Architecture description').fill('React frontend calls a Node.js REST API over HTTPS. Node.js REST API queries PostgreSQL over TLS.\nKNOWN ISSUES:\n- Node.js API has no input validation.');
  await page.locator('#useLocalSlm').uncheck();
  await update(() => page.getByRole('button', { name: 'Review architecture', exact: true }).click());
  assert.equal(preview.diagram, '');
  assert.equal(await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).isDisabled(), true);
  await page.screenshot({ path: path.join(output, 'questionnaire-light.png'), fullPage: true });
  const questions = preview.questionnaire.questions;
  await page.getByRole('button', { name: /^All checks/ }).click();
  for (let index = 0; index < questions.length; index += 1) {
    if (index && index % 5 === 0) await page.getByRole('button', { name: 'Next questions', exact: true }).click();
    const q = questions[index];
    const answer = page.getByLabel(`Answer: ${q.id}`, { exact: true });
    if (['control', 'choice'].includes(q.answer_type)) await answer.selectOption('unknown');
    else await answer.fill('unknown');
    await page.getByLabel(`Brief explanation: ${q.id}`, { exact: true }).fill('Architecture owner will validate these deployment settings.');
    const form = page.locator('form').filter({ has: answer });
    await update(() => form.getByRole('button', { name: 'Record answer', exact: true }).click());
  }
  assert.equal(preview.questionnaire.complete, true);
  await update(() => page.getByRole('button', { name: 'Generate DFD', exact: true }).click());
  await page.locator('[aria-label="Draft architecture diagram"] svg').waitFor();
  assert.ok(preview.flows.every(flow => /^F-\d+$/.test(flow.flow_number)));
  const flowNumbers = preview.flows.map(flow => flow.flow_number);
  await page.getByRole('button', { name: 'Layout', exact: true }).click();
  const layout = page.getByLabel('Drag component layout');
  await layout.locator('canvas').first().waitFor({ state: 'attached' });
  await page.getByRole('button', { name: 'Fit layout', exact: true }).click();
  const node = await layout.evaluate(element => {
    const cy = element._cyreg.cy;
    const selected = cy.nodes().filter(n => !n.isParent())[0];
    const { x, y } = selected.renderedPosition();
    const bounds = element.getBoundingClientRect();
    return { x: bounds.x + x, y: bounds.y + y };
  });
  await update(async () => {
    await page.mouse.move(node.x, node.y); await page.mouse.down();
    await page.mouse.move(node.x + 40, node.y + 30, { steps: 8 }); await page.mouse.up();
  });
  assert.ok(Object.keys(preview.architecture.metadata.diagram_layout).length > 0);
  assert.equal(preview.questionnaire.complete, true);
  assert.deepEqual(preview.flows.map(flow => flow.flow_number), flowNumbers);
  assert.equal(await layout.locator('canvas').evaluateAll(canvases => canvases.some(canvas => {
    const ctx = canvas.getContext('2d');
    if (!ctx) return false;
    const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    let nontransparent = 0;
    for (let i = 3; i < pixels.length; i += 4) if (pixels[i]) nontransparent++;
    return nontransparent > 200;
  })), true);
  await page.screenshot({ path: path.join(output, 'layout.png') });
  await page.getByRole('button', { name: 'DFD', exact: true }).click();
  await page.locator('[aria-label="Draft architecture diagram"] svg').waitFor();
  await page.screenshot({ path: path.join(output, 'dfd-light.png'), fullPage: true });
  await page.getByTitle('Dark mode', { exact: true }).click();
  await page.locator('[aria-label="Draft architecture diagram"] svg[data-theme="dark"]').waitFor();
  await page.screenshot({ path: path.join(output, 'dfd-dark.png'), fullPage: true });
  await page.getByTitle('Light mode', { exact: true }).click();
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).click();
  await page.getByRole('button', { name: 'Risk register', exact: true }).waitFor({ timeout: 180000 });
  await page.getByRole('button', { name: 'Risk register', exact: true }).click();
  await page.getByRole('button', { name: /^View details for / }).first().click();
  await page.getByLabel('Product review status', { exact: true }).selectOption('in_review');
  await page.getByLabel('Product team remarks', { exact: true }).fill('Product architect is validating the affected request path.');
  const savedReview = page.waitForResponse(response => response.request().method() === 'POST' && response.url().includes('/reviews/'));
  await page.getByRole('button', { name: 'Record review', exact: true }).click();
  assert.equal((await savedReview).status(), 200);
  await page.getByText('Product architect is validating the affected request path.', { exact: true }).waitFor();
  await page.screenshot({ path: path.join(output, 'risk-review.png'), fullPage: true });
  await page.getByRole('button', { name: 'Close risk details', exact: true }).click();
  const csv = page.waitForEvent('download');
  await page.getByRole('button', { name: 'CSV', exact: true }).click();
  await (await csv).saveAs(path.join(output, 'risk-register.csv'));
  const pdf = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export PDF', exact: true }).click();
  await (await pdf).saveAs(path.join(output, 'assessment-report.pdf'));
  await page.getByRole('button', { name: 'Security Reports', exact: true }).click();
  await page.getByLabel('Security assessment', { exact: true }).selectOption('sast');
  await page.getByText('Import SAST report', { exact: true }).click();
  const inputs = page.locator('form').filter({ has: page.getByLabel('Security report file') });
  for (const [label, value] of [['title', 'QA SAST'], ['source', 'QA scanner'], ['report date', '2026-09-19'], ['environment', 'test'], ['deployment version', '26.09']]) {
    await inputs.getByLabel(label, { exact: true }).fill(value);
  }
  await page.getByLabel('Security report file').setInputFiles({ name: 'qa.sarif', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ version: '2.1.0', runs: [{ results: [{ ruleId: 'QA-1', level: 'warning', message: { text: 'Review input validation' } }] }] })) });
  const imported = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/security-reports'));
  await page.getByRole('button', { name: 'Import report', exact: true }).click();
  assert.equal((await imported).status(), 200);
  await page.locator('li').getByText('Review input validation', { exact: true }).waitFor();
  await page.getByLabel('External report status', { exact: true }).selectOption('under_review');
  await page.getByLabel('External report remarks', { exact: true }).fill('Product team reviewed the scanner scope and linked its evidence.');
  await page.getByLabel('Imported finding to link', { exact: true }).selectOption({ index: 1 });
  await page.getByLabel('Linked component', { exact: true }).selectOption({ index: 1 });
  await page.getByLabel('Link evidence', { exact: true }).fill('Scanner source location matches the modeled component.');
  await page.getByRole('button', { name: 'Add model link', exact: true }).click();
  const reportReviewed = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/review'));
  await page.getByRole('button', { name: 'Save report review', exact: true }).click();
  assert.equal((await reportReviewed).status(), 200);
  await page.getByText('Product team reviewed the scanner scope and linked its evidence.', { exact: true }).waitFor();
  await page.screenshot({ path: path.join(output, 'security-reports.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'security-reports-mobile.png'), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2), false);
  assert.deepEqual(errors, []);
  await writeFile(path.join(output, 'result.json'), JSON.stringify({ passed: true, questions: questions.length, components: preview.architecture.components.length, flows: preview.flows.length, errors }, null, 2));
  console.log(JSON.stringify({ passed: true, questions: questions.length, output }));
} catch (error) {
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true }).catch(() => {});
  console.error(JSON.stringify({ pageErrors: errors, failure: error.message, body: await page.locator('body').innerText().catch(() => '') }));
  throw error;
} finally {
  await context.close();
  await browser.close();
}
