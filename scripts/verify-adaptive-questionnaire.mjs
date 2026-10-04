import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const api = process.env.AEGIS_TEST_API_URL || 'http://127.0.0.1:8012';
const output = path.resolve('backend/evaluation_reports/adaptive-questionnaire');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
await context.addInitScript(() => { sessionStorage.setItem('aegis-workspace-token', 'questionnaire-qa'); localStorage.setItem('theme', 'light'); });
const page = await context.newPage();
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.setDefaultTimeout(45000);
await page.route('http://127.0.0.1:8000/**', async route => {
  const url = new URL(route.request().url());
  const response = await route.fetch({ url: api + url.pathname + url.search, timeout: 120000 });
  await route.fulfill({ response });
});
let preview;
let updates = 0;
async function update(action) {
  const pending = page.waitForResponse(r => r.url().endsWith('/model-review/prepare'));
  await action();
  const response = await pending;
  assert.equal(response.status(), 200, await response.text());
  preview = await response.json();
  updates++;
  await page.getByText('Updating architecture...', { exact: true }).waitFor({ state: 'hidden' });
}
async function screenshot(name) {
  await page.getByRole('heading', { name: /^Pre-DFD questionnaire/ }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(output, name) });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2), false);
}

try {
  await page.goto(process.env.AEGIS_UI_URL || 'http://127.0.0.1:5173/');
  await page.getByTitle('Static Analysis', { exact: true }).click();
  await page.getByPlaceholder('e.g. Payment Gateway V2').fill('Adaptive questionnaire QA');
  await page.getByLabel('Select Application Type').selectOption('api');
  await page.getByLabel('Architecture description').fill([
    'A telecom platform has a public React frontend for subscribers and operators.',
    'React frontend calls Orders API over HTTPS.',
    'Orders API calls Billing API over HTTPS.',
    'Billing API calls Payments API over HTTPS.',
    'Payments API calls Notifications API over HTTPS.',
    'Orders API has rate limiting enabled.',
    'Billing API has no rate limiting.',
    'The platform stores sensitive personal data and invoices in PostgreSQL.',
    'Payments API integrates with external Stripe for payment processing.',
  ].join('\n'));
  await page.locator('#useLocalSlm').uncheck();
  await update(() => page.getByRole('button', { name: 'Review architecture', exact: true }).click());
  const initial = preview.questionnaire;
  assert.equal(initial.complete, false);
  assert.equal(preview.diagram, '');
  assert.ok(initial.questionnaire_summary.clarification_groups < initial.questions.length);
  assert.equal(await page.getByRole('button', { name: 'Generate DFD', exact: true }).isDisabled(), true);
  await screenshot('desktop-light.png');
  await page.getByTitle('Dark mode', { exact: true }).click();
  await screenshot('desktop-dark.png');
  await page.setViewportSize({ width: 390, height: 844 });
  await screenshot('mobile-dark.png');
  await page.getByTitle('Light mode', { exact: true }).click();
  await screenshot('mobile-light.png');
  await page.setViewportSize({ width: 1440, height: 1000 });

  const authGroups = Map.groupBy(initial.questions.filter(q => q.key === 'authentication' && !q.proposal), q => q.group_key);
  const auth = [...authGroups.values()].sort((a, b) => b.length - a.length)[0];
  const excluded = initial.questions.find(q => q.key === 'authentication' && q.group_key !== auth[0].group_key);
  assert.ok(auth.length >= 2 && excluded);
  const form = page.locator('form').filter({ has: page.getByLabel(`Apply answer: ${auth[0].id}`, { exact: true }) });
  assert.equal(await form.locator('input[type=checkbox]:checked').count(), 0);
  await form.getByLabel(`Apply answer: ${auth[0].id}`, { exact: true }).check();
  await form.getByLabel(`Apply answer: ${auth[1].id}`, { exact: true }).check();
  await form.locator('[aria-label^="Group answer:"]').selectOption('present');
  const explanation = form.getByLabel(`Brief explanation: ${auth[0].group_key}`, { exact: true });
  assert.match(await explanation.getAttribute('placeholder'), /design document confirms/);
  assert.equal(await explanation.inputValue(), '');
  assert.equal(await form.getByRole('button', { name: 'Record for selected (2)', exact: true }).isDisabled(), true);
  await form.locator('[aria-label^="Group answer:"]').selectOption('unknown');
  assert.match(await explanation.getAttribute('placeholder'), /check with the application owner/);
  await page.setViewportSize({ width: 390, height: 844 });
  await explanation.scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(output, 'explanation-mobile.png') });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2), false);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await form.locator('[aria-label^="Why are you unsure:"]').selectOption({ label: 'Awaiting confirmation from the component owner.' });
  await form.locator('[aria-label^="Who can confirm this:"]').fill('Identity team');
  await update(() => form.getByRole('button', { name: 'Record for selected (2)', exact: true }).click());
  assert.equal(preview.questionnaire.answers.filter(a => a.question_key === 'authentication').length, 2);
  assert.equal(preview.questionnaire.questions.find(q => q.id === excluded.id).status, 'unanswered');

  await page.getByRole('button', { name: /^Suggested answers/ }).click();
  const proposals = preview.questionnaire.questions.filter(q => q.proposal && q.status !== 'answered');
  assert.ok(proposals.some(q => q.control === 'rate_limiting'));
  const suggested = page.getByRole('region', { name: 'Suggested questionnaire answers', exact: true });
  assert.equal(await suggested.locator('input[type=checkbox]:checked').count(), 0);
  await suggested.getByLabel('Select listed proposals', { exact: true }).check();
  await screenshot('source-proposals.png');
  await update(() => suggested.getByRole('button', { name: /^Confirm selected answers/ }).click());
  assert.equal(preview.questionnaire.answers.filter(a => a.confirmation_basis === 'source').length, proposals.length);

  await page.getByRole('button', { name: /^Needs input/ }).click();
  let prompts = 0;
  while (!preview.questionnaire.complete && prompts++ < 40) {
    const activeForm = page.locator('form').filter({ has: page.locator('[aria-label^="Group answer:"]') }).first();
    for (const checkbox of await activeForm.locator('input[aria-label^="Apply answer:"]').all()) await checkbox.check();
    const answer = activeForm.locator('[aria-label^="Group answer:"]');
    if (await answer.evaluate(el => el.tagName === 'SELECT')) await answer.selectOption('unknown');
    else await answer.fill('unknown');
    await activeForm.locator('[aria-label^="Brief explanation:"]').fill('Awaiting confirmation from the responsible component owner.');
    await update(() => activeForm.getByRole('button', { name: /^Record for selected/ }).click());
  }
  assert.equal(preview.questionnaire.complete, true);
  await update(() => page.getByRole('button', { name: 'Generate DFD', exact: true }).click());
  await page.locator('[aria-label="Draft architecture diagram"] svg').waitFor();
  assert.ok(preview.diagram && preview.flows.every(f => f.flow_number));
  assert.deepEqual(errors, []);
  const result = { passed: true, initialChecks: initial.questions.length,
    initialClarificationGroups: initial.questionnaire_summary.clarification_groups,
    confirmedProposals: proposals.length, manualGroupSubmissions: prompts + 1, prepareRequests: updates, errors };
  await writeFile(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} catch (error) {
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true }).catch(() => {});
  console.error(JSON.stringify({ error: error.message, pageErrors: errors, body: await page.locator('body').innerText().catch(() => '') }));
  throw error;
} finally {
  await browser.close();
}
