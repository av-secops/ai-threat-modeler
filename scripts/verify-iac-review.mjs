import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/iac-review-ui');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (error) => errors.push(error.message));
const report = {};
const responseFor = (endpoint) => page.waitForResponse((r) => r.url().endsWith(endpoint) && r.request().method() === 'POST');
async function prepare(action) {
  const response = responseFor('/model-review/prepare');
  await action();
  const result = await response;
  assert.equal(result.status(), 200, await result.text());
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some((button) => button.textContent === 'Analyze reviewed model' && !button.disabled));
  return result.json();
}
try {
  await page.goto('http://127.0.0.1:5173/');
  await page.getByTitle('IaC Analysis', { exact: true }).click();
  await page.getByLabel('IaC project name').fill('Mixed infrastructure review QA');
  await page.getByLabel('IaC format', { exact: true }).selectOption('bicep');
  await page.getByLabel('IaC source').fill("param adminPassword string = 'qa-literal-password'\nresource db 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {}");
  let preview = await prepare(() => page.getByRole('button', { name: 'Review infrastructure', exact: true }).click());
  assert.ok(preview.architecture.metadata.iac_findings.some((f) => f.rule_id === 'IAC-BICEP-HARDCODED-SECRET'));
  report.pastedFormatHonored = true;
  await page.getByRole('navigation', { name: 'Model review sections' }).getByRole('button', { name: 'Sources', exact: true }).click();
  await page.getByLabel('Additional architecture context').fill('React calls a Node.js API over HTTPS. Redis stores API sessions.');
  await prepare(() => page.getByRole('button', { name: 'Add context to draft', exact: true }).click());
  preview = await prepare(() => page.getByLabel('Add review files', { exact: true }).setInputFiles([
    { name: 'storage.tf', mimeType: 'text/plain', buffer: Buffer.from('resource "aws_s3_bucket" "images" {\n bucket = "qa-images"\n acl = "public-read"\n}\n') },
    { name: 'secondary.bicep', mimeType: 'text/plain', buffer: Buffer.from("param adminPassword string = 'qa-second-password'\nresource secondary 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {}") },
    { name: 'docker-compose.yml', mimeType: 'application/yaml', buffer: Buffer.from('services:\n  orders:\n    image: postgres:16\n    ports: ["5432:5432"]\n') },
  ]));
  await page.getByText('secondary.bicep', { exact: false }).first().waitFor();
  assert.ok(preview.architecture.components.some((c) => /react/i.test(c.name)));
  const before = preview.architecture.metadata.iac_findings;
  assert.ok(before.some((f) => f.source_file === 'storage.tf'));
  assert.ok(before.some((f) => f.source_file === 'secondary.bicep'));
  report.mixedFilesAndContext = true;

  await page.getByText('storage.tf', { exact: false }).first().click();
  await prepare(() => page.getByLabel('Environment: storage.tf', { exact: true }).fill('staging'));
  await prepare(() => page.getByLabel('Version: storage.tf', { exact: true }).fill('review-2'));
  preview = await prepare(() => page.getByLabel('Replace storage.tf', { exact: true }).setInputFiles({ name: 'storage.tf', mimeType: 'text/plain', buffer: Buffer.from('resource "aws_s3_bucket" "images" {\n bucket = "qa-images"\n acl = "private"\n}\n') }));
  await page.waitForFunction(() => document.querySelector('[aria-label="Source text: storage.tf"]')?.value.includes('acl = "private"'));
  assert.equal(await page.getByLabel('Environment: storage.tf', { exact: true }).inputValue(), 'staging');
  assert.equal(await page.getByLabel('Version: storage.tf', { exact: true }).inputValue(), 'review-2');
  report.replacementPreservesScope = true;
  const excluded = preview.architecture.components.find((c) => c.properties.source_file === 'docker-compose.yml');
  assert.ok(excluded);
  await page.getByRole('navigation', { name: 'Model review sections' }).getByRole('button', { name: 'Architecture', exact: true }).click();
  preview = await prepare(() => page.getByRole('button', { name: `Exclude ${excluded.name}`, exact: true }).click());
  assert.ok(preview.architecture.metadata.review_exclusions.some((e) => e.finding.resource_id === excluded.id));
  assert.equal(preview.architecture.metadata.iac_findings.some((f) => f.resource_id === excluded.id), false);
  const analyzed = responseFor('/model-review/analyze');
  await page.getByRole('button', { name: 'Analyze reviewed model', exact: true }).click();
  const result = await analyzed;
  assert.equal(result.status(), 200, await result.text());
  const data = await result.json();
  assert.ok(data.threats.some((t) => t.id.startsWith('IAC-')));
  assert.equal(data.threats.some((t) => t.component_id === excluded.id), false);
  await page.getByRole('navigation', { name: 'Analysis result views' }).waitFor();
  report.resourceExclusionPassed = true;
  await page.screenshot({ path: path.join(output, 'mixed-iac-report.png'), fullPage: true });
  assert.deepEqual(errors, []);
  report.passed = true;
} catch (error) {
  report.failure = error.message;
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
  throw error;
} finally {
  report.errors = errors;
  await writeFile(path.join(output, 'verification.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(JSON.stringify(report, null, 2));
