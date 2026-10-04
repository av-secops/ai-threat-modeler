import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/products-workspace');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
await context.addInitScript(() => {
  sessionStorage.setItem('aegis-workspace-token', 'dashboard-test-editor');
  localStorage.setItem('theme', 'light');
});
const page = await context.newPage();
const errors = [];
const settleTheme = async () => {
  await page.evaluate(async () => {
  await document.fonts.ready;
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  await Promise.all(document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity).map(animation => animation.finished.catch(() => {})));
  });
};
const checkButtonContrast = async () => {
  const ratios = await page.locator('.ui-button-secondary:not(:disabled)').evaluateAll(nodes => nodes.map(node => {
    const style = getComputedStyle(node);
    const luminance = color => color.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4).reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
    const text = luminance(style.color), bg = luminance(style.backgroundColor);
    return { label: node.getAttribute('aria-label') || node.textContent, ratio: (Math.max(text, bg) + 0.05) / (Math.min(text, bg) + 0.05), color: style.color };
  }));
  for (const row of ratios) assert.ok(row.ratio >= 4.5, `Button contrast: ${JSON.stringify(row)}`);
};
page.on('pageerror', error => errors.push(error.message));
page.setDefaultTimeout(15000);
await page.route('**/enterprise/**', async route => {
  const url = new URL(route.request().url());
  const response = await route.fetch({ url: (process.env.AEGIS_TEST_API_URL || 'http://127.0.0.1:8011') + url.pathname + url.search });
  await route.fulfill({ response });
});
try {
  await page.goto(process.env.AEGIS_UI_URL || 'http://127.0.0.1:5173/');
  await page.getByRole('button', { name: 'Atlas Product', exact: true }).waitFor();
  await page.screenshot({ path: path.join(output, 'products-desktop-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Atlas Product', exact: true }).click();
  await page.getByRole('table', { name: 'Product releases' }).waitFor();
  await page.getByRole('button', { name: 'Open release 26.09', exact: true }).click();
  await page.getByRole('table', { name: 'Release threat models' }).waitFor();
  const releaseUrl = page.url();
  await page.getByRole('button', { name: 'New threat model', exact: true }).click();
  await page.getByRole('radio', { name: 'One application', exact: true }).check();
  await page.getByLabel('Application', { exact: true }).selectOption({ label: 'Billing' });
  await page.screenshot({ path: path.join(output, 'release-desktop-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Continue to architecture', exact: true }).click();
  await page.getByText('Application: Billing', { exact: true }).waitFor();
  await page.goBack();
  await page.getByRole('table', { name: 'Release threat models' }).waitFor();
  assert.equal(page.url(), releaseUrl);
  await page.getByRole('button', { name: 'New threat model', exact: true }).click();
  await page.getByRole('radio', { name: 'Full release', exact: true }).check();
  await page.getByRole('button', { name: 'Continue to architecture', exact: true }).click();
  await page.getByRole('button', { name: 'Back to release', exact: true }).click();
  await page.getByRole('table', { name: 'Release threat models' }).waitFor();
  await page.getByRole('button', { name: /^View report:/ }).first().click();
  await page.getByRole('button', { name: 'Back to release', exact: true }).waitFor();
  const reportUrl = page.url();
  assert.match(reportUrl, /model=/);
  await page.reload();
  await page.getByRole('button', { name: 'Back to release', exact: true }).waitFor();
  assert.equal(page.url(), reportUrl);
  await page.getByRole('button', { name: 'Back to release', exact: true }).click();
  await page.getByRole('table', { name: 'Release threat models' }).waitFor();
  await page.getByRole('button', { name: 'Dark mode', exact: true }).click();
  await settleTheme();
  await checkButtonContrast();
  const darkText = await page.getByRole('heading', { name: 'Release 26.09', exact: true }).evaluate(node => getComputedStyle(node).color);
  console.log(`Dark-mode heading color: ${darkText}`);
  await page.screenshot({ path: path.join(output, 'release-desktop-dark.png'), fullPage: true });
  for (const width of [390, 768]) {
    await page.setViewportSize({ width, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.screenshot({ path: path.join(output, `release-${width}-dark.png`), fullPage: true });
  }
  await page.getByRole('button', { name: 'Light mode', exact: true }).click();
  await settleTheme();
  await checkButtonContrast();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'release-mobile-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Back to releases', exact: true }).click();
  await page.getByRole('button', { name: 'New release', exact: true }).click();
  await page.getByRole('dialog').waitFor();
  const releaseName = `QA-${Date.now()}`;
  await page.getByLabel('Release name', { exact: true }).fill(releaseName);
  await page.getByRole('button', { name: 'Create release', exact: true }).click();
  await page.getByRole('heading', { name: `Release ${releaseName}`, exact: true }).waitFor();
  assert.equal(await page.getByRole('dialog').count(), 0);
  assert.deepEqual(errors, []);
  await writeFile(path.join(output, 'verification.json'), JSON.stringify({
    scope: 'Isolated test database; not user data', errors, passed: true,
    viewports: [1440, 768, 390], checks: ['creation', 'application reuse', 'whole release', 'browser Back', 'report deep link', 'reload', 'light/dark layout'],
  }, null, 2));
  console.log(`Product workspace browser checks passed. Screenshots: ${output}`);
} finally {
  await browser.close();
}
