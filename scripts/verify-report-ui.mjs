// Run against the local app with an isolated browser context and real API output.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile, stat } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/ui-2026-09-05');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
const page = await context.newPage();
await page.route('**/feedback/findings', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
const errors = [];
page.on('pageerror', (error) => errors.push(error.message));
const report = {};
try {
    const response = await context.request.post('http://127.0.0.1:8000/analyze', { data: {
        project_name: 'QA Multi-tenant Workspace', use_local_slm: false,
        description: 'A multi-tenant SaaS uses React, a Node.js GraphQL API, PostgreSQL, Redis sessions, Auth0 and Stripe. React calls GraphQL over HTTPS. GraphQL reads PostgreSQL over TLS and Redis over TLS. Stripe sends HTTPS webhooks to the Node.js API. KNOWN ISSUES:\n- The GraphQL endpoint has no query depth or cost limits.\n- Session tokens remain valid after password changes.\n- Tenant identifiers from requests are trusted without checking the authenticated tenant.\n- Stripe webhook signatures are not verified.',
    }, timeout: 120000 });
    assert.equal(response.status(), 200, await response.text());
    const analysis = await response.json();
    report.findings = analysis.threats.length;
    report.confirmed = analysis.threats.filter((item) => item.tier === 'Confirmed').length;
    await page.goto('http://127.0.0.1:5173/');
    await page.evaluate(async (result) => {
        const { mapAnalysisResult } = await import('/src/utils/analysisMapper.js');
        localStorage.setItem('savedAnalyses', JSON.stringify([{ id: 1, projectName: result.project_name, data: mapAnalysisResult(result), timestamp: new Date().toISOString() }]));
    }, analysis);
    await page.getByTitle('History', { exact: true }).click();
    await page.getByTitle('Load analysis', { exact: true }).click();
    await page.getByRole('heading', { name: 'QA Multi-tenant Workspace', exact: true }).waitFor();
    const views = page.getByRole('navigation', { name: 'Analysis result views' });
    const verifyReport = async (theme) => {
        await views.getByRole('button', { name: 'Report', exact: true }).click();
        const heading = page.getByRole('heading', { name: 'Final report', exact: true });
        await heading.waitFor({ timeout: 5000 });
        assert.equal(await page.getByText('Something went wrong', { exact: true }).count(), 0);
        const finalReport = page.locator('section').filter({ has: heading });
        const confirmed = analysis.threats.filter((item) => item.tier === 'Confirmed');
        assert.ok(confirmed.length > 0, 'Report regression requires confirmed risks to render severity badges');
        for (const threat of confirmed.slice(0, 8)) {
            const risk = finalReport.getByRole('button').filter({ hasText: threat.title });
            await risk.waitFor();
            assert.equal(await risk.getByText(threat.severity, { exact: true }).count(), 1);
        }
        await finalReport.getByRole('button').filter({ hasText: confirmed[0].title }).click();
        await page.getByRole('dialog').waitFor();
        await page.keyboard.press('Escape');
        await page.getByRole('dialog').waitFor({ state: 'hidden' });
        await page.screenshot({ path: path.join(output, `desktop-report-${theme}.png`), fullPage: true });
        report[`report${theme === 'dark' ? 'Dark' : 'Light'}Passed`] = true;
    };
    await verifyReport('light');
    await views.getByRole('button', { name: /Overview/ }).click();
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export PDF', exact: true }).click();
    const pdf = await downloadPromise;
    const pdfPath = path.join(output, 'qa-export.pdf');
    await pdf.saveAs(pdfPath);
    report.pdfBytes = (await stat(pdfPath)).size;
    assert.ok(report.pdfBytes > 1000);
    await page.screenshot({ path: path.join(output, 'desktop-overview.png'), fullPage: true });
    await views.getByRole('button', { name: /Risk register/ }).click();
    await page.getByRole('searchbox').count();
    const search = page.getByRole('textbox', { name: 'Search findings' });
    await search.fill('impossible-absent-qa');
    await page.getByText('No matching risks', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Reset finding filters' }).click();
    await page.getByRole('button', { name: /^Evidenced/ }).click();
    assert.equal(await page.locator('tbody tr').count(), report.confirmed);
    await page.getByRole('button', { name: /^All findings/ }).click();
    await page.screenshot({ path: path.join(output, 'desktop-register.png'), fullPage: true });
    const details = page.getByRole('button', { name: /^View details for/ }).first();
    await details.click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: /^evidence$/i }).click();
    await dialog.getByRole('region', { name: 'Versioned framework references' }).waitFor();
    await dialog.getByText('Taxonomy alignment, not a compliance certification.', { exact: true }).waitFor();
    await page.screenshot({ path: path.join(output, 'desktop-evidence.png') });
    await dialog.getByRole('button', { name: /^remediation$/i }).click();
    await dialog.getByText('Verify the fix', { exact: true }).waitFor();
    await dialog.getByRole('combobox', { name: 'Finding review status' }).selectOption('accepted');
    assert.equal(await dialog.getByRole('combobox', { name: 'Finding review status' }).inputValue(), 'accepted');
    await page.keyboard.press('Escape');
    await dialog.waitFor({ state: 'hidden' });
    assert.equal(await details.evaluate((node) => node === document.activeElement), true);
    await views.getByRole('button', { name: /Architecture/ }).click();
    const diagram = page.locator('svg[data-base-width]');
    await diagram.waitFor({ timeout: 30000 });
    const firstWidth = await diagram.evaluate((node) => node.getBoundingClientRect().width);
    await page.getByRole('button', { name: 'Zoom in architecture diagram', exact: true }).click();
    await page.waitForFunction((width) => document.querySelector('svg[data-base-width]')?.getBoundingClientRect().width > width, firstWidth);
    await page.getByRole('button', { name: 'Reset architecture diagram zoom' }).click();
    await page.screenshot({ path: path.join(output, 'desktop-architecture-light.png'), fullPage: true });
    await page.getByTitle('Dark mode', { exact: true }).click();
    await page.waitForFunction(() => document.documentElement.classList.contains('dark'));
    await diagram.waitFor();
    await page.waitForTimeout(500);
    report.visibleFlows = await page.locator('svg[data-base-width] .flowchart-link').evaluateAll((nodes) => nodes.filter((node) => {
        const style = getComputedStyle(node);
        return style.stroke !== 'none' && style.stroke !== 'transparent' && Number(style.opacity) > 0;
    }).length);
    report.darkBoundaryFills = await page.locator('svg[data-base-width] .cluster rect').evaluateAll((nodes) => nodes.map((node) => getComputedStyle(node).fill));
    assert.ok(report.darkBoundaryFills.length && report.darkBoundaryFills.every((fill) => fill !== 'rgb(255, 255, 255)'));
    assert.ok(report.visibleFlows > 0);
    await page.screenshot({ path: path.join(output, 'desktop-architecture-dark.png'), fullPage: true });
    const viewport = page.getByLabel('Architecture diagram. Use the mouse wheel or zoom controls to change scale.', { exact: true });
    await viewport.hover();
    const beforeWheel = await diagram.evaluate((node) => node.getBoundingClientRect().width);
    await page.mouse.wheel(0, -120);
    await page.waitForFunction((width) => document.querySelector('svg[data-base-width]')?.getBoundingClientRect().width > width, beforeWheel);
    await verifyReport('dark');
    await page.setViewportSize({ width: 390, height: 844 });
    await views.getByRole('button', { name: /Risk register/ }).click();
    await page.screenshot({ path: path.join(output, 'mobile-register-dark.png'), fullPage: true });
    report.mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
    assert.equal(report.mobileOverflow, false, 'Page overflows the mobile viewport');
    await page.getByRole('button', { name: /^View details for/ }).first().click();
    await page.screenshot({ path: path.join(output, 'mobile-dialog-dark.png') });
    await page.keyboard.press('Escape');
    await page.getByTitle('Light mode', { exact: true }).click();
    await views.getByRole('button', { name: /Overview/ }).click();
    await page.screenshot({ path: path.join(output, 'mobile-overview-light.png'), fullPage: true });
    await page.evaluate(async (result) => {
        const { mapAnalysisResult } = await import('/src/utils/analysisMapper.js');
        const data = mapAnalysisResult(result);
        // Repeated rows test rendering and pagination only, not security accuracy.
        data.threats = Array.from({ length: 60 }, (_, index) => ({ ...data.threats[index % data.threats.length], id: `ui-fixture-${index}`, title: `UI pagination fixture ${index}` }));
        localStorage.setItem('savedAnalyses', JSON.stringify([{ id: 2, projectName: 'UI Pagination Fixture', data, timestamp: new Date().toISOString() }]));
    }, analysis);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.getByTitle('History', { exact: true }).click();
    await page.getByTitle('Load analysis', { exact: true }).click();
    await views.getByRole('button', { name: /Risk register/ }).click();
    assert.equal(await page.locator('tbody tr').count(), 25);
    await page.getByRole('button', { name: 'Next findings page' }).click();
    await page.getByText('Page 2 of 3', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Next findings page' }).click();
    assert.equal(await page.locator('tbody tr').count(), 10);
    assert.equal(await page.getByRole('button', { name: 'Next findings page' }).isDisabled(), true);
    report.paginationPassed = true;
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
