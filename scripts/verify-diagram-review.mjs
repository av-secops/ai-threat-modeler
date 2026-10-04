import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve('backend/evaluation_reports/diagram-review');
await mkdir(output, { recursive: true });
const fixture = JSON.parse(await readFile(path.join(output, 'fixture.json'), 'utf8'));
const browser = await chromium.launch({ headless: true, channel: 'msedge' });
const page = await browser.newPage({ viewport: { width: 1500, height: 1050 } });
const errors = [];
page.on('pageerror', e => { errors.push(e.message); console.error(e.message); });
await page.route('**/__diagram-review-fixture**', route => route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module">
import RefreshRuntime from '/@react-refresh';
RefreshRuntime.injectIntoGlobalHook(window); window.$RefreshReg$=()=>{}; window.$RefreshSig$=()=>type=>type; window.__vite_plugin_react_preamble_installed__=true;
const {default: React} = await import('/node_modules/.vite/deps/react.js');
const {default: ReactDOM} = await import('/node_modules/.vite/deps/react-dom_client.js');
await import('/src/index.css');
const {default:Workspace} = await import('/src/components/ModelReviewWorkspace.jsx');
const {draftSignature} = await import('/src/utils/modelWorkspace.js');
const data = ${JSON.stringify(fixture).replaceAll('<', '\\u003c')};
function App(){ const [workspace,setWorkspace]=React.useState({id:'diagram-review-test',projectName:'Commerce diagram review',revisions:[],draft:{...data,preparedSignature:draftSignature(data.payload)}});
return React.createElement('main',{className:'p-5 bg-white dark:bg-brand-900 text-brand-900 dark:text-brand-100 min-h-screen'},React.createElement(Workspace,{workspace,onChange:next=>{window.lastDraft=next;setWorkspace(next)},onPrepare:()=>{},onAnalyze:()=>{},onUpload:()=>{},onSave:()=>{},busy:false,saveStatus:'Saved',darkMode:new URLSearchParams(location.search).get('theme')==='dark'})); }
if(new URLSearchParams(location.search).get('theme')==='dark')document.documentElement.classList.add('dark');
ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
</script></body></html>` }));
try {
  const base = process.env.AEGIS_UI_URL || 'http://127.0.0.1:5173';
  for (const [theme, width] of [['light', 1500], ['dark', 1500], ['light', 390]]) {
    await page.setViewportSize({ width, height: 1050 });
    await page.goto(`${base}/__diagram-review-fixture?theme=${theme}`);
    await page.getByRole('region', { name: 'Original architecture image' }).waitFor();
    await page.getByRole('button', { name: /Inspect component.*Orders API/ }).waitFor();
    await page.getByRole('button', { name: /Inspect component.*Orders API/ }).click();
    const region = page.getByRole('button', { name: 'Source region: Orders API', exact: true });
    assert.match(await region.getAttribute('class'), /bg-cyan-300/);
    await page.getByRole('button', { name: 'Zoom in original image', exact: true }).click();
    await page.getByRole('button', { name: 'Fit original image', exact: true }).click();
    await region.click();
    const outlined = await page.locator('[data-element-ids]').evaluateAll(nodes => nodes.filter(n => n.style.outline.includes('2px')).length);
    assert.ok(outlined > 0);
    await page.screenshot({ path: path.join(output, `${theme}-${width}.png`), fullPage: true });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Page should not overflow horizontally');
    const task = fixture.preview.diagram_questions.find(q => q.kind === 'flow');
    await page.getByLabel(`Interpretation: ${task.id}`, { exact: true }).selectOption('reverse');
    await page.getByLabel(`Review note: ${task.id}`, { exact: true }).fill('Architecture owner verified response direction.');
    await page.getByRole('button', { name: 'Record decision', exact: true }).click();
    assert.equal(await page.evaluate(() => window.lastDraft.draft.payload.diagram_decisions[0].action), 'reverse');
  }
  assert.deepEqual(errors, []);
  console.log('Diagram review passed: desktop light/dark, mobile, selection, zoom, and review decision.');
} catch (error) {
  await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
  console.error(await page.locator('body').innerText());
  throw error;
} finally { await browser.close(); }
