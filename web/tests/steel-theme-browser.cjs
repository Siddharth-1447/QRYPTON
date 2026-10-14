/* eslint-disable @typescript-eslint/no-require-imports -- Browser regression runner. */
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const fixture = require('./design-fixture.cjs');
const ts = require('typescript');
const Module = require('node:module');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
function compileComponent(filename, replace = text => text) {
  const component = new Module(filename, module); component.paths = module.paths;
  const output = ts.transpileModule(replace(fs.readFileSync(filename, 'utf8')), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText;
  component._compile(output, filename); return component.exports;
}
const utilsFile = path.resolve(__dirname, '../src/lib/utils.ts');
const utils = compileComponent(utilsFile);
require.cache[utilsFile] = { exports: utils };
const { RiskBadge } = compileComponent(path.resolve(__dirname, '../src/components/ui/primitives.tsx'), source => source.replace('@/lib/utils', utilsFile.replaceAll('\\', '/')));
const riskLevels = ['critical', 'high', 'medium', 'low', 'safe', 'unknown', 'informational', 'unassessed'];

async function textContrast(page) {
  return page.evaluate(() => {
    const cache = new Map(); const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1; const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const rgb = value => { if (cache.has(value)) return cache.get(value); ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = value; ctx.fillRect(0, 0, 1, 1); const result = [...ctx.getImageData(0, 0, 1, 1).data].map((c, i) => i === 3 ? c / 255 : c); cache.set(value, result); return result; };
    const over = (fg, bg) => [...fg.slice(0, 3).map((c, i) => c * fg[3] + bg[i] * (1 - fg[3])), 1];
    const lum = c => c.slice(0, 3).map(x => { x /= 255; return x <= .04045 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4; }).reduce((v, c, i) => v + c * [.2126, .7152, .0722][i], 0);
    const pairs = new Map();
    for (const el of document.querySelectorAll('body *')) {
      if (!el.getClientRects().length || el.closest('[aria-hidden="true"], .sr-only, :disabled') || ![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || Number(style.opacity) < 1) continue;
      const chain = []; for (let p = el; p; p = p.parentElement) chain.unshift(p);
      let bg = rgb(getComputedStyle(document.documentElement).backgroundColor);
      for (const p of chain) bg = over(rgb(getComputedStyle(p).backgroundColor), bg);
      const fg = over(rgb(style.color), bg);
      const ratio = (Math.max(lum(fg), lum(bg)) + .05) / (Math.min(lum(fg), lum(bg)) + .05);
      const key = `${style.color}/${bg.slice(0, 3).map(Math.round)}`;
      const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && Number(style.fontWeight) >= 700);
      if (!pairs.has(key)) pairs.set(key, { text: el.textContent.trim().slice(0, 90), foreground: style.color, background: bg.slice(0, 3).map(Math.round), ratio: +ratio.toFixed(2), required: large ? 3 : 4.5 });
    }
    return [...pairs.values()];
  });
}

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const out = path.resolve(__dirname, '../../tmp/steel-theme'); fs.mkdirSync(out, { recursive: true });
  const results = [];
  try {
    for (const width of [1440, 390]) for (const theme of ['dark', 'light']) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      await context.addInitScript(theme => { localStorage.setItem('qrypton.theme', theme); }, theme);
      const page = await context.newPage(); const errors = []; page.on('pageerror', e => { errors.push(e.message); console.log('PAGE ERROR', e.message); });
      await page.route('**/api/v1/**', route => {
        const url = new URL(route.request().url()); const endpoint = url.pathname;
      const body = endpoint.endsWith('/export-preview') ? { run_id: 'visual-test', scope: 'Test fixture', target_type: 'source_repo', asset_count: 6, finding_count: 6, risk_summary: Object.fromEntries(fixture.inventory.map(row => [row.risk_level, 1])), cbom_available: true, report_available: true, provenance: 'Browser test fixture' } : endpoint.endsWith('/inventory/views') ? { views: [] } : endpoint.endsWith('/dashboard') ? fixture.dashboard : endpoint.endsWith('/posture') ? fixture.posture : endpoint.endsWith('/inventory') ? fixture.inventory : endpoint.endsWith('/roadmap') ? fixture.roadmap : endpoint.includes('/findings/') ? { ...fixture.detail, mosca: { urgency: 'critical', mosca_applicable: 'yes', x_data_lifetime_years: 7, y_migration_years: 3, z_crqc_horizon_years: 6, required_security_years: 10, time_margin_years: -4 } } : endpoint.endsWith('/scans') ? [{ scan_id: 'visual-test', artifact: 'TEST FIXTURE ONLY', target_type: 'source_repo', environment: 'test', status: 'COMPLETED', completed_at: '2026-10-08', ...fixture.posture }] : {};
        return route.fulfill({ status: Object.keys(body).length ? 200 : 404, json: body, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': String(fixture.inventory.length) } });
      });
      await page.goto('http://127.0.0.1:3011/login');
      await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
      await page.screenshot({ animations: "disabled", path: path.join(out, `landing-${theme}-${width}.png`), fullPage: true });
      results.push({ theme, width, screen: 'landing', pairs: await textContrast(page) });
      await page.evaluate(() => sessionStorage.setItem('qrypton.session', 'active'));
      const response = await page.goto('http://127.0.0.1:3011/');
      console.log({status: response.status(), errors});
      await page.getByRole('button', { name: 'Start a new cryptographic scan' }).waitFor();
      await page.getByRole('button', { name: 'Raw table', exact: true }).click();
      await page.locator('#inventory .inventory-data-row').first().waitFor();
      await page.evaluate(() => document.fonts.ready);
      fs.writeFileSync(path.join(out, `debug-${theme}-${width}.html`), await page.content());
      console.log(await page.evaluate(() => ({ url: location.href, root: document.documentElement.outerHTML.slice(0, 250), canvas: getComputedStyle(document.documentElement).getPropertyValue('--canvas') })));
      assert.equal(await page.locator('html').getAttribute('data-resolved-theme'), theme);
      if (width === 1440) {
        assert.equal(await page.locator('aside[aria-label="Primary"] [data-logo-tone="on-dark"]').count(), 1);
        const marker = await page.locator('aside[aria-label="Primary"] button[aria-current]').evaluate(el => getComputedStyle(el, '::before').width);
        assert.equal(marker, '2px');
      }
      for (const id of ['dashboard', 'inventory', 'risk', 'roadmap', 'reports']) {
        await page.locator(`#${id}`).scrollIntoViewIfNeeded();
        await page.screenshot({ animations: "disabled", path: path.join(out, `${id}-${theme}-${width}.png`) });
      }
      assert.ok(await page.locator('.risk-cell').first().evaluate(el => getComputedStyle(el).borderColor === getComputedStyle(el).color), 'Heatmap boundary matches its AA label colour');
      const downloaded = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download HTML Report', exact: true }).click();
      const reportPath = path.join(out, `report-${theme}-${width}.html`);
      await (await downloaded).saveAs(reportPath);
      const report = await context.newPage();
      await report.goto(require('node:url').pathToFileURL(reportPath).href);
      assert.ok(await report.locator('[data-risk-level="critical"] svg').count());
      await report.screenshot({ animations: 'disabled', path: path.join(out, `html-report-${theme}-${width}.png`), fullPage: true });
      results.push({ theme, width, screen: 'offline HTML report', pairs: await textContrast(report) });
      await report.close();
      const row = page.locator('#inventory .inventory-data-row').first();
      const height = await row.evaluate(el => el.getBoundingClientRect().height);
      await row.getByRole('checkbox').check();
      assert.equal(await row.getAttribute('aria-selected'), 'true');
      assert.equal(await row.evaluate(el => el.getBoundingClientRect().height), height);
      await row.getByRole('checkbox').uncheck();
      results.push({ theme, width, screen: 'workspace', pairs: await textContrast(page) });
      await page.locator('#inventory .inventory-data-row').first().click();
      await page.getByRole('heading', { name: 'Will protection outlast the planning horizon?' }).waitFor();
      assert.equal(await page.locator('.qrypton-threshold').first().evaluate(el => getComputedStyle(el).borderLeftColor), await page.locator('html').evaluate(el => { const probe = document.createElement('span'); probe.style.color = 'var(--primary)'; el.append(probe); const color = getComputedStyle(probe).color; probe.remove(); return color; }));
      await page.screenshot({ animations: "disabled", path: path.join(out, `finding-${theme}-${width}.png`) });
      results.push({ theme, width, screen: 'finding', pairs: await textContrast(page) });
      assert.deepEqual(errors, []);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Horizontal overflow');
      if (width === 1440 && theme === 'dark') {
        const stylesheet = await page.locator('link[rel="stylesheet"]').first().getAttribute('href');
        const badges = riskLevels.map(level => renderToStaticMarkup(React.createElement(RiskBadge, { level }))).join(' ');
        await page.setContent(`<html data-resolved-theme="dark"><head><link rel="stylesheet" href="http://127.0.0.1:3011${stylesheet}"></head><body class="bg-background p-6"><button class="bg-primary text-primary-foreground rounded-md px-4 py-2">Accent</button><div class="qrypton-card mt-4 flex flex-wrap gap-4 p-6">${badges}</div></body></html>`);
        await page.locator('[data-risk-level="safe"]').waitFor();
        const cdp = await context.newCDPSession(page);
        for (const type of ['achromatopsia', 'deuteranopia', 'protanopia', 'tritanopia']) {
          await cdp.send('Emulation.setEmulatedVisionDeficiency', { type });
          for (const level of riskLevels) {
            const badge = page.locator(`[data-risk-level="${level}"]`).first();
            assert.ok(await badge.locator('svg').count()); assert.ok((await badge.textContent()).trim());
          }
          await page.screenshot({ animations: 'disabled', path: path.join(out, `risk-${type}.png`), fullPage: true });
        }
      }
      await context.close();
    }
    fs.writeFileSync(path.join(out, 'contrast.json'), JSON.stringify(results, null, 2));
    const failures = results.flatMap(result => result.pairs.filter(pair => pair.ratio < pair.required).map(pair => ({ ...result, pairs: undefined, ...pair })));
    console.log(JSON.stringify({ screens: results.length, failures, output: out }, null, 2));
    assert.equal(failures.length, 0);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
