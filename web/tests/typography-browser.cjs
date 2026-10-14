/* eslint-disable @typescript-eslint/no-require-imports -- Standalone browser regression runner. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fixture = require('./design-fixture.cjs');

const longPath = 'services/' + 'payment processing/cryptographic evidence/'.repeat(6) + 'keyexchange.py:118';
const inventory = fixture.inventory.map(row => ({ ...row, application: 'Payment application', environment: 'production', observations: { key_size: { state: 'observed', value: 2048 }, function: { state: 'observed', value: 'key_exchange' }, mode: { state: 'observed', value: 'OAEP' } }, evidence_rows: [{ id: 'evidence-' + 'a'.repeat(80), kind: 'source', location: longPath }], evidence_count: 1 }));
const dashboard = { ...fixture.dashboard, inventory };
const detail = { ...fixture.detail, finding: { ...fixture.detail.finding, algorithm_family: 'RSA', algorithm_identification_status: 'identified' }, mosca: { urgency: 'critical', mosca_applicable: 'yes', x_data_lifetime_years: 7, y_migration_years: 3, z_crqc_horizon_years: 6, required_security_years: 10, time_margin_years: -4 }, evidence_provenance: [{ ...fixture.detail.evidence_provenance[0], location: { relative_path: longPath, line_start: 118, line_end: 121 } }] };

async function inspect(page) {
  return page.evaluate(() => {
    const badWeights = [], clipped = [];
    for (const el of document.querySelectorAll('body *')) {
      const style = getComputedStyle(el);
      if (!el.getClientRects().length || el.closest('.sr-only,[aria-hidden="true"]') || style.visibility === 'hidden') continue;
      if (style.fontFamily.includes('Space Mono') && !['400', '700'].includes(style.fontWeight)) badWeights.push({ text: el.textContent.slice(0, 70), weight: style.fontWeight });
      if (el.childNodes.length && [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()) && el.scrollWidth > el.clientWidth + 2 && ['hidden', 'clip'].includes(style.overflowX) && style.textOverflow !== 'ellipsis' && !el.closest('pre, svg')) clipped.push({ text: el.textContent.trim().slice(0, 80), className: el.className });
    }
    return { fonts: [...document.fonts].filter(face => face.status === 'loaded').map(face => ({ family: face.family, weight: face.weight })), family: getComputedStyle(document.body).fontFamily, badWeights, clipped, pageOverflow: document.documentElement.scrollWidth > innerWidth, shifts: window.fontShifts ?? [], fontReady: window.fontReadyTime ?? 0 };
  });
}

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const out = path.resolve(__dirname, '../../tmp/fonts/browser'); fs.mkdirSync(out, { recursive: true });
  const results = [];
  try {
    for (const width of [1280, 1440]) for (const theme of ['dark', 'light']) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      await context.addInitScript(theme => {
        try { localStorage.setItem('qrypton.theme', theme); } catch { /* Offline file origins. */ }
        window.fontShifts = [];
        new PerformanceObserver(list => { for (const entry of list.getEntries()) if (!entry.hadRecentInput) window.fontShifts.push({ value: entry.value, time: entry.startTime }); }).observe({ type: 'layout-shift', buffered: true });
        document.fonts.addEventListener('loadingdone', () => { window.fontReadyTime = performance.now(); });
      }, theme);
      const page = await context.newPage(); const errors = [], fontRequests = [], external = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('request', request => { if (request.resourceType() === 'font') fontRequests.push(request.url()); });
      await context.route(/^https?:\/\//, route => { const hostname = new URL(route.request().url()).hostname; if (hostname !== '127.0.0.1' && hostname !== 'localhost') { external.push(route.request().url()); return route.abort(); } return route.continue(); });
      await page.route('**/api/v1/**', route => {
        const endpoint = new URL(route.request().url()).pathname;
        const body = endpoint.endsWith('/dashboard') ? dashboard : endpoint.endsWith('/inventory') ? inventory : endpoint.endsWith('/posture') ? fixture.posture : endpoint.endsWith('/roadmap') ? fixture.roadmap : endpoint.includes('/findings/') ? detail : endpoint.endsWith('/inventory/views') ? [] : endpoint.endsWith('/export-preview') ? { run_id: 'visual-test', scope: 'Test fixture', target_type: 'source_repo', asset_count: 6, finding_count: 6, risk_summary: Object.fromEntries(inventory.map(row => [row.risk_level, 1])), cbom_available: true, report_available: true, provenance: 'Browser test fixture' } : endpoint.endsWith('/scans') ? [{ scan_id: 'visual-test', artifact: 'TEST FIXTURE ONLY', target_type: 'source_repo', environment: 'test', status: 'COMPLETED', completed_at: '2026-10-08', ...fixture.posture }] : null;
        return route.fulfill({ status: body === null ? 404 : 200, json: body ?? {}, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': '6' } });
      });
      await page.goto('http://127.0.0.1:3011/login');
      await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
      await page.evaluate(() => document.fonts.ready);
      const landing = await inspect(page); results.push({ theme, width, screen: 'landing', ...landing });
      await page.screenshot({ animations: 'disabled', path: path.join(out, `landing-${theme}-${width}.png`) });
      await page.evaluate(() => sessionStorage.setItem('qrypton.session', 'active'));
      await page.goto('http://127.0.0.1:3011/');
      await page.getByRole('button', { name: 'Raw table', exact: true }).click();
      await page.locator('.inventory-data-row').first().waitFor();
      await page.evaluate(() => document.fonts.ready);
      assert.ok((await page.locator('.inventory-data-row').first().locator('td').nth(2).evaluate(el => getComputedStyle(el.querySelector('.font-mono')).fontFamily)).includes('Space Mono'));
      assert.ok(await page.locator('.tabular-nums.text-2xl').first().evaluate(el => getComputedStyle(el).fontFamily.includes('Space Grotesk')));
      for (const id of ['dashboard', 'inventory', 'risk', 'roadmap', 'reports']) { await page.locator(`#${id}`).scrollIntoViewIfNeeded(); await page.screenshot({ animations: 'disabled', path: path.join(out, `${id}-${theme}-${width}.png`) }); }
      results.push({ theme, width, screen: 'workspace', ...await inspect(page) });
      const downloaded = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download HTML Report', exact: true }).click();
      const reportPath = path.join(out, `report-${theme}-${width}.html`); await (await downloaded).saveAs(reportPath);
      const offline = await browser.newContext({ offline: true, viewport: { width, height: 900 } });
      const report = await offline.newPage(); await report.goto(pathToFileURL(reportPath).href); await report.evaluate(() => document.fonts.ready);
      const offlineFonts = await inspect(report); results.push({ theme, width, screen: 'offline report', ...offlineFonts });
      assert.deepEqual([...new Set(offlineFonts.fonts.map(face => face.family.replaceAll('"', '')))].sort(), ['Space Grotesk', 'Space Mono']);
      await report.screenshot({ animations: 'disabled', path: path.join(out, `offline-report-${theme}-${width}.png`), fullPage: true }); await offline.close();
      await page.locator('.inventory-data-row').first().click();
      await page.getByRole('heading', { name: 'Will protection outlast the planning horizon?' }).waitFor(); await page.evaluate(() => document.fonts.ready);
      results.push({ theme, width, screen: 'finding', ...await inspect(page) });
      await page.screenshot({ animations: 'disabled', path: path.join(out, `finding-${theme}-${width}.png`) });
      await page.getByRole('heading', { name: 'Inspect the basis of this finding', exact: true }).scrollIntoViewIfNeeded();
      assert.ok(await page.locator('pre').first().evaluate(el => getComputedStyle(el).fontFamily.includes('Space Mono')));
      assert.ok(await page.locator('pre').first().evaluate(el => el.scrollWidth <= el.clientWidth + 2));
      await page.screenshot({ animations: 'disabled', path: path.join(out, `evidence-${theme}-${width}.png`) });
      assert.deepEqual(errors, []); assert.deepEqual(external, []);
      assert.ok(fontRequests.every(url => url.includes('/fonts/space-') && url.endsWith('.woff2')));
      await context.setOffline(true);
      assert.ok(await page.evaluate(() => document.fonts.check('400 14px "Space Grotesk"') && document.fonts.check('700 14px "Space Mono"')));
      await context.close();
    }
    fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(results, null, 2));
    const failures = results.filter(result => result.pageOverflow || result.badWeights.length || result.clipped.length || result.shifts.some(shift => shift.time < result.fontReady));
    console.log(JSON.stringify({ screens: results.length, failures, shifts: results.map(({ screen, theme, width, shifts, fontReady }) => ({ screen, theme, width, fontReady, shifts })) }, null, 2));
    assert.equal(failures.length, 0);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
