/* eslint-disable @typescript-eslint/no-require-imports -- Standalone runner resolves the bundled Playwright through NODE_PATH. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const fixture = require('./design-fixture.cjs');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const out = path.resolve('..', 'tmp', 'design-foundation');
  fs.mkdirSync(out, { recursive: true });
  try {
    for (const width of [1440, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      await page.goto('http://127.0.0.1:3011/dev/design-reference');
      await page.getByRole('heading', { name: 'Design reference', exact: true }).waitFor();
      await page.evaluate(() => document.fonts.ready);
      await page.waitForFunction(() => document.querySelector('[data-testid="motion-duration"]')?.textContent === '200');
      assert.equal(await page.locator('[data-risk-level="critical"]').count(), 3);
      assert.equal(await page.locator('[data-risk-level="unknown"]').first().evaluate((el) => getComputedStyle(el).borderStyle), 'dashed');
      assert.equal(await page.locator('tr[data-risk="critical"]').evaluate((el) => getComputedStyle(el).borderLeftWidth), '4px');
      assert.equal(await page.locator('tbody tr').first().evaluate((el) => el.getBoundingClientRect().height), 40);
      const fonts = await page.evaluate(() => ({ family: getComputedStyle(document.body).fontFamily, loaded: [...document.fonts].filter((font) => font.status === 'loaded').map((font) => font.family) }));
      assert.ok(fonts.loaded.some((font) => /sans|localFont|geist/i.test(font)));
      await page.getByRole('button', { name: 'Toggle confirmation' }).click();
      await page.locator('[data-testid="motion-preview"]').waitFor({ state: 'visible' });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await page.waitForFunction(() => document.querySelector('[data-testid="motion-duration"]')?.textContent === '0');
      assert.equal(await page.locator('[data-testid="motion-preview"]').evaluate((el) => getComputedStyle(el).transitionDuration), '0s');
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      await page.waitForFunction(() => document.querySelector('[data-testid="motion-duration"]')?.textContent === '200');
      await page.screenshot({ path: path.join(out, `reference-${width}.png`), fullPage: true });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Reference page overflow');
      await page.goto('http://127.0.0.1:3011/login');
      await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
      assert.equal(await page.locator('.qrypton-kicker.text-primary-foreground').evaluate((el) => getComputedStyle(el).color), await page.getByRole('button', { name: 'Sign in', exact: true }).evaluate((el) => getComputedStyle(el).color));
      await page.screenshot({ path: path.join(out, `login-${width}.png`), fullPage: true });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Login overflow');
      // Isolated browser session only. No authentication or enterprise records are modified.
      await page.evaluate(() => sessionStorage.setItem('qrypton.session', 'active'));
      await page.goto('http://127.0.0.1:3011/');
      await page.getByRole('button', { name: 'Start a new cryptographic scan' }).waitFor();
      await page.screenshot({ path: path.join(out, `dashboard-${width}.png`), fullPage: true });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Dashboard overflow');
      await page.getByRole('button', { name: 'Start a new cryptographic scan' }).click();
      await page.getByRole('dialog').waitFor();
      await page.screenshot({ path: path.join(out, `scan-dialog-${width}.png`), fullPage: true });
      await page.route('**/api/v1/**', async (route) => {
        const endpoint = new URL(route.request().url()).pathname;
        const body = endpoint.endsWith('/dashboard') ? fixture.dashboard
          : endpoint.endsWith('/posture') ? fixture.posture
          : endpoint.endsWith('/inventory') ? fixture.inventory
          : endpoint.endsWith('/roadmap') ? fixture.roadmap
          : endpoint.includes('/findings/') ? fixture.detail
          : endpoint.endsWith('/scans') ? [{ scan_id: 'visual-test', artifact: 'TEST FIXTURE ONLY', target_type: 'source_repo', environment: 'test', status: 'COMPLETED', completed_at: '2026-10-08', ...fixture.posture }] : {};
        await route.fulfill({ json: body, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': '1' } });
      });
      await page.goto('http://127.0.0.1:3011/');
      await page.locator('#inventory tbody tr[data-risk="critical"]').waitFor();
      await page.locator('#inventory').scrollIntoViewIfNeeded();
      const rowHeights = await page.locator('#inventory tbody tr').evaluateAll((rows) => rows.map((row) => row.getBoundingClientRect().height));
      assert.ok(rowHeights.every((height) => height === 40), `Inventory rows: ${rowHeights}`);
      await page.screenshot({ path: path.join(out, `inventory-${width}.png`) });
      await page.locator('#inventory tbody tr[data-risk="critical"]').click();
      await page.getByRole('heading', { name: 'Canonical finding detail' }).waitFor();
      await page.getByText('test/crypto.ts', { exact: true }).waitFor();
      await page.screenshot({ path: path.join(out, `finding-${width}.png`) });
      await page.getByRole('button', { name: 'Close', exact: true }).click();
      await page.locator('#risk').scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(out, `risk-${width}.png`) });
      const cell = page.getByRole('button', { name: '1 findings: Mosca urgency critical, business criticality high', exact: true });
      await cell.click();
      assert.equal(await page.locator('#inventory tbody tr').count(), 1);
      await page.getByRole('button', { name: 'Clear matrix filter' }).click();
      const downloaded = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download HTML Report', exact: true }).click();
      const download = await downloaded;
      const reportPath = path.join(out, `report-${width}.html`);
      await download.saveAs(reportPath);
      const report = await context.newPage();
      await report.goto(require('node:url').pathToFileURL(reportPath).href);
      assert.equal(await report.locator('[data-risk-level="critical"] svg').count(), 1);
      assert.equal(await report.locator('[data-risk-level="unknown"]').evaluate((el) => getComputedStyle(el).borderStyle), 'dashed');
      await report.close();
      assert.deepEqual(errors, []);
      console.log(JSON.stringify({ width, fonts, errors, screenshots: out }));
      await context.close();
    }
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
