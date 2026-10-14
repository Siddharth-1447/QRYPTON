/* eslint-disable @typescript-eslint/no-require-imports -- Standalone browser regression runner. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fixture = require('./design-fixture.cjs');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true, args: ['--disable-features=LocalNetworkAccessChecks'] });
  try {
    const page = await browser.newPage();
    const hydrationErrors = [];
    page.on('console', message => {
      if (message.type() === 'error' && /hydrated|hydration/i.test(message.text())) hydrationErrors.push(message.text());
    });
    page.on('pageerror', error => hydrationErrors.push(error.message));
    await page.addInitScript(() => {
      window.injectedFooterAttributes = 0;
      const observer = new MutationObserver(() => {
        for (const button of document.querySelectorAll('.qrypton-tools > button')) {
          if (!button.hasAttribute('fdprocessedid')) {
            button.setAttribute('fdprocessedid', `extension-test-${++window.injectedFooterAttributes}`);
          }
        }
      });
      observer.observe(document, { childList: true, subtree: true });
      document.addEventListener('DOMContentLoaded', () => observer.disconnect(), { once: true });
    });
    const requestedRuns = [];
    let backendRecovered = false;
    await page.route('**/api/v1/**', route => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('/dashboard')) {
        requestedRuns.push(url.searchParams.get('run_id'));
        return route.fulfill({ status: backendRecovered ? 200 : 503, json: backendRecovered ? fixture.dashboard : { detail: 'Temporary outage' }, headers: { 'access-control-allow-origin': '*' } });
      }
      const body = url.pathname.endsWith('/scans') ? [{ scan_id: 'retry-test', artifact: 'Test scan', status: 'COMPLETED', ...fixture.posture }] : url.pathname.endsWith('/export-preview') ? { run_id: 'retry-test', scope: 'Test fixture', target_type: 'source_repo', asset_count: 6, finding_count: 6, risk_summary: {}, cbom_available: true, report_available: true, provenance: 'Browser fixture' } : url.pathname.endsWith('/auth/providers') ? { providers: { google: false, github: false, gitlab: false }, token_configured: false } : url.pathname.endsWith('/session') ? null : [];
      return route.fulfill({ status: body === null ? 401 : 200, json: body ?? {}, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': '1' } });
    });
    await page.goto('http://127.0.0.1:3000/login');
    await page.getByRole('button', { name: 'Continue as read-only Viewer' }).waitFor();
    await page.evaluate(() => document.fonts.ready);
    assert.equal(await page.evaluate(() => window.injectedFooterAttributes), 1);
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.getByRole('dialog', { name: 'Settings' }).waitFor();
    await page.keyboard.press('Escape');
    assert.equal(await page.getByRole('button', { name: 'Keyboard shortcuts', exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Search', exact: true }).count(), 0);
    await page.evaluate(() => sessionStorage.setItem('qrypton.session', 'active'));
    await page.goto('http://127.0.0.1:3000/');
    await page.getByRole('button', { name: 'Retry Connection', exact: true }).waitFor();
    backendRecovered = true;
    await page.getByRole('button', { name: 'Retry Connection', exact: true }).click();
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    await page.getByRole('dialog', { name: 'Command palette' }).waitFor();
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Raw table', exact: true }).click();
    await page.locator('.inventory-data-row').first().waitFor();
    assert.ok(requestedRuns.length >= 2);
    assert.ok(requestedRuns.every(id => id === 'retry-test'));
    assert.equal(await page.getByRole('button', { name: 'Retry Connection', exact: true }).count(), 0);
    assert.deepEqual(hydrationErrors, []);
    console.log('PASS: injected extension attributes hydrate; footer controls work; Retry reloads the same canonical scan.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
