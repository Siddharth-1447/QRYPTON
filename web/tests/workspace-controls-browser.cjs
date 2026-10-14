/* eslint-disable @typescript-eslint/no-require-imports -- Standalone browser checks. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fixture = require('./design-fixture.cjs');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true, args: ['--disable-features=LocalNetworkAccessChecks'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1480, height: 800 }, acceptDownloads: true });
    const errors = [], exports = [];
    page.on('pageerror', error => errors.push(error.message));
    const choices = [
      { id: 'current', asset_id: 'payments', target: 'Payments', timestamp: '2026-10-12T10:00:00Z' },
      { id: 'baseline', asset_id: 'payments', target: 'Payments', timestamp: '2026-10-11T10:00:00Z' },
      { id: 'other', asset_id: 'other', target: 'Other app', timestamp: '2026-10-10T10:00:00Z' },
    ];
    await page.route('**/api/v1/**', async route => {
      const url = new URL(route.request().url()), path = url.pathname;
      let status = 200, body = [];
      if (path.endsWith('/auth/providers')) body = { providers: { google: false, github: false }, token_configured: false };
      else if (path.endsWith('/auth/signin')) { status = 401; body = { detail: 'Account not found or password incorrect. Check your details or create an account.' }; }
      else if (path.endsWith('/auth/signup')) { status = 201; body = { access_token: 'test-session', subject: 'account:test', email: 'analyst@example.test', role: 'Viewer' }; }
      else if (path.endsWith('/start')) { status = 503; body = { detail: 'Provider needs administrator OAuth configuration.' }; }
      else if (path.endsWith('/session')) body = { subject: 'account:test', role: 'Viewer' };
      else if (path.endsWith('/dashboard')) body = fixture.dashboard;
      else if (path.endsWith('/scan-comparison/options')) body = choices;
      else if (path.endsWith('/scan-comparison')) {
        assert.equal(url.searchParams.get('before'), 'baseline'); assert.equal(url.searchParams.get('after'), 'current');
        body = { risk_before: 100, risk_after: 60, risk_measure: 'Recorded risk', unscored: [0, 0], categories: { New: [], Resolved: [], Changed: [], Persistent: [] } };
      } else if (path.endsWith('/scans') && route.request().method() === 'POST') body = { scan_id: 'new-scan', status: 'COMPLETED', exit_code: 0 };
      else if (path.endsWith('/scans')) body = [{ scan_id: 'current', status: 'COMPLETED', artifact: 'Payments', ...fixture.posture }];
      else if (path.endsWith('/scan-context')) body = { context: null };
      else if (path.endsWith('/export-preview')) { status = 404; body = {}; }
      else if (path.endsWith('/report/pdf') || path.endsWith('/cbom/export')) {
        exports.push(url.href);
        return route.fulfill({ status: 200, contentType: 'application/octet-stream', body: 'test-only-export', headers: { 'access-control-allow-origin': '*' } });
      }
      await route.fulfill({ status, json: body, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': '1' } });
    });
    await page.goto('http://127.0.0.1:3000/login');
    await page.getByLabel('Email Address', { exact: true }).fill('analyst@example.test');
    await page.getByLabel('Password', { exact: true }).fill('test account password');
    await page.locator('form').getByRole('button', { name: 'Sign In', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Account not found' }).waitFor();
    await page.getByRole('button', { name: 'Create an account', exact: true }).click();
    await page.getByLabel('Password', { exact: true }).fill('test account password');
    await page.getByLabel('Confirm Password', { exact: true }).fill('test account password');
    await page.locator('form').getByRole('button', { name: 'Create Account', exact: true }).click();
    await page.getByRole('button', { name: 'Open command center' }).click();
    await page.getByTitle('Hello, Analyst').waitFor();
    const sidebar = page.locator('aside[aria-label="Primary"]');
    assert.equal(await sidebar.evaluate(el => el.getBoundingClientRect().width), 304);
    const tagline = sidebar.getByText('Before the math changes.');
    assert.equal(await tagline.evaluate(el => el.scrollWidth <= el.clientWidth), true);
    const resize = page.getByRole('separator', { name: 'Resize navigation' });
    const bounds = await resize.boundingBox();
    await page.mouse.move(bounds.x + bounds.width / 2, 200); await page.mouse.down(); await page.mouse.move(bounds.x + bounds.width / 2 + 64, 200, { steps: 8 }); await page.mouse.up();
    assert.equal(await sidebar.evaluate(el => el.getBoundingClientRect().width), 368);
    await resize.focus(); await page.keyboard.press('ArrowLeft');
    assert.equal(await sidebar.evaluate(el => el.getBoundingClientRect().width), 352);
    const findings = page.locator('[aria-labelledby="risk-findings-heading"]');
    await findings.locator('article').first().waitFor();
    assert.equal(await findings.locator('article').count(), 5);
    await findings.getByRole('button', { name: 'Next', exact: true }).click();
    assert.equal(await findings.locator('article').count(), 1);
    await findings.getByRole('button', { name: 'Previous', exact: true }).click();
    assert.equal(await findings.locator('article').count(), 5);
    const filters = page.getByRole('button', { name: 'Inventory Filters', exact: true });
    await filters.click(); await page.waitForFunction(() => !document.querySelector('[aria-label="Inventory filters"]'));
    await filters.click(); await page.getByLabel('Search cryptographic inventory').waitFor();
    const comparison = page.locator('#scan-comparison');
    await comparison.getByRole('button', { name: 'About scan comparison' }).click();
    await page.locator('#comparison-help').waitFor();
    assert.equal(await comparison.getByLabel('Baseline', { exact: true }).inputValue(), 'baseline');
    assert.equal(await comparison.getByLabel('Current', { exact: true }).locator('option').count(), 2);
    await comparison.getByRole('button', { name: 'Compare scans' }).click();
    await comparison.getByText('Recorded risk', { exact: false }).waitFor();
    await comparison.getByLabel('Baseline', { exact: true }).selectOption('other');
    assert.equal(await comparison.getByLabel('Current', { exact: true }).locator('option').count(), 1);
    assert.equal(await comparison.getByText('Recorded risk', { exact: false }).count(), 0);
    await page.getByRole('button', { name: 'Start a new cryptographic scan', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Continue', exact: false }).click();
    await dialog.getByPlaceholder('https://github.com/org/repo, https://gitlab.com/group/repo, or https://bitbucket.org/owner/repo').fill('https://github.com/example/payments');
    await dialog.getByRole('button', { name: 'Continue', exact: false }).click();
    await dialog.getByRole('button', { name: 'Continue', exact: false }).click();
    await dialog.getByLabel('Download reports when this scan finishes').check();
    await dialog.getByLabel('Report Format').selectOption('all');
    await dialog.getByRole('button', { name: 'Start scan', exact: true }).click();
    await dialog.getByRole('button', { name: 'Show Results', exact: false }).waitFor();
    assert.equal(exports.length, 3);
    assert.ok(exports.every(url => url.includes('/scans/new-scan/')));
    fs.mkdirSync('../tmp/workspace-controls', { recursive: true });
    await page.screenshot({ path: '../tmp/workspace-controls/scan-downloads.png' });
    assert.deepEqual(errors, []);
    console.log('PASS: account flow, full tagline, mouse/keyboard resizing, five-item pagination, disclosures, valid comparison pairs, and three scan-bound downloads.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
