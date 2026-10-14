/* eslint-disable @typescript-eslint/no-require-imports -- Standalone browser regression runner. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fixture = require('./design-fixture.cjs');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true, args: ['--disable-features=LocalNetworkAccessChecks'] });
  try {
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    let authConfigured = false;
    let dashboardReads = 0, releaseDashboard;
    const pendingDashboard = new Promise(resolve => { releaseDashboard = resolve; });
    await page.route('**/api/v1/**', async route => {
      const endpoint = new URL(route.request().url()).pathname;
      let status = 200, body = [];
      if (endpoint.endsWith('/auth/providers')) body = { providers: { google: authConfigured, github: authConfigured, gitlab: false }, token_configured: authConfigured };
      else if (endpoint.endsWith('/auth/exchange')) {
        assert.equal(route.request().postDataJSON().verifier, 'v'.repeat(64));
        body = { access_token: 'test-oauth-session', subject: 'gitlab:42', role: 'Viewer', email: 'analyst@example.test' };
      }
      else if (endpoint.endsWith('/start')) { status = 503; body = { detail: 'Provider requires administrator OAuth configuration.' }; assert.equal(route.request().postDataJSON().challenge.length, 43); }
      else if (endpoint.endsWith('/session')) {
        const verified = route.request().headers().authorization === 'Bearer test-admin-token';
        status = verified ? 200 : 401; body = verified ? { subject: 'test-admin', role: 'Security Engineer' } : { detail: 'Invalid token' };
      } else if (endpoint.endsWith('/dashboard')) { dashboardReads++; await pendingDashboard; body = fixture.dashboard; }
      else if (endpoint.endsWith('/scans')) body = [{ scan_id: 'login-test', status: 'COMPLETED', ...fixture.posture }];
      else if (endpoint.endsWith('/export-preview')) { status = 404; body = {}; }
      return route.fulfill({ status, json: body, headers: { 'access-control-allow-origin': '*', 'X-Total-Count': '1' } });
    });
    fs.mkdirSync('../tmp/login-refresh', { recursive: true });
    for (const width of [1480, 1280, 390]) for (const theme of ['dark', 'light']) {
      await page.setViewportSize({ width, height: 800 });
      await page.goto('http://127.0.0.1:3000/login');
      await page.evaluate(theme => { localStorage.setItem('qrypton.theme', theme); document.documentElement.dataset.resolvedTheme = theme; }, theme);
      await page.getByRole('button', { name: 'Continue as read-only Viewer' }).waitFor();
      await page.evaluate(() => document.fonts.ready);
      await page.waitForFunction(() => {
        const settings = document.querySelector('button[aria-label="Settings"]');
        return settings && Object.keys(settings).some(key => key.startsWith('__reactProps'));
      });
      assert.equal(await page.locator('input[name="scan-scope"]').count(), 0);
      assert.equal(await page.getByText('Secure sign in', { exact: true }).count(), 0);
      assert.equal(await page.getByRole('button', { name: 'Search', exact: true }).count(), 0);
      assert.equal(await page.getByRole('button', { name: 'Keyboard shortcuts', exact: true }).count(), 0);
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await page.getByRole('dialog', { name: 'Settings' }).waitFor(); await page.keyboard.press('Escape');
      assert.equal(await page.getByLabel('Workspace Access Token', { exact: true }).count(), 0);
      assert.equal(await page.getByRole('button', { name: 'Sign in with Google' }).count(), 1);
      assert.equal(await page.getByRole('button', { name: 'Sign in with GitLab' }).count(), 0);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await page.screenshot({ path: `../tmp/login-refresh/login-${width}-${theme}.png`, fullPage: true });
    }
    await page.setViewportSize({ width: 1480, height: 800 });
    authConfigured = true;
    await page.reload();
    await page.getByRole('button', { name: 'Use a workspace access token' }).click();
    const google = await page.getByRole('button', { name: 'Sign in with Google' }).locator('path').first().evaluate(element => getComputedStyle(element).fill);
    assert.equal(google, 'rgb(66, 133, 244)');
    assert.equal(await page.getByRole('button', { name: 'Sign in with GitLab' }).count(), 0);
    await page.locator('form').getByRole('button', { name: 'Sign In', exact: true }).click();
    assert.equal(await page.locator('#email').evaluate(element => element.validity.valid), false);
    await page.getByLabel('Email Address', { exact: true }).fill('admin@example.test');
    await page.getByLabel('Workspace Access Token', { exact: true }).fill('invalid-test-token');
    await page.locator('form').getByRole('button', { name: 'Sign In', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'This token is invalid' }).waitFor();
    for (const provider of ['Google', 'GitHub']) {
      await page.getByRole('button', { name: `Sign in with ${provider}` }).click();
      await page.getByRole('alert').filter({ hasText: 'administrator OAuth configuration' }).waitFor();
    }
    await page.getByLabel('Workspace Access Token', { exact: true }).fill('test-admin-token');
    await page.locator('form').getByRole('button', { name: 'Sign In', exact: true }).click();
    await page.getByRole('heading', { name: 'Start with Your Workspace’s Security Posture' }).waitFor();
    assert.equal(await page.evaluate(() => sessionStorage.getItem('qrypton.role')), 'Security Engineer');
    await page.getByRole('button', { name: 'Open command center' }).click();
    await page.getByRole('button', { name: 'Spin QRYPTON Q symbol' }).waitFor();
    await page.getByTitle('Hello, Admin').waitFor();
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.getByRole('button', { name: 'Logout' }).waitFor();
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => document.body.textContent.includes('Loading canonical assessment data'));
    assert.equal(dashboardReads, 1);
    releaseDashboard();
    await page.getByRole('button', { name: 'Raw table', exact: true }).click();
    await page.locator('.inventory-data-row').first().waitFor();
    await page.locator('#results-quick-export').getByRole('heading', { name: 'Latest Scan — Quick Export' }).waitFor();
    assert.equal(await page.locator('#your-scans').getByRole('heading', { name: 'Latest Scan — Quick Export' }).count(), 0);
    await page.getByRole('button', { name: 'Bar Graph' }).click();
    assert.equal(await page.locator('#risk [aria-label="Findings by quantum urgency"] > button').count(), 6);
    await page.locator('#risk button[data-urgency="critical"]').click();
    assert.equal(await page.locator('#risk button[data-urgency="critical"]').getAttribute('aria-pressed'), 'true');
    await page.locator('#risk').getByText('1 matching findings', { exact: false }).waitFor();
    await page.screenshot({ path: '../tmp/login-refresh/dashboard-risk-1480.png' });
    const logoColors = await page.evaluate(() => {
      const polygon = document.querySelector('aside[aria-label="Primary"] svg polygon');
      document.documentElement.dataset.resolvedTheme = 'light';
      const light = getComputedStyle(polygon).stroke;
      document.documentElement.dataset.resolvedTheme = 'dark';
      return { light, dark: getComputedStyle(polygon).stroke };
    });
    assert.deepEqual(logoColors, { light: 'rgb(124, 149, 255)', dark: 'rgb(124, 149, 255)' });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: '../tmp/login-refresh/dashboard-hero-1480.png' });
    await page.getByRole('button', { name: 'Show navigation icons only' }).click();
    assert.equal(await page.locator('aside[aria-label="Primary"]').evaluate(el => el.getBoundingClientRect().width), 72);
    assert.equal(await page.locator('aside[aria-label="Primary"] nav button').count(), 9);
    assert.equal(await page.locator('aside[aria-label="Primary"] nav span.truncate').count(), 0);
    assert.equal(await page.locator('.qrypton-tools').evaluate(el => el.getBoundingClientRect().right <= 72), true);
    await page.getByRole('button', { name: 'Expand navigation' }).click();
    assert.equal(await page.locator('aside[aria-label="Primary"]').evaluate(el => el.getBoundingClientRect().width), 304);
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    await page.getByRole('dialog', { name: 'Command palette' }).waitFor(); await page.keyboard.press('Escape');
    assert.equal(await page.getByRole('button', { name: 'Keyboard shortcuts', exact: true }).count(), 0);
    await page.evaluate(() => sessionStorage.setItem('qrypton.oauth-verifier', 'v'.repeat(64)));
    await page.goto('http://127.0.0.1:3000/login#auth_code=test-browser-bound-handoff');
    await page.getByRole('heading', { name: 'Start with Your Workspace’s Security Posture' }).waitFor();
    assert.equal(await page.evaluate(() => window.location.hash), '');
    assert.equal(await page.evaluate(() => sessionStorage.getItem('qrypton.oauth-verifier')), null);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('qrypton.role')), 'Viewer');
    assert.equal(await page.evaluate(() => sessionStorage.getItem('qrypton.email')), 'analyst@example.test');
    assert.deepEqual(errors, []);
    console.log('PASS: six responsive theme views, unavailable auth controls hidden, token validation, provider handling, greeting, Settings, and immediate dashboard shell.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
