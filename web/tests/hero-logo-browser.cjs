/* eslint-disable @typescript-eslint/no-require-imports -- Standalone browser regression runner. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fixture = require('./design-fixture.cjs');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true, args: ['--disable-features=LocalNetworkAccessChecks'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1480, height: 800 } });
    await page.addInitScript(() => {
      sessionStorage.setItem('qrypton.session', 'active');
      window.logoTurns = { starts: 0, ends: 0 };
      document.addEventListener('animationstart', event => { if (event.animationName === 'qrypton-logo-spin') window.logoTurns.starts++; });
      document.addEventListener('animationend', event => { if (event.animationName === 'qrypton-logo-spin') window.logoTurns.ends++; });
    });
    await page.route('**/api/v1/**', route => {
      const endpoint = new URL(route.request().url()).pathname;
      const body = endpoint.endsWith('/dashboard') ? fixture.dashboard : endpoint.endsWith('/scans') ? [{ scan_id: 'hero-test', status: 'COMPLETED', ...fixture.posture }] : endpoint.endsWith('/session') || endpoint.endsWith('/export-preview') ? null : [];
      return route.fulfill({ status: body === null ? 404 : 200, json: body ?? {}, headers: { 'access-control-allow-origin': '*' } });
    });
    await page.goto('http://127.0.0.1:3000/login');
    const loginLogo = page.getByRole('button', { name: 'Spin QRYPTON Q symbol' });
    await loginLogo.waitFor();
    assert.equal(await page.locator('.crypto-cube-stage').count(), 0);
    assert.equal(await loginLogo.evaluate(element => element.getBoundingClientRect().width), 192);
    assert.equal(await loginLogo.locator('.qrypton-hero-float').evaluate(element => getComputedStyle(element).animationName), 'qrypton-logo-float');
    assert.deepEqual(await page.evaluate(() => window.logoTurns), { starts: 0, ends: 0 });
    await loginLogo.click();
    await loginLogo.click();
    await page.waitForFunction(() => window.logoTurns.ends === 2);
    await loginLogo.focus();
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => window.logoTurns.ends === 3);
    assert.equal(await page.locator('.qrypton-hero-spin').count(), 0);
    console.log('PASS: login Q replaces the cube at the same size; clicks and keyboard each complete a turn.');
    for (const width of [1480, 390]) {
      await page.setViewportSize({ width, height: 800 });
      await page.goto('http://127.0.0.1:3000/');
      await page.waitForFunction(() => window.logoTurns.ends === 1);
      const logo = page.getByRole('button', { name: 'Spin QRYPTON Q symbol' });
      assert.equal(await logo.locator('.qrypton-hero-float').evaluate(element => getComputedStyle(element).animationName), 'qrypton-logo-float');
      await logo.click();
      await logo.click();
      await page.waitForFunction(() => window.logoTurns.ends === 3);
      assert.deepEqual(await page.evaluate(() => window.logoTurns), { starts: 3, ends: 3 });
      await logo.focus();
      await page.keyboard.press('Enter');
      await page.waitForFunction(() => window.logoTurns.ends === 4);
      assert.equal(await page.locator('.qrypton-hero-spin').count(), 0);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      const sizes = await page.evaluate(() => ({ initial: document.querySelector('.qrypton-hero-initial').getBoundingClientRect().width, symbol: document.querySelector('.qrypton-hero-symbol').getBoundingClientRect().width }));
      console.log(width, sizes, 'PASS: opening, queued clicks and keyboard each complete one turn.');
    }
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    await page.getByRole('button', { name: 'Spin QRYPTON Q symbol' }).waitFor();
    await page.waitForFunction(() => !document.querySelector('.qrypton-hero-spin'));
    await page.getByRole('button', { name: 'Spin QRYPTON Q symbol' }).click();
    assert.deepEqual(await page.evaluate(() => window.logoTurns), { starts: 0, ends: 0 });
    assert.equal(await page.locator('.qrypton-hero-float').evaluate(element => getComputedStyle(element).animationName), 'none');
    assert.equal(await page.locator('.qrypton-hero-symbol-mark').evaluate(element => getComputedStyle(element).animationDuration), '0s');
    console.log('PASS: reduced motion has no visible rotation.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
