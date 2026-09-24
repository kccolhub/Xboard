// Optional browser smoke test: install Playwright externally, then run this file.
// PLAYWRIGHT_MODULE may point at an absolute Playwright index.mjs; no live account is used.
import http from 'node:http';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const {default: decodeQr} = await import(process.env.JSQR_MODULE || 'jsqr');
const bundle = fs.readFileSync(new URL('../../theme/Xboard/assets/umi.js', import.meta.url));
const subscription = {subscribe_url: 'https://panel.example/s/test?token=fixture', plan_id: 1, plan: {name: 'Test plan'}, transfer_enable: 107374182400, u: 0, d: 0, expired_at: 2000000000};
const server = http.createServer((req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  if (path === '/assets/umi.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(bundle); }
  if (path.startsWith('/api/')) {
    const data = path.endsWith('/user/info') ? {...subscription, email: 'test@example.com', uuid: 'fixture', balance: 0}
      : path.endsWith('/user/getSubscribe') ? subscription
      : path.endsWith('/user/getStat') ? [0, 0, 0]
      : path.endsWith('/user/server/fetch') ? [{type: 'hysteria', version: 2}, {type: 'trojan'}]
      : path.endsWith('/notice/fetch') ? [] : {};
    res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({data}));
  }
  res.setHeader('Content-Type', 'text/html');
  res.end(`<!doctype html><html lang="zh-CN"><meta name="viewport" content="width=device-width,initial-scale=1"><body><script>window.routerBase='/';window.settings={title:'Test panel',theme:{color:'default'},assets_path:'/assets',version:'test',background_url:'',description:'',logo:'',i18n:['zh-CN']};</script><div id="app"></div><script type="module" src="/assets/umi.js"></script></body></html>`);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({channel: 'chrome', headless: true});
  const context = await browser.newContext({viewport: {width: 1100, height: 850}, userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'});
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
  await page.addInitScript(() => {
    localStorage.setItem('VUE_NAIVE_ACCESS_TOKEN', JSON.stringify({value: 'test', time: Date.now(), expire: null}));
    window.testCopies = [];
    Object.defineProperty(navigator, 'clipboard', {value: {writeText: async value => window.testCopies.push(value)}});
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/#/dashboard`);
  await page.addStyleTag({content: '*,*::before,*::after{transition-duration:0s!important;animation-duration:0s!important}'});
  const qrValue = async () => {
    const pixels = await page.locator('canvas').evaluate(canvas => {
      const {data, width, height} = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
      return {data: Array.from(data), width, height};
    });
    return decodeQr(Uint8ClampedArray.from(pixels.data), pixels.width, pixels.height)?.data;
  };
  await page.getByText('一键订阅', {exact: true}).click({timeout: 15000});
  const menu = page.locator('.subscription-actions');
  await menu.waitFor();
  assert.equal(await menu.locator('[data-client="General"]').count(), 1);
  const general = menu.locator('[data-client="General"]');
  assert.ok(await general.locator('[data-action="import"]').isDisabled());
  await general.locator('[data-action="copy"]').click();
  assert.equal(new URL((await page.evaluate(() => window.testCopies)).at(-1)).searchParams.get('flag'), 'general');
  await page.screenshot({path: '/tmp/xboard-subscription-desktop.png'});
  await general.locator('[data-action="qr"]').click();
  await page.getByText('General · 扫描二维码订阅', {exact: true}).waitFor();
  assert.ok(await page.locator('canvas').count() > 0);
  assert.equal(await qrValue(), (await page.evaluate(() => window.testCopies)).at(-1));
  await page.keyboard.press('Escape');
  await page.getByText('一键订阅', {exact: true}).click();
  await menu.locator('[data-client="SingBox"] [data-action="qr"]').click();
  await page.getByText('SingBox · 扫描二维码订阅', {exact: true}).waitFor();
  assert.equal(new URL(await qrValue()).searchParams.get('flag'), 'sing-box');
  await page.getByText('Hy2', {exact: true}).click();
  assert.equal(new URL(await qrValue()).searchParams.get('flag'), 'sing-box');
  assert.equal(new URL(await qrValue()).searchParams.get('types'), 'hysteria2');
  await page.screenshot({path: '/tmp/xboard-subscription-qr.png'});
  await page.keyboard.press('Escape');
  await page.setViewportSize({width: 320, height: 640});
  await page.getByText('一键订阅', {exact: true}).click();
  await menu.waitFor();
  const bounds = await menu.boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 320, JSON.stringify(bounds));
  const overflow = await menu.evaluate(element => element.scrollWidth > element.clientWidth);
  assert.equal(overflow, false);
  await page.screenshot({path: '/tmp/xboard-subscription-mobile.png'});
  await page.emulateMedia({colorScheme: 'dark'});
  await page.waitForFunction(() => document.documentElement.classList.contains('dark'));
  await page.screenshot({path: '/tmp/xboard-subscription-dark.png'});
  const android = await browser.newContext({viewport: {width: 393, height: 780}, userAgent: 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0.0.0 Mobile Safari/537.36', storageState: await context.storageState(), colorScheme: 'dark'});
  const androidPage = await android.newPage();
  androidPage.on('pageerror', error => errors.push(error.message));
  await androidPage.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
  await androidPage.goto(`http://127.0.0.1:${server.address().port}/#/dashboard`);
  await androidPage.addStyleTag({content: '*,*::before,*::after{transition-duration:0s!important;animation-duration:0s!important}'});
  await androidPage.getByText('一键订阅', {exact: true}).click();
  await androidPage.locator('.subscription-actions').waitFor();
  await androidPage.waitForFunction(() => {
    let element = document.querySelector('.subscription-actions');
    if (!element) return false;
    while (element) {
      if (Number(getComputedStyle(element).opacity) < 1) return false;
      element = element.parentElement;
    }
    return true;
  });
  assert.deepEqual(await androidPage.locator('[data-client]').evaluateAll(elements => elements.map(element => element.dataset.client)), ['自动识别', 'General', 'Clash Meta', 'Hiddify', 'SingBox', 'NekoBox', 'Surfboard', 'Hysteria2']);
  await androidPage.screenshot({path: '/tmp/xboard-subscription-android.png'});
  assert.deepEqual(errors, []);
  console.log('Browser checks passed: General copy, decoded QR formats/filtering, desktop/320px/dark/Android layouts, no runtime errors.');
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
