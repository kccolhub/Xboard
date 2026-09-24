// Run with PLAYWRIGHT_MODULE pointing to an externally installed playwright/index.mjs.
import fs from 'node:fs';
import http from 'node:http';
import assert from 'node:assert/strict';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = new URL('../../public/assets/admin/', import.meta.url);
const node = {id: 17, name: 'racknerd-test', type: 'hysteria', host: '192.0.2.1', port: '443', server_port: 443,
  show: true, enabled: true, group_ids: ['1'], groups: [{id: 1, name: 'Test'}], rate: 1, available_status: 1,
  online: 0, u: 0, d: 0, parent: null, tags: [], protocol_settings: {version: 2}, http_test: null,
  load_status: {cpu: 0, mem: {used: 423000000, total: 2060000000}, disk: {used: 3500000000, total: 36000000000}},
  metrics: {uptime: 250000, active_connections: 0, active_users: 0, total_users: 1, goroutines: 50, ws: {enabled: true, connected: true}, kernel_status: true}};
let calls = 0, nextStatus = 'success', finish;
const apiRequests = [];
const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  if (path.startsWith('/api/')) {
    apiRequests.push(path);
    let data = {};
    if (path.endsWith('/getNodes')) data = [node];
    else if (path.endsWith('/testHttp')) {
      calls++;
      let body = ''; for await (const chunk of req) body += chunk;
      assert.equal(JSON.parse(body).id, 17); assert.equal(req.method, 'POST');
      await new Promise(resolve => finish = resolve);
      data = node.http_test = {status: nextStatus, http_status: nextStatus === 'success' ? 204 : null,
        latency_ms: nextStatus === 'success' ? 138 : null, checked_at: Math.floor(Date.now() / 1000),
        target: 'https://www.gstatic.com/generate_204', source: 'panel', stale: false,
        message: nextStatus === 'success' ? '代理 HTTPS 请求成功。' : '代理连接或 HTTPS 请求超时。'};
    } else if (path.endsWith('/user/info')) data = {id: 1, email: 'test@example.com', is_admin: true};
    else if (path.endsWith('/fetch') || path.endsWith('/getMenus') || path.endsWith('/getPlugins')) data = [];
    res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({data}));
  }
  if (path === '/settings.js' || path === '/settings.local.js') {
    res.setHeader('Content-Type', 'text/javascript');
    return res.end('window.settings={base_url:"/",secure_path:"admin-fixture",title:"Test panel",version:"test",logo:""};');
  }
  if (/^\/(assets|locales)\/[a-zA-Z0-9_.-]+$/.test(path)) {
    const file = new URL(path.slice(1), root);
    if (fs.existsSync(file)) {
      res.setHeader('Content-Type', path.endsWith('.css') ? 'text/css' : 'text/javascript');
      return res.end(fs.readFileSync(file));
    }
  }
  res.setHeader('Content-Type', 'text/html'); res.end(fs.readFileSync(new URL('index.html', root)));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser, page;
const errors = [];
try {
  browser = await chromium.launch({channel: 'chrome', headless: true});
  page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
  await page.addInitScript(() => {
    localStorage.setItem('XBOARD_ACCESS_TOKEN', JSON.stringify({value: 'fixture-token', time: Date.now(), expire: null}));
    localStorage.setItem('i18nextLng', 'zh-CN'); localStorage.setItem('vite-ui-theme', 'dark');
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/#/server/manage`);
  const row = page.getByRole('row').filter({hasText: 'racknerd-test'});
  await row.waitFor({timeout: 15000});
  const openStatus = async () => {
    await row.locator('span.rounded-full.cursor-pointer').first().hover();
    await page.getByTestId('node-http-result').first().waitFor();
    await page.waitForFunction(() => {
      const element = document.querySelector('[data-radix-popper-content-wrapper]:has([data-testid="node-http-result"])');
      if (!element) return false;
      const rect = element.getBoundingClientRect();
      return rect.x >= 0 && rect.y >= 0 && rect.bottom <= innerHeight;
    });
  };
  await openStatus();
  assert.match(await page.getByTestId('node-http-result').first().innerText(), /未测试/);
  await page.mouse.move(0, 0);
  await row.getByRole('button', {name: '操作', exact: true}).click();
  await page.getByTestId('node-http-test').click();
  await page.waitForFunction(() => document.body.innerText.includes('正在测试…'));
  assert.equal(calls, 1);
  assert.equal(await page.getByTestId('node-http-test').getAttribute('data-disabled'), '');
  finish();
  await page.getByText('HTTP 测试: 204 · 138 ms', {exact: true}).waitFor();
  await page.keyboard.press('Escape');
  await openStatus();
  assert.match(await page.getByTestId('node-http-result').first().innerText(), /HTTP 204 · 138 ms/);
  await page.screenshot({path: '/tmp/xboard-node-http-success.png', animations: 'disabled'});
  await page.reload();
  await row.waitFor(); await openStatus();
  assert.match(await page.getByTestId('node-http-result').first().innerText(), /HTTP 204/);
  await page.mouse.move(0, 0);
  nextStatus = 'failed';
  await row.getByRole('button', {name: '操作', exact: true}).click();
  await page.getByTestId('node-http-test').click();
  await page.waitForFunction(() => document.body.innerText.includes('正在测试…'));
  assert.equal(calls, 2); finish();
  await page.getByText('HTTP 测试: 代理连接或 HTTPS 请求超时。', {exact: true}).waitFor();
  await page.keyboard.press('Escape'); await openStatus();
  assert.match(await page.getByTestId('node-http-result').first().innerText(), /失败/);
  await page.screenshot({path: '/tmp/xboard-node-http-failed.png', animations: 'disabled'});
  node.http_test.stale = true;
  await page.reload(); await row.waitFor(); await openStatus();
  assert.match(await page.getByTestId('node-http-result').first().innerText(), /历史结果/);
  assert.deepEqual(errors, []);
  console.log('Admin browser passed: menu, pending/disabled state, success, failure, refresh persistence, stale result.');
} catch (error) {
  console.error({errors, apiRequests, body: await page?.locator('body').innerText()});
  await page?.screenshot({path: '/tmp/xboard-node-http-debug.png'});
  console.error(error.message);
  throw error;
} finally {
  finish?.(); await browser?.close(); await new Promise(resolve => server.close(resolve));
}
