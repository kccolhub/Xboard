import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHttpProbeStore, selectHttpProbeResult, createNodeHttpProbeComponents} from '../../public/assets/admin/node-http-probe.mjs';

test('store shares loading state and prevents duplicate requests', async () => {
  const store = createHttpProbeStore();
  let finish, changes = 0;
  const unsubscribe = store.subscribe(() => changes++);
  const first = store.run(1, () => new Promise(resolve => finish = resolve));
  assert.equal(store.get(1).pending, true);
  assert.equal(await store.run(1, assert.fail), null);
  finish({data: {status: 'success', checked_at: 100, http_status: 204}});
  await first;
  assert.equal(store.get(1).pending, false);
  assert.equal(changes, 2);
  unsubscribe();
});

test('failed request preserves previous result and allows retry', async () => {
  const store = createHttpProbeStore();
  await store.run(1, async () => ({data: {status: 'success', checked_at: 100}}));
  await assert.rejects(store.run(1, async () => {throw new Error('offline');}));
  assert.equal(store.get(1).pending, false);
  assert.equal(store.get(1).result.status, 'success');
  await store.run(1, async () => ({data: {status: 'failed', checked_at: 101}}));
  assert.equal(store.get(1).result.status, 'failed');
});

test('server result wins ties so configuration changes mark results stale', () => {
  const saved = {status: 'success', checked_at: 100, stale: true};
  assert.equal(selectHttpProbeResult({http_test: saved}, {result: {...saved, stale: false}}), saved);
  assert.equal(selectHttpProbeResult({}, {result: saved}), saved);
});

test('action uses authenticated POST with node ID and longer bounded timeout', async () => {
  const requests = [], notices = [];
  let refreshed = false;
  const jsx = (type, props) => ({type, props});
  const {Action} = createNodeHttpProbeComponents({useSyncExternalStore: (subscribe, get) => get()}, {jsx, jsxs: jsx}, {
    Item: 'menuitem', base: 'admin-fixture', post: async (...args) => {
      requests.push(args); return {data: {status: 'success', checked_at: 100, http_status: 204, latency_ms: 12}};
    }, toast: {success: message => notices.push(message), error: assert.fail},
    useTranslation: () => ({i18n: {language: 'zh-CN'}}),
  });
  await Action({node: {id: 17}, refetch: () => {refreshed = true;}}).props.onSelect({preventDefault() {}});
  assert.deepEqual(requests, [['admin-fixture/server/manage/testHttp', {id: 17}, {timeout: 25000}]]);
  assert.equal(refreshed, true);
  assert.equal(notices[0], 'HTTP 测试: 204 · 12 ms');
});

test('distributed bundle contains helper, menu action and status popover integration', () => {
  const root = new URL('../../public/assets/admin/', import.meta.url);
  const manifest = JSON.parse(fs.readFileSync(new URL('manifest.json', root)));
  const source = fs.readFileSync(new URL(manifest['index.html'].file, root), 'utf8');
  assert.ok(source.includes(fs.readFileSync(new URL('node-http-probe.mjs', root), 'utf8').replace(/^export /gm, '')));
  assert.ok(source.includes('Q.jsx(NodeHttpProbeAction,{node:e,refetch:t})'));
  assert.ok(source.includes('Q.jsx(NodeHttpProbeResult,{node:e})'));
  assert.ok(source.includes('CertificateGeneratorButton'));
  assert.ok(fs.readFileSync(new URL('index.html', root), 'utf8').includes(manifest['index.html'].file));
});
