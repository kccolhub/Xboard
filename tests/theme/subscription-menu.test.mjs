import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {subscriptionRows, subscriptionUrl, subscriptionQrValue, renderSubscriptionMenu} from '../../theme/Xboard/assets/subscription-menu.mjs';

const base = 'https://panel.example/s/test?token=example&types=trojan&flag=old';
const names = ['Clash', 'Clash Meta', 'Hiddify', 'SingBox', 'Shadowrocket', 'QuantumultX', 'Surge', 'Stash', 'NekoBox', 'Surfboard'];
const clients = names.flatMap(name => [{name, url: 'existing://import'}, {name: `复制${name}`, url: 'copy', copyFor: name}]);
const rows = subscriptionRows(clients, base, '测试 & Panel', true);

test('one row per client, plus automatic, General and optional HY2', () => {
  assert.equal(rows.length, names.length + 3);
  assert.equal(new Set(rows.map(row => row.name)).size, rows.length);
  assert.deepEqual(subscriptionRows(clients, '', ''), []);
  assert.equal(subscriptionRows(clients, base, '').length, names.length + 2);
  assert.equal(rows[0].subscribeUrl, base);
});

test('General is explicit and keeps authentication and filters', () => {
  const general = rows.find(row => row.name === 'General');
  const url = new URL(general.subscribeUrl);
  assert.equal(url.searchParams.get('flag'), 'general');
  assert.equal(url.searchParams.getAll('flag').length, 1);
  assert.equal(url.searchParams.get('token'), 'example');
  assert.equal(url.searchParams.get('types'), 'trojan');
  assert.equal(general.url, null);
  assert.equal(new URL(subscriptionUrl(general.subscribeUrl, null, 'hysteria2')).searchParams.get('flag'), 'general');
  const hy2 = rows.find(row => row.name === 'Hysteria2');
  assert.equal(new URL(hy2.subscribeUrl).searchParams.get('types'), 'hysteria2');
});

test('import links contain exactly the same subscription as QR/copy', () => {
  for (const row of rows.filter(row => row.url)) {
    const link = new URL(row.url);
    let imported;
    if (row.name === 'Shadowrocket') {
      imported = Buffer.from(link.pathname.slice('/sub://'.length), 'base64url').toString();
    } else if (row.name === 'Hiddify') {
      imported = row.url.slice('hiddify://import/'.length).split('#')[0];
    } else if (row.name === 'QuantumultX') {
      imported = JSON.parse(link.searchParams.get('remote-resource')).server_remote[0].split(', tag=')[0];
    } else imported = link.searchParams.get('url');
    assert.equal(imported, row.subscribeUrl, row.name);
    assert.notEqual(new URL(imported).searchParams.get('flag'), 'old');
  }
});

test('three accessible icon buttons per row; actions only fire their own handler', () => {
  const events = [];
  const h = (type, props, children) => ({type, props, children});
  const tree = renderSubscriptionMenu(h, {rows, onImport: row => events.push(['import', row.name]), onQr: row => events.push(['qr', row.name]), onCopy: row => events.push(['copy', row.name])});
  const list = tree.children[1].children;
  for (const row of list) {
    const buttons = row.children[1].children;
    assert.equal(buttons.length, 3);
    for (const button of buttons) {
      assert.equal(button.type, 'button');
      assert.ok(button.props['aria-label']);
      assert.equal(button.children[0].type, 'svg');
    }
  }
  const general = list.find(row => row.props['data-client'] === 'General').children[1].children;
  assert.equal(general[0].props.disabled, true);
  general.forEach(button => button.props.onClick());
  assert.deepEqual(events, [['qr', 'General'], ['copy', 'General']]);
});

test('SingBox QR exposes the remote URL to the official import-link parser', () => {
  const row = rows.find(row => row.name === 'SingBox');
  const value = subscriptionQrValue(row.name, row.subscribeUrl, '测试 & Panel');
  assert.equal(value, row.url);
  const link = new URL(value);
  assert.equal(link.protocol, 'sing-box:');
  assert.equal(link.hostname, 'import-remote-profile');
  assert.equal(link.searchParams.get('url'), row.subscribeUrl);
  assert.equal(decodeURIComponent(link.hash.slice(1)), '测试 & Panel');

  const filtered = subscriptionUrl(row.subscribeUrl, null, 'hysteria2,trojan');
  const remote = new URL(new URL(subscriptionQrValue('SingBox', filtered)).searchParams.get('url'));
  assert.equal(remote.searchParams.get('flag'), 'sing-box');
  assert.equal(remote.searchParams.get('types'), 'hysteria2,trojan');
  assert.equal(remote.searchParams.get('token'), 'example');
  assert.equal(subscriptionQrValue('SingBox', ''), '');
  for (const other of rows.filter(row => row.name !== 'SingBox')) {
    assert.equal(subscriptionQrValue(other.name, other.subscribeUrl), other.subscribeUrl);
  }
});

test('bundle embeds the current helper and hooks the existing reactive QR modal', () => {
  const bundle = fs.readFileSync(new URL('../../theme/Xboard/assets/umi.js', import.meta.url), 'utf8');
  const helper = fs.readFileSync(new URL('../../theme/Xboard/assets/subscription-menu.mjs', import.meta.url), 'utf8').replace(/^export /gm, '');
  assert.ok(bundle.includes(helper));
  assert.ok(bundle.includes('renderSubscriptionMenu(Lr,{rows:subscriptionRows(y.value'));
  assert.ok(bundle.includes('const t=subscriptionQrBase.value||'));
  assert.ok(bundle.includes('subscriptionQrBase.value=row.subscribeUrl'));
  assert.ok(bundle.includes('Lr(F,{value:subscriptionQrValue(subscriptionQrName.value,p.value,r.title),'));
  assert.ok(!bundle.includes('onClick:C}'));
});
