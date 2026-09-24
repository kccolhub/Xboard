// Small, readable extension for the distributed Xboard theme (Vue sources are not shipped).
const formats = {
  Clash: 'clash', 'Clash Meta': 'meta', Hiddify: 'sing-box', SingBox: 'sing-box',
  Shadowrocket: 'shadowrocket', QuantumultX: 'quantumult-x', Surge: 'surge',
  Stash: 'stash', NekoBox: 'nekobox', Surfboard: 'surfboard',
};

export function subscriptionUrl(base, flag, types) {
  const url = new URL(base);
  if (flag) url.searchParams.set('flag', flag);
  if (types) url.searchParams.set('types', types);
  return url.toString();
}

function importUrl(client, url, title) {
  const encoded = encodeURIComponent(url);
  const name = encodeURIComponent(title || '订阅');
  switch (client) {
    case 'Clash': case 'Clash Meta': case 'NekoBox':
      return `clash://install-config?url=${encoded}&name=${name}`;
    case 'Hiddify': return `hiddify://import/${url}#${name}`;
    case 'SingBox': return `sing-box://import-remote-profile?url=${encoded}#${name}`;
    case 'Shadowrocket': {
      const base64 = btoa(unescape(encodeURIComponent(url)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      return `shadowrocket://add/sub://${base64}?remark=${name}`;
    }
    case 'QuantumultX':
      return `quantumult-x:///update-configuration?remote-resource=${encodeURIComponent(JSON.stringify({server_remote: [`${url}, tag=${title || '订阅'}`]}))}`;
    case 'Surge': return `surge:///install-config?url=${encoded}&name=${name}`;
    case 'Stash': return `stash://install-config?url=${encoded}&name=${name}`;
    case 'Surfboard': return `surfboard:///install-config?url=${encoded}&name=${name}`;
    default: return null;
  }
}

export function subscriptionRows(clients, base, title, hasHy2 = false) {
  if (!base) return [];
  const rows = [
    {name: '自动识别', subscribeUrl: base, url: null},
    {name: 'General', subscribeUrl: subscriptionUrl(base, 'general'), url: null},
  ];
  const seen = new Set();
  for (const client of clients) {
    if (client.url === 'copy' || seen.has(client.name)) continue;
    seen.add(client.name);
    const url = subscriptionUrl(base, formats[client.name]);
    rows.push({...client, subscribeUrl: url, url: importUrl(client.name, url, title)});
  }
  if (hasHy2) rows.push({name: 'Hysteria2', subscribeUrl: subscriptionUrl(base, 'general', 'hysteria2'), url: null});
  return rows;
}

const paths = {
  import: ['M14 3h7v7', 'M10 14 21 3', 'M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5'],
  qr: ['M3 3h6v6H3z', 'M15 3h6v6h-6z', 'M3 15h6v6H3z', 'M15 15h2v2h-2z', 'M21 15v3h-3v3h3', 'M12 3v3m0 6h3m-3 3v6'],
  copy: ['M9 9h12v12H9z', 'M15 6V3H3v12h3'],
  link: ['M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2', 'M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2'],
};

export const menuCss = `
.subscription-actions{width:100%;padding:8px;box-sizing:border-box}
.subscription-actions__heading,.subscription-actions__row{display:flex;align-items:center;gap:8px}
.subscription-actions__heading{padding:4px 4px 8px;font-size:11px;opacity:.65}
.subscription-actions__name{flex:1;min-width:0;display:flex;align-items:center;gap:9px;font-size:14px}
.subscription-actions__label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.subscription-actions__heading .subscription-actions__name{font-size:12px}
.subscription-actions__columns,.subscription-actions__buttons{display:flex;gap:4px;flex-shrink:0}
.subscription-actions__columns span{width:36px;text-align:center}
.subscription-actions__list{max-height:min(65vh,520px);overflow-y:auto;overscroll-behavior:contain}
.subscription-actions__row{padding:3px 4px;border-radius:7px;min-height:40px}
.subscription-actions__row:hover{background:rgba(128,128,128,.08)}
.subscription-actions__logo{height:26px;width:26px;object-fit:contain;border-radius:5px;flex-shrink:0}
.subscription-actions__button{display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;padding:8px;box-sizing:border-box;border:0;border-radius:7px;background:transparent;color:inherit;cursor:pointer;touch-action:manipulation}
.subscription-actions__button:hover:not(:disabled){background:rgba(128,128,128,.18)}
.subscription-actions__button:focus-visible{outline:2px solid currentColor;outline-offset:1px}
.subscription-actions__button:disabled{opacity:.25;cursor:not-allowed}
.subscription-actions svg{display:block;width:20px;height:20px;flex-shrink:0}
`;

export function renderSubscriptionMenu(h, {rows, translate, onImport, onQr, onCopy}) {
  if (typeof document !== 'undefined' && !document.getElementById('subscription-actions-style')) {
    const style = document.createElement('style');
    style.id = 'subscription-actions-style';
    style.textContent = menuCss;
    document.head.append(style);
  }
  const t = translate || (text => text);
  const icon = kind => h('svg', {viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true'}, paths[kind].map(d => h('path', {d})));
  const button = (kind, label, row, action, disabled = false) => h('button', {
    type: 'button', class: 'subscription-actions__button', disabled,
    title: label, 'aria-label': label, 'data-action': kind,
    onClick: () => { if (!disabled) action(row); },
  }, [icon(kind)]);
  return h('div', {class: 'subscription-actions'}, [
    h('div', {class: 'subscription-actions__heading', 'aria-hidden': 'true'}, [
      h('span', {class: 'subscription-actions__name'}, t('订阅')),
      h('div', {class: 'subscription-actions__columns'}, ['导入', '二维码', '复制'].map(label => h('span', null, t(label)))),
    ]),
    h('div', {class: 'subscription-actions__list'}, rows.map(row => h('div', {class: 'subscription-actions__row', key: row.name, 'data-client': row.name}, [
      h('div', {class: 'subscription-actions__name'}, [
        row.iconType === 'img' ? h('img', {src: row.icon, alt: '', class: 'subscription-actions__logo'}) : icon('link'),
        h('span', {class: 'subscription-actions__label'}, t(row.name)),
      ]),
      h('div', {class: 'subscription-actions__buttons'}, [
        button('import', row.url ? `${t('导入到')} ${row.name}` : `${row.name}: ${t('通用格式，请在客户端中粘贴链接或扫码导入')}`, row, onImport, !row.url),
        button('qr', `${row.name}: ${t('扫描二维码订阅')}`, row, onQr),
        button('copy', `${row.name}: ${t('复制订阅地址')}`, row, onCopy),
      ]),
    ]))),
  ], 16);
}
