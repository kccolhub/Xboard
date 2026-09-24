// This repository distributes umi.js without the original Vue project.
// Keep the integration surgical and fail loudly if the upstream bundle changes.
// Run: node scripts/patch-subscription-menu.mjs
import fs from 'node:fs';
const file = new URL('../theme/Xboard/assets/umi.js', import.meta.url);
let source = fs.readFileSync(file, 'utf8');
source = source.replace('h.value=[new URL(row.subscribeUrl).searchParams.get("types")||"auto"]', 'h.value=(new URL(row.subscribeUrl).searchParams.get("types")||"auto").split(",")');
const helper = fs.readFileSync(new URL('../theme/Xboard/assets/subscription-menu.mjs', import.meta.url), 'utf8').replace(/^export /gm, '');
const prefix = `/* compact-subscription-menu */\n${helper}\n/* end-subscription-menu */\n`;
if (source.includes('/* compact-subscription-menu */')) {
  const end = '/* end-subscription-menu */\n';
  if (source.includes(end)) source = prefix + source.slice(source.indexOf(end) + end.length);
  else source = source.replace(/^\/\* compact-subscription-menu \*\/\nimport[^\n]+\n/, prefix);
  fs.writeFileSync(file, source);
  console.log('Subscription menu helper refreshed.');
  process.exit(0);
}
function replaceOnce(before, after) {
  if (source.split(before).length !== 2) throw new Error(`Expected one integration anchor: ${before.slice(0, 100)}`);
  source = source.replace(before, after);
}
replaceOnce('d=Et(!1),p=Et("")', 'd=Et(!1),subscriptionQrBase=Et(""),subscriptionQrName=Et(""),p=Et("")');
replaceOnce('g=()=>{var e;const t=null==(e=b.value)?void 0:e.subscribe_url;', 'g=()=>{var e;const t=subscriptionQrBase.value||(null==(e=b.value)?void 0:e.subscribe_url);');
replaceOnce('C=()=>{var e;p.value=(null==(e=b.value)?void 0:e.subscribe_url)||"",d.value=!0}', 'C=row=>{subscriptionQrBase.value=row.subscribeUrl;subscriptionQrName.value=row.name;h.value=(new URL(row.subscribeUrl).searchParams.get("types")||"auto").split(",");p.value=row.subscribeUrl;u.value=!1;d.value=!0}');
const start = 'Lr(k,{hoverable:""},{default:hn((()=>{var n;return[';
const end = 'Lr(S,{class:"m-0!"})';
const from = source.indexOf(start);
const to = source.indexOf(end, from);
if (from < 0 || to < 0 || source.indexOf(start, from + 1) >= 0) throw new Error('Subscription list anchors changed');
source = source.slice(0, from) + 'renderSubscriptionMenu(Lr,{rows:subscriptionRows(y.value,b.value?.subscribe_url,r.title,O.value?.includes("hysteria2")),translate:e.$t,onImport:x,onQr:C,onCopy:row=>Xf(row.subscribeUrl)}),' + source.slice(to);
replaceOnce('class:"max-w-full w-75",bordered:!1,size:"huge","content-style":"padding:0"', 'class:"max-w-full",style:{width:"360px",maxWidth:"calc(100vw - 24px)"},bordered:!1,size:"huge","content-style":"padding:0"');
replaceOnce('Ir("div",dq,oe(e.$t("选择协议"))+":",1)', 'Ir("div",{style:{fontWeight:600,marginBottom:"12px"}},oe(subscriptionQrName.value)+" · "+oe(e.$t("扫描二维码订阅")),1),Ir("div",dq,oe(e.$t("选择协议"))+":",1)');
source = prefix + source;
fs.writeFileSync(file, source);
console.log('Integrated compact subscription menu.');
