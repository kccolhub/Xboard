// Apply to the distributed React bundle, preserving existing admin customizations.
import fs from 'node:fs';
import crypto from 'node:crypto';
const root = new URL('../public/assets/admin/', import.meta.url);
const manifest = JSON.parse(fs.readFileSync(new URL('manifest.json', root), 'utf8'));
const oldFile = manifest['index.html'].file;
let source = fs.readFileSync(new URL(oldFile, root), 'utf8');
const helper = fs.readFileSync(new URL('node-http-probe.mjs', root), 'utf8').replace(/^export /gm, '');
const start = '/* xboard-node-http-probe */\n', end = '/* end-xboard-node-http-probe */\n';
const prefix = start + helper + '\n' + end;
function replaceOnce(before, after) {
  if (source.split(before).length !== 2) throw new Error(`Admin integration anchor changed: ${before.slice(0, 90)}`);
  source = source.replace(before, after);
}
if (source.startsWith(start)) {
  if (!source.includes(end)) throw new Error('HTTP probe helper marker is incomplete');
  source = prefix + source.slice(source.indexOf(end) + end.length);
} else {
  replaceOnce('function B5t({node:e,refetch:t,t:n})', 'const {Action:NodeHttpProbeAction,Result:NodeHttpProbeResult}=createNodeHttpProbeComponents(H,Q,{Item:$st,post:RL,base:UL,toast:gE,useTranslation:()=>jy("server")});function B5t({node:e,refetch:t,t:n})');
  replaceOnce('Q.jsxs(Ust,{align:"end",className:"w-40",children:[Q.jsx($st,', 'Q.jsxs(Ust,{align:"end",className:"w-40",children:[Q.jsx(NodeHttpProbeAction,{node:e,refetch:t}),Q.jsx($st,');
  replaceOnce('z5t=({node:e,t:t})=>Q.jsxs("div",{className:"space-y-3",children:[', 'z5t=({node:e,t:t})=>Q.jsxs("div",{className:"space-y-3",children:[Q.jsx(NodeHttpProbeResult,{node:e}),');
  source = prefix + source;
}
const newFile = 'assets/index-http-probe-' + crypto.createHash('sha256').update(source).digest('hex').slice(0, 12) + '.js';
fs.writeFileSync(new URL(newFile, root), source);
manifest['index.html'].file = newFile;
fs.writeFileSync(new URL('manifest.json', root), JSON.stringify(manifest, null, 2) + '\n');
const htmlFile = new URL('index.html', root);
const html = fs.readFileSync(htmlFile, 'utf8');
if (!html.includes(oldFile)) throw new Error('Admin HTML entry does not match manifest');
fs.writeFileSync(htmlFile, html.replace(oldFile, newFile));
// Keep the previous hashed asset: cached pages may still reference it during rollout.
console.log(`Admin HTTP test integrated: ${newFile}`);
