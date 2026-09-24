import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { generateCertificateIntoForm, CertificateGeneratorButton } from '../../public/assets/admin/certificate-generator.mjs';

const generated = { data: {
  cert_content: '-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----',
  key_content: '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----',
} };
function formFixture() {
  const values = { 'cert_config.cert_mode': 'content', 'cert_config.domain': 'node.example.com',
    'cert_config.cert_content': '', 'cert_config.key_content': '' };
  const edits = [];
  return { values, edits, getValues: name => values[name], watch: name => values[name],
    setValue(name, value, options) { edits.push({ name, options }); values[name] = value; } };
}

test('button request fills both controlled fields and marks the form dirty', async () => {
  const form = formFixture();
  const result = await generateCertificateIntoForm(form, 'cert_config', async domain => {
    assert.equal(domain, 'node.example.com'); return generated;
  });
  assert.equal(result, true);
  assert.equal(form.values['cert_config.cert_content'], generated.data.cert_content);
  assert.equal(form.values['cert_config.key_content'], generated.data.key_content);
  assert.equal(form.edits.length, 2);
  assert.ok(form.edits.every(edit => edit.options.shouldDirty && edit.options.shouldValidate));
});

for (const field of ['domain', 'cert_mode', 'cert_content', 'key_content']) {
  test(`pending response does not overwrite a changed ${field}`, async () => {
    const form = formFixture();
    let complete;
    const promise = generateCertificateIntoForm(form, 'cert_config', () => new Promise(resolve => { complete = resolve; }));
    form.values[`cert_config.${field}`] = 'edited';
    complete(generated);
    assert.equal(await promise, false);
    assert.equal(form.edits.length, 0);
  });
}

test('failed or incomplete generation preserves the current certificate and key', async () => {
  const form = formFixture();
  await assert.rejects(generateCertificateIntoForm(form, 'cert_config', async () => { throw new Error('offline'); }));
  await assert.rejects(generateCertificateIntoForm(form, 'cert_config', async () => ({ data: {} })));
  assert.equal(form.edits.length, 0);
});

test('button uses the authenticated admin API, shows loading and does not submit the node', async () => {
  const form = formFixture();
  const states = [], requests = [], successes = [];
  const ui = { React: { useState: () => [false, value => states.push(value)] },
    useTranslation: () => ({ i18n: { language: 'zh-CN' } }),
    jsx: (component, props) => ({ component, props }), Button: 'button', adminPath: 'admin-test',
    post: async (url, body) => { requests.push({ url, body }); return generated; },
    toast: { success: value => successes.push(value), error: assert.fail },
  };
  const button = CertificateGeneratorButton({ form, certPath: 'cert_config', ui });
  assert.equal(button.props.children, '自动生成');
  assert.equal(button.props.type, 'button');
  await button.props.onClick();
  assert.deepEqual(states, [true, false]);
  assert.deepEqual(requests, [{ url: 'admin-test/server/manage/generateCertificate', body: { domain: 'node.example.com' } }]);
  assert.equal(successes.length, 1);
  form.values['cert_config.domain'] = '';
  assert.equal(CertificateGeneratorButton({ form, certPath: 'cert_config', ui }).props.disabled, true);
});

test('shipped admin bundle renders the button beside the domain only for content mode', () => {
  const root = new URL('../../public/assets/admin/', import.meta.url);
  const manifest = JSON.parse(fs.readFileSync(new URL('manifest.json', root)));
  const source = fs.readFileSync(new URL(manifest['index.html'].file, root), 'utf8');
  const from = source.indexOf('function a5t('), to = source.indexOf('function l5t(', from);
  assert.ok(from > 0 && to > from);
  const jsx = (type, props) => ({ type, props });
  const context = { Q: { jsx, jsxs: jsx, Fragment: 'Fragment' }, jy: () => ({ t: key => key }),
    H: {}, RL() {}, UL: 'admin-test', gE: {}, CertificateGeneratorButton };
  for (const name of ['$y','Gy','Zy','Yy','u8e','$f','yzt','Czt','wzt','Nzt','Lzt','Xy','aZt','YXt','xtt']) context[name] = name;
  vm.createContext(context);
  vm.runInContext(source.slice(from, to), context);
  const find = (element, predicate) => {
    if (!element || typeof element !== 'object') return null;
    if (predicate(element)) return element;
    for (const child of [element.props?.children].flat()) { const found = find(child, predicate); if (found) return found; }
    return null;
  };
  for (const mode of ['content', 'self', 'http', 'dns', 'none']) {
    const form = formFixture();
    const view = context.a5t({ form, certPath: 'cert_config', certMode: mode, dnsEnvText: '', onDnsEnvTextChange() {} });
    const domainField = find(view, element => element.props?.name === 'cert_config.domain');
    if (mode === 'none') { assert.equal(domainField, null); continue; }
    const field = { value: 'node.example.com', onChange() {} };
    const rendered = domainField.props.render({ field });
    const button = find(rendered, element => element.type === CertificateGeneratorButton);
    assert.equal(Boolean(button), mode === 'content');
    if (button) { assert.equal(button.props.form, form); assert.equal(button.props.certPath, 'cert_config'); }
    assert.equal(find(rendered, element => element.type === 'u8e').props.onChange, field.onChange);
  }
});
