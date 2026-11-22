'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync, writeFileSync} = require('node:fs');
const {join} = require('node:path');

const policy = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*>/gi;
const privacyDirectives = new Map([
  ['default-src', "'none'"], ['style-src', "'unsafe-inline'"], ['img-src', 'data:'],
  ['base-uri', "'none'"], ['form-action', "'none'"]
]);

const anyCspMeta = /<meta\b[^>]*\bhttp-equiv\s*=\s*(?:"content-security-policy"|'content-security-policy'|content-security-policy(?=[\s/>]))/gi;

function readPolicy(html) {
  const allPolicies = [...html.matchAll(anyCspMeta)];
  const policies = [...html.matchAll(policy)];
  assert.equal(allPolicies.length, 1, '页面应有且仅有一个可检查的 CSP 元标签');
  assert.equal(policies.length, 1, '页面应有且仅有一个可检查的 CSP 元标签');
  const match = policies[0];
  const before = html.slice(0, match.index);
  assert(/<head\s*>/i.test(before) && !/<\/head\s*>|<(?:script|link|style|base|body|iframe|img|object|embed|audio|video|source)\b/i.test(before),
    'CSP 应在 head 中，且出现在页面资源之前');
  const directives = new Map();
  for (const directive of match[1].split(';').map(item => item.trim()).filter(Boolean)) {
    const [name, ...sources] = directive.split(/\s+/);
    const key = name.toLowerCase();
    assert(!directives.has(key), `重复的 CSP 指令：${key}`);
    directives.set(key, sources.join(' '));
  }
  for (const [name, sources] of privacyDirectives) {
    assert.equal(directives.get(name), sources, `CSP ${name} 必须保持本地处理限制`);
  }
  assert(directives.has('script-src') && directives.size === privacyDirectives.size + 1,
    'CSP 必须包含 script-src，且不能用额外的资源指令覆盖限制');
  return {match, hashes: directives.get('script-src')};
}

function scriptSources(html) {
  // HTML 解析器会把 CRLF 和 CR 变成 LF，CSP 校验的是解析后的脚本文本。
  const scripts = [...html.replace(/\r\n?/g, '\n').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  assert(scripts.length && scripts.every(script => !script[1].trim()), '页面只能使用无属性的内联脚本');
  return scripts.map(script => `'sha256-${createHash('sha256').update(script[2]).digest('base64')}'`).join(' ');
}

function checkScriptPolicy(html) {
  const {hashes} = readPolicy(html);
  assert.equal(hashes, scriptSources(html), '请运行 node tests/check-csp.js --write 更新 CSP 摘要');
}

if (require.main === module) {
  const path = join(__dirname, '..', 'index.html');
  const html = readFileSync(path, 'utf8');
  if (process.argv[2] === '--write') {
    const {match} = readPolicy(html);
    const sources = scriptSources(html);
    const updated = match[1].replace(/(^|;\s*)script-src\s+[^;]*/i, (_, prefix) => `${prefix}script-src ${sources}`);
    writeFileSync(path, html.replace(match[0], () => match[0].replace(match[1], () => updated)));
  } else {
    checkScriptPolicy(html);
  }
}

module.exports = {checkScriptPolicy};
