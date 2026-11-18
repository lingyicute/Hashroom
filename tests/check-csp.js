'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync, writeFileSync} = require('node:fs');
const {join} = require('node:path');

const policy = /(<meta http-equiv="Content-Security-Policy"\s+content="[^\"]*?\bscript-src\s+)([^;\"]+)(;)/i;

function scriptSources(html) {
  // HTML 解析器会把 CRLF 和 CR 变成 LF，CSP 校验的是解析后的脚本文本。
  const scripts = [...html.replace(/\r\n?/g, '\n').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  assert(scripts.length && scripts.every(script => !script[1].trim()), '页面只能使用无属性的内联脚本');
  return scripts.map(script => `'sha256-${createHash('sha256').update(script[2]).digest('base64')}'`).join(' ');
}

function checkScriptPolicy(html) {
  const match = html.match(policy);
  assert(match, '找不到 CSP script-src');
  assert.equal(match[2], scriptSources(html), '请运行 node tests/check-csp.js --write 更新 CSP 摘要');
}

if (require.main === module) {
  const path = join(__dirname, '..', 'index.html');
  const html = readFileSync(path, 'utf8');
  if (process.argv[2] === '--write') {
    assert(policy.test(html), '找不到 CSP script-src');
    writeFileSync(path, html.replace(policy, (_, before, current, after) => before + scriptSources(html) + after));
  } else {
    checkScriptPolicy(html);
  }
}

module.exports = {checkScriptPolicy};
