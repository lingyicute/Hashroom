'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {createServer} = require('node:http');
const {join} = require('node:path');
const {pathToFileURL} = require('node:url');
const playwright = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const path = join(__dirname, '..', 'index.html');
const checksum = (text, algorithm = 'sha256') => createHash(algorithm).update(text).digest('hex');
const choose = (page, name, text = 'abc') => page.locator('#fileInput').setInputFiles({name, mimeType: 'text/plain', buffer: Buffer.from(text)});
const expected = (page, text) => page.locator('#expectedInput').fill(text);
const compute = page => page.locator('#computeButton').click();

async function session(browser, options, exercise) {
  const page = await browser.newPage(options);
  page.setDefaultTimeout(6000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (message.type() === 'error' && /content security policy/i.test(message.text())) errors.push(message.text());
  });
  try {
    await exercise(page);
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
  }
}

async function banner(page, kind, title) {
  const heading = page.locator(`#compareBanner.is-${kind} strong`);
  await heading.waitFor();
  assert.match(await heading.textContent(), title);
}

async function offline(page) {
  const network = [];
  page.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
  await page.addInitScript(() => {
    window.AbortController = window.TextEncoder = undefined;
    Array.prototype.flatMap = String.prototype.trimStart = String.prototype.trimEnd = undefined;
    Blob.prototype.arrayBuffer = undefined;
    if (window.crypto) Object.defineProperty(window.crypto, 'subtle', {value: undefined});
  });
  await page.goto(pathToFileURL(path).href);
  assert.equal(await page.locator('input[name=algorithm]:enabled').count(), 14);
  await choose(page, 'offline.txt');
  const hex = checksum('abc');
  await expected(page, `SHA256     ${hex}     C:\\Downloads\\offline.txt`);
  await compute(page);
  await banner(page, 'match', /SHA-256/);
  assert.equal(await page.locator('.digest-value').textContent(), hex);
  await expected(page, `${hex} offline.txt`);
  await banner(page, 'match', /SHA-256/);
  assert.deepEqual(network, []);
}

async function verdicts(page, url) {
  await page.goto(url);
  const defaultHint = await page.locator('#compareHint').textContent();
  assert.match(defaultHint, /十六进制.*Base64 和文件名区分大小写/);
  await expected(page, `SHA-256: ${checksum('abc')}`);
  await choose(page, 'current.txt');
  await page.locator('#clearExpected').click();
  assert.doesNotMatch(await page.locator('#resultsPanel .empty-description').textContent(), /与预期值比对/);
  await expected(page, `SHA256 (other.txt) = ${checksum('abc')}`);
  await compute(page);
  await page.locator('.digest-row').waitFor();
  await banner(page, 'info', /没有当前文件/);
  assert.equal(await page.locator('.match-pill').count(), 0);
  await expected(page, checksum('abc', 'sha3-256'));
  await banner(page, 'info', /仍有算法未计算/);
  await page.locator('#applySuggested').click();
  await compute(page);
  await banner(page, 'match', /SHA3-256/);
  assert.equal(await page.locator('.match-pill').count(), 1);
  assert.match(await page.locator('#statusLine').textContent(), /SHA3-256.*一致/);
  await expected(page, `SHA256 (current.txt) = ${checksum('abc')}\nSHA256 (current.txt) = ${checksum('other')}`);
  await banner(page, 'mismatch', /清单有冲突/);
  assert.equal(await page.locator('.digest-row.is-conflict .match-pill').textContent(), '清单冲突');
  await expected(page, `SHA256 (current.txt) = ${checksum('abc')}\nSM3 (current.txt) = ${checksum('abc')}`);
  await banner(page, 'info', /已匹配 SHA-256/);
  await page.locator('#clearExpected').click();
  assert.equal(await page.locator('.match-pill').count(), 0);
  assert.equal(await page.locator('#compareHint').textContent(), defaultHint);
  await page.locator('#clearFile').click();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'dropzone');
}

async function cancellation(page, url) {
  await page.addInitScript(() => {
    window.pendingDigests = [];
    const native = SubtleCrypto.prototype.digest;
    SubtleCrypto.prototype.digest = function (...args) {
      return new Promise((resolve, reject) => {
        window.pendingDigests.push(() => native.apply(this, args).then(resolve, reject));
      });
    };
  });
  await page.goto(url);
  await choose(page, 'stale.txt');
  await compute(page);
  await page.waitForFunction(() => window.pendingDigests.length === 1);
  assert.equal(await page.getByRole('progressbar', {name: '摘要计算进度'}).getAttribute('aria-valuenow'), '0');
  assert.ok(await page.locator('#computeIcon').isHidden());
  assert.ok(await page.locator('#buttonSpinner').isVisible());
  const leaveFlags = () => page.evaluate(() => {
    const event = new Event('beforeunload', {cancelable: true});
    Object.defineProperty(event, 'returnValue', {value: '', writable: true});
    window.dispatchEvent(event);
    return [event.defaultPrevented, Boolean(event.returnValue)];
  });
  assert.deepEqual(await leaveFlags(), [true, true]);
  await page.getByRole('button', {name: '取消计算'}).click();
  assert.deepEqual(await leaveFlags(), [false, false]);
  assert.match(await page.locator('#statusLine').textContent(), /已取消/);
  assert.ok(await page.locator('#computeIcon').isVisible());
  assert.ok(await page.locator('#buttonSpinner').isHidden());
  await choose(page, 'current.txt', 'def');
  await expected(page, checksum('def'));
  await compute(page);
  await banner(page, 'match', /SHA-256/);
  await page.evaluate(() => window.pendingDigests.shift()());
  assert.equal(await page.locator('.digest-value').textContent(), checksum('def'));
  await page.evaluate(() => { FileReader.prototype.readAsArrayBuffer = () => { throw new Error('read failed'); }; });
  await compute(page);
  await page.locator('#resultsPanel.is-error').waitFor();
  assert.equal(await page.locator('#compareBanner.is-match, .digest-row').count(), 0);
  assert.ok(await page.locator('#copyAllButton').isDisabled());
}

async function clipboard(page, url) {
  await page.goto(url);
  await choose(page, 'before.txt');
  await compute(page);
  await page.locator('.digest-row').waitFor();
  const button = page.locator('#copyAllButton');
  const status = await page.locator('#statusLine').textContent();
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
      writeText: text => { window.copiedText = text; return Promise.resolve(); }
    }});
  });
  await button.click();
  await page.waitForFunction(() => document.getElementById('copyStatus').textContent.includes('已复制'));
  assert.equal(await page.evaluate(() => window.copiedText), `SHA-256: ${checksum('abc')}`);
  assert.equal(await page.locator('#copyAllButton.is-copied').count(), 1);
  await page.evaluate(() => {
    navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));
    document.execCommand = () => { throw new Error('denied'); };
  });
  await button.focus();
  await button.click();
  await page.locator('#copyStatus.is-error').waitFor();
  assert.equal(await page.locator('#copyAllButton.is-copied').count(), 0);
  assert.equal(await page.locator('textarea').count(), 1);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'copyAllButton');
  assert.equal(await page.locator('#statusLine').textContent(), status);
  await page.evaluate(() => {
    const value = document.querySelector('.digest-value').firstChild;
    window.getSelection().setBaseAndExtent(value, value.length, value, 0);
    document.getElementById('copyAllButton').click();
  });
  await page.locator('#copyStatus.is-error').waitFor();
  assert.deepEqual(await page.evaluate(() => {
    const selection = window.getSelection();
    return [selection.toString(), selection.anchorOffset > selection.focusOffset];
  }), [checksum('abc'), true]);
  await page.evaluate(() => {
    navigator.clipboard.writeText = () => new Promise(resolve => { window.finishCopy = resolve; });
  });
  await button.click();
  await page.waitForFunction(() => typeof window.finishCopy === 'function');
  await choose(page, 'after.txt');
  await page.evaluate(() => window.finishCopy());
  assert.equal(await page.locator('#copyStatus').textContent(), '');
  assert.match(await page.locator('#statusLine').textContent(), /文件已就绪/);
}

async function dragAndTheme(page, url) {
  await page.addInitScript(() => {
    Storage.prototype.getItem = Storage.prototype.setItem = () => { throw new DOMException('disabled', 'SecurityError'); };
  });
  await page.goto(url);
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.emulateMedia({colorScheme: 'light'});
  await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  await page.locator('#themeToggle').click();
  await page.emulateMedia({colorScheme: 'dark'});
  await page.emulateMedia({colorScheme: 'light'});
  await page.locator('#paletteToggle').click();
  const menu = await page.locator('#paletteMenu').boundingBox();
  assert.ok(menu.x >= 0 && menu.x + menu.width <= 280);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 280);
  await page.getByRole('radio', {checked: true}).focus();
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.getByRole('radio', {checked: true}).getAttribute('aria-label'), '海蓝');
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'paletteToggle');
  assert.equal(await page.locator('meta[name=theme-color]').getAttribute('content'), '#10141a');
  const dropped = await page.evaluate(() => {
    const data = new DataTransfer();
    data.items.add(new File(['abc'], 'first.txt'));
    data.items.add(new File(['def'], 'second.txt'));
    const files = new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: data});
    document.body.dispatchEvent(files);
    const folder = new Event('drop', {bubbles: true, cancelable: true});
    Object.defineProperty(folder, 'dataTransfer', {value: {
      files: [], types: [], items: {0: {kind: 'file', webkitGetAsEntry: () => ({isDirectory: true})}, length: 1}
    }});
    document.getElementById('dropzone').dispatchEvent(folder);
    return files.defaultPrevented && folder.defaultPrevented;
  });
  assert.ok(dropped);
  assert.match(await page.locator('#fileNotice').textContent(), /不支持文件夹/);
  assert.equal(await page.locator('#fileName').textContent(), 'first.txt');
  const extension = 'x'.repeat(180);
  await choose(page, `long.${extension}`);
  assert.ok((await page.locator('#fileMeta').textContent()).startsWith(extension.toUpperCase()));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 280);
}

async function main() {
  const html = readFileSync(path);
  const server = createServer((request, response) => {
    if (request.url === '/') response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}).end(html);
    else response.writeHead(204).end();
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    const name = process.env.HASHROOM_BROWSER || 'chromium';
    const browser = await playwright[name].launch();
    try {
      for (const exercise of [offline, verdicts, cancellation, clipboard]) {
        await session(browser, {}, page => exercise(page, url));
        console.log('ok   ', exercise.name);
      }
      await session(browser, {viewport: {width: 280, height: 800}, colorScheme: 'dark', reducedMotion: 'reduce'}, page => dragAndTheme(page, url));
      console.log('ok    dragAndTheme');
      console.log(`ok    ${name} ${browser.version()}`);
    } finally {
      await browser.close();
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
