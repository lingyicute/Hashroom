// 用 Node 内置 crypto 校验 index.html 中的纯 JS 摘要实现与比对逻辑。
// 运行：node tests/verify.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const cut = (from, to) => {
  const start = src.indexOf(from);
  const end = src.indexOf(to, start);
  assert(start >= 0 && end > start, `找不到代码片段：${from}`);
  return src.slice(start, end);
};

const code = [
  cut('const ALGORITHMS = [', 'const WEB_CRYPTO'),
  "const WEB_CRYPTO = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);",
  'const BUFFER_LIMIT = 256 * 1024 * 1024;',
  'const HASH_LENGTHS = new Set(ALGORITHMS.map(item => item.bits / 4));',
  'let runToken = 1; const window = globalThis;',
  // 让出线程的辅助函数在 Node 里会让 MessagePort 挂住事件循环，测试中走 setTimeout 的退路。
  'const MessageChannel = undefined;',
  cut('function rotr32', 'function hexEqual'),
  'globalThis.__writeBitLength = writeBitLength;',
  cut('function canonicalAlgorithm', 'function entryTargets'),
  cut('const yieldQueue', 'async function computeHashes'),
  'return {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected};'
].join('\n');

const {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected} =
  new Function('crypto', 'performance', code)(crypto.webcrypto, performance);

const NODE_NAMES = {
  'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
  'SHA-512': 'sha512', 'SHA-512/224': 'sha512-224', 'SHA-512/256': 'sha512-256',
  'SHA3-224': 'sha3-224', 'SHA3-256': 'sha3-256', 'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512',
  'RIPEMD-160': 'ripemd160'
};

function expected(id, buf) {
  if (id === 'CRC32') return require('zlib').crc32(buf).toString(16).padStart(8, '0');
  return crypto.createHash(NODE_NAMES[id]).update(buf).digest('hex');
}

function checkBitLength() {
  const write = globalThis.__writeBitLength;
  const sizes = [0, 1, 55, 2 ** 29 - 1, 2 ** 29, 2 ** 32, 2 ** 32 + 5, 2 ** 40 + 12345, 2 ** 50 + 7, Number.MAX_SAFE_INTEGER];
  for (const size of sizes) {
    for (const [width, little] of [[8, false], [8, true], [16, false]]) {
      const buf = new Uint8Array(16);
      write(buf, 0, size, width, little);
      const bytes = Array.from(buf.subarray(0, width));
      if (little) bytes.reverse();
      const got = bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
      assert.strictEqual(got, BigInt(size) * 8n, `长度编码错误 (${size} 字节, ${width} 字节宽, ${little ? 'LE' : 'BE'})`);
    }
  }
  console.log('ok    bit length');
}

// 启动自检用的标准向量本身必须正确，否则浏览器里会误停用算法。
function checkSelfTestVectors() {
  const vectors = new Function(`${cut('const MSG56 =', 'const failed = new Set()')}\nreturn vectors;`)();
  const hasCrc = typeof require('zlib').crc32 === 'function';
  const text = new TextEncoder();
  vectors.forEach(([id, message, want]) => {
    if (id === 'CRC32' && !hasCrc) return;
    assert.strictEqual(want, expected(id, Buffer.from(text.encode(message))), `自检向量有误：${id} "${message.slice(0, 12)}"`);
  });
  console.log('ok    self-test vectors', vectors.length);
}

async function main() {
  checkBitLength();
  checkSelfTestVectors();
  const hasCrc = typeof require('zlib').crc32 === 'function';
  const sizes = [];
  for (let i = 0; i <= 300; i += 1) sizes.push(i);
  sizes.push(4096, 65537, 1048576 + 13);

  for (const {id} of ALGORITHMS) {
    if (id === 'CRC32' && !hasCrc) continue;
    for (const size of sizes) {
      const buf = crypto.randomBytes(size);
      const want = expected(id, buf);
      assert.strictEqual(digestBytes(id, buf), want, `${id} 一次性计算失败 (${size} 字节)`);
      const hasher = createHasher(id);
      for (let offset = 0; offset < size;) {
        const step = 1 + Math.floor(Math.random() * 200);
        hasher.update(buf.subarray(offset, offset + step));
        offset += step;
      }
      assert.strictEqual(hasher.digest(), want, `${id} 分块计算失败 (${size} 字节)`);
    }
    console.log('ok   ', id);
  }

  const buf = crypto.randomBytes(3 * 1048576 + 7);
  for (const ids of [['SHA-256'], ['SHA-256', 'MD5', 'SHA3-256'], ['MD5', 'SHA-512/256']]) {
    const results = await hashFile(new Blob([buf]), ids, 1, () => {});
    results.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile ${item.algorithm}`));
  }
  // 一次性读取失败时应退回到流式处理，结果保持一致。
  const flaky = new Blob([buf]);
  flaky.arrayBuffer = () => Promise.reject(new Error('out of memory'));
  const fallback = await hashFile(flaky, ['SHA-256', 'MD5'], 1, () => {});
  fallback.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile fallback ${item.algorithm}`));
  // 没有 Blob.arrayBuffer() 的旧浏览器应通过 FileReader 读取，结果保持一致。
  globalThis.FileReader = class {
    readAsArrayBuffer(blob) {
      Blob.prototype.arrayBuffer.call(blob).then(
        buffer => { this.result = buffer; this.onload(); },
        error => { this.error = error; this.onerror(); }
      );
    }
  };
  const legacy = new Blob([buf]);
  legacy.arrayBuffer = undefined;
  legacy.slice = (start, end) => {
    const part = Blob.prototype.slice.call(legacy, start, end);
    part.arrayBuffer = undefined;
    return part;
  };
  for (const streaming of [false, true]) {
    const results = await hashFile(legacy, streaming ? ['MD5'] : ['SHA-256', 'MD5'], 1, () => {});
    results.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile legacy ${item.algorithm}`));
  }
  delete globalThis.FileReader;
  console.log('ok    hashFile');

  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const spaced = sha256.match(/.{8}/g).join(' ');
  const cases = [
    [`SHA-256: ${spaced}`, 'SHA-256', 64],
    [`sha256sum ${sha256}  deadbeef.bin`, 'SHA-256', 64],
    [`SHA256 (file.iso) = ${sha256}`, 'SHA-256', 64],
    ['MD5: d41d8cd9 8f00b204 e9800998 ecf8427e', 'MD5', 32],
    ['CRC32: CBF43926', 'CRC32', 8],
    [sha256.toUpperCase(), null, 64],
    [`${sha256}  release.sha256`, null, 64],
    [`${sha256}  app-md5.iso`, null, 64],
    [`sha256sum ${sha256} *app_md5.bin`, 'SHA-256', 64],
    ['d41d8cd98f00b204e9800998ecf8427e  cafebabe', null, 32],
    ['d41d8cd98f00b204e9800998ecf8427e  deadbeef.bin', null, 32],
    ['cbf43926  cafe.txt', null, 8],
    [`${sha256}  sha1.txt`, null, 64],
    [`${sha256} *sha256.sum`, null, 64],
    [`${sha256}  md5.exe`, null, 64],
    [`SHA2-256(file.iso)= ${sha256}`, 'SHA-256', 64],
    [`SHA2-512/256(file.iso)= ${sha256}`, 'SHA-512/256', 64],
    [`SHA3-256(file.iso)= ${sha256}`, 'SHA3-256', 64],
    [`SHA512-256 (file.iso) = ${sha256}`, 'SHA-512/256', 64],
    ['Hash: d41d8cd9 8f00b204 e9800998 ecf8427e', null, 32],
    ['Checksum: d41d8cd9 8f00b204 e9800998 ecf8427e', null, 32],
    ['d41d8cd9 8f00b204 e9800998 ecf8427e  a.txt', null, 32],
    [`Checksum: ${spaced}`, null, 64],
    [`--sha256 ${sha256}`, 'SHA-256', 64],
    [`SHA-256：${sha256}`, 'SHA-256', 64],
    [`SHA-256：${sha256.match(/.{8}/g).join('，')}`, 'SHA-256', 64],
    [`${sha256}  my-sha256.txt`, null, 64],
    ['da39a3ee5e6b4b0d3255bfef95601890afd80709  sha256-notes.txt', null, 40],
    ['SHA-256: da39a3ee5e6b4b0d3255bfef95601890afd80709', null, 40]
  ];
  cases.forEach(([line, algorithm, length]) => {
    const parsed = parseExpected(line);
    assert.strictEqual(parsed.entries.length, 1, line);
    assert.strictEqual(parsed.entries[0].algorithm, algorithm, line);
    assert.strictEqual(parsed.entries[0].hex.length, length, line);
  });
  // Base64 摘要：SRI、带算法名的行，含无填充和 URL 安全字母表。
  for (const [name, id, node] of [['sha256', 'SHA-256', 'sha256'], ['sha384', 'SHA-384', 'sha384'], ['sha512', 'SHA-512', 'sha512'], ['sha1', 'SHA-1', 'sha1'], ['md5', 'MD5', 'md5']]) {
    for (const data of ['', 'abc', 'hashroom']) {
      const digest = crypto.createHash(node).update(data).digest();
      const forms = [digest.toString('base64'), digest.toString('base64').replace(/=+$/, ''), digest.toString('base64url')];
      forms.forEach(b64 => {
        [`${name}-${b64}`, `${name.toUpperCase()}: ${b64}`, `${name}sum ${b64}  file.bin`].forEach(line => {
          const parsed = parseExpected(line);
          assert.strictEqual(parsed.entries.length, 1, line);
          assert.strictEqual(parsed.entries[0].algorithm, id, line);
          assert.strictEqual(parsed.entries[0].hex, digest.toString('hex'), line);
        });
      });
    }
  }
  assert.strictEqual(parseExpected('sha384 ' + sha256).entries[0].hex, sha256);
  assert.strictEqual(parseExpected('garbage').invalid, true);
  const truncated = parseExpected(`SHA-256: ${sha256.slice(1)}`);
  assert.strictEqual(truncated.invalid, true);
  assert.strictEqual(truncated.strayLength, 63);
  assert.ok(parseExpected('garbage').strayLength <= 8);
  const mixed = parseExpected(`SHA256 hash of file.iso:\n${sha256}\nCertUtil: -hashfile command completed successfully.`);
  assert.strictEqual(mixed.entries.length, 1);
  assert.strictEqual(mixed.partialInvalid, true);
  assert.strictEqual(mixed.invalidLines, 2);
  console.log('ok    parseExpected');
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
