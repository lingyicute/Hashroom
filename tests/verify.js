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
  cut('function rotl32', 'function hexEqual'),
  'globalThis.__writeBitLength = writeBitLength;',
  cut('function canonicalAlgorithm', 'function entryTargets'),
  cut('const yieldQueue', 'async function computeHashes'),
  'return {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected, entriesForFile};'
].join('\n');

const {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected, entriesForFile} =
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

// 用时格式：999.6 毫秒进位成 1.0 秒；按毫秒先取整再换算秒会二次舍入（1049.6 毫秒会变成 1.1 秒），所以直接用原值。
function checkDurationFormat() {
  const formatDuration = new Function(`${cut('function formatDuration', 'function formatBytes')}\nreturn formatDuration;`)();
  for (const [ms, want] of [
    [0, '1 毫秒'],
    [999.4, '999 毫秒'],
    [999.6, '1.0 秒'],
    [1000, '1.0 秒'],
    [1049.6, '1.0 秒'],
    [1234, '1.2 秒'],
    [59400, '59.4 秒'],
    [59500, '1 分 0 秒'],
    [119999, '2 分 0 秒']
  ]) {
    assert.strictEqual(formatDuration(ms), want, `用时格式错误（${ms} 毫秒）`);
  }
  console.log('ok    duration format');
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
  checkDurationFormat();
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
  // 流式读取若在中途返回空分块，应直接报错而不是算出截断后的错误摘要。
  const truncated = {
    size: 2 * 1048576,
    slice: start => new Blob(start === 0 ? [buf.subarray(0, 1048576)] : [])
  };
  await assert.rejects(hashFile(truncated, ['MD5'], 1, () => {}), /Unexpected end of file/);
  // 分块非空但比应有的短，同样不能悄悄算下去。
  const short = {
    size: 2 * 1048576,
    slice: start => new Blob([buf.subarray(0, start === 0 ? 1048576 : 1000)])
  };
  await assert.rejects(hashFile(short, ['MD5'], 1, () => {}), /Unexpected end of file/);
  // 末块本来就比分块小，完整读到时照常通过。
  const oddSize = 1048576 + 1000;
  const odd = {size: oddSize, slice: (start, end) => new Blob([buf.subarray(start, Math.min(end, oddSize))])};
  const oddResult = await hashFile(odd, ['MD5'], 1, () => {});
  assert.strictEqual(oddResult[0].hex, crypto.createHash('md5').update(buf.subarray(0, oddSize)).digest('hex'));
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
    [`${sha256}  sha256-notes.txt`, null, 64],
    [`${sha256}  sha256sum.txt`, null, 64],
    [`${sha256}  sha256_notes.txt`, null, 64],
    ['d41d8cd9 8f00b204 e9800998 ecf8427e  deadbeef.bin', null, 32],
    ['d41d8cd98f00b204e9800998ecf8427e  da39a3ee5e6b4b0d3255bfef95601890afd80709', null, 32],
    ['CRC32 (deadbeef) = cbf43926', 'CRC32', 8],
    ['SHA-256: da39a3ee5e6b4b0d3255bfef95601890afd80709', null, 40],
    [`sha3_256: ${sha256}`, 'SHA3-256', 64],
    [`sha512_256 = ${sha256}`, 'SHA-512/256', 64],
    [`SHA_256: ${sha256}`, 'SHA-256', 64],
    [`SHA512t256 (file.iso) = ${sha256}`, 'SHA-512/256', 64],
    [`${sha256}  sha3_256.txt`, null, 64],
    // 分组哈希用多个空白、或两侧带空格的分隔符书写时，仍应拼回完整的哈希，而不是把第一组误认成 CRC32。
    [`SHA-256: ${sha256.match(/.{8}/g).join('  ')}`, 'SHA-256', 64],
    [`SHA-256: ${sha256.match(/.{8}/g).join(' - ')}`, 'SHA-256', 64],
    [`SHA-256: ${sha256.match(/.{8}/g).join(' : ')}`, 'SHA-256', 64]
  ];
  cases.forEach(([line, algorithm, length]) => {
    const parsed = parseExpected(line);
    assert.strictEqual(parsed.entries.length, 1, line);
    assert.strictEqual(parsed.entries[0].algorithm, algorithm, line);
    assert.strictEqual(parsed.entries[0].hex.length, length, line);
  });
  assert.strictEqual(parseExpected('CRC32 (deadbeef) = cbf43926').entries[0].hex, 'cbf43926');
  // coreutils 转义过文件名的行（行首带反斜杠）认不出文件名，但哈希和算法照常识别。
  for (const [line, algorithm] of [[`\\${sha256}  a\\nb.txt`, null], [`\\${sha256} *dir\\\\x.bin`, null], [`\\SHA256 (a\\nb.txt) = ${sha256}`, 'SHA-256']]) {
    const parsed = parseExpected(line);
    assert.deepStrictEqual(parsed.entries.map(entry => [entry.algorithm, entry.hex, entry.file]), [[algorithm, sha256, '']], line);
  }
  // 网页上复制来的哈希可能用不换行空格、全角空格分组或夹带零宽字符；文件名可能是 NFD 形式。
  for (const space of ['\u00a0', '\u3000', '\u202f']) {
    const parsed = parseExpected(`SHA-256:${space}${sha256.match(/.{8}/g).join(space)}`);
    assert.deepStrictEqual(parsed.entries.map(entry => [entry.algorithm, entry.hex]), [['SHA-256', sha256]], JSON.stringify(space));
  }
  assert.strictEqual(parseExpected(`\u200b${sha256.slice(0, 32)}\u200b${sha256.slice(32)}  a.iso`).entries[0].hex, sha256);
  const composed = parseExpected(`${sha256}  caf\u00e9.iso\u2028d41d8cd98f00b204e9800998ecf8427e  other.iso`);
  assert.strictEqual(composed.entries.length, 2);
  assert.strictEqual(entriesForFile(composed.entries, 'cafe\u0301.iso').entries.length, 1);
  // Base64 摘要：SRI、带算法名的行，含无填充、URL 安全字母表及以连字符开头的 Base64url。
  for (const [name, id, node] of [['sha256', 'SHA-256', 'sha256'], ['sha384', 'SHA-384', 'sha384'], ['sha512', 'SHA-512', 'sha512'], ['sha1', 'SHA-1', 'sha1'], ['md5', 'MD5', 'md5']]) {
    for (const data of ['', 'abc', 'hashroom', '14']) {
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
  assert.strictEqual(parseExpected('deafbeefs').invalid, true);
  assert.strictEqual(parseExpected('deadbeef.bin').invalid, true);
  // 标着不支持的算法（BLAKE2、SM3 等）的摘要不按长度去猜，免得与等长的 SHA-256、MD5、CRC32 硬比。
  for (const line of [
    `BLAKE2s (file.iso) = ${sha256}`,
    `SM3(file.iso)= ${sha256}`,
    `BLAKE2b-512: ${sha256}${sha256}`,
    `b3sum ${sha256}  file.iso`,
    `b2sum ${sha256}${sha256}  file.iso`,
    'XXH3-128: d41d8cd98f00b204e9800998ecf8427e',
    'XXH3_128bits (file.iso) = d41d8cd98f00b204e9800998ecf8427e',
    `HMAC-SHA256: ${sha256}`,
    `HMAC SHA256: ${sha256}`,
    `SHA-256 HMAC: ${sha256}`,
    `HMAC-SHA256(stdin)= ${sha256}`,
    `Keccak-256: ${sha256}`,
    'MD4 (file.iso) = d41d8cd98f00b204e9800998ecf8427e',
    'CRC32C: cbf43926'
  ]) {
    const foreign = parseExpected(line);
    assert.strictEqual(foreign.invalid, true, line);
    assert.strictEqual(foreign.unsupported.length, 1, line);
  }
  assert.deepStrictEqual(parseExpected(`blake2s: ${sha256}\nBLAKE2s: ${sha256}`).unsupported, ['blake2s']);
  const distinfo = parseExpected(`BLAKE2s (file.iso) = ${sha256}\nSHA512 (file.iso) = ${sha256}${sha256}\nSize (file.iso) = 1234 bytes`);
  assert.deepStrictEqual(distinfo.entries.map(entry => entry.algorithm), ['SHA-512']);
  assert.deepStrictEqual(distinfo.unsupported, ['BLAKE2s']);
  // 混着可用算法的清单不是整体无效，不支持的算法只能在提示里说明，而不是只说“无法识别”。
  assert.strictEqual(distinfo.invalid, false);
  assert.strictEqual(distinfo.partialInvalid, true);
  // 不支持算法的那一行单独计数，提示里不会再把它算进“无法识别”的行数（这里只剩 Size 一行）。
  assert.strictEqual(distinfo.invalidLines, 2);
  assert.strictEqual(distinfo.unsupportedLines, 1);
  // 文件名里的同类名字不算标记，带着可用算法名的行也照常识别。
  assert.strictEqual(parseExpected(`${sha256}  blake3.iso`).entries.length, 1);
  assert.strictEqual(parseExpected(`blake3-notes.txt: ${sha256}`).entries.length, 1);
  assert.strictEqual(parseExpected(`b3sum-notes.txt: ${sha256}`).entries.length, 1);
  assert.strictEqual(parseExpected(`b3sum.txt: ${sha256}`).entries.length, 1);
  assert.strictEqual(parseExpected(`hmac-sha256-notes.txt: ${sha256}`).entries.length, 1);
  assert.strictEqual(parseExpected(`SHA256 (hmac.c) = ${sha256}`).entries[0].algorithm, 'SHA-256');
  assert.strictEqual(parseExpected(`BLAKE2b / SHA-512: ${sha256}${sha256}`).entries[0].algorithm, 'SHA-512');
  for (const sample of [`SHA-256: ${sha256.slice(1)}`, `SHA-256: ${spaced.slice(0, -1)}`, `SHA-256: ${spaced.slice(1)}`]) {
    const truncated = parseExpected(sample);
    assert.strictEqual(truncated.invalid, true, sample);
    assert.strictEqual(truncated.strayLength, 63, sample);
  }
  assert.ok(parseExpected('garbage').strayLength <= 8);
  const mixed = parseExpected(`SHA256 hash of file.iso:\n${sha256}\nCertUtil: -hashfile command completed successfully.`);
  assert.strictEqual(mixed.entries.length, 1);
  assert.strictEqual(mixed.partialInvalid, true);
  assert.strictEqual(mixed.invalidLines, 2);
  // 整份校验清单：只比对写明了当前文件名的那一行，其他文件的行不参与。
  const list = parseExpected([
    `${sha256}  ubuntu.iso`,
    'd41d8cd98f00b204e9800998ecf8427e  ./sub/other.iso',
    `SHA256 (win.iso) = ${sha256}`,
    `${sha256} *C:\\dl\\x.bin`,
    `SHA-256: ${sha256}`
  ].join('\n'));
  assert.deepStrictEqual(list.entries.map(entry => entry.file), ['ubuntu.iso', 'other.iso', 'win.iso', 'x.bin', '']);
  assert.strictEqual(entriesForFile(list.entries, 'other.iso').entries.length, 2);
  assert.strictEqual(entriesForFile(list.entries, 'other.iso').ignored, 3);
  assert.strictEqual(entriesForFile(list.entries, 'missing.iso').ignored, 0);
  assert.strictEqual(entriesForFile(list.entries, '').entries.length, 5);
  // 超长的行不能拖慢解析（输入框每次改动都会重新解析）。
  const started = performance.now();
  const hostile = parseExpected(`${'sha256 '.repeat(20000)}\n${'ab '.repeat(40000)}\n${sha256}  ok.iso`);
  assert.ok(performance.now() - started < 1000, '超长行解析太慢');
  assert.strictEqual(hostile.entries.length, 1);
  assert.strictEqual(hostile.invalidLines, 2);
  // 不超过长度上限、但挤满短十六进制片段的行同样不能拖慢解析。
  const crowdedStart = performance.now();
  const crowded = parseExpected(`${'ab '.repeat(680)}\n`.repeat(50) + `${spaced}  ok.iso`);
  assert.ok(performance.now() - crowdedStart < 500, '短片段密集的行解析太慢');
  assert.strictEqual(crowded.entries.length, 1);
  assert.strictEqual(crowded.invalidLines, 50);
  console.log('ok    parseExpected');
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
