// 用 Node 内置 crypto 校验 index.html 中的纯 JS 摘要实现与比对逻辑。
// 运行：node tests/verify.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('node:zlib');
const assert = require('assert');
const {checkScriptPolicy} = require('./check-csp');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const cut = (from, to) => {
  const start = src.indexOf(from);
  const end = src.indexOf(to, start);
  assert(start >= 0 && end > start, `找不到代码片段：${from}`);
  return src.slice(start, end);
};

const code = [
  cut('const ALGORITHMS = [', 'const DROPZONE_LABEL'),
  'const HASH_LENGTHS = new Set(ALGORITHMS.map(item => item.bits / 4));',
  // 避免 MessagePort 挂住 Node 的事件循环，走 setTimeout 退路。
  'const MessageChannel = undefined;',
  cut('function rotl32', 'function firstDifference'),
  cut('function canonicalAlgorithm', 'function missingCandidates'),
  cut('const yieldQueue', '// 结果已经显示时'),
  'return {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected, entriesForFile, compareDigests, writeBitLength};'
].join('\n');

const loadHashroom = (subtle = crypto.webcrypto.subtle) => new Function('window', 'performance', code)({crypto: {subtle}}, performance);
const {ALGORITHMS, createHasher, digestBytes, hashFile, parseExpected, entriesForFile, compareDigests, writeBitLength} = loadHashroom();
const freshSignal = () => new AbortController().signal;

const NODE_NAMES = {
  'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384',
  'SHA-512': 'sha512', 'SHA-512/224': 'sha512-224', 'SHA-512/256': 'sha512-256',
  'SHA3-224': 'sha3-224', 'SHA3-256': 'sha3-256', 'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512',
  'RIPEMD-160': 'ripemd160'
};

// 保持数据和分块可重现，同时覆盖高位字节与不规则步长。
let state = 0xa53c9bef;
function randomWord() {
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return state >>> 0;
}

function fixture(size) {
  const bytes = Buffer.allocUnsafe(size);
  for (let i = 0; i < size; i += 1) bytes[i] = randomWord() & 255;
  return bytes;
}

function referenceCrc32(buf) {
  if (typeof zlib.crc32 === 'function') return zlib.crc32(buf);
  // Node 22.0/22.1 还没有 zlib.crc32；用逐位参考实现，不能跳过 CRC32 掩盖问题。
  let crc = -1;
  for (const byte of buf) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (~crc) >>> 0;
}

function expected(id, buf) {
  if (id === 'CRC32') return referenceCrc32(buf).toString(16).padStart(8, '0');
  return crypto.createHash(NODE_NAMES[id]).update(buf).digest('hex');
}

function checkBitLength() {
  const sizes = [0, 1, 55, 2 ** 29 - 1, 2 ** 29, 2 ** 32, 2 ** 32 + 5, 2 ** 40 + 12345, 2 ** 50 + 7, Number.MAX_SAFE_INTEGER];
  for (const size of sizes) {
    for (const [width, little] of [[8, false], [8, true], [16, false]]) {
      const buf = new Uint8Array(16);
      writeBitLength(buf, 0, size, width, little);
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

function checkFileMetadata() {
  const {formatBytes, describeFile} = new Function(`${cut('function formatBytes', 'function hasExpectedValue')}\nreturn {formatBytes, describeFile};`)();
  for (const [bytes, label] of [[0, '0 B'], [1023, '1023 B'], [1024, '1.0 KiB'], [1536, '1.5 KiB'], [2 ** 20, '1.0 MiB'], [2 ** 50, '1.0 PiB']]) {
    assert.strictEqual(formatBytes(bytes), label);
  }
  const epoch = new Date(0).toLocaleDateString('zh-CN', {year: 'numeric', month: '2-digit', day: '2-digit'});
  assert.strictEqual(describeFile({name: 'empty.txt', size: 0, lastModified: 0}), `TXT · 0 B · ${epoch}`);
  console.log('ok    file metadata');
}

// 启动自检用的标准向量本身必须正确，否则浏览器里会误停用算法。
function checkSelfTestVectors() {
  const vectors = new Function(`${cut('const MSG56 =', 'const failed = new Set()')}\nreturn vectors;`)();
  const text = new TextEncoder();
  vectors.forEach(([id, message, want]) => {
    assert.strictEqual(want, expected(id, Buffer.from(text.encode(message))), `自检向量有误：${id} "${message.slice(0, 12)}"`);
  });
  console.log('ok    self-test vectors', vectors.length);
}

function checkComparison() {
  const enabled = new Set(ALGORITHMS.map(item => item.id));
  const sha256 = {algorithm: 'SHA-256', hex: expected('SHA-256', Buffer.from('abc'))};
  const sha3 = {algorithm: 'SHA3-256', hex: expected('SHA3-256', Buffer.from('abc'))};
  const sha512t = {algorithm: 'SHA-512/256', hex: expected('SHA-512/256', Buffer.from('abc'))};
  const wrong = '1'.repeat(64);
  // 页面复制的「算法: 摘要」必须能原样粘回去，不变成路径或同长度的其他算法。
  for (const {id} of ALGORITHMS) {
    const hex = expected(id, Buffer.from('abc'));
    const parsed = parseExpected(`${id}: ${hex}`);
    assert.deepStrictEqual(parsed.entries, [{algorithm: id, hex, file: ''}], id);
    assert.deepStrictEqual(parsed.files, [], id);
    assert.deepStrictEqual([...compareDigests(parsed.entries, [{algorithm: id, hex}], enabled).matched], [id]);
  }
  const tagged = parseExpected(`SHA-512/256: ${sha256.hex}`);
  assert.deepStrictEqual([...compareDigests(tagged.entries, [sha256], enabled).needed], ['SHA-512/256']);
  assert.deepStrictEqual(parseExpected(`SHA-512/192: ${sha256.hex}`).unsupported, ['SHA-512/192']);
  assert.deepStrictEqual(parseExpected(`release/256: ${sha256.hex}`).entries.map(entry => entry.path), ['release/256']);
  const check = (text, results, supported = enabled) => compareDigests(parseExpected(text).entries, results, supported);
  const pending = check(sha3.hex, [sha256]);
  assert.deepStrictEqual([...pending.needed], ['SHA-512/256', 'SHA3-256']);
  assert.strictEqual(pending.mismatched.size, 0);
  assert.strictEqual(pending.rows.size, 0);
  const match = check(sha3.hex, [sha256, sha3]);
  assert.deepStrictEqual([...match.rows], [['SHA3-256', 'match']]);
  assert.strictEqual(match.needed.size, 0);
  const miss = check(wrong, [sha256, sha3, sha512t]);
  assert.strictEqual(miss.mismatched.size, 1);
  assert.strictEqual(miss.rows.size, 3);
  const scoped = check(`SHA-256 (file) = ${wrong}\n${sha256.hex}`, [sha256]);
  assert.strictEqual(scoped.rows.get('SHA-256'), 'mismatch');
  const conflict = check(`SHA-256 (file) = ${wrong}\nSHA-256 (file) = ${sha256.hex}`, [sha256]);
  assert.deepStrictEqual([...conflict.conflicts], ['SHA-256']);
  assert.deepStrictEqual([...conflict.rows], [['SHA-256', 'conflict']]);
  const differentFiles = check(`SHA-256 (a/file) = ${wrong}\nSHA-256 (b/file) = ${sha256.hex}`, []);
  assert.strictEqual(differentFiles.conflicts.size, 0);
  const alternatives = check(`SHA-256: ${wrong}\nSHA-256: ${sha256.hex}`, [sha256]);
  assert.deepStrictEqual([...alternatives.rows], [['SHA-256', 'match']]);
  const disabled = check(sha3.hex, [sha256], new Set(['SHA-256']));
  assert.deepStrictEqual([...disabled.unavailable], ['SHA-512/256', 'SHA3-256']);
  assert.strictEqual(disabled.mismatched.size, 0);
  const independent = check(`${sha256.hex}  file\n${sha3.hex}  file`, [sha256]);
  assert.strictEqual(independent.matched.size, 1);
  assert.strictEqual(independent.pending.size, 1);
  console.log('ok    comparison decisions');
}

async function checkCancellation() {
  const blob = new Blob([Buffer.alloc(2 * 1048576 + 3, 7)]);
  const want = expected('SHA-256', Buffer.alloc(blob.size, 7));
  let started;
  let complete;
  let nativeCalls = 0;
  const ready = new Promise(resolve => { started = resolve; });
  const delayed = loadHashroom({digest() {
    nativeCalls += 1;
    if (nativeCalls > 1) return new Uint8Array(1).buffer; // 损坏的原生结果必须回退。
    started();
    return new Promise(resolve => { complete = resolve; });
  }});
  const firstRun = new AbortController();
  const progress = [];
  const first = delayed.hashFile(blob, ['SHA-256'], firstRun.signal, value => progress.push(value));
  await ready;
  firstRun.abort();
  assert.deepStrictEqual(await delayed.hashFile(blob, ['SHA-256'], freshSignal(), () => {}), [{algorithm: 'SHA-256', hex: want}]);
  assert.strictEqual(nativeCalls, 1, '旧的原生计算未返回时不能再读一个整文件');
  complete(new Uint8Array(32).buffer);
  assert.strictEqual(await first, null);
  assert.deepStrictEqual(progress, [0]);
  assert.deepStrictEqual(await delayed.hashFile(blob, ['SHA-256'], freshSignal(), () => {}), [{algorithm: 'SHA-256', hex: want}]);
  assert.strictEqual(nativeCalls, 2);

  let reads = 0;
  let aborts = 0;
  let finishFirstSlice = false;
  globalThis.FileReader = class {
    readAsArrayBuffer(part) {
      reads += 1;
      if (finishFirstSlice && reads === 1) {
        part.arrayBuffer().then(buffer => { this.result = buffer; if (this.onload) this.onload(); });
      }
    }
    abort() { aborts += 1; }
  };
  try {
    const reading = new AbortController();
    const buffered = hashFile(blob, ['SHA-256'], reading.signal, () => assert.fail('不应计算已取消的读取'));
    assert.strictEqual(reads, 1);
    reading.abort();
    assert.strictEqual(await buffered, null);
    assert.strictEqual(aborts, 1);
    reads = 0;
    finishFirstSlice = true;
    const streaming = new AbortController();
    assert.strictEqual(await hashFile(blob, ['MD5'], streaming.signal, () => streaming.abort()), null);
    assert.strictEqual(reads, 2, '曾经预读下一块，但不会继续读第三块');
    assert.strictEqual(aborts, 2, '预读也应中止');
  } finally {
    delete globalThis.FileReader;
  }
  console.log('ok    aborting reads and bounding native digest work');
}

async function checkLargeStream() {
  // 512 MiB 后的位数不再能放进 32 位。复用测试块，避免在测试机上分配整个文件。
  const chunkSize = 1024 * 1024;
  const size = 2 ** 29 + 13;
  const chunk = Uint8Array.from(fixture(chunkSize));
  const tail = chunk.slice(0, size % chunkSize);
  let reads = 0;
  const file = {
    size,
    arrayBuffer() { assert.fail('大文件必须分块读取'); },
    slice(start, end) {
      assert.strictEqual(start, reads++ * chunkSize);
      assert.strictEqual(end, Math.min(start + chunkSize, size));
      return {arrayBuffer: async () => (end - start === chunkSize ? chunk : tail).buffer};
    }
  };
  const reference = crypto.createHash('sha256');
  for (let offset = 0; offset + chunkSize <= size; offset += chunkSize) reference.update(chunk);
  reference.update(tail);
  let progress;
  const [digest] = await hashFile(file, ['SHA-256'], freshSignal(), value => { progress = value; });
  assert.equal(digest.hex, reference.digest('hex'));
  assert.equal(reads, Math.ceil(size / chunkSize));
  assert.equal(progress, 1);
  console.log('ok    streaming across the 32-bit bit-length boundary');
}

async function main() {
  checkScriptPolicy(src);
  assert.throws(() => checkScriptPolicy(src.replace('<head>', '<head><script>/* 检查顺序 */</script>')), /出现在页面资源之前/);
  assert.throws(() => checkScriptPolicy(src.replace("default-src 'none'", "default-src 'self'")), /本地处理限制/);
  assert.throws(() => checkScriptPolicy(src.replace("form-action 'none'", "form-action 'none'; connect-src 'self'")), /覆盖限制/);
  assert.throws(() => checkScriptPolicy(src.replace("default-src 'none'", "default-src 'none'; default-src 'self'")), /重复的 CSP 指令/);
  console.log('ok    CSP placement, restrictions and script hashes');
  checkBitLength();
  checkDurationFormat();
  checkFileMetadata();
  checkSelfTestVectors();
  checkComparison();
  const sizes = [];
  for (let i = 0; i <= 300; i += 1) sizes.push(i);
  sizes.push(4096, 65537, 1048576 + 13);

  for (const {id} of ALGORITHMS) {
    for (const size of sizes) {
      const buf = fixture(size);
      const want = expected(id, buf);
      assert.strictEqual(digestBytes(id, buf), want, `${id} 一次性计算失败 (${size} 字节)`);
      const hasher = createHasher(id);
      for (let offset = 0; offset < size;) {
        const step = 1 + randomWord() % 200;
        hasher.update(buf.subarray(offset, offset + step));
        offset += step;
      }
      assert.strictEqual(hasher.digest(), want, `${id} 分块计算失败 (${size} 字节)`);
    }
    console.log('ok   ', id);
  }

  const buf = fixture(3 * 1048576 + 7);
  for (const ids of [['SHA-256'], ['SHA-256', 'MD5', 'SHA3-256'], ['MD5', 'SHA-512/256']]) {
    const results = await hashFile(new Blob([buf]), ids, freshSignal(), () => {});
    results.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile ${item.algorithm}`));
  }
  // 一次性读取失败时应退回到流式处理，结果保持一致。
  const flaky = new Blob([buf]);
  flaky.arrayBuffer = () => Promise.reject(new Error('out of memory'));
  const fallback = await hashFile(flaky, ['SHA-256', 'MD5'], freshSignal(), () => {});
  fallback.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile fallback ${item.algorithm}`));
  // 一次性读取没有报错、却只读到一部分时，同样不能算出截断数据的摘要，应退回流式处理。
  const shortFirstRead = new Blob([buf]);
  shortFirstRead.arrayBuffer = () => Promise.resolve(buf.slice(0, 1048576).buffer.slice(buf.byteOffset, buf.byteOffset + 1048576));
  const shortFallback = await hashFile(shortFirstRead, ['SHA-256', 'MD5'], freshSignal(), () => {});
  shortFallback.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile short-read fallback ${item.algorithm}`));
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
    const results = await hashFile(legacy, streaming ? ['MD5'] : ['SHA-256', 'MD5'], freshSignal(), () => {});
    results.forEach(item => assert.strictEqual(item.hex, expected(item.algorithm, buf), `hashFile legacy ${item.algorithm}`));
  }
  delete globalThis.FileReader;
  // 流式读取若在中途返回空分块，应直接报错而不是算出截断后的错误摘要。
  const truncated = {
    size: 2 * 1048576,
    slice: start => new Blob(start === 0 ? [buf.subarray(0, 1048576)] : [])
  };
  await assert.rejects(hashFile(truncated, ['MD5'], freshSignal(), () => {}), /Unexpected file read length/);
  // 分块非空但比应有的短，同样不能悄悄算下去。
  const short = {
    size: 2 * 1048576,
    slice: start => new Blob([buf.subarray(0, start === 0 ? 1048576 : 1000)])
  };
  await assert.rejects(hashFile(short, ['MD5'], freshSignal(), () => {}), /Unexpected file read length/);
  // 读取超过请求的范围也不能算出包含额外字节的错误摘要（包括不足一块的末块）。
  for (const [size, badOffset] of [[2 * 1048576, 0], [1048576 + 1000, 1048576]]) {
    const oversized = {
      size,
      slice: (start, end) => new Blob([buf.subarray(start, Math.min(end + (start === badOffset ? 1 : 0), size + 1))])
    };
    await assert.rejects(hashFile(oversized, ['MD5'], freshSignal(), () => {}), /Unexpected file read length/);
  }
  // 末块本来就比分块小，完整读到时照常通过。
  const oddSize = 1048576 + 1000;
  const odd = {size: oddSize, slice: (start, end) => new Blob([buf.subarray(start, Math.min(end, oddSize))])};
  const oddResult = await hashFile(odd, ['MD5'], freshSignal(), () => {});
  assert.strictEqual(oddResult[0].hex, crypto.createHash('md5').update(buf.subarray(0, oddSize)).digest('hex'));
  const empty = await hashFile(new Blob([]), ['MD5'], freshSignal(), () => {});
  assert.strictEqual(empty[0].hex, expected('MD5', Buffer.alloc(0)));
  const gone = {size: 0, arrayBuffer: async () => { throw new Error('file was removed'); }};
  await assert.rejects(hashFile(gone, ['MD5'], freshSignal(), () => {}), /file was removed/);
  const changedEmpty = {size: 0, arrayBuffer: async () => new ArrayBuffer(1)};
  await assert.rejects(hashFile(changedEmpty, ['MD5'], freshSignal(), () => {}), /Unexpected file read length/);
  for (const value of [null, 0, new Uint8Array(0)]) {
    for (const algorithm of ['MD5', 'SHA-256']) {
      const unread = {size: 0, arrayBuffer: async () => value};
      await assert.rejects(hashFile(unread, [algorithm], freshSignal(), () => {}), /Invalid file read buffer/);
    }
  }
  const invalidNative = loadHashroom({digest: async () => 32});
  assert.deepStrictEqual(await invalidNative.hashFile(new Blob(['abc']), ['SHA-256'], freshSignal(), () => {}),
    [{algorithm: 'SHA-256', hex: expected('SHA-256', Buffer.from('abc'))}]);
  for (const size of [-1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    const invalidFile = {size, arrayBuffer() { assert.fail('无效大小不应触发读取'); }};
    await assert.rejects(hashFile(invalidFile, ['SHA-256'], freshSignal(), () => {}), /Invalid file size/);
  }
  console.log('ok    hashFile');
  await checkCancellation();
  await checkLargeStream();

  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const spaced = sha256.match(/.{8}/g).join(' ');
  for (const file of ['cafe  edition.iso', '   leading spaces.iso']) {
    const groupedRecord = parseExpected(`${spaced}  ${file}`);
    assert.deepStrictEqual(groupedRecord.entries, [{algorithm: null, hex: sha256, file, path: file}]);
  }
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
  // GNU coreutils 的文件名转义不能把带名字的条目变成无名条目。
  for (const [line, algorithm, file] of [
    [`\\${sha256}  a\\nb.txt`, null, 'a\nb.txt'],
    [`\\${sha256} *dir\\\\x.bin`, null, 'dir\\x.bin'],
    [`\\SHA256 (a\\rb.txt) = ${sha256}`, 'SHA-256', 'a\rb.txt'],
    [`${sha256}   padded  name  `, null, ' padded  name  '],
    [`SHA256 (a\u200bb\u3000c) = ${sha256}`, 'SHA-256', 'a\u200bb\u3000c']
  ]) {
    const parsed = parseExpected(line);
    assert.deepStrictEqual(parsed.entries.map(entry => [entry.algorithm, entry.hex, entry.file]), [[algorithm, sha256, file]], line);
    assert.strictEqual(entriesForFile(parsed.entries, file).entries.length, 1);
    assert.strictEqual(entriesForFile(parsed.entries, 'elsewhere').entries.length, 0);
  }
  assert.strictEqual(parseExpected(`\\${sha256}  bad\\q.iso`).invalid, true);
  for (const file of ['win\\unix', 'line\u2028separator', 'para\u2029separator']) {
    const lines = [`SHA2-256(${file})= ${sha256}`];
    if (!file.includes('\\')) lines.push(`${sha256}  ${file}`);
    for (const line of lines) {
      const parsed = parseExpected(line);
      assert.deepStrictEqual(parsed.entries.map(entry => entry.file), [file]);
      assert.strictEqual(entriesForFile(parsed.entries, file).entries.length, 1);
    }
  }
  for (const file of ['cafe  edition.iso', 'cafe beef  edition.iso', 'a'.repeat(24), '   padded.txt']) {
    const parsed = parseExpected(`cbf43926  ${file}`);
    assert.deepStrictEqual(parsed.entries, [{algorithm: null, hex: 'cbf43926', file, path: file}]);
    assert.deepStrictEqual(entriesForFile(parsed.entries, 'other.txt', parsed.files).entries, []);
  }
  const brokenManifest = parseExpected(`${sha256}  a/same.iso\nfffffff  b/same.iso`);
  assert.strictEqual(brokenManifest.invalidLines, 1);
  assert.deepStrictEqual(brokenManifest.files.map(entry => entry.path), ['a/same.iso', 'b/same.iso']);
  assert.strictEqual(entriesForFile(brokenManifest.entries, 'same.iso', brokenManifest.files).issue, 'ambiguous');
  // 网页上复制来的哈希可能用不换行空格、全角空格分组或夹带零宽字符；文件名可能是 NFD 形式。
  for (const space of ['\u00a0', '\u3000', '\u2028', '\u2029', '\u202f']) {
    const parsed = parseExpected(`SHA-256:${space}${sha256.match(/.{8}/g).join(space)}`);
    assert.deepStrictEqual(parsed.entries.map(entry => [entry.algorithm, entry.hex]), [['SHA-256', sha256]], JSON.stringify(space));
  }
  assert.strictEqual(parseExpected(`\u200b${sha256.slice(0, 32)}\u200b${sha256.slice(32)}  a.iso`).entries[0].hex, sha256);
  const composed = parseExpected(`${sha256}  caf\u00e9.iso\nd41d8cd98f00b204e9800998ecf8427e  other.iso`);
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
  for (const line of [
    `SHA-256: ${sha256.slice(0, 56)}`,
    `SHA-256 (file) = ${sha256.slice(0, 56)}`,
    `sha384 ${sha256}`,
    `${sha256} trailing garbage`,
    `SHA-256: ${sha256}.zip`,
    `SHA-256: ${sha256} / ${sha256}`,
    `sha256-${sha256.slice(0, 56)}`,
    `UNKNOWN256 (file) = ${sha256}`,
    `SHA256 () = ${sha256}`
  ]) assert.strictEqual(parseExpected(line).invalid, true, line);
  const wrongLength = parseExpected(`SHA-256: ${sha256.slice(0, 56)}`);
  assert.deepStrictEqual(wrongLength.malformed, {algorithm: 'SHA-256', strayLength: 56});
  for (const separator of ['  ', '\t', ' , ', ' : ']) {
    const grouped = parseExpected(sha256.match(/.{8}/g).join(separator));
    assert.deepStrictEqual(grouped.entries.map(entry => [entry.hex, entry.file]), [[sha256, '']], separator);
  }
  const sri = ['sha256', 'sha384'].map(id => `${id}-${crypto.createHash(id).update('abc').digest('base64')}`);
  const sriResult = parseExpected(`${sri[0]}?option=1 ${sri[1]}`);
  assert.deepStrictEqual(sriResult.entries.map(entry => entry.algorithm), ['SHA-256', 'SHA-384']);
  const mixedSri = parseExpected(`future256-${Buffer.from(sha256, 'hex').toString('base64')} ${sri.join(' ')}`);
  assert.deepStrictEqual(mixedSri.entries, sriResult.entries);
  assert.deepStrictEqual(mixedSri.unsupported, ['future256']);
  assert.strictEqual(mixedSri.partialInvalid, true);
  assert.strictEqual(mixedSri.invalidLines, 1);
  assert.strictEqual(parseExpected('ordinary-text').unsupported.length, 0);
  assert.deepStrictEqual(parseExpected(`# ${sha256}\n; ${sha256}`).entries, []);
  const tooLarge = parseExpected(`${sha256}\n${'copy '.repeat(60000)}`);
  assert.strictEqual(tooLarge.tooLarge, true);
  assert.strictEqual(tooLarge.invalid, true);
  assert.deepStrictEqual(tooLarge.entries, []);
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
    'CRC32C: cbf43926',
    `SHAKE-128-256: ${sha256}`,
    `GOST256: ${sha256}`,
    '12345678 42 ./sample.zip',
    `12345678 42 ${'a'.repeat(22)}`, // 文件名全为十六进制字符、拼接后正好有 32 位。
    '1234 5678' // 从标准输入计算时没有文件名。
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
  assert.deepStrictEqual(mixed.entries, [{algorithm: 'SHA-256', hex: sha256, file: 'file.iso', path: 'file.iso'}]);
  assert.strictEqual(mixed.invalidLines, 0);
  const certBytes = '12 34 ' + 'a1 '.repeat(30).trim();
  assert.strictEqual(parseExpected(`SHA256 hash of file.iso:\n${certBytes}`).entries[0].hex, certBytes.replace(/ /g, ''));
  const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
  const hexName = 'a'.repeat(32);
  const separate = parseExpected(`SHA256 hash of current.iso:\n${md5}  ${hexName}`);
  assert.deepStrictEqual(separate.entries, [{algorithm: null, hex: md5, file: hexName, path: hexName}]);
  assert.strictEqual(entriesForFile(separate.entries, 'current.iso', separate.files).issue, 'unusable');
  assert.strictEqual(separate.invalidLines, 1);
  const windows = parseExpected(`Algorithm   Hash   Path\n---------   ----   ----\nSHA256       ${sha256}       C:\\Downloads\\test.iso`);
  assert.strictEqual(windows.invalidLines, 0);
  assert.deepStrictEqual(windows.entries.map(({algorithm, file}) => [algorithm, file]), [['SHA-256', 'test.iso']]);
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
  const missing = entriesForFile(list.entries, 'missing.iso');
  assert.strictEqual(missing.ignored, 4);
  assert.strictEqual(missing.issue, 'missing');
  assert.deepStrictEqual(missing.entries, list.entries.slice(-1));
  const ambiguous = parseExpected(`${sha256}  a/same.iso\nSHA256 (b/same.iso) = ${sha256.slice(1)}`);
  const scoped = entriesForFile(ambiguous.entries, 'same.iso', ambiguous.files);
  assert.strictEqual(scoped.issue, 'ambiguous');
  assert.deepStrictEqual(scoped.entries, []);
  const normalized = parseExpected(`${sha256}  café.iso\n${'f'.repeat(64)}  cafe\u0301.iso`);
  assert.strictEqual(entriesForFile(normalized.entries, 'café.iso').entries[0].hex, sha256);
  assert.strictEqual(entriesForFile(normalized.entries, 'cafe\u0301.iso').entries[0].hex, 'f'.repeat(64));
  const unusable = parseExpected(`SHA256 (a.iso) = ${sha256.slice(1)}\n${sha256}  b.iso`);
  assert.strictEqual(entriesForFile(unusable.entries, 'a.iso', unusable.files).issue, 'unusable');
  const base64 = parseExpected(`sha256sum ${Buffer.from(sha256, 'hex').toString('base64')} *other.iso`);
  assert.strictEqual(entriesForFile(base64.entries, 'a.iso').entries.length, 0);
  assert.strictEqual(entriesForFile(list.entries, '').entries.length, 5);
  // 只用一个空格或制表符分隔哈希与文件名的清单（脚本输出、表格粘贴）也要认出文件名，才能按文件筛选。
  assert.deepStrictEqual(parseExpected(`${sha256} ubuntu.iso`).entries.map(entry => entry.file), ['ubuntu.iso']);
  assert.deepStrictEqual(parseExpected(`${sha256}\t./sub/other.iso`).entries.map(entry => entry.file), ['other.iso']);
  assert.deepStrictEqual(parseExpected(`sha256sum ${sha256} dir/win.iso`).entries.map(entry => [entry.algorithm, entry.file]), [['SHA-256', 'win.iso']]);
  assert.deepStrictEqual(parseExpected(`${sha256} LICENSE`).entries.map(entry => entry.file), ['LICENSE']);
  assert.deepStrictEqual(parseExpected(`sha256sum ${sha256}\t说明`).entries.map(entry => [entry.algorithm, entry.file]), [['SHA-256', '说明']]);
  assert.strictEqual(parseExpected(`${sha256} *`).invalid, true); // 不是名为 * 的单空格条目。
  assert.strictEqual(parseExpected(`SHA-256 ${sha256} / ${sha256}`).invalid, true);
  // 分隔符后是另一段十六进制（分组哈希的后续片段）时不能当成文件名。
  assert.deepStrictEqual(parseExpected(`${sha256.slice(0, 32)} ${sha256.slice(32)}`).entries, [{algorithm: null, hex: sha256, file: ''}]);
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
  const paddingStart = performance.now();
  const padded = parseExpected(`ab${' '.repeat(2030)}\n`.repeat(125));
  assert.strictEqual(padded.invalidLines, 125);
  assert.ok(performance.now() - paddingStart < 300, '带大量行尾空格的输入解析太慢');
  console.log('ok    parseExpected');
}

// 测试运行器会把始终未完成的 Promise 计为失败，而不是让空闲事件循环正常退出。
require('node:test').test('Hashroom 回归', {timeout: 60000}, main);
