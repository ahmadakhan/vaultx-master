/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const vm = require("node:vm");
const ts = require("typescript");
const { webcrypto } = require("node:crypto");

// Same in-memory TypeScript compilation as the security harness, isolated so
// controlled crypto and buffer observers never patch the process globals.
function load(crypto = webcrypto, Bytes = Uint8Array) {
  const compile = name => ts.transpileModule(fs.readFileSync(require.resolve(`../lib/crypto/${name}.ts`), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const base = { exports: {} };
  vm.runInNewContext(compile("base"), { exports: base.exports, Uint8Array, atob, btoa });
  const exports = {};
  vm.runInNewContext(compile("chunking"), {
    exports, require: () => base.exports, crypto, Uint8Array: Bytes, DataView,
  });
  return exports;
}
const { CHUNK_SIZE, buildChunkIv, decryptChunkedGCM } = load();
const nonce = Uint8Array.from({ length: 12 }, (_, i) => i);
const iv = Buffer.from(nonce).toString("base64");
const chunkSize = 32;

async function seal(length) {
  const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plain = Uint8Array.from({ length }, (_, i) => i % 251);
  const chunks = [];
  for (let i = 0; i < Math.max(1, Math.ceil(length / chunkSize)); i++) {
    chunks.push(Buffer.from(await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv: buildChunkIv(nonce, i) }, key,
      plain.slice(i * chunkSize, (i + 1) * chunkSize),
    )));
  }
  return { key, plain, ciphertext: Uint8Array.from(Buffer.concat(chunks)).buffer };
}

test("roundtrip preserves empty, partial, full and multiple chunks, with optional size", async () => {
  for (const length of [0, 1, 31, 32, 33, 64, 101]) {
    const { key, plain, ciphertext } = await seal(length);
    for (const expected of [undefined, length]) {
      assert.deepEqual(new Uint8Array(await decryptChunkedGCM(ciphertext, key, iv, chunkSize, expected)), plain);
    }
  }
});

test("later-chunk tampering returns a generic failure", async () => {
  const { key, ciphertext } = await seal(96);
  new Uint8Array(ciphertext)[48 + 3] ^= 1;
  await assert.rejects(decryptChunkedGCM(ciphertext, key, iv, chunkSize, 96),
    { message: "File decryption failed (wrong key or corrupted data)" });
});

test("authenticated size detects whole-chunk truncation and partial truncation", async () => {
  const { key, ciphertext } = await seal(96);
  for (const removed of [1, 48, 96]) {
    await assert.rejects(decryptChunkedGCM(ciphertext.slice(0, -removed), key, iv, chunkSize, 96), /size/);
  }
  // Legacy framing alone cannot authenticate the total number of chunks.
  assert.equal((await decryptChunkedGCM(ciphertext.slice(0, -48), key, iv, chunkSize)).byteLength, 64);
});

test("invalid sizes, incomplete final tags and counter overflow fail before decrypt", async () => {
  let calls = 0;
  const decoder = load({ subtle: { decrypt: async () => { calls++; throw new Error("unexpected"); } } });
  for (const size of [0, -1, NaN, Infinity, 1.5, CHUNK_SIZE + 1, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(decoder.decryptChunkedGCM(new ArrayBuffer(48), {}, iv, size), /chunk size/);
  }
  for (const size of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1, 31, 33]) {
    await assert.rejects(decoder.decryptChunkedGCM(new ArrayBuffer(48), {}, iv, 32, size), /size/);
  }
  for (const length of [0, 1, 15, 49, 63, 64]) {
    await assert.rejects(decoder.decryptChunkedGCM(new ArrayBuffer(length), {}, iv, 32), /malformed/);
  }
  // Synthetic byteLength checks the pre-allocation counter bound without a
  // multi-terabyte allocation. No slice/decrypt should be attempted.
  await assert.rejects(decoder.decryptChunkedGCM({ byteLength: (2 ** 32 + 1) * 17 }, {}, iv, 1), /malformed/);
  for (const index of [-1, 0.5, NaN, Infinity, 2 ** 32, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => buildChunkIv(nonce, index), /chunk index/);
  }
  assert.deepEqual(Array.from(buildChunkIv(nonce, 0xffffffff).slice(8)), [255, 255, 255, 255]);
  assert.deepEqual(Array.from(nonce), Array.from({ length: 12 }, (_, i) => i));
  for (const badIv of ["!", "AA=="]) {
    await assert.rejects(decoder.decryptChunkedGCM(new ArrayBuffer(48), {}, badIv, 32), /Invalid file IV/);
  }
  assert.equal(calls, 0);
});

test("owned plaintext buffers are cleared on success, later failure and copy failure", async () => {
  for (const mode of ["success", "decrypt failure", "copy failure", "wrong length"]) {
    const parts = [];
    const outputs = [];
    class ObservedBytes extends Uint8Array {
      set(source, offset) {
        outputs.push(this);
        super.set(source, offset);
        if (mode === "copy failure") throw new Error("sensitive copy detail");
      }
    }
    const decoder = load({ subtle: { decrypt: async () => {
      if (parts.length) {
        assert.ok(parts[0].every(byte => byte === 0), "previous part cleared before next decrypt");
        if (mode === "decrypt failure") throw new Error("sensitive provider detail");
      }
      const part = new Uint8Array(mode === "wrong length" && parts.length ? 31 : 32).fill(73);
      parts.push(part);
      return part.buffer;
    } } }, ObservedBytes);
    const result = decoder.decryptChunkedGCM(new ArrayBuffer(96), {}, iv, 32, 64);
    if (mode === "success") {
      assert.ok(new Uint8Array(await result).every(byte => byte === 73));
    } else {
      await assert.rejects(result, { message: "File decryption failed (wrong key or corrupted data)" });
      assert.ok(outputs.length > 0);
      assert.ok(outputs.every(output => output.every(byte => byte === 0)), "accumulated plaintext cleared");
    }
    assert.ok(parts.every(part => part.every(byte => byte === 0)), "all returned temporary buffers cleared");
  }
});
