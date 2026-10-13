/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");
const { webcrypto } = require("node:crypto");

const source = fs.readFileSync(require.resolve("../lib/owner-download.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function buildChunkIv(nonce, index) {
  const iv = new Uint8Array(nonce);
  new DataView(iv.buffer).setUint32(8, index, false);
  return iv;
}

function loadOwnerDownload() {
  const exports = {};
  vm.runInNewContext(compiled, {
    exports,
    crypto: webcrypto,
    performance,
    Blob,
    Response,
    ReadableStream,
    DOMException,
    AbortController,
    Uint8Array,
    ArrayBuffer,
    DataView,
    TextEncoder,
    document: undefined,
    window: undefined,
    URL,
    require(name) {
      if (name === "./api") return { api: {} };
      if (name === "./crypto/base") return { b64ToBuf: value => Uint8Array.from(Buffer.from(value, "base64")).buffer };
      if (name === "./crypto/aes") return { buildChunkAad: (version, fileId, index, length) => new TextEncoder().encode(`vaultx-chunk|v${version}|${fileId}|${index}|${length}`) };
      if (name === "./crypto/chunking") return { buildChunkIv, CHUNK_FORMAT_VERSION: 1, CHUNK_SIZE: 32 };
      throw new Error(`Unexpected module ${name}`);
    },
  });
  return exports;
}

const { downloadOwnerFile } = loadOwnerDownload();
const nonce = Uint8Array.from({ length: 12 }, (_, index) => index);
const fileIv = Buffer.from(nonce).toString("base64");
const chunkSize = 8;

async function framedFixture() {
  const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["decrypt", "encrypt"]);
  const plain = Uint8Array.from({ length: 11 }, (_, index) => index + 1);
  const frames = [];
  for (let index = 0; index < 2; index += 1) {
    const part = plain.slice(index * chunkSize, (index + 1) * chunkSize);
    frames.push(new Uint8Array(await webcrypto.subtle.encrypt({
      name: "AES-GCM",
      iv: buildChunkIv(nonce, index),
      additionalData: new TextEncoder().encode(`vaultx-chunk|v1|file-1|${index}|${part.byteLength}`),
    }, key, part)));
  }
  return { key, plain, ciphertext: new Uint8Array(frames.reduce((all, frame) => [...all, ...frame], [])) };
}

function responseFor(bytes, iv = fileIv) {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice(0, 7));
      controller.enqueue(bytes.slice(7));
      controller.close();
    },
  });
  return new Response(body, {
    status: 206,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Range": `bytes 0-${bytes.byteLength - 1}/${bytes.byteLength}`,
      "X-File-Iv": iv,
    },
  });
}

test("owner download decrypts frames directly into a sink without assembling ciphertext", async () => {
  const fixture = await framedFixture();
  const writes = [];
  const result = await downloadOwnerFile({
    fileId: "file-1",
    token: "token",
    fileName: "fixture.bin",
    key: fixture.key,
    chunkSize,
    expectedPlaintextSize: fixture.plain.byteLength,
    createSink: async () => ({ write: value => writes.push(new Uint8Array(value)), close() {} }),
    request: async () => responseFor(fixture.ciphertext),
  });
  assert.equal(result.status, "completed");
  assert.deepEqual(Array.from(new Uint8Array(writes.reduce((all, part) => [...all, ...part], []))), Array.from(fixture.plain));
});

test("abort preserves pause state at a frame boundary and cancel drops it", async () => {
  for (const intent of ["pause", "cancel"]) {
    const controller = new AbortController();
    controller.abort();
    const result = await downloadOwnerFile({
      fileId: "file-1", token: "token", fileName: "fixture.bin", key: {},
      chunkSize, signal: controller.signal, intent: () => intent,
      request: async () => { throw new DOMException("aborted", "AbortError"); },
      createSink: async () => null,
    });
    assert.equal(result.status, intent === "pause" ? "paused" : "cancelled");
    if (result.status === "paused") assert.equal(result.resume.ciphertextOffset % (chunkSize + 16), 0);
  }
});
