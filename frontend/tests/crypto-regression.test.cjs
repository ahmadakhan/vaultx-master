/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const ts = require("typescript");
const { webcrypto } = require("node:crypto");

globalThis.crypto = webcrypto;
require.extensions[".ts"] = (module, filename) => {
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  module._compile(output, filename);
};

const { aesEncryptArrayBuffer, aesDecryptArrayBuffer } = require("../lib/crypto/aes.ts");

async function key() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

test("AES-GCM roundtrip binds associated data", async () => {
  const aesKey = await key();
  const plain = new TextEncoder().encode("prototype crypto acceptance fixture");
  const sealed = await aesEncryptArrayBuffer(plain.buffer, aesKey, undefined, "vaultx:acceptance:v1");

  assert.deepEqual(
    new Uint8Array(await aesDecryptArrayBuffer(sealed.ciphertext_b64, sealed.iv_b64, aesKey, "vaultx:acceptance:v1")),
    plain,
  );
  await assert.rejects(
    aesDecryptArrayBuffer(sealed.ciphertext_b64, sealed.iv_b64, aesKey, "vaultx:acceptance:wrong"),
  );
});

test("AES-GCM uses a fresh 12-byte IV for independent messages", async () => {
  const aesKey = await key();
  const plain = new Uint8Array([1, 2, 3, 4]).buffer;
  const first = await aesEncryptArrayBuffer(plain, aesKey);
  const second = await aesEncryptArrayBuffer(plain, aesKey);

  assert.equal(Buffer.from(first.iv_b64, "base64").byteLength, 12);
  assert.equal(Buffer.from(second.iv_b64, "base64").byteLength, 12);
  assert.notEqual(first.iv_b64, second.iv_b64);
});

test("AES-GCM rejects ciphertext modification", async () => {
  const aesKey = await key();
  const sealed = await aesEncryptArrayBuffer(new Uint8Array([9, 8, 7]).buffer, aesKey);
  const ciphertext = Buffer.from(sealed.ciphertext_b64, "base64");
  ciphertext[0] ^= 1;
  await assert.rejects(aesDecryptArrayBuffer(ciphertext.toString("base64"), sealed.iv_b64, aesKey));
});
