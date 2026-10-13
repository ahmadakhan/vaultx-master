/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const ts = require("typescript");
const { webcrypto } = require("node:crypto");
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Compile the real TypeScript modules in memory; no second implementation of
// the algorithms and no generated code or key material written to disk.
require.extensions[".ts"] = (module, filename) => {
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  module._compile(output, filename);
};
const { bufToB64, b64ToBuf } = require("../lib/crypto/base.ts");
const { aesEncryptArrayBuffer, aesDecryptArrayBuffer } = require("../lib/crypto/aes.ts");
const { CHUNK_SIZE, buildChunkIv, decryptChunkedGCM, encryptChunkSecure, decryptChunkSecure } = require("../lib/crypto/chunking.ts");
const { deriveMasterKey, generateFileKey } = require("../lib/crypto/keys.ts");
const { prepareUserKeyBundle } = require("../lib/crypto/setupUserKeys.ts");
const { unlockUserKeyBundle } = require("../lib/crypto/bundle.ts");
const { encryptWithPassphrase, decryptWithPassphrase, shareLinkPassphrase } = require("../lib/crypto/passphrase.ts");
const session = require("../lib/crypto/context.ts");
const { api } = require("../lib/api.ts");

async function sealedFile(plain, chunkSize = 32) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = [];
  for (let i = 0; i < Math.max(1, Math.ceil(plain.length / chunkSize)); i++) {
    const ct = await aesEncryptArrayBuffer(plain.slice(i * chunkSize, (i + 1) * chunkSize).buffer, key, buildChunkIv(nonce, i));
    sealed.push(Buffer.from(b64ToBuf(ct.ciphertext_b64)));
  }
  return { key, iv: bufToB64(nonce.buffer), ciphertext: Uint8Array.from(Buffer.concat(sealed)).buffer };
}

test("chunk framing roundtrips empty, single, boundary and multi-chunk files", async () => {
  for (const length of [0, 1, 31, 32, 33, 96, 101]) {
    const plain = Uint8Array.from({ length }, (_, i) => i % 251);
    const { key, iv, ciphertext } = await sealedFile(plain);
    assert.deepEqual(new Uint8Array(await decryptChunkedGCM(ciphertext, key, iv, 32, length)), plain);
  }
});

test("tampering, whole-chunk truncation, IV counter overflow and malformed framing fail closed", async () => {
  const { key, iv, ciphertext } = await sealedFile(new Uint8Array(96));
  const changed = ciphertext.slice(0);
  new Uint8Array(changed)[0] ^= 1;
  await assert.rejects(decryptChunkedGCM(changed, key, iv, 32, 96));
  await assert.rejects(decryptChunkedGCM(ciphertext.slice(0, -48), key, iv, 32, 96), /size/);
  for (const size of [0, -1, NaN, Infinity, 1.5]) await assert.rejects(decryptChunkedGCM(ciphertext, key, iv, size));
  for (const index of [-1, 2 ** 32, 0.5]) assert.throws(() => buildChunkIv(new Uint8Array(12), index));
});

test("production 5MiB boundary and sliced IVs retain the actual encryption nonce", async () => {
  const plain = new Uint8Array(CHUNK_SIZE + 17).fill(37);
  const { key, iv, ciphertext } = await sealedFile(plain, CHUNK_SIZE);
  assert.deepEqual(new Uint8Array(await decryptChunkedGCM(ciphertext, key, iv, CHUNK_SIZE, plain.length)), plain);
  const backing = crypto.getRandomValues(new Uint8Array(24));
  const sealed = await aesEncryptArrayBuffer(new Uint8Array([1, 2, 3]).buffer, key, backing.subarray(4, 16));
  assert.equal(b64ToBuf(sealed.iv_b64).byteLength, 12);
  assert.deepEqual(new Uint8Array(await aesDecryptArrayBuffer(sealed.ciphertext_b64, sealed.iv_b64, key)), new Uint8Array([1, 2, 3]));
});

test("AES-GCM accepts string additionalData and preserves versioned bundle binding", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plain = new Uint8Array([1, 2, 3, 4, 5]);
  const sealed = await aesEncryptArrayBuffer(plain.buffer, key, undefined, "vaultx:key-bundle:v2:master");
  const recovered = new Uint8Array(await aesDecryptArrayBuffer(sealed.ciphertext_b64, sealed.iv_b64, key, "vaultx:key-bundle:v2:master"));
  assert.deepEqual(recovered, plain);

  const bundle = await prepareUserKeyBundle("Synthetic Password 123!");
  assert.equal(bundle.key_bundle_version, 2);
  assert.equal(bundle.kdf_iterations, 600000);
  const keys = await unlockUserKeyBundle("Synthetic Password 123!", bundle);
  assert.equal(b64ToBuf(keys.masterKey_b64).byteLength, 32);
  const priv = await crypto.subtle.importKey("pkcs8", b64ToBuf(keys.privateKey_b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const pub = await crypto.subtle.importKey("spki", b64ToBuf(keys.publicKey_b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, b64ToBuf(keys.masterKey_b64));
  assert.equal(bufToB64(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, wrapped)), keys.masterKey_b64);
  await assert.rejects(unlockUserKeyBundle("wrong password", bundle));
  await assert.rejects(unlockUserKeyBundle("Synthetic Password 123!", { ...bundle, enc_master_key_b64: bundle.enc_search_key_b64, enc_master_key_iv: bundle.enc_search_key_iv }));
  await assert.rejects(unlockUserKeyBundle("Synthetic Password 123!", { ...bundle, key_bundle_version: 999 }), /version/);
});

test("versioned chunk format uses deterministic AAD and ciphertext||tag framing", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const nonce = new Uint8Array(12).fill(7);
  const plain = Uint8Array.from([1, 2, 3, 4]).buffer;
  const options = { tenantId: "tenant-a" };
  const first = await encryptChunkSecure(plain, key, nonce, 3, options);
  const second = await encryptChunkSecure(plain, key, nonce, 3, options);
  assert.equal(first.formatVersion, 1);
  assert.equal(first.encryptedAt, 0);
  assert.equal(first.ciphertext_b64, second.ciphertext_b64);
  assert.deepEqual(new Uint8Array(await decryptChunkSecure(first, key, nonce)), new Uint8Array(plain));
  await assert.rejects(decryptChunkSecure({ ...first, tenantId: "other" }, key, nonce));
});

test("legacy bundles retain the 150k PBKDF2 contract", async () => {
  const { key, salt_b64 } = await deriveMasterKey("old password");
  const raw = new Uint8Array(32).fill(19);
  const wrapped = await aesEncryptArrayBuffer(raw.buffer, key);
  const fixture = { password_salt_b64: salt_b64, public_key_b64: "unused" };
  for (const role of ["master", "search", "private"]) {
    fixture[`enc_${role}_key_b64`] = wrapped.ciphertext_b64;
    fixture[`enc_${role}_key_iv`] = wrapped.iv_b64;
  }
  assert.equal((await unlockUserKeyBundle("old password", fixture)).masterKey_b64, bufToB64(raw.buffer));
  await assert.rejects(deriveMasterKey("x", salt_b64, 10000001), /KDF/);
  await assert.rejects(deriveMasterKey("x", "AA=="), /salt/);
  const derived = await deriveMasterKey("old password", salt_b64, 600000);
  await assert.rejects(aesDecryptArrayBuffer(wrapped.ciphertext_b64, wrapped.iv_b64, derived.key));
});

test("new share wraps require the fragment secret, not server-known file ID or access code", async () => {
  const secret = await generateFileKey();
  const fileKey = await generateFileKey();
  const wrapped = await encryptWithPassphrase(fileKey, secret);
  const fullUrl = new URL(`https://vault.example/shared/synthetic#key=${encodeURIComponent(secret)}`);
  assert.equal(fullUrl.search, "");
  const recovered = new URLSearchParams(fullUrl.hash.slice(1)).get("key");
  assert.equal(bufToB64(await decryptWithPassphrase(wrapped.ciphertext_b64, wrapped.iv_b64, wrapped.salt_b64, recovered)), fileKey);
  for (const guess of [shareLinkPassphrase("synthetic-file-id"), "access-code-known-by-server"]) {
    await assert.rejects(decryptWithPassphrase(wrapped.ciphertext_b64, wrapped.iv_b64, wrapped.salt_b64, guess));
  }
});

function fakeStorage() {
  const values = new Map([["vaultx_master_key", "legacy-secret"], ["unrelated", "keep"]]);
  return { get length() { return values.size; }, key: i => [...values.keys()][i], removeItem: k => values.delete(k), values };
}

test("unlocked state is memory-only; logout clears keys without clearing unrelated storage", () => {
  const localStorage = fakeStorage(), sessionStorage = fakeStorage();
  globalThis.window = { localStorage, sessionStorage };
  const ctx = { accessToken: "synthetic", masterKey_b64: "master", searchKey_b64: "search", privateKey_b64: "private", publicKey_b64: "public" };
  session.setVaultXContext(ctx);
  session.memorySession.setItem("vaultx_kf_fixture", "file-key");
  assert.equal(session.getVaultXContext(), ctx);
  for (const storage of [localStorage, sessionStorage]) assert.deepEqual([...storage.values], [["unrelated", "keep"]]);
  session.clearVaultXContext();
  assert.equal(session.memorySession.getItem("vaultx_kf_fixture"), null);
  assert.equal(session.getSessionContext(), null);
  assert.throws(session.getVaultXContext, /log in again/);
  delete globalThis.window;
});

test("API normalizes paths, keeps access codes in headers, and handles validation/malformed errors", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url, "/api/shares/link/synthetic");
      assert.equal(init.headers.get("X-Access-Code"), "synthetic-code");
      assert.equal(init.cache, "no-store");
      return new Response(JSON.stringify({ detail: [{ msg: "Invalid value", input: "SECRET" }] }), { status: 422 });
    };
    await assert.rejects(api.get("/shares/link/synthetic", undefined, { "X-Access-Code": "synthetic-code" }), error => error.message === "Invalid value" && error.status === 422);
    globalThis.fetch = async () => new Response("not JSON", { status: 200 });
    await assert.rejects(api.get("/files"), /invalid response/);
    globalThis.fetch = async () => new Response(null, { status: 204 });
    assert.deepEqual(await api.delete("/files/synthetic"), {});
  } finally { globalThis.fetch = originalFetch; }
});
