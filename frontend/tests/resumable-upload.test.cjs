/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

const source = fs.readFileSync(require.resolve("../lib/resumable-upload.ts"), "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const calls = [];
const exportsObject = {};
vm.runInNewContext(output, {
  exports: exportsObject,
  require: name => name === "./api" ? { api: {
    post: async (...args) => { calls.push(["post", ...args]); return { id: "published" }; },
    patch: async (...args) => { calls.push(["patch", ...args]); return args[0]; },
    get: async (...args) => { calls.push(["get", ...args]); return args[0]; },
  } } : {},
});

const session = { id: "session-1", file_id: "file-1", total_bytes: 4, offset: 4, chunk_size: 4, status: "complete", expires_at: "never" };
const payload = { metadata_ciphertext_b64: "a", metadata_iv_b64: "b", encrypted_kf_b64: "c", encrypted_kf_iv_b64: "d", file_iv_b64: "e" };

test("finalization publishes metadata only after the upload reaches its terminal offset", async () => {
  assert.deepEqual(await exportsObject.finalizeResumableUpload(session, payload, "token"), { id: "published" });
  assert.deepEqual(calls[0], ["post", "upload-sessions/session-1/finalize", payload, "token"]);
  assert.deepEqual(await exportsObject.finalizeResumableUpload({ ...session, status: "finalized" }, payload, "token"), { id: "published" });
  await assert.rejects(exportsObject.finalizeResumableUpload({ ...session, offset: 3 }, payload, "token"), /not complete/);
  assert.equal(calls.length, 2);
});
