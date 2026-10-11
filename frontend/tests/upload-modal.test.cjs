/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const vm = require("node:vm");
const ts = require("typescript");
const { webcrypto } = require("node:crypto");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Exercise the real component's callbacks with a minimal hook/JSX harness.
// Requests are controlled so pause/stop can land while a chunk is in flight.
function harness({ importKey } = {}) {
  const slots = [];
  let cursor = 0;
  const requests = [], rawKeys = [], plaintext = [], alerts = [];
  const session = new Map([
    ["vaultx_access_token", "fixture"],
    ["vaultx_master_key", Buffer.alloc(32, 7).toString("base64")],
    ["vaultx_search_key", Buffer.alloc(32, 8).toString("base64")],
  ]);
  const jsx = (type, props) => ({ type, props });
  const modules = {
    react: {
      useState: initial => { const i = cursor++; if (!(i in slots)) slots[i] = initial; return [slots[i], value => { slots[i] = typeof value === "function" ? value(slots[i]) : value; }]; },
      useRef: initial => { const i = cursor++; return slots[i] ||= { current: initial }; },
      useEffect: () => {},
    },
    "react/jsx-runtime": { jsx, jsxs: jsx },
    "@/lib/crypto/base": { genRandomBytes: n => webcrypto.getRandomValues(new Uint8Array(n)), bufToB64: b => Buffer.from(b).toString("base64") },
    "@/lib/crypto/keys": { generateFileKey: async () => Buffer.alloc(32, 9).toString("base64") },
    "@/lib/crypto/chunking": { CHUNK_SIZE: 4, buildChunkIv: () => new Uint8Array(12) },
    "@/lib/crypto/aes": {
      aesEncryptArrayBuffer: async (buffer, key, iv) => { if (iv) plaintext.push(buffer); return { ciphertext_b64: "AQ==", iv_b64: "AAAAAAAAAAAAAAAA" }; },
      encryptStringWithAes: async () => ({ ciphertext_b64: "AQ==", iv_b64: "AAAAAAAAAAAAAAAA" }),
    },
    "@/lib/crypto/context": { memorySession: { getItem: k => session.get(k), setItem: (k, v) => session.set(k, v) } },
    "@/lib/types": { errorMessage: error => error.message },
    "@/lib/api": { api: { post: (path, data) => { const pending = deferred(); requests.push({ path, data, ...pending }); return pending.promise; } } },
    mammoth: {},
  };
  const source = fs.readFileSync(require.resolve("../components/upload-modal.tsx"), "utf8");
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const exports = {};
  vm.runInNewContext(output, {
    exports, require: name => modules[name] || new Proxy({}, { get: (_, key) => key }),
    crypto: { randomUUID: () => webcrypto.randomUUID(), subtle: { importKey: async (_, raw) => { rawKeys.push(raw); return importKey ? importKey(rawKeys.length) : {}; } } },
    Uint8Array, TextEncoder, FormData, Blob, atob, performance, alert: message => alerts.push(message),
  });
  function render() { cursor = 0; return exports.UploadModal({ open: true, onOpenChange() {} }); }
  function find(predicate, node = render()) {
    if (!node || typeof node !== "object") return;
    if (predicate(node.props || {})) return node.props;
    for (const child of [node.props?.children].flat(Infinity)) { if (child === undefined) continue; const match = find(predicate, child); if (match) return match; }
  }
  async function add(name = "sample", size = 9) {
    const file = { name, size, type: "", slice: (start, end) => new Blob([new Uint8Array(end - start).fill(5)]) };
    find(p => p.onDrop).onDrop({ preventDefault() {}, stopPropagation() {}, dataTransfer: { files: [file] } });
    await until(() => slots[0].every(item => item.status !== "preparing"));
  }
  return { add, find, requests, rawKeys, plaintext, alerts, files: () => slots[0] };
}

async function until(predicate) {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail("Expected async boundary was not reached");
}

test("32-byte tokens, chunk-boundary pause, and locked resume preserve acknowledged cursor", async () => {
  const h = harness();
  await h.add();
  h.find(p => p.placeholder).onChange({ target: { value: "sample" } });
  h.find(p => p.children === "Add").onClick();
  const done = h.find(p => p.children === "Start / resume queue").onClick;
  const running = done();
  await done(); // second click before rendering cannot start another worker
  await until(() => h.requests.length === 1);
  const tokens = JSON.parse(h.requests[0].data.get("tokens_json"));
  assert.equal(Buffer.from(tokens[0].token, "base64").length, 32);
  h.find(p => p["aria-label"] === "Pause sample").onClick();
  assert.equal(h.files()[0].status, "pausing");
  assert.equal(h.find(p => p["aria-label"] === "Resume sample"), undefined);
  await done();
  assert.equal(h.requests.length, 1);
  h.requests[0].resolve({});
  await running;
  assert.equal(h.files()[0].status, "paused");
  assert.equal(h.files()[0].pausedAtChunk, 1);
  const resume = h.find(p => p["aria-label"] === "Resume sample").onClick;
  const resumed = resume();
  await resume();
  await until(() => h.requests.length === 2);
  assert.equal(h.requests[1].data.get("chunk_index"), "1");
  h.requests[1].resolve({});
  await until(() => h.requests.length === 3);
  h.requests[2].resolve({});
  await until(() => h.requests.length === 4);
  assert.equal(h.requests[3].path, "/user/index_state");
  h.requests[3].resolve({});
  await resumed;
  assert.equal(h.files()[0].status, "completed");
  assert.ok(h.rawKeys.every(bytes => bytes.every(value => value === 0)));
  assert.ok(h.plaintext.every(buffer => new Uint8Array(buffer).every(value => value === 0)));
});

test("stop survives request success or failure without changing queued files", async () => {
  for (const fail of [false, true]) {
    const h = harness();
    await h.add(); await h.add("queued");
    const running = h.find(p => p.children === "Start / resume queue").onClick();
    await until(() => h.requests.length === 1);
    h.find(p => p["aria-label"] === "Abort sample").onClick();
    if (fail) h.requests[0].reject(new Error("network failure"));
    else h.requests[0].resolve({});
    await running;
    assert.equal(h.files()[0].status, "stopped");
    assert.equal(h.files()[0].uploadedBytes, 0);
    assert.equal(h.files()[1].status, "pending");
    assert.equal(h.requests.length, 1);
    assert.ok(h.plaintext.every(buffer => new Uint8Array(buffer).every(value => value === 0)));
    assert.ok(h.rawKeys.every(bytes => bytes.every(value => value === 0)));
  }
});

test("stop during the final request keeps stopped state while publishing its search head", async () => {
  const h = harness(); await h.add("sample", 1);
  const running = h.find(p => p.children === "Start / resume queue").onClick();
  await until(() => h.requests.length === 1);
  h.find(p => p["aria-label"] === "Abort sample").onClick();
  h.requests[0].resolve({});
  await until(() => h.requests.length === 2);
  assert.equal(h.requests[1].path, "/user/index_state");
  h.requests[1].resolve({});
  await running;
  assert.equal(h.files()[0].status, "stopped");
});

test("stop during preparation prevents the first request and wipes raw keys", async () => {
  const preparation = deferred();
  const h = harness({ importKey: count => count === 2 ? preparation.promise : {} });
  await h.add();
  const running = h.find(p => p.children === "Start / resume queue").onClick();
  await until(() => h.rawKeys.length === 2);
  h.find(p => p["aria-label"] === "Abort sample").onClick();
  preparation.resolve({});
  await running;
  assert.equal(h.files()[0].status, "stopped");
  assert.equal(h.requests.length, 0);
  assert.ok(h.rawKeys.every(bytes => bytes.every(value => value === 0)));
});

test("failed key imports wipe owned bytes and only fail the active file", async () => {
  const h = harness({ importKey: count => { if (count === 3) throw new Error("import failed"); return {}; } });
  await h.add(); await h.add("queued");
  await h.find(p => p.children === "Start / resume queue").onClick();
  assert.equal(h.files()[0].status, "error");
  assert.equal(h.files()[1].status, "pending");
  assert.equal(h.requests.length, 0);
  assert.ok(h.rawKeys.every(bytes => bytes.every(value => value === 0)));
});
