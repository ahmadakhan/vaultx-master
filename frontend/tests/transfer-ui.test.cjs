/* eslint-disable @typescript-eslint/no-require-imports */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const ts = require("typescript");
const exportsObject = {};
vm.runInNewContext(ts.transpileModule(fs.readFileSync(require.resolve("../lib/transfer-ui.ts"), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports: exportsObject });
const { transferMetrics, transferBytes, transferEta } = exportsObject;

test("unknown totals and unsampled speeds remain unavailable", () => {
  assert.equal(transferMetrics(0, 0, 0).percent, null);
  assert.equal(transferMetrics(0, 100, 20).rate, null);
  assert.equal(transferMetrics(50, 0, 1000).eta, null);
  assert.equal(transferMetrics(50, Infinity, 1000).percent, null);
});
test("precision and ETA derive from actual bytes and active milliseconds", () => {
  const sample = transferMetrics(12345, 100000, 2500);
  assert.equal(sample.percent.toFixed(2), "12.35");
  assert.equal(sample.rate, 4938);
  assert.equal(sample.eta, (100000 - 12345) / 4938);
  // A resumed transfer provides accumulated active time, never paused wall time.
  assert.equal(transferMetrics(2000, 4000, 2000).rate, 1000);
  assert.equal(transferMetrics(5000, 4000, 2000).percent, 100);
  assert.equal(transferMetrics(5000, 4000, 2000).eta, 0);
});
test("binary units and unavailable estimates are explicit", () => {
  assert.equal(transferBytes(1048576), "1.00 MiB");
  assert.equal(transferBytes(NaN), "—");
  assert.equal(transferEta(null), "—");
  assert.equal(transferEta(61), "1m 1s");
});
