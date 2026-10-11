/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");

require.extensions[".ts"] = (module, filename) => {
  module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, filename);
};
const { allocationSummary, requestWorkspaceSwitch, PERSONAL_VAULT_CONTEXT } = require("../lib/workspace-context.ts");
const css = fs.readFileSync(path.join(__dirname, "../app/globals.css"), "utf8");
const tokens = (selector) => Object.fromEntries([...css.match(new RegExp(`${selector} \\{([\\s\\S]*?)\\n\\}`))[1]
  .matchAll(/--([\w-]+):\s*(#[\da-f]{6});/gi)].map((match) => [match[1], match[2]]));
const light = tokens(":root");
const dark = { ...light, ...tokens("\\.dark") };
function luminance(hex) {
  const rgb = hex.slice(1).match(/../g).map((value) => parseInt(value, 16) / 255)
    .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
}
function contrast(a, b) {
  const values = [luminance(a), luminance(b)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test("exact slate/ink primary and decorative emerald tokens", () => {
  assert.equal(light.primary, "#0F172A");
  assert.equal(light["primary-foreground"], "#F8FAFC");
  assert.equal(dark.primary, "#F8FAFC");
  assert.equal(dark["primary-foreground"], "#0F172A");
  assert.equal(light.emerald, "#10B981");
  assert.notEqual(light.success, light.emerald);
});

for (const [mode, palette] of Object.entries({ light, dark })) {
  test(`${mode}: body, secondary and status text meet 7:1`, () => {
    for (const surface of ["background", "card", "muted", "accent"]) {
      for (const text of ["foreground", "muted-foreground"]) {
        assert.ok(contrast(palette[text], palette[surface]) >= 7, `${text} on ${surface}`);
      }
    }
    for (const name of ["primary", "secondary", "success", "warning", "destructive", "info"]) {
      assert.ok(contrast(palette[name], palette[`${name}-foreground`]) >= 7, name);
    }
  });
  test(`${mode}: control boundaries and focus meet 3:1`, () => {
    for (const surface of ["background", "card", "muted", "accent"]) {
      for (const edge of ["input-border", "ring"]) {
        assert.ok(contrast(palette[edge], palette[surface]) >= 3, `${edge} on ${surface}`);
      }
    }
  });
}

test("missing allocation never becomes a zero-usage meter", () => {
  for (const status of ["loading", "unknown", "unavailable", "error"]) {
    assert.equal(allocationSummary({ status, message: "Unavailable" }).percent, null);
  }
  for (const value of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(allocationSummary({ status: "ready", usedBytes: value, limitBytes: 100 }).percent, null);
    assert.equal(allocationSummary({ status: "ready", usedBytes: 0, limitBytes: value }).percent, null);
  }
});

test("allocation accurately describes zero, partial, full and over-quota usage", () => {
  const summarize = (usedBytes, limitBytes) => allocationSummary({ status: "ready", usedBytes, limitBytes });
  assert.equal(summarize(0, 0).percent, 0);
  assert.equal(summarize(1, 0).percent, 100);
  assert.equal(summarize(1, 0).overQuota, true);
  assert.equal(summarize(512, 1024).percent, 50);
  assert.equal(summarize(1024, 1024).overQuota, false);
  assert.deepEqual(summarize(2048, 1024), { label: "2 KiB of 1 KiB · Over allocation", percent: 100, overQuota: true });
});

test("mounted personal context has no fabricated organizations, quota or switching", async () => {
  assert.equal(PERSONAL_VAULT_CONTEXT.current.name, "Personal vault");
  assert.equal(PERSONAL_VAULT_CONTEXT.memberships.status, "unavailable");
  assert.equal(PERSONAL_VAULT_CONTEXT.allocation.status, "unavailable");
  assert.equal(PERSONAL_VAULT_CONTEXT.switchWorkspace, undefined);
  await assert.rejects(requestWorkspaceSwitch(PERSONAL_VAULT_CONTEXT, "organization"), /unavailable/);
});

test("switching awaits authoritative adapter and propagates failures without changing scope", async () => {
  let complete;
  let called = 0;
  const adapter = {
    ...PERSONAL_VAULT_CONTEXT,
    memberships: { status: "ready", workspaces: [{ id: "member-workspace", name: "Membership fixture", kind: "organization" }] },
    switchWorkspace: () => { called++; return new Promise((resolve) => { complete = resolve; }); },
  };
  let settled = false;
  const request = requestWorkspaceSwitch(adapter, "member-workspace").then(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(called, 1);
  complete();
  await request;
  assert.equal(settled, true);
  assert.equal(adapter.current.id, "personal");
  await requestWorkspaceSwitch(adapter, "personal");
  assert.equal(called, 1);
  await assert.rejects(requestWorkspaceSwitch(adapter, "non-member"), /unavailable/);
  adapter.switchWorkspace = async () => { throw new Error("Service rejected switch"); };
  await assert.rejects(requestWorkspaceSwitch(adapter, "member-workspace"), /rejected/);
  assert.equal(adapter.current.id, "personal");
});
