/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict")
const test = require("node:test")
const fs = require("node:fs")
const vm = require("node:vm")
const ts = require("typescript")
const exportsObject = {}
vm.runInNewContext(ts.transpileModule(fs.readFileSync(require.resolve("../lib/guest-link.ts"), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports: exportsObject })
const { guestLinkPayload, guestLinkStatus, copyGuestLink, MAX_GUEST_DOWNLOADS } = exportsObject
const now = Date.parse("2026-10-11T12:00:00Z")
const options = { expiryEnabled: true, expiryPreset: "1day", customExpiry: "", downloadsEnabled: false, maxDownloads: "1", codeEnabled: false, accessCode: "" }

test("expiry presets are exact and custom times must be future", () => {
  assert.equal(guestLinkPayload(options, now).expires_at, "2026-10-12T12:00:00.000Z")
  assert.equal(guestLinkPayload({ ...options, expiryPreset: "1h" }, now).expires_at, "2026-10-11T13:00:00.000Z")
  for (const customExpiry of ["", "invalid", "2026-10-11T12:00:00Z", "2020-01-01T00:00:00Z"]) {
    assert.throws(() => guestLinkPayload({ ...options, expiryPreset: "custom", customExpiry }, now), /future/)
  }
  assert.equal(guestLinkPayload({ ...options, expiryPreset: "custom", customExpiry: "2026-10-13T15:00:00+03:00" }, now).expires_at, "2026-10-13T12:00:00.000Z")
  assert.equal(guestLinkPayload({ ...options, expiryEnabled: false, customExpiry: "invalid" }, now).expires_at, null)
})

test("download limits match server boundaries without truncation", () => {
  for (const maxDownloads of ["", "0", "-1", "1.5", "1e2", "12x", " 1", String(MAX_GUEST_DOWNLOADS + 1)]) {
    assert.throws(() => guestLinkPayload({ ...options, downloadsEnabled: true, maxDownloads }, now), /downloads/)
  }
  for (const maxDownloads of ["1", String(MAX_GUEST_DOWNLOADS)]) {
    assert.equal(guestLinkPayload({ ...options, downloadsEnabled: true, maxDownloads }, now).max_downloads, Number(maxDownloads))
  }
  assert.equal(guestLinkPayload({ ...options, maxDownloads: "invalid" }, now).max_downloads, null)
})

test("optional access codes preserve exact value and validate server character length", () => {
  assert.equal(guestLinkPayload({ ...options, accessCode: "hidden" }, now).access_code, undefined)
  for (const accessCode of ["", "abc", "1234567890123"]) assert.throws(() => guestLinkPayload({ ...options, codeEnabled: true, accessCode }, now), /4–12/)
  for (const accessCode of ["1234", "123456789012", " 🔑🔑 "]) assert.equal(guestLinkPayload({ ...options, codeEnabled: true, accessCode }, now).access_code, accessCode)
})

test("link lifecycle describes expired and exhausted links accurately", () => {
  const link = { expires_at: null, max_downloads: null, download_count: 3 }
  assert.equal(guestLinkStatus(link, now), "Available")
  assert.equal(guestLinkStatus({ ...link, max_downloads: 3 }, now), "Limit reached")
  assert.equal(guestLinkStatus({ ...link, expires_at: "2026-10-11T12:00:00Z" }, now), "Expired")
})

test("copy keeps the exact fragment URL and selects it only on failure", async () => {
  const url = "https://vault.example/shared/token#key=abc%2B123%3D"
  let written; let selected = false
  assert.equal(await copyGuestLink(url, async value => { written = value }, () => { selected = true }), true)
  assert.equal(written, url)
  assert.equal(selected, false)
  assert.equal(await copyGuestLink(url, async () => { throw new Error("denied") }, () => { selected = true }), false)
  assert.equal(selected, true)
})
