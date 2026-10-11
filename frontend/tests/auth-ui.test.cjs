/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict")
const test = require("node:test")
const fs = require("node:fs")
const vm = require("node:vm")
const ts = require("typescript")

function load(file, modules = {}) {
  const source = fs.readFileSync(require.resolve(file), "utf8")
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  vm.runInNewContext(output, { exports, require: name => modules[name], DOMException })
  return exports
}
const helpers = load("../lib/auth-ui.ts")

test("OTP normalization accepts pasted spacing and preserves leading zeros", () => {
  assert.equal(helpers.normalizeOtp(" 012 345\n"), "012345")
  assert.equal(helpers.normalizeOtp("123456789"), "123456")
  assert.equal(helpers.isCompleteOtp("012345"), true)
  for (const value of ["12345", "1234567", "12345x"]) assert.equal(helpers.isCompleteOtp(value), false)
})

test("completion submits once, blocks concurrent manual requests, and permits explicit retry", async () => {
  const gate = helpers.createOtpGate()
  let release
  let calls = 0
  const verify = () => { calls++; return new Promise(resolve => { release = resolve }) }
  const first = gate.run("012345", true, verify)
  assert.equal(await gate.run("012345", true, verify), false)
  assert.equal(await gate.run("012345", false, verify), false)
  assert.equal(calls, 1)
  release()
  await first
  assert.equal(await gate.run("012345", true, verify), false)
  const retry = gate.run("012345", false, verify)
  assert.equal(calls, 2)
  release()
  await retry
  gate.changed("01234")
  const reentered = gate.run("012345", true, verify)
  assert.equal(calls, 3)
  release()
  await reentered
})

test("failed verification releases the lock without an automatic retry loop", async () => {
  const gate = helpers.createOtpGate()
  let calls = 0
  const fail = async () => { calls++; throw new Error("Invalid code") }
  await assert.rejects(gate.run("123456", true, fail), /Invalid code/)
  assert.equal(await gate.run("123456", true, fail), false)
  await assert.rejects(gate.run("123456", false, fail), /Invalid code/)
  assert.equal(calls, 2)
})

test("passkey success requires the supplied adapter's verified receipt; cancellation wins", async () => {
  const controller = new AbortController()
  await helpers.verifyPasskey({ verify: async () => ({ verified: true }) }, controller.signal)
  await assert.rejects(helpers.verifyPasskey({ verify: async () => ({ verified: false }) }, controller.signal), /did not verify/)
  controller.abort()
  await assert.rejects(helpers.verifyPasskey({ verify: async () => ({ verified: true }) }, controller.signal), { name: "AbortError" })
})

function deckHarness(autoSubmit = true) {
  const slots = []
  let cursor = 0
  let value = ""
  const calls = []
  const jsx = (type, props) => ({ type, props })
  const { OtpDeck } = load("../components/otp-deck.tsx", {
    "react/jsx-runtime": { jsx, jsxs: jsx },
    react: {
      useId: () => "otp",
      useRef: initial => { const i = cursor++; return slots[i] ||= { current: initial } },
      useState: initial => { const i = cursor++; if (!(i in slots)) slots[i] = initial; return [slots[i], next => { slots[i] = next }] },
    },
    "@/components/ui/button": { Button: "button" },
    "@/lib/auth-ui": helpers,
  })
  const render = () => { cursor = 0; return OtpDeck({ value, onChange: next => { value = next }, onVerify: async code => { calls.push(code) }, autoSubmit }) }
  function find(type, node = render()) {
    if (!node || typeof node !== "object") return
    if (node.type === type) return node.props
    for (const child of [node.props?.children].flat(Infinity)) { if (child === undefined) continue; const found = find(type, child); if (found) return found }
  }
  return { find, calls }
}

test("one semantic input exposes numeric autofill, handles paste, and retains manual fallback", async () => {
  const deck = deckHarness()
  const input = deck.find("input")
  assert.equal(input.inputMode, "numeric")
  assert.equal(input.autoComplete, "one-time-code")
  assert.ok(input["aria-describedby"])
  input.onPaste({ preventDefault() {}, clipboardData: { getData: () => "012 345" } })
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(deck.calls, ["012345"])
  deck.find("input").onChange({ target: { value: "012345" } })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(deck.calls.length, 1)
  deck.find("button").onClick()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(deck.calls.length, 2)
})

test("destructive MFA disable requires explicit confirmation", async () => {
  const deck = deckHarness(false)
  deck.find("input").onChange({ target: { value: "123456" } })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(deck.calls.length, 0)
  deck.find("button").onClick()
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(deck.calls, ["123456"])
})

test("unconfigured passkeys show truthful unavailable copy without a verification button", () => {
  const jsx = (type, props) => ({ type, props })
  const { PasskeyGateway } = load("../components/passkey-gateway.tsx", {
    "react/jsx-runtime": { jsx, jsxs: jsx },
    react: { useState: value => [value, () => {}], useRef: value => ({ current: value }), useEffect() {} },
    "lucide-react": { KeyRound: "icon" },
    "@/components/ui/button": { Button: "button" },
    "@/components/ui/dialog": {},
    "@/lib/auth-ui": helpers,
  })
  const rendered = JSON.stringify(PasskeyGateway({}))
  assert.match(rendered, /Unavailable on this server/)
  assert.doesNotMatch(rendered, /"type":"button"/)
})

test("a cancelled in-flight passkey cannot report success even if the adapter resolves", async () => {
  const controller = new AbortController()
  let resolve
  const request = helpers.verifyPasskey({ verify: () => new Promise(done => { resolve = done }) }, controller.signal)
  controller.abort()
  resolve({ verified: true })
  await assert.rejects(request, { name: "AbortError" })
})
