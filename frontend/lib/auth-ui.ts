export const normalizeOtp = (value: string) => value.replace(/\D/g, "").slice(0, 6)
export const isCompleteOtp = (value: string) => /^\d{6}$/.test(value)

/** A synchronous lock also covers clicks before React commits its busy state. */
export function createOtpGate() {
  let busy = false
  let lastAutomatic = ""
  return {
    changed(code: string) { if (!isCompleteOtp(code)) lastAutomatic = "" },
    async run(code: string, automatic: boolean, verify: (code: string) => Promise<void>) {
      if (busy || !isCompleteOtp(code) || (automatic && lastAutomatic === code)) return false
      busy = true
      lastAutomatic = code
      try { await verify(code); return true } finally { busy = false }
    },
  }
}

export type PasskeyState = "idle" | "verifying" | "success" | "error" | "cancel" | "unsupported"
/** The host must obtain a server challenge and verify the assertion on its server.
 * Resolving a browser credential alone is never proof of authorization. */
export type PasskeyVerificationAdapter = {
  verify: (signal: AbortSignal) => Promise<{ verified: true }>
}

export async function verifyPasskey(adapter: PasskeyVerificationAdapter, signal: AbortSignal) {
  if (signal.aborted) throw new DOMException("Verification cancelled", "AbortError")
  const result = await adapter.verify(signal)
  if (signal.aborted) throw new DOMException("Verification cancelled", "AbortError")
  if (result?.verified !== true) throw new Error("The server did not verify this passkey.")
}
