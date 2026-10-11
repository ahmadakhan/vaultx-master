export interface VaultXContext {
  accessToken: string
  masterKey_b64: string
  searchKey_b64: string
  privateKey_b64: string
  publicKey_b64: string
  email?: string
}

// Memory-only, tab-local unlocked state. This limits persistence; it does not
// protect an unlocked session against JavaScript already executing in the app.
let context: VaultXContext | null = null
const values = new Map<string, string>()
export const memorySession = {
  getItem: (key: string): string | null => values.get(key) ?? null,
  setItem: (key: string, value: string): void => { values.set(key, value) },
  removeItem: (key: string): void => { values.delete(key) },
}

function removeLegacyStorage(): void {
  if (typeof window === "undefined") return
  for (const name of ["localStorage", "sessionStorage"] as const) {
    try {
      const storage = window[name]
      for (let i = storage.length - 1; i >= 0; i--) {
        const key = storage.key(i)
        if (key?.startsWith("vaultx_")) storage.removeItem(key)
      }
    } catch { /* Storage may be disabled. It is never needed for login. */ }
  }
}

export function setVaultXContext(ctx: VaultXContext): void {
  removeLegacyStorage()
  values.clear()
  context = ctx
  memorySession.setItem("vaultx_access_token", ctx.accessToken)
  memorySession.setItem("vaultx_master_key", ctx.masterKey_b64)
  memorySession.setItem("vaultx_search_key", ctx.searchKey_b64)
  memorySession.setItem("vaultx_private_key", ctx.privateKey_b64)
  memorySession.setItem("vaultx_public_key", ctx.publicKey_b64)
}

export function getSessionContext(): VaultXContext | null {
  return context
}

export function getVaultXContext(): VaultXContext {
  if (!context) throw new Error("Vault locked — please log in again. Reloading locks your vault.")
  return context
}

export function clearVaultXContext(): void {
  context = null
  values.clear()
  removeLegacyStorage()
}
