export interface VaultXContext {
  accessToken: string
  masterKey_b64: string
  searchKey_b64: string
  privateKey_b64: string
  publicKey_b64: string
  email?: string
  tenantId?: string
  expiresAt?: number
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
  if (ctx.tenantId) memorySession.setItem("vaultx_tenant_id", ctx.tenantId)
  if (ctx.expiresAt) memorySession.setItem("vaultx_expires_at", ctx.expiresAt.toString())
}

export function getSessionContext(): VaultXContext | null {
  // Try to recover context from memory session first
  if (values.size > 0) {
    const accessToken = values.get("vaultx_access_token") || null
    const masterKey_b64 = values.get("vaultx_master_key") || null
    const searchKey_b64 = values.get("vaultx_search_key") || null
    const privateKey_b64 = values.get("vaultx_private_key") || null
    const publicKey_b64 = values.get("vaultx_public_key") || null
    const tenantId = values.get("vaultx_tenant_id") || undefined
    const expiresAt = values.get("vaultx_expires_at") ? parseInt(values.get("vaultx_expires_at") || "0", 10) : undefined
    
    if (accessToken && masterKey_b64 && searchKey_b64 && privateKey_b64 && publicKey_b64) {
      return {
        accessToken,
        masterKey_b64,
        searchKey_b64,
        privateKey_b64,
        publicKey_b64,
        ...(tenantId ? { tenantId } : {}),
        ...(expiresAt ? { expiresAt } : {}),
      }
    }
  }
  
  // Also check the context variable as a fallback
  if (context) {
    return context
  }
  
  return null
}

export function getVaultXContext(): VaultXContext {
  const ctx = context ?? getSessionContext()
  if (!ctx) throw new Error("Session expired — please log in again. Reloading locks your vault.")
  
  // Check if context has expired
  if (ctx.expiresAt && Date.now() >= ctx.expiresAt) {
    clearVaultXContext()
    throw new Error("Session expired — please log in again. Reloading locks your vault.")
  }
  
  return ctx
}

export function clearVaultXContext(): void {
  context = null
  values.clear()
  removeLegacyStorage()
}

export function isAuthenticated(): boolean {
  return getSessionContext() !== null
}
