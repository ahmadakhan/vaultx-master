export interface VaultXContext {
  accessToken: string
  masterKey_b64: string
  searchKey_b64: string
  privateKey_b64: string
  publicKey_b64: string
}

// In-memory session store. Keys are intentionally NOT persisted to
// localStorage/sessionStorage because any XSS can read those stores and
// exfiltrate the entire vault. Keeping keys in a module-scoped variable makes
// them invisible to JavaScript running outside this bundle.
let _ctx: VaultXContext | null = null

export function setVaultXContext(ctx: VaultXContext): void {
  _ctx = ctx
}

/**
 * Rebuild the context after a page reload. The access token lives in
 * localStorage and the unlocked key material in sessionStorage (written at
 * login); this repopulates the in-memory context from those stores so that
 * `getVaultXContext()` keeps working across refreshes.
 */
function rehydrateVaultXContext(): VaultXContext | null {
  if (typeof window === "undefined") return null
  const accessToken = localStorage.getItem("vaultx_access_token")
  if (!accessToken) return null
  return {
    accessToken,
    masterKey_b64: sessionStorage.getItem("vaultx_master_key") || "",
    searchKey_b64: sessionStorage.getItem("vaultx_search_key") || "",
    privateKey_b64: sessionStorage.getItem("vaultx_private_key") || "",
    publicKey_b64: sessionStorage.getItem("vaultx_public_key") || "",
  }
}

export function getVaultXContext(): VaultXContext {
  if (!_ctx) {
    _ctx = rehydrateVaultXContext()
  }
  if (!_ctx) {
    throw new Error("Session expired — please log in again.")
  }
  return _ctx
}

export function clearVaultXContext(): void {
  _ctx = null
  // Best-effort cleanup of any legacy storage from previous versions.
  localStorage.removeItem("vaultx_access_token")
  sessionStorage.removeItem("vaultx_master_key")
  sessionStorage.removeItem("vaultx_search_key")
  sessionStorage.removeItem("vaultx_private_key")
  sessionStorage.removeItem("vaultx_public_key")
  sessionStorage.removeItem("vaultx_keyword_chain")
  sessionStorage.removeItem("vaultx_user_email")
}
