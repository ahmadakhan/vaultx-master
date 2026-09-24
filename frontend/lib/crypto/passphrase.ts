import { bufToB64 } from "./base"

const AES_ALGO = "AES-GCM"
const IV_LEN = 12
const PBKDF2_ITERATIONS = 100_000

export async function deriveAesKeyFromPassphrase(
  passphrase: string,
  salt_b64: string,
): Promise<CryptoKey> {
  const salt = base64ToBuf(salt_b64)
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  )
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: AES_ALGO, length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

export function genSalt(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer;
}

export async function encryptWithPassphrase(
  data_b64: string,
  passphrase: string,
): Promise<{ ciphertext_b64: string; iv_b64: string; salt_b64: string }> {
  const saltBuf = genSalt()
  const key = await deriveAesKeyFromPassphrase(passphrase, bufToB64(saltBuf))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
  const data = base64ToBuf(data_b64)
  const ct = await crypto.subtle.encrypt(
    { name: AES_ALGO, iv },
    key,
    data,
  )
  return {
    ciphertext_b64: bufToB64(ct),
    iv_b64: bufToB64(iv.buffer as ArrayBuffer),
    salt_b64: bufToB64(saltBuf),
  }
}

export async function decryptWithPassphrase(
  ciphertext_b64: string,
  iv_b64: string,
  salt_b64: string,
  passphrase: string,
): Promise<ArrayBuffer> {
  const key = await deriveAesKeyFromPassphrase(passphrase, salt_b64)
  const iv = new Uint8Array(base64ToBuf(iv_b64))
  const ct = base64ToBuf(ciphertext_b64)
  return crypto.subtle.decrypt(
    { name: AES_ALGO, iv },
    key,
    ct,
  )
}

function base64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer as ArrayBuffer;
}

/**
 * Single source of truth for the passphrase that wraps a share link's file
 * key (Kf) when no access code is set. Both the owner (share-modal) and the
 * guest page (shared/[token]) MUST derive it from the same inputs — the file
 * id alone — otherwise the guest can never decrypt the wrapped key.
 *
 * Note that link confidentiality without an access code rests on the random
 * link token itself, not on this passphrase.
 */
export function shareLinkPassphrase(fileId: string): string {
  return `vaultx_link_${fileId}_`
}
