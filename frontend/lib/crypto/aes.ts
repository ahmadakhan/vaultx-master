import { bufToB64, b64ToBuf } from "./base";

export const AES_GCM_IV_LENGTH = 12;
export const AES_GCM_TAG_LENGTH = 16;

type AesAad = string | ArrayBuffer | ArrayBufferView;

function aadBytes(value?: AesAad): Uint8Array | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError("Invalid AES-GCM additional data");
}

/** Stable, unambiguous AAD for the versioned chunk format. */
export function buildChunkAad(version: number, tenantId: string, chunkIndex: number, plaintextLength: number): Uint8Array {
  if (!Number.isSafeInteger(version) || version < 1) throw new Error("Invalid crypto format version");
  if (!tenantId || !Number.isSafeInteger(chunkIndex) || chunkIndex < 0 ||
      !Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    throw new Error("Invalid chunk metadata");
  }
  return new TextEncoder().encode(`vaultx-chunk|v${version}|${tenantId}|${chunkIndex}|${plaintextLength}`);
}

function enhancedAad(additionalData?: AesAad, chunkIndex?: number, tenantId?: string, plaintextLength?: number) {
  if (chunkIndex === undefined || tenantId === undefined) return aadBytes(additionalData);
  if (plaintextLength === undefined) throw new Error("Plaintext length is required for chunk AAD");
  const chunkAad = buildChunkAad(1, tenantId, chunkIndex, plaintextLength);
  const base = aadBytes(additionalData);
  if (!base) return chunkAad;
  const combined = new Uint8Array(base.length + chunkAad.length + 1);
  combined.set(base); combined[base.length] = 0; combined.set(chunkAad, base.length + 1);
  return combined;
}

export async function importAesKeyFromB64(key_b64: string, usages: KeyUsage[] = ["encrypt", "decrypt"]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", b64ToBuf(key_b64), { name: "AES-GCM" }, false, usages);
}

export async function aesEncryptArrayBuffer(
  plain: ArrayBuffer, key: CryptoKey, iv?: Uint8Array, additionalData?: AesAad,
  chunkIndex?: number, tenantId?: string,
): Promise<{ ciphertext_b64: string; iv_b64: string; tag_b64: string }> {
  const ivBytes = iv ?? crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));
  if (ivBytes.byteLength !== AES_GCM_IV_LENGTH) throw new Error("Invalid AES-GCM IV");
  const aad = enhancedAad(additionalData, chunkIndex, tenantId, plain.byteLength);
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivBytes as BufferSource, ...(aad ? { additionalData: aad as BufferSource } : {}) }, key, plain,
  ));
  // Web Crypto's representation is ciphertext || tag (tag is the final 16 bytes).
  const tag = sealed.slice(-AES_GCM_TAG_LENGTH);
  return { ciphertext_b64: bufToB64(sealed.buffer), iv_b64: bufToB64(ivBytes.slice().buffer), tag_b64: bufToB64(tag.buffer) };
}

export async function aesDecryptArrayBuffer(
  ciphertext_b64: string, iv_b64: string, key: CryptoKey, additionalData?: AesAad,
  tag_b64?: string, chunkIndex?: number, tenantId?: string,
): Promise<ArrayBuffer> {
  const ciphertext = new Uint8Array(b64ToBuf(ciphertext_b64));
  const iv = new Uint8Array(b64ToBuf(iv_b64));
  if (iv.byteLength !== AES_GCM_IV_LENGTH) throw new Error("Invalid AES-GCM IV");
  let sealed = ciphertext;
  if (tag_b64) {
    const tag = new Uint8Array(b64ToBuf(tag_b64));
    if (tag.byteLength !== AES_GCM_TAG_LENGTH) throw new Error("Invalid authentication tag length");
    sealed = new Uint8Array(ciphertext.length + tag.length);
    sealed.set(ciphertext); sealed.set(tag, ciphertext.length);
  }
  const plaintextLength = tag_b64 ? ciphertext.byteLength : ciphertext.byteLength - AES_GCM_TAG_LENGTH;
  if (plaintextLength < 0) throw new Error("Invalid AES-GCM ciphertext");
  const aad = enhancedAad(additionalData, chunkIndex, tenantId, plaintextLength);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource, ...(aad ? { additionalData: aad as BufferSource } : {}) }, key, sealed);
}

export async function decryptBytesWithAes(ciphertext_b64: string, iv_b64: string, key_b64: string, tag_b64?: string, chunkIndex?: number, tenantId?: string) {
  return new Uint8Array(await aesDecryptArrayBuffer(ciphertext_b64, iv_b64, await importAesKeyFromB64(key_b64, ["decrypt"]), undefined, tag_b64, chunkIndex, tenantId));
}
export async function encryptStringWithAes(text: string, key_b64: string) { return aesEncryptArrayBuffer(new TextEncoder().encode(text).buffer, await importAesKeyFromB64(key_b64, ["encrypt"])); }
export async function decryptStringWithAes(ct: string, iv: string, key: string, tag?: string) { return new TextDecoder().decode(await aesDecryptArrayBuffer(ct, iv, await importAesKeyFromB64(key, ["decrypt"]), undefined, tag)); }
export async function encryptFileWithAes(file: File, key_b64: string) { return aesEncryptArrayBuffer(await file.arrayBuffer(), await importAesKeyFromB64(key_b64, ["encrypt"])); }
export async function decryptFileWithAes(ct: string, iv: string, key: string, tag?: string) { return new Blob([await aesDecryptArrayBuffer(ct, iv, await importAesKeyFromB64(key, ["decrypt"]), undefined, tag)]); }
