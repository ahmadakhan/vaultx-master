import { bufToB64, b64ToBuf } from "./base";

const AES_ALGO = "AES-GCM";
const IV_LEN = 12;

export async function importAesKeyFromB64(key_b64: string, usages: KeyUsage[] = ["encrypt", "decrypt"]): Promise<CryptoKey> {
  const keyBuf = b64ToBuf(key_b64);
  return crypto.subtle.importKey("raw", keyBuf, { name: AES_ALGO }, false, usages);
}

export async function decryptBytesWithAes(ciphertext_b64: string, iv_b64: string, key_b64: string) {
  const key = await importAesKeyFromB64(key_b64, ["decrypt"]);
  const buf = await aesDecryptArrayBuffer(ciphertext_b64, iv_b64, key);
  return new Uint8Array(buf);
}

export async function aesEncryptArrayBuffer(
  plain: ArrayBuffer,
  key: CryptoKey,
  iv?: Uint8Array<ArrayBuffer>,
) {
  // When an IV is supplied (chunked uploads) it MUST be the one persisted with
  // the ciphertext; otherwise generate a random one for single-shot messages.
  const ivBytes = iv ?? crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = await crypto.subtle.encrypt({ name: AES_ALGO, iv: ivBytes }, key, plain);
  return { ciphertext_b64: bufToB64(ct), iv_b64: bufToB64(ivBytes.buffer as ArrayBuffer) };
}

export async function aesDecryptArrayBuffer(ciphertext_b64: string, iv_b64: string, key: CryptoKey): Promise<ArrayBuffer> {
  const ct = b64ToBuf(ciphertext_b64);
  const iv = new Uint8Array(b64ToBuf(iv_b64));
  const plain = await crypto.subtle.decrypt({ name: AES_ALGO, iv }, key, ct);
  return plain;
}

export async function encryptStringWithAes(plainText: string, key_b64: string) {
  const key = await importAesKeyFromB64(key_b64, ["encrypt"]);
  const buf = new TextEncoder().encode(plainText).buffer as ArrayBuffer;
  return aesEncryptArrayBuffer(buf, key);
}

export async function decryptStringWithAes(ciphertext_b64: string, iv_b64: string, key_b64: string) {
  const key = await importAesKeyFromB64(key_b64, ["decrypt"]);
  const buf = await aesDecryptArrayBuffer(ciphertext_b64, iv_b64, key);
  return new TextDecoder().decode(buf);
}

export async function encryptFileWithAes(file: File, key_b64: string) {
  const key = await importAesKeyFromB64(key_b64, ["encrypt"]);
  const buf = await file.arrayBuffer();
  return aesEncryptArrayBuffer(buf as ArrayBuffer, key);
}

export async function decryptFileWithAes(ciphertext_b64: string, iv_b64: string, key_b64: string) {
  const key = await importAesKeyFromB64(key_b64, ["decrypt"]);
  const buf = await aesDecryptArrayBuffer(ciphertext_b64, iv_b64, key);
  return new Blob([buf]);
}
