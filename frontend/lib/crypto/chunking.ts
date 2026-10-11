/**
 * Chunked file-encryption framing shared by the upload and download paths.
 *
 * A file is encrypted chunk-by-chunk with AES-256-GCM. Each chunk is sealed
 * with its own 16-byte tag and a counter-derived IV:
 *
 *     iv_i = file_nonce (12 bytes) with bytes 8..11 replaced by the big-endian
 *            chunk index
 *
 * The file nonce is persisted server-side as `file_iv`, so any download path
 * can re-derive every per-chunk IV. Ciphertext on disk is simply the
 * concatenation of the sealed chunks; segments are re-framed using
 * CHUNK_SIZE + 16 byte boundaries (the last segment takes the remainder).
 */
import { b64ToBuf } from "./base";

/** Plaintext bytes per chunk. Must stay in sync between upload and download. */
export const CHUNK_SIZE = 5 * 1024 * 1024;

const GCM_TAG_LENGTH = 16;
const NONCE_LENGTH = 12;

/** Derive the AES-GCM IV for a given chunk index from the file nonce. */
export function buildChunkIv(nonce: Uint8Array, chunkIndex: number): Uint8Array<ArrayBuffer> {
  if (nonce.byteLength !== NONCE_LENGTH) {
    throw new Error("Invalid file IV: expected 12 bytes");
  }
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > 0xffffffff) {
    throw new Error("Invalid chunk index");
  }
  const iv = new Uint8Array(nonce);
  new DataView(iv.buffer).setUint32(8, chunkIndex, false);
  return iv;
}

/**
 * Decrypt a ciphertext produced by encrypting a file chunk-by-chunk.
 *
 * @param ciphertext The concatenated sealed chunks as stored by the server.
 * @param key        The imported AES-GCM file key (Kf).
 * @param fileIvB64  Base64 of the persisted file nonce (`file_iv`).
 * @param chunkSize  Plaintext chunk size used at upload time.
 * @param expectedSize Plaintext size from authenticated metadata, when available.
 */
export async function decryptChunkedGCM(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  fileIvB64: string,
  chunkSize: number = CHUNK_SIZE,
  expectedSize?: number,
): Promise<ArrayBuffer> {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > CHUNK_SIZE) {
    throw new Error("Invalid chunk size");
  }
  let nonce: Uint8Array;
  try {
    nonce = new Uint8Array(b64ToBuf(fileIvB64));
  } catch {
    throw new Error("Invalid file IV");
  }
  if (nonce.byteLength !== NONCE_LENGTH) {
    throw new Error("Invalid file IV");
  }

  const total = ciphertext.byteLength;
  const segmentSize = chunkSize + GCM_TAG_LENGTH;
  const segmentCount = Math.ceil(total / segmentSize);
  const finalSegmentLength = total - (segmentCount - 1) * segmentSize;
  // A single tag encodes an empty file. Later chunks must contain plaintext;
  // every segment must have its own complete tag, and counters must not wrap.
  if (segmentCount === 0 || segmentCount > 0x100000000 ||
      finalSegmentLength < GCM_TAG_LENGTH ||
      (segmentCount > 1 && finalSegmentLength === GCM_TAG_LENGTH)) {
    throw new Error("Empty or malformed ciphertext");
  }
  // The authenticated metadata carries the plaintext size. Check it to detect
  // removal of complete trailing chunks, which individual tags cannot detect.
  if (expectedSize !== undefined && (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || total - GCM_TAG_LENGTH * segmentCount !== expectedSize)) {
    throw new Error("File size does not match authenticated metadata");
  }

  const plaintext = new Uint8Array(total - GCM_TAG_LENGTH * segmentCount);
  let inOffset = 0;
  let outOffset = 0;

  try {
    for (let i = 0; i < segmentCount; i++) {
      const segmentLength = i === segmentCount - 1 ? finalSegmentLength : segmentSize;
      const segment = ciphertext.slice(inOffset, inOffset + segmentLength);
      const iv = buildChunkIv(nonce, i);
      const part = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, segment));
      try {
        if (part.byteLength !== segmentLength - GCM_TAG_LENGTH) {
          throw new Error("Invalid decrypted chunk size");
        }
        plaintext.set(part, outOffset);
        outOffset += part.byteLength;
      } finally {
        // Best-effort clearing of this owned buffer, not engine-internal copies.
        part.fill(0);
      }
      inOffset += segmentLength;
    }
  } catch {
    plaintext.fill(0);
    throw new Error("File decryption failed (wrong key or corrupted data)");
  }

  return plaintext.buffer;
}
