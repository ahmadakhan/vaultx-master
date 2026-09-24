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
 */
export async function decryptChunkedGCM(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  fileIvB64: string,
  chunkSize: number = CHUNK_SIZE,
): Promise<ArrayBuffer> {
  const nonce = new Uint8Array(b64ToBuf(fileIvB64));
  if (nonce.byteLength !== NONCE_LENGTH) {
    throw new Error("Invalid file IV");
  }

  const total = ciphertext.byteLength;
  const segmentSize = chunkSize + GCM_TAG_LENGTH;
  const segmentCount = Math.ceil(total / segmentSize);
  if (segmentCount === 0 || total <= GCM_TAG_LENGTH * segmentCount) {
    throw new Error("Empty or malformed ciphertext");
  }

  const plaintext = new Uint8Array(total - GCM_TAG_LENGTH * segmentCount);
  let inOffset = 0;
  let outOffset = 0;

  for (let i = 0; i < segmentCount; i++) {
    const segmentLength =
      i === segmentCount - 1 ? total - (segmentCount - 1) * segmentSize : segmentSize;
    const segment = ciphertext.slice(inOffset, inOffset + segmentLength);
    const iv = buildChunkIv(nonce, i);
    let part: ArrayBuffer;
    try {
      part = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, segment);
    } catch (err) {
      throw new Error(
        `File decryption failed at chunk ${i} (wrong key or corrupted data): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    plaintext.set(new Uint8Array(part), outOffset);
    outOffset += part.byteLength;
    inOffset += segmentLength;
  }

  return plaintext.buffer;
}