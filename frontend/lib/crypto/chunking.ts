/**
 * Chunked file encryption helpers shared by upload and download paths.
 */
import { b64ToBuf, bufToB64 } from "./base";
import { AES_GCM_TAG_LENGTH, buildChunkAad } from "./aes";

/** Plaintext bytes per chunk. Must stay in sync between upload and download. */
export const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB per chunk

const GCM_TAG_LENGTH = 16;
const NONCE_LENGTH = 12;

export interface ChunkMetadata {
  formatVersion: 1;
  index: number;
  iv_b64: string;
  ciphertext_b64: string;
  tag_b64: string;
  encryptedAt: number;
  keyDerivationVersion: number;
  tenantId: string;
}

export const CHUNK_FORMAT_VERSION = 1;

export interface ChunkEncryptionOptions {
  tenantId: string;
  keyDerivationVersion?: number;
  enableEnhancedSecurity?: boolean;
}

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
 * Encrypt a chunk of data using AES-256-GCM with enhanced security.
 * 
 * @param chunkData - The chunk data to encrypt
 * @param masterKey - The master key for encryption
 * @param baseIV - The base IV for the file
 * @param chunkIndex - The chunk index
 * @param options - Encryption options
 * @returns Encrypted chunk with metadata
 */
export async function encryptChunkSecure(
  chunkData: ArrayBuffer,
  masterKey: CryptoKey,
  baseIV: Uint8Array,
  chunkIndex: number,
  options: ChunkEncryptionOptions
): Promise<ChunkMetadata> {
  // Validate inputs
  if (!masterKey) {
    throw new Error("Master key is required for encryption");
  }
  
  if (baseIV.byteLength !== NONCE_LENGTH) {
    throw new Error("Base IV must be 12 bytes for AES-GCM");
  }
  
  if (!options.tenantId) {
    throw new Error("Tenant ID is required");
  }
  
  // Derive chunk IV from base IV
  const chunkIV = buildChunkIv(baseIV, chunkIndex);
  
  // Enhanced additional authenticated data
  const version = options.keyDerivationVersion ?? CHUNK_FORMAT_VERSION;
  if (version !== CHUNK_FORMAT_VERSION) throw new Error(`Unsupported crypto format version: ${version}`);
  const aad = buildChunkAad(CHUNK_FORMAT_VERSION, options.tenantId, chunkIndex, chunkData.byteLength);
  
  // Encrypt the chunk
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
       iv: chunkIV as BufferSource,
       additionalData: aad as BufferSource,
      tagLength: 128,
    },
    masterKey,
    chunkData
  );
  
  // Extract tag and ciphertext
  const encryptedUint8 = new Uint8Array(encrypted);
  const tag = encryptedUint8.slice(-GCM_TAG_LENGTH);
  const ciphertext = encryptedUint8.slice(0, -GCM_TAG_LENGTH);
  
  return {
    formatVersion: CHUNK_FORMAT_VERSION,
    index: chunkIndex,
    iv_b64: bufToB64(chunkIV.buffer),
    ciphertext_b64: bufToB64(ciphertext.buffer),
    tag_b64: bufToB64(tag.buffer),
    encryptedAt: 0,
    keyDerivationVersion: CHUNK_FORMAT_VERSION,
    tenantId: options.tenantId
  };
}

/**
 * Decrypt a chunk of data using AES-256-GCM.
 * 
 * @param metadata - Chunk metadata containing IV, tag, and ciphertext
 * @param masterKey - The master key for decryption
 * @param baseIV - The base IV for the file
 * @returns Decrypted chunk data
 */
export async function decryptChunkSecure(
  metadata: ChunkMetadata,
  masterKey: CryptoKey,
  baseIV: Uint8Array
): Promise<ArrayBuffer> {
  // Validate inputs
  if (!masterKey) {
    throw new Error("Master key is required for decryption");
  }
  
  if (baseIV.byteLength !== NONCE_LENGTH) {
    throw new Error("Base IV must be 12 bytes for AES-GCM");
  }
  
  if (metadata.index < 0 || metadata.index > 0xffffffff) {
    throw new Error("Invalid chunk index");
  }
  
  // Reconstruct IV for this chunk
  const chunkIV = buildChunkIv(baseIV, metadata.index);
  if (metadata.formatVersion !== CHUNK_FORMAT_VERSION) throw new Error(`Unsupported crypto format version: ${metadata.formatVersion}`);
  if (metadata.iv_b64 !== bufToB64(chunkIV.buffer)) throw new Error("Chunk IV does not match file nonce and counter");
  
  // Reconstruct encrypted data
  const tag = new Uint8Array(b64ToBuf(metadata.tag_b64));
  const ciphertext = new Uint8Array(b64ToBuf(metadata.ciphertext_b64));
  
  if (tag.byteLength !== AES_GCM_TAG_LENGTH) throw new Error("Invalid authentication tag length");
  const reconstructed = new Uint8Array(tag.length + ciphertext.length);
  reconstructed.set(ciphertext, 0);
  reconstructed.set(tag, ciphertext.length);
  
  // Enhanced additional authenticated data
  const aad = buildChunkAad(CHUNK_FORMAT_VERSION, metadata.tenantId, metadata.index, ciphertext.byteLength);
  
  // Decrypt the chunk
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
       iv: chunkIV as BufferSource,
       additionalData: aad as BufferSource,
      tagLength: 128,
    },
    masterKey,
    reconstructed.buffer
  );
  
  return decrypted;
}

/**
 * Validate chunk integrity with comprehensive security checks.
 * 
 * @param chunk - Chunk metadata to validate
 * @returns Validation result with detailed error messages
 */
export function validateChunkIntegrity(chunk: ChunkMetadata): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Check required fields
  if (chunk.index === undefined || chunk.index === null) {
    errors.push("Chunk index is required");
  }
  
  if (!chunk.iv_b64) {
    errors.push("IV is required");
  }
  
  if (!chunk.ciphertext_b64) {
    errors.push("Ciphertext is required");
  }
  
  if (!chunk.tag_b64) {
    errors.push("Authentication tag is required");
  }
  
  if (!chunk.tenantId) {
    errors.push("Tenant ID is required");
  }
  
  // Validate IV format
  try {
    const iv = b64ToBuf(chunk.iv_b64);
    if (iv.byteLength !== NONCE_LENGTH) {
      errors.push(`Invalid IV length: expected ${NONCE_LENGTH} bytes, got ${iv.byteLength}`);
    }
  } catch {
    errors.push("Invalid IV format - not valid base64");
  }
  
  // Validate tag format
  try {
    const tag = b64ToBuf(chunk.tag_b64);
    if (tag.byteLength !== GCM_TAG_LENGTH) {
      errors.push(`Invalid tag length: expected ${GCM_TAG_LENGTH} bytes, got ${tag.byteLength}`);
    }
  } catch {
    errors.push("Invalid tag format - not valid base64");
  }
  
  // Validate chunk index range
  if (chunk.index < 0 || chunk.index > 0xffffffff) {
    errors.push(`Invalid chunk index range: ${chunk.index}`);
  }
  
  if (chunk.formatVersion !== CHUNK_FORMAT_VERSION) {
    errors.push(`Unsupported chunk format version: ${chunk.formatVersion}`);
  }
  
  // Validate tenant ID format
  if (typeof chunk.tenantId !== 'string' || chunk.tenantId.length < 1) {
    errors.push("Tenant ID must be a non-empty string");
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Calculate the number of chunks needed for a given file size.
 * 
 * @param fileSize - Size of the file in bytes
 * @param chunkSize - Size of each chunk in bytes
 * @returns Number of chunks required
 */
export function calculateChunkCount(fileSize: number, chunkSize: number = CHUNK_SIZE): number {
  return Math.ceil(fileSize / chunkSize);
}

/**
 * Generate chunk range for efficient retrieval of file chunks.
 * 
 * @param totalChunks - Total number of chunks
 * @param requestedChunk - Requested chunk index
 * @returns Object containing chunk range information
 */
export function generateChunkRange(
  totalChunks: number,
  requestedChunk: number
): { start: number; end: number; chunkCount: number } {
  if (requestedChunk < 0 || requestedChunk >= totalChunks) {
    throw new Error("Invalid chunk request");
  }
  
  const startChunk = Math.max(0, requestedChunk - 1);
  const endChunk = Math.min(totalChunks - 1, requestedChunk + 1);
  
  return {
    start: startChunk,
    end: endChunk,
    chunkCount: endChunk - startChunk + 1
  };
}

/** Decrypt server-stored ciphertext framed as consecutive AES-GCM chunks. */
export async function decryptChunkedGCM(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  fileIvB64: string,
  chunkSize: number = CHUNK_SIZE,
  expectedSize?: number,
  fileId?: string,
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
  if (nonce.byteLength !== NONCE_LENGTH) throw new Error("Invalid file IV");

  const segmentSize = chunkSize + GCM_TAG_LENGTH;
  const segmentCount = Math.ceil(ciphertext.byteLength / segmentSize);
  const finalSegmentLength = ciphertext.byteLength - (segmentCount - 1) * segmentSize;
  if (
    segmentCount === 0 ||
    segmentCount > 0x100000000 ||
    finalSegmentLength < GCM_TAG_LENGTH ||
    (segmentCount > 1 && finalSegmentLength === GCM_TAG_LENGTH)
  ) {
    throw new Error("Empty or malformed ciphertext");
  }

  if (
    expectedSize !== undefined &&
    (!Number.isSafeInteger(expectedSize) || expectedSize < 0 ||
      ciphertext.byteLength - GCM_TAG_LENGTH * segmentCount !== expectedSize)
  ) {
    throw new Error("File size does not match authenticated metadata");
  }

  const plaintext = new Uint8Array(ciphertext.byteLength - GCM_TAG_LENGTH * segmentCount);
  let inOffset = 0;
  let outOffset = 0;

  try {
    for (let index = 0; index < segmentCount; index++) {
      const segmentLength = index === segmentCount - 1 ? finalSegmentLength : segmentSize;
      const segment = ciphertext.slice(inOffset, inOffset + segmentLength);
      const iv = buildChunkIv(nonce, index);
      const params: AesGcmParams = { name: "AES-GCM", iv };
      if (fileId) {
        params.additionalData = buildChunkAad(CHUNK_FORMAT_VERSION, fileId, index, segmentLength - GCM_TAG_LENGTH) as BufferSource;
      }
      const decryptedChunk = await crypto.subtle.decrypt(params, key, segment);
      const part = new Uint8Array(decryptedChunk);
      try {
        if (part.byteLength !== segmentLength - GCM_TAG_LENGTH) {
          throw new Error("Invalid decrypted chunk size");
        }
        plaintext.set(part, outOffset);
        outOffset += part.byteLength;
      } finally {
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

export interface PlaintextSink {
  write(chunk: Uint8Array): Promise<void>;
  close?(): Promise<void>;
}

/**
 * Decrypt a complete framed response incrementally. When a File System Access
 * sink is supplied, plaintext and ciphertext stay bounded to one frame.
 */
export async function decryptChunkedResponseToSink(
  response: Response,
  key: CryptoKey,
  fileIvB64: string,
  tenantOrFileId: string,
  chunkSize: number,
  sink: PlaintextSink,
  signal?: AbortSignal,
): Promise<number> {
  const nonce = new Uint8Array(b64ToBuf(fileIvB64));
  if (nonce.byteLength !== NONCE_LENGTH) throw new Error("Invalid file IV");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Streaming not supported by browser");
  const frameSize = chunkSize + GCM_TAG_LENGTH;
  let pending = new Uint8Array(0);
  let index = 0;
  let total = 0;
  const decryptFrame = async (frame: Uint8Array, final: boolean) => {
    if (frame.byteLength < GCM_TAG_LENGTH || (!final && frame.byteLength !== frameSize)) {
      throw new Error("Malformed encrypted file");
    }
    const iv = buildChunkIv(nonce, index);
    const aad = buildChunkAad(CHUNK_FORMAT_VERSION, tenantOrFileId, index, frame.byteLength - GCM_TAG_LENGTH);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }, key, frame as BufferSource));
    index += 1;
    total += plain.byteLength;
    try { await sink.write(plain); } finally { plain.fill(0); }
  };
  try {
    while (true) {
      if (signal?.aborted) throw new DOMException("Download cancelled", "AbortError");
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;
      const merged = new Uint8Array(pending.byteLength + value.byteLength);
      merged.set(pending); merged.set(value, pending.byteLength); pending = merged;
      while (pending.byteLength >= frameSize) {
        const frame = pending.slice(0, frameSize);
        pending = pending.slice(frameSize);
        await decryptFrame(frame, false);
      }
    }
    if (!pending.byteLength) throw new Error("Malformed encrypted file");
    await decryptFrame(pending, true);
    if (sink.close) await sink.close();
    return total;
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }
}
