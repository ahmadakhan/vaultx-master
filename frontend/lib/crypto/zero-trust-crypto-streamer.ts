/** Bounded-memory browser encryption helpers. PQ key exchange is not provided. */
import { aesEncryptArrayBuffer, buildChunkAad } from "./aes";
import { buildChunkIv, CHUNK_FORMAT_VERSION } from "./chunking";

export interface ZeroTrustCryptoStreamerOptions {
  chunkSize?: number;
  enablePostQuantum?: boolean;
}

export interface EncryptedChunk {
  index: number;
  ciphertext: ArrayBuffer;
  iv: Uint8Array;
  tag: Uint8Array;
}

export class ZeroTrustCryptoStreamer {
  readonly chunkSize: number;

  constructor(options: ZeroTrustCryptoStreamerOptions = {}) {
    this.chunkSize = options.chunkSize ?? 5 * 1024 * 1024;
    if (!Number.isSafeInteger(this.chunkSize) || this.chunkSize <= 0) throw new Error("Invalid chunk size");
    if (options.enablePostQuantum) throw new Error("Post-quantum key exchange is not implemented");
  }

  async deriveMasterKey(passphrase: string, tenantId: string, salt?: Uint8Array): Promise<CryptoKey> {
    if (!passphrase || !tenantId) throw new Error("Passphrase and tenant ID are required");
    const bytes = new TextEncoder().encode(passphrase);
    const actualSalt = salt ?? new TextEncoder().encode(`vaultx-kdf-v2|${tenantId}`);
    const base = await crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveKey"]);
    bytes.fill(0);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: actualSalt as BufferSource, iterations: 600_000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
  }

  generateBaseIV(): Uint8Array<ArrayBuffer> { return crypto.getRandomValues(new Uint8Array(12)); }
  incrementIV(baseIV: Uint8Array, chunkIndex: number): Uint8Array<ArrayBuffer> { return buildChunkIv(baseIV, chunkIndex); }

  async encryptChunk(data: ArrayBuffer, key: CryptoKey, nonce: Uint8Array, index: number, tenantId: string): Promise<EncryptedChunk> {
    const iv = buildChunkIv(nonce, index);
    const aad = buildChunkAad(CHUNK_FORMAT_VERSION, tenantId, index, data.byteLength);
    const sealed = await aesEncryptArrayBuffer(data, key, iv, aad);
    const encoded = Uint8Array.from(atob(sealed.ciphertext_b64), (char) => char.charCodeAt(0));
    const ciphertext = encoded.slice(0, -16);
    const tag = encoded.slice(-16);
    encoded.fill(0);
    return { index, ciphertext: ciphertext.buffer, iv, tag };
  }

  async *encryptFile(file: Blob, key: CryptoKey, nonce = this.generateBaseIV(), tenantId: string): AsyncGenerator<EncryptedChunk> {
    for (let index = 0, offset = 0; offset < file.size || (file.size === 0 && index === 0); index += 1) {
      const data = await file.slice(offset, Math.min(offset + this.chunkSize, file.size)).arrayBuffer();
      try { yield await this.encryptChunk(data, key, nonce, index, tenantId); }
      finally { new Uint8Array(data).fill(0); }
      offset += data.byteLength;
      if (file.size === 0) break;
    }
  }
}
