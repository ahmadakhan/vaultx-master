import { api, ApiError } from "./api";
import { b64ToBuf } from "./crypto/base";
import { buildChunkAad } from "./crypto/aes";
import { buildChunkIv, CHUNK_FORMAT_VERSION, CHUNK_SIZE } from "./crypto/chunking";

/** Maximum plaintext retained when File System Access is unavailable. */
export const MAX_BLOB_FALLBACK_BYTES = 256 * 1024 * 1024;
const GCM_TAG_BYTES = 16;

export interface DownloadWritable {
  write(data: Uint8Array): Promise<void> | void;
  close(): Promise<void> | void;
  abort?(): Promise<void> | void;
  seek?(position: number): Promise<void> | void;
  truncate?(size: number): Promise<void> | void;
}

export interface OwnerDownloadResumeState {
  /** Ciphertext offset. This is always an authenticated frame boundary. */
  ciphertextOffset: number;
  totalCiphertext: number;
  plaintextBytes: number;
  activeMs: number;
  fileIv?: string;
  /** All frames verified; only committing the output remains after a pause. */
  complete?: boolean;
  /** Retained only for the bounded Blob fallback. */
  plaintextParts: Uint8Array[];
  /** A native sink can remain open across a pause and be reused on resume. */
  sink?: DownloadWritable;
}

export type OwnerDownloadResult =
  | { status: "completed"; received: number; total: number; plaintextBytes: number; activeMs: number; blob?: Blob }
  | { status: "paused"; resume: OwnerDownloadResumeState }
  | { status: "cancelled" };

export interface OwnerDownloadOptions {
  fileId: string;
  token: string;
  fileName: string;
  key: CryptoKey;
  fileIv?: string;
  chunkSize?: number;
  expectedPlaintextSize?: number;
  resume?: OwnerDownloadResumeState;
  signal?: AbortSignal;
  /** Return the current user intent when signal is aborted. */
  intent?: () => "pause" | "cancel" | undefined;
  onProgress?: (progress: { received: number; total: number; plaintextBytes: number; activeMs: number }) => void;
  /** Override the network call in tests or an alternate frontend transport. */
  request?: (range: string | undefined, signal: AbortSignal) => Promise<Response>;
  /** Override save-file selection. Returning null uses the bounded Blob path. */
  createSink?: (fileName: string, resume: OwnerDownloadResumeState | undefined) => Promise<DownloadWritable | null>;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError" || error instanceof Error && error.name === "AbortError";
}

function validateChunkSize(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > CHUNK_SIZE) throw new Error("Invalid chunk size");
  return value;
}

function defaultSink(fileName: string): Promise<DownloadWritable | null> {
  if (typeof window === "undefined") return Promise.resolve(null);
  const picker = (window as unknown as {
    showSaveFilePicker?: (options?: unknown) => Promise<{ createWritable: (options?: unknown) => Promise<DownloadWritable> }>;
  }).showSaveFilePicker;
  if (!picker) return Promise.resolve(null);
  return picker.call(window, { suggestedName: fileName }).then(handle => handle.createWritable()).catch(error => {
    if (isAbortError(error)) throw error;
    return null;
  });
}

function clearParts(parts: Uint8Array[]): void {
  for (const part of parts) part.fill(0);
  parts.length = 0;
}

function disposition(options: OwnerDownloadOptions): "pause" | "cancel" {
  return options.intent?.() === "pause" ? "pause" : "cancel";
}

function triggerBlobDownload(blob: Blob, fileName: string): void {
  if (typeof document === "undefined" || typeof URL === "undefined") return;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName || "download";
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Release a paused download when the user cancels or leaves the file manager. */
export async function discardOwnerDownload(state: OwnerDownloadResumeState): Promise<void> {
  clearParts(state.plaintextParts);
  await state.sink?.abort?.();
}

/**
 * Download an owner's framed ciphertext without assembling the encrypted file.
 * Each frame is authenticated before it is written to a File System Access
 * sink. Browsers without that API use a deliberately bounded Blob fallback.
 * Pause returns only at a frame boundary so a later Range request can resume
 * without retaining unbounded ciphertext; cancel wipes retained plaintext.
 */
export async function downloadOwnerFile(options: OwnerDownloadOptions): Promise<OwnerDownloadResult> {
  const chunkSize = validateChunkSize(options.chunkSize ?? CHUNK_SIZE);
  const frameSize = chunkSize + GCM_TAG_BYTES;
  const resume = options.resume;
  if (resume && (!Number.isSafeInteger(resume.ciphertextOffset) || resume.ciphertextOffset < 0 || (!resume.complete && resume.ciphertextOffset % frameSize !== 0))) {
    throw new Error("Invalid download resume offset");
  }
  if (!Number.isSafeInteger(options.expectedPlaintextSize ?? 0) || (options.expectedPlaintextSize ?? 0) < 0) {
    if (options.expectedPlaintextSize !== undefined) throw new Error("Invalid plaintext size");
  }

  const controller = options.signal ? null : new AbortController();
  const signal = options.signal ?? controller!.signal;
  const started = performance.now();
  const priorActiveMs = resume?.activeMs ?? 0;
  const activeMs = () => priorActiveMs + performance.now() - started;
  let received = resume?.ciphertextOffset ?? 0;
  let total = resume?.totalCiphertext ?? 0;
  let plaintextBytes = resume?.plaintextBytes ?? 0;
  const parts = resume?.plaintextParts ?? [];
  let sink: DownloadWritable | undefined = resume?.sink;
  let frameIndex = received / frameSize;
  let fileIv = resume?.fileIv ?? options.fileIv;
  // One ciphertext frame plus the browser's current network read, independent
  // of file length. Never repeatedly concatenate the remaining response.
  const pending = new Uint8Array(frameSize);
  let pendingLength = 0;
  let complete = resume?.complete ?? false;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let response: Response | undefined;

  const progress = () => options.onProgress?.({ received, total, plaintextBytes, activeMs: activeMs() });
  const pausedState = (): OwnerDownloadResumeState => ({
    ciphertextOffset: received,
    totalCiphertext: total,
    plaintextBytes,
    activeMs: activeMs(),
    fileIv,
    complete,
    plaintextParts: parts,
    ...(sink ? { sink } : {}),
  });
  const handleAbort = async (): Promise<OwnerDownloadResult> => {
    if (disposition(options) === "pause") {
      if (received === total && received >= GCM_TAG_BYTES && (options.expectedPlaintextSize === undefined || plaintextBytes === options.expectedPlaintextSize)) complete = true;
      // Do not retain a partial frame. It will be requested again from the
      // authenticated boundary on resume.
      pending.fill(0);
      return { status: "paused", resume: pausedState() };
    }
    clearParts(parts);
    if (sink?.abort) await sink.abort();
    return { status: "cancelled" };
  };

  const request = options.request ?? ((range: string | undefined, requestSignal: AbortSignal) =>
    api.getRaw(`/files/${encodeURIComponent(options.fileId)}/download${range ? `?range=${encodeURIComponent(range)}` : ""}`, options.token, range, undefined, requestSignal));
  const abortRead = () => { void reader?.cancel().catch(() => undefined); };
  try {
    if (signal.aborted) return await handleAbort();
    // Resume retains the original destination, including the Blob choice.
    if (!resume) sink = (await (options.createSink ?? defaultSink)(options.fileName, resume)) ?? undefined;
    if (sink && resume?.plaintextBytes && sink.seek) await sink.seek(resume.plaintextBytes);
    if (signal.aborted) return await handleAbort();
    if (!sink && (options.expectedPlaintextSize ?? plaintextBytes) > MAX_BLOB_FALLBACK_BYTES) {
      throw new Error("This browser cannot safely download files larger than 256 MiB; use file-save streaming support");
    }
    if (!complete) {
    try {
      response = await request(`bytes=${received}-`, signal);
    } catch (error) {
      // Only the known legacy no-range response merits retry, never auth or
      // uncertain transport failures.
      if (received === 0 && error instanceof ApiError && error.status === 404 && !signal.aborted) response = await request(undefined, signal);
      else throw error;
    }
    if (signal.aborted) return await handleAbort();
    if (!response.ok) throw new Error("Download request failed");
    const contentRange = response.headers.get("Content-Range");
    if (response.status === 206) {
    const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(contentRange ?? "");
    if (!match || Number(match[1]) !== received || !Number.isSafeInteger(Number(match[3])) || Number(match[2]) !== Number(match[3]) - 1) throw new Error("Download range does not match the requested offset");
    total = Number(match[3]);
    } else if (response.status === 200) {
    if (received !== 0) {
      if (sink) {
        if (!sink.seek || !sink.truncate) throw new Error("The server cannot resume this download; cancel and start again");
        await sink.truncate(0);
        await sink.seek(0);
      }
      clearParts(parts);
      plaintextBytes = 0;
      received = 0;
      frameIndex = 0;
    }
    total = Number(response.headers.get("Content-Length")) || 0;
    } else throw new Error("Unexpected download response");
    if (!response.headers.get("Content-Type")?.includes("application/octet-stream")) {
    // Inline legacy response. It is only accepted when it fits the explicit
    // memory bound; normal large files use the streaming response above.
    // The legacy JSON route is for files <= 1 MiB. Bound the response *before*
    // parsing so a misleading Content-Length cannot trigger unlimited JSON.
    reader = response.body?.getReader();
    if (!reader) throw new Error("Missing download body");
    signal.addEventListener("abort", abortRead, { once: true });
    const jsonParts: Uint8Array[] = [];
    let jsonBytes = 0;
    while (true) {
      if (signal.aborted) return await handleAbort();
      const { done, value } = await reader.read();
      if (done) break;
      jsonBytes += value.byteLength;
      if (jsonBytes > 4 * 1024 * 1024) throw new Error("Inline download exceeds the 4 MiB response limit");
      jsonParts.push(value);
    }
    reader.releaseLock();
    reader = undefined;
    const json = new Uint8Array(jsonBytes);
    let offset = 0;
    for (const part of jsonParts) { json.set(part, offset); offset += part.length; }
    const data = JSON.parse(new TextDecoder().decode(json)) as { ciphertext?: string; file_iv?: string };
    if (!data.ciphertext || data.ciphertext.length > MAX_BLOB_FALLBACK_BYTES * 2) throw new Error("This browser cannot safely download this file without streaming save support");
    const inline = new Uint8Array(b64ToBuf(data.ciphertext));
    if (inline.byteLength > MAX_BLOB_FALLBACK_BYTES) throw new Error("This browser cannot safely download this file without streaming save support");
    if (data.file_iv) fileIv = data.file_iv;
    total = inline.byteLength;
    response = new Response(inline, { status: 200, headers: { "Content-Length": String(total), "Content-Type": "application/octet-stream" } });
  }

  const responseIv = response.headers.get("X-File-Iv");
  if (fileIv && responseIv && fileIv !== responseIv) throw new Error("File IV changed during download");
  if (!fileIv) fileIv = responseIv ?? undefined;
  if (!fileIv) throw new Error("Missing file IV");
  const nonce = new Uint8Array(b64ToBuf(fileIv));
  if (nonce.byteLength !== 12) throw new Error("Invalid file IV");

  const consume = async (frame: Uint8Array, final: boolean): Promise<void> => {
    if (frame.byteLength < GCM_TAG_BYTES || (frameIndex > 0 && frame.byteLength === GCM_TAG_BYTES) || (!final && frame.byteLength !== frameSize)) throw new Error("Malformed encrypted file");
    const iv = buildChunkIv(nonce, frameIndex);
    const decrypted = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv,
      additionalData: buildChunkAad(CHUNK_FORMAT_VERSION, options.fileId, frameIndex, frame.byteLength - GCM_TAG_BYTES) as BufferSource,
    }, options.key, frame as BufferSource);
    const plain = new Uint8Array(decrypted);
    try {
      if (!sink && plaintextBytes + plain.byteLength > MAX_BLOB_FALLBACK_BYTES) throw new Error("This browser cannot safely download files larger than 256 MiB; use file-save streaming support");
      if (signal.aborted) throw new DOMException("Download interrupted", "AbortError");
      if (sink) await sink.write(plain);
      else parts.push(plain.slice());
      plaintextBytes += plain.byteLength;
      frameIndex += 1;
      received += frame.byteLength;
      progress();
    } finally {
      plain.fill(0);
    }
  };

    reader = response.body?.getReader();
    if (!reader) throw new Error("Streaming not supported by browser");
    signal.addEventListener("abort", abortRead, { once: true });
    while (true) {
      if (signal.aborted) {
        await reader.cancel().catch(() => undefined);
        return await handleAbort();
      }
      const { done, value } = await reader.read();
      if (signal.aborted) return await handleAbort();
      if (done) break;
      if (!value?.byteLength) continue;
      let offset = 0;
      while (offset < value.byteLength) {
        const count = Math.min(frameSize - pendingLength, value.byteLength - offset);
        pending.set(value.subarray(offset, offset + count), pendingLength);
        pendingLength += count;
        offset += count;
        if (pendingLength === frameSize) {
          await consume(pending, false);
          pending.fill(0);
          pendingLength = 0;
        }
        if (signal.aborted) {
          await reader.cancel().catch(() => undefined);
          return await handleAbort();
        }
      }
    }
    if (pendingLength) {
      await consume(pending.subarray(0, pendingLength), true);
    }
    if (received < GCM_TAG_BYTES || (total > 0 && received !== total)) throw new Error("File size does not match authenticated metadata");
    if (options.expectedPlaintextSize !== undefined && plaintextBytes !== options.expectedPlaintextSize) throw new Error("File size does not match authenticated metadata");
    complete = true;
    }
    if (signal.aborted) return await handleAbort();
    if (sink) {
      await sink.close();
      return { status: "completed", received, total, plaintextBytes, activeMs: activeMs() };
    }
    const blob = new Blob(parts.map(part => part.buffer as ArrayBuffer));
    triggerBlobDownload(blob, options.fileName);
    clearParts(parts);
    return { status: "completed", received, total, plaintextBytes, activeMs: activeMs(), blob };
  } catch (error) {
    if (isAbortError(error) || signal.aborted && !reader) return await handleAbort();
    clearParts(parts);
    if (sink?.abort) await sink.abort();
    throw error;
  } finally {
    pending.fill(0);
    signal.removeEventListener("abort", abortRead);
    if (reader) {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    } else await response?.body?.cancel().catch(() => undefined);
  }
}
