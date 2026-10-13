import { api } from "./api";

export interface UploadSession {
  id: string;
  file_id: string;
  total_bytes: number;
  offset: number;
  chunk_size: number;
  status: "active" | "complete" | "finalized" | "expired" | "cancelled";
  expires_at: string;
}

export interface UploadSessionFinalize {
  metadata_ciphertext_b64: string;
  metadata_iv_b64: string;
  encrypted_kf_b64: string;
  encrypted_kf_iv_b64: string;
  file_iv_b64: string;
  tokens?: Array<{
    token: string;
    prev_token?: string | null;
    value: { ciphertext_b64: string; iv_b64: string };
  }>;
}

export async function beginResumableUpload(fileId: string, totalBytes: number, token: string, chunkSize = 4 * 1024 * 1024): Promise<UploadSession> {
  return api.post("upload-sessions", { file_id: fileId, total_bytes: totalBytes, chunk_size: chunkSize }, token);
}

export async function resumeResumableUpload(sessionId: string, token: string): Promise<UploadSession> {
  return api.get(`upload-sessions/${encodeURIComponent(sessionId)}`, token);
}

export async function sendUploadChunk(session: UploadSession, chunk: Blob, token: string): Promise<UploadSession> {
  if (session.status !== "active") throw new Error("Upload session is not active");
  if (chunk.size === 0) throw new Error("Upload chunk cannot be empty");
  if (chunk.size > session.chunk_size || session.offset + chunk.size > session.total_bytes) {
    throw new Error("Upload chunk exceeds the server session boundary");
  }
  return api.patch(`upload-sessions/${encodeURIComponent(session.id)}`, chunk, token, false, {
    "Content-Type": "application/octet-stream",
    "Upload-Offset": String(session.offset),
  });
}

/** Finalize the staged ciphertext and publish its encrypted file metadata. */
export async function finalizeResumableUpload(session: UploadSession, payload: UploadSessionFinalize, token: string) {
  if ((session.status !== "complete" && session.status !== "finalized") || session.offset !== session.total_bytes) {
    throw new Error("Upload session is not complete");
  }
  return api.post(`upload-sessions/${encodeURIComponent(session.id)}/finalize`, payload, token);
}

export async function cancelResumableUpload(sessionId: string, token: string) {
  return api.delete(`upload-sessions/${encodeURIComponent(sessionId)}`, token);
}

/** Kept for the lifetime of the selected File, never reconstructed from a new selection. */
export interface DurableUploadState {
  begin?: { fileId: string; total: number; frameSize: number };
  session?: UploadSession;
  acknowledged: number;
  nextChunk: number;
  pending?: { bytes: Blob; end: number };
  // A failed encryption may already have used the IV. Never try that IV again.
  encryptionFailed?: boolean;
}

export function createDurableUploadState(): DurableUploadState {
  return { acknowledged: 0, nextChunk: 0 };
}

export async function cancelDurableUpload(state: DurableUploadState, token: string) {
  // Recover a begin receipt lost in transit before cancelling its reservation.
  if (!state.session && state.begin) {
    state.session = await beginResumableUpload(state.begin.fileId, state.begin.total, token, state.begin.frameSize);
  }
  if (state.session) await cancelResumableUpload(state.session.id, token);
  state.pending = undefined;
}

/** Reconcile before sending anything; only our exact retained frame may advance. */
function reconcile(state: DurableUploadState, session: UploadSession, fileId: string, total: number, frameSize: number) {
  if (session.file_id !== fileId || session.total_bytes !== total || session.chunk_size !== frameSize ||
      !Number.isSafeInteger(session.offset) || session.offset < 0 || session.offset > total) {
    throw new Error("Upload session does not match this encrypted file");
  }
  if (session.status === "cancelled" || session.status === "expired") throw new Error(`Upload session ${session.status}; select the file again`);
  if (state.pending && session.offset === state.pending.end) {
    state.acknowledged = session.offset;
    state.nextChunk += 1;
    state.pending = undefined;
  }
  if (session.offset !== state.acknowledged) throw new Error("Unexpected upload offset; refusing to reuse a chunk nonce");
  if ((session.offset === total) !== (session.status === "complete" || session.status === "finalized")) {
    throw new Error("Inconsistent upload session status");
  }
  state.session = session;
}

/** One retained ciphertext frame bounds memory and makes retries byte-identical. */
export async function runDurableUpload(options: {
  state: DurableUploadState;
  fileId: string;
  plaintextSize: number;
  chunkSize: number;
  token: string;
  payload: UploadSessionFinalize;
  encrypt: (index: number) => Promise<Blob>;
  control: () => "run" | "pause" | "cancel";
  onAcknowledged: (chunks: number) => void;
}): Promise<"paused" | "cancelled" | "finalized"> {
  const { state, fileId, plaintextSize, chunkSize, token, payload, encrypt, control, onAcknowledged } = options;
  const count = Math.max(1, Math.ceil(plaintextSize / chunkSize));
  const total = plaintextSize + count * 16;
  // The session limit is ciphertext bytes (AES-GCM adds a 16-byte tag).
  const frameSize = Math.max(64 * 1024, chunkSize + 16);
  state.begin = { fileId, total, frameSize };
  // Begin is idempotent by file_id, including a lost begin response.
  const session = state.session
    ? await resumeResumableUpload(state.session.id, token)
    : await beginResumableUpload(fileId, total, token, frameSize);
  reconcile(state, session, fileId, total, frameSize);
  onAcknowledged(state.nextChunk);
  const boundary = async () => {
    if (control() === "cancel") {
      await cancelResumableUpload(session.id, token);
      state.pending = undefined;
      return "cancelled" as const;
    }
    if (control() === "pause") return "paused" as const;
  };
  while (state.acknowledged < total) {
    const stopped = await boundary();
    if (stopped) return stopped;
    if (!state.pending) {
      if (state.encryptionFailed) throw new Error("Encryption failed; select the file again to use a fresh key and nonce");
      state.encryptionFailed = true;
      const bytes = await encrypt(state.nextChunk);
      const expected = Math.min(chunkSize, plaintextSize - state.nextChunk * chunkSize) + 16;
      if (bytes.size !== expected) throw new Error("Invalid encrypted frame length");
      state.pending = { bytes, end: state.acknowledged + bytes.size };
      state.encryptionFailed = false;
    }
    const stoppedAfterEncryption = await boundary();
    if (stoppedAfterEncryption) return stoppedAfterEncryption;
    const before = state.acknowledged;
    try {
      const next = await sendUploadChunk(state.session!, state.pending.bytes, token);
      reconcile(state, next, fileId, total, frameSize);
      if (state.acknowledged === before) throw new Error("Server did not acknowledge the encrypted frame");
    } catch (error) {
      // A lost response is not a failed write. Query, never blindly replay.
      reconcile(state, await resumeResumableUpload(session.id, token), fileId, total, frameSize);
      if (state.acknowledged === before) {
        const stoppedAfterFailure = await boundary();
        if (stoppedAfterFailure) return stoppedAfterFailure;
        throw error;
      }
    }
    onAcknowledged(state.nextChunk);
  }
  const stopped = await boundary();
  if (stopped) return stopped;
  try {
    await finalizeResumableUpload(state.session!, payload, token);
  } catch (error) {
    reconcile(state, await resumeResumableUpload(session.id, token), fileId, total, frameSize);
    if (state.session!.status !== "finalized") throw error;
    // Retrieve the idempotent publication receipt using the identical payload.
    await finalizeResumableUpload(state.session!, payload, token);
  }
  state.session = { ...state.session!, status: "finalized" };
  return "finalized";
}
