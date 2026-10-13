import { api } from "./api";

export interface GuestDropbox {
  id: string;
  expires_at: string;
  max_bytes: number;
  max_uploads: number;
  active: boolean;
  capability: string;
}

export interface GuestDropboxUpload {
  id: string;
  size: number;
  finalized: boolean;
  status: "pending" | "accepted" | "rejected";
  file_id?: string | null;
}

export async function createGuestDropbox(token: string, options: { maxBytes: number; maxUploads?: number; ttlSeconds?: number }): Promise<GuestDropbox> {
  return api.post("dropboxes", { max_bytes: options.maxBytes, max_uploads: options.maxUploads ?? 1, ttl_seconds: options.ttlSeconds ?? 86400 }, token);
}

/** Guest clients only receive this write operation; no read/list/delete helper exists. */
export async function submitToGuestDropbox(capability: string, payload: Blob, signal?: AbortSignal): Promise<GuestDropboxUpload> {
  const response = await fetch(`/api/dropboxes/${encodeURIComponent(capability)}/uploads`, {
    method: "POST",
    body: payload,
    headers: { "Content-Type": "application/octet-stream" },
    signal,
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error("Dropbox upload was rejected");
  return response.json();
}

export function listGuestDropboxUploads(token: string, dropboxId: string): Promise<GuestDropboxUpload[]> {
  return api.get(`dropboxes/${encodeURIComponent(dropboxId)}/uploads`, token);
}

export function getGuestDropboxUpload(token: string, dropboxId: string, uploadId: string): Promise<GuestDropboxUpload> {
  return api.get(`dropboxes/${encodeURIComponent(dropboxId)}/uploads/${encodeURIComponent(uploadId)}`, token);
}

export function acceptGuestDropboxUpload(token: string, dropboxId: string, uploadId: string, metadata: Record<string, unknown>): Promise<{ id: string; created_at: string }> {
  return api.post(`dropboxes/${encodeURIComponent(dropboxId)}/uploads/${encodeURIComponent(uploadId)}/accept`, metadata, token);
}

export function rejectGuestDropboxUpload(token: string, dropboxId: string, uploadId: string): Promise<GuestDropboxUpload> {
  return api.post(`dropboxes/${encodeURIComponent(dropboxId)}/uploads/${encodeURIComponent(uploadId)}/reject`, undefined, token);
}
