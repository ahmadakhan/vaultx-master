export interface FileItem {
  plaintextSize?: number;
  chunkSize?: number;
  id: string
  name: string
  type: "file"
  fileType?: string
  size: string
  modified: string
  owner: string
  shared: boolean
  shared_with?: string[]
  is_shared_with_me?: boolean
}

export interface RawFile {
  id: string
  encrypted_kf_b64?: string
  encrypted_kf_iv?: string
  wrapped_key_b64?: string
  metadata_ciphertext: string
  metadata_iv: string
  created_at: string
  owner_email?: string
  shared_with?: string[]
}

export interface RawLog {
  id: number | string
  entry_json?: Record<string, unknown> | string
  entry?: Record<string, unknown> | string
  entry_hash: string
  prev_hash?: string | null
  created_at: string
}

export type SortKey = "name" | "size" | "modified"
export type SortOrder = "asc" | "desc"

export function errorMessage(err: unknown, fallback = "Something went wrong."): string {
  if (err instanceof Error) return err.message
  if (typeof err === "string") return err
  return fallback
}
