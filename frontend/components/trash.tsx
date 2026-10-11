"use client";
import { memorySession } from "@/lib/crypto/context";

import { useState, useCallback, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { RefreshCw, RotateCcw, Trash2 } from "lucide-react";
import { decryptBytesWithAes, decryptStringWithAes } from "@/lib/crypto/aes";
import { getVaultXContext, clearVaultXContext } from "@/lib/crypto/context";
import { api } from "@/lib/api";
import { bufToB64 } from "@/lib/crypto/base";
import { FileIcon } from "@/components/file-icon";
import { ErrorState } from "@/components/error-state";
import { EmptyState } from "@/components/empty-state";
import type { FileItem, RawFile } from "@/lib/types";
import { errorMessage } from "@/lib/types";

export function Trash() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const decryptFiles = useCallback(async (filesRaw: RawFile[]) => {
    const masterKey_b64 = memorySession.getItem("vaultx_master_key");
    if (!masterKey_b64)
      throw new Error("Missing master key — please log in again.");

    const decryptedFiles: FileItem[] = [];
    for (const f of filesRaw) {
      try {
        if (!f.encrypted_kf_b64 || !f.encrypted_kf_iv) continue;

        const kf_bytes = await decryptBytesWithAes(
          f.encrypted_kf_b64,
          f.encrypted_kf_iv,
          masterKey_b64
        );
        const kf_b64 = bufToB64(kf_bytes.buffer);
        memorySession.setItem(`vaultx_kf_${f.id}`, kf_b64);

        const metadataJson = await decryptStringWithAes(
          f.metadata_ciphertext,
          f.metadata_iv,
          kf_b64
        );
        const meta = JSON.parse(metadataJson);

        decryptedFiles.push({
          id: f.id,
          name: meta.name || "Untitled",
          type: "file",
          fileType: meta.type || "unknown",
          size: meta.size ? `${(meta.size / 1024).toFixed(2)} KB` : "—",
          modified: new Date(f.created_at).toLocaleString(),
          owner: f.owner_email || "You",
          shared: (f.shared_with || []).length > 0,
          shared_with: f.shared_with,
        });
      } catch (err) {
        console.warn("Failed to decrypt metadata for file:", f.id, err);
      }
    }

    return decryptedFiles;
  }, []);

  const fetchTrash = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const ctx = getVaultXContext();
      if (!ctx.accessToken) {
        clearVaultXContext();
        alert("Please log in again.");
        window.location.href = "/";
        return;
      }

      const data = await api.get("/files/deleted", ctx.accessToken);
      const decryptedFiles = await decryptFiles(data.files || []);
      setFiles(decryptedFiles);
    } catch (err) {
      console.error("Error fetching trash:", err);
      setError(errorMessage(err, "Failed to load trash."));
      setFiles([]);
    } finally {
      setLoading(false);
    }
  }, [decryptFiles]);

  useEffect(() => {
    fetchTrash();
  }, [fetchTrash]);

  const handleRestore = async (id: string) => {
    const file = files.find((f) => f.id === id);
    if (!file) return;

    try {
      const ctx = getVaultXContext();
      if (!ctx.accessToken) {
        clearVaultXContext();
        alert("Session expired — please log in again.");
        window.location.href = "/";
        return;
      }

      await api.post(`/files/${id}/restore`, {}, ctx.accessToken);
      setFiles((prev) => prev.filter((f) => f.id !== id));
    } catch (err) {
      console.error("Restore failed:", err);
      alert(`Failed to restore "${file.name}". Try again.`);
    }
  };

  const handlePurge = async (id: string) => {
    const file = files.find((f) => f.id === id);
    if (!file) return;
    if (!confirm(`Permanently delete "${file.name}"? This cannot be undone.`)) return;
    try {
      const ctx = getVaultXContext();
      if (!ctx.accessToken) {
        clearVaultXContext();
        alert("Session expired — please log in again.");
        window.location.href = "/";
        return;
      }
      await api.delete(`/files/${id}/purge`, ctx.accessToken);
      setFiles((prev) => prev.filter((f) => f.id !== id));
    } catch (err) {
      console.error("Purge failed:", err);
      alert(errorMessage(err, `Failed to permanently delete "${file.name}".`));
    }
  };


  return (
    <div className="flex flex-col h-full">
      <div className="border-b border-border bg-card p-4 flex items-center justify-between shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">Trash</h2>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchTrash}
          className="flex items-center gap-1"
        >
          <RefreshCw className="w-4 h-4" strokeWidth={1.5} />
          <span>Refresh</span>
        </Button>
      </div>

      <div className="flex-1 overflow-auto p-6 bg-muted/10">
        {loading ? (
          <TrashSkeleton />
        ) : error ? (
          <ErrorState
            title="Couldn't load trash"
            message={error}
            onRetry={fetchTrash}
          />
        ) : files.length === 0 ? (
          <EmptyState
            title="The bin is empty"
            description="Deleted files stay here until you restore them or permanently delete them."
            actionLabel="Refresh"
            onAction={fetchTrash}
          />
        ) : (
          <div className="space-y-3">
            {files.map((file) => (
              <div
                key={file.id}
                className="flex items-center justify-between gap-4 rounded-lg border border-border bg-card p-3 shadow-sm"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <FileIcon fileType={file.fileType} name={file.name} className="w-10 h-10" />
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {file.name}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {file.size} • {file.modified}
                    </p>
                  </div>
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  className="shrink-0 border-green-600/30 text-success hover:bg-success-muted/30 hover:text-success"
                  onClick={() => handleRestore(file.id)}
                >
                  <RotateCcw className="w-4 h-4 mr-1" strokeWidth={1.5} />
                  Restore
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="shrink-0 border-destructive/30 text-destructive hover:bg-destructive/10"
                  onClick={() => handlePurge(file.id)}
                >
                  <Trash2 className="w-4 h-4 mr-1" strokeWidth={1.5} />
                  Delete forever
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function TrashSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 6 }).map((_, i) => (
        <div
          key={i}
          className="flex items-center gap-3 rounded-lg border border-border bg-card p-3"
        >
          <Skeleton className="h-10 w-10 rounded" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-4 w-40 rounded" />
            <Skeleton className="h-3 w-24 rounded" />
          </div>
          <Skeleton className="h-8 w-20 rounded" />
        </div>
      ))}
    </div>
  );
}
