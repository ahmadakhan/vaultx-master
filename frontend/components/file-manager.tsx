"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { UploadCloud, Pause, Play, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sidebar } from "@/components/sidebar";
import { FileGrid } from "@/components/file-grid";
import { FileList } from "@/components/file-list";
import { UploadModal } from "@/components/upload-modal";
import { ShareModal } from "@/components/share-modal";
import { FileDetailModal } from "@/components/file-detail-modal";
import { FileListSkeleton } from "@/components/file-skeleton";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { ViewToggle } from "@/components/view-toggle";
import { SortSelect, applySort } from "@/components/sort-select";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Logs } from "@/components/logs";
import { Progress } from "@/components/ui/progress";
import { Trash } from "./trash";
import { MfaSettings } from "@/components/mfa-settings";
import { decryptBytesWithAes, decryptStringWithAes } from "@/lib/crypto/aes";
import { getVaultXContext, clearVaultXContext } from "@/lib/crypto/context";
import { api } from "@/lib/api";
import { b64ToBuf, bufToB64 } from "@/lib/crypto/base";
import { decryptChunkedGCM } from "@/lib/crypto/chunking";
import type { FileItem, RawFile } from "@/lib/types";
import { errorMessage } from "@/lib/types";

export function FileManager() {
  const [viewMode, setViewMode] = useState<"grid" | "list">("list");
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [shareFileId, setShareFileId] = useState<string | null>(null);
  const [detailFileId, setDetailFileId] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [allFiles, setAllFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState("modified-desc");

  const [activeSection, setActiveSection] = useState("My Vault");
  const [downloadProgress, setDownloadProgress] = useState<Record<string, { percent: number; status: "downloading" | "paused" | "completed" | "stopped" | "error" }>>({});
  const [pausedDownloads, setPausedDownloads] = useState<Record<string, { received: number; total: number; chunks: Uint8Array[] }>>({});
  const abortControllers = useRef<Record<string, AbortController>>({});
  const suppressNextFetch = useRef(false);

  const decryptFiles = useCallback(async (filesRaw: RawFile[]) => {
    const masterKey_b64 = sessionStorage.getItem("vaultx_master_key");
    const privateKey_b64 = sessionStorage.getItem("vaultx_private_key");
    if (!masterKey_b64 || !privateKey_b64)
      throw new Error("Missing master or private key — please log in again.");

    const privKey = await window.crypto.subtle.importKey(
      "pkcs8",
      b64ToBuf(privateKey_b64),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );

    const decryptedFiles: FileItem[] = [];

    for (const f of filesRaw) {
      try {
        let kf_b64: string | null = null;

        if (f.encrypted_kf_b64 && f.encrypted_kf_iv) {
          const kf_bytes = await decryptBytesWithAes(
            f.encrypted_kf_b64,
            f.encrypted_kf_iv,
            masterKey_b64
          );
          kf_b64 = bufToB64(kf_bytes.buffer);
        } else if (f.wrapped_key_b64) {
          try {
            const wrappedKeyBytes = b64ToBuf(f.wrapped_key_b64);
            const unwrapped = await window.crypto.subtle.decrypt(
              { name: "RSA-OAEP" },
              privKey,
              wrappedKeyBytes
            );
            kf_b64 = bufToB64(unwrapped);
          } catch (e) {
            console.warn(`Failed to unwrap Kf for shared file ${f.id}:`, e);
            continue;
          }
        }

        if (!kf_b64) continue;

        sessionStorage.setItem(`vaultx_kf_${f.id}`, kf_b64);

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
          is_shared_with_me: !!f.wrapped_key_b64,
        });
      } catch (err) {
        console.warn("Failed to decrypt metadata for file:", f.id, err);
      }
    }

    return decryptedFiles;
  }, []);

  const fetchAllFiles = useCallback(async () => {
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

      const data = await api.get("/files", ctx.accessToken);
      const decryptedFiles = await decryptFiles(data.files || []);
      setAllFiles(decryptedFiles);
    } catch (err) {
      console.error("Error fetching files:", err);
      setError(errorMessage(err, "Failed to load files."));
      setAllFiles([]);
    } finally {
      setLoading(false);
    }
  }, [decryptFiles]);

  useEffect(() => {
    if (activeSection === "My Vault" || activeSection === "Shared with Me") {
      if (suppressNextFetch.current) {
        suppressNextFetch.current = false;
        return;
      }
      void fetchAllFiles();
    }
  }, [fetchAllFiles, activeSection]);

  useEffect(() => {
    let result = allFiles;
    if (activeSection === "Shared with Me") {
      result = allFiles.filter((f) => f.is_shared_with_me);
    }
    result = applySort(result, sortKey, {
      name: (f) => f.name,
      size: (f) => parseFloat(f.size) || 0,
      modified: (f) => f.modified,
    });
    setFiles(result);
  }, [allFiles, activeSection, sortKey]);

  const handleSearch = useCallback(
    async (query: string) => {
      query = (query || "").trim();

      if (activeSection !== "My Vault") {
        suppressNextFetch.current = true;
        setActiveSection("My Vault");
      }

      if (!query) {
        void fetchAllFiles();
        return;
      }

      setLoading(true);
      try {
        const ctx = getVaultXContext();
        if (!ctx.accessToken) {
          clearVaultXContext();
          alert("Please log in again.");
          window.location.href = "/";
          return;
        }

        const chainJson = sessionStorage.getItem("vaultx_keyword_chain");
        if (!chainJson)
          throw new Error(
            "No keyword chain found. Try uploading a file first."
          );

        const keywordChains = JSON.parse(chainJson);
        const latestToken = keywordChains[query.trim().toLowerCase()];
        if (!latestToken) {
          setAllFiles([]);
          setLoading(false);
          return;
        }

        const searchRes = await api.post(
          "/search",
          { token: latestToken },
          ctx.accessToken
        );
        const values: string[] = searchRes.values || [];
        if (values.length === 0) {
          setAllFiles([]);
          setLoading(false);
          return;
        }

        const searchKey_b64 = sessionStorage.getItem("vaultx_search_key");
        if (!searchKey_b64) throw new Error("Missing search key.");

        const decryptedIds: string[] = [];
        for (const v of values) {
          try {
            const valueObj = typeof v === "string" ? JSON.parse(v) : v;
            if (!valueObj.ciphertext_b64 || !valueObj.iv_b64) continue;
            const id = await decryptStringWithAes(
              valueObj.ciphertext_b64,
              valueObj.iv_b64,
              searchKey_b64
            );
            decryptedIds.push(id);
          } catch (err) {
            console.warn("Failed to decrypt search result:", err);
          }
        }

        const batchRes = await api.post(
          "/files/batch",
          { ids: decryptedIds },
          ctx.accessToken
        );
        const decryptedFiles = await decryptFiles(batchRes.files || []);
        setAllFiles(decryptedFiles);
      } catch (err) {
        console.error("Search failed:", err);
        setError(errorMessage(err, "Search failed"));
        setAllFiles([]);
      } finally {
        setLoading(false);
      }
    },
    [decryptFiles, fetchAllFiles, activeSection]
  );

  const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

  const _mergeChunks = (chunks: Uint8Array[], total: number): ArrayBuffer => {
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result.buffer;
  };

  const handleDownloadFile = async (id: string) => {
    const file = files.find((f) => f.id === id);
    if (!file) {
      console.warn("Download: file not found", id);
      return;
    }
    try {
      await downloadFile(file, id, false);
    } catch (err) {
      console.error("Download failed:", err);
      alert(`Failed to download "${file.name}". Check console for details.`);
    }
  };

  const handlePauseDownload = (id: string) => {
    const controller = abortControllers.current[id];
    if (controller) {
      controller.abort();
    }
    setDownloadProgress((prev) => ({
      ...prev,
      [id]: { ...prev[id], status: "paused" },
    }));
  };

  const handleStopDownload = (id: string) => {
    const controller = abortControllers.current[id];
    if (controller) {
      controller.abort();
    }
    setDownloadProgress((prev) => ({
      ...prev,
      [id]: { percent: 0, status: "stopped" },
    }));
    setPausedDownloads((prev) => {
      const rest = { ...prev };
      delete rest[id];
      return rest;
    });
    delete abortControllers.current[id];
  };

  const handleResumeDownload = async (id: string) => {
    const file = files.find((f) => f.id === id);
    if (!file) return;

    await downloadFile(file, id, true);
  };

   const downloadFile = useCallback(async (file: FileItem, fileId: string, isResume: boolean = false) => {
    const ctx = getVaultXContext();
    if (!ctx.accessToken) {
      clearVaultXContext();
      alert("Please log in again.");
      window.location.href = "/";
      return;
    }

    const controller = new AbortController();
    abortControllers.current[fileId] = controller;

    setDownloadProgress((prev) => ({
      ...prev,
      [fileId]: { percent: 0, status: "downloading" },
    }));

    let totalBytes = 0;
    let file_iv = "";
    let encrypted_kf_b64: string | null = null;
    let encrypted_kf_iv: string | null = null;
    let wrapped_key_b64: string | null = null;
    let ciphertext: ArrayBuffer | null = null;

    let rangeStart = 0;
    let receivedChunks: Uint8Array[] = [];
    let receivedBytes = 0;

    if (isResume && pausedDownloads[fileId]) {
      receivedBytes = pausedDownloads[fileId].received;
      receivedChunks = [...pausedDownloads[fileId].chunks];
      rangeStart = receivedBytes;
    }

    try {
      const rangeHeader = `bytes=${rangeStart}-`;
      const res = await api.getRaw(
        `/files/${fileId}/download?range=${encodeURIComponent(rangeHeader)}`,
        ctx.accessToken,
        rangeHeader
      );

      if (res.status === 206) {
        file_iv = res.headers.get("X-File-Iv") || "";
        encrypted_kf_b64 = res.headers.get("X-Encrypted-Kf");
        encrypted_kf_iv = res.headers.get("X-Encrypted-Kf-Iv") || null;
        wrapped_key_b64 = res.headers.get("X-Wrapped-Key") || null;

        const contentRange = res.headers.get("Content-Range");
        if (contentRange) {
          const parts = contentRange.split("/");
          totalBytes = parseInt(parts[1], 10);
        }

        const reader = res.body?.getReader();
        if (!reader) {
          throw new Error("Streaming not supported by browser");
        }

        while (true) {
          if (controller.signal.aborted) {
            setPausedDownloads((prev) => ({
              ...prev,
              [fileId]: { received: receivedBytes, total: totalBytes, chunks: receivedChunks },
            }));
            setDownloadProgress((prev) => ({
              ...prev,
              [fileId]: {
                percent: totalBytes > 0 ? Math.round((receivedBytes / totalBytes) * 100) : 0,
                status: "paused",
              },
            }));
            return;
          }

          const { done, value } = await reader.read();
          if (done) break;

          receivedChunks.push(value);
          receivedBytes += value.length;

          const percent = totalBytes > 0 ? Math.round((receivedBytes / totalBytes) * 100) : 0;
          setDownloadProgress((prev) => ({
            ...prev,
            [fileId]: { percent, status: "downloading" },
          }));
        }

        ciphertext = _mergeChunks(receivedChunks, receivedBytes);
      } else {
        const data = await res.json();
        ciphertext = b64ToBuf(data.ciphertext) as ArrayBuffer;
        file_iv = data.file_iv;
        encrypted_kf_b64 = data.encrypted_kf_b64;
        encrypted_kf_iv = data.encrypted_kf_iv;
        wrapped_key_b64 = data.wrapped_key_b64;
        totalBytes = ciphertext.byteLength;
      }
    } catch (err) {
      if (controller.signal.aborted) return;
      console.error("Download stream failed, falling back to JSON:", err);
      const data = await api.get(`/files/${fileId}/download`, ctx.accessToken);
      ciphertext = b64ToBuf(data.ciphertext) as ArrayBuffer;
      file_iv = data.file_iv;
      encrypted_kf_b64 = data.encrypted_kf_b64;
      encrypted_kf_iv = data.encrypted_kf_iv;
      wrapped_key_b64 = data.wrapped_key_b64;
      totalBytes = ciphertext.byteLength;
    }

    try {
      const masterKey_b64 = sessionStorage.getItem("vaultx_master_key");
      if (!masterKey_b64) throw new Error("Missing master key — please log in again.");

      let kf_b64: string | null = null;

      if (encrypted_kf_b64 && encrypted_kf_iv) {
        const kf_bytes = await decryptBytesWithAes(
          encrypted_kf_b64,
          encrypted_kf_iv,
          masterKey_b64
        );
        kf_b64 = bufToB64(kf_bytes.buffer);
      } else if (wrapped_key_b64) {
        const privateKeyPem = sessionStorage.getItem("vaultx_private_key");
        if (!privateKeyPem) throw new Error("Missing RSA private key — please log in again.");

        const privateKey = await window.crypto.subtle.importKey(
          "pkcs8",
          Uint8Array.from(atob(privateKeyPem), (c) => c.charCodeAt(0)),
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["decrypt"]
        );

        const encryptedBytes = Uint8Array.from(atob(wrapped_key_b64), (c) => c.charCodeAt(0));
        const unwrappedKey = await window.crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          privateKey,
          encryptedBytes
        );

        kf_b64 = bufToB64(unwrappedKey);
      } else {
        throw new Error("No valid key material found for this file.");
      }

      if (controller.signal.aborted) return;

      const fileKey = await crypto.subtle.importKey(
        "raw",
        Uint8Array.from(atob(kf_b64), (c) => c.charCodeAt(0)),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Segment-wise GCM decryption: files are sealed chunk-by-chunk, each
      // chunk with an IV derived from the persisted file nonce + index.
      const decryptedBytes = await decryptChunkedGCM(ciphertext!, fileKey, file_iv);

      const blob = new Blob([decryptedBytes]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = file.name || "download";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setDownloadProgress((prev) => ({
        ...prev,
        [fileId]: { percent: 100, status: "completed" },
      }));
      delete abortControllers.current[fileId];
      setTimeout(() => {
        setDownloadProgress((prev) => {
          const rest = { ...prev };
          delete rest[fileId];
          return rest;
        });
      }, 2000);
    } catch (err) {
      // Everything after the streaming phase (key unwrap, decryption, blob
      // creation) must surface failures instead of dying as an unhandled
      // rejection with the spinner stuck on "downloading".
      if (controller.signal.aborted) return;
      console.error("Download failed:", err);
      alert(errorMessage(err, "Download failed"));
      setDownloadProgress((prev) => ({
        ...prev,
        [fileId]: { percent: 0, status: "error" },
      }));
      delete abortControllers.current[fileId];
      setTimeout(() => {
        setDownloadProgress((prev) => {
          const rest = { ...prev };
          delete rest[fileId];
          return rest;
        });
      }, 3000);
    }
  }, [pausedDownloads]);

  const handleDeleteFile = async (id: string) => {
    const file = files.find((f) => f.id === id);
    if (!file) {
      console.warn("Delete: file not found", id);
      return;
    }

    const confirmDelete = confirm(
      `Are you sure you want to delete "${file.name}"?`
    );

    if (!confirmDelete) return;

    const prevFiles = files;
    setFiles((cur) => cur.filter((f) => f.id !== id));

    try {
      const ctx = getVaultXContext();
      if (!ctx.accessToken) {
        clearVaultXContext();
        alert("Session expired — please log in again.");
        window.location.href = "/";
        return;
      }

      await api.delete(`/files/${id}`, ctx.accessToken);
    } catch (err) {
      console.error("Delete failed:", err);
      setFiles(prevFiles);
      alert(`Failed to delete "${file.name}". Try again.`);
    }
  };

  const handleShareFile = (id: string) => {
    setShareFileId(id);
    setShareModalOpen(true);
  };

  const handleViewFile = (id: string) => {
    setDetailFileId(id);
    setDetailModalOpen(true);
  };

  const renderContent = () => {
    if (loading) return <FileListSkeleton rows={8} viewMode={viewMode} />;
    if (error)
      return (
        <ErrorState title="Couldn't load files" message={error} onRetry={fetchAllFiles} />
      );
    if (files.length === 0)
      return (
        <EmptyState
          title="No files found"
          description="Upload a file to get started. Your vault is encrypted end-to-end before it leaves your device."
          actionLabel="Upload Files"
          onAction={() => setUploadModalOpen(true)}
        />
      );

    return viewMode === "grid" ? (
      <FileGrid
        files={files}
        onShareFile={handleShareFile}
        onDownloadFile={handleDownloadFile}
        onDeleteFile={handleDeleteFile}
        onViewFile={(f) => handleViewFile(f.id)}
        onPauseDownload={handlePauseDownload}
        onResumeDownload={handleResumeDownload}
        onStopDownload={handleStopDownload}
        downloadProgress={downloadProgress}
      />
    ) : (
      <FileList
        files={files}
        onShareFile={handleShareFile}
        onDownloadFile={handleDownloadFile}
        onDeleteFile={handleDeleteFile}
        onViewFile={(f) => handleViewFile(f.id)}
        onPauseDownload={handlePauseDownload}
        onResumeDownload={handleResumeDownload}
        onStopDownload={handleStopDownload}
        downloadProgress={downloadProgress}
      />
    );
  };

  return (
    <DashboardLayout onSearch={handleSearch} onNavigate={setActiveSection}>
      <div className="flex flex-1">
        {/* Sidebar */}
        <Sidebar
          activeSection={activeSection}
          setActiveSection={setActiveSection}
          onNavigate={setActiveSection}
        />

        <div
          className={`flex-1 flex flex-col overflow-hidden ${
            isDragOver ? "bg-primary/5" : "bg-background"
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            setIsDragOver(false);
          }}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragOver(false);
            setUploadModalOpen(true);
          }}
        >
           {activeSection === "Logs" ? (
            <Logs />
          ) : activeSection === "Trash" ? (
            <Trash />
          ) : activeSection === "Security" ? (
            <div className="flex-1 overflow-y-auto">
              <div className="border-b border-border bg-card px-6 py-4 shadow-sm">
                <h1 className="text-xl font-semibold text-foreground">Security</h1>
                <p className="text-sm text-muted-foreground mt-1">
                  Manage your account security settings.
                </p>
              </div>
              <div className="p-6">
                <MfaSettings />
              </div>
            </div>
          ) : (
            <>
              <div className="border-b border-border bg-card px-6 py-4 flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-4">
                  <h1 className="text-xl font-semibold text-foreground">
                    {activeSection === "Shared with Me"
                      ? "Shared with Me"
                      : "My Vault"}
                  </h1>
                  <SortSelect value={sortKey} onChange={setSortKey} />
                  <span className="text-xs text-muted-foreground">
                    {files.length} item{files.length === 1 ? "" : "s"}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  {activeSection === "My Vault" && (
                    <>
                      <ViewToggle value={viewMode} onChange={setViewMode} />
                      <Button
                        variant="default"
                        size="sm"
                        className="bg-primary hover:bg-primary/90 text-primary-foreground"
                        onClick={() => setUploadModalOpen(true)}
                      >
                        <UploadCloud className="w-4 h-4 mr-2" strokeWidth={1.5} />
                        Upload
                      </Button>
                    </>
                  )}
                  {activeSection === "Shared with Me" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setUploadModalOpen(true)}
                    >
                      <UploadCloud className="w-4 h-4 mr-2" strokeWidth={1.5} />
                      Upload
                    </Button>
                  )}
                </div>
              </div>

              <div className="flex-1 overflow-auto">{renderContent()}</div>
            </>
          )}

          <UploadModal
            open={uploadModalOpen}
            onOpenChange={setUploadModalOpen}
            onUploadSuccess={fetchAllFiles}
          />

          {shareModalOpen && shareFileId && (
            <ShareModal
              open={shareModalOpen}
              onOpenChange={setShareModalOpen}
              file={files.find((f) => f.id === shareFileId)!}
            />
          )}

          {detailModalOpen && detailFileId && (
            <FileDetailModal
              open={detailModalOpen}
              onOpenChange={setDetailModalOpen}
              file={files.find((f) => f.id === detailFileId) ?? null}
            />
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
