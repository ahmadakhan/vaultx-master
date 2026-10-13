"use client";

import { useState, useRef, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TransferStats } from "@/components/transfer-stats";
import { Badge } from "@/components/ui/badge";
import {
  UploadCloud,
  X,
  CheckCircle,
  AlertTriangle,
  FileText,
  Sparkles,
  Pause,
  Play,
  Square,
} from "lucide-react";
import { aesEncryptArrayBuffer, encryptStringWithAes } from "@/lib/crypto/aes";
import { generateFileKey } from "@/lib/crypto/keys";
import { bufToB64, genRandomBytes } from "@/lib/crypto/base";
import { CHUNK_SIZE, buildChunkIv } from "@/lib/crypto/chunking";
import { api } from "@/lib/api";
import { errorMessage } from "@/lib/types";
import { memorySession } from "@/lib/crypto/context";
import mammoth from "mammoth";

interface UploadFile {
  id: string;
  file: File;
  progress: number;
  status: "preparing" | "pending" | "uploading" | "pausing" | "paused" | "completed" | "error" | "stopped";
  activeMs?: number;
  errorMessage?: string;
  selectedKeywords?: string[];
  autoKeywords?: string[];
  uploadedBytes: number;
  pausedAtChunk: number;
  totalChunks: number;
  fileKey_b64?: string;
  metadataEnc?: { ciphertext_b64: string; iv_b64: string };
  kfEnc?: { ciphertext_b64: string; iv_b64: string };
  fileEncIv?: string;
  tokens_json?: string;
  keywordChains?: Record<string, string>;
  encFileId?: { ciphertext_b64: string; iv_b64: string };
}

interface UploadModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUploadSuccess?: () => void;
  initialFiles?: File[];
}

async function extractKeywordsFromFile(file: File): Promise<string[]> {
  const nameKeywords = file.name
    .replace(/\.[^/.]+$/, "")
    .split(/[\s\-_]+/)
    .map((k) => k.toLowerCase())
    .filter((k) => k.length > 2);

  const typeKeywords = getTypeKeywords(file.type, file.name);
  const contentText = await readFileContent(file);
  const contentKeywords = getTopKeywords(contentText, 10);

  const combined = new Set([...nameKeywords, ...typeKeywords, ...contentKeywords]);
  return Array.from(combined);
}

function getTypeKeywords(type: string, name: string): string[] {
  const lower = name.toLowerCase();
  if (type.startsWith("text/")) return ["text", "document"];
  if (type.startsWith("image/")) return ["image", "photo"];
  if (type.startsWith("video/")) return ["video", "media"];
  if (type === "application/pdf" || lower.endsWith(".pdf")) return ["pdf", "document"];
  if (lower.endsWith(".docx")) return ["word", "document"];
  if (lower.endsWith(".xlsx") || lower.endsWith(".xls")) return ["excel", "spreadsheet"];
  if (lower.endsWith(".csv")) return ["csv", "data"];
  if (lower.endsWith(".pptx")) return ["presentation", "slides"];
  if (lower.endsWith(".zip") || lower.endsWith(".tar") || lower.endsWith(".gz")) return ["archive"];
  return [];
}

async function readFileContent(file: File): Promise<string> {
  const lower = file.name.toLowerCase();
  // Content indexing is optional; bound parser input independently of upload
  // size so large files do not exhaust the tab before encryption starts.
  if (file.size > 10 * 1024 * 1024) return "";

  try {
    if (file.type.startsWith("text/") || lower.endsWith(".json") || lower.endsWith(".csv")) {
      return await file.text();
    }

    if (file.type === "application/pdf" || lower.endsWith(".pdf")) {
      const pdfjsLib = await import("pdfjs-dist/webpack");
      // webpack entry bundles its matching worker locally.

      const pdf = await pdfjsLib
        .getDocument({ data: await file.arrayBuffer() })
        .promise;

      let text = "";
      const maxPages = Math.min(pdf.numPages, 3);
      for (let i = 1; i <= maxPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        text += content.items.map((i: { str: string }) => i.str).join(" ");
      }
      return text;
    }

    if (lower.endsWith(".docx")) {
      const buffer = await file.arrayBuffer();
      const result = await mammoth.extractRawText({ arrayBuffer: buffer });
      return result.value || "";
    }

    // Spreadsheet uploads retain filename/type keywords. Avoid parsing
    // untrusted workbooks with the unmaintained npm xlsx distribution.

    return "";
  } catch {
    return "";
  }
}

function getTopKeywords(text: string, max: number): string[] {
  if (!text) return [];
  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 3);

  const freq: Record<string, number> = Object.create(null);
  for (const w of words) freq[w] = (freq[w] || 0) + 1;

  const stopWords = new Set([
    "this", "that", "from", "with", "have", "were", "there", "their", "which", "about",
    "would", "could", "your", "when", "where", "what", "will", "then", "them", "they",
    "been", "into", "some", "more", "than", "just", "also", "very", "and", "for", "not",
    "are", "was", "the", "you", "but", "all", "can"
  ]);

  return Object.entries(freq)
    .filter(([w]) => !stopWords.has(w))
    .sort((a, b) => b[1] - a[1])
    .slice(0, max)
    .map(([w]) => w);
}

function formatSize(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(2)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(2)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function UploadModal({ open, onOpenChange, onUploadSuccess, initialFiles }: UploadModalProps) {
  const [uploadFiles, renderUploadFiles] = useState<UploadFile[]>([]);
  // Synchronous ownership/state guards also cover clicks before React renders.
  const filesRef = useRef<UploadFile[]>([]);
  const workerActive = useRef(false);
  const setUploadFiles = (update: UploadFile[] | ((files: UploadFile[]) => UploadFile[])) => {
    filesRef.current = typeof update === "function" ? update(filesRef.current) : update;
    renderUploadFiles(filesRef.current);
  };
  const [globalKeywords, setGlobalKeywords] = useState<string[]>([]);
  const [currentKeyword, setCurrentKeyword] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [queueError, setQueueError] = useState<string | null>(null);
  const clocks = useRef<Record<string, { started: number; elapsed: number }>>({});
  const lastBatch = useRef<File[] | undefined>(undefined);
  useEffect(() => {
    if (initialFiles && initialFiles !== lastBatch.current) {
      lastBatch.current = initialFiles;
      void addFiles(initialFiles);
    }
  });

  const resetModal = () => {
    setUploadFiles([]);
    setGlobalKeywords([]);
    setCurrentKeyword("");
    setIsUploading(false);
    setQueueError(null);
    clocks.current = {};
  };

  const closeModal = (openState: boolean) => {
    if (!openState && workerActive.current) return;
    if (!openState) {
      resetModal();
    }
    onOpenChange(openState);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!workerActive.current) setDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    void addFiles(Array.from(e.dataTransfer.files));
  };

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    await addFiles(files);
  }

  function handleToggleKeyword(fileId: string, kw: string) {
    setUploadFiles((prev) =>
      prev.map((f) => {
        if (f.id !== fileId) return f;
        const exists = f.selectedKeywords?.includes(kw);
        const updated = exists
          ? f.selectedKeywords?.filter((k) => k !== kw)
          : [...(f.selectedKeywords || []), kw];
        return { ...f, selectedKeywords: updated };
      })
    );
  }

  const addFiles = async (files: File[]) => {
    if (workerActive.current) return;
    const seen = new Set(filesRef.current.map(({ file }) => `${file.name}:${file.size}:${file.lastModified}`));
    const unique = files.filter((file) => {
      const key = `${file.name}:${file.size}:${file.lastModified}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    setQueueError(unique.length < files.length ? "Duplicate selections skipped." : null);
    const newFiles = unique.map((file) => ({
      id: crypto.randomUUID(),
      file,
      progress: 0,
      status: "preparing" as const,
      uploadedBytes: 0,
      pausedAtChunk: 0,
      totalChunks: Math.ceil(file.size / CHUNK_SIZE) || 1,
    }));
    setUploadFiles((prev) => [...prev, ...newFiles]);
    for (const item of newFiles) {
      if (!filesRef.current.some((f) => f.id === item.id && f.status === "preparing")) continue;
      try {
        const autoKeywords = await extractKeywordsFromFile(item.file);
        setUploadFiles((prev) => prev.map((f) => f.id === item.id && f.status === "preparing" ? { ...f, autoKeywords, selectedKeywords: autoKeywords, status: "pending" } : f));
      } catch (error) {
        setUploadFiles((prev) => prev.map((f) => f.id === item.id && f.status === "preparing" ? { ...f, status: "error", errorMessage: errorMessage(error, "Could not prepare file") } : f));
      }
    }
  };

  const handleAddKeyword = () => {
    const k = currentKeyword.trim().toLowerCase();
    if (k && !globalKeywords.includes(k)) {
      setGlobalKeywords((prev) => [...prev, k]);
      setCurrentKeyword("");
    }
  };

  const handleRemoveKeyword = (kw: string) =>
    setGlobalKeywords((prev) => prev.filter((k) => k !== kw));

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAddKeyword();
    }
  };

  const handlePauseUpload = (fileId: string) => {
    setUploadFiles((prev) =>
      prev.map((f) => (f.id === fileId && f.status === "uploading" ? { ...f, status: "pausing" } : f))
    );
  };

  const handleStopUpload = (fileId: string) => {
    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === fileId && f.status !== "completed"
          ? { ...f, status: "stopped" }
          : f
      )
    );
  };

  async function handleDone(fileId?: string) {
    if (workerActive.current || filesRef.current.some((f) => f.status === "preparing")) return;
    const pendingFiles = filesRef.current.filter(
      (f) => (!fileId || f.id === fileId) && (f.status === "pending" || f.status === "paused")
    );
    if (pendingFiles.length === 0) return;

    const token = memorySession.getItem("vaultx_access_token");
    const masterKey_b64 = memorySession.getItem("vaultx_master_key");
    if (!token || !masterKey_b64) {
      setQueueError("Missing keys or token. Please log in again.");
      return;
    }

    workerActive.current = true;
    setIsUploading(true);
    let activeFileId: string | undefined;
    try {
      const keywordChains: Record<string, string> = JSON.parse(
        memorySession.getItem("vaultx_keyword_chain") || "{}"
      );

      const masterKeyBytes = Uint8Array.from(atob(masterKey_b64), (c) =>
        c.charCodeAt(0)
      );
      let masterKey: CryptoKey;
      try {
        masterKey = await crypto.subtle.importKey(
          "raw",
          masterKeyBytes,
          { name: "AES-GCM" },
          false,
          ["encrypt"]
        );
      } finally {
        // Best effort for this owned buffer; JS strings/runtime copies remain.
        masterKeyBytes.fill(0);
      }

      for (const item of pendingFiles) {
        const current = filesRef.current.find((f) => f.id === item.id);
        if (!current || current.status === "stopped") continue;
        activeFileId = current.id;

        const completed = await uploadSingleFile(current, token, masterKey_b64, masterKey, keywordChains);
        if (!completed) break;
      }

    } catch (err) {
      const msg = errorMessage(err, "Upload failed");
      setUploadFiles((prev) =>
        prev.map((f) => f.id === activeFileId && f.status !== "stopped" ? ({
          ...f,
          status: "error" as const,
          errorMessage: msg,
        }) : f)
      );
      setQueueError(msg);
    } finally {
      workerActive.current = false;
      setIsUploading(false);
    }
  }

  async function uploadSingleFile(
    item: UploadFile,
    token: string,
    masterKey_b64: string,
    masterKey: CryptoKey,
    persistedChains: Record<string, string>
  ) {
    clocks.current[item.id] = { started: performance.now(), elapsed: item.activeMs ?? 0 };
    const elapsed = () => {
      const clock = clocks.current[item.id];
      return clock.elapsed + performance.now() - clock.started;
    };
    const keywordChains: Record<string, string> = Object.assign(Object.create(null), persistedChains, item.keywordChains);
    const stopAtBoundary = () => {
      const status = filesRef.current.find((f) => f.id === item.id)?.status;
      if (status === "pausing") {
        setUploadFiles((prev) => prev.map((f) => f.id === item.id ? { ...f, status: "paused", activeMs: elapsed() } : f));
      }
      return status === "pausing" || status === "stopped" || !status;
    };

    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === item.id
          ? { ...f, status: "uploading" }
          : f
      )
    );

    // Encryption state resolves into LOCALS: React state snapshots held by
    // this closure can be stale, and the file IV must never fall back to a
    // fresh random value — the server persists whatever the first chunk sends
    // and every download derives all chunk IVs from it.
    let fileKey_b64 = item.fileKey_b64;
    let metadataEnc = item.metadataEnc;
    let kfEnc = item.kfEnc;
    let tokens_json: string | undefined = item.tokens_json;
    let fileEncIv = item.fileEncIv;

    if (!fileKey_b64 || !metadataEnc || !kfEnc) {
      fileKey_b64 = await generateFileKey();
      const fileKeyBytes = Uint8Array.from(atob(fileKey_b64), (c) => c.charCodeAt(0));
      try {
        const fileKey = await crypto.subtle.importKey(
          "raw",
          fileKeyBytes,
          { name: "AES-GCM" },
          false,
          ["encrypt"]
        );

        const metadata = JSON.stringify({
          name: item.file.name,
          size: item.file.size,
          type: item.file.type,
          chunk_size: CHUNK_SIZE,
          keywords: [
            ...new Set([
              ...globalKeywords,
              ...(item.selectedKeywords?.length
                ? item.selectedKeywords
                : item.autoKeywords || []),
            ]),
          ],
        });

        metadataEnc = await aesEncryptArrayBuffer(
          new TextEncoder().encode(metadata).buffer,
          fileKey
        );

        kfEnc = await aesEncryptArrayBuffer(fileKeyBytes.buffer, masterKey);
      } finally {
        fileKeyBytes.fill(0);
      }

      const searchKey_b64 = memorySession.getItem("vaultx_search_key");
      if (!searchKey_b64) {
        throw new Error("Missing search key. Please log in again.");
      }
      const encFileId = await encryptStringWithAes(item.id, searchKey_b64);

      const allKeywords = [
        ...new Set([
          ...globalKeywords,
          ...(item.selectedKeywords?.length
            ? item.selectedKeywords
            : item.autoKeywords || []),
        ]),
      ];

      const tokens = allKeywords.map((kw) => {
        const tokenBytes = genRandomBytes(32);
        const prev_token = keywordChains[kw] || null;
        const obj = {
          token: bufToB64(tokenBytes.buffer as ArrayBuffer),
          value: {
            ciphertext_b64: encFileId.ciphertext_b64,
            iv_b64: encFileId.iv_b64,
          },
          prev_token,
        };
        keywordChains[kw] = obj.token;
        return obj;
      });

      tokens_json = JSON.stringify(tokens);
      // One nonce per file, generated once and persisted — every chunk IV is
      // derived from it (see lib/crypto/chunking.ts).
      const fileIvBytes = crypto.getRandomValues(new Uint8Array(12));
      fileEncIv = bufToB64(fileIvBytes.buffer as ArrayBuffer);

      setUploadFiles((prev) =>
        prev.map((f) =>
          f.id === item.id && f.status !== "stopped"
            ? {
                ...f,
                fileKey_b64,
                metadataEnc,
                kfEnc,
                tokens_json,
                fileEncIv,
                keywordChains: { ...keywordChains },
              }
            : f
        )
      );

      if (stopAtBoundary()) return false;
    }

    if (!fileKey_b64 || !metadataEnc || !kfEnc || !tokens_json || !fileEncIv) {
      throw new Error("Encryption state lost. Please retry.");
    }

    const totalSize = item.file.size;
    let uploadedBytes = Math.min(item.pausedAtChunk * CHUNK_SIZE, totalSize);
    const totalChunks = Math.ceil(totalSize / CHUNK_SIZE) || 1;
    const fileNonce = Uint8Array.from(atob(fileEncIv), (c) => c.charCodeAt(0));

      for (let chunkIndex = item.pausedAtChunk; chunkIndex < totalChunks; chunkIndex++) {
        if (stopAtBoundary()) return false;

        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, totalSize);
        const chunk = item.file.slice(start, end);
        const chunkBuffer = await chunk.arrayBuffer();
        try {
          const fileKeyBytes = Uint8Array.from(atob(fileKey_b64), (c) => c.charCodeAt(0));
          let chunkKey: CryptoKey;
          try {
            chunkKey = await crypto.subtle.importKey(
              "raw",
              fileKeyBytes,
              { name: "AES-GCM" },
              false,
              ["encrypt", "decrypt"]
            );
          } finally {
            fileKeyBytes.fill(0);
          }

          // Derive this chunk's IV from the persisted file nonce + chunk index.
          const chunkIv = buildChunkIv(fileNonce, chunkIndex);
        const encryptedChunk = await aesEncryptArrayBuffer(chunkBuffer, chunkKey, chunkIv);
        if (stopAtBoundary()) return false;
        const chunkBytes = Uint8Array.from(atob(encryptedChunk.ciphertext_b64), (c) =>
          c.charCodeAt(0)
        );

        const formData = new FormData();
        formData.append("file_id", item.id);
        formData.append("metadata_ciphertext", metadataEnc.ciphertext_b64);
        formData.append("metadata_iv", metadataEnc.iv_b64);
        formData.append("encrypted_kf_b64", kfEnc.ciphertext_b64);
        formData.append("encrypted_kf_iv", kfEnc.iv_b64);
        formData.append("file_iv", fileEncIv);
        formData.append("tokens_json", tokens_json);
        formData.append("file", new Blob([chunkBytes.buffer]));
        formData.append("chunk_index", String(chunkIndex));
        formData.append("total_chunks", String(totalChunks));
        formData.append("is_last_chunk", chunkIndex === totalChunks - 1 ? "true" : "false");

        await api.post("/files/upload", formData, token, false);

        uploadedBytes = end;
        const percent = totalSize === 0 ? 100 : (uploadedBytes / totalSize) * 100;
        setUploadFiles((prev) =>
          prev.map((f) =>
            f.id === item.id && f.status !== "stopped"
              ? { ...f, progress: percent, uploadedBytes, pausedAtChunk: chunkIndex + 1, activeMs: elapsed() }
              : f
          )
        );
      } finally {
        // Only the owned plaintext chunk can be overwritten, not runtime copies.
        new Uint8Array(chunkBuffer).fill(0);
      }
    }

    // Acknowledgement of the final chunk commits the file on the server.
    // Finish its search head even if stop/pause arrived during that request.
    // Persist the search head after each completed file, using actual async
    // completion rather than the stale React snapshot captured by the caller.
    const chainJson = JSON.stringify(keywordChains);
    const encChain = await encryptStringWithAes(chainJson, masterKey_b64);
    await api.post("/user/index_state", {
      index_state_ciphertext: encChain.ciphertext_b64,
      index_state_iv: encChain.iv_b64,
    }, token);
    Object.assign(persistedChains, keywordChains);
    memorySession.setItem("vaultx_keyword_chain", chainJson);
    memorySession.setItem(`vaultx_kf_${item.id}`, fileKey_b64);
    const wasAborted = filesRef.current.find((f) => f.id === item.id)?.status === "stopped";
    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === item.id && f.status !== "stopped" ? { ...f, status: "completed", progress: 100, uploadedBytes: totalSize, activeMs: elapsed() } : f
      )
    );
    onUploadSuccess?.();
    return !wasAborted;
  }

  const handleResumeUpload = async (fileId: string) => {
    const file = filesRef.current.find((f) => f.id === fileId);
    if (!file || file.status !== "paused") return;
    await handleDone(fileId);
  };

  const removeFile = (id: string) =>
    setUploadFiles((prev) => prev.filter((f) => f.id !== id));

  const completedCount = uploadFiles.filter(
    (f) => f.status === "completed"
  ).length;
  const pendingCount = uploadFiles.filter(
      (f) => f.status === "pending" || f.status === "uploading" || f.status === "pausing" || f.status === "paused"
  ).length;
  const errorCount = uploadFiles.filter((f) => f.status === "error").length;

  const statusIcon = (s: UploadFile["status"]) =>
    s === "completed" ? (
      <CheckCircle className="w-4 h-4 text-success" />
    ) : s === "uploading" || s === "pausing" || s === "preparing" ? (
      <span className="w-4 h-4 animate-spin border-2 border-primary border-t-transparent rounded-full" />
    ) : s === "paused" ? (
      <Pause className="w-4 h-4 text-warning" />
    ) : s === "stopped" ? (
      <Square className="w-4 h-4 text-muted-foreground" />
    ) : s === "error" ? (
      <AlertTriangle className="w-4 h-4 text-destructive" />
    ) : (
      <FileText className="w-4 h-4 text-muted-foreground" />
    );

  return (
    <Dialog open={open} onOpenChange={closeModal}>
      <DialogContent className="max-w-3xl max-h-[90dvh] flex flex-col overflow-y-auto border border-border shadow-none">
        <DialogHeader>
          <DialogTitle>Upload Files</DialogTitle>
          <DialogDescription className="text-sm text-muted-foreground">
            Files are encrypted client-side before leaving your device.
            {" "}Files upload sequentially. Pause waits for the current chunk request and holds the queue. Abort does not undo chunks already sent;
            a final chunk already in flight may complete the file.
          </DialogDescription>
        </DialogHeader>

        <div
          className={`flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-6 text-center transition-colors duration-200 ease-[cubic-bezier(0.2,0,0,1)] motion-reduce:transition-none ${dragActive ? "border-primary bg-primary/10" : "border-border bg-muted/30"}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <UploadCloud className="w-10 h-10 mx-auto mb-3 text-muted-foreground" strokeWidth={1.5} />
          <p className="text-sm font-medium text-foreground mb-1">
            Drag & drop files here, or select files
          </p>
          <p className="text-xs text-muted-foreground mb-4">
            Any file type · Configured upload limit unavailable
          </p>
          <Button variant="outline" className="min-h-11" disabled={isUploading} onClick={() => fileInputRef.current?.click()}>
              Select files
          </Button>
              <input
                ref={fileInputRef}
                aria-label="Select files to upload"
                type="file"
                multiple
                className="hidden"
                onChange={handleFileSelect}
                disabled={isUploading}
              />
        </div>

        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <Label className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground">
              Global Keywords
            </Label>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Sparkles className="w-3.5 h-3.5" strokeWidth={1.5} />
              <span>Suggested automatically</span>
            </div>
          </div>
          <div className="flex space-x-2 mb-2">
            <Input
              value={currentKeyword}
              onChange={(e) => setCurrentKeyword(e.target.value)}
              onKeyDown={handleKeyPress}
              placeholder="Add a keyword and press Enter"
              className="min-h-11 border-border focus:border-ring"
              disabled={isUploading}
            />
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="min-h-11"
              onClick={handleAddKeyword}
              disabled={!currentKeyword.trim() || isUploading}
            >
              Add
            </Button>
          </div>
          <div className="flex flex-wrap gap-2">
            {globalKeywords.map((kw) => (
              <Badge
                key={kw}
                variant="outline"
                className="text-xs border-border text-muted-foreground"
              >
                {kw}
                <button
                  type="button"
                  onClick={() => handleRemoveKeyword(kw)}
                  className="ml-1.5 min-h-11 min-w-11 inline-flex items-center justify-center rounded hover:bg-muted cursor-pointer"
                  aria-label={`Remove keyword ${kw}`}
                  disabled={isUploading}
                >
                  <X className="w-3 h-3" />
                </button>
              </Badge>
            ))}
          </div>
        </div>

        {queueError && <p role="alert" className="text-sm text-destructive">{queueError}</p>}
        {uploadFiles.length === 0 && <p className="text-sm text-muted-foreground">Your upload queue is empty. Select files to prepare encrypted uploads.</p>}
        {uploadFiles.length > 0 && (
          <div className="space-y-4 overflow-y-auto flex-1">
            {uploadFiles.map((f) => (
              <div
                key={f.id}
                className="flex flex-wrap items-start gap-3 rounded-lg border border-border bg-muted/20 p-3"
              >
                <div className="flex items-center justify-center w-10 h-10 rounded bg-muted/60 shrink-0">
                  {statusIcon(f.status)}
                </div>

                <div className="flex-1 min-w-0 basis-[70%]">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-foreground truncate">
                      {f.file.name}
                    </p>
                    <span className="text-xs text-muted-foreground">
                      {formatSize(f.file.size)}
                    </span>
                  </div>

                  <p role="status" className="my-2 text-xs text-muted-foreground">{f.status === "preparing" ? "Preparing keywords locally…" : f.status === "pausing" ? "Pausing at chunk boundary…" : f.status === "pending" ? "Queued" : f.status}</p>
                  <TransferStats bytes={f.uploadedBytes} total={f.file.size} activeMs={f.activeMs ?? 0} complete={f.status === "completed"} paused={f.status === "paused"} />

                  {f.status === "error" && f.errorMessage && (
                    <p className="mt-1 text-xs text-destructive">
                      {f.errorMessage}
                    </p>
                  )}

                  {f.status === "stopped" && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      Stopped locally. Requests already sent may still finish.
                    </p>
                  )}

                  {f.status === "completed" && (
                    <p className="mt-1 text-xs text-success">
                      Encrypted & uploaded successfully
                    </p>
                  )}

                  {(f.autoKeywords?.length || 0) > 0 &&
                    f.status !== "completed" &&
                    f.status !== "uploading" &&
                    f.status !== "pausing" &&
                    f.status !== "paused" && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {(f.autoKeywords || []).map((kw) => {
                          const selected = f.selectedKeywords?.includes(kw);
                          return (
                            <button
                              key={kw}
                              type="button"
                              onClick={() => handleToggleKeyword(f.id, kw)}
                              className={
                                "cursor-pointer min-h-11 px-3 py-1 rounded text-xs " +
                                (selected
                                  ? "bg-primary/10 text-primary"
                                  : "bg-muted/60 text-muted-foreground hover:bg-muted")
                              }
                            >
                              {kw}
                            </button>
                          );
                        })}
                      </div>
                    )}
                </div>

                {f.status === "uploading" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="min-h-11 px-3"
                    onClick={() => handlePauseUpload(f.id)}
                    aria-label={`Pause ${f.file.name}`}
                  >
                    <Pause className="w-3.5 h-3.5" />
                    Pause
                  </Button>
                )}

                {f.status === "paused" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="min-h-11 px-3"
                    onClick={() => handleResumeUpload(f.id)}
                    disabled={isUploading}
                    aria-label={`Resume ${f.file.name}`}
                  >
                    <Play className="w-3.5 h-3.5" />
                    Resume
                  </Button>
                )}

                {f.status !== "stopped" && f.status !== "completed" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="min-h-11 px-3 text-destructive"
                    onClick={() => handleStopUpload(f.id)}
                    aria-label={`Abort ${f.file.name}`}
                  >
                    <Square className="w-3.5 h-3.5" />
                    Abort
                  </Button>
                )}

                {(f.status === "pending" || f.status === "error") && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="min-h-11 min-w-11 p-0 hover:bg-muted cursor-pointer"
                      onClick={() => removeFile(f.id)}
                      disabled={isUploading}
                      aria-label={`Remove ${f.file.name}`}
                    >
                      <X className="w-3.5 h-3.5" />
                    </Button>
                  )}
              </div>
            ))}
          </div>
        )}

        <p className="text-xs text-muted-foreground">Statistics use acknowledged plaintext bytes and active processing time, excluding pauses. Updates arrive at chunk boundaries.</p>
        <div className="flex flex-wrap gap-3 items-center justify-between pt-4 border-t border-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            {isUploading ? (
              <>
                <UploadCloud className="w-3 h-3 animate-bounce" />
                <span>
                  Uploading {pendingCount} of {uploadFiles.length}
                </span>
              </>
            ) : errorCount > 0 ? (
              <span className="text-destructive">
                {errorCount} file{errorCount === 1 ? "" : "s"} failed
              </span>
            ) : completedCount > 0 ? (
              <span className="text-success">
                {completedCount} file{completedCount === 1 ? "" : "s"} ready
              </span>
            ) : (
              <>
                <FileText className="w-3 h-3" />
                <span>{uploadFiles.length} file{uploadFiles.length === 1 ? "" : "s"} selected</span>
              </>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => closeModal(false)}
              className="min-h-11"
              disabled={isUploading}
            >
              Close
            </Button>
            <Button
              size="sm"
              onClick={() => handleDone()}
              className="min-h-11"
              disabled={isUploading || uploadFiles.some((f) => f.status === "preparing") || !uploadFiles.some((f) => f.status === "pending" || f.status === "paused")}
            >
              {isUploading ? "Uploading…" : "Start / resume queue"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
