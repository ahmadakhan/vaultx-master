"use client";

import { useState, useRef, useCallback } from "react";
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
import { Progress } from "@/components/ui/progress";
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
import { v4 as uuidv4 } from "uuid";
import { clearVaultXContext } from "@/lib/crypto/context";
import * as XLSX from "xlsx";
import mammoth from "mammoth";

interface UploadFile {
  id: string;
  file: File;
  progress: number;
  status: "pending" | "uploading" | "paused" | "completed" | "error" | "stopped";
  errorMessage?: string;
  selectedKeywords?: string[];
  autoKeywords?: string[];
  uploadedBytes: number;
  abortController?: AbortController;
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

  try {
    if (file.type.startsWith("text/") || lower.endsWith(".json") || lower.endsWith(".csv")) {
      return await file.text();
    }

    if (file.type === "application/pdf" || lower.endsWith(".pdf")) {
      const pdfjsLib = await import("pdfjs-dist/webpack");
      pdfjsLib.GlobalWorkerOptions.workerSrc =
        "https://cdn.jsdelivr.net/npm/pdfjs-dist@4.6.82/build/pdf.worker.min.mjs";

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

    if (lower.endsWith(".xlsx") || lower.endsWith(".xls")) {
      const data = await file.arrayBuffer();
      const workbook = XLSX.read(data, { type: "array" });
      const text = workbook.SheetNames.map(
        (sheet) => XLSX.utils.sheet_to_csv(workbook.Sheets[sheet])
      ).join(" ");
      return text;
    }

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

  const freq: Record<string, number> = {};
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

export function UploadModal({ open, onOpenChange, onUploadSuccess }: UploadModalProps) {
  const [uploadFiles, setUploadFiles] = useState<UploadFile[]>([]);
  const [globalKeywords, setGlobalKeywords] = useState<string[]>([]);
  const [currentKeyword, setCurrentKeyword] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const dropZoneRef = useRef<HTMLDivElement>(null);

  const resetModal = () => {
    setUploadFiles([]);
    setGlobalKeywords([]);
    setCurrentKeyword("");
    setIsUploading(false);
  };

  const closeModal = (openState: boolean) => {
    if (!openState && !isUploading) {
      resetModal();
    }
    onOpenChange(openState);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    dropZoneRef.current?.classList.add("drop-active");
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    dropZoneRef.current?.classList.remove("drop-active");
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    dropZoneRef.current?.classList.remove("drop-active");
    addFiles(Array.from(e.dataTransfer.files));
  };

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files || []);
    const newFiles = await Promise.all(
      files.map(async (file) => {
        const autoKeywords = await extractKeywordsFromFile(file);
        return {
          id: crypto.randomUUID(),
          file,
          autoKeywords,
          selectedKeywords: [...autoKeywords],
          status: "pending" as const,
          progress: 0,
          uploadedBytes: 0,
          pausedAtChunk: 0,
          totalChunks: Math.ceil(file.size / CHUNK_SIZE) || 1,
        };
      })
    );
    setUploadFiles((prev) => [...prev, ...newFiles]);
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

  const addFiles = (files: File[]) => {
    const newFiles = files.map((file) => ({
      id: uuidv4(),
      file,
      progress: 0,
      status: "pending" as const,
      uploadedBytes: 0,
      pausedAtChunk: 0,
      totalChunks: Math.ceil(file.size / CHUNK_SIZE) || 1,
    }));
    setUploadFiles((prev) => [...prev, ...newFiles]);
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
    const file = uploadFiles.find((f) => f.id === fileId);
    if (!file || !file.abortController) return;
    file.abortController.abort();
    setUploadFiles((prev) =>
      prev.map((f) => (f.id === fileId ? { ...f, status: "paused" } : f))
    );
  };

  const handleStopUpload = (fileId: string) => {
    const file = uploadFiles.find((f) => f.id === fileId);
    if (!file || !file.abortController) return;
    file.abortController.abort();
    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === fileId
          ? { ...f, status: "stopped", progress: 0, uploadedBytes: 0, pausedAtChunk: 0 }
          : f
      )
    );
  };

  async function handleDone() {
    const pendingFiles = uploadFiles.filter(
      (f) => f.status === "pending" || f.status === "paused"
    );
    if (pendingFiles.length === 0) return;

    const token = localStorage.getItem("vaultx_access_token");
    const masterKey_b64 = sessionStorage.getItem("vaultx_master_key");
    if (!token || !masterKey_b64) {
      alert("Missing keys or token. Please log in again.");
      return;
    }

    setIsUploading(true);
    try {
      const keywordChains: Record<string, string> = JSON.parse(
        sessionStorage.getItem("vaultx_keyword_chain") || "{}"
      );

      const masterKeyBytes = Uint8Array.from(atob(masterKey_b64), (c) =>
        c.charCodeAt(0)
      );
      const masterKey = await crypto.subtle.importKey(
        "raw",
        masterKeyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      for (const item of pendingFiles) {
        if (item.status === "stopped") continue;

        await uploadSingleFile(item, token, masterKey_b64, masterKey, keywordChains);

        if (item.abortController?.signal.aborted && item.status !== "completed") {
          break;
        }
      }

      if (uploadFiles.every((f) => f.status === "completed")) {
        const chainJson = JSON.stringify(keywordChains);
        const encChain = await encryptStringWithAes(chainJson, masterKey_b64);
        await api.post(
          "/user/index_state",
          {
            index_state_ciphertext: encChain.ciphertext_b64,
            index_state_iv: encChain.iv_b64,
          },
          token
        );
        sessionStorage.setItem("vaultx_keyword_chain", JSON.stringify(keywordChains));

        onUploadSuccess?.();
        window.location.reload();
      }
    } catch (err) {
      const msg = errorMessage(err, "Upload failed");
      setUploadFiles((prev) =>
        prev.map((f) => ({
          ...f,
          status: "error" as const,
          errorMessage: msg,
        }))
      );
      alert(msg);
    } finally {
      setIsUploading(false);
    }
  }

  async function uploadSingleFile(
    item: UploadFile,
    token: string,
    masterKey_b64: string,
    masterKey: CryptoKey,
    keywordChains: Record<string, string>
  ) {
    const controller = new AbortController();

    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === item.id
          ? { ...f, status: "uploading", abortController: controller }
          : f
      )
    );

    if (controller.signal.aborted) {
      setUploadFiles((prev) =>
        prev.map((f) => (f.id === item.id ? { ...f, status: "paused" } : f))
      );
      return;
    }

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

      const searchKey_b64 = sessionStorage.getItem("vaultx_search_key");
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
        const tokenBytes = genRandomBytes(16);
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
      // FIX: Generate the file IV once and use it for encryption, not a separate random value
      const fileIvBytes = genRandomBytes(12);
      fileEncIv = bufToB64(fileIvBytes.buffer as ArrayBuffer);

      setUploadFiles((prev) =>
        prev.map((f) =>
          f.id === item.id
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

      if (controller.signal.aborted) {
        setUploadFiles((prev) =>
          prev.map((f) => (f.id === item.id ? { ...f, status: "paused" } : f))
        );
        return;
      }
    }

    if (fileKey_b64 && !fileEncIv) {
      // Partial state from an older run: keep the keys, mint the nonce.
      fileEncIv = bufToB64(genRandomBytes(12).buffer as ArrayBuffer);
      setUploadFiles((prev) =>
        prev.map((f) => (f.id === item.id ? { ...f, fileEncIv } : f))
      );
    }

    if (!fileKey_b64 || !metadataEnc || !kfEnc || !tokens_json || !fileEncIv) {
      throw new Error("Encryption state lost. Please retry.");
    }

    const totalSize = item.file.size;
    let uploadedBytes = item.pausedAtChunk * CHUNK_SIZE;
    const totalChunks = Math.ceil(totalSize / CHUNK_SIZE) || 1;
    const fileNonce = Uint8Array.from(atob(fileEncIv), (c) => c.charCodeAt(0));

    for (let chunkIndex = item.pausedAtChunk; chunkIndex < totalChunks; chunkIndex++) {
      if (controller.signal.aborted) {
        setUploadFiles((prev) =>
          prev.map((f) =>
            f.id === item.id
              ? { ...f, status: "paused", pausedAtChunk: chunkIndex, uploadedBytes }
              : f
          )
        );
        return;
      }

      const start = chunkIndex * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, totalSize);
      const chunk = item.file.slice(start, end);
      const chunkBuffer = await chunk.arrayBuffer();

      const fileKeyBytes = Uint8Array.from(atob(fileKey_b64), (c) => c.charCodeAt(0));
      const chunkKey = await crypto.subtle.importKey(
        "raw",
        fileKeyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );

      // Derive this chunk's IV from the persisted file nonce + chunk index.
      const chunkIv = buildChunkIv(fileNonce, chunkIndex);
      // FIX: Use the file IV for encryption instead of generating a new random one
      const encryptedChunk = await aesEncryptArrayBuffer(chunkBuffer, chunkKey, chunkIv);
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
      const percent = Math.round((uploadedBytes / totalSize) * 100);
      setUploadFiles((prev) =>
        prev.map((f) =>
          f.id === item.id
            ? { ...f, progress: percent, uploadedBytes, pausedAtChunk: chunkIndex + 1 }
            : f
        )
      );
    }

    setUploadFiles((prev) =>
      prev.map((f) =>
        f.id === item.id ? { ...f, status: "completed", progress: 100 } : f
      )
    );
  }

  const handleResumeUpload = async (fileId: string) => {
    const file = uploadFiles.find((f) => f.id === fileId);
    if (!file || file.status !== "paused") return;

    const token = localStorage.getItem("vaultx_access_token");
    const masterKey_b64 = sessionStorage.getItem("vaultx_master_key");
    if (!token || !masterKey_b64) return;

    const masterKeyBytes = Uint8Array.from(atob(masterKey_b64), (c) => c.charCodeAt(0));
    const masterKey = await crypto.subtle.importKey(
      "raw",
      masterKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const keywordChains: Record<string, string> = JSON.parse(
      sessionStorage.getItem("vaultx_keyword_chain") || "{}"
    );

    setUploadFiles((prev) =>
      prev.map((f) => (f.id === fileId ? { ...f, status: "uploading", pausedAtChunk: 0, uploadedBytes: 0 } : f))
    );

    setIsUploading(true);
    try {
      await uploadSingleFile(file, token, masterKey_b64, masterKey, keywordChains);

      if (uploadFiles.every((f) => f.status === "completed")) {
        const chainJson = JSON.stringify(keywordChains);
        const encChain = await encryptStringWithAes(chainJson, masterKey_b64);
        await api.post(
          "/user/index_state",
          {
            index_state_ciphertext: encChain.ciphertext_b64,
            index_state_iv: encChain.iv_b64,
          },
          token
        );
        sessionStorage.setItem("vaultx_keyword_chain", JSON.stringify(keywordChains));
        onUploadSuccess?.();
        window.location.reload();
      }
    } catch (err) {
      const msg = errorMessage(err, "Upload failed");
      setUploadFiles((prev) =>
        prev.map((f) =>
          f.id === fileId ? { ...f, status: "error", errorMessage: msg } : f
        )
      );
      alert(msg);
    } finally {
      setIsUploading(false);
    }
  };

  const removeFile = (id: string) =>
    setUploadFiles((prev) => prev.filter((f) => f.id !== id));

  const completedCount = uploadFiles.filter(
    (f) => f.status === "completed"
  ).length;
  const pendingCount = uploadFiles.filter(
    (f) => f.status === "pending" || f.status === "uploading" || f.status === "paused"
  ).length;
  const errorCount = uploadFiles.filter((f) => f.status === "error").length;

  const statusIcon = (s: UploadFile["status"]) =>
    s === "completed" ? (
      <CheckCircle className="w-4 h-4 text-success" />
    ) : s === "uploading" ? (
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
      <DialogContent className="max-w-2xl max-h-[80vh] flex flex-col border-border shadow-xl">
        <DialogHeader>
          <DialogTitle>Upload Files</DialogTitle>
          <DialogDescription className="text-sm text-muted-foreground">
            Files are encrypted client-side before leaving your device.
          </DialogDescription>
        </DialogHeader>

        <div
          ref={dropZoneRef}
          className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/30 px-6 py-8 text-center transition-colors dropzone-inactive"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <UploadCloud className="w-10 h-10 mx-auto mb-3 text-muted-foreground" strokeWidth={1.5} />
          <p className="text-sm font-medium text-foreground mb-1">
            Drag & drop files here, or select files
          </p>
          <p className="text-xs text-muted-foreground mb-4">
            Supports PDF, documents, images, spreadsheets and archives
          </p>
          <Button variant="outline" size="sm" asChild>
            <label className="cursor-pointer">
              Select files
              <input
                type="file"
                multiple
                className="hidden"
                onChange={handleFileSelect}
                disabled={isUploading}
              />
            </label>
          </Button>
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
              className="h-9 border-border focus:border-ring"
              disabled={isUploading}
            />
            <Button
              type="button"
              size="sm"
              variant="ghost"
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
                  className="ml-1.5 rounded-full p-0.5 hover:bg-muted cursor-pointer"
                  aria-label={`Remove keyword ${kw}`}
                  disabled={isUploading}
                >
                  <X className="w-3 h-3" />
                </button>
              </Badge>
            ))}
          </div>
        </div>

        {uploadFiles.length > 0 && (
          <div className="space-y-4 overflow-y-auto flex-1">
            {uploadFiles.map((f) => (
              <div
                key={f.id}
                className="flex items-start gap-3 rounded-lg border border-border bg-muted/20 p-3"
              >
                <div className="flex items-center justify-center w-10 h-10 rounded bg-muted/60 shrink-0">
                  {statusIcon(f.status)}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-foreground truncate">
                      {f.file.name}
                    </p>
                    <span className="text-xs text-muted-foreground">
                      {formatSize(f.file.size)}
                    </span>
                  </div>

                  {f.status === "uploading" && (
                    <div className="mt-2">
                      <Progress value={f.progress} className="h-1.5" />
                      <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                        <span>{formatSize(f.uploadedBytes)}</span>
                        <span>{f.progress}%</span>
                      </div>
                    </div>
                  )}

                  {f.status === "paused" && (
                    <div className="mt-2">
                      <Progress value={f.progress} className="h-1.5" />
                      <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                        <span>{formatSize(f.uploadedBytes)} / {formatSize(f.file.size)}</span>
                        <span>Paused at {f.progress}%</span>
                      </div>
                    </div>
                  )}

                  {f.status === "error" && f.errorMessage && (
                    <p className="mt-1 text-xs text-destructive">
                      {f.errorMessage}
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
                                "cursor-pointer px-2 py-1 rounded text-xs " +
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
                    className="h-6 w-6 p-0 hover:bg-warning/10 hover:text-warning"
                    onClick={() => handlePauseUpload(f.id)}
                    aria-label={`Pause ${f.file.name}`}
                  >
                    <Pause className="w-3.5 h-3.5" />
                  </Button>
                )}

                {f.status === "paused" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 hover:bg-primary/10 hover:text-primary"
                    onClick={() => handleResumeUpload(f.id)}
                    aria-label={`Resume ${f.file.name}`}
                  >
                    <Play className="w-3.5 h-3.5" />
                  </Button>
                )}

                {f.status !== "uploading" && f.status !== "completed" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 hover:bg-destructive/10 hover:text-destructive"
                    onClick={() => handleStopUpload(f.id)}
                    aria-label={`Cancel ${f.file.name}`}
                  >
                    <Square className="w-3.5 h-3.5" />
                  </Button>
                )}

                {(f.status === "pending" || f.status === "error") && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0 hover:bg-muted cursor-pointer"
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

        <div className="flex items-center justify-between pt-4 border-t border-border">
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
              disabled={isUploading}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleDone}
              disabled={isUploading || uploadFiles.length === 0}
            >
              {isUploading ? "Uploading…" : "Done"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
