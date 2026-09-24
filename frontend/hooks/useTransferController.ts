"use client";

import { useState, useRef, useCallback } from "react";

export type TransferStatus =
  | "idle"
  | "uploading"
  | "paused"
  | "completed"
  | "stopped"
  | "error";

export interface TransferProgress {
  status: TransferStatus;
  percent: number;
  uploadedBytes: number;
  totalBytes: number;
  transferredBytes: number;
  error?: string;
}

export interface TransferController {
  status: TransferStatus;
  abort: () => void;
  pause: () => void;
  resume: () => void;
  getProgress: () => TransferProgress;
  updateProgress: (uploaded: number, total: number) => void;
}

export function useTransferController(
  initialTotal: number = 0
): TransferController {
  const [status, setStatus] = useState<TransferStatus>("idle");
  const [percent, setPercent] = useState(0);
  const [uploadedBytes, setUploadedBytes] = useState(0);
  const abortControllerRef = useRef<AbortController | null>(null);

  const abort = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setStatus("stopped");
  }, []);

  const pause = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setStatus("paused");
  }, []);

  const resume = useCallback(() => {
    abortControllerRef.current = new AbortController();
    setStatus("uploading");
  }, []);

  const updateProgress = useCallback((uploaded: number, total: number) => {
    setUploadedBytes(uploaded);
    setPercent(total > 0 ? Math.round((uploaded / total) * 100) : 0);
  }, []);

  const getProgress = useCallback(
    (): TransferProgress => ({
      status,
      percent,
      uploadedBytes,
      totalBytes: initialTotal,
      transferredBytes: uploadedBytes,
    }),
    [status, percent, uploadedBytes, initialTotal]
  );

  return {
    status,
    abort,
    pause,
    resume,
    getProgress,
    updateProgress,
  };
}
