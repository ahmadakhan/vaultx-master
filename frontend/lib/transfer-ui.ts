export interface DownloadProgressInfo {
  percent: number;
  status: "downloading" | "pausing" | "paused" | "decrypting" | "completed" | "stopped" | "error";
  bytes?: number;
  total?: number;
  activeMs?: number;
}

export function transferMetrics(bytes: number, total: number, activeMs: number) {
  const safeBytes = Number.isFinite(bytes) ? Math.max(0, bytes) : 0;
  const knownTotal = Number.isFinite(total) && total > 0;
  const rate = activeMs > 0 && Number.isFinite(activeMs) && safeBytes > 0 ? safeBytes / (activeMs / 1000) : null;
  return {
    percent: knownTotal ? Math.min(100, safeBytes / total * 100) : null,
    rate,
    eta: knownTotal && rate ? Math.max(0, total - safeBytes) / rate : null,
  };
}

export function transferBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes.toFixed(0)} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  const exponent = Math.min(4, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** exponent).toFixed(2)} ${units[exponent - 1]}`;
}

export function transferEta(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds)) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.ceil(seconds % 60)}s`;
}
