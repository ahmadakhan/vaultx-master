"use client";

import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { transferBytes, transferEta, transferMetrics, type DownloadProgressInfo } from "@/lib/transfer-ui";

export function TransferStats({ bytes, total, activeMs, complete = false, paused = false }: {
  bytes: number; total: number; activeMs: number; complete?: boolean; paused?: boolean;
}) {
  const metrics = transferMetrics(bytes, total, activeMs);
  const stats = [
    ["Progress", complete ? "100.00%" : metrics.percent === null ? "—" : `${metrics.percent.toFixed(2)}%`],
    ["Transferred", transferBytes(bytes)],
    ["Avg. speed", metrics.rate === null ? "—" : `${transferBytes(metrics.rate)}/s`],
    ["Est. remaining", complete ? "0s" : paused ? "Paused" : transferEta(metrics.eta)],
  ];
  return <div className="space-y-3">
    <Progress aria-label="Transfer progress" aria-valuenow={complete ? 100 : metrics.percent ?? undefined} aria-valuetext={complete ? "100.00%" : metrics.percent === null ? "Total unavailable" : `${metrics.percent.toFixed(2)}%`} value={complete ? 100 : metrics.percent ?? 0} className="h-1.5 [&>div]:duration-200 [&>div]:ease-[cubic-bezier(0.2,0,0,1)] motion-reduce:[&>div]:transition-none" />
    <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-left text-xs tabular-nums">
      {stats.map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-muted-foreground">{label}</dt><dd className="mt-1 whitespace-nowrap font-medium text-foreground">{value}</dd></div>)}
    </dl>
  </div>;
}

export function DownloadTransfer({ name, progress, onPause, onResume, onAbort }: {
  name: string; progress: DownloadProgressInfo; onPause?: () => void; onResume?: () => void; onAbort?: () => void;
}) {
  const { status } = progress;
  const labels = { downloading: "Downloading encrypted bytes", pausing: "Pausing after current read…", paused: "Paused", decrypting: "Decrypting locally…", completed: "Ready · saved to browser", stopped: "Aborted", error: "Download failed · try Download again" };
  return <section aria-label={`Download ${name}`} className="w-full min-w-0 space-y-3 rounded-lg border border-border bg-muted/20 p-3 text-left">
    <p role="status" className="text-xs text-muted-foreground">{labels[status]}</p>
    <TransferStats bytes={progress.bytes ?? 0} total={progress.total ?? 0} activeMs={progress.activeMs ?? 0} complete={status === "completed"} paused={status === "paused"} />
    <div className="flex flex-wrap gap-2">
      {status === "downloading" && <Button variant="outline" className="min-h-11" disabled={!onPause} onClick={onPause}>Pause</Button>}
      {status === "paused" && <Button variant="outline" className="min-h-11" disabled={!onResume} onClick={onResume}>Resume</Button>}
      {["downloading", "pausing", "paused", "decrypting"].includes(status) && <Button variant="outline" className="min-h-11 text-destructive" disabled={!onAbort} onClick={onAbort}>Abort</Button>}
    </div>
    {status === "paused" && <p className="text-xs text-muted-foreground">Resume requests the remaining bytes. A server without range support restarts the download.</p>}
  </section>;
}
