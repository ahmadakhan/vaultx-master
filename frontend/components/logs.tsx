"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle, XCircle, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { getVaultXContext } from "@/lib/crypto/context";
import { api } from "@/lib/api";
import { ErrorState } from "@/components/error-state";
import { EmptyState } from "@/components/empty-state";
import { errorMessage } from "@/lib/types";
import type { RawLog } from "@/lib/types";

interface AuditLog {
  id: string;
  entry: Record<string, unknown> | string;
  entry_hash: string;
  prev_hash: string;
  created_at: string;
}

export function Logs() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState<null | boolean>(null);
  const [verifyErrors, setVerifyErrors] = useState<string[]>([]);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const ctx = getVaultXContext();
      const data = await api.get("/audit/logs", ctx.accessToken);
      const rawLogs: RawLog[] = data.logs || [];
      const parsedLogs = rawLogs.map((log) => {
        const rawEntry = log.entry_json ?? log.entry ?? {};
        let entry: Record<string, unknown> = {};
        if (typeof rawEntry === "string") {
          try {
            const parsed: unknown = JSON.parse(rawEntry);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              entry = parsed as Record<string, unknown>;
            }
          } catch {
            entry = {};
          }
        } else if (rawEntry && typeof rawEntry === "object" && !Array.isArray(rawEntry)) {
          entry = rawEntry;
        }
        return { ...log, id: String(log.id), entry, prev_hash: log.prev_hash ?? "" };
      });
      setLogs(parsedLogs);
    } catch (err) {
      console.error("Error fetching logs:", err);
      setFetchError(errorMessage(err, "Failed to load audit logs."));
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  const verifyAudit = async () => {
    setVerifying(true);
    try {
      const ctx = getVaultXContext();
      const res = await api.get("/audit/verify", ctx.accessToken);
      setVerified(res.valid);
      setVerifyErrors(res.errors || []);
    } catch (err) {
      console.error("Audit verification failed:", err);
      setVerified(false);
      setVerifyErrors(
        (err as { detail?: { errors?: string[] } })?.detail?.errors ?? [
          "Unknown verification error",
        ]
      );
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    verifyAudit();
  }, []);

  return (
    <div className="flex flex-col h-full">
      <div className="border-b border-border bg-card p-4 flex items-center justify-between shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">Audit Trail</h2>
        <Button
          variant="outline"
          size="sm"
          disabled={verifying}
          onClick={verifyAudit}
        >
          {verifying ? (
            <>
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              Verifying…
            </>
          ) : (
            <>
              <RefreshCw className="w-4 h-4 mr-2" strokeWidth={1.5} />
              Re-verify
            </>
          )}
        </Button>
      </div>

      <div className="flex-1 p-6 flex flex-col space-y-6 overflow-auto">
        {loading ? (
          <LogSkeleton />
        ) : fetchError ? (
          <ErrorState
            title="Couldn't load audit logs"
            message={fetchError}
            onRetry={fetchLogs}
          />
        ) : (
          <>
            {verified !== null && !verifying && (
              <div
                className={cn(
                  "flex items-start gap-3 rounded-md border p-3 text-sm",
                  "transition-colors",
                  verified
                    ? "border-success/30 bg-success-muted/30"
                    : "border-destructive/30 bg-destructive/5"
                )}
              >
                {verified ? (
                  <CheckCircle className="mt-0.5 h-5 w-5 text-success shrink-0" strokeWidth={1.5} />
                ) : (
                  <XCircle className="mt-0.5 h-5 w-5 text-destructive shrink-0" strokeWidth={1.5} />
                )}
                {verified ? (
                  <p>No integrity issues detected. Your audit chain is valid.</p>
                ) : (
                  <div className="space-y-1">
                    <p>Integrity verification failed. Possible breaches:</p>
                    <div className="mt-1 space-y-1">
                      {verifyErrors.map((err, i) => (
                        <p key={i} className="text-sm">
                          • {err}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {logs.length === 0 ? (
              <EmptyState
                title="No audit logs"
                description="When activity occurs, it will be recorded here as an immutable chain entry."
                actionLabel="Refresh"
                onAction={fetchLogs}
              />
            ) : (
              <div className="border border-border rounded-lg overflow-hidden transition-colors">
                <div className="grid grid-cols-4 bg-muted/50 text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground px-4 py-2.5">
                  <span>Action</span>
                  <span>IP Address</span>
                  <span>User Agent</span>
                  <span className="text-right">Timestamp</span>
                </div>

                {logs.map((log) => {
                  const entry =
                    typeof log.entry === "object"
                      ? log.entry
                      : JSON.parse(log.entry || "{}");

                  return (
                    <div
                      key={log.id}
                      className="grid grid-cols-4 px-4 py-3 text-sm hover:bg-accent/40 transition-colors"
                    >
                      <span className="text-primary font-medium truncate">
                        {String(entry.action || "—")}
                      </span>
                      <span className="text-muted-foreground truncate">
                        {String(entry.ip || "—")}
                      </span>
                      <span className="text-muted-foreground truncate">
                        {String(entry.user_agent || "—")}
                      </span>
                      <span className="text-right text-muted-foreground">
                        {new Date(log.created_at).toLocaleString()}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function LogSkeleton() {
  return (
    <div className="space-y-3">
      <div className="border border-border rounded-lg overflow-hidden">
        <Skeleton className="h-9 w-full" />
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    </div>
  );
}
