"use client";

import { useId, useRef, useState } from "react";
import { Building2, ChevronDown, Loader2, ShieldCheck, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { allocationSummary, PERSONAL_VAULT_CONTEXT, requestWorkspaceSwitch, type Allocation, type WorkspaceContextAdapter } from "@/lib/workspace-context";

export function AllocationMeter({ allocation }: { allocation: Allocation }) {
  const id = useId();
  const summary = allocationSummary(allocation);
  const meterClass = summary.overQuota ? "from-red-500 to-red-400" : "from-emerald-500 to-teal-400";

  const usedDisplay = allocation.status === "ready" ? allocation.usedBytes : null;
  const limitDisplay = allocation.status === "ready" ? allocation.limitBytes : null;

  return (
    <div className="min-w-0 space-y-2 rounded-xl border border-border/80 bg-muted/20 p-3" aria-busy={allocation.status === "loading"}>
      <div className="flex items-center justify-between gap-3 text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
        <span>Storage allocation</span>
        <span className={summary.overQuota ? "text-destructive" : "text-emerald-700 dark:text-emerald-400"}>{summary.label}</span>
      </div>
      {summary.percent !== null && (
        <div role="meter" aria-labelledby={id} aria-valuemin={0} aria-valuemax={100} aria-valuenow={summary.percent} aria-valuetext={summary.label} className="h-2.5 overflow-hidden rounded-full border border-border bg-background/60">
          <div className={`h-full rounded-full bg-gradient-to-r ${meterClass}`} style={{ width: `${Math.min(summary.percent, 100)}%` }} />
        </div>
      )}
      {usedDisplay !== null && limitDisplay !== null && (
        <div id={id} className="flex items-center justify-between text-sm text-muted-foreground">
          <span>{usedDisplay.toLocaleString()} used</span>
          <span>{limitDisplay.toLocaleString()} total</span>
        </div>
      )}
      {allocation.status === "error" && <p role="alert" className="text-sm text-destructive">{allocation.message}</p>}
    </div>
  );
}

export function WorkspaceHub({ adapter = PERSONAL_VAULT_CONTEXT }: { adapter?: WorkspaceContextAdapter }) {
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const switching = useRef(false);
  const descriptionId = useId();
  const canSwitch = adapter.memberships.status === "ready" && !!adapter.switchWorkspace && adapter.memberships.workspaces.some((workspace) => workspace.id !== adapter.current.id);
  const Icon = adapter.current.kind === "personal" ? UserRound : Building2;

  async function switchTo(id: string) {
    if (switching.current || id === adapter.current.id) return;
    switching.current = true;
    setPending(id);
    setError(null);
    try {
      await requestWorkspaceSwitch(adapter, id);
    } catch {
      setError("Could not switch workspace. Your current workspace is unchanged. Try again.");
    } finally {
      switching.current = false;
      setPending(null);
    }
  }

  const membershipDescription = adapter.memberships.status === "loading"
    ? "Loading workspaces…"
    : adapter.memberships.status === "error"
      ? "Workspaces could not be loaded"
      : adapter.memberships.status === "unavailable"
        ? "Organization switching unavailable"
        : canSwitch
          ? "Choose a workspace"
          : "No other workspace available";

  return (
    <section aria-label="Workspace context" aria-busy={pending !== null} className="border-b border-border bg-background/80 px-4 py-4 backdrop-blur-sm sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-7xl gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(17rem,22rem)]">
        <div className="min-w-0 rounded-xl border border-border bg-muted/20 p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-background text-foreground">
                <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">Current workspace</p>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" disabled={!canSwitch || pending !== null} aria-describedby={descriptionId} aria-label={`Current workspace: ${adapter.current.name}`} className="max-w-full justify-start px-0 py-1 disabled:opacity-100">
                      {pending ? <Loader2 aria-hidden="true" className="mr-2 h-4 w-4 animate-spin" /> : <Icon aria-hidden="true" className="mr-2 h-4 w-4" />}
                      <span className="truncate text-base font-semibold text-foreground">{adapter.current.name}</span>
                      {canSwitch && <ChevronDown aria-hidden="true" className="ml-2 h-4 w-4" />}
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-72 max-w-[calc(100vw-2rem)]">
                    {adapter.memberships.status === "ready" && adapter.memberships.workspaces.map((workspace) => (
                      <DropdownMenuItem key={workspace.id} disabled={workspace.id === adapter.current.id || pending !== null} onSelect={() => { void switchTo(workspace.id); }} className="flex justify-between gap-4">
                        <span className="truncate">{workspace.name}</span>
                        {workspace.id === adapter.current.id && <span className="text-xs text-muted-foreground">Current</span>}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>
            <span className="rounded-full border border-border bg-background px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
              Secure tenant
            </span>
          </div>
          <p id={descriptionId} className="mt-3 text-sm text-muted-foreground">{membershipDescription}</p>
          <div role="status" aria-live="polite" className="mt-1 text-sm text-foreground">{pending ? "Switching workspace…" : ""}</div>
          {error && <p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
          {adapter.memberships.status === "error" && <p role="alert" className="mt-3 text-sm text-destructive">{adapter.memberships.message}</p>}
        </div>

        <div className="self-center">
          <AllocationMeter allocation={adapter.allocation} />
        </div>
      </div>
    </section>
  );
}
