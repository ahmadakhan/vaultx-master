"use client";

import { useId, useRef, useState } from "react";
import { Building2, ChevronDown, Loader2, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { allocationSummary, PERSONAL_VAULT_CONTEXT, requestWorkspaceSwitch, type Allocation, type WorkspaceContextAdapter } from "@/lib/workspace-context";

export function AllocationMeter({ allocation }: { allocation: Allocation }) {
  const id = useId();
  const summary = allocationSummary(allocation);
  return (
    <div className="min-w-0 space-y-2" aria-busy={allocation.status === "loading"}>
      <p id={id} className={`text-sm ${summary.overQuota ? "text-destructive" : "text-muted-foreground"}`}>
        {summary.label}
      </p>
      {summary.percent !== null && (
        <div role="meter" aria-labelledby={id} aria-valuemin={0} aria-valuemax={100}
          aria-valuenow={summary.percent} aria-valuetext={summary.label}
          className="h-2 overflow-hidden rounded-sm border border-input-border bg-muted">
          <div className={`h-full ${summary.overQuota ? "bg-destructive" : "bg-success"}`} style={{ width: `${summary.percent}%` }} />
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
  const canSwitch = adapter.memberships.status === "ready" && !!adapter.switchWorkspace &&
    adapter.memberships.workspaces.some((workspace) => workspace.id !== adapter.current.id);
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

  const membershipDescription = adapter.memberships.status === "loading" ? "Loading workspaces…"
    : adapter.memberships.status === "error" ? "Workspaces could not be loaded"
    : adapter.memberships.status === "unavailable" ? "Organization switching unavailable"
    : canSwitch ? "Choose a workspace" : "No other workspace available";

  return (
    <section aria-label="Workspace context" aria-busy={pending !== null}
      className="grid min-w-0 gap-4 border-b border-border bg-card px-4 py-4 sm:grid-cols-[minmax(0,1fr)_minmax(12rem,20rem)] sm:px-6 lg:px-8">
      <div className="min-w-0">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" disabled={!canSwitch || pending !== null}
              aria-describedby={descriptionId} aria-label={`Current workspace: ${adapter.current.name}`}
              className="max-w-full justify-start px-0 disabled:opacity-100">
              {pending ? <Loader2 aria-hidden="true" className="animate-spin" /> : <Icon aria-hidden="true" />}
              <span className="truncate text-base font-semibold">{adapter.current.name}</span>
              {canSwitch && <ChevronDown aria-hidden="true" />}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-72 max-w-[calc(100vw-2rem)]">
            {adapter.memberships.status === "ready" && adapter.memberships.workspaces.map((workspace) => (
              <DropdownMenuItem key={workspace.id} disabled={workspace.id === adapter.current.id || pending !== null}
                onSelect={() => { void switchTo(workspace.id); }} className="flex justify-between gap-4">
                <span className="truncate">{workspace.name}</span>
                {workspace.id === adapter.current.id && <span className="text-xs">Current</span>}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
        <p id={descriptionId} className="text-sm text-muted-foreground">{membershipDescription}</p>
        <div role="status" aria-live="polite" className="text-sm">{pending ? "Switching workspace…" : ""}</div>
        {error && <p role="alert" className="mt-2 text-sm text-destructive">{error}</p>}
        {adapter.memberships.status === "error" && <p role="alert" className="mt-2 text-sm text-destructive">{adapter.memberships.message}</p>}
      </div>
      <div className="self-center">
        <AllocationMeter allocation={adapter.allocation} />
      </div>
    </section>
  );
}
