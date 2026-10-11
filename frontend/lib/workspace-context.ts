/** Presentation contract only. Adapters must obtain membership and usage from
 * an authoritative service and finish scoped-data invalidation before resolving
 * switchWorkspace. Selecting an item here never grants access or isolates data. */
export interface Workspace {
  id: string;
  name: string;
  kind: "personal" | "organization";
}

export type Allocation =
  | { status: "unavailable" | "loading" | "unknown" }
  | { status: "error"; message: string }
  | { status: "ready"; usedBytes: number; limitBytes: number };

export type Memberships =
  | { status: "unavailable" | "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; workspaces: readonly Workspace[] };

export interface WorkspaceContextAdapter {
  current: Workspace;
  memberships: Memberships;
  allocation: Allocation;
  /** Resolve only after server authorization, data invalidation and parent
   * context update. Reject on failure; retain the previous authoritative scope. */
  switchWorkspace?: (workspaceId: string) => Promise<void>;
}

export const PERSONAL_VAULT_CONTEXT: WorkspaceContextAdapter = {
  current: { id: "personal", name: "Personal vault", kind: "personal" },
  memberships: { status: "unavailable" },
  allocation: { status: "unavailable" },
};

export function allocationSummary(allocation: Allocation): {
  label: string;
  percent: number | null;
  overQuota: boolean;
} {
  if (allocation.status !== "ready") {
    const labels = {
      unavailable: "Allocation unavailable",
      loading: "Loading allocation…",
      unknown: "Allocation not reported",
      error: "Allocation could not be loaded",
    };
    return { label: labels[allocation.status], percent: null, overQuota: false };
  }
  const { usedBytes, limitBytes } = allocation;
  if (!Number.isSafeInteger(usedBytes) || !Number.isSafeInteger(limitBytes) || usedBytes < 0 || limitBytes < 0) {
    return { label: "Allocation not reported", percent: null, overQuota: false };
  }
  const overQuota = usedBytes > limitBytes;
  const percent = limitBytes === 0 ? (overQuota ? 100 : 0) : Math.min(100, usedBytes / limitBytes * 100);
  return {
    label: `${formatAllocationBytes(usedBytes)} of ${formatAllocationBytes(limitBytes)}${overQuota ? " · Over allocation" : ""}`,
    percent,
    overQuota,
  };
}

export function formatAllocationBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${Number((bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1))} ${units[index]}`;
}

export async function requestWorkspaceSwitch(adapter: WorkspaceContextAdapter, workspaceId: string): Promise<void> {
  if (workspaceId === adapter.current.id) return;
  if (adapter.memberships.status !== "ready" || !adapter.switchWorkspace ||
    !adapter.memberships.workspaces.some((workspace) => workspace.id === workspaceId)) {
    throw new Error("Workspace switching is unavailable.");
  }
  await adapter.switchWorkspace(workspaceId);
}
