"use client";

import { useAuth } from "@/hooks/useAuth";
import { FileManager } from "@/components/file-manager";
import { Skeleton } from "@/components/ui/skeleton";

export default function DashboardPage() {
  const { token, loading } = useAuth();

  if (loading)
    return (
      <div className="flex h-screen w-full items-center justify-center gap-3 text-muted-foreground">
        <Skeleton className="h-5 w-5 rounded-full" />
        <span>Checking session…</span>
      </div>
    );

  if (!token) return null;

  return <FileManager />;
}
