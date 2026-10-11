"use client"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface FileListSkeletonProps {
  rows?: number
  viewMode?: "grid" | "list"
}

export function FileListSkeleton({
  rows = 6,
  viewMode = "list",
}: FileListSkeletonProps) {
  if (viewMode === "grid") {
    return (
      <div role="status" aria-label="Loading files" className="p-4 sm:p-6">
        <span className="sr-only">Loading files…</span>
        <div aria-hidden="true" className="grid grid-cols-1 min-[440px]:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4">
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="flex flex-col items-center gap-3 p-5 pt-12 rounded-xl border border-border bg-card">
              <Skeleton className="w-12 h-12 rounded-lg" />
              <Skeleton className="h-4 w-24 rounded" />
              <Skeleton className="h-3 w-16 rounded" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div role="status" aria-label="Loading files" className="p-4 sm:p-6">
      <span className="sr-only">Loading files…</span>
      <div aria-hidden="true" className="space-y-1">
        {Array.from({ length: rows }).map((_, i) => (
          <div
            key={i}
            className={cn(
              "grid grid-cols-[minmax(0,1fr)_auto] lg:grid-cols-12 gap-4 items-center py-3 px-2",
              i === 0 ? "border-b border-border pb-3" : ""
            )}
          >
            <div className="lg:col-span-4 flex min-w-0 items-center gap-3">
              <Skeleton className="w-6 h-6 rounded" />
              <Skeleton className="h-4 w-32 max-w-full rounded" />
            </div>
            <Skeleton className="hidden lg:block col-span-3 h-4 w-20 rounded" />
            <Skeleton className="hidden lg:block col-span-3 h-4 w-28 rounded" />
            <Skeleton className="lg:col-span-2 h-4 w-10 rounded" />
          </div>
        ))}
      </div>
    </div>
  )
}
