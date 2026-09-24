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
      <div className="p-6">
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="flex flex-col items-center gap-3 p-4">
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
    <div className="p-6">
      <div className="space-y-1">
        {Array.from({ length: rows }).map((_, i) => (
          <div
            key={i}
            className={cn(
              "grid grid-cols-12 gap-4 items-center py-3 px-2",
              i === 0 ? "border-b border-border pb-3" : ""
            )}
          >
            <div className="col-span-4 flex items-center gap-3">
              <Skeleton className="w-6 h-6 rounded" />
              <Skeleton className="h-4 w-32 rounded" />
            </div>
            <Skeleton className="col-span-3 h-4 w-20 rounded" />
            <Skeleton className="col-span-3 h-4 w-28 rounded" />
            <Skeleton className="col-span-1 h-4 w-10 rounded" />
          </div>
        ))}
      </div>
    </div>
  )
}
