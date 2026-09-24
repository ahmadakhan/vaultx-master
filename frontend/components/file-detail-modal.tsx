"use client"

import { X } from "lucide-react"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { FileIcon } from "@/components/file-icon"
import { getFileTypeLabel } from "@/components/file-icon"
import type { FileItem } from "@/lib/types"
import { cn } from "@/lib/utils"

interface FileDetailModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  file: FileItem | null
}

interface ActivityEvent {
  id: string
  action: string
  actor: string
  timestamp: string
  detail?: string
}

export function FileDetailModal({ open, onOpenChange, file }: FileDetailModalProps) {
  if (!file) return null

  const meta = getFileTypeLabel(file.fileType, file.name)
  const isShared = file.shared

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg p-0 border-border shadow-xl">
        <DialogHeader className="sr-only">
          <DialogTitle>File details</DialogTitle>
        </DialogHeader>

        <div className="flex items-start gap-4 p-6 pb-4">
          <div className="rounded-lg bg-muted/50 p-2">
            <FileIcon fileType={file.fileType} name={file.name} className="w-10 h-10" />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-lg font-semibold text-foreground truncate">
              {file.name}
            </h3>
            <p className="text-sm text-muted-foreground">{meta} file</p>
          </div>
          <DialogClose asChild>
            <button
              type="button"
              className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-accent/50"
              aria-label="Close"
            >
              <X className="h-4 w-4" strokeWidth={1.5} />
            </button>
          </DialogClose>
        </div>

        <div className="px-6 pb-6 space-y-5">
          <div>
            <p className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground mb-2">
              Properties
            </p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <Property label="Size" value={file.size} />
              <Property label="Type" value={meta} />
              <Property label="Owner" value={file.owner} />
              <Property label="Modified" value={file.modified} />
              <Property
                label="Shared"
                value={
                  <Badge
                    variant={isShared ? "success" : "outline"}
                    className={cn(
                      "text-xs",
                      isShared ? "" : "border-border text-muted-foreground"
                    )}
                  >
                    {isShared ? "Yes" : "No"}
                  </Badge>
                }
              />
            </div>
          </div>

          {isShared && file.shared_with && file.shared_with.length > 0 && (
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground mb-2">
                Shared with
              </p>
              <div className="space-y-1">
                {file.shared_with.map((user, i) => (
                  <div
                    key={`${file.id}-${i}`}
                    className="flex items-center justify-between py-1"
                  >
                    <span className="text-sm text-foreground">{user}</span>
                    <Badge variant="outline" className="text-xs border-border text-muted-foreground">
                      read
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          <ActivityTimeline file={file} />
        </div>
      </DialogContent>
    </Dialog>
  )
}

function Property({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-sm text-foreground break-all">{value}</span>
    </div>
  )
}

function ActivityTimeline({ file }: { file: FileItem }) {
  const activities: ActivityEvent[] = [
    {
      id: "1",
      action: file.shared ? "Shared" : "Uploaded",
      actor: "You",
      timestamp: file.modified,
      detail: file.shared ? `${file.shared_with?.length || 0} recipient${(file.shared_with?.length || 0) === 1 ? "" : "s"}` : "Original upload",
    },
  ]

  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground mb-3">
        Activity
      </p>
      <ul className="relative pl-5 space-y-4 text-sm">
        {activities.map((event, i) => {
          const isLast = i === activities.length - 1
          return (
            <li key={event.id} className="relative">
              {!isLast && (
                <div className="absolute left-2 top-5 bottom-[-1rem] w-px bg-border" />
              )}
              <div className="absolute left-0 top-4 w-4 h-4 rounded-full bg-primary/10 border border-primary/20" />
              <div className="ml-6">
                <p className="font-medium text-foreground">{event.action}</p>
                <p className="text-xs text-muted-foreground">
                  {event.actor} · {event.detail}
                </p>
                <p className="text-xs text-muted-foreground">
                  {formatReadable(event.timestamp)}
                </p>
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function formatReadable(value: string): string {
  try {
    const d = new Date(value)
    if (Number.isNaN(d.getTime())) return value
    return d.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    })
  } catch {
    return value
  }
}
