"use client"

import { Button } from "@/components/ui/button"

interface EmptyStateProps {
  title?: string
  description?: string
  actionLabel?: string
  onAction?: () => void
  secondaryLabel?: string
  onSecondary?: () => void
}

export function EmptyState({
  title = "No files here",
  description = "Upload your first file to keep your documents organized in one place.",
  actionLabel = "Upload Files",
  onAction,
  secondaryLabel,
  onSecondary,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-72 h-full px-6 py-12 text-center">
      <div aria-hidden="true" className="inline-flex items-center justify-center w-16 h-16 rounded-2xl border border-border bg-muted/50 mb-6">
        <EmptyVaultIcon className="w-8 h-8 text-muted-foreground" />
      </div>
      <h3 className="vaultx-subheading mb-2">{title}</h3>
      <p className="vaultx-secondary max-w-sm mb-6">{description}</p>
      <div className="flex flex-wrap justify-center items-center gap-3">
        {actionLabel && onAction && (
          <Button onClick={onAction}>{actionLabel}</Button>
        )}
        {secondaryLabel && onSecondary && (
          <Button variant="link" onClick={onSecondary}>
            {secondaryLabel}
          </Button>
        )}
      </div>
    </div>
  )
}

function EmptyVaultIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      {...props}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M3 7v10a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3V8a3 3 0 0 0-3-3H6a3 3 0 0 0-3 3Z"
      />
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M8 5l4-4 4 4"
      />
      <circle cx="12" cy="12" r="2.5" />
    </svg>
  )
}
