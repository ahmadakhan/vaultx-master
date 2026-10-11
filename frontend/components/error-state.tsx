"use client"

import { AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
  retryLabel?: string
  className?: string
}

export function ErrorState({
  title = "Something went wrong",
  message = "We couldn't load this section. Please check your connection and try again.",
  onRetry,
  retryLabel = "Try Again",
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center min-h-72 h-full px-6 py-12 text-center",
        className
      )}
    >
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-destructive/10 mb-4">
        <AlertCircle aria-hidden="true" className="w-6 h-6 text-destructive" strokeWidth={1.5} />
      </div>
      <h3 className="vaultx-subheading mb-1">{title}</h3>
      <p className="vaultx-secondary max-w-sm mb-6">{message}</p>
      {onRetry && (
        <Button variant="outline" onClick={onRetry}>
          {retryLabel}
        </Button>
      )}
    </div>
  )
}
