"use client"

import { Grid3X3, List } from "lucide-react"
import { cn } from "@/lib/utils"

interface ViewToggleProps {
  value: "grid" | "list"
  onChange: (value: "grid" | "list") => void
}

export function ViewToggle({ value, onChange }: ViewToggleProps) {
  return (
    <div className="inline-flex items-center p-1 border border-border rounded-md bg-muted/40">
      <button
        type="button"
        aria-pressed={value === "grid"}
        aria-label="Grid view"
        onClick={() => onChange("grid")}
        className={cn(
          "flex items-center justify-center w-9 h-8 rounded-sm transition-all",
          value === "grid"
            ? "bg-primary text-primary-foreground shadow-xs"
            : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
        )}
      >
        <Grid3X3 className="w-4 h-4" strokeWidth={1.5} />
      </button>
      <button
        type="button"
        aria-pressed={value === "list"}
        aria-label="List view"
        onClick={() => onChange("list")}
        className={cn(
          "flex items-center justify-center w-9 h-8 rounded-sm transition-all",
          value === "list"
            ? "bg-primary text-primary-foreground shadow-xs"
            : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
        )}
      >
        <List className="w-4 h-4" strokeWidth={1.5} />
      </button>
    </div>
  )
}
