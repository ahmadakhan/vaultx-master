"use client"

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

interface SortSelectProps {
  value: string
  onChange: (value: string) => void
}

export function SortSelect({ value, onChange }: SortSelectProps) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="w-[150px] h-9 text-sm border-border bg-muted/50 hover:bg-background focus:border-ring">
        <SelectValue placeholder="Sort by" />
      </SelectTrigger>
      <SelectContent className="w-[150px]">
        <SelectItem value="name-asc">Name (A–Z)</SelectItem>
        <SelectItem value="name-desc">Name (Z–A)</SelectItem>
        <SelectItem value="size-desc">Size (Largest)</SelectItem>
        <SelectItem value="size-asc">Size (Smallest)</SelectItem>
        <SelectItem value="modified-desc">Newest first</SelectItem>
        <SelectItem value="modified-asc">Oldest first</SelectItem>
      </SelectContent>
    </Select>
  )
}

export const sortLabelMap: Record<string, string> = {
  "name-asc": "Name (A–Z)",
  "name-desc": "Name (Z–A)",
  "size-desc": "Size (Largest)",
  "size-asc": "Size (Smallest)",
  "modified-desc": "Newest first",
  "modified-asc": "Oldest first",
}

export function applySort<T>(
  items: T[],
  sortKey: string,
  accessors: {
    name: (i: T) => string
    size: (i: T) => number
    modified: (i: T) => string | number
  }
): T[] {
  const [field, order] = sortKey.split("-") as [string, string]
  const compare = order === "desc" ? -1 : 1

  return [...items].sort((a, b) => {
    if (field === "name")
      return compare * accessors.name(a).localeCompare(accessors.name(b))
    if (field === "size")
      return compare * (accessors.size(a) - accessors.size(b))
    return (
      compare *
      String(accessors.modified(a)).localeCompare(String(accessors.modified(b)))
    )
  })
}
