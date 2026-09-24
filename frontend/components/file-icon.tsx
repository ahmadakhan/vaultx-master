"use client"

import {
  FileText,
  FileImage,
  FileVideo,
  FileAudio,
  Archive,
  Code,
  File,
  FileJson,
  FileType,
} from "lucide-react"
import { type ComponentType } from "react"
import { cn } from "@/lib/utils"

interface FileIconProps {
  fileType?: string
  name?: string
  className?: string
}

function classify(fileType?: string, name?: string): "pdf" | "word" | "excel" | "image" | "video" | "audio" | "archive" | "code" | "text" | "markdown" | "default" {
  const type = (fileType || "").toLowerCase()
  const lowerName = (name || "").toLowerCase()

  if (type.includes("pdf") || lowerName.endsWith(".pdf")) return "pdf"
  if (type.includes("word") || type.includes("document") || lowerName.match(/\.(doc|docx|rtf)$/)) return "word"
  if (type.includes("excel") || type.includes("spreadsheet") || lowerName.match(/\.(xls|xlsx|csv)$/)) return "excel"
  if (type.startsWith("image/") || lowerName.match(/\.(png|jpe?g|gif|webp|svg|bmp|tiff?)$/)) return "image"
  if (type.startsWith("video/") || lowerName.match(/\.(mp4|webm|mov|avi|mkv)$/)) return "video"
  if (type.startsWith("audio/") || lowerName.match(/\.(mp3|wav|ogg|flac|m4a)$/)) return "audio"
  if (type.includes("zip") || type.includes("rar") || type.includes("tar") || lowerName.match(/\.(zip|tar|gz|rar|7z)$/)) return "archive"
  if (type.includes("javascript") || type.includes("json") || type.includes("python") || lowerName.match(/\.(js|ts|jsx|tsx|json|py|java|c|cpp|rb|go|rs|php)$/)) return "code"
  if (lowerName.endsWith(".md") || type.includes("markdown")) return "markdown"
  if (type.startsWith("text/") || lowerName.endsWith(".txt")) return "text"
  return "default"
}

const iconMap: Record<ReturnType<typeof classify>, ComponentType<React.SVGProps<SVGSVGElement>>> = {
  pdf: FileText,
  word: FileType,
  excel: FileJson,
  image: FileImage,
  video: FileVideo,
  audio: FileAudio,
  archive: Archive,
  code: Code,
  text: FileText,
  markdown: File,
  default: File,
}

const colorMap: Record<ReturnType<typeof classify>, string> = {
  pdf: "text-file-pdf",
  word: "text-file-word",
  excel: "text-file-excel",
  image: "text-file-image",
  video: "text-file-video",
  audio: "text-file-audio",
  archive: "text-file-archive",
  code: "text-file-code",
  text: "text-file-text",
  markdown: "text-file-markdown",
  default: "text-muted-foreground",
}

const labelMap: Record<ReturnType<typeof classify>, string> = {
  pdf: "PDF",
  word: "Word",
  excel: "Excel",
  image: "Image",
  video: "Video",
  audio: "Audio",
  archive: "Archive",
  code: "Code",
  text: "Text",
  markdown: "Markdown",
  default: "File",
}

export function FileIcon({ fileType, name, className }: FileIconProps) {
  const kind = classify(fileType, name)
  const Icon = iconMap[kind]
  const color = colorMap[kind]
  const label = labelMap[kind]
  return (
    <div
      className={cn("flex items-center justify-center rounded-lg bg-muted/60", className)}
      aria-label={label}
      role="img"
    >
      <Icon className={cn("w-6 h-6", color)} strokeWidth={1.5} aria-hidden="true" />
    </div>
  )
}

export function getFileTypeLabel(fileType?: string, name?: string): string {
  return labelMap[classify(fileType, name)]
}
