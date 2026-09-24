"use client";

import {
  Eye,
  Download,
  Pause,
  Play,
  Square,
  Share2,
  Trash2,
  MoreHorizontal,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { FileIcon } from "@/components/file-icon";
import type { FileItem } from "@/lib/types";

export interface DownloadProgressInfo {
  percent: number;
  status: "downloading" | "paused" | "completed" | "stopped" | "error";
}

interface FileGridProps {
  files: FileItem[];
  onShareFile?: (fileId: string) => void;
  onDownloadFile?: (fileId: string) => void;
  onDeleteFile?: (fileId: string) => void;
  onViewFile?: (file: FileItem) => void;
  onPauseDownload?: (fileId: string) => void;
  onResumeDownload?: (fileId: string) => void;
  onStopDownload?: (fileId: string) => void;
  downloadProgress?: Record<string, DownloadProgressInfo>;
}

export function FileGrid({
  files,
  onShareFile,
  onDownloadFile,
  onDeleteFile,
  onViewFile,
  onPauseDownload,
  onResumeDownload,
  onStopDownload,
  downloadProgress,
}: FileGridProps) {
  return (
    <div className="p-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
        {files.map((file) => (
          <FileCard
            key={file.id}
            file={file}
            onShareFile={onShareFile}
            onDownloadFile={onDownloadFile}
            onDeleteFile={onDeleteFile}
            onViewFile={onViewFile}
            onPauseDownload={onPauseDownload}
            onResumeDownload={onResumeDownload}
            onStopDownload={onStopDownload}
            downloadProgress={downloadProgress?.[file.id]}
          />
        ))}
      </div>
    </div>
  );
}

function FileCard({
  file,
  onShareFile,
  onDownloadFile,
  onDeleteFile,
  onViewFile,
  onPauseDownload,
  onResumeDownload,
  onStopDownload,
  downloadProgress,
}: {
  file: FileItem;
  onShareFile?: (fileId: string) => void;
  onDownloadFile?: (fileId: string) => void;
  onDeleteFile?: (fileId: string) => void;
  onViewFile?: (file: FileItem) => void;
  onPauseDownload?: (fileId: string) => void;
  onResumeDownload?: (fileId: string) => void;
  onStopDownload?: (fileId: string) => void;
  downloadProgress?: DownloadProgressInfo;
}) {
  const dl = downloadProgress;
  const showProgress = dl && dl.status !== "completed" && dl.status !== "stopped";

  return (
    <div className="group relative flex flex-col items-center p-4 rounded-lg border border-border bg-card shadow-sm hover:shadow-md transition-shadow text-center">
      <div
        className="flex flex-col items-center w-full"
        onClick={() => dl?.status === "downloading" || dl?.status === "paused" ? undefined : onViewFile?.(file)}
      >
        <div className="flex justify-center mb-3">
          <FileIcon fileType={file.fileType} name={file.name} className="w-12 h-12" />
        </div>
        <p
          className="text-sm font-medium text-foreground truncate w-full"
          title={file.name}
        >
          {file.name}
        </p>
        <p className="mt-1 text-xs text-muted-foreground truncate">{file.size}</p>

        {file.shared && (
          <div className="mt-2 flex items-center justify-center">
            <Badge
              variant="outline"
              className="text-xs font-medium border-border text-muted-foreground"
            >
              Shared
            </Badge>
          </div>
        )}

        {showProgress && (
          <div className="mt-2 w-full">
            <Progress value={dl!.percent} className="h-1.5" />
            <div className="flex items-center justify-center gap-1 mt-1">
              {dl!.status === "downloading" && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-5 w-5 p-0"
                  onClick={(e) => { e.stopPropagation(); onPauseDownload?.(file.id); }}
                >
                  <Pause className="w-3 h-3" strokeWidth={1.5} />
                </Button>
              )}
              {dl!.status === "paused" && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-5 w-5 p-0"
                  onClick={(e) => { e.stopPropagation(); onResumeDownload?.(file.id); }}
                >
                  <Play className="w-3 h-3" strokeWidth={1.5} />
                </Button>
              )}
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0"
                onClick={(e) => { e.stopPropagation(); onStopDownload?.(file.id); }}
              >
                <Square className="w-3 h-3" strokeWidth={1.5} />
              </Button>
              <span className="text-xs text-muted-foreground">{dl!.percent}%</span>
            </div>
          </div>
        )}
      </div>

      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 rounded-md text-muted-foreground hover:bg-accent/50"
              aria-label="More actions"
            >
              <MoreHorizontal className="w-4 h-4" strokeWidth={1.5} />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-40">
            <DropdownMenuItem
              onSelect={() => onViewFile?.(file)}
              className="cursor-pointer focus:bg-accent/50"
            >
              <Eye className="w-4 h-4 mr-2" strokeWidth={1.5} />
              <span>Details</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              onSelect={() => onDownloadFile?.(file.id)}
              className="cursor-pointer focus:bg-accent/50"
            >
              <Download className="w-4 h-4 mr-2" strokeWidth={1.5} />
              <span>Download</span>
            </DropdownMenuItem>
            {!file.is_shared_with_me && (
              <>
                <DropdownMenuItem
                  onSelect={() => onShareFile?.(file.id)}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <Share2 className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  <span>Share</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={() => onDeleteFile?.(file.id)}
                  className="text-destructive focus:text-destructive cursor-pointer focus:bg-destructive/10"
                >
                  <Trash2 className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  <span>Delete</span>
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}
