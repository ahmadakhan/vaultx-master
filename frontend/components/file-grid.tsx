"use client";

import {
  Eye,
  Download,
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
import { DownloadTransfer } from "@/components/transfer-stats";
import type { DownloadProgressInfo } from "@/lib/transfer-ui";
import { FileIcon } from "@/components/file-icon";
import type { FileItem } from "@/lib/types";

export type { DownloadProgressInfo } from "@/lib/transfer-ui";

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
    <div className="p-4 sm:p-6">
      <div role="list" aria-label="Files" className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
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
  const showProgress = !!dl;

  return (
    <div role="listitem" className="group relative min-w-0 flex flex-col items-center p-5 pt-12 rounded-xl border border-border bg-card hover:border-primary/40 transition-colors duration-200 ease-[cubic-bezier(0.2,0,0,1)] motion-reduce:transition-none text-center">
      <button
        type="button"
        disabled={!onViewFile || dl?.status === "downloading" || dl?.status === "paused"}
        aria-label={`View details for ${file.name}`}
        className="flex flex-col items-center w-full min-w-0 rounded-md disabled:cursor-default"
        onClick={() => dl?.status === "downloading" || dl?.status === "paused" ? undefined : onViewFile?.(file)}
      >
        <span aria-hidden="true" className="flex justify-center mb-3">
          <FileIcon fileType={file.fileType} name={file.name} className="w-12 h-12" />
        </span>
        <span
          className="text-sm font-medium text-foreground truncate w-full"
          title={file.name}
        >
          {file.name}
        </span>
        <span className="mt-1 text-xs text-muted-foreground truncate">{file.size}</span>

        {file.shared && (
          <span className="mt-2 flex items-center justify-center">
            <Badge
              variant="outline"
              className="text-xs font-medium border-border text-muted-foreground"
            >
              Shared
            </Badge>
          </span>
        )}
      </button>

        {showProgress && (
          <div className="mt-2 w-full">
            <DownloadTransfer name={file.name} progress={dl!} onPause={() => onPauseDownload?.(file.id)} onResume={() => onResumeDownload?.(file.id)} onAbort={() => onStopDownload?.(file.id)} />
          </div>
        )}
      <div className="absolute top-2 right-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-11 w-11 rounded-md text-muted-foreground hover:bg-accent/50"
              aria-label={`Actions for ${file.name}`}
            >
              <MoreHorizontal className="w-4 h-4" strokeWidth={1.5} />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-40">
            <DropdownMenuItem
              disabled={!onViewFile}
              onSelect={() => onViewFile?.(file)}
              className="cursor-pointer focus:bg-accent/50"
            >
              <Eye className="w-4 h-4 mr-2" strokeWidth={1.5} />
              <span>Details</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={!onDownloadFile || !!dl && ["downloading", "pausing", "paused", "decrypting"].includes(dl.status)}
              onSelect={() => onDownloadFile?.(file.id)}
              className="cursor-pointer focus:bg-accent/50"
            >
              <Download className="w-4 h-4 mr-2" strokeWidth={1.5} />
              <span>Download</span>
            </DropdownMenuItem>
            {!file.is_shared_with_me && (
              <>
                <DropdownMenuItem
                  disabled={!onShareFile}
                  onSelect={() => onShareFile?.(file.id)}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <Share2 className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  <span>Share</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  disabled={!onDeleteFile}
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
