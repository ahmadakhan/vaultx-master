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
import { getSessionContext } from "@/lib/crypto/context";

export type { DownloadProgressInfo } from "@/lib/transfer-ui";

interface FileListProps {
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

export function FileList({
  files,
  onShareFile,
  onDownloadFile,
  onDeleteFile,
  onViewFile,
  onPauseDownload,
  onResumeDownload,
  onStopDownload,
  downloadProgress,
}: FileListProps) {
  const current_user = getSessionContext()?.email ?? null;

  return (
    <div className="p-4 sm:p-6">
      <div className="grid grid-cols-[minmax(0,1fr)_auto] lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_10rem] gap-4 px-2 pb-3 border-b border-border text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground">
        <div>Name</div>
        <div className="hidden lg:block">Owner</div>
        <div className="hidden lg:block">Modified</div>
        <div className="text-right">Size / Actions</div>
      </div>

      <div role="list" aria-label="Files" className="space-y-1">
        {files.map((file) => (
          <Row
            key={file.id}
            file={file}
            isCurrentUser={file.owner === current_user}
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

function Row({
  file,
  isCurrentUser,
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
  isCurrentUser: boolean;
  onShareFile?: (fileId: string) => void;
  onDownloadFile?: (fileId: string) => void;
  onDeleteFile?: (fileId: string) => void;
  onViewFile?: (file: FileItem) => void;
  onPauseDownload?: (fileId: string) => void;
  onResumeDownload?: (fileId: string) => void;
  onStopDownload?: (fileId: string) => void;
  downloadProgress?: DownloadProgressInfo;
}) {
  const displayOwner = isCurrentUser ? "You" : file.owner;
  const dl = downloadProgress;
  const showProgress = !!dl;

  return (
     <div role="listitem" className="grid grid-cols-[minmax(0,1fr)_auto] lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_10rem] gap-4 items-center group py-3 px-2 border-b border-border/60 hover:bg-accent/50 transition-colors">
      <button
        type="button"
        aria-label={`View details for ${file.name}`}
        disabled={!onViewFile || dl?.status === "downloading" || dl?.status === "paused"}
        className="flex items-center space-x-3 min-w-0 text-left rounded-md disabled:cursor-default"
        onClick={dl?.status === "downloading" || dl?.status === "paused" ? undefined : () => onViewFile?.(file)}
      >
        <FileIcon fileType={file.fileType} name={file.name} className="w-6 h-6 flex-shrink-0" />
        <span className="flex flex-wrap items-center gap-2 min-w-0">
          <span title={file.name} className="text-sm font-medium text-foreground truncate">
            {file.name}
          </span>
          {file.shared && (
            <Badge
              variant="outline"
              className="text-xs font-medium border-border text-muted-foreground"
            >
              Shared
            </Badge>
          )}
        </span>
      </button>

      <div title={displayOwner} className="hidden lg:block text-sm text-muted-foreground truncate">
        {displayOwner}
      </div>

      <div title={file.modified} className="hidden lg:block text-sm text-muted-foreground truncate">
        {file.modified}
      </div>

      <div className="flex items-center justify-end gap-2">
        {!showProgress && <span className="text-xs text-muted-foreground tabular-nums whitespace-nowrap">{file.size}</span>}
        {(
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-11 w-11 text-muted-foreground hover:bg-accent/50"
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
        )}
      </div>
      {showProgress && <div className="col-span-full"><DownloadTransfer name={file.name} progress={dl!} onPause={() => onPauseDownload?.(file.id)} onResume={() => onResumeDownload?.(file.id)} onAbort={() => onStopDownload?.(file.id)} /></div>}
    </div>
  );
}
