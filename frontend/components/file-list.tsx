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
  const current_user =
    typeof sessionStorage !== "undefined"
      ? sessionStorage.getItem("vaultx_user_email")
      : null;

  return (
    <div className="p-6">
      <div className="grid grid-cols-12 gap-4 pb-3 border-b border-border text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground">
        <div className="col-span-5">Name</div>
        <div className="col-span-3">Owner</div>
        <div className="col-span-3">Modified</div>
        <div className="col-span-1 text-right">Size</div>
      </div>

      <div className="space-y-1">
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
  const showProgress = dl && dl.status !== "completed" && dl.status !== "stopped";

  return (
    <div className="grid grid-cols-12 gap-4 items-center group py-3 px-2 rounded-lg hover:bg-accent/50 transition-colors">
      <div
        className="col-span-5 flex items-center space-x-3 min-w-0"
        onClick={dl?.status === "downloading" || dl?.status === "paused" ? undefined : () => onViewFile?.(file)}
      >
        <FileIcon fileType={file.fileType} name={file.name} className="w-6 h-6 flex-shrink-0" />
        <div className="flex items-center space-x-2 min-w-0">
          <span className="text-sm font-medium text-foreground truncate">
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
        </div>
      </div>

      <div className="col-span-3 flex items-center text-sm text-muted-foreground truncate">
        {displayOwner}
      </div>

      <div className="col-span-3 flex items-center text-sm text-muted-foreground truncate">
        {file.modified}
      </div>

      <div className="col-span-1 flex items-center justify-end">
        {showProgress ? (
          <div className="flex items-center gap-1 w-24">
            <Progress value={dl!.percent} className="h-1 flex-1" />
            {dl!.status === "downloading" && (
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0"
                onClick={() => onPauseDownload?.(file.id)}
              >
                <Pause className="w-3 h-3" strokeWidth={1.5} />
              </Button>
            )}
            {dl!.status === "paused" && (
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0"
                onClick={() => onResumeDownload?.(file.id)}
              >
                <Play className="w-3 h-3" strokeWidth={1.5} />
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              className="h-5 w-5 p-0"
              onClick={() => onStopDownload?.(file.id)}
            >
              <Square className="w-3 h-3" strokeWidth={1.5} />
            </Button>
          </div>
        ) : (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 opacity-0 group-hover:opacity-100 text-muted-foreground hover:bg-accent/50"
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
        )}
      </div>
    </div>
  );
}
