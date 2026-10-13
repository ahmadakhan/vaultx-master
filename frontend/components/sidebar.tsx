"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { clearVaultXContext } from "@/lib/crypto/context";
import {
  Vault,
  UploadCloud,
  Share2,
  Trash2,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  LogOut,
  LayoutDashboard,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { UploadModal } from "@/components/upload-modal";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface SidebarProps {
  activeSection: string;
  setActiveSection: (section: string) => void;
  onNavigate?: (section: string) => void;
}

interface SidebarItem {
  icon: React.ReactNode;
  label: string;
  value: string;
}

export function Sidebar({ activeSection, setActiveSection, onNavigate }: SidebarProps) {
  const router = useRouter();
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  const sidebarItems: SidebarItem[] = [
    { icon: <Vault strokeWidth={1.5} />, label: "My Vault", value: "My Vault" },
    { icon: <Share2 strokeWidth={1.5} />, label: "Shared with Me", value: "Shared with Me" },
    { icon: <Trash2 strokeWidth={1.5} />, label: "Trash", value: "Trash" },
    { icon: <ShieldCheck strokeWidth={1.5} />, label: "Audit Logs", value: "Logs" },
    { icon: <ShieldCheck strokeWidth={1.5} />, label: "Security", value: "Security" },
  ];

  const adminItems: SidebarItem[] = [
    { icon: <LayoutDashboard strokeWidth={1.5} />, label: "Admin Dashboard", value: "admin" },
  ];

  const handleNavigation = (item: SidebarItem) => {
    setActiveSection(item.value);
    onNavigate?.(item.value);
  };

  const handleUpload = () => {
    setActiveSection("My Vault");
    setUploadModalOpen(true);
  };

  return (
    <aside
      className={cn(
        "vaultx-sidebar shrink-0 flex flex-col border-r border-border bg-card transition-[width] duration-200",
        collapsed ? "w-20" : "w-60"
      )}
    >
      <div className="p-3 border-b border-border">
        <Button
          variant={collapsed ? "ghost" : "default"}
          size={collapsed ? "icon" : "default"}
          className={cn(
            "w-full",
            collapsed
              ? "h-10 w-10 mx-auto"
              : "bg-primary hover:bg-primary/90 text-primary-foreground"
          )}
          onClick={handleUpload}
          aria-label="Upload file"
          title="Upload file"
        >
          <UploadCloud className={cn("shrink-0", collapsed ? "w-5 h-5" : "w-4 h-4 mr-2")} />
          {!collapsed && <span className="sidebar-label">Upload File</span>}
        </Button>
      </div>

      <nav aria-label="Workspace" className="flex-1 px-3 py-5 space-y-1 overflow-y-auto">
        {adminItems.map((item) => {
          const isActive = activeSection === item.value;
          const button = (
            <Button
              key={item.value}
              variant="ghost"
              size={collapsed ? "icon" : "default"}
              className={cn(
                "w-full justify-start h-10 relative transition-colors",
                isActive
                  ? "bg-accent/60 text-primary hover:bg-accent/70"
                  : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
              )}
              onClick={() => {
                router.push("/dashboard/admin")
              }}
              aria-label={item.label}
              title={item.label}
              aria-current={isActive ? "page" : undefined}
            >
              <span className="flex items-center shrink-0 w-5 justify-center">
                {item.icon}
              </span>
              {!collapsed && <span className="sidebar-label">{item.label}</span>}
              {isActive && (
                <span className={cn(
                  "absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r bg-primary",
                  collapsed && "hidden"
                )} />
              )}
            </Button>
          );

          if (collapsed) {
            return (
              <Tooltip key={item.value}>
                <TooltipTrigger asChild>
                  {button}
                </TooltipTrigger>
                <TooltipContent side="right" className="ml-2">
                  {item.label}
                </TooltipContent>
              </Tooltip>
            );
          }

          return <div key={item.value} className="relative">{button}</div>;
        })}

        {sidebarItems.map((item) => {
          const isActive = activeSection === item.value;
          const button = (
            <Button
              key={item.value}
              variant="ghost"
              size={collapsed ? "icon" : "default"}
              className={cn(
                "w-full justify-start h-10 relative transition-colors",
                isActive
                  ? "bg-accent/60 text-primary hover:bg-accent/70"
                  : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
              )}
              onClick={() => handleNavigation(item)}
              aria-label={item.label}
              title={item.label}
              aria-current={isActive ? "page" : undefined}
            >
              <span
                className={cn(
                  "flex items-center shrink-0 transition-all",
                  isActive
                    ? "text-primary"
                    : "text-muted-foreground group-hover:text-foreground",
                  collapsed ? "justify-center w-5" : "mr-3 w-5"
                )}
              >
                {item.icon}
              </span>
              {!collapsed && <span className="sidebar-label">{item.label}</span>}
              {isActive && (
                <div
                  className={cn(
                    "absolute left-0 top-1/2 -translate-y-1/2 h-6 w-1 rounded-r bg-primary",
                    collapsed ? "hidden" : ""
                  )}
                />
              )}
            </Button>
          );

          if (collapsed) {
            return (
              <Tooltip key={item.value}>
                <TooltipTrigger asChild>
                  {button}
                </TooltipTrigger>
                <TooltipContent side="right" className="ml-2">
                  {item.label}
                </TooltipContent>
              </Tooltip>
            );
          }

          return (
            <div key={item.value} className="relative">
              {button}
            </div>
          );
        })}
      </nav>

      <div className="p-3 border-t border-border">
        <Button
          variant="ghost"
          size={collapsed ? "icon" : "default"}
          className={cn(
            "w-full mt-1 text-muted-foreground hover:text-destructive hover:bg-destructive/10",
            collapsed && "h-10 w-10 mx-auto"
          )}
          onClick={() => {
            clearVaultXContext();
            router.replace("/");
          }}
          aria-label="Log out"
          title="Log out"
        >
          <LogOut className={cn("shrink-0", collapsed ? "w-5 h-5" : "w-4 h-4 mr-2")} />
          {!collapsed && <span className="sidebar-label">Log out</span>}
        </Button>

      </div>

      <div className="sidebar-collapse p-2 border-t border-border flex justify-center">
        <Button
          variant="ghost"
          size="sm"
          className={cn("w-full", collapsed && "h-8 w-8 mx-auto")}
          onClick={() => setCollapsed(!collapsed)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4 mr-2" />}
          {!collapsed && <span>Collapse</span>}
        </Button>
      </div>

      <UploadModal open={uploadModalOpen} onOpenChange={setUploadModalOpen} />
    </aside>
  );
}
