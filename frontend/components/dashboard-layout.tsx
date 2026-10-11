"use client";

import type React from "react";
import { useEffect, useRef, useState } from "react";
import { useTheme } from "next-themes";
import {
  Search,
  X,
  SunMoon,
  LogOut,
  ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { clearVaultXContext, getSessionContext } from "@/lib/crypto/context";
import { WorkspaceHub } from "@/components/workspace-context";
import type { WorkspaceContextAdapter } from "@/lib/workspace-context";

interface DashboardLayoutProps {
  children: React.ReactNode;
  onSearch?: (query: string) => void;
  onNavigate?: (section: string) => void;
  workspaceContext?: WorkspaceContextAdapter;
}

export function DashboardLayout({ children, onSearch, onNavigate, workspaceContext }: DashboardLayoutProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const [email, setEmail] = useState("");
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const storedEmail = getSessionContext()?.email;
    if (storedEmail) setEmail(storedEmail);
  }, []);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  };

  const handleSearchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    inputRef.current?.blur();
    onNavigate?.("My Vault");
    await new Promise((r) => setTimeout(r, 0));
    onSearch?.(searchQuery.trim());
    setSearchQuery(searchQuery.trim());
  };

  const clearSearch = () => {
    inputRef.current?.blur();
    setSearchQuery("");
    onSearch?.("");
  };

  const toggleTheme = () => {
    if (!mounted) return;
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  };

  const displayName = email ? email.split("@")[0] : "user";
  const avatarFallback = email ? email.charAt(0).toUpperCase() : "U";

  if (!mounted) {
    return (
      <div role="status" className="min-h-screen flex items-center justify-center bg-background text-muted-foreground">
        Loading...
      </div>
    );
  }

  return (
    <div className="vaultx-shell min-h-screen flex flex-col bg-background">
      <a href="#vaultx-content" className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-card focus:px-4 focus:py-3 focus:shadow-md">Skip to content</a>
      {/* ——— Enhanced Header (Top Bar) ——— */}
      <header className="border-b border-border bg-card">
        <div className="flex min-h-18 flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8 w-full mx-auto">
          {/* Left Section: Logo + app name */}
          <div className="flex items-center space-x-3">
            <div className="size-10 rounded-lg border-b-2 border-emerald bg-primary flex items-center justify-center">
              <VaultIcon className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-semibold text-foreground tracking-tight">
              VaultX
            </span>
          </div>

          {/* Center Section: Global search */}
          <div className="order-3 w-full sm:order-none sm:w-auto sm:flex-1 sm:max-w-xl sm:mx-6 flex items-center">
            <form role="search" onSubmit={handleSearchSubmit} className="relative flex-1">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none"
                strokeWidth={1.5}
              />
              <Input
                ref={inputRef}
                aria-label="Search files in your vault"
                placeholder="Search files…"
                value={searchQuery}
                onChange={handleSearchChange}
                className={cn(
                  "pl-10 pr-12 h-11 bg-muted/50 border-input-border rounded-md",
                  "focus:bg-background focus:border-ring"
                )}
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={clearSearch}
                   className="absolute right-0 top-1/2 -translate-y-1/2 flex size-11 items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-muted cursor-pointer"
                  aria-label="Clear search"
                >
                  <X className="w-3.5 h-3.5" strokeWidth={1.5} />
                </button>
              )}
            </form>
          </div>

          {/* Right Section: Theme toggle + user dropdown */}
          <div className="flex items-center space-x-2">
            <Button
              variant="ghost"
              size="icon"
              className="size-11 text-muted-foreground hover:text-foreground hover:bg-accent/50"
              onClick={toggleTheme}
              aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
            >
              <SunMoon className="w-5 h-5" strokeWidth={1.5} />
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  className="flex items-center space-x-2 h-auto px-2 hover:bg-accent/50"
                  aria-label="User menu"
                >
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary/10 text-primary">
                      {avatarFallback}
                    </AvatarFallback>
                  </Avatar>
                  <span className="hidden lg:block max-w-36 truncate text-sm font-medium text-foreground">
                    {displayName}
                  </span>
                  <ChevronDown className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
                </Button>
              </DropdownMenuTrigger>

              <DropdownMenuContent align="end" className="w-56">
                <div className="px-3 py-2 border-b border-border">
                  <p className="break-words text-sm font-medium text-foreground">{email || "Your account"}</p>
                </div>

                <DropdownMenuItem
                  onSelect={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <SunMoon className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  Toggle Theme
                </DropdownMenuItem>

                <DropdownMenuSeparator />

                <DropdownMenuItem
                  onSelect={() => {
                    clearVaultXContext();
                    window.location.href = "/";
                  }}
                  className="text-destructive focus:text-destructive cursor-pointer focus:bg-destructive/10"
                >
                  <LogOut className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  Logout
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </header>

      <WorkspaceHub adapter={workspaceContext} />

      <div id="vaultx-content" tabIndex={-1} className="flex flex-1 flex-col min-w-0 outline-none">{children}</div>
    </div>
  );
}

function VaultIcon(props: React.SVGProps<SVGSVGElement>) {
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
        d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2H5a2 2 0 0 0-2-2z"
      />
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M8 5l4-4 4 4"
      />
    </svg>
  );
}
