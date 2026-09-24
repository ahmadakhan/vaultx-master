"use client";

import type React from "react";
import { useEffect, useRef, useState } from "react";
import { useTheme } from "next-themes";
import {
  Search,
  X,
  SunMoon,
  User,
  LogOut,
  Settings,
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

interface DashboardLayoutProps {
  children: React.ReactNode;
  onSearch?: (query: string) => void;
  onNavigate?: (section: string) => void;
}

export function DashboardLayout({ children, onSearch, onNavigate }: DashboardLayoutProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const [email, setEmail] = useState("");
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const storedEmail = sessionStorage.getItem("vaultx_user_email");
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
      <div className="min-h-screen flex items-center justify-center bg-background text-muted-foreground">
        Loading...
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* ——— Enhanced Header (Top Bar) ——— */}
      <header className="border-b border-border bg-card shadow-sm">
        <div className="flex h-16 items-center justify-between px-6 w-full max-w-[var(--container-max)] mx-auto">
          {/* Left Section: Logo + app name */}
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-primary flex items-center justify-center">
              <VaultIcon className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-semibold text-foreground tracking-tight">
              VaultX
            </span>
          </div>

          {/* Center Section: Global search */}
          <div className="flex-1 max-w-2xl mx-8 flex items-center space-x-3">
            <form onSubmit={handleSearchSubmit} className="relative flex-1">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none"
                strokeWidth={1.5}
              />
              <Input
                ref={inputRef}
                placeholder="Search Vault"
                value={searchQuery}
                onChange={handleSearchChange}
                className={cn(
                  "pl-10 pr-10 h-10 bg-muted/50 border-border rounded-md",
                  "focus:bg-background focus:border-ring"
                )}
              />
              <kbd
                className="absolute right-24 top-1/2 -translate-y-1/2 hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 text-xs text-muted-foreground bg-muted/60 border border-border rounded">
                <span className="text-xs">⌘</span>K
              </kbd>
              {searchQuery && (
                <button
                  type="button"
                  onClick={clearSearch}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-0.5 text-muted-foreground hover:text-foreground hover:bg-muted cursor-pointer"
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
              className="h-9 w-9 text-muted-foreground hover:text-foreground hover:bg-accent/50"
              onClick={toggleTheme}
              aria-label="Toggle theme"
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
                  <span className="hidden sm:block text-sm font-medium text-foreground">
                    {displayName}
                  </span>
                  <ChevronDown className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
                </Button>
              </DropdownMenuTrigger>

              <DropdownMenuContent align="end" className="w-56">
                <div className="px-3 py-2 border-b border-border">
                  <p className="text-sm font-medium text-foreground">{email || "user@example.com"}</p>
                  <p className="text-xs text-muted-foreground">Enterprise plan</p>
                </div>

                <DropdownMenuItem
                  onSelect={() => {}}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <User className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  Profile
                </DropdownMenuItem>

                <DropdownMenuItem
                  onSelect={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <SunMoon className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  Toggle Theme
                </DropdownMenuItem>

                <DropdownMenuItem
                  onSelect={() => {}}
                  className="cursor-pointer focus:bg-accent/50"
                >
                  <Settings className="w-4 h-4 mr-2" strokeWidth={1.5} />
                  Settings
                </DropdownMenuItem>

                <DropdownMenuSeparator />

                <DropdownMenuItem
                  onSelect={() => {
                    localStorage.clear();
                    sessionStorage.clear();
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

      {children}
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
