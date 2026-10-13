"use client"
import { memorySession } from "@/lib/crypto/context"

import { useState, useEffect, useCallback } from "react"
import { Shield, Users, Trash2, Plus, Check, X, Loader2, Search, Lock, Calendar, Eye } from "lucide-react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/types"
import { MfaSettings } from "@/components/mfa-settings"
import { Sidebar } from "@/components/sidebar"
import { DashboardLayout } from "@/components/dashboard-layout"

interface AdminUser {
  id: string
  email: string
  mfa_enabled: boolean
  is_active: boolean
  created_at: string
  roles: string[]
}

interface AuditLogEntry {
  id: number
  user_id: string | null
  seq: number
  entry_json: Record<string, unknown>
  entry_hash: string
  created_at: string
}

interface AuditVerifyResponse {
  valid: boolean
  errors: string[]
  user_id: string
}

interface CreateUserForm {
  email: string
  password: string
  role: string
}

export default function AdminPage() {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState("users")
  const [users, setUsers] = useState<AdminUser[]>([])
  const [usersLoading, setUsersLoading] = useState(false)
  const [usersError, setUsersError] = useState<string | null>(null)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [createForm, setCreateForm] = useState<CreateUserForm>({
    email: "",
    password: "",
    role: "user",
  })
  const [creatingUser, setCreatingUser] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditError, setAuditError] = useState<string | null>(null)
  const [auditCount, setAuditCount] = useState(0)
  const [verifyUserId, setVerifyUserId] = useState("")
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [userSearch, setUserSearch] = useState("")

  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  const loadUsers = useCallback(async () => {
    if (typeof window === "undefined") return
    const t = memorySession.getItem("vaultx_access_token")
    if (!t) return
    setUsersLoading(true)
    setUsersError(null)
    try {
      const res = await api.get("/admin/users", t)
      setUsers(res || [])
    } catch (err) {
      setUsersError(errorMessage(err, "Failed to load users."))
    } finally {
      setUsersLoading(false)
    }
  }, [])

  useEffect(() => {
    const t = memorySession.getItem("vaultx_access_token")
    if (!mounted || !t) {
      if (!t) router.replace("/")
      return
    }
    loadUsers()
  }, [loadUsers, mounted, router])

  const loadAuditLogs = useCallback(async () => {
    const t = memorySession.getItem("vaultx_access_token")
    if (!t) return
    setAuditLoading(true)
    setAuditError(null)
    try {
      const res = await api.get("/admin/audit/logs?limit=100", t)
      setAuditLogs(res.logs || res || [])
      setAuditCount(res.count || 0)
    } catch (err) {
      setAuditError(errorMessage(err, "Failed to load audit logs."))
    } finally {
      setAuditLoading(false)
    }
  }, [])

  const handleCreateUser = async () => {
    if (!createForm.email || !createForm.password) return
    setCreatingUser(true)
    setCreateError(null)
    try {
      const t = memorySession.getItem("vaultx_access_token")
      if (!t) return
      await api.post(
        "/admin/users",
        {
          email: createForm.email,
          password: createForm.password,
          role: createForm.role,
        },
        t
      )
      setShowCreateDialog(false)
      setCreateForm({ email: "", password: "", role: "user" })
      await loadUsers()
    } catch (err) {
      setCreateError(errorMessage(err, "Failed to create user."))
    } finally {
      setCreatingUser(false)
    }
  }

  const handleDeactivateUser = async (userId: string) => {
    if (!confirm("Deactivate this user? They will lose access immediately.")) return
    const t = memorySession.getItem("vaultx_access_token")
    if (!t) return
    try {
      await api.delete(`/admin/users/${userId}`, t)
      setUsers(users.filter((u) => u.id !== userId))
    } catch (err) {
      alert(errorMessage(err, "Failed to deactivate user."))
    }
  }

  const handleVerifyChain = async () => {
    if (!verifyUserId) return
    setVerifying(true)
    setVerifyResult(null)
    try {
      const t = memorySession.getItem("vaultx_access_token")
      if (!t) return
      const res = await api.get(
        `/admin/audit/verify?user_id=${encodeURIComponent(verifyUserId)}`,
        t
      )
      setVerifyResult(res)
    } catch (err) {
      alert(errorMessage(err, "Failed to verify audit chain."))
    } finally {
      setVerifying(false)
    }
  }

  const userInitial = (email: string) => email.charAt(0).toUpperCase()
  const activeUserCount = users.filter((user) => user.is_active).length
  const mfaUserCount = users.filter((user) => user.mfa_enabled).length
  const adminUserCount = users.filter((user) => user.roles.includes("admin")).length
  const filteredUsers = users.filter((user) => {
    const query = userSearch.trim().toLowerCase()
    return !query || user.email.toLowerCase().includes(query) || user.roles.some((role) => role.includes(query))
  })

  return (
    <DashboardLayout>
    <div className="flex min-h-0 flex-1 bg-background">
      <Sidebar
        activeSection="admin"
        setActiveSection={() => {}}
        onNavigate={(section) => {
          if (section !== "admin") router.push("/dashboard")
        }}
      />
      <div className="min-w-0 flex-1">
      <header className="border-b border-border bg-card px-4 py-5 sm:px-6 lg:px-8">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-end justify-between gap-4">
          <div>
            <p className="vaultx-caption mb-1">Administration</p>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" strokeWidth={1.5} />
              <h1 className="text-xl font-semibold tracking-tight text-foreground">Admin Dashboard</h1>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">Manage access, review audit activity, and enforce account security.</p>
          </div>
          <nav aria-label="Administration sections" role="tablist" className="grid w-full max-w-[520px] grid-cols-3 gap-1 rounded-md border border-border bg-muted/40 p-1">
            <Button
              role="tab"
              aria-label="Users"
              aria-selected={activeTab === "users"}
              title="Users"
              variant={activeTab === "users" ? "default" : "ghost"}
              size="sm"
              className="min-w-0 px-2"
              onClick={() => setActiveTab("users")}
            >
              <Users className="h-4 w-4 sm:mr-2" strokeWidth={1.5} />
              <span className="hidden sm:inline">Users</span>
            </Button>
            <Button
              role="tab"
              aria-label="Audit Logs"
              aria-selected={activeTab === "audit"}
              title="Audit Logs"
              variant={activeTab === "audit" ? "default" : "ghost"}
              size="sm"
              className="min-w-0 px-2"
              onClick={() => {
                setActiveTab("audit")
                loadAuditLogs()
              }}
            >
              <Lock className="h-4 w-4 sm:mr-2" strokeWidth={1.5} />
              <span className="hidden sm:inline">Audit Logs</span>
            </Button>
            <Button
              role="tab"
              aria-label="MFA Settings"
              aria-selected={activeTab === "mfa"}
              title="MFA Settings"
              variant={activeTab === "mfa" ? "default" : "ghost"}
              size="sm"
              className="min-w-0 px-2"
              onClick={() => setActiveTab("mfa")}
            >
              <Shield className="h-4 w-4 sm:mr-2" strokeWidth={1.5} />
              <span className="hidden sm:inline">MFA Settings</span>
            </Button>
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 sm:px-6 lg:px-8">
        {/* Users Tab */}
        <div className={activeTab !== "users" ? "hidden" : "space-y-5"}>
          <div className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-3 sm:gap-px">
            <div className="bg-card px-4 py-3">
              <p className="text-xs font-medium text-muted-foreground">Total accounts</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{users.length}</p>
            </div>
            <div className="bg-card px-4 py-3">
              <p className="text-xs font-medium text-muted-foreground">Active accounts</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{activeUserCount}</p>
            </div>
            <div className="bg-card px-4 py-3">
              <p className="text-xs font-medium text-muted-foreground">Administrators · MFA enabled</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{adminUserCount} <span className="text-sm font-normal text-muted-foreground">· {mfaUserCount} MFA</span></p>
            </div>
          </div>

          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-foreground">User accounts</h2>
              <p className="mt-1 text-sm text-muted-foreground">Review roles, account status, and multi-factor coverage.</p>
            </div>
            <Button size="sm" onClick={() => setShowCreateDialog(true)}>
              <Plus className="w-4 h-4 mr-2" strokeWidth={1.5} />
              Create User
            </Button>
          </div>

          {usersError && (
            <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 text-sm text-destructive">
              {usersError}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="relative w-full max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
              <Input
                aria-label="Search users"
                placeholder="Search email or role"
                value={userSearch}
                onChange={(event) => setUserSearch(event.target.value)}
                className="h-10 pl-9"
              />
            </div>
            <p className="text-sm tabular-nums text-muted-foreground" aria-live="polite">
              {filteredUsers.length} of {users.length} accounts
            </p>
          </div>

          <div className="overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full min-w-[760px]">
              <caption className="sr-only">User accounts, roles, multi-factor status, creation dates, and actions</caption>
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    User
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Role
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    MFA
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Created
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {usersLoading ? (
                  <tr className="border-b border-border">
                    <td colSpan={5} className="py-8 text-center text-muted-foreground">
                      <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                      Loading users…
                    </td>
                  </tr>
                ) : filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-muted-foreground">
                      {users.length === 0 ? "No users found." : "No accounts match this search."}
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => (
                    <tr key={u.id} className="transition-colors hover:bg-muted/30">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          <Avatar className="h-8 w-8">
                            <AvatarFallback className="bg-primary/10 text-primary">
                              {userInitial(u.email)}
                            </AvatarFallback>
                          </Avatar>
                          <div>
                            <p className="text-sm font-medium text-foreground">{u.email}</p>
                            {!u.is_active && (
                              <Badge variant="secondary" className="text-xs mt-0.5">
                                Deactivated
                              </Badge>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        {u.roles.includes("admin") ? (
                          <Badge className="text-xs bg-primary/10 text-primary">
                            Admin
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="text-xs">
                            User
                          </Badge>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {u.mfa_enabled ? (
                          <Badge className="text-xs bg-green-500/10 text-green-500">
                            Enabled
                          </Badge>
                        ) : (
                          <span className="text-sm text-muted-foreground">Disabled</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-sm text-muted-foreground">
                        <Calendar className="w-3 h-3 inline mr-1" strokeWidth={1.5} />
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-muted-foreground hover:text-destructive"
                          onClick={() => handleDeactivateUser(u.id)}
                          disabled={!u.is_active || u.roles.includes("admin")}
                          aria-label={`Deactivate ${u.email}`}
                          title={`Deactivate ${u.email}`}
                        >
                          <Trash2 className="w-4 h-4" strokeWidth={1.5} />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Audit Logs Tab */}
        <div className={activeTab !== "audit" ? "hidden" : "space-y-6"}>
          <h2 className="text-lg font-semibold text-foreground">Tamper-Proof Audit Logs</h2>

          <Card className="border-border">
            <CardHeader>
              <CardTitle className="text-md">Verify Audit Chain</CardTitle>
              <CardDescription>
                Enter a user ID to verify the integrity of their audit log chain.
                The system checks hash consistency, RSA signatures, and chain
                linkage to detect tampering.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <Input
                  placeholder="User UUID"
                  value={verifyUserId}
                  onChange={(e) => setVerifyUserId(e.target.value)}
                  className="border-border flex-1"
                />
                <Button onClick={handleVerifyChain} disabled={verifying || !verifyUserId}>
                  {verifying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
                </Button>
              </div>

              {verifyResult && (
                <div className="mt-4">
                  <div
                    className={`flex items-center gap-2 ${
                      verifyResult.valid ? "text-green-500" : "text-destructive"
                    }`}
                  >
                    {verifyResult.valid ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      <X className="w-4 h-4" />
                    )}
                    <span className="font-medium">
                      {verifyResult.valid ? "Chain is valid" : "Chain verification failed"}
                    </span>
                  </div>
                  {!verifyResult.valid && verifyResult.errors.length > 0 && (
                    <ul className="mt-2 space-y-1 text-sm text-destructive">
                      {verifyResult.errors.map((e, i) => (
                        <li key={i}>• {e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="flex items-center justify-between">
            <h3 className="text-md font-semibold text-foreground">Recent Log Entries (all users)</h3>
            <span className="text-xs text-muted-foreground">Total: {auditCount}</span>
          </div>

          {auditError && (
            <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 text-sm text-destructive">
              {auditError}
            </div>
          )}

          <div className="border border-border rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-muted/20">
                <tr>
                  <th className="text-left py-2 px-4 text-xs font-medium text-muted-foreground uppercase">
                    Time
                  </th>
                  <th className="text-left py-2 px-4 text-xs font-medium text-muted-foreground uppercase">
                    User ID
                  </th>
                  <th className="text-left py-2 px-4 text-xs font-medium text-muted-foreground uppercase">
                    Action
                  </th>
                  <th className="text-left py-2 px-4 text-xs font-medium text-muted-foreground uppercase">
                    Hash
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {auditLoading ? (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-muted-foreground">
                      <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                      Loading logs…
                    </td>
                  </tr>
                ) : auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-muted-foreground">
                      No audit logs found.
                    </td>
                  </tr>
                ) : (
                  auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="py-2 px-4 text-sm text-muted-foreground">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="py-2 px-4 text-sm font-mono text-muted-foreground">
                        {log.user_id ? log.user_id.substring(0, 8) + "..." : "system"}
                      </td>
                      <td className="py-2 px-4 text-sm text-foreground">
                        {String(log.entry_json?.action || "unknown")}
                      </td>
                      <td className="py-2 px-4 text-sm font-mono text-muted-foreground">
                        {log.entry_hash.substring(0, 12)}...
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* MFA Tab */}
        <div className={activeTab !== "mfa" ? "hidden" : ""}>
          <h2 className="text-lg font-semibold text-foreground mb-4">Security Settings</h2>
          <MfaSettings />
        </div>
      </main>

      {/* Create User Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="border-border">
          <DialogHeader>
            <DialogTitle>Create New User</DialogTitle>
            <DialogDescription>
              Create a new user account. Set an initial password.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="user@example.com"
                value={createForm.email}
                onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
                className="border-border"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Minimum 12 characters"
                value={createForm.password}
                onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                className="border-border"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="role">Role</Label>
              <Select
                value={createForm.role}
                onValueChange={(v) => setCreateForm({ ...createForm, role: v })}
              >
                <SelectTrigger className="border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {createError && (
              <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 text-sm text-destructive">
                {createError}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-border" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateUser} disabled={creatingUser || !createForm.email || !createForm.password}>
              {creatingUser ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Create User
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </div>
    </div>
    </DashboardLayout>
  )
}
