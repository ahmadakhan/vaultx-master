"use client"

import { useRef, useState, useEffect } from "react"
import { Share2, Trash2, Loader2, UserPlus } from "lucide-react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { getVaultXContext, memorySession } from "@/lib/crypto/context"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/types"
import { GuestLinkPanel } from "@/components/guest-link-panel"

interface FileItem {
  id: string; name: string; type: "file" | "folder"; fileType?: string
  size: string; modified: string; owner: string; shared: boolean; shared_with?: string[]
}
interface ShareModalProps { open: boolean; onOpenChange: (open: boolean) => void; file: FileItem | null }

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----.*-----/g, "").replace(/\s+/g, "")
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function PeopleAccess({ file }: { file: FileItem }) {
  const [email, setEmail] = useState("")
  const [sharedUsers, setSharedUsers] = useState<string[]>(file.shared_with || [])
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const busy = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  async function addUser(event: React.FormEvent) {
    event.preventDefault()
    if (busy.current) return
    const recipient = email.trim().toLowerCase()
    if (!recipient) return
    if (sharedUsers.includes(recipient)) { setError("This user already has access."); return }
    busy.current = true; setAdding(true); setError(null)
    try {
      const ctx = getVaultXContext()
      if (!ctx.accessToken) throw new Error("Not logged in")
      const { public_key_pem } = await api.get(`/auth/public-key/${recipient}`, ctx.accessToken)
      const pubKey = await window.crypto.subtle.importKey("spki", pemToArrayBuffer(public_key_pem), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"])
      const fileKey_b64 = memorySession.getItem(`vaultx_kf_${file.id}`)
      if (!fileKey_b64) throw new Error("Missing file encryption key (Kf)")
      const fileKeyBytes = Uint8Array.from(atob(fileKey_b64), c => c.charCodeAt(0))
      const wrappedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, fileKeyBytes)
      const wrappedKey_b64 = btoa(String.fromCharCode(...new Uint8Array(wrappedKey)))
      if (!alive.current) return
      await api.post("/shares", { file_id: file.id, recipient_email: recipient, wrapped_key_b64: wrappedKey_b64, permissions: "read" }, ctx.accessToken)
      if (alive.current) { setSharedUsers(previous => [...previous, recipient]); setEmail("") }
    } catch (err) { if (alive.current) setError(errorMessage(err, "Failed to share file.")) }
    finally { busy.current = false; if (alive.current) setAdding(false) }
  }
  async function removeUser(recipient: string) {
    if (busy.current || !confirm(`Revoke access for ${recipient}?`)) return
    busy.current = true; setRemoving(recipient); setError(null)
    try {
      const ctx = getVaultXContext()
      if (!ctx.accessToken) throw new Error("Not logged in")
      await api.post("/shares/revoke", { file_id: file.id, recipient_email: recipient }, ctx.accessToken)
      if (alive.current) setSharedUsers(previous => previous.filter(item => item !== recipient))
    } catch (err) { if (alive.current) setError(errorMessage(err, "Failed to revoke access.")) }
    finally { busy.current = false; if (alive.current) setRemoving(null) }
  }
  return <section className="space-y-3">
    <form onSubmit={addUser} className="space-y-2">
      <Label htmlFor="share-email" className="text-sm font-medium">Add people</Label>
      <div className="flex flex-wrap gap-2"><Input id="share-email" type="email" placeholder="Email address" value={email} onChange={e => setEmail(e.target.value)} required disabled={adding} className="min-h-11 min-w-0 flex-1 basis-48 shadow-none" /><Button type="submit" disabled={adding || !!removing || !email.trim()} className="min-h-11 shadow-none">{adding ? <Loader2 className="size-4 animate-spin" /> : <UserPlus className="size-4" />}{adding ? "Adding…" : "Add"}</Button></div>
    </form>
    {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    {sharedUsers.length > 0 && <ul className="space-y-2">{sharedUsers.map(recipient => <li key={recipient} className="flex items-center justify-between gap-2 rounded-md border border-border p-2"><div className="min-w-0"><p className="truncate text-sm">{recipient}</p><p className="text-xs text-muted-foreground">Read only</p></div><Button type="button" variant="ghost" className="min-h-11 min-w-11 shrink-0 text-muted-foreground hover:text-destructive" aria-label={`Revoke access for ${recipient}`} disabled={adding || !!removing} onClick={() => removeUser(recipient)}>{removing === recipient ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}</Button></li>)}</ul>}
  </section>
}

export function ShareModal({ open, onOpenChange, file }: ShareModalProps) {
  if (!file) return null
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent className="max-h-[90dvh] overflow-y-auto border border-border bg-background p-4 text-foreground shadow-none sm:max-w-xl sm:p-6 [&>button]:min-h-11 [&>button]:min-w-11">
      <DialogHeader className="pr-9 text-left">
        <DialogTitle className="flex min-w-0 items-start gap-2 text-left"><Share2 className="mt-0.5 size-5 shrink-0 text-emerald-600 dark:text-emerald-400" /><span className="break-all">Share “{file.name}”</span></DialogTitle>
        <DialogDescription className="text-left">Grant read access to people or generate a guest link.</DialogDescription>
      </DialogHeader>
      {open && <div key={file.id} className="min-w-0 space-y-5"><PeopleAccess file={file} /><GuestLinkPanel fileId={file.id} /></div>}
      <div className="flex justify-end border-t border-border pt-4"><Button className="min-h-11 min-w-24 shadow-none" onClick={() => onOpenChange(false)}>Done</Button></div>
    </DialogContent>
  </Dialog>
}
