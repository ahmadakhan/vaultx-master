"use client"

import { useState, useEffect } from "react"
import { Share2, Trash2, Mail, Check, Loader2, Link as LinkIcon, Copy, QrCode, Shield } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { getVaultXContext } from "@/lib/crypto/context"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/types"
import { bufToB64, b64ToBuf } from "@/lib/crypto/base"
import { deriveAesKeyFromPassphrase, encryptWithPassphrase, genSalt, shareLinkPassphrase } from "@/lib/crypto/passphrase"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

interface FileItem {
  id: string
  name: string
  type: "file" | "folder"
  fileType?: string
  size: string
  modified: string
  owner: string
  shared: boolean
  shared_with?: string[]
}

interface ShareLinkData {
  id: string
  file_id: string
  token: string
  has_access_code: boolean
  expires_at: string | null
  max_downloads: number | null
  download_count: number
  created_at: string
  link_url?: string
}

interface ShareModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  file: FileItem | null
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----.*-----/g, "").replace(/\s+/g, "")
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

export function ShareModal({ open, onOpenChange, file }: ShareModalProps) {
  const [email, setEmail] = useState("")
  const [sharedUsers, setSharedUsers] = useState<string[]>([])
  const [isAdding, setIsAdding] = useState(false)
  const [addingError, setAddingError] = useState<string | null>(null)
  const [links, setLinks] = useState<ShareLinkData[]>([])
  const [linksLoading, setLinksLoading] = useState(false)
  const [showLinkForm, setShowLinkForm] = useState(false)
  const [accessCode, setAccessCode] = useState("")
  const [expiresHours, setExpiresHours] = useState<string>("24")
  const [maxDownloads, setMaxDownloads] = useState<string>("0")
  const [creatingLink, setCreatingLink] = useState(false)
  const [linkError, setLinkError] = useState<string | null>(null)
  const [linkSuccess, setLinkSuccess] = useState<string | null>(null)

  const ctx = getVaultXContext()

  useEffect(() => {
    if (file?.id) {
      loadLinks()
    }
  }, [file])

  const loadLinks = async () => {
    if (!file || !ctx.accessToken) return
    setLinksLoading(true)
    try {
      const res = await api.get(`/shares/links/${file.id}`, ctx.accessToken)
      setLinks(res.links || res || [])
    } catch (err) {
      console.error("Failed to load links:", err)
    } finally {
      setLinksLoading(false)
    }
  }

  const createLink = async () => {
    if (!file || !ctx.accessToken) return

    setCreatingLink(true)
    setLinkError(null)
    setLinkSuccess(null)
    try {
      let expiresAt = null
      if (expiresHours !== "never") {
        const date = new Date(Date.now() + parseInt(expiresHours) * 60 * 60 * 1000)
        expiresAt = date.toISOString()
      }

      let encryptedKfB64: string | null = null
      let encryptedKfIvB64: string | null = null
      let kfSaltB64: string | null = null
      const fileKeyB64 = ctx.masterKey_b64 ? sessionStorage.getItem(`vaultx_kf_${file.id}`) : null
      const useAccessCode = !!accessCode
      if (!fileKeyB64) {
        // Refuse to create a link with no key material: guests could never
        // decrypt the file, yet the UI would claim success.
        throw new Error(
          "This file's encryption key is not loaded yet. Wait for the file list to finish loading (or download the file once), then try again."
        )
      }
      if (useAccessCode) {
        const { ciphertext_b64, iv_b64, salt_b64 } = await encryptWithPassphrase(
          fileKeyB64, accessCode
        )
        encryptedKfB64 = ciphertext_b64
        encryptedKfIvB64 = iv_b64
        kfSaltB64 = salt_b64
      } else {
        // Must match the guest page's derivation exactly (shared helper).
        const tokenPass = shareLinkPassphrase(file.id)
        const salt = genSalt()
        const key = await deriveAesKeyFromPassphrase(tokenPass, bufToB64(salt))
        const iv = new Uint8Array(12)
        crypto.getRandomValues(iv)
        const fileKeyBuf = b64ToBuf(fileKeyB64)
        const ct = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          fileKeyBuf,
        )
        encryptedKfB64 = bufToB64(ct)
        encryptedKfIvB64 = bufToB64(iv.buffer)
        kfSaltB64 = bufToB64(salt)
      }

      const res = await api.post(
        "/shares/link",
        {
          file_id: file.id,
          access_code: accessCode || undefined,
          expires_at: expiresAt,
          max_downloads: maxDownloads === "0" ? null : parseInt(maxDownloads),
          encrypted_kf_b64: encryptedKfB64,
          encrypted_kf_iv_b64: encryptedKfIvB64,
          kf_salt_b64: kfSaltB64,
        },
        ctx.accessToken
      )
      const data = res
      const newLink = {
        id: data.id,
        file_id: data.file_id,
        token: data.token,
        has_access_code: data.has_access_code,
        expires_at: data.expires_at,
        max_downloads: data.max_downloads,
        download_count: data.download_count,
        created_at: data.created_at,
        link_url: `${window.location.origin}/shared/${data.token}`,
      }
      setLinks([newLink, ...links])
      setLinkSuccess("Shareable link created!")
      setShowLinkForm(false)
      setAccessCode("")
      setExpiresHours("24")
      setMaxDownloads("0")
    } catch (err) {
      setLinkError(errorMessage(err, "Failed to create link."))
    } finally {
      setCreatingLink(false)
    }
  }

  const revokeLink = async (linkId: string) => {
    if (!file || !ctx.accessToken) return
    try {
      await api.delete(`/shares/link/${linkId}?file_id=${file.id}`, ctx.accessToken)
      setLinks(links.filter((l) => l.id !== linkId))
    } catch (err) {
      console.error("Failed to revoke link:", err)
    }
  }

  const copyLink = (url: string) => {
    navigator.clipboard.writeText(url)
    setLinkSuccess("Link copied to clipboard!")
  }

  if (!file) return null

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmedEmail = email.trim().toLowerCase()
    if (!trimmedEmail) return
    if (sharedUsers.includes(trimmedEmail)) {
      setAddingError("This user already has access.")
      return
    }

    setIsAdding(true)
    setAddingError(null)
    try {
      const ctx = getVaultXContext()
      if (!ctx.accessToken) throw new Error("Not logged in")

      const { public_key_pem } = await api.get(
        `/auth/public-key/${trimmedEmail}`,
        ctx.accessToken
      )
      const pubKey = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(public_key_pem),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      )

      const fileKey_b64 = sessionStorage.getItem(`vaultx_kf_${file.id}`)
      if (!fileKey_b64) throw new Error("Missing file encryption key (Kf)")

      const fileKeyBytes = Uint8Array.from(atob(fileKey_b64), (c) => c.charCodeAt(0))

      const wrappedKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        pubKey,
        fileKeyBytes
      )
      const wrappedKey_b64 = btoa(String.fromCharCode(...new Uint8Array(wrappedKey)))

      await api.post(
        "/shares",
        {
          file_id: file.id,
          recipient_email: trimmedEmail,
          wrapped_key_b64: wrappedKey_b64,
          permissions: "read",
        },
        ctx.accessToken
      )

      setSharedUsers((prev) => [...prev, trimmedEmail])
      setEmail("")
    } catch (err) {
      console.error("Share failed:", err)
      setAddingError(errorMessage(err, "Failed to share file."))
    } finally {
      setIsAdding(false)
    }
  }

  const handleRemoveUser = async (userEmail: string) => {
    if (!confirm(`Revoke access for ${userEmail}?`)) return

    try {
      const ctx = getVaultXContext()
      if (!ctx.accessToken) throw new Error("Not logged in")

      await api.post(
        "/shares/revoke",
        { file_id: file.id, recipient_email: userEmail },
        ctx.accessToken
      )

      setSharedUsers((prev) => prev.filter((e) => e !== userEmail))
    } catch (err) {
      console.error("Revoke failed:", err)
      alert(errorMessage(err, "Failed to revoke access."))
    }
  }

  const userInitial = (email: string) => email.charAt(0).toUpperCase()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-border shadow-xl">
        <DialogHeader className="flex flex-row items-start gap-4 pb-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <Share2 className="h-5 w-5 text-primary" strokeWidth={1.5} />
          </div>
          <div>
            <DialogTitle className="text-left">Share &ldquo;{file.name}&rdquo;</DialogTitle>
            <DialogDescription className="text-left">
              Add people by email. They will receive an encrypted link.
            </DialogDescription>
          </div>
        </DialogHeader>

        <div className="mt-4 space-y-5">
          <div>
            <Label htmlFor="share-email" className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground">
              Add people
            </Label>
            <form onSubmit={handleAddUser} className="mt-2 flex gap-2">
              <div className="relative flex-1">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
                <Input
                  id="share-email"
                  type="email"
                  placeholder="Enter email address"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setAddingError(null)}
                  className="h-10 pl-10 border-border focus:border-ring"
                  required
                  disabled={isAdding}
                />
              </div>
              <Button type="submit" size="sm" disabled={isAdding || !email.trim()}>
                {isAdding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              </Button>
            </form>
            {addingError && (
              <p className="mt-2 text-xs text-destructive">{addingError}</p>
            )}
          </div>

           {sharedUsers.length > 0 && (
             <div>
               <p className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground mb-2">
                 People with access
               </p>
               <div className="space-y-2">
                 {sharedUsers.map((userEmail) => (
                   <div
                     key={userEmail}
                     className="flex items-center justify-between rounded-md border border-border p-2.5 bg-muted/20"
                   >
                     <div className="flex items-center gap-3 min-w-0">
                       <Avatar className="h-8 w-8">
                         <AvatarFallback className="bg-primary/10 text-primary">
                           {userInitial(userEmail)}
                         </AvatarFallback>
                       </Avatar>
                       <div className="min-w-0">
                         <p className="text-sm font-medium text-foreground truncate">
                           {userEmail}
                         </p>
                         <Badge
                           variant="secondary"
                           className="text-xs border-border text-muted-foreground"
                         >
                           read only
                         </Badge>
                       </div>
                     </div>
                     <Button
                       variant="ghost"
                       size="sm"
                       className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                       onClick={() => handleRemoveUser(userEmail)}
                     >
                       <Trash2 className="w-4 h-4" strokeWidth={1.5} />
                       <span className="sr-only">Revoke</span>
                     </Button>
                   </div>
                 ))}
               </div>
             </div>
           )}
         </div>

         <div className="pt-4 border-t border-border">
           <div className="flex items-center justify-between mb-3">
             <h3 className="text-sm font-medium">Shareable Link</h3>
             <Button
               variant="ghost"
               size="sm"
               onClick={() => setShowLinkForm(!showLinkForm)}
               className="text-xs"
             >
               {showLinkForm ? "Cancel" : "Create Link"}
             </Button>
           </div>

           {showLinkForm && (
             <div className="space-y-3 mb-3">
               <div className="space-y-2">
                 <Label className="text-xs text-muted-foreground">Access Code (optional)</Label>
                 <div className="relative">
                   <Shield className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
                   <Input
                     type="password"
                     placeholder="Enter access code..."
                     value={accessCode}
                     onChange={(e) => setAccessCode(e.target.value)}
                     className="h-9 pl-10 border-border"
                   />
                 </div>
               </div>
               <div className="grid grid-cols-2 gap-3">
                 <div className="space-y-2">
                   <Label className="text-xs text-muted-foreground">Expires</Label>
                   <Select value={expiresHours} onValueChange={setExpiresHours}>
                     <SelectTrigger className="h-9 border-border">
                       <SelectValue />
                     </SelectTrigger>
                     <SelectContent>
                       <SelectItem value="1">1 hour</SelectItem>
                       <SelectItem value="24">24 hours</SelectItem>
                       <SelectItem value="168">7 days</SelectItem>
                       <SelectItem value="720">30 days</SelectItem>
                       <SelectItem value="never">Never</SelectItem>
                     </SelectContent>
                   </Select>
                 </div>
                 <div className="space-y-2">
                   <Label className="text-xs text-muted-foreground">Max Downloads</Label>
                   <Input
                     type="number"
                     min="0"
                     placeholder="0 = unlimited"
                     value={maxDownloads}
                     onChange={(e) => setMaxDownloads(e.target.value)}
                     className="h-9 border-border"
                   />
                 </div>
               </div>
               {linkError && <p className="text-xs text-destructive">{linkError}</p>}
               {linkSuccess && <p className="text-xs text-green-500">{linkSuccess}</p>}
               <Button
                 size="sm"
                 className="w-full"
                 disabled={creatingLink || isAdding}
                 onClick={createLink}
               >
                 {creatingLink ? (
                   <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating...</>
                 ) : (
                   "Create Link"
                 )}
               </Button>
             </div>
           )}

           {links.length > 0 && (
             <div className="space-y-2">
               <p className="text-xs font-medium uppercase tracking-[0.05em] text-muted-foreground">
                 Active Links
               </p>
               {links.map((link) => (
                 <div key={link.id} className="rounded-md border border-border p-3 space-y-2">
                   <div className="flex items-center justify-between">
                     <div className="flex items-center gap-2">
                       <LinkIcon className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
                       <span className="text-sm font-mono truncate max-w-[200px]">
                         {link.token.substring(0, 8)}...
                       </span>
                     </div>
                     <div className="flex gap-1">
                       {link.link_url && (
                         <Tooltip>
                           <TooltipTrigger asChild>
                             <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                               <Copy className="w-3 h-3" strokeWidth={1.5} onClick={() => copyLink(link.link_url!)} />
                             </Button>
                           </TooltipTrigger>
                           <TooltipContent>Copy link</TooltipContent>
                         </Tooltip>
                       )}
                       <Tooltip>
                         <TooltipTrigger asChild>
                           <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => revokeLink(link.id)}>
                             <Trash2 className="w-3 h-3" strokeWidth={1.5} />
                           </Button>
                         </TooltipTrigger>
                         <TooltipContent>Revoke link</TooltipContent>
                       </Tooltip>
                     </div>
                   </div>
                   <div className="flex gap-4 text-xs text-muted-foreground">
                     {link.has_access_code && <span><Shield className="w-3 h-3 inline mr-1" />Access code protected</span>}
                     {link.expires_at && <span>Expires: {new Date(link.expires_at).toLocaleDateString()}</span>}
                     {link.max_downloads !== null && <span>{link.download_count}/{link.max_downloads} downloads</span>}
                   </div>
                 </div>
               ))}
             </div>
           )}
         </div>

        <div className="pt-4 border-t border-border flex justify-end">
          <Button onClick={() => onOpenChange(false)} className="min-w-[80px]">
            Done
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
