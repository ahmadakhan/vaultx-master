"use client"

import { useEffect, useRef, useState } from "react"
import { Check, Copy, Link2, Loader2, ShieldCheck, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"
import { getSessionContext, memorySession } from "@/lib/crypto/context"
import { encryptWithPassphrase } from "@/lib/crypto/passphrase"
import { generateFileKey } from "@/lib/crypto/keys"
import { errorMessage } from "@/lib/types"
import { copyGuestLink, guestLinkPayload, guestLinkStatus, MAX_GUEST_DOWNLOADS, type GuestLinkOptions } from "@/lib/guest-link"

interface GuestLink {
  id: string; file_id: string; token: string; has_access_code: boolean
  expires_at: string | null; max_downloads: number | null; download_count: number
  created_at: string; link_url?: string
}

const initialOptions: GuestLinkOptions = {
  expiryEnabled: true,
  expiryPreset: "1day",
  customExpiry: "",
  downloadsEnabled: false,
  maxDownloads: "1",
  codeEnabled: false,
  accessCode: "",
}
const motion = "min-h-11 shadow-none transition-colors duration-[180ms] ease-[cubic-bezier(0.2,0,0,1)] motion-reduce:transition-none"

function GuestLinkRow({ link, revoke }: { link: GuestLink; revoke: (link: GuestLink) => Promise<void> }) {
  const field = useRef<HTMLInputElement>(null)
  const busy = useRef(false)
  const alive = useRef(true)
  const [revoking, setRevoking] = useState(false)
  const [copying, setCopying] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    alive.current = true
    return () => { alive.current = false }
  }, [])

  async function copy() {
    if (!link.link_url || busy.current) return
    busy.current = true
    setCopying(true)
    setError(null)
    const success = await copyGuestLink(link.link_url, value => navigator.clipboard.writeText(value), () => {
      field.current?.focus(); field.current?.select()
    })
    busy.current = false
    if (!alive.current) return
    setCopying(false)
    setCopied(success)
    if (!success) setError("Clipboard unavailable. The complete link is selected; copy it manually (Ctrl+C or ⌘C).")
  }

  async function remove() {
    if (busy.current) return
    busy.current = true
    setRevoking(true)
    setError(null)
    try { await revoke(link) }
    catch (err) { if (alive.current) setError(errorMessage(err, "Could not revoke this link. Try again.")) }
    finally { busy.current = false; if (alive.current) setRevoking(false) }
  }

  return (
    <li className="space-y-3 rounded-xl border border-border bg-background/70 p-3 shadow-none">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="flex items-center gap-2 font-medium text-foreground"><Link2 className="size-4" />Guest link · {guestLinkStatus(link)}</span>
        <span className="rounded-full border border-border bg-muted/30 px-2 py-1 text-muted-foreground">{link.download_count}{link.max_downloads !== null ? ` / ${link.max_downloads}` : ""} downloads</span>
      </div>

      {link.link_url ? (
        <div className="space-y-1.5">
          <label htmlFor={`guest-url-${link.id}`} className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">Complete guest URL</label>
          <Input ref={field} id={`guest-url-${link.id}`} value={link.link_url} readOnly onFocus={event => event.target.select()} className={`${motion} font-mono text-xs`} />
        </div>
      ) : (
        <p className="text-xs leading-relaxed text-muted-foreground">The decryption secret is unavailable in this session. Use your saved complete link, or revoke and create a new one.</p>
      )}

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>{link.expires_at ? `Expires ${new Date(link.expires_at).toLocaleString()}` : "No expiration"}</span>
        <span>{link.has_access_code ? "Access code required" : "No access code"}</span>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" className={`${motion} flex-1`} disabled={!link.link_url || copying || revoking} onClick={copy}>
          {copying ? <Loader2 className="size-4 animate-spin" /> : copied ? <Check className="size-4 text-emerald-600 dark:text-emerald-400" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Secure copy"}
        </Button>
        <Button type="button" variant="outline" className={`${motion} text-destructive`} disabled={revoking || copying} onClick={remove} aria-label="Revoke this guest link">
          {revoking ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
          {revoking ? "Revoking…" : "Revoke"}
        </Button>
      </div>
      <span role="status" className="sr-only">{copied ? "Complete guest link copied" : ""}</span>
      {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    </li>
  )
}

export function GuestLinkPanel({ fileId }: { fileId: string }) {
  const [links, setLinks] = useState<GuestLink[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [retry, setRetry] = useState(0)
  const [options, setOptions] = useState(initialOptions)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const alive = useRef(false)
  const creationLock = useRef(false)
  const token = getSessionContext()?.accessToken

  useEffect(() => {
    alive.current = true
    return () => { alive.current = false }
  }, [])

  useEffect(() => {
    let current = true
    setLoading(true); setLoadError(null)
    if (!token) { setLoading(false); setLoadError("Sign in to manage guest links."); return }
    api.get(`/shares/links/${fileId}`, token).then(res => {
      if (!current) return
      const data = res.links || res || []
      if (!Array.isArray(data)) throw new Error("Unexpected link response. Please retry.")
      setLinks(data.filter((link: GuestLink) => link.file_id === fileId).map((link: GuestLink) => ({
        ...link, link_url: memorySession.getItem(`vaultx_link_${link.token}`) || undefined,
      })))
    }).catch(err => { if (current) setLoadError(errorMessage(err, "Could not load guest links.")) })
      .finally(() => { if (current) setLoading(false) })
    return () => { current = false }
  }, [fileId, token, retry])

  function update<K extends keyof GuestLinkOptions>(key: K, value: GuestLinkOptions[K]) {
    setOptions(previous => ({ ...previous, [key]: value })); setError(null)
  }

  async function create(event: React.FormEvent) {
    event.preventDefault()
    if (creationLock.current || !token || loading || loadError) return
    creationLock.current = true; setCreating(true); setError(null); setSuccess(null)
    try {
      const payload = guestLinkPayload(options)
      const fileKeyB64 = memorySession.getItem(`vaultx_kf_${fileId}`)
      if (!fileKeyB64) throw new Error("This file's encryption key is not loaded yet. Wait for the file list to finish loading (or download the file once), then try again.")
      const secret = await generateFileKey()
      const wrapped = await encryptWithPassphrase(fileKeyB64, secret)
      if (!alive.current) return
      const data = await api.post("/shares/link", {
        file_id: fileId, ...payload,
        encrypted_kf_b64: wrapped.ciphertext_b64,
        encrypted_kf_iv_b64: wrapped.iv_b64, kf_salt_b64: wrapped.salt_b64,
      }, token)
      const newLink: GuestLink = { ...data, link_url: `${window.location.origin}/shared/${data.token}#key=${encodeURIComponent(secret)}` }
      if (getSessionContext()?.accessToken !== token) return
      memorySession.setItem(`vaultx_link_${data.token}`, newLink.link_url!)
      if (!alive.current) return
      setLinks(previous => [newLink, ...previous]); setOptions(initialOptions)
      setSuccess("Link created. Copy the complete URL now; its decryption secret cannot be recovered after logout or reload.")
    } catch (err) { if (alive.current) setError(errorMessage(err, "Could not create the guest link.")) }
    finally { creationLock.current = false; if (alive.current) setCreating(false) }
  }

  async function revoke(link: GuestLink) {
    if (!token) throw new Error("Sign in to revoke this link.")
    await api.delete(`/shares/link/${link.id}?file_id=${fileId}`, token)
    memorySession.removeItem(`vaultx_link_${link.token}`)
    if (alive.current) setLinks(previous => previous.filter(item => item.id !== link.id))
  }

  return (
    <section className="space-y-4 border-t border-border pt-4" aria-labelledby="guest-links-title">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/5">
          <ShieldCheck className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
        </div>
        <div>
          <h3 id="guest-links-title" className="text-sm font-semibold text-foreground">Guest links</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">Share encrypted files without an account. Anyone with the complete URL and any required access code can download.</p>
        </div>
      </div>

      <form onSubmit={create} className="space-y-3 rounded-xl border border-border bg-muted/20 p-3 shadow-none">
        <fieldset disabled={creating} className="space-y-3">
          <legend className="sr-only">Guest link controls</legend>

          <label className="flex min-h-11 cursor-pointer items-center justify-between gap-3 text-sm font-medium text-foreground" htmlFor="guest-expiry">
            <span>Expiration</span>
            <input id="guest-expiry" type="checkbox" role="switch" className="size-5 accent-emerald-600" checked={options.expiryEnabled} onChange={e => update("expiryEnabled", e.target.checked)} />
          </label>

          {options.expiryEnabled && (
            <div className="space-y-2">
              <label htmlFor="guest-expiry-preset" className="sr-only">Expiration period</label>
              <select id="guest-expiry-preset" value={options.expiryPreset} onChange={e => update("expiryPreset", e.target.value as GuestLinkOptions["expiryPreset"])} className={`${motion} w-full rounded-md border border-border bg-background px-3 text-sm focus-visible:outline-2 focus-visible:outline-ring`}>
                <option value="1h">In 1 hour</option>
                <option value="1day">In 1 day</option>
                <option value="custom">Custom date & time</option>
              </select>
              {options.expiryPreset === "custom" && (
                <div className="space-y-1.5">
                  <label htmlFor="guest-custom-expiry" className="text-xs text-muted-foreground">Future date & time (your local timezone)</label>
                  <Input id="guest-custom-expiry" type="datetime-local" required value={options.customExpiry} onChange={e => update("customExpiry", e.target.value)} className={motion} />
                </div>
              )}
            </div>
          )}

          <div className="border-t border-border pt-3">
            <label htmlFor="guest-limit" className="flex min-h-11 cursor-pointer items-center justify-between gap-3 text-sm font-medium text-foreground">
              <span>Maximum downloads</span>
              <input id="guest-limit" type="checkbox" role="switch" className="size-5 accent-emerald-600" checked={options.downloadsEnabled} onChange={e => update("downloadsEnabled", e.target.checked)} />
            </label>
            {options.downloadsEnabled ? (
              <div className="mt-2 space-y-1.5">
                <label htmlFor="guest-downloads" className="text-xs text-muted-foreground">Allowed downloads (1–2,147,483,647)</label>
                <Input id="guest-downloads" type="number" min={1} max={MAX_GUEST_DOWNLOADS} step={1} required value={options.maxDownloads} onChange={e => update("maxDownloads", e.target.value)} className={motion} />
              </div>
            ) : (
              <p className="mt-2 text-xs text-muted-foreground">No download limit</p>
            )}
          </div>

          <div className="border-t border-border pt-3">
            <label htmlFor="guest-code-toggle" className="flex min-h-11 cursor-pointer items-center justify-between gap-3 text-sm font-medium text-foreground">
              <span>Require access code</span>
              <input id="guest-code-toggle" type="checkbox" role="switch" className="size-5 accent-emerald-600" checked={options.codeEnabled} onChange={e => update("codeEnabled", e.target.checked)} />
            </label>
            {options.codeEnabled && (
              <div className="mt-2 space-y-1.5">
                <label htmlFor="guest-code" className="text-xs text-muted-foreground">Access code (4–12 characters)</label>
                <Input id="guest-code" type="password" autoComplete="new-password" required value={options.accessCode} onChange={e => update("accessCode", e.target.value)} className={motion} />
                <p className="text-xs leading-relaxed text-muted-foreground">Checked by the server before access. Share this code separately; it does not replace the URL’s decryption secret.</p>
              </div>
            )}
          </div>
        </fieldset>

        {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
        <Button type="submit" disabled={creating || loading || !!loadError || !token} className={`${motion} w-full`}>
          {creating ? <Loader2 className="size-4 animate-spin" /> : <Link2 className="size-4" />}
          {creating ? "Creating guest link…" : "Generate guest link"}
        </Button>
      </form>

      {success && <p role="status" className="rounded-md border border-emerald-600/30 bg-emerald-500/5 p-3 text-xs leading-relaxed text-foreground">{success}</p>}

      {loading ? (
        <p role="status" className="flex items-center gap-2 py-3 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Loading guest links…</p>
      ) : loadError ? (
        <div role="alert" className="space-y-2">
          <p className="text-sm text-destructive">{loadError}</p>
          <Button type="button" variant="outline" className={motion} onClick={() => setRetry(value => value + 1)}>Retry loading links</Button>
        </div>
      ) : links.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">No guest links yet. Generate one with the controls above.</p>
      ) : (
        <div className="space-y-2">
          <h4 className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">Guest links · {links.length}</h4>
          <ul className="space-y-3">{links.map(link => <GuestLinkRow key={link.id} link={link} revoke={revoke} />)}</ul>
        </div>
      )}
    </section>
  )
}
