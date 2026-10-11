"use client"

import { useEffect, useRef, useState } from "react"
import { KeyRound } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { verifyPasskey, type PasskeyState, type PasskeyVerificationAdapter } from "@/lib/auth-ui"

export function PasskeyGateway({ adapter }: { adapter?: PasskeyVerificationAdapter }) {
  const [state, setState] = useState<PasskeyState>(adapter ? "idle" : "unsupported")
  const [error, setError] = useState("")
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => { request.current?.abort() }, [])
  const supported = !!adapter && typeof window !== "undefined" && !!window.PublicKeyCredential

  function cancel() {
    request.current?.abort()
    request.current = null
    setState("cancel")
  }
  async function verify() {
    if (!adapter || !supported) { setState("unsupported"); return }
    if (request.current) return
    const controller = new AbortController()
    request.current = controller
    setState("verifying")
    setError("")
    try {
      await verifyPasskey(adapter, controller.signal)
      if (request.current === controller) setState("success")
    } catch (err) {
      if (request.current !== controller) return
      if (controller.signal.aborted || (err instanceof DOMException && ["AbortError", "NotAllowedError"].includes(err.name))) setState("cancel")
      else { setState("error"); setError(err instanceof Error ? err.message : "Passkey verification failed.") }
    } finally { if (request.current === controller) request.current = null }
  }

  return (
    <section className="rounded-xl border border-border bg-card p-6 space-y-3" aria-label="Passkeys">
      <h3 className="flex items-center gap-2 font-semibold"><KeyRound aria-hidden="true" className="size-5" />Passkeys</h3>
      {!adapter ? <p className="text-sm text-muted-foreground">Unavailable on this server. Passkey verification is not configured. Continue using your password and authenticator code.</p> : (
        <Dialog onOpenChange={(open) => { if (!open) cancel(); else setState(supported ? "idle" : "unsupported") }}>
          <DialogTrigger asChild><Button variant="outline" className="min-h-11">Verify with a passkey</Button></DialogTrigger>
          <DialogContent className="shadow-none" showCloseButton={false}>
            <DialogHeader><DialogTitle>Verify with your passkey</DialogTitle><DialogDescription>Your device may ask for a PIN, a security key, or biometrics. Verification is completed by the server.</DialogDescription></DialogHeader>
            <p role="status" aria-live="polite" className="text-sm">
              {state === "verifying" ? "Waiting for your device and server…" : state === "success" ? "Passkey verified by the server." : state === "error" ? error : state === "cancel" ? "Verification cancelled. You can try again." : state === "unsupported" ? "Passkeys are not supported in this browser or server configuration." : "Ready when you are."}
            </p>
            <Button className="min-h-11" disabled={state === "verifying" || state === "success" || state === "unsupported"} onClick={() => void verify()}>{state === "error" || state === "cancel" ? "Try again" : "Continue"}</Button>
            <Button variant="outline" className="min-h-11" onClick={cancel}>Cancel verification</Button>
            <DialogClose asChild><Button variant="ghost" className="min-h-11">Close</Button></DialogClose>
          </DialogContent>
        </Dialog>
      )}
    </section>
  )
}
