"use client"

import { useId, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { createOtpGate, normalizeOtp } from "@/lib/auth-ui"

type OtpDeckProps = {
  value: string
  onChange: (code: string) => void
  onVerify: (code: string) => Promise<void>
  busy?: boolean
  error?: string | null
  autoSubmit?: boolean
  autoFocus?: boolean
  label?: string
  actionLabel?: string
}

export function OtpDeck({ value, onChange, onVerify, busy = false, error, autoSubmit = true, autoFocus = false, label = "Authenticator code", actionLabel = "Verify code" }: OtpDeckProps) {
  const id = useId()
  const input = useRef<HTMLInputElement>(null)
  const gate = useRef(createOtpGate())
  const [pending, setPending] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const [focused, setFocused] = useState(false)
  const [position, setPosition] = useState(0)
  const working = busy || pending
  const message = error || localError

  async function verify(code: string, automatic: boolean) {
    if (working) return
    if (code.length !== 6) {
      setLocalError("Enter all six digits from your authenticator app.")
      input.current?.focus()
      return
    }
    try {
      await gate.current.run(code, automatic, async (next) => {
        setPending(true)
        setLocalError(null)
        try { await onVerify(next) } finally { setPending(false) }
      })
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : "Verification failed. Please try again.")
    }
  }

  function change(raw: string) {
    const next = normalizeOtp(raw)
    gate.current.changed(next)
    onChange(next)
    setPosition(Math.min(next.length, 5))
    setLocalError(null)
    if (autoSubmit && next.length === 6) void verify(next, true)
  }

  return (
    <div className="space-y-3" aria-busy={working}>
      <label htmlFor={id} className="text-sm font-medium text-foreground">{label}</label>
      <div className="relative">
        <div aria-hidden="true" className="grid grid-cols-6 gap-2">
          {Array.from({ length: 6 }, (_, index) => (
            <div key={index} className={`flex h-14 min-w-0 items-center justify-center rounded-lg border bg-background font-mono text-2xl text-foreground transition-colors duration-150 ease-[cubic-bezier(0.2,0,0,1)] motion-reduce:transition-none ${message ? "border-destructive" : focused && index === position ? "border-ring ring-2 ring-ring/30" : "border-border"}`}>
              {value[index] || <span className="h-1 w-1 rounded-full bg-muted-foreground/40" />}
            </div>
          ))}
        </div>
        <input ref={input} id={id} type="text" inputMode="numeric" autoComplete="one-time-code" autoFocus={autoFocus}
          value={value} readOnly={working} aria-invalid={!!message} aria-describedby={`${id}-hint ${id}-status`}
          aria-label={label} className="absolute inset-0 h-full w-full cursor-text opacity-0"
          onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
          onSelect={(event) => setPosition(Math.min(event.currentTarget.selectionStart ?? value.length, 5))}
          onChange={(event) => change(event.target.value)}
          onPaste={(event) => { event.preventDefault(); if (!working) change(event.clipboardData.getData("text")) }}
          onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void verify(value, false) } }} />
      </div>
      <p id={`${id}-hint`} className="text-xs leading-relaxed text-muted-foreground">
        {autoSubmit ? "Verifies automatically after six digits. You can also use the button below to verify or retry." : "Enter six digits, then use the button below to confirm."}
      </p>
      <p id={`${id}-status`} role="status" aria-live="polite" className={`min-h-5 text-sm ${message ? "text-destructive" : "text-muted-foreground"}`}>
        {working ? "Verifying your code…" : message || "You can paste a code from your authenticator."}
      </p>
      <Button type="button" className="min-h-11 w-full" disabled={working} onClick={() => void verify(value, false)}>
        {working ? "Verifying…" : actionLabel}
      </Button>
    </div>
  )
}
