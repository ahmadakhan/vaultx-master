"use client"
import { memorySession } from "@/lib/crypto/context"

import { useState, useEffect, useRef } from "react"
import Image from "next/image"
import { BadgeCheck, Copy, Loader2, Shield, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"
import { OtpDeck } from "@/components/otp-deck"
import { PasskeyGateway } from "@/components/passkey-gateway"

export function MfaSettings() {
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [step, setStep] = useState<"check" | "setup" | "verify">("check")
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null)
  const [secret, setSecret] = useState<string | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [backupCodesVisible, setBackupCodesVisible] = useState(false)
  const [verificationCode, setVerificationCode] = useState("")
  const [useBackupCode, setUseBackupCode] = useState(false)
  const [backupRemaining, setBackupRemaining] = useState<number | null>(null)

  const requestBusy = useRef(false)

  useEffect(() => {
    void loadMfaStatus()
  }, [])

  const loadMfaStatus = async () => {
    setLoading(true)
    try {
      const t = memorySession.getItem("vaultx_access_token") || undefined
      const res = await api.get("/auth/mfa/status", t)
      setMfaEnabled(res.mfa_enabled)
      setBackupRemaining(res.backup_codes_remaining ?? null)
      setStep("check")
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load MFA status")
    } finally {
      setLoading(false)
    }
  }

  const beginMfaSetup = async () => {
    if (requestBusy.current || loading) return
    requestBusy.current = true
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const t = memorySession.getItem("vaultx_access_token") || undefined
      const res = await api.post("/auth/mfa/setup", {}, t, true)
      const data = res
      setQrCodeUrl(data.qr_code_url)
      setSecret(data.secret)
      setBackupCodes(data.backup_codes || [])
      setBackupCodesVisible(false)
      setStep("verify")
      setSuccess("Scan the QR code above with your authenticator app, then enter the 6-digit code.")
      setVerificationCode("")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set up MFA")
    } finally {
      requestBusy.current = false
      setLoading(false)
    }
  }

  const verifyAndEnable = async (code: string) => {
    if (requestBusy.current || loading) return
    if (!/^\d{6}$/.test(code)) {
      setError("Please enter a valid 6-digit code from your authenticator app.")
      return
    }
    requestBusy.current = true
    setLoading(true)
    setError(null)
    try {
      const t = memorySession.getItem("vaultx_access_token") || undefined
      await api.post("/auth/mfa/enable", { code }, t)
      setSuccess("MFA has been successfully enabled.")
      setMfaEnabled(true)
      setStep("check")
      setVerificationCode("")
      await loadMfaStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed. Please check the code and try again.")
    } finally {
      requestBusy.current = false
      setLoading(false)
    }
  }

  const disableMfa = async (code: string) => {
    if (requestBusy.current || loading) return
    if (!code) {
      setError(useBackupCode ? "Please enter a backup code." : "Please enter your current 6-digit code to disable MFA.")
      return
    }
    if (!useBackupCode && !/^\d{6}$/.test(code)) {
      setError("Please enter a valid 6-digit code from your authenticator app.")
      return
    }
    requestBusy.current = true
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const t = memorySession.getItem("vaultx_access_token") || undefined
      await api.post("/auth/mfa/disable", { code, use_backup: useBackupCode }, t)
      setMfaEnabled(false)
      setBackupCodes([])
      setSuccess("MFA has been disabled.")
      setStep("check")
      setVerificationCode("")
      setUseBackupCode(false)
      await loadMfaStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable MFA. Please verify your code.")
    } finally {
      requestBusy.current = false
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <Card className="border-border bg-background/80 shadow-none">
        <CardHeader className="flex flex-col gap-4 pb-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/5">
              <Shield className="h-4 w-4 text-emerald-600 dark:text-emerald-400" strokeWidth={1.8} />
            </div>
            <div className="min-w-0 space-y-1">
              <CardTitle className="text-lg font-semibold">Two-Factor Authentication</CardTitle>
              <CardDescription className="text-sm text-muted-foreground">Protect your vault with a trusted authenticator or a passkey-bound device challenge.</CardDescription>
            </div>
          </div>
          {!mfaEnabled && step !== "verify" && (
            <Button onClick={() => void beginMfaSetup()} disabled={loading} className="min-h-11 w-full shrink-0 bg-primary text-primary-foreground hover:bg-primary/90 sm:w-auto">
              {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" strokeWidth={1.8} />}
              Set up MFA
            </Button>
          )}
        </CardHeader>

        <CardContent className="space-y-5">
          {error && (
            <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          {success && (
            <div role="status" className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm text-foreground">
              {success}
            </div>
          )}

          {mfaEnabled && (
            <div className="space-y-4 rounded-xl border border-border bg-muted/20 p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-foreground">
                  <BadgeCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" strokeWidth={1.8} />
                  <span className="text-sm font-medium">MFA is currently enabled</span>
                </div>
                {backupRemaining !== null && (
                  <Badge variant="outline" className="text-[11px] uppercase tracking-[0.12em]">
                    {backupRemaining} backup codes left
                  </Badge>
                )}
              </div>

              <div className="space-y-3">
                {mfaEnabled && backupRemaining !== null && backupRemaining > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={loading}
                    onClick={() => { setUseBackupCode(!useBackupCode); setVerificationCode(""); setError(null) }}
                    className="min-h-11 text-xs"
                  >
                    {useBackupCode ? "Use authenticator code" : "Use backup code"}
                  </Button>
                )}

                {useBackupCode ? (
                  <>
                    <Label htmlFor="disable-code" className="text-sm font-medium text-foreground">Enter a backup code</Label>
                    <Input
                      id="disable-code"
                      type="text"
                      placeholder="Backup code"
                      maxLength={32}
                      disabled={loading}
                      value={verificationCode}
                      onChange={(e) => {
                        setVerificationCode(e.target.value)
                        setError(null)
                      }}
                      className="min-h-11 font-mono text-center"
                    />
                    <Button variant="destructive" onClick={() => void disableMfa(verificationCode)} disabled={loading || !verificationCode} className="min-h-11 w-full">
                      {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      Disable MFA
                    </Button>
                  </>
                ) : (
                  <OtpDeck
                    value={verificationCode}
                    onChange={(code) => { setVerificationCode(code); setError(null) }}
                    onVerify={disableMfa}
                    busy={loading}
                    error={error}
                    autoSubmit={false}
                    actionLabel="Disable MFA"
                  />
                )}
              </div>
            </div>
          )}

        </CardContent>
      </Card>

      {step === "verify" && qrCodeUrl && secret && (
        <Card className="border-border bg-background/80 shadow-none">
          <CardHeader className="space-y-2">
            <CardTitle className="text-lg font-semibold text-foreground">TOTP setup</CardTitle>
            <CardDescription className="text-sm text-muted-foreground">Open Google Authenticator, Authy, or any TOTP app and scan this QR code.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="flex justify-center rounded-xl border border-border bg-muted/20 p-4">
              <Image src={qrCodeUrl} alt="MFA QR Code" width={192} height={192} unoptimized className="h-48 w-48 rounded-lg border border-border bg-white p-2" />
            </div>

            <div className="space-y-2">
              <Label className="text-sm font-medium text-foreground">Authenticator secret</Label>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded-md border border-border bg-muted/30 px-3 py-2 text-sm font-mono text-foreground">
                  {secret}
                </code>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Copy authenticator secret"
                  className="min-h-11 min-w-11"
                  onClick={async () => {
                    await navigator.clipboard.writeText(secret)
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <OtpDeck
              value={verificationCode}
              onChange={(code) => { setVerificationCode(code); setError(null) }}
              onVerify={verifyAndEnable}
              busy={loading}
              error={error}
              autoFocus
              label="Authenticator code"
              actionLabel="Enable MFA"
            />
          </CardContent>
        </Card>
      )}

      {backupCodes.length > 0 && !backupCodesVisible && (
        <Card className="border-border bg-background/80 shadow-none">
          <CardHeader className="space-y-2">
            <CardTitle className="text-lg font-semibold text-foreground">Backup codes</CardTitle>
            <CardDescription className="text-sm text-muted-foreground">Store these in a safe place. Each code can be used once.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" onClick={() => setBackupCodesVisible(true)} className="min-h-11">
              Show backup codes
            </Button>
          </CardContent>
        </Card>
      )}

      {backupCodesVisible && backupCodes.length > 0 && (
        <Card className="border-border bg-background/80 shadow-none">
          <CardHeader className="space-y-2">
            <CardTitle className="text-lg font-semibold text-foreground">Backup codes</CardTitle>
            <CardDescription className="text-sm text-muted-foreground">Store these securely and do not share them with anyone.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2 text-sm font-mono">
              {backupCodes.map((code) => (
                <div key={code} className="rounded-md border border-border bg-muted px-3 py-2 text-center text-foreground">
                  {code}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {backupCodes.length === 0 && !mfaEnabled && step === "check" && <PasskeyGateway />}
    </div>
  )
}
