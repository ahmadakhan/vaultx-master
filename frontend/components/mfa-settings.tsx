"use client"
import { memorySession } from "@/lib/crypto/context"

import { useState, useEffect, useRef } from "react"
import { Shield, ShieldCheck, Loader2, Copy } from "lucide-react"
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
    loadMfaStatus()
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
      await api.post(
        "/auth/mfa/enable",
        { code },
        t
      )
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
      await api.post(
        "/auth/mfa/disable",
        { code, use_backup: useBackupCode },
        t
      )
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
      <Card className="border-border">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" strokeWidth={1.5} />
            Two-Factor Authentication
          </CardTitle>
          <CardDescription>
            Add an extra layer of security to your account using a TOTP authenticator app.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div role="alert" className="p-3 rounded-md border border-destructive/30 bg-destructive/5 text-sm text-destructive">
              {error}
            </div>
          )}
          {success && (
            <div role="status" className="p-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 text-sm text-foreground">
              {success}
            </div>
          )}

          {mfaEnabled && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-foreground">
                  <ShieldCheck className="w-4 h-4" strokeWidth={1.5} />
                  <span className="text-sm font-medium">MFA is currently enabled</span>
                </div>
                {backupRemaining !== null && (
                  <Badge variant="outline" className="text-xs">
                    {backupRemaining} backup codes left
                  </Badge>
                )}
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
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
                </div>
                {useBackupCode ? <>
                <Label htmlFor="disable-code">Enter a backup code</Label>
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
              <Button
                variant="destructive"
                onClick={() => void disableMfa(verificationCode)}
                disabled={loading || !verificationCode}
                className="min-h-11 w-full"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                Disable MFA
              </Button>
              </> : <OtpDeck value={verificationCode} onChange={(code) => { setVerificationCode(code); setError(null) }}
                onVerify={disableMfa} busy={loading} error={error} autoSubmit={false} actionLabel="Disable MFA" />}
              </div>
            </div>
          )}
          {!mfaEnabled && step !== "verify" && (
            <div className="space-y-2">
              <Button
                onClick={beginMfaSetup}
                disabled={loading}
                className="min-h-11 w-full bg-primary hover:bg-primary/90"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Shield className="w-4 h-4 mr-2" strokeWidth={1.5} />}
                Set Up MFA
              </Button>
            </div>
          )}
        </CardContent>
    </Card>

    {step === "verify" && qrCodeUrl && secret && (
      <Card className="border-border">
        <CardHeader>
          <CardTitle className="text-lg font-semibold">Scan the QR Code</CardTitle>
          <CardDescription>
            Open Google Authenticator, Authy, or any TOTP app and scan this QR code.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex justify-center">
            <img src={qrCodeUrl} alt="MFA QR Code" className="w-48 h-48" />
          </div>
          <div className="space-y-2">
            <Label className="text-sm">Your secret key:</Label>
            <div className="flex items-center gap-2">
              <code className="text-sm font-mono bg-muted px-3 py-2 rounded border border-border flex-1 break-all">
                {secret}
              </code>
              <Button
                size="sm"
                variant="ghost"
                aria-label="Copy authenticator secret"
                className="min-h-11 min-w-11"
                onClick={async () => {
                  await navigator.clipboard.writeText(secret)
                  setSuccess("Secret copied to clipboard!")
                }}
              >
                <Copy className="w-4 h-4" />
              </Button>
            </div>
          </div>
          {backupCodes.length > 0 && (
            <div className="space-y-2">
              <Label className="text-sm flex items-center justify-between">
                <span>Backup recovery codes (save these!):</span>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Copy backup recovery codes"
                  className="min-h-11 min-w-11"
                  onClick={async () => {
                    await navigator.clipboard.writeText(backupCodes.join("\n"))
                    setSuccess("Backup codes copied to clipboard!")
                  }}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </Label>
              <div className={`grid grid-cols-2 gap-2 border border-border rounded-md p-3 ${backupCodesVisible ? "" : "blur-sm"}`}>
                {backupCodes.map((code) => (
                  <code key={code} className="text-sm font-mono bg-muted px-3 py-1 rounded text-center">
                    {code}
                  </code>
                ))}
              </div>
              {!backupCodesVisible && (
                <Button size="sm" variant="outline" className="min-h-11 border-border" onClick={() => setBackupCodesVisible(true)}>
                  Show backup codes
                </Button>
              )}
            </div>
          )}
          <OtpDeck value={verificationCode} onChange={(code) => { setVerificationCode(code); setError(null) }}
            onVerify={verifyAndEnable} busy={loading} error={error} actionLabel="Verify & Enable MFA" />
        </CardContent>
      </Card>
    )}
    {mfaEnabled && backupCodes.length > 0 && (
      <section className="space-y-3 rounded-xl border border-border p-6" aria-label="Save recovery codes">
        <h3 className="font-semibold">Save your backup recovery codes</h3>
        <p className="text-sm text-muted-foreground">MFA is enabled. Keep these one-time codes somewhere safe before leaving this page.</p>
        {backupCodesVisible ? (
          <div className="grid grid-cols-2 gap-2">
            {backupCodes.map((code) => <code key={code} className="break-all rounded bg-muted p-2 text-center font-mono text-sm">{code}</code>)}
          </div>
        ) : <Button variant="outline" className="min-h-11" onClick={() => setBackupCodesVisible(true)}>Show backup codes</Button>}
        <Button variant="outline" className="min-h-11 w-full" onClick={() => { setBackupCodes([]); setSecret(null); setQrCodeUrl(null) }}>I have saved my backup codes</Button>
      </section>
    )}
    <PasskeyGateway />
    </div>
  )
}
