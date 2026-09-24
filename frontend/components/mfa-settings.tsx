"use client"

import { useState, useEffect } from "react"
import { Shield, ShieldCheck, Loader2, Copy, Check } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"

const sanitizeDigits = (value: string) => value.replace(/\D/g, "").slice(0, 6)

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

  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    loadMfaStatus()
  }, [])

  const loadMfaStatus = async () => {
    setLoading(true)
    try {
      const t = localStorage.getItem("vaultx_access_token") || undefined
      const res = await api.get("/auth/mfa/status", t)
      setMfaEnabled(res.mfa_enabled)
      setBackupRemaining(res.backup_codes_remaining ?? null)
      setStep("check")
      setSuccess(null)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load MFA status")
    } finally {
      setLoading(false)
    }
  }

  const beginMfaSetup = async () => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const t = localStorage.getItem("vaultx_access_token") || undefined
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
      setLoading(false)
    }
  }

  const verifyAndEnable = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      setError("Please enter a valid 6-digit code from your authenticator app.")
      return
    }
    setLoading(true)
    setError(null)
    try {
      const t = localStorage.getItem("vaultx_access_token") || undefined
      await api.post(
        "/auth/mfa/enable",
        { code: verificationCode },
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
      setLoading(false)
    }
  }

  const disableMfa = async () => {
    if (!verificationCode) {
      setError(useBackupCode ? "Please enter a backup code." : "Please enter your current 6-digit code to disable MFA.")
      return
    }
    if (!useBackupCode && verificationCode.length !== 6) {
      setError("Please enter a valid 6-digit code from your authenticator app.")
      return
    }
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const t = localStorage.getItem("vaultx_access_token") || undefined
      await api.post(
        "/auth/mfa/disable",
        { code: verificationCode, use_backup: useBackupCode },
        t
      )
      setMfaEnabled(false)
      setSuccess("MFA has been disabled.")
      setStep("check")
      setVerificationCode("")
      setUseBackupCode(false)
      await loadMfaStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable MFA. Please verify your code.")
    } finally {
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
            <div className="p-3 rounded-md border border-destructive/30 bg-destructive/5 text-sm text-destructive">
              {error}
            </div>
          )}
          {success && (
            <div className="p-3 rounded-md border border-green-500/30 bg-green-500/5 text-sm text-green-600">
              {success}
            </div>
          )}

          {mfaEnabled && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-green-600">
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
                  <Label className="text-sm">
                    {useBackupCode ? "Enter a backup code" : "Enter your 6-digit TOTP code"}
                  </Label>
                  {mfaEnabled && backupRemaining !== null && backupRemaining > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setUseBackupCode(!useBackupCode)}
                      className="text-xs"
                    >
                      Use backup code
                    </Button>
                  )}
                </div>
                <Input
                  id="disable-code"
                  type={useBackupCode ? "text" : "number"}
                  inputMode={useBackupCode ? "text" : "numeric"}
                  placeholder={useBackupCode ? "Backup code" : "000000"}
                  maxLength={useBackupCode ? 32 : 6}
                  value={verificationCode}
                  onChange={(e) => {
                    if (useBackupCode) {
                      setVerificationCode(e.target.value)
                    } else {
                      setVerificationCode(sanitizeDigits(e.target.value))
                    }
                  }}
                  className="font-mono text-center"
                />
              </div>
              <Button
                variant="destructive"
                onClick={disableMfa}
                disabled={loading || !verificationCode}
                className="w-full"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                Disable MFA
              </Button>
            </div>
          )}
          {!mfaEnabled && (
            <div className="space-y-2">
              <Button
                onClick={beginMfaSetup}
                disabled={loading}
                className="w-full bg-primary hover:bg-primary/90"
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
                <Button size="sm" variant="outline" className="border-border" onClick={() => setBackupCodesVisible(true)}>
                  Show backup codes
                </Button>
              )}
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="mfa-verify-code" className="text-sm">
              Enter the 6-digit code from your authenticator app
            </Label>
            <Input
              id="mfa-verify-code"
              type="text"
              inputMode="numeric"
              placeholder="000000"
              maxLength={6}
              value={verificationCode}
              onChange={(e) => setVerificationCode(sanitizeDigits(e.target.value))}
              className="font-mono text-center text-lg tracking-widest"
            />
          </div>
          <Button
            onClick={verifyAndEnable}
            disabled={loading || !verificationCode || verificationCode.length !== 6}
            className="w-full bg-primary hover:bg-primary/90"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Check className="w-4 h-4 mr-2" strokeWidth={1.5} />}
            Verify & Enable MFA
          </Button>
        </CardContent>
      </Card>
    )}
    </div>
  )
}
