"use client"

import { useState, useEffect } from "react"
import { Download, Shield, AlertCircle, Loader2, FileText, Check } from "lucide-react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { api } from "@/lib/api"
import { bufToB64, b64ToBuf } from "@/lib/crypto/base"
import { decryptStringWithAes } from "@/lib/crypto/aes"
import {
  deriveAesKeyFromPassphrase,
  decryptWithPassphrase,
  shareLinkPassphrase,
} from "@/lib/crypto/passphrase"
import { decryptChunkedGCM, CHUNK_SIZE } from "@/lib/crypto/chunking"

interface FileMetadata {
  id: string
  file_iv: string
  metadata_ciphertext: string
  metadata_iv: string
  encrypted_kf_b64: string | null
  encrypted_kf_iv: string | null
  kf_salt: string | null
  has_access_code: boolean
  file_size: number | null
}

interface DecryptedMetadata {
  name: string
  type: string
  size: number
  chunk_size?: number
}

export default function SharedAccessPage({ params }: { params: { token: string } }) {
  const { token } = params
  const router = useRouter()
  const [metadata, setMetadata] = useState<FileMetadata | null>(null)
  const [accessCode, setAccessCode] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCodeInput, setShowCodeInput] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [fileInfo, setFileInfo] = useState<DecryptedMetadata | null>(null)
  const [downloading, setDownloading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null)
  const [accessGranted, setAccessGranted] = useState(false)

  useEffect(() => {
    loadMetadata()
  }, [token])

  const loadMetadata = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get(`/shares/link/${token}`, undefined)
      setMetadata(res)
      if (res.has_access_code) {
        setShowCodeInput(true)
      } else {
        await decryptFileMetadata(res, null)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load file."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const decryptFileMetadata = async (meta: FileMetadata, code: string | null) => {
    try {
      let kf_b64: string | null = null

      if (meta.encrypted_kf_b64 && meta.encrypted_kf_iv && meta.kf_salt) {
        if (code) {
          const kf_buf = await decryptWithPassphrase(
            meta.encrypted_kf_b64,
            meta.encrypted_kf_iv,
            meta.kf_salt,
            code
          )
          kf_b64 = bufToB64(kf_buf)
        } else {
          // Same derivation as the owner used when creating the link.
          const tokenPass = shareLinkPassphrase(meta.id)
          const key = await deriveAesKeyFromPassphrase(tokenPass, meta.kf_salt)
          const kf_buf = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64ToBuf(meta.encrypted_kf_iv) },
            key,
            b64ToBuf(meta.encrypted_kf_b64),
          )
          kf_b64 = bufToB64(kf_buf)
        }
      }

      if (!kf_b64) throw new Error("Could not decrypt file key.")

      sessionStorage.setItem(`vaultx_kf_${meta.id}`, kf_b64)

      const metadataJson = await decryptStringWithAes(
        meta.metadata_ciphertext,
        meta.metadata_iv,
        kf_b64
      )
      const parsed: DecryptedMetadata = JSON.parse(metadataJson)
      setFileInfo(parsed)
      setAccessGranted(true)
      setShowCodeInput(false)
    } catch (err) {
      setError("Failed to decrypt file metadata. Check your access code.")
      console.error(err)
    }
  }

  const handleSubmitCode = async () => {
    if (!metadata || !accessCode) return
    setSubmitting(true)
    setError(null)
    try {
      // The wrapped file key is only released once the access code is proven;
      // the code travels in a header, never in the URL.
      const res = await api.get(`/shares/link/${token}`, undefined, {
        "X-Access-Code": accessCode,
      })
      setMetadata(res)
      await decryptFileMetadata(res, accessCode)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid access code.")
    } finally {
      setSubmitting(false)
    }
  }

  const handleDownload = async () => {
    if (!metadata || !fileInfo) return

    setDownloading(true)
    setProgress(0)

    try {
      const rangeParam = ""
      let received = 0
      const total = metadata.file_size || 0
      const chunks: Uint8Array[] = []

      const response = await api.getRaw(
        `/shares/link/${token}/download`,
        undefined,
        undefined,
        accessCode ? { "X-Access-Code": accessCode } : undefined,
      )

      // Headers contain metadata
      const fileIv = response.headers.get("X-File-Iv")
      const metadataCt = response.headers.get("X-Metadata-Ciphertext")
      const metadataIv = response.headers.get("X-Metadata-Iv")
      const encryptedKf = response.headers.get("X-Encrypted-Kf")
      const encryptedKfIv = response.headers.get("X-Encrypted-Kf-Iv")
      const kfSalt = response.headers.get("X-Kf-Salt")
      const fileId = response.headers.get("X-File-Id") || metadata.id

      // Get Kf — reuse the one we decrypted, or decrypt from headers
      let kf_b64 = sessionStorage.getItem(`vaultx_kf_${fileId}`)

      if (!kf_b64 && encryptedKf && encryptedKfIv && kfSalt) {
        if (accessCode) {
          const kf_buf = await decryptWithPassphrase(
            encryptedKf, encryptedKfIv, kfSalt, accessCode
          )
          kf_b64 = bufToB64(kf_buf)
        }
      }

      if (!kf_b64) throw new Error("Missing file encryption key")

      sessionStorage.setItem(`vaultx_kf_${fileId}`, kf_b64)

      // Stream the ciphertext
      const reader = response.body!.getReader()
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        if (value) {
          chunks.push(value)
          received += value.length
          if (total > 0) {
            setProgress(Math.min((received / total) * 100, 99))
          }
        }
      }

      // Merge chunks
      const combined = new Uint8Array(received)
      let offset = 0
      for (const chunk of chunks) {
        combined.set(chunk, offset)
        offset += chunk.byteLength
      }

      // Decrypt file content
      const kf_key = await window.crypto.subtle.importKey(
        "raw",
        b64ToBuf(kf_b64),
        { name: "AES-GCM" },
        false,
        ["decrypt"],
      )
      // Segment-wise GCM decryption (the file was sealed chunk-by-chunk with
      // counter-derived IVs derived from the persisted file nonce).
      const plaintext = await decryptChunkedGCM(
        combined.buffer as ArrayBuffer,
        kf_key,
        fileIv || metadata.file_iv,
        fileInfo.chunk_size ?? CHUNK_SIZE,
      )

      // Create download
      const blob = new Blob([plaintext])
      const url = URL.createObjectURL(blob)
      setDownloadUrl(url)
      const a = document.createElement("a")
      a.href = url
      a.download = fileInfo.name
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error("Download failed:", err)
      setError(err instanceof Error ? err.message : "Download failed.")
    } finally {
      setDownloading(false)
      setProgress(100)
      setTimeout(() => setProgress(0), 500)
    }
  }

  if (loading) {
    return (
      <div className="flex h-screen w-full items-center justify-center gap-3">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="text-muted-foreground">Loading shared file…</span>
      </div>
    )
  }

  if (error && !accessGranted) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="max-w-md border-border">
          <CardHeader>
            <CardTitle className="text-destructive">Unable to Access File</CardTitle>
          </CardHeader>
            <CardContent>
            <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2 mb-4">
              <AlertCircle className="h-4 w-4 text-destructive mt-0.5" />
              <span className="text-sm text-destructive">{error}</span>
            </div>
            <Button className="w-full" onClick={() => router.back()}>
              Go Back
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border p-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <h1 className="text-xl font-semibold">VaultX — Shared File</h1>
          <Button variant="ghost" size="sm" onClick={() => router.back()}>
            Close
          </Button>
        </div>
      </header>

      <main className="max-w-2xl mx-auto p-6 space-y-6">
        {showCodeInput && metadata?.has_access_code ? (
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" strokeWidth={1.5} />
                Access Code Required
              </CardTitle>
              <CardDescription>
                This shared link requires an access code to view the file.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="access-code">Access Code</Label>
                  <Input
                    id="access-code"
                    type="password"
                    placeholder="Enter access code"
                    value={accessCode}
                    onChange={(e) => setAccessCode(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && !submitting && handleSubmitCode()}
                    className="border-border"
                  />
                </div>
                {error && (
                  <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-destructive mt-0.5" />
                    <span className="text-sm text-destructive">{error}</span>
                  </div>
                )}
                <div className="flex gap-2">
                  <Button
                    className="flex-1"
                    onClick={handleSubmitCode}
                    disabled={submitting || !accessCode}
                  >
                    {submitting ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Verifying…
                      </>
                    ) : (
                      "Unlock File"
                    )}
                  </Button>
                  <Button variant="outline" className="border-border" onClick={() => router.back()}>
                    Cancel
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : null}

        {!showCodeInput && fileInfo ? (
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <FileText className="h-8 w-8 text-primary" strokeWidth={1.5} />
                {fileInfo.name}
              </CardTitle>
              <CardDescription>
                {fileInfo.size ? `${(fileInfo.size / 1024).toFixed(1)} KB` : ""}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {error && (
                  <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-destructive mt-0.5" />
                    <span className="text-sm text-destructive">{error}</span>
                  </div>
                )}

                {downloading && (
                  <div className="space-y-2">
                    <Progress value={progress} className="h-2" />
                    <p className="text-xs text-muted-foreground">
                      Downloading… {Math.round(progress)}%
                    </p>
                  </div>
                )}

                <Button
                  className="w-full md:w-auto"
                  onClick={handleDownload}
                  disabled={downloading}
                  size="lg"
                >
                  {downloading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Downloading…
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4 mr-2" />
                      Download File
                    </>
                  )}
                </Button>

                {downloadUrl && (
                  <div className="flex items-center gap-2 text-xs text-green-500">
                    <Check className="w-3 h-3" />
                    <span>Download complete!</span>
                    <a
                      href={downloadUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 underline"
                    >
                      Open file
                    </a>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ) : null}
      </main>
    </div>
  )
}
