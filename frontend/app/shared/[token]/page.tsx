"use client"

import { useState, useEffect, useRef } from "react"
import { Download, Shield, AlertCircle, Loader2, FileText, Check } from "lucide-react"
import { useParams, useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { api } from "@/lib/api"
import { bufToB64, b64ToBuf } from "@/lib/crypto/base"
import { decryptStringWithAes } from "@/lib/crypto/aes"
import { buildChunkAad } from "@/lib/crypto/aes"
import {
  deriveAesKeyFromPassphrase,
  decryptWithPassphrase,
  shareLinkPassphrase,
} from "@/lib/crypto/passphrase"
import { CHUNK_SIZE } from "@/lib/crypto/chunking"

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

export default function SharedAccessPage() {
  const { token } = useParams<{ token: string }>()
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
  const fileKey = useRef<string | null>(null)
  const downloadAbort = useRef<AbortController | null>(null)

  // The fallback deliberately has a bound. Large downloads use the
  // File System Access API when the browser exposes it, avoiding a second
  // whole-file ciphertext/plaintext allocation. Native mobile support is not
  // implied by this capability check.
  const MAX_BUFFERED_DOWNLOAD = 256 * 1024 * 1024

  useEffect(() => {
    fileKey.current = null
    setAccessGranted(false)
    loadMetadata()
    return () => { fileKey.current = null }
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
        const fragment = new URLSearchParams(window.location.hash.slice(1))
        const secret = fragment.get("key")
        if (secret && b64ToBuf(secret).byteLength !== 32) throw new Error("Invalid link secret")
        if (secret || code) {
          const kf_buf = await decryptWithPassphrase(
            meta.encrypted_kf_b64,
            meta.encrypted_kf_iv,
            meta.kf_salt,
            secret || code!
          )
          kf_b64 = bufToB64(kf_buf)
        } else {
          // Read-only legacy compatibility. New links always carry #key=.
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

      const metadataJson = await decryptStringWithAes(
        meta.metadata_ciphertext,
        meta.metadata_iv,
        kf_b64
      )
      const parsed: DecryptedMetadata = JSON.parse(metadataJson)
      fileKey.current = kf_b64
      setFileInfo(parsed)
      setAccessGranted(true)
      setShowCodeInput(false)
    } catch {
      fileKey.current = null
      setAccessGranted(false)
      setError("Cannot unlock this file. Open the complete shared link (including #key=) and check your access code.")
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
    const abort = new AbortController()
    downloadAbort.current = abort

    try {
      let received = 0
      const total = metadata.file_size || 0
      let bufferedPlaintext = 0
      const plaintextParts: Uint8Array[] = []
      let sink: FileSystemWritableFileStream | null = null
      const picker = (window as unknown as { showSaveFilePicker?: (options?: unknown) => Promise<{ createWritable: () => Promise<FileSystemWritableFileStream> }> }).showSaveFilePicker
      if (picker) {
        try {
          const handle = await picker({ suggestedName: fileInfo.name })
          sink = await handle.createWritable()
        } catch (error) {
          if (error instanceof DOMException && error.name === "AbortError") return
          // A denied picker is recoverable; use the bounded in-memory path.
        }
      }

      const response = await api.getRaw(
        `/shares/link/${token}/download`,
        undefined,
        undefined,
        accessCode ? { "X-Access-Code": accessCode } : undefined,
        abort.signal,
      )

      // Headers contain metadata
      const fileIv = response.headers.get("X-File-Iv")
      // Only the key that successfully authenticated the displayed metadata
      // may decrypt this download; never substitute server-provided key data.
      const kf_b64 = fileKey.current

      if (!kf_b64) throw new Error("Missing file encryption key")

      // Decrypt framed ciphertext as it arrives. Each frame is independently
      // authenticated, so no complete ciphertext buffer is required.
      const kf_key = await window.crypto.subtle.importKey("raw", b64ToBuf(kf_b64), { name: "AES-GCM" }, false, ["decrypt"])
      const nonce = new Uint8Array(b64ToBuf(fileIv || metadata.file_iv))
      if (nonce.byteLength !== 12) throw new Error("Invalid file IV")
      const frameSize = (fileInfo.chunk_size ?? CHUNK_SIZE) + 16
      let pending = new Uint8Array(0)
      let frameIndex = 0
      const consume = async (frame: Uint8Array, final: boolean) => {
        if (frame.byteLength < 16 || (!final && frame.byteLength !== frameSize)) throw new Error("Malformed encrypted file")
        const iv = new Uint8Array(nonce)
        new DataView(iv.buffer).setUint32(8, frameIndex++, false)
        const params: AesGcmParams = {
          name: "AES-GCM",
          iv,
          additionalData: buildChunkAad(1, metadata.id, frameIndex - 1, frame.byteLength - 16) as BufferSource,
        }
        const decrypted = await window.crypto.subtle.decrypt(params, kf_key, frame as BufferSource)
        const plain = new Uint8Array(decrypted)
        bufferedPlaintext += plain.byteLength
        if (!sink && bufferedPlaintext > MAX_BUFFERED_DOWNLOAD) throw new Error("This browser cannot safely download files larger than 256 MiB; use a browser with file-save streaming support.")
        if (sink) await sink.write(plain)
        else plaintextParts.push(plain)
      }
      const reader = response.body!.getReader()
      while (true) {
        if (abort.signal.aborted) throw new DOMException("Download cancelled", "AbortError")
        const { done, value } = await reader.read()
        if (done) break
        if (value) {
          received += value.length
          const merged = new Uint8Array(pending.byteLength + value.byteLength)
          merged.set(pending); merged.set(value, pending.byteLength)
          pending = merged
          while (pending.byteLength >= frameSize) {
            await consume(pending.slice(0, frameSize), false)
            pending = pending.slice(frameSize)
          }
          if (total > 0) {
            setProgress(Math.min((received / total) * 100, 99))
          }
        }
      }
      if (pending.byteLength) await consume(pending, true)
      if (received < 16 || bufferedPlaintext !== fileInfo.size) throw new Error("File size does not match authenticated metadata")
      if (sink) {
        await sink.close()
        setProgress(100)
        return
      }
      const plaintext = new Blob(plaintextParts.map(part => part.buffer as ArrayBuffer))

      // Create download
      const url = URL.createObjectURL(plaintext)
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
      downloadAbort.current = null
      setDownloading(false)
      setProgress(100)
      setTimeout(() => setProgress(0), 500)
    }
  }

  const cancelDownload = () => downloadAbort.current?.abort()

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
                {downloading && (
                  <Button variant="outline" className="ml-2" onClick={cancelDownload}>Cancel</Button>
                )}

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
