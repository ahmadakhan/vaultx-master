"use client"

import React, { useState } from "react"
import { useRouter } from "next/navigation"
import { Eye, EyeOff, Lock, Mail, AlertCircle, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import Link from "next/link"
import { api } from "@/lib/api"
import { deriveMasterKey } from "@/lib/crypto/keys"
import { aesDecryptArrayBuffer, decryptStringWithAes } from "@/lib/crypto/aes"
import { prepareUserKeyBundle } from "@/lib/crypto/setupUserKeys"
import { setVaultXContext } from "@/lib/crypto/context"

export function LoginForm() {
  const [mode, setMode] = useState<"login" | "register">("login")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [mfaCode, setMfaCode] = useState("")
  const [showMfa, setShowMfa] = useState(false)
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const router = useRouter()

  const clearError = () => setError(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    clearError()

    try {
      if (mode === "register") {
        if (password !== confirmPassword) {
          setError("Passwords do not match.")
          setLoading(false)
          return
        }
      }

      if (!email || !password) {
        setError("Please fill in all required fields.")
        setLoading(false)
        return
      }

      const { accessToken, keys, mfaRequired } = await signInOrRegister(mode, email, password)

      if (mfaRequired) {
        setMfaToken(accessToken)
        setShowMfa(true)
        setLoading(false)
        return
      }

      if (!accessToken) throw new Error("No access token returned")

      await activateSession(accessToken, keys, password, email)

      router.push("/dashboard")
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong. Please try again."
      )
    } finally {
      setLoading(false)
    }
  }

  async function signInOrRegister(
    mode: "login" | "register",
    email: string,
    password: string
  ) {
    if (mode === "register") {
      const bundle = await prepareUserKeyBundle(password)
      const res = await api.post("/auth/register", { email, password, ...bundle })
      const data = res.data || res
      return { accessToken: data.access_token, keys: data.keys, mfaRequired: false }
    }
    const res = await api.post("/auth/login", { email, password })
    const data = res.data || res
    return {
      accessToken: data.access_token,
      keys: data.keys,
      mfaRequired: data.mfa_required === true,
    }
  }

  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    clearError()

    try {
      if (!mfaCode || mfaCode.length !== 6) {
        setError("Please enter the 6-digit code from your authenticator app.")
        setLoading(false)
        return
      }

      const res = await api.post("/auth/mfa/verify", { code: mfaCode }, mfaToken || undefined)
      const data = res.data || res

      const accessToken = data.access_token
      if (!accessToken) throw new Error("No access token returned")
      // The key bundle is only released after the second factor is proven;
      // unlock it now and populate both storage and the in-memory context.
      const keys = data.keys
      if (!keys) throw new Error("The server returned no vault keys. Please log in again.")
      await activateSession(accessToken, keys, password, email)

      router.push("/dashboard")
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong. Please try again."
      )
    } finally {
      setLoading(false)
    }
  }

  async function decryptToB64(ciphertext: string, iv: string, pwKey: CryptoKey) {
    const raw = await aesDecryptArrayBuffer(ciphertext, iv, pwKey)
    return btoa(String.fromCharCode(...new Uint8Array(raw)))
  }

  /**
   * Unwrap the vault key bundle with the password-derived key, persist the
   * session (localStorage token + sessionStorage keys) and populate the
   * in-memory VaultXContext that every authenticated screen reads.
   * Used by both the plain login and the post-MFA verification path.
   */
  async function activateSession(
    accessToken: string,
    keys: {
      password_salt_b64: string
      enc_master_key_b64: string
      enc_master_key_iv: string
      enc_search_key_b64: string
      enc_search_key_iv: string
      enc_private_key_b64: string
      enc_private_key_iv: string
      public_key_b64: string
    },
    password: string,
    email: string
  ) {
    const { key: pwKey } = await deriveMasterKey(password, keys.password_salt_b64)

    const masterKey_b64 = await decryptToB64(
      keys.enc_master_key_b64,
      keys.enc_master_key_iv,
      pwKey
    )
    const searchKey_b64 = await decryptToB64(
      keys.enc_search_key_b64,
      keys.enc_search_key_iv,
      pwKey
    )
    const privateKey_b64 = await decryptToB64(
      keys.enc_private_key_b64,
      keys.enc_private_key_iv,
      pwKey
    )

    localStorage.setItem("vaultx_access_token", accessToken)
    sessionStorage.setItem("vaultx_master_key", masterKey_b64)
    sessionStorage.setItem("vaultx_search_key", searchKey_b64)
    sessionStorage.setItem("vaultx_private_key", privateKey_b64)
    sessionStorage.setItem("vaultx_public_key", keys.public_key_b64)
    sessionStorage.setItem("vaultx_user_email", email)

    const chainData = await api.get("/user/index_state", accessToken)
    if (chainData?.index_state_ciphertext) {
      const chainJson = await decryptStringWithAes(
        chainData.index_state_ciphertext,
        chainData.index_state_iv,
        masterKey_b64
      )
      sessionStorage.setItem("vaultx_keyword_chain", chainJson)
    }

    setVaultXContext({
      accessToken,
      masterKey_b64,
      searchKey_b64,
      privateKey_b64,
      publicKey_b64: keys.public_key_b64,
    })
  }

  const toggleMode = () => {
    setMode(mode === "login" ? "register" : "login")
    clearError()
  }

  return (
    <Card className="w-full max-w-md mx-auto border-border shadow-xl">
      <CardHeader className="space-y-5 text-center pb-4">
        <div className="flex items-center justify-center space-x-2">
          <div className="w-9 h-9 rounded-lg bg-primary flex items-center justify-center">
            <VaultIcon className="w-5 h-5 text-primary-foreground" />
          </div>
          <span className="text-xl font-semibold tracking-tight text-foreground">
            VaultX
          </span>
        </div>
        <div>
          <CardTitle className="text-2xl font-semibold text-foreground">
            {mode === "login" ? "Welcome back" : "Create your account"}
          </CardTitle>
          <CardDescription className="text-sm text-muted-foreground mt-1">
            {mode === "login"
              ? "Enter your credentials to access your encrypted vault."
              : "Join VaultX — your data, encrypted end-to-end."}
          </CardDescription>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        {error && (
          <div className="flex items-start gap-2.5 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

           {showMfa ? (
             <form onSubmit={handleMfaSubmit} className="space-y-4">
               <div className="flex items-center justify-center pb-2">
                 <Shield className="w-8 h-8 text-primary" strokeWidth={1.5} />
               </div>
               <div className="space-y-2">
                 <Label htmlFor="mfa-code" className="vaultx-label text-xs">
                   2FA Code
                 </Label>
                 <div className="relative">
                   <Shield
                     className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                     strokeWidth={1.5}
                   />
                   <Input
                     id="mfa-code"
                     type="text"
                     inputMode="numeric"
                     placeholder="6-digit code from authenticator"
                     maxLength={6}
                     value={mfaCode}
                     onChange={(e) => {
                       setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                       clearError()
                     }}
                     onFocus={clearError}
                     className="h-10 pl-10 border-border focus:border-ring focus:ring-ring/50"
                     required
                   />
                 </div>
               </div>

               <Button
                 type="submit"
                 disabled={loading}
                 className="w-full bg-primary hover:bg-primary/90 text-primary-foreground h-11"
               >
                 {loading ? "Verifying…" : "Verify & Sign In"}
               </Button>
             </form>
           ) : (
             <form onSubmit={handleSubmit} className="space-y-4">
               <div className="space-y-2">
                 <Label htmlFor={mode === "login" ? "email" : "reg-email"} className="vaultx-label text-xs">
                   {mode === "register" ? "New Email" : "Email"}
                 </Label>
                 <div className="relative">
                   <Mail
                     className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                     strokeWidth={1.5}
                   />
                   <Input
                     id={mode === "login" ? "email" : "reg-email"}
                     type="email"
                     placeholder="Enter your email"
                     autoComplete="email"
                     value={email}
                     onChange={(e) => {
                       setEmail(e.target.value)
                       clearError()
                     }}
                     onFocus={clearError}
                     className="h-10 pl-10 border-border focus:border-ring focus:ring-ring/50"
                     required
                   />
                 </div>
               </div>

               <div className="space-y-2">
                 <div className="flex items-center justify-between">
                   <Label htmlFor={mode === "login" ? "password" : "reg-password"} className="vaultx-label text-xs">
                     Password
                   </Label>
                   <button
                     type="button"
                     tabIndex={-1}
                     onClick={() => setShowPassword((v) => !v)}
                     className="text-xs text-muted-foreground hover:text-foreground"
                     aria-label={showPassword ? "Hide password" : "Show password"}
                   >
                     {showPassword ? "Hide" : "Show"}
                   </button>
                 </div>
                 <div className="relative">
                   <Lock
                     className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                     strokeWidth={1.5}
                   />
                   <Input
                     id={mode === "login" ? "password" : "reg-password"}
                     type={showPassword ? "text" : "password"}
                     placeholder="Enter your password"
                     autoComplete={mode === "login" ? "current-password" : "new-password"}
                     value={password}
                     onChange={(e) => {
                       setPassword(e.target.value)
                       clearError()
                     }}
                     onFocus={clearError}
                     className="h-10 pl-10 border-border focus:border-ring focus:ring-ring/50"
                     required
                   />
                   <button
                     type="button"
                     tabIndex={-1}

                     onClick={() => setShowPassword((v) => !v)}
                     className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                     aria-label={showPassword ? "Hide password" : "Show password"}
                   >
                     {showPassword ? (
                       <EyeOff className="w-4 h-4" strokeWidth={1.5} />
                     ) : (
                       <Eye className="w-4 h-4" strokeWidth={1.5} />
                     )}
                   </button>
                 </div>
               </div>

               {mode === "register" && (
                 <div className="space-y-2">
                   <Label htmlFor="confirm" className="vaultx-label text-xs">
                     Confirm Password
                   </Label>
                   <div className="relative">
                     <Lock
                       className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                       strokeWidth={1.5}
                     />
                     <Input
                       id="confirm"
                       type={showPassword ? "text" : "password"}
                       placeholder="Re-enter your password"
                       autoComplete="new-password"
                       value={confirmPassword}
                       onChange={(e) => setConfirmPassword(e.target.value)}
                       className="h-10 pl-10 border-border focus:border-ring focus:ring-ring/50"
                       required
                     />
                   </div>
                 </div>
               )}

               <Button
                 type="submit"
                 disabled={loading}
                 className="w-full bg-primary hover:bg-primary/90 text-primary-foreground h-11"
               >
                 {loading
                   ? mode === "login"
                     ? "Signing in…"
                     : "Creating account…"
                   : mode === "login"
                     ? "Sign In"
                     : "Create Account"}
               </Button>
             </form>
           )}

        <div className="text-center text-sm text-muted-foreground">
          {mode === "login" ? (
            <>
              Don&apos;t have an account?{" "}
              <button
                type="button"
                onClick={toggleMode}
                className="font-medium text-primary hover:text-primary/90"
              >
                Register
              </button>
            </>
          ) : (
            <>
              Already have an account?{" "}
              <button
                type="button"
                onClick={toggleMode}
                className="font-medium text-primary hover:text-primary/90"
              >
                Login
              </button>
            </>
          )}
        </div>

        <div className="text-center text-xs text-muted-foreground">
          Having trouble?{" "}
          <Link
            href="#"
            className="font-medium text-primary hover:text-primary/90"
          >
            Contact support
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

function VaultIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      {...props}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z"
      />
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M8 5l4-4 4 4"
      />
    </svg>
  )
}
