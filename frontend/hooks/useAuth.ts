"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { clearVaultXContext, getSessionContext } from "@/lib/crypto/context"

/**
 * Custom hook for authentication logic.
 * - Checks the memory-only unlocked session; reloading requires login
 * - Redirects to "/" if not found
 * - Returns the token so components can use it
 */
export function useAuth() {
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    // This runs only on the client side
    const storedToken = getSessionContext()?.accessToken

    if (!storedToken) {
      clearVaultXContext()
      // No token → redirect to login
      router.replace("/")
    } else {
      // Token found → store it in state
      setToken(storedToken)
    }

    setLoading(false)
  }, [router])

  return { token, loading }
}
