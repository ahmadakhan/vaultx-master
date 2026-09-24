"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"

/**
 * Custom hook for authentication logic.
 * - Checks if access token exists in localStorage
 * - Redirects to "/" if not found
 * - Returns the token so components can use it
 */
export function useAuth() {
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    // This runs only on the client side
    const storedToken = localStorage.getItem("vaultx_access_token")

    if (!storedToken) {
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
