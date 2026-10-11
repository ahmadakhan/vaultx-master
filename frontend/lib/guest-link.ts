export const MAX_GUEST_DOWNLOADS = 2_147_483_647

export interface GuestLinkOptions {
  expiryEnabled: boolean
  expiryPreset: "1h" | "1day" | "custom"
  customExpiry: string
  downloadsEnabled: boolean
  maxDownloads: string
  codeEnabled: boolean
  accessCode: string
}

export function guestLinkPayload(options: GuestLinkOptions, now = Date.now()) {
  let expires_at: string | null = null
  if (options.expiryEnabled) {
    const timestamp = options.expiryPreset === "custom"
      ? new Date(options.customExpiry).getTime()
      : now + (options.expiryPreset === "1h" ? 1 : 24) * 3_600_000
    if (!Number.isFinite(timestamp) || timestamp <= now) throw new Error("Choose an expiration date and time in the future.")
    expires_at = new Date(timestamp).toISOString()
  }
  let max_downloads: number | null = null
  if (options.downloadsEnabled) {
    if (!/^\d+$/.test(options.maxDownloads)) throw new Error("Maximum downloads must be a whole number.")
    max_downloads = Number(options.maxDownloads)
    if (!Number.isSafeInteger(max_downloads) || max_downloads < 1 || max_downloads > MAX_GUEST_DOWNLOADS) {
      throw new Error(`Maximum downloads must be between 1 and ${MAX_GUEST_DOWNLOADS.toLocaleString("en-US")}.`)
    }
  }
  if (options.codeEnabled && (Array.from(options.accessCode).length < 4 || Array.from(options.accessCode).length > 12)) {
    throw new Error("Access code must contain 4–12 characters.")
  }
  return { expires_at, max_downloads, access_code: options.codeEnabled ? options.accessCode : undefined }
}

export function guestLinkStatus(link: { expires_at: string | null; max_downloads: number | null; download_count: number }, now = Date.now()) {
  if (link.expires_at && new Date(link.expires_at).getTime() <= now) return "Expired"
  if (link.max_downloads !== null && link.download_count >= link.max_downloads) return "Limit reached"
  return "Available"
}

export async function copyGuestLink(url: string, write: (value: string) => Promise<void>, select: () => void) {
  try {
    await write(url)
    return true
  } catch {
    select()
    return false
  }
}
