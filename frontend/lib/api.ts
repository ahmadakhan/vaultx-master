import { clearVaultXContext, getSessionContext } from "./crypto/context";

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

function errorDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // Validation payloads can include the submitted password in `input`.
    // Only display human-readable messages, never stringify the whole object.
    const messages = detail.flatMap(item =>
      item && typeof item.msg === "string" ? [item.msg] : []);
    if (messages.length) return messages.join("; ");
  }
  return "Request failed. Please try again.";
}

async function request(endpoint: string, token: string | undefined, init: RequestInit = {}): Promise<Response> {
  const path = endpoint.replace(/^\/+/, "");
  if (!path || path.includes("://")) throw new Error("Invalid API endpoint");
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`/api/${path}`, { ...init, headers, cache: "no-store", credentials: "same-origin" });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw error;
    throw new Error("Server unreachable. Please try again later.");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    if (response.status === 401 && token && token === getSessionContext()?.accessToken) {
      clearVaultXContext();
      if (typeof window !== "undefined") window.location.assign("/");
    }
    throw new ApiError(errorDetail(payload?.detail), response.status);
  }
  return response;
}

async function jsonResponse(response: Response) {
  if (response.status === 204) return {};
  try { return await response.json(); }
  catch { throw new ApiError("The server returned an invalid response.", response.status); }
}

export const api = {
  post: async (endpoint: string, data?: unknown, token?: string, json = true) =>
    jsonResponse(await request(endpoint, token, {
      method: "POST",
      headers: json ? { "Content-Type": "application/json" } : {},
      body: json ? JSON.stringify(data) : data as BodyInit,
    })),
  get: async (endpoint: string, token?: string, extraHeaders?: Record<string, string>) =>
    jsonResponse(await request(endpoint, token, { headers: { Accept: "application/json", ...extraHeaders } })),
  getRaw: async (endpoint: string, token?: string, range?: string, extraHeaders?: Record<string, string>) =>
    request(endpoint, token, { headers: { Accept: "application/octet-stream", ...(range ? { Range: range } : {}), ...extraHeaders } }),
  delete: async (endpoint: string, token?: string) =>
    jsonResponse(await request(endpoint, token, { method: "DELETE" })),
};
