import { clearVaultXContext } from "./crypto/context";

class NetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NetworkError";
  }
}

export const api = {
  post: async (endpoint: string, data?: unknown, token?: string, json = true) => {
    try {
      const headers: Record<string, string> = token
        ? { Authorization: `Bearer ${token}` }
        : {};
      if (json) headers["Content-Type"] = "application/json";

      const res = await fetch(`/api/${endpoint}`, {
        method: "POST",
        headers,
        body: json ? JSON.stringify(data) : (data as BodyInit),
      });

      const data_ = await res.json().catch(() => ({}));

      if (res.status === 401 && data_.detail == "Invalid or expired token") {
        clearVaultXContext();
        alert("Please log in again.");
        window.location.href = "/";
      }

      if (!res.ok) throw new Error(data_.detail || "Something went wrong.");
      return data_;
    } catch (error) {
      if (
        error instanceof TypeError ||
        (error as Error).message === "Failed to fetch"
      ) {
        throw new NetworkError("Server unreachable. Please try again later.");
      }
      throw error;
    }
  },

  get: async (endpoint: string, token?: string, extraHeaders?: Record<string, string>) => {
    try {
      const res = await fetch(`/api/${endpoint}`, {
        headers: {
          Accept: "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(extraHeaders || {}),
        },
      });

      const data_ = await res.json().catch(() => ({}));

      if (res.status === 401 && data_.detail == "Invalid or expired token") {
        clearVaultXContext();
        alert("Please log in again.");
        window.location.href = "/";
      }

      if (!res.ok) throw new Error(data_.detail || "Something went wrong.");
      return data_;
    } catch (error) {
      if (
        error instanceof TypeError ||
        (error as Error).message === "Failed to fetch"
      ) {
        throw new NetworkError("Server unreachable. Please try again later.");
      }
      throw error;
    }
  },

  /**
   * GET a download endpoint, returning the raw Response so callers can
   * stream large file bodies or issue Range requests.
   */
  getRaw: async (
    endpoint: string,
    token?: string,
    range?: string,
    extraHeaders?: Record<string, string>,
  ) => {
    try {
      const headers: Record<string, string> = {
        Accept: "application/octet-stream",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(extraHeaders || {}),
      };
      if (range) {
        headers["Range"] = range;
      }

      const res = await fetch(`/api/${endpoint}`, { headers });

      if (res.status === 401) {
        const data_ = await res.json().catch(() => ({}));
        if (data_.detail == "Invalid or expired token") {
          clearVaultXContext();
          alert("Please log in again.");
          window.location.href = "/";
        }
      }

      if (!res.ok) {
        const data_ = await res.json().catch(() => ({}));
        throw new Error(data_.detail || "Something went wrong.");
      }
      return res;
    } catch (error) {
      if (
        error instanceof TypeError ||
        (error as Error).message === "Failed to fetch"
      ) {
        throw new NetworkError("Server unreachable. Please try again later.");
      }
      throw error;
    }
  },

  delete: async (endpoint: string, token?: string) => {
    try {
      const res = await fetch(`/api/${endpoint}`, {
        method: "DELETE",
        headers: {
          Accept: "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });

      const data_ = await res.json().catch(() => ({}));


      if (res.status === 401 && data_.detail === "Invalid or expired token") {
        clearVaultXContext();
        alert("Please log in again.");
        window.location.href = "/";
      }

      if (!res.ok) throw new Error(data_.detail || "Something went wrong.");
      return data_;
    } catch (error) {
      if (
        error instanceof TypeError ||
        (error as Error).message === "Failed to fetch"
      ) {
        throw new NetworkError("Server unreachable. Please try again later.");
      }
      throw error;
    }
  },
};
