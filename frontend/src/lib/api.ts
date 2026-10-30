// Fetch wrapper for the ThreatMapper FastAPI backend. Every request attaches the JWT from localStorage('token').
export const API_BASE_URL = (
  (import.meta.env["VITE_API_BASE_URL"] as string | undefined) ?? "http://localhost:8000"
).replace(/\/$/, "");

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function friendly(status: number, detail: string | undefined) {
  if (status === 401) return detail || "Not authorized. Please sign in again.";
  if (status === 403) return detail || "You don't have access to this resource.";
  if (status === 404) return detail || "Not found.";
  if (status >= 500) return detail || "Server error. Please try again later.";
  return detail || `Request failed (${status})`;
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, `Cannot reach the server at ${API_BASE_URL}. Is it running, with CORS enabled?`);
  }
  if (!res.ok) {
    let detail: string | undefined;
    try {
      const j = await res.json();
      if (typeof j.detail === "string") detail = j.detail;
      else if (Array.isArray(j.detail)) detail = j.detail.map((d: { msg?: string }) => d.msg).filter(Boolean).join("; ");
      else if (typeof j.message === "string") detail = j.message;
    } catch {
      /* ignore */
    }
    // Only a 401 on an authenticated request means the session is gone (login itself returns 401 for bad credentials).
    if (res.status === 401 && token && typeof window !== "undefined") {
      window.dispatchEvent(new Event("tm:unauthorized"));
    }
    throw new ApiError(res.status, friendly(res.status, detail));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const post = <T,>(path: string, body: unknown) =>
  api<T>(path, { method: "POST", body: JSON.stringify(body) });
