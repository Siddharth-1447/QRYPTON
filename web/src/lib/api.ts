/** Shared backend origin for scan, dashboard, and persisted report requests. */
export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export function accessHeaders(): Record<string, string> {
  const token = typeof window === "undefined" ? null : sessionStorage.getItem("qrypton.access-token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function workspaceRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}/api/v1${path}`, {
    ...init, headers: { "Content-Type": "application/json", ...accessHeaders(), ...init?.headers },
    signal: init?.signal ?? AbortSignal.timeout(15000), cache: "no-store",
  });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed");
  return data as T;
}
