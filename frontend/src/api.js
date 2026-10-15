const API_BASE = import.meta.env.VITE_API_BASE_URL || ""
const WARDEN_API_BASE = import.meta.env.VITE_WARDEN_API_BASE_URL || ""

export async function api(path, options = {}) {
  const token = sessionStorage.getItem("hinderman_token")
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed (${response.status})`)
  }
  return response.json()
}

export async function login(userId, password) {
  const result = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, password }),
  })
  sessionStorage.setItem("hinderman_token", result.access_token)
  return result.user
}

export async function chatWithWarden(prompt) {
  const response = await fetch(`${WARDEN_API_BASE}/gateway/v1/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: "demo",
      messages: [{ role: "user", content: prompt }],
    }),
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `WARDEN request failed (${response.status})`)
  }

  const result = await response.json()
  if (typeof result.reply !== "string" || !result.gateway_report) {
    throw new Error("WARDEN returned an unexpected response")
  }
  return result
}

export function logout() {
  sessionStorage.removeItem("hinderman_token")
}
