const API_BASE = import.meta.env.VITE_API_BASE_URL || ""

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

export function logout() {
  sessionStorage.removeItem("hinderman_token")
}
