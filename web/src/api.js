const TOKEN_KEY = 'subadmin_token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(token) {
  if (!token) {
    localStorage.removeItem(TOKEN_KEY)
    return
  }
  localStorage.setItem(TOKEN_KEY, token)
}

export async function apiRequest(path, options = {}) {
  const token = getToken()
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const response = await fetch(path, {
    credentials: 'include',
    ...options,
    headers
  })

  const text = await response.text()
  let payload = null

  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }

  if (!response.ok) {
    const message =
      (payload && typeof payload === 'object' && payload.error) ||
      response.statusText ||
      'request failed'
    throw new Error(message)
  }

  return payload
}

export async function login(username, password) {
  const result = await apiRequest('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  })
  if (result?.token) {
    setToken(result.token)
  }
  return result
}

export async function logout() {
  try {
    await apiRequest('/api/logout', { method: 'POST' })
  } finally {
    setToken('')
  }
}
