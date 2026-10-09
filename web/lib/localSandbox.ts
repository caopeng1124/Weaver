import { getApiBaseUrl } from './api'

export function sandboxHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {}
  const token = sessionStorage.getItem('weaver.sandboxToken') || ''
  const apiKey = sessionStorage.getItem('weaver.internalApiKey') || ''
  return { ...(token ? { 'X-Weaver-Sandbox-Token': token } : {}),
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) }
}

export async function sandboxRequest(path: string, method = 'GET', body?: unknown) {
  const response = await fetch(`${getApiBaseUrl()}/api/local-sandbox${path}`, {
    method, headers: { 'Content-Type': 'application/json', ...sandboxHeaders() },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {})
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.detail || '沙箱请求失败')
  return data
}
