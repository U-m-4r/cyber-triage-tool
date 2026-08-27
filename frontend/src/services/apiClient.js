/**
 * Minimal fetch wrapper for the Cyber Triage backend.
 *
 * Base URL resolution:
 *   - `VITE_API_BASE_URL` if set (e.g. a deployed backend origin)
 *   - otherwise `/api`, which the Vite dev server proxies to Flask on :5000
 *     (see vite.config.js)
 *
 * Nothing in Phase 1 calls a mutating endpoint. This exists so that when the
 * real endpoints are wired up, components keep talking to services and never
 * to `fetch` directly.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

export class ApiError extends Error {
  constructor(message, { status, code, payload } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.payload = payload
  }
}

async function parseBody(response) {
  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    return response.json()
  }
  return response.text()
}

/**
 * @param {string} path  Endpoint path relative to the API base, e.g. `/health`.
 * @param {RequestInit & { signal?: AbortSignal }} [options]
 */
export async function request(path, options = {}) {
  let response
  try {
    response = await fetch(`${BASE_URL}${path}`, options)
  } catch (cause) {
    // Network-level failure: backend not running, DNS, offline, aborted.
    throw new ApiError('Unable to reach the Cyber Triage backend.', {
      code: 'NETWORK_ERROR',
      payload: cause,
    })
  }

  const body = await parseBody(response)

  if (!response.ok) {
    // backend/app.py returns either {error: {code, message}} or {error: "..."}.
    const error = typeof body === 'object' && body !== null ? body.error : null
    const message =
      (typeof error === 'object' && error?.message) ||
      (typeof error === 'string' && error) ||
      `Request failed with status ${response.status}`

    throw new ApiError(message, {
      status: response.status,
      code: (typeof error === 'object' && error?.code) || 'HTTP_ERROR',
      payload: body,
    })
  }

  return body
}

export function get(path, options) {
  return request(path, { method: 'GET', ...options })
}

export function postJson(path, data, options) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
    ...options,
  })
}

/** Multipart upload. The backend reads the part named `file`. */
export function postFile(path, file, options = {}) {
  const form = new FormData()
  form.append('file', file)
  if (options.data) {
    for (const [key, value] of Object.entries(options.data)) {
      form.append(key, value)
    }
  }
  return request(path, { method: 'POST', body: form, ...options })
}

export { BASE_URL }
