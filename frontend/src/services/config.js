/** All workspace data comes from the configured Flask API. */
export function readFrontendConfig(env = {}) {
  const apiBase = (env.VITE_API_BASE_URL || '/api').replace(/\/$/, '')
  if (!(apiBase.startsWith('/') && !apiBase.startsWith('//')) && !/^https?:\/\//.test(apiBase)) {
    throw new Error('VITE_API_BASE_URL must be a relative path or HTTP(S) URL.')
  }
  return { apiBase }
}

export const frontendConfig = readFrontendConfig(import.meta.env ?? {})
