/** Demo fixtures are opt-in and never a fallback for a failed backend. */
export function readFrontendConfig(env = {}) {
  const apiBase = (env.VITE_API_BASE_URL || '/api').replace(/\/$/, '')
  if (!(apiBase.startsWith('/') && !apiBase.startsWith('//')) && !/^https?:\/\//.test(apiBase)) {
    throw new Error('VITE_API_BASE_URL must be a relative path or HTTP(S) URL.')
  }
  if (env.VITE_DEMO_MODE && !['true', 'false'].includes(env.VITE_DEMO_MODE)) {
    throw new Error('VITE_DEMO_MODE must be true or false.')
  }
  return { apiBase, demoMode: env.VITE_DEMO_MODE === 'true' }
}

export const frontendConfig = readFrontendConfig(import.meta.env ?? {})
