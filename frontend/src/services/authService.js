import { frontendConfig } from './config.js'

const SESSION_KEY = 'cyber-triage:session'
export function getSession() {
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)) } catch { return null }
}
export function signOut() {
  try { sessionStorage.removeItem(SESSION_KEY) } catch { /* storage may be unavailable */ }
  globalThis.window?.dispatchEvent(new Event('session-changed'))
}
export async function authenticate({ investigatorId, apiToken = '' }) {
  signOut()
  const token = apiToken.trim()
  let response
  try {
    response = await fetch(`${frontendConfig.apiBase}/session`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
  } catch { throw new Error('Unable to reach Flask. Start the backend and check the API connection.') }
  const body = await response.json()
  if (!response.ok) throw new Error(body.error?.message || 'Authentication failed.')
  const session = { investigatorId: investigatorId.trim(), apiToken: token,
    signedInAt: new Date().toISOString(), authMode: body.authMode }
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)) }
  catch { throw new Error('Session storage is unavailable. Enable browser storage to sign in.') }
  globalThis.window?.dispatchEvent(new Event('session-changed'))
  return session
}
export function getInvestigatorLabel() {
  return getSession()?.investigatorId?.toUpperCase() || 'Workspace operator'
}
