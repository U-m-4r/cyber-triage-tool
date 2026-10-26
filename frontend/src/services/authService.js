/**
 * Prototype session handling.
 *
 * The investigator label remains a prototype. An optional operator-supplied API
 * token is kept for this browser session and checked by the backend on requests.
 * This is not user identity or case authorization; those belong to Phase 2.
 */

const SESSION_KEY = 'cyber-triage:session'

/** @returns {{ investigatorId: string, signedInAt: string } | null} */
export function getSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

/**
 * Records a prototype session. Resolves after a short delay so the login
 * button's pending state is visible — the real call will be async too.
 */
export function authenticate({ investigatorId, apiToken = '' }) {
  const session = {
    investigatorId: investigatorId.trim(),
    signedInAt: new Date().toISOString(),
    apiToken: apiToken.trim(),
  }

  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(session))
      } catch {
        // Private-mode storage failure is not fatal for a prototype.
      }
      resolve(session)
    }, 450)
  })
}

export function signOut() {
  try {
    sessionStorage.removeItem(SESSION_KEY)
  } catch {
    // no-op
  }
}

/** Falls back to a placeholder so the shell renders if /dashboard is hit directly. */
export function getInvestigatorLabel() {
  const session = getSession()
  if (!session?.investigatorId) return 'INV-0000'
  return session.investigatorId.toUpperCase()
}
