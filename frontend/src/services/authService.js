/**
 * Prototype session handling.
 *
 * There is no authentication in Phase 1 and none on the Flask backend either.
 * This stores the submitted investigator ID so the top bar can show a session
 * indicator, and nothing more. It is NOT a security boundary — swap this whole
 * module for a real token exchange when auth lands.
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
export function authenticate({ investigatorId }) {
  const session = {
    investigatorId: investigatorId.trim(),
    signedInAt: new Date().toISOString(),
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
