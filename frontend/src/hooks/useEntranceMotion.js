import { useCallback, useEffect, useRef, useState } from 'react'

const FALLBACK_MS = 3500

/**
 * Drives the landing page's one-shot entrance choreography.
 *
 * While pending, the composition's elements sit at their pre-animation offsets
 * (see LandingPage.css `[data-motion='pending']`). The last element in the
 * timeline calls `onSettled` from its `animationend`; a fallback timer clears the
 * state if that event never fires (e.g. the element was never painted).
 *
 * Users with `prefers-reduced-motion: reduce` skip the timeline entirely.
 */
export default function useEntranceMotion() {
  const prefersReduced =
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

  const [pending, setPending] = useState(!prefersReduced)
  const timerRef = useRef(null)

  const settle = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
    setPending(false)
  }, [])

  useEffect(() => {
    if (!pending) return undefined

    timerRef.current = setTimeout(settle, FALLBACK_MS)
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
    // Intentionally only on mount: the fallback should not restart on re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return {
    /** Spread onto the composition root. */
    motionProps: { 'data-motion': pending ? 'pending' : 'settled' },
    /** Attach to the final element in the timeline. */
    onSettled: settle,
    pending,
  }
}
