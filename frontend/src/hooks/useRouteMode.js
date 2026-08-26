import { useEffect } from 'react'

/**
 * Marks the document with a route mode so global CSS can react to it.
 *
 * The landing and login routes are fixed full-viewport compositions with no page
 * scroll; the application shell scrolls normally. Rather than locking overflow
 * globally, each cinematic route declares itself and releases the lock on unmount.
 *
 * @param {'cinematic'|null} mode
 */
export default function useRouteMode(mode) {
  useEffect(() => {
    if (!mode) return undefined

    const root = document.documentElement
    const previous = root.dataset.routeMode
    root.dataset.routeMode = mode

    return () => {
      if (previous) {
        root.dataset.routeMode = previous
      } else {
        delete root.dataset.routeMode
      }
    }
  }, [mode])
}
