import { useEffect, useState } from 'react'
import { get } from '../services/apiClient.js'

export default function useApi(path, revision = 0) {
  const [state, setState] = useState({ data: null, loading: true, error: null })
  useEffect(() => {
    const controller = new AbortController()
    setState({ data: null, loading: Boolean(path), error: null })
    if (path) get(path, { signal: controller.signal }).then((data) => {
      if (!controller.signal.aborted) setState({ data, loading: false, error: null })
    }).catch((error) => {
      if (!controller.signal.aborted) setState({ data: null, loading: false, error: error.message })
    })
    return () => controller.abort()
  }, [path, revision])
  return state
}
