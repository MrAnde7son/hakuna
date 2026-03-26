import { useState, useEffect } from 'react'
import { getNewSinceCounts, recordPageVisit } from '../api'

/**
 * Hook that returns the count of new items since the user's last visit to a page.
 * Automatically records the visit after fetching the count.
 *
 * @param {string} pageKey - e.g. "findings", "assets", "threat_intel", "campaigns:3"
 * @returns {{ count: number, dismiss: () => void }}
 */
export function useNewSince(pageKey) {
  const [count, setCount] = useState(0)

  useEffect(() => {
    if (!pageKey) return
    let cancelled = false

    getNewSinceCounts(pageKey)
      .then(data => {
        if (!cancelled) setCount(data[pageKey] || 0)
        // Record the visit after fetching (fire-and-forget)
        recordPageVisit(pageKey).catch(() => {})
      })
      .catch(() => {})

    return () => { cancelled = true }
  }, [pageKey])

  const dismiss = () => setCount(0)

  return { count, dismiss }
}
