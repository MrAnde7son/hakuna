import { useState, useEffect } from 'react'
import { getNewSinceCounts, recordPageVisit } from '../api'

/**
 * Hook that returns the count of new items since the user's last visit to a page,
 * plus the last-visited timestamp (ISO string) for use as a filter parameter.
 *
 * @param {string} pageKey - e.g. "findings", "assets", "threat_intel", "campaigns:3"
 * @returns {{ count: number, since: string|null, dismiss: () => void }}
 */
export function useNewSince(pageKey) {
  const [count, setCount] = useState(0)
  const [since, setSince] = useState(null)

  useEffect(() => {
    if (!pageKey) return
    let cancelled = false

    getNewSinceCounts(pageKey)
      .then(data => {
        if (cancelled) return
        // Support both new { counts, timestamps } and legacy flat format
        if (data.counts) {
          setCount(data.counts[pageKey] || 0)
          setSince(data.timestamps?.[pageKey] || null)
        } else {
          setCount(data[pageKey] || 0)
        }
        // Record the visit after fetching (fire-and-forget)
        recordPageVisit(pageKey).catch(() => {})
      })
      .catch(() => {})

    return () => { cancelled = true }
  }, [pageKey])

  const dismiss = () => setCount(0)

  return { count, since, dismiss }
}
