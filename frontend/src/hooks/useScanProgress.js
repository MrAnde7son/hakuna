import { useEffect, useRef, useState, useCallback } from 'react'
import { getScanStatus } from '../api.js'

// Poll cadence while a scan is actively running. VM scanner imports per-job
// and EASM streams incrementally, so 3s gives a responsive feel without
// hammering the backend. Once the scan is terminal we stop polling entirely.
const ACTIVE_POLL_MS = 3000

// Statuses that mean the scan is still producing data. We treat anything not
// in TERMINAL_STATUSES as "live" so newer statuses the backend might emit
// (e.g. "queued", "importing") don't accidentally stop the poll.
const TERMINAL_STATUSES = new Set(['completed', 'completed_with_errors', 'failed'])

/**
 * Poll GET /api/scans/{scan_id} while the scan is running. Returns progress
 * metadata and a monotonically-increasing tick the caller can use to trigger
 * its own list refresh (e.g. re-fetch findings when a new target completes).
 *
 *  - null scanId → no polling, no progress
 *  - terminal scan → one-time fetch, then idle
 *  - running scan → poll every ACTIVE_POLL_MS until it flips terminal
 *
 * Returned shape:
 *   { progress, status, loading, refreshTick, refresh() }
 * where refreshTick is bumped after every successful poll that observed
 * forward movement (more targets done or more incremental rows).
 */
export default function useScanProgress(scanId) {
  const [progress, setProgress] = useState(null)
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(false)
  const [refreshTick, setRefreshTick] = useState(0)

  // Track the last observed "progress fingerprint" so we only tick when
  // something actually changed — prevents pointlessly re-rendering downstream
  // lists on every poll even when the scan is idle-but-running.
  const lastFingerprintRef = useRef('')

  const fetchStatus = useCallback(async () => {
    if (!scanId) return null
    try {
      const data = await getScanStatus(scanId)
      setStatus(data?.status || null)
      setProgress(data?.progress || null)

      const fingerprint = JSON.stringify({
        s: data?.status,
        a: data?.asset_count,
        f: data?.finding_count,
        cj: data?.progress?.completed_jobs,
        si: data?.progress?.stage_index,
        ia: data?.progress?.incremental_asset_count,
        ifx: data?.progress?.incremental_finding_count,
      })
      if (fingerprint !== lastFingerprintRef.current) {
        lastFingerprintRef.current = fingerprint
        setRefreshTick(t => t + 1)
      }
      return data
    } catch {
      // Swallow — the scan card will surface errors via its own path.
      return null
    }
  }, [scanId])

  // One-shot load whenever scanId changes, so consumers see status quickly.
  useEffect(() => {
    if (!scanId) {
      setProgress(null)
      setStatus(null)
      lastFingerprintRef.current = ''
      return
    }
    setLoading(true)
    fetchStatus().finally(() => setLoading(false))
  }, [scanId, fetchStatus])

  // Live poll while running — stopped as soon as status flips terminal.
  useEffect(() => {
    if (!scanId) return
    if (status && TERMINAL_STATUSES.has(status)) return
    const id = setInterval(() => { fetchStatus() }, ACTIVE_POLL_MS)
    return () => clearInterval(id)
  }, [scanId, status, fetchStatus])

  const isRunning = status && !TERMINAL_STATUSES.has(status)

  return { progress, status, loading, refreshTick, isRunning, refresh: fetchStatus }
}
