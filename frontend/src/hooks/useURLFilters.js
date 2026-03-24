import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * Generic hook that syncs filter/sort/page state with URL search params.
 *
 * Mirrors the inline pattern established in FindingExplorer:
 *   - setFilter deletes param when value is null/undefined/''
 *   - setFilter resets the page param when a non-page filter changes
 *   - clearFilters only removes params defined in the schema
 *
 * @param {Object} schema - Describes each param.  Key = param name.
 *   Each value: { default, type: 'string'|'number'|'boolean' }
 *   `type` controls parsing; omit for string (the default).
 * @param {Object} [options]
 * @param {string} [options.pageKey='page'] - Name of the pagination param.
 */
export default function useURLFilters(schema, { pageKey = 'page' } = {}) {
  const [searchParams, setSearchParams] = useSearchParams()

  // Parse current URL into a typed object
  const filters = useMemo(() => {
    const out = {}
    for (const [key, def] of Object.entries(schema)) {
      const raw = searchParams.get(key)
      if (raw === null || raw === '') {
        out[key] = def.default ?? (def.type === 'number' ? null : def.type === 'boolean' ? null : '')
      } else if (def.type === 'number') {
        out[key] = Number(raw)
      } else if (def.type === 'boolean') {
        out[key] = raw === 'true'
      } else {
        out[key] = raw
      }
    }
    return out
  }, [searchParams, schema])

  // Set a single filter value; resets page unless the key IS page.
  // Matches FindingExplorer: only delete on null/undefined/'', NOT on false.
  const setFilter = useCallback((key, value) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (value === null || value === undefined || value === '') {
        next.delete(key)
      } else {
        next.set(key, String(value))
      }
      if (key !== pageKey) next.delete(pageKey)
      return next
    }, { replace: true })
  }, [setSearchParams, pageKey])

  // Bulk-set multiple params at once
  const setFilters = useCallback((obj) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      let pageReset = false
      for (const [key, value] of Object.entries(obj)) {
        if (value === null || value === undefined || value === '') {
          next.delete(key)
        } else {
          next.set(key, String(value))
        }
        if (key !== pageKey) pageReset = true
      }
      if (pageReset) next.delete(pageKey)
      return next
    }, { replace: true })
  }, [setSearchParams, pageKey])

  // Clear only params defined in the schema (preserves other URL params like ?tab=)
  const clearFilters = useCallback(() => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      for (const key of Object.keys(schema)) {
        next.delete(key)
      }
      return next
    }, { replace: true })
  }, [setSearchParams, schema])

  const resetPage = useCallback(() => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      next.delete(pageKey)
      return next
    }, { replace: true })
  }, [setSearchParams, pageKey])

  return { filters, setFilter, setFilters, clearFilters, resetPage }
}
