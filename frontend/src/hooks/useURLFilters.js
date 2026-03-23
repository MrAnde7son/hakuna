import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * Generic hook that syncs filter/sort/page state with URL search params.
 *
 * @param {Object} schema - Describes each param.  Key = param name.
 *   Each value: { default, type: 'string'|'number'|'boolean' }
 *   `type` controls parsing; omit for string (the default).
 *
 * @returns {{ filters, setFilter, setFilters, clearFilters, resetPage }}
 *   - filters: object whose keys match schema, values parsed from URL
 *   - setFilter(key, value): sets one param (resets `page` to 1 unless key === 'page')
 *   - setFilters(obj): bulk-set multiple params at once (resets page)
 *   - clearFilters(): removes all params
 *   - resetPage(): convenience to set page=1
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

  // Set a single filter value; resets page unless the key IS page
  const setFilter = useCallback((key, value) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (value === null || value === undefined || value === '' || value === false) {
        next.delete(key)
      } else {
        next.set(key, String(value))
      }
      if (key !== pageKey) next.delete(pageKey)
      return next
    }, { replace: true })
  }, [setSearchParams])

  // Bulk-set multiple params at once
  const setFilters = useCallback((obj) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      let pageReset = false
      for (const [key, value] of Object.entries(obj)) {
        if (value === null || value === undefined || value === '' || value === false) {
          next.delete(key)
        } else {
          next.set(key, String(value))
        }
        if (key !== 'page') pageReset = true
      }
      if (pageReset) next.delete('page')
      return next
    }, { replace: true })
  }, [setSearchParams])

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
      next.delete('page')
      return next
    }, { replace: true })
  }, [setSearchParams])

  return { filters, setFilter, setFilters, clearFilters, resetPage }
}
