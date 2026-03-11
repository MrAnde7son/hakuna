import { useState, useRef, useCallback, useEffect } from 'react'
import { nlpSearch } from '../api'

const EXAMPLES = [
  'critical Windows servers with exploits',
  'high severity findings in DMZ',
  'quick wins with CVE in KEV',
  'Linux assets with more than 3 critical findings',
  'ransomware-linked vulnerabilities',
  'SLA breached high risk assets',
]

const CHIP_STYLE = (color) => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  padding: '2px 8px',
  borderRadius: 12,
  fontSize: 11,
  fontWeight: 600,
  background: `${color}22`,
  color: color,
  border: `1px solid ${color}44`,
  whiteSpace: 'nowrap',
})

/**
 * NLPSearchBar — natural-language query bar that parses the query server-side
 * and calls onResult with { asset_filters, finding_filters, sort, explanation }.
 *
 * Props:
 *   scanId       — current scan id (optional, narrows counts)
 *   onResult     — ({ asset_filters, finding_filters, sort, explanation }) => void
 *   onClear      — () => void  (called when query is cleared)
 *   placeholder  — override default placeholder
 *   autoFocus    — boolean
 */
export default function NLPSearchBar({ scanId, onResult, onClear, placeholder, autoFocus }) {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [chips, setChips] = useState([])
  const [counts, setCounts] = useState(null)
  const [error, setError] = useState(null)
  const [showExamples, setShowExamples] = useState(false)
  const debounceRef = useRef(null)
  const inputRef = useRef(null)

  const runSearch = useCallback(async (q) => {
    if (!q.trim()) {
      setChips([])
      setCounts(null)
      setError(null)
      onClear?.()
      return
    }
    setLoading(true)
    setError(null)
    try {
      const result = await nlpSearch(q.trim(), scanId)
      setChips(result.explanation || [])
      setCounts({ assets: result.asset_count, findings: result.finding_count })
      onResult?.({
        asset_filters: result.asset_filters,
        finding_filters: result.finding_filters,
        sort: result.sort,
        explanation: result.explanation,
      })
    } catch (e) {
      setError('Search failed')
    } finally {
      setLoading(false)
    }
  }, [scanId, onResult, onClear])

  const handleChange = (e) => {
    const val = e.target.value
    setQuery(val)
    clearTimeout(debounceRef.current)
    if (!val.trim()) {
      setChips([])
      setCounts(null)
      onClear?.()
      return
    }
    debounceRef.current = setTimeout(() => runSearch(val), 500)
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      clearTimeout(debounceRef.current)
      runSearch(query)
    }
    if (e.key === 'Escape') {
      handleClear()
    }
  }

  const handleClear = () => {
    setQuery('')
    setChips([])
    setCounts(null)
    setError(null)
    onClear?.()
    inputRef.current?.focus()
  }

  const handleExample = (ex) => {
    setQuery(ex)
    setShowExamples(false)
    runSearch(ex)
  }

  useEffect(() => {
    if (autoFocus) inputRef.current?.focus()
  }, [autoFocus])

  useEffect(() => () => clearTimeout(debounceRef.current), [])

  const hasResult = chips.length > 0

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      {/* Input row */}
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        {/* Sparkle icon */}
        <span style={{
          position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)',
          fontSize: 15, pointerEvents: 'none', userSelect: 'none',
          opacity: loading ? 0.5 : 1,
        }}>
          {loading ? '⏳' : '✨'}
        </span>

        <input
          ref={inputRef}
          value={query}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onFocus={() => setShowExamples(!hasResult && !query)}
          onBlur={() => setTimeout(() => setShowExamples(false), 150)}
          placeholder={placeholder || 'Ask anything: "critical Windows servers with exploits in DMZ"'}
          style={{
            flex: 1,
            background: 'var(--bg-card)',
            border: hasResult ? '1px solid #6366f144' : '1px solid var(--border)',
            borderRadius: 8,
            color: 'var(--text-primary)',
            padding: '9px 36px 9px 34px',
            fontSize: 13,
            outline: 'none',
            boxShadow: hasResult ? '0 0 0 3px #6366f115' : 'none',
            transition: 'all 0.15s',
          }}
        />

        {query && (
          <button
            onClick={handleClear}
            style={{
              position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', fontSize: 16, lineHeight: 1,
              padding: '2px 4px',
            }}
            title="Clear"
          >×</button>
        )}
      </div>

      {/* Examples dropdown — floats over content */}
      {showExamples && !query && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 4px)', left: 0, right: 0,
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '6px 0',
          boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
          zIndex: 200,
        }}>
          <div style={{ padding: '4px 12px 6px', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Try an example
          </div>
          {EXAMPLES.map(ex => (
            <button
              key={ex}
              onMouseDown={() => handleExample(ex)}
              style={{
                display: 'block', width: '100%', textAlign: 'left',
                padding: '6px 12px', background: 'none', border: 'none',
                color: 'var(--text-primary)', cursor: 'pointer', fontSize: 13,
              }}
              onMouseEnter={e => e.target.style.background = 'var(--bg-hover)'}
              onMouseLeave={e => e.target.style.background = 'none'}
            >
              <span style={{ marginRight: 6, opacity: 0.5 }}>✨</span>{ex}
            </button>
          ))}
        </div>
      )}

      {/* Interpreted chips + counts — floats below input as a popover */}
      {hasResult && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 4px)', left: 0,
          display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '5px 10px',
          boxShadow: '0 4px 12px rgba(0,0,0,0.25)',
          zIndex: 200,
          maxWidth: '600px',
        }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>Interpreted as:</span>
          {chips.map((chip, i) => (
            <span key={i} style={CHIP_STYLE(chip.color)}>
              <span style={{ opacity: 0.7 }}>{chip.label}:</span>
              <span>{chip.value}</span>
            </span>
          ))}
          {counts && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', marginLeft: 4 }}>
              — {counts.assets} asset{counts.assets !== 1 ? 's' : ''} · {counts.findings} finding{counts.findings !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}

      {error && (
        <span style={{ position: 'absolute', top: 'calc(100% + 4px)', left: 0, fontSize: 12, color: '#ef4444', zIndex: 200 }}>{error}</span>
      )}
    </div>
  )
}
