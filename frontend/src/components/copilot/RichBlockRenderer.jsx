/**
 * RichBlockRenderer — OpenUI-like generative UI for the copilot.
 *
 * The LLM outputs fenced code blocks with language "richblock" containing JSON.
 * This component parses the JSON and renders interactive Recharts charts,
 * data tables, stat cards, progress bars, and KPI widgets inline in chat.
 *
 * Supported block types:
 *   bar_chart, pie_chart, line_chart, area_chart
 *   data_table, stat_cards, kpi, progress_bar, finding_list
 */
import React, { useState, useMemo } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, PieChart, Pie, Cell, Legend,
  LineChart, Line, AreaChart, Area,
} from 'recharts'
import {
  ArrowUp, ArrowDown, Minus, ChevronUp, ChevronDown,
  AlertTriangle, Shield, ShieldAlert, Info, AlertCircle,
} from 'lucide-react'


// ── Color palette ────────────────────────────────────────────────────

const CHART_COLORS = [
  'var(--accent)', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6',
  '#06b6d4', '#ec4899', '#14b8a6', '#f97316', '#6366f1',
]

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
}

const SEVERITY_ICONS = {
  critical: ShieldAlert,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Shield,
  info: Info,
}


// ── Shared styles ────────────────────────────────────────────────────

const blockWrapper = {
  margin: '8px 0',
  borderRadius: 8,
  border: '1px solid var(--border)',
  background: 'var(--bg-card, var(--bg-secondary))',
  overflow: 'hidden',
}

const blockTitle = {
  fontSize: 12,
  fontWeight: 600,
  color: 'var(--text)',
  padding: '8px 12px 4px',
}

const blockSubtitle = {
  fontSize: 10,
  color: 'var(--text-muted)',
  padding: '0 12px 6px',
}


// ── Custom tooltip ───────────────────────────────────────────────────

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'var(--bg)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '6px 10px', fontSize: 11, boxShadow: '0 2px 8px rgba(0,0,0,.12)',
    }}>
      <div style={{ fontWeight: 600, marginBottom: 2 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: p.color, flexShrink: 0 }} />
          {p.name}: <strong>{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</strong>
        </div>
      ))}
    </div>
  )
}


// ── Bar Chart ────────────────────────────────────────────────────────

function RichBarChart({ data, xKey, yKeys, title, subtitle, height = 220, stacked }) {
  if (!data?.length || !xKey) return null
  const keys = yKeys || Object.keys(data[0]).filter(k => k !== xKey)
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      {subtitle && <div style={blockSubtitle}>{subtitle}</div>}
      <div style={{ padding: '4px 8px 8px' }}>
        <ResponsiveContainer width="100%" height={height}>
          <BarChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey={xKey} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <Tooltip content={<ChartTooltip />} />
            {keys.length > 1 && <Legend wrapperStyle={{ fontSize: 10 }} />}
            {keys.map((key, i) => (
              <Bar
                key={key}
                dataKey={key}
                fill={SEVERITY_COLORS[key.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]}
                stackId={stacked ? 'stack' : undefined}
                radius={stacked ? 0 : [3, 3, 0, 0]}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}


// ── Pie Chart ────────────────────────────────────────────────────────

function RichPieChart({ data, nameKey, valueKey, title, subtitle, height = 220 }) {
  if (!data?.length) return null
  const nk = nameKey || 'name'
  const vk = valueKey || 'value'
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      {subtitle && <div style={blockSubtitle}>{subtitle}</div>}
      <div style={{ padding: '4px 8px 8px' }}>
        <ResponsiveContainer width="100%" height={height}>
          <PieChart>
            <Pie
              data={data}
              dataKey={vk}
              nameKey={nk}
              cx="50%"
              cy="50%"
              outerRadius={75}
              innerRadius={40}
              paddingAngle={2}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              labelLine={{ stroke: 'var(--text-muted)', strokeWidth: 1 }}
              style={{ fontSize: 10 }}
            >
              {data.map((entry, i) => (
                <Cell
                  key={i}
                  fill={SEVERITY_COLORS[entry[nk]?.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]}
                />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}


// ── Line Chart ───────────────────────────────────────────────────────

function RichLineChart({ data, xKey, yKeys, title, subtitle, height = 220 }) {
  if (!data?.length || !xKey) return null
  const keys = yKeys || Object.keys(data[0]).filter(k => k !== xKey)
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      {subtitle && <div style={blockSubtitle}>{subtitle}</div>}
      <div style={{ padding: '4px 8px 8px' }}>
        <ResponsiveContainer width="100%" height={height}>
          <LineChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey={xKey} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <Tooltip content={<ChartTooltip />} />
            {keys.length > 1 && <Legend wrapperStyle={{ fontSize: 10 }} />}
            {keys.map((key, i) => (
              <Line
                key={key}
                type="monotone"
                dataKey={key}
                stroke={CHART_COLORS[i % CHART_COLORS.length]}
                strokeWidth={2}
                dot={{ r: 3 }}
                activeDot={{ r: 5 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}


// ── Area Chart ───────────────────────────────────────────────────────

function RichAreaChart({ data, xKey, yKeys, title, subtitle, height = 220 }) {
  if (!data?.length || !xKey) return null
  const keys = yKeys || Object.keys(data[0]).filter(k => k !== xKey)
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      {subtitle && <div style={blockSubtitle}>{subtitle}</div>}
      <div style={{ padding: '4px 8px 8px' }}>
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey={xKey} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
            <Tooltip content={<ChartTooltip />} />
            {keys.map((key, i) => (
              <Area
                key={key}
                type="monotone"
                dataKey={key}
                stroke={CHART_COLORS[i % CHART_COLORS.length]}
                fill={CHART_COLORS[i % CHART_COLORS.length]}
                fillOpacity={0.15}
                strokeWidth={2}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}


// ── Stat Cards ───────────────────────────────────────────────────────

function RichStatCards({ cards, title }) {
  if (!cards?.length) return null
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      <div style={{
        display: 'grid',
        gridTemplateColumns: `repeat(${Math.min(cards.length, 4)}, 1fr)`,
        gap: 8, padding: '6px 10px 10px',
      }}>
        {cards.map((card, i) => {
          const trendColor = card.trend === 'up' ? '#22c55e' : card.trend === 'down' ? '#ef4444' : 'var(--text-muted)'
          const TrendIcon = card.trend === 'up' ? ArrowUp : card.trend === 'down' ? ArrowDown : Minus
          return (
            <div key={i} style={{
              padding: '10px 12px', borderRadius: 6,
              background: 'var(--bg)', border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 500 }}>
                {card.label}
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{
                  fontSize: 20, fontWeight: 700,
                  color: card.color || SEVERITY_COLORS[card.severity?.toLowerCase()] || 'var(--text)',
                }}>
                  {typeof card.value === 'number' ? card.value.toLocaleString() : card.value}
                </span>
                {card.change != null && (
                  <span style={{ fontSize: 10, color: trendColor, display: 'flex', alignItems: 'center', gap: 2 }}>
                    <TrendIcon size={10} />
                    {card.change}
                  </span>
                )}
              </div>
              {card.subtitle && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{card.subtitle}</div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}


// ── KPI (single big number) ─────────────────────────────────────────

function RichKPI({ label, value, change, trend, subtitle, color }) {
  const trendColor = trend === 'up' ? '#22c55e' : trend === 'down' ? '#ef4444' : 'var(--text-muted)'
  const TrendIcon = trend === 'up' ? ArrowUp : trend === 'down' ? ArrowDown : Minus
  return (
    <div style={{ ...blockWrapper, padding: '12px 16px', textAlign: 'center' }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || 'var(--text)' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {change != null && (
        <div style={{ fontSize: 11, color: trendColor, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 3, marginTop: 4 }}>
          <TrendIcon size={12} />
          {change}
        </div>
      )}
      {subtitle && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>{subtitle}</div>}
    </div>
  )
}


// ── Progress Bar ─────────────────────────────────────────────────────

function RichProgressBar({ items, title }) {
  if (!items?.length) return null
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      <div style={{ padding: '4px 12px 10px', display: 'flex', flexDirection: 'column', gap: 8 }}>
        {items.map((item, i) => {
          const pct = Math.min(100, Math.max(0, item.percent || 0))
          const barColor = pct >= 80 ? '#22c55e' : pct >= 50 ? '#f59e0b' : pct >= 25 ? '#f97316' : '#ef4444'
          return (
            <div key={i}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text)' }}>{item.label}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {item.detail || `${pct}%`}
                </span>
              </div>
              <div style={{
                height: 6, borderRadius: 3, background: 'var(--bg-muted, var(--border))', overflow: 'hidden',
              }}>
                <div style={{
                  width: `${pct}%`, height: '100%', borderRadius: 3,
                  background: item.color || barColor,
                  transition: 'width 0.4s ease',
                }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}


// ── Data Table ───────────────────────────────────────────────────────

function RichDataTable({ columns, rows, title, subtitle }) {
  const [sortCol, setSortCol] = useState(null)
  const [sortDir, setSortDir] = useState('asc')

  const cols = useMemo(() => {
    if (columns) return columns
    if (rows?.length) return Object.keys(rows[0]).map(k => ({ key: k, label: k }))
    return []
  }, [columns, rows])

  const sorted = useMemo(() => {
    if (!rows?.length || !sortCol) return rows || []
    return [...rows].sort((a, b) => {
      const av = a[sortCol], bv = b[sortCol]
      if (av == null) return 1
      if (bv == null) return -1
      const cmp = typeof av === 'number' ? av - bv : String(av).localeCompare(String(bv))
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [rows, sortCol, sortDir])

  if (!sorted.length) return null

  const handleSort = (key) => {
    if (sortCol === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(key); setSortDir('asc') }
  }

  const cellColor = (val) => {
    if (typeof val !== 'string') return undefined
    const lv = val.toLowerCase()
    return SEVERITY_COLORS[lv] || undefined
  }

  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      {subtitle && <div style={blockSubtitle}>{subtitle}</div>}
      <div style={{ overflowX: 'auto', padding: '0 0 4px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr>
              {cols.map(col => {
                const key = col.key || col
                const label = col.label || col
                return (
                  <th
                    key={key}
                    onClick={() => handleSort(key)}
                    style={{
                      padding: '6px 10px', textAlign: 'left', fontWeight: 600,
                      background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)',
                      cursor: 'pointer', whiteSpace: 'nowrap', userSelect: 'none',
                      color: sortCol === key ? 'var(--accent)' : 'var(--text)',
                    }}
                  >
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                      {label}
                      {sortCol === key && (sortDir === 'asc' ? <ChevronUp size={10} /> : <ChevronDown size={10} />)}
                    </span>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, ri) => (
              <tr key={ri} style={{ background: ri % 2 === 0 ? 'transparent' : 'var(--bg-secondary)' }}>
                {cols.map(col => {
                  const key = col.key || col
                  const val = row[key]
                  return (
                    <td key={key} style={{
                      padding: '5px 10px', borderBottom: '1px solid var(--border)',
                      color: cellColor(val) || 'var(--text)',
                      fontWeight: cellColor(val) ? 600 : 400,
                    }}>
                      {val != null ? String(val) : '—'}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}


// ── Finding List ─────────────────────────────────────────────────────

function RichFindingList({ findings, title }) {
  if (!findings?.length) return null
  return (
    <div style={blockWrapper}>
      {title && <div style={blockTitle}>{title}</div>}
      <div style={{ padding: '4px 10px 8px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {findings.map((f, i) => {
          const sev = (f.severity || 'info').toLowerCase()
          const SevIcon = SEVERITY_ICONS[sev] || Info
          return (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px',
              borderRadius: 6, background: 'var(--bg)', border: '1px solid var(--border)',
            }}>
              <SevIcon size={14} style={{ color: SEVERITY_COLORS[sev], flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.name || f.title}
                </div>
                {f.detail && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{f.detail}</div>}
              </div>
              <span style={{
                fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                padding: '2px 6px', borderRadius: 4,
                color: SEVERITY_COLORS[sev], background: SEVERITY_COLORS[sev] + '18',
              }}>
                {f.severity || 'info'}
              </span>
              {f.score != null && (
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', minWidth: 24, textAlign: 'right' }}>
                  {f.score}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}


// ── Error fallback ───────────────────────────────────────────────────

function RichBlockError({ raw, error }) {
  return (
    <pre style={{
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      borderRadius: 6, padding: 8, overflowX: 'auto', fontSize: 11,
      fontFamily: 'monospace', margin: '6px 0', color: 'var(--text)',
    }}>
      <code>{raw}</code>
    </pre>
  )
}


// ── Main dispatcher ──────────────────────────────────────────────────

const BLOCK_RENDERERS = {
  bar_chart: RichBarChart,
  pie_chart: RichPieChart,
  line_chart: RichLineChart,
  area_chart: RichAreaChart,
  stat_cards: RichStatCards,
  kpi: RichKPI,
  progress_bar: RichProgressBar,
  data_table: RichDataTable,
  finding_list: RichFindingList,
}

/**
 * Attempt to parse and render a rich block from a code fence.
 * Returns the rendered component, or null if this isn't a rich block.
 */
export function tryRenderRichBlock(language, rawContent) {
  if (!language || !language.startsWith('richblock')) return null

  try {
    const json = JSON.parse(rawContent)
    const blockType = json.type || language.split(':')[1]
    const Renderer = BLOCK_RENDERERS[blockType]
    if (!Renderer) return null
    return <Renderer {...json} />
  } catch (e) {
    // If it starts with richblock but JSON is invalid, show error fallback
    return <RichBlockError raw={rawContent} error={e.message} />
  }
}

export default tryRenderRichBlock
