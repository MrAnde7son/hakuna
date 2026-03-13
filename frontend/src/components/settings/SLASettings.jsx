import React, { useState, useEffect } from 'react'
import { Clock, Save, RefreshCw } from 'lucide-react'
import { getSLAConfig, saveSLAConfig, recalculateSLA } from '../../api.js'
import { Card, Button, Spinner } from '../shared/ui.jsx'

const SEV_COLORS = {
  4: '#dc2626',
  3: '#ea580c',
  2: '#d97706',
  1: '#65a30d',
  0: '#6b7280',
}

function NumberInput({ value, onChange, min = 1, max = 3650 }) {
  return (
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={e => onChange(Math.max(min, Math.min(max, Number(e.target.value))))}
      style={{
        width: 72,
        background: 'var(--bg)',
        border: '1px solid var(--border)',
        borderRadius: 6,
        padding: '5px 8px',
        fontSize: 13,
        color: 'var(--text-primary)',
        textAlign: 'center',
      }}
    />
  )
}

function Toggle({ checked, onChange }) {
  return (
    <div
      onClick={() => onChange(!checked)}
      style={{
        width: 36, height: 20, borderRadius: 10, position: 'relative',
        background: checked ? 'var(--accent)' : 'var(--border)',
        transition: 'background 0.2s', cursor: 'pointer', flexShrink: 0,
      }}
    >
      <div style={{
        position: 'absolute', top: 2, left: checked ? 18 : 2,
        width: 16, height: 16, borderRadius: '50%', background: '#fff',
        transition: 'left 0.2s',
      }} />
    </div>
  )
}

export default function SLASettings() {
  const [configs, setConfigs] = useState(null)
  const [saving, setSaving] = useState(false)
  const [recalculating, setRecalculating] = useState(false)
  const [saved, setSaved] = useState(false)
  const [recalcResult, setRecalcResult] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    getSLAConfig()
      .then(setConfigs)
      .catch(e => setError(e.message))
  }, [])

  const updateConfig = (severity, key, value) => {
    setConfigs(prev => prev.map(c =>
      c.severity === severity ? { ...c, [key]: value } : c
    ))
  }

  const handleSave = async () => {
    setSaving(true)
    setSaved(false)
    setError(null)
    try {
      await saveSLAConfig(configs)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleRecalculate = async () => {
    setRecalculating(true)
    setRecalcResult(null)
    try {
      const result = await recalculateSLA()
      setRecalcResult(result)
    } catch (e) {
      setError(e.message)
    } finally {
      setRecalculating(false)
    }
  }

  if (!configs) {
    return error
      ? <div style={{ color: '#fca5a5', fontSize: 13 }}>Error: {error}</div>
      : <Spinner />
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Clock size={16} color="var(--accent)" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>SLA Configuration</span>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {recalcResult && (
            <span style={{ fontSize: 12, color: '#86efac' }}>
              Recalculated {recalcResult.updated_findings} findings
            </span>
          )}
          <Button variant="ghost" size="sm" onClick={handleRecalculate} disabled={recalculating}>
            <RefreshCw size={13} style={{ animation: recalculating ? 'spin 1s linear infinite' : 'none' }} />
            {recalculating ? 'Recalculating…' : 'Recalculate Now'}
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            <Save size={13} />
            {saving ? 'Saving…' : saved ? 'Saved!' : 'Save'}
          </Button>
        </div>
      </div>

      {error && (
        <div style={{
          marginBottom: 16, padding: '10px 14px',
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 6, fontSize: 13, color: '#fca5a5',
        }}>
          {error}
        </div>
      )}

      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
        Set how many days your team has to remediate findings at each severity level.
        The SLA clock starts from the scan upload date.
        Findings within the warning window will be marked <b>at risk</b>.
      </div>

      {/* Column headers */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '140px 1fr 120px 120px 80px',
        gap: 12,
        padding: '0 16px 8px',
        fontSize: 11,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}>
        <span>Severity</span>
        <span>SLA Window</span>
        <span>Days to Fix</span>
        <span>Warn Before</span>
        <span>Enabled</span>
      </div>

      <Card style={{ padding: 0 }}>
        {configs.map((cfg, i) => (
          <div
            key={cfg.severity}
            style={{
              display: 'grid',
              gridTemplateColumns: '140px 1fr 120px 120px 80px',
              gap: 12,
              alignItems: 'center',
              padding: '14px 16px',
              borderBottom: i < configs.length - 1 ? '1px solid var(--border)' : 'none',
              opacity: cfg.is_enabled ? 1 : 0.5,
            }}
          >
            {/* Severity label */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 10, height: 10, borderRadius: '50%',
                background: SEV_COLORS[cfg.severity] || '#6b7280',
                flexShrink: 0,
              }} />
              <span style={{ fontWeight: 600, fontSize: 13, color: SEV_COLORS[cfg.severity] || 'var(--text-primary)' }}>
                {cfg.severity_label}
              </span>
            </div>

            {/* Visual SLA bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                flex: 1, height: 6, background: 'var(--border)',
                borderRadius: 3, overflow: 'hidden', position: 'relative',
              }}>
                {/* warn zone */}
                <div style={{
                  position: 'absolute',
                  right: 0,
                  width: `${Math.min((cfg.warn_days_before / cfg.days_to_remediate) * 100, 50)}%`,
                  height: '100%',
                  background: '#d97706',
                  opacity: 0.4,
                }} />
                {/* green zone */}
                <div style={{
                  width: `${Math.min(((cfg.days_to_remediate - cfg.warn_days_before) / cfg.days_to_remediate) * 100, 100)}%`,
                  height: '100%',
                  background: SEV_COLORS[cfg.severity] || '#6366f1',
                  opacity: 0.6,
                  borderRadius: 3,
                }} />
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                {cfg.days_to_remediate}d window
              </span>
            </div>

            {/* Days to fix input */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <NumberInput
                value={cfg.days_to_remediate}
                onChange={v => updateConfig(cfg.severity, 'days_to_remediate', v)}
              />
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>days</span>
            </div>

            {/* Warn before input */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <NumberInput
                value={cfg.warn_days_before}
                min={1}
                max={cfg.days_to_remediate - 1}
                onChange={v => updateConfig(cfg.severity, 'warn_days_before', v)}
              />
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>days</span>
            </div>

            {/* Enabled toggle */}
            <div>
              <Toggle
                checked={cfg.is_enabled}
                onChange={v => updateConfig(cfg.severity, 'is_enabled', v)}
              />
            </div>
          </div>
        ))}
      </Card>

      <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        {[
          { color: '#16a34a', label: 'On Track', desc: 'Before warning window' },
          { color: '#d97706', label: 'At Risk', desc: 'Within warning window' },
          { color: '#dc2626', label: 'Breached', desc: 'Past SLA deadline' },
        ].map(s => (
          <div key={s.label} style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 14px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 8, fontSize: 12,
          }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: s.color, flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, color: s.color }}>{s.label}</div>
              <div style={{ color: 'var(--text-muted)', marginTop: 1 }}>{s.desc}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
