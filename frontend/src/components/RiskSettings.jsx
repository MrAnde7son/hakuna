import React, { useState, useEffect, useCallback } from 'react'
import { Trash2, RefreshCw, AlertTriangle, Plus } from 'lucide-react'
import { getRiskConfig, saveRiskConfig, recalculateRisk, getRuleEngineCatalog } from '../api.js'
import RuleBuilder from './RuleBuilder.jsx'

// ─── Finding weight labels ─────────────────────────────────────────────────────

const FINDING_WEIGHT_LABELS = {
  severity:       { label: 'CVSS Severity',           desc: 'CVSS score (v3 preferred, v2 fallback), normalized 0–10' },
  intel:          { label: 'Threat Intel (VPR)',       desc: 'Nessus VPR score, normalized 0–10' },
  exploitability: { label: 'Exploitability',           desc: 'Exploit availability, maturity, and zero-day flag' },
  criticality:    { label: 'Asset Criticality',        desc: 'Criticality level of the affected asset (1–5)' },
  family:         { label: 'Plugin Family Risk',       desc: 'Risk signal from the Nessus plugin family' },
  controls:       { label: 'Compensating Controls',    desc: 'Penalty when AV/firewall absent on the asset' },
  reachability:   { label: 'Network Reachability',     desc: 'Established connections on the asset (lateral movement)' },
}
import { Card } from './ui.jsx'

// ─── Constants ────────────────────────────────────────────────────────────────

const WEIGHT_LABELS = {
  severity:       { label: 'Technical Severity',       desc: 'Weighted average of finding severity levels' },
  exploitability: { label: 'Exploitability',           desc: 'Exploit availability, maturity, and VPR score' },
  intel:          { label: 'Threat Intelligence',      desc: 'Highest VPR / CVE intel score for the asset' },
  criticality:    { label: 'Asset Criticality',        desc: 'User-defined or auto-assigned criticality (1–5)' },
  controls:       { label: 'Compensating Controls',    desc: 'Penalty when AV/firewall controls are absent' },
  reachability:   { label: 'Network Reachability',     desc: 'Established outbound connections (lateral movement)' },
}

const SEV_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
const SEV_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d', info: '#0ea5e9' }

// Migrate an old-format rule {field, op, value, criticality} → new compound format
function migrateRule(rule) {
  if (rule.conditions) return rule
  return {
    conditions: [{ field: rule.field || 'environment_tag', op: rule.op || 'eq', value: rule.value ?? null }],
    logic: 'AND',
    criticality: rule.criticality || 3,
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function weightTotal(weights) {
  return Object.values(weights).reduce((s, v) => s + parseFloat(v || 0), 0)
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function WeightRow({ id, value, label, desc, onChange }) {
  const pct = Math.round(parseFloat(value || 0) * 100)
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr 60px', gap: 12, alignItems: 'center', marginBottom: 10 }}>
      <div>
        <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{label}</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{desc}</div>
      </div>
      <input
        type="range" min={0} max={1} step={0.01}
        value={parseFloat(value || 0)}
        onChange={e => onChange(parseFloat(e.target.value))}
        style={{ accentColor: 'var(--accent)', width: '100%' }}
      />
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)', textAlign: 'right' }}>
        {pct}%
      </div>
    </div>
  )
}

function SeverityScoreRow({ id, value, label, color, onChange }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr 52px', gap: 10, alignItems: 'center', marginBottom: 8 }}>
      <span style={{ fontSize: 13, fontWeight: 600, color }}>{label}</span>
      <input
        type="range" min={0} max={10} step={0.5}
        value={parseFloat(value || 0)}
        onChange={e => onChange(parseFloat(e.target.value))}
        style={{ accentColor: color, width: '100%' }}
      />
      <input
        type="number" min={0} max={10} step={0.5}
        value={parseFloat(value || 0)}
        onChange={e => onChange(parseFloat(e.target.value))}
        style={{
          width: 52, padding: '3px 6px', borderRadius: 5, border: '1px solid var(--border)',
          background: 'var(--bg)', color: 'var(--text)', fontSize: 13, textAlign: 'center',
        }}
      />
    </div>
  )
}

function CritMultRow({ level, value, onChange }) {
  const colors = { 1: '#0ea5e9', 2: '#65a30d', 3: '#d97706', 4: '#ea580c', 5: '#dc2626' }
  const c = colors[level] || 'var(--text)'
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '36px 1fr 64px', gap: 10, alignItems: 'center', marginBottom: 6 }}>
      <span style={{ fontSize: 13, fontWeight: 700, color: c, textAlign: 'center' }}>{level}</span>
      <input
        type="range" min={0.1} max={3} step={0.05}
        value={parseFloat(value || 1)}
        onChange={e => onChange(parseFloat(e.target.value))}
        style={{ accentColor: c, width: '100%' }}
      />
      <span style={{ fontSize: 13, fontWeight: 600, color: c, textAlign: 'right' }}>×{parseFloat(value || 1).toFixed(2)}</span>
    </div>
  )
}

const CRIT_COLORS = { 1: '#0ea5e9', 2: '#65a30d', 3: '#d97706', 4: '#ea580c', 5: '#dc2626' }

function RuleCard({ rule, index, onChange, onDelete, catalog }) {
  const criticality = rule.criticality || 3
  const critColor   = CRIT_COLORS[criticality] || 'var(--text)'

  return (
    <Card style={{ marginBottom: 12 }}>
      {/* Rule header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>Rule {index + 1}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
            Match conditions below to assign criticality to an asset.
          </div>
        </div>
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Assign criticality</span>
        <select
          value={criticality}
          onChange={e => onChange({ ...rule, criticality: parseInt(e.target.value) })}
          style={{ ...selStyle, width: 60, fontWeight: 700, color: critColor }}
        >
          {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
        <button onClick={onDelete} style={iconBtnStyle} title="Delete rule">
          <Trash2 size={13} color="#ef4444" />
        </button>
      </div>

      {/* Conditions label */}
      <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 8 }}>
        Conditions
      </label>

      {/* Conditions via shared RuleBuilder */}
      <RuleBuilder
        conditions={rule.conditions || []}
        logic={rule.logic || 'AND'}
        catalog={catalog}
        onChange={(conditions, logic) => onChange({ ...rule, conditions, logic })}
        showLogic
        addLabel="Add Condition"
      />
    </Card>
  )
}

const selStyle = {
  padding: '4px 8px', borderRadius: 5, border: '1px solid var(--border)',
  background: 'var(--bg)', color: 'var(--text)', fontSize: 12,
}
const inputStyle = {
  padding: '4px 8px', borderRadius: 5, border: '1px solid var(--border)',
  background: 'var(--bg)', color: 'var(--text)', fontSize: 12,
}
const iconBtnStyle = {
  display: 'flex', alignItems: 'center', padding: '4px 6px',
  borderRadius: 5, border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer',
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function RiskSettings({ onSave }) {
  const [cfg, setCfg]           = useState(null)
  const [catalog, setCatalog]   = useState(null)
  const [saving, setSaving]     = useState(false)
  const [saved, setSaved]       = useState(false)
  const [running, setRunning]   = useState(false)
  const [runResult, setRunResult] = useState(null)
  const [error, setError]       = useState(null)

  useEffect(() => {
    Promise.all([getRiskConfig(), getRuleEngineCatalog()])
      .then(([cfgData, cat]) => {
        setCatalog(cat)
        setCfg({
          ...cfgData,
          criticality_rules: (cfgData.criticality_rules || []).map(migrateRule),
        })
      })
      .catch(e => setError(e.message))
  }, [])

  const setWeights = useCallback((key, val) => {
    setCfg(p => ({ ...p, formula_weights: { ...p.formula_weights, [key]: val } }))
  }, [])

  const setFindingWeights = useCallback((key, val) => {
    setCfg(p => ({ ...p, finding_formula_weights: { ...p.finding_formula_weights, [key]: val } }))
  }, [])

  const setSevScore = useCallback((key, val) => {
    setCfg(p => ({ ...p, severity_scores: { ...p.severity_scores, [key]: val } }))
  }, [])

  const setCritMult = useCallback((level, val) => {
    setCfg(p => ({ ...p, criticality_multipliers: { ...p.criticality_multipliers, [String(level)]: val } }))
  }, [])

  const addRule = () => {
    setCfg(p => ({
      ...p,
      criticality_rules: [
        ...(p.criticality_rules || []),
        { conditions: [{ field: 'environment_tag', op: 'eq', value: '' }], logic: 'AND', criticality: 4 },
      ],
    }))
  }

  const updateRule = useCallback((idx, rule) => {
    setCfg(p => {
      const rules = [...p.criticality_rules]
      rules[idx] = rule
      return { ...p, criticality_rules: rules }
    })
  }, [])

  const deleteRule = useCallback((idx) => {
    setCfg(p => ({ ...p, criticality_rules: p.criticality_rules.filter((_, i) => i !== idx) }))
  }, [])

  const handleSave = async () => {
    setSaving(true)
    setSaved(false)
    try {
      await saveRiskConfig(cfg)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
      onSave?.()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleRecalculate = async (applyCrit, recalcFindings = false) => {
    setRunning(true)
    setRunResult(null)
    try {
      const result = await recalculateRisk(null, applyCrit, recalcFindings)
      setRunResult(result)
    } catch (e) {
      setRunResult({ error: e.message })
    } finally {
      setRunning(false)
    }
  }

  if (!cfg) {
    return <div style={{ padding: 24, fontSize: 14, color: 'var(--text-muted)' }}>{error || 'Loading…'}</div>
  }

  const total = weightTotal(cfg.formula_weights || {})
  const weightsOk = Math.abs(total - 1.0) < 0.01
  const findingTotal = weightTotal(cfg.finding_formula_weights || {})
  const findingWeightsOk = Math.abs(findingTotal - 1.0) < 0.01

  return (
    <div>
      {error && (
        <div style={{ marginBottom: 16, padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, fontSize: 13, color: '#fca5a5' }}>
          {error}
        </div>
      )}

      {/* ── Formula Weights ── */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Formula Weights</div>
          <div style={{ fontSize: 12, fontWeight: 600, color: weightsOk ? '#86efac' : '#fca5a5', display: 'flex', alignItems: 'center', gap: 5 }}>
            {!weightsOk && <AlertTriangle size={12} />}
            Total: {Math.round(total * 100)}%{!weightsOk && ' (should be 100%)'}
          </div>
        </div>
        {Object.entries(WEIGHT_LABELS).map(([key, { label, desc }]) => (
          <WeightRow
            key={key} id={key}
            value={cfg.formula_weights?.[key] ?? 0}
            label={label} desc={desc}
            onChange={val => setWeights(key, val)}
          />
        ))}
      </Card>

      {/* ── Severity Scores ── */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>Severity Base Scores</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
          Raw score (0–10) assigned to each finding severity level before weighting.
        </div>
        {Object.entries(SEV_LABELS).map(([key, label]) => (
          <SeverityScoreRow
            key={key} id={key} label={label}
            color={SEV_COLORS[key]}
            value={cfg.severity_scores?.[key] ?? 0}
            onChange={val => setSevScore(key, val)}
          />
        ))}
      </Card>

      {/* ── Criticality Multipliers ── */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>Criticality Multipliers</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
          Final score multiplier applied based on asset criticality level (1 = lowest, 5 = highest).
        </div>
        {[1, 2, 3, 4, 5].map(level => (
          <CritMultRow
            key={level} level={level}
            value={cfg.criticality_multipliers?.[String(level)] ?? 1.0}
            onChange={val => setCritMult(level, val)}
          />
        ))}
      </Card>

      {/* ── Criticality Auto-Rules ── */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Criticality Auto-Rules</div>
          <button onClick={addRule} style={{
            display: 'flex', alignItems: 'center', gap: 5, padding: '5px 10px', borderRadius: 6,
            fontSize: 12, border: '1px solid var(--accent)', background: 'transparent',
            color: 'var(--accent)', cursor: 'pointer',
          }}>
            <Plus size={12} /> Add Rule
          </button>
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
          Automatically assign criticality when a scan is uploaded. Rules match asset properties.
        </div>

        {/* Rule mode + toggle */}
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', marginRight: 8 }}>When multiple rules match:</span>
            {['first_match', 'last_match', 'max'].map(mode => (
              <button key={mode} onClick={() => setCfg(p => ({ ...p, criticality_rule_mode: mode }))}
                style={{
                  fontSize: 12, padding: '3px 10px', borderRadius: 6, cursor: 'pointer', marginRight: 5,
                  border: `1px solid ${cfg.criticality_rule_mode === mode ? 'var(--accent)' : 'var(--border)'}`,
                  background: cfg.criticality_rule_mode === mode ? 'rgba(99,102,241,0.15)' : 'transparent',
                  color: cfg.criticality_rule_mode === mode ? 'var(--accent)' : 'var(--text-muted)',
                }}>
                {mode === 'first_match' ? 'First match' : mode === 'last_match' ? 'Last match' : 'Highest'}
              </button>
            ))}
          </div>
        </div>

        {/* Toggle auto-apply */}
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginBottom: 14 }}>
          <div
            onClick={() => setCfg(p => ({ ...p, auto_apply_rules_on_upload: !p.auto_apply_rules_on_upload }))}
            style={{
              width: 36, height: 20, borderRadius: 10, position: 'relative', cursor: 'pointer', flexShrink: 0,
              background: cfg.auto_apply_rules_on_upload ? 'var(--accent)' : 'var(--border)',
              transition: 'background 0.2s',
            }}
          >
            <div style={{
              position: 'absolute', top: 2, left: cfg.auto_apply_rules_on_upload ? 18 : 2,
              width: 16, height: 16, borderRadius: '50%', background: '#fff', transition: 'left 0.2s',
            }} />
          </div>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Apply rules automatically on upload
          </span>
        </label>

        {/* Rules list */}
        {(cfg.criticality_rules || []).length === 0 ? (
          <div style={{
            padding: '12px', textAlign: 'center', background: 'var(--bg-secondary)',
            borderRadius: 8, border: '1px dashed var(--border)',
            fontSize: 12, color: 'var(--text-muted)',
          }}>
            No rules yet — click "Add Rule" to create one.
          </div>
        ) : (
          (cfg.criticality_rules || []).map((rule, idx) => (
            <RuleCard
              key={idx} rule={rule} index={idx}
              catalog={catalog}
              onChange={r => updateRule(idx, r)}
              onDelete={() => deleteRule(idx)}
            />
          ))
        )}
      </Card>

      {/* ── Finding Priority Score Weights ── */}
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Finding Priority Score Weights</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              Controls how each factor contributes to an individual finding's priority score (0–10).
            </div>
          </div>
          <div style={{ fontSize: 12, fontWeight: 600, color: findingWeightsOk ? '#86efac' : '#fca5a5', display: 'flex', alignItems: 'center', gap: 5 }}>
            {!findingWeightsOk && <AlertTriangle size={12} />}
            Total: {Math.round(findingTotal * 100)}%{!findingWeightsOk && ' (should be 100%)'}
          </div>
        </div>
        <div style={{ marginTop: 14 }}>
          {Object.entries(FINDING_WEIGHT_LABELS).map(([key, { label, desc }]) => (
            <WeightRow
              key={key} id={key}
              value={cfg.finding_formula_weights?.[key] ?? 0}
              label={label} desc={desc}
              onChange={val => setFindingWeights(key, val)}
            />
          ))}
        </div>
      </Card>

      {/* ── Actions ── */}
      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 12 }}>Apply Changes</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            onClick={handleSave}
            disabled={saving || !weightsOk || !findingWeightsOk}
            style={{
              padding: '7px 16px', borderRadius: 6, fontSize: 13,
              cursor: saving || !weightsOk || !findingWeightsOk ? 'not-allowed' : 'pointer',
              border: '1px solid var(--accent)', background: 'var(--accent)', color: '#fff',
              opacity: saving || !weightsOk || !findingWeightsOk ? 0.6 : 1,
            }}
          >
            {saving ? 'Saving…' : saved ? 'Saved!' : 'Save Config'}
          </button>

          <button
            onClick={() => handleRecalculate(false)}
            disabled={running}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 6,
              fontSize: 13, cursor: running ? 'not-allowed' : 'pointer',
              border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)',
              opacity: running ? 0.6 : 1,
            }}
          >
            <RefreshCw size={13} /> {running ? 'Running…' : 'Recalculate Asset Scores'}
          </button>

          <button
            onClick={() => handleRecalculate(false, true)}
            disabled={running}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 6,
              fontSize: 13, cursor: running ? 'not-allowed' : 'pointer',
              border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)',
              opacity: running ? 0.6 : 1,
            }}
          >
            <RefreshCw size={13} /> Recalculate All (Assets + Findings)
          </button>

          <button
            onClick={() => handleRecalculate(true, true)}
            disabled={running}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 6,
              fontSize: 13, cursor: running ? 'not-allowed' : 'pointer',
              border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)',
              opacity: running ? 0.6 : 1,
            }}
          >
            <RefreshCw size={13} /> Recalculate + Apply Criticality Rules
          </button>

          {runResult && !runResult.error && (
            <span style={{ fontSize: 12, color: '#86efac' }}>
              Updated {runResult.updated_assets} asset{runResult.updated_assets !== 1 ? 's' : ''}
              {runResult.updated_findings > 0 && `, ${runResult.updated_findings} finding${runResult.updated_findings !== 1 ? 's' : ''}`}
            </span>
          )}
          {runResult?.error && (
            <span style={{ fontSize: 12, color: '#fca5a5' }}>{runResult.error}</span>
          )}
        </div>
        {(!weightsOk || !findingWeightsOk) && (
          <div style={{ marginTop: 10, fontSize: 12, color: '#fca5a5', display: 'flex', alignItems: 'center', gap: 5 }}>
            <AlertTriangle size={12} /> Adjust weights to total 100% before saving.
          </div>
        )}
      </Card>
    </div>
  )
}
