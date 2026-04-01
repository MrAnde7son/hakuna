import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Building2, Users, Target, Wrench, Bot, Route, BarChart3, Link,
  ShieldCheck, ArrowRight, ArrowLeft, Check, Loader2, Sparkles,
  ChevronRight, Globe,
} from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  getOnboardingOptions,
  getOnboardingStatus,
  getOnboardingRecommendations,
  applyOnboardingPackages,
  getOnboardingDomainInfo,
} from '../../api.js'

// ── Icon map for objectives ─────────────────────────────────────
const ICON_MAP = {
  target: Target,
  wrench: Wrench,
  bot: Bot,
  route: Route,
  'bar-chart': BarChart3,
  link: Link,
  'shield-check': ShieldCheck,
  building: Building2,
}

// ── Step indicator ──────────────────────────────────────────────
function StepIndicator({ steps, current }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, marginBottom: 32 }}>
      {steps.map((s, i) => {
        const done = i < current
        const active = i === current
        return (
          <React.Fragment key={s.id}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, minWidth: 80 }}>
              <div style={{
                width: 32, height: 32, borderRadius: '50%',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 13, fontWeight: 700,
                background: done ? '#16a34a' : active ? 'var(--accent)' : 'var(--bg-secondary)',
                color: done || active ? '#fff' : 'var(--text-muted)',
                transition: 'all 0.2s',
              }}>
                {done ? <Check size={15} /> : i + 1}
              </div>
              <span style={{
                fontSize: 11, fontWeight: active ? 700 : 500,
                color: active ? 'var(--text-primary)' : 'var(--text-muted)',
              }}>
                {s.label}
              </span>
            </div>
            {i < steps.length - 1 && (
              <div style={{
                flex: 1, height: 2, maxWidth: 60,
                background: done ? '#16a34a' : 'var(--border)',
                marginBottom: 22,
                transition: 'background 0.2s',
              }} />
            )}
          </React.Fragment>
        )
      })}
    </div>
  )
}

// ── Selectable card ─────────────────────────────────────────────
function SelectCard({ selected, onClick, children, style = {} }) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        border: `2px solid ${selected ? 'var(--accent)' : hovered ? 'var(--text-muted)' : 'var(--border)'}`,
        borderRadius: 10,
        padding: '14px 16px',
        cursor: 'pointer',
        background: selected ? 'color-mix(in srgb, var(--accent) 8%, var(--bg-primary))' : 'var(--bg-primary)',
        transition: 'all 0.15s',
        position: 'relative',
        ...style,
      }}
    >
      {selected && (
        <div style={{
          position: 'absolute', top: 8, right: 8,
          width: 20, height: 20, borderRadius: '50%',
          background: 'var(--accent)', display: 'flex',
          alignItems: 'center', justifyContent: 'center',
        }}>
          <Check size={12} color="#fff" />
        </div>
      )}
      {children}
    </div>
  )
}

// ── Step 1: Organization Profile ────────────────────────────────
function StepOrgProfile({ data, onChange, options, domainInfo }) {
  return (
    <div>
      <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4, color: 'var(--text-primary)' }}>
        Tell us about your organization
      </h2>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 24 }}>
        This helps us tailor Hakuna to your needs.
      </p>

      {domainInfo?.enriched && (
        <div style={{
          padding: '10px 14px', borderRadius: 8,
          background: 'color-mix(in srgb, var(--accent) 10%, var(--bg-secondary))',
          border: '1px solid var(--accent)',
          marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8,
          fontSize: 13,
        }}>
          <Globe size={16} color="var(--accent)" />
          <span>Detected corporate domain: <strong>{domainInfo.domain}</strong></span>
        </div>
      )}

      <div style={{ marginBottom: 20 }}>
        <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 8 }}>
          Organization name
        </label>
        <input
          type="text"
          value={data.org_name || ''}
          onChange={e => onChange({ ...data, org_name: e.target.value })}
          placeholder="Acme Corp"
          style={{
            width: '100%', padding: '10px 14px', borderRadius: 8,
            border: '1px solid var(--border)', background: 'var(--bg-primary)',
            color: 'var(--text-primary)', fontSize: 14, outline: 'none',
            boxSizing: 'border-box',
          }}
        />
      </div>

      <div style={{ marginBottom: 20 }}>
        <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 8 }}>
          Industry
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
          {(options?.industries || []).map(ind => (
            <SelectCard
              key={ind.id}
              selected={data.industry === ind.id}
              onClick={() => onChange({ ...data, industry: ind.id })}
            >
              <span style={{ fontSize: 13, fontWeight: 600 }}>{ind.label}</span>
            </SelectCard>
          ))}
        </div>
      </div>

      <div>
        <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 8 }}>
          Organization size
        </label>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {(options?.org_sizes || []).map(s => (
            <SelectCard
              key={s.id}
              selected={data.org_size === s.id}
              onClick={() => onChange({ ...data, org_size: s.id })}
              style={{ flex: '1 1 120px' }}
            >
              <span style={{ fontSize: 13, fontWeight: 600 }}>{s.label}</span>
            </SelectCard>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Step 2: Team Profile ────────────────────────────────────────
function StepTeamProfile({ data, onChange, options }) {
  const toggleFn = (fnId) => {
    const fns = data.team_functions || []
    const next = fns.includes(fnId) ? fns.filter(f => f !== fnId) : [...fns, fnId]
    onChange({ ...data, team_functions: next })
  }

  return (
    <div>
      <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4, color: 'var(--text-primary)' }}>
        Tell us about your team
      </h2>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 24 }}>
        We'll set up roles, tags, and ownership rules to match your team structure.
      </p>

      <div style={{ marginBottom: 20 }}>
        <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 8 }}>
          Security team size
        </label>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {(options?.team_sizes || []).map(s => (
            <SelectCard
              key={s.id}
              selected={data.team_size === s.id}
              onClick={() => onChange({ ...data, team_size: s.id })}
              style={{ flex: '1 1 100px' }}
            >
              <span style={{ fontSize: 13, fontWeight: 600 }}>{s.label}</span>
            </SelectCard>
          ))}
        </div>
      </div>

      <div>
        <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 8 }}>
          What functions does your team cover? <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(select all that apply)</span>
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8 }}>
          {(options?.team_functions || []).map(fn => (
            <SelectCard
              key={fn.id}
              selected={(data.team_functions || []).includes(fn.id)}
              onClick={() => toggleFn(fn.id)}
            >
              <span style={{ fontSize: 13, fontWeight: 600 }}>{fn.label}</span>
            </SelectCard>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Step 3: Objectives ──────────────────────────────────────────
function StepObjectives({ data, onChange, options }) {
  const toggleObj = (objId) => {
    const objs = data.objectives || []
    const next = objs.includes(objId) ? objs.filter(o => o !== objId) : [...objs, objId]
    onChange({ ...data, objectives: next })
  }

  return (
    <div>
      <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4, color: 'var(--text-primary)' }}>
        What are you trying to achieve?
      </h2>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 24 }}>
        Select your goals and we'll configure Hakuna with the right tools, reports, and automations.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
        {(options?.objectives || []).map(obj => {
          const Icon = ICON_MAP[obj.icon] || Target
          const selected = (data.objectives || []).includes(obj.id)
          return (
            <SelectCard
              key={obj.id}
              selected={selected}
              onClick={() => toggleObj(obj.id)}
              style={{ padding: '16px 18px' }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8,
                  background: selected ? 'var(--accent)' : 'var(--bg-secondary)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0, transition: 'background 0.15s',
                }}>
                  <Icon size={18} color={selected ? '#fff' : 'var(--text-muted)'} />
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4, color: 'var(--text-primary)' }}>
                    {obj.label}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    {obj.description}
                  </div>
                </div>
              </div>
            </SelectCard>
          )
        })}
      </div>
    </div>
  )
}

// ── Step 4: Package Recommendations ─────────────────────────────
function StepPackages({ recommendations, selectedPkgs, onToggle }) {
  const pkgs = recommendations?.packages || {}
  const entries = Object.entries(pkgs)

  const provisionLabels = {
    tags: 'Tags',
    auto_tag_rules: 'Auto-tag rules',
    sla_preset: 'SLA policies',
    campaigns: 'Campaign templates',
    agents: 'AI Agents',
    reports: 'Report templates',
    roles: 'RBAC roles',
  }

  if (entries.length === 0) {
    return (
      <div>
        <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4, color: 'var(--text-primary)' }}>
          Review your setup
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>
          Select at least one objective to see recommended packages.
        </p>
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4, color: 'var(--text-primary)' }}>
        Your personalized setup
      </h2>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 8 }}>
        Based on your objectives, we'll automatically configure these packages. Toggle any you don't need.
      </p>
      {recommendations?.sla_note && (
        <div style={{
          padding: '10px 14px', borderRadius: 8, marginBottom: 16,
          background: 'color-mix(in srgb, var(--accent) 10%, var(--bg-secondary))',
          fontSize: 13, color: 'var(--text-secondary)',
        }}>
          {recommendations.sla_note}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {entries.map(([id, pkg]) => {
          const selected = selectedPkgs.includes(id)
          const provisions = pkg.provisions || {}
          return (
            <SelectCard
              key={id}
              selected={selected}
              onClick={() => onToggle(id)}
              style={{ padding: '16px 20px' }}
            >
              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {pkg.label}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
                  {pkg.description}
                </div>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {Object.entries(provisions).map(([key, val]) => {
                  if (!val) return null
                  const label = provisionLabels[key] || key
                  const count = Array.isArray(val) ? val.length : (typeof val === 'string' ? 1 : null)
                  return (
                    <span key={key} style={{
                      fontSize: 11, fontWeight: 600,
                      padding: '3px 8px', borderRadius: 6,
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-secondary)',
                    }}>
                      {label}{count ? ` (${count})` : ''}
                    </span>
                  )
                })}
              </div>
            </SelectCard>
          )
        })}
      </div>
    </div>
  )
}

// ── Step 5: Applying / Done ─────────────────────────────────────
function StepApply({ applying, result, error }) {
  if (error) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 0' }}>
        <div style={{ fontSize: 40, marginBottom: 16 }}>Something went wrong</div>
        <p style={{ color: 'var(--danger)', fontSize: 14 }}>{error}</p>
      </div>
    )
  }

  if (applying) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 0' }}>
        <Loader2 size={40} color="var(--accent)" style={{ animation: 'spin 1s linear infinite', marginBottom: 16 }} />
        <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
          Setting up your workspace...
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>
          Creating tags, campaigns, agents, reports, and more.
        </p>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>
    )
  }

  if (result) {
    const items = [
      { label: 'Tags', count: result.tags },
      { label: 'Auto-tag rules', count: result.auto_tag_rules },
      { label: 'SLA policies', count: result.sla_configs },
      { label: 'Campaigns', count: result.campaigns },
      { label: 'AI Agents', count: result.agents },
      { label: 'Reports', count: result.reports },
      { label: 'Roles', count: result.roles },
    ].filter(i => i.count > 0)

    return (
      <div style={{ textAlign: 'center', padding: '40px 0' }}>
        <div style={{
          width: 64, height: 64, borderRadius: '50%',
          background: 'linear-gradient(135deg, #16a34a, #22c55e)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto 20px',
        }}>
          <Sparkles size={28} color="#fff" />
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
          Your workspace is ready!
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 24 }}>
          Here's what we set up for you:
        </p>

        {items.length > 0 && (
          <div style={{
            display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 10,
            marginBottom: 32,
          }}>
            {items.map(item => (
              <div key={item.label} style={{
                padding: '10px 18px', borderRadius: 10,
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--accent)' }}>{item.count}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>{item.label}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return null
}


// ── Main Wizard ─────────────────────────────────────────────────

const STEPS = [
  { id: 'org', label: 'Organization' },
  { id: 'team', label: 'Team' },
  { id: 'objectives', label: 'Objectives' },
  { id: 'packages', label: 'Setup' },
  { id: 'done', label: 'Done' },
]

export default function OnboardingWizard() {
  const navigate = useNavigate()
  const { t } = useTranslation()
  const { user, org } = useAuth()

  const [step, setStep] = useState(0)
  const [options, setOptions] = useState(null)
  const [domainInfo, setDomainInfo] = useState(null)
  const [recommendations, setRecommendations] = useState(null)
  const [selectedPkgs, setSelectedPkgs] = useState([])
  const [applying, setApplying] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const [data, setData] = useState({
    org_name: '',
    industry: null,
    org_size: null,
    team_size: null,
    team_functions: [],
    objectives: [],
  })

  // Load options + check status + domain info on mount
  useEffect(() => {
    Promise.all([
      getOnboardingOptions().catch(() => null),
      getOnboardingStatus().catch(() => null),
      user?.email ? getOnboardingDomainInfo(user.email).catch(() => null) : Promise.resolve(null),
    ]).then(([opts, status, domain]) => {
      if (opts) setOptions(opts)
      if (domain) setDomainInfo(domain)

      // Pre-fill org name
      const orgName = org?.name || (domain?.enriched ? domain.org_name_guess : '') || ''
      setData(d => ({ ...d, org_name: orgName }))

      // If already completed, redirect
      if (status?.completed) {
        navigate('/', { replace: true })
        return
      }
      setLoading(false)
    })
  }, [])

  // Fetch recommendations when moving to packages step
  const fetchRecommendations = useCallback(async () => {
    try {
      const recs = await getOnboardingRecommendations({
        industry: data.industry,
        org_size: data.org_size,
        team_size: data.team_size,
        team_functions: data.team_functions,
        objectives: data.objectives,
      })
      setRecommendations(recs)
      setSelectedPkgs(Object.keys(recs.packages || {}))
    } catch {}
  }, [data])

  const handleNext = async () => {
    if (step === 2) {
      // Moving from objectives → packages: fetch recommendations
      await fetchRecommendations()
    }
    if (step === 3) {
      // Apply packages
      setStep(4)
      setApplying(true)
      setError(null)
      try {
        const res = await applyOnboardingPackages({
          industry: data.industry,
          org_size: data.org_size,
          team_size: data.team_size,
          team_functions: data.team_functions,
          objectives: data.objectives,
          selected_packages: selectedPkgs,
        })
        setResult(res.created)
      } catch (err) {
        setError(err.message || 'Failed to apply packages')
      } finally {
        setApplying(false)
      }
      return
    }
    setStep(s => Math.min(s + 1, STEPS.length - 1))
  }

  const handleBack = () => setStep(s => Math.max(s - 1, 0))

  const handleFinish = () => navigate('/', { replace: true })

  const togglePkg = (id) => {
    setSelectedPkgs(prev => prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id])
  }

  const canNext = () => {
    if (step === 0) return true // org profile is optional
    if (step === 1) return true // team profile is optional
    if (step === 2) return (data.objectives || []).length > 0
    if (step === 3) return selectedPkgs.length > 0
    return false
  }

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center',
        justifyContent: 'center', background: 'var(--bg-muted)',
      }}>
        <Loader2 size={32} color="var(--accent)" style={{ animation: 'spin 1s linear infinite' }} />
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>
    )
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-muted)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      padding: '40px 20px',
    }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 32 }}>
        <div style={{
          fontSize: 28, fontWeight: 900, color: 'var(--text-primary)',
          letterSpacing: '-0.02em',
        }}>
          Welcome to Hakuna
        </div>
        <div style={{ fontSize: 14, color: 'var(--text-muted)', marginTop: 4 }}>
          Let's set up your workspace in a few quick steps.
        </div>
      </div>

      {/* Card */}
      <div style={{
        width: '100%', maxWidth: 720,
        background: 'var(--bg-primary)',
        borderRadius: 14,
        border: '1px solid var(--border)',
        boxShadow: '0 4px 24px rgba(0,0,0,0.08)',
        padding: '32px 36px',
      }}>
        <StepIndicator steps={STEPS} current={step} />

        {/* Step content */}
        {step === 0 && (
          <StepOrgProfile data={data} onChange={setData} options={options} domainInfo={domainInfo} />
        )}
        {step === 1 && (
          <StepTeamProfile data={data} onChange={setData} options={options} />
        )}
        {step === 2 && (
          <StepObjectives data={data} onChange={setData} options={options} />
        )}
        {step === 3 && (
          <StepPackages
            recommendations={recommendations}
            selectedPkgs={selectedPkgs}
            onToggle={togglePkg}
          />
        )}
        {step === 4 && (
          <StepApply applying={applying} result={result} error={error} />
        )}

        {/* Navigation buttons */}
        <div style={{
          display: 'flex', justifyContent: 'space-between',
          alignItems: 'center', marginTop: 32,
          paddingTop: 20, borderTop: '1px solid var(--border)',
        }}>
          <div>
            {step > 0 && step < 4 && (
              <button
                onClick={handleBack}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '10px 18px', borderRadius: 8,
                  border: '1px solid var(--border)', background: 'var(--bg-primary)',
                  color: 'var(--text-secondary)', fontWeight: 600, fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                <ArrowLeft size={14} /> Back
              </button>
            )}
            {step === 0 && (
              <button
                onClick={() => navigate('/', { replace: true })}
                style={{
                  padding: '10px 18px', borderRadius: 8,
                  border: '1px solid var(--border)', background: 'var(--bg-primary)',
                  color: 'var(--text-muted)', fontWeight: 600, fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                Skip for now
              </button>
            )}
          </div>

          <div>
            {step < 4 && (
              <button
                onClick={handleNext}
                disabled={!canNext()}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '10px 22px', borderRadius: 8,
                  border: 'none',
                  background: canNext() ? 'var(--accent)' : 'var(--bg-secondary)',
                  color: canNext() ? '#fff' : 'var(--text-muted)',
                  fontWeight: 700, fontSize: 13,
                  cursor: canNext() ? 'pointer' : 'not-allowed',
                  transition: 'all 0.15s',
                }}
              >
                {step === 3 ? 'Apply & Set Up' : 'Continue'}
                <ArrowRight size={14} />
              </button>
            )}
            {step === 4 && !applying && (
              <button
                onClick={handleFinish}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '10px 22px', borderRadius: 8,
                  border: 'none',
                  background: 'var(--accent)',
                  color: '#fff',
                  fontWeight: 700, fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                Go to Dashboard <ChevronRight size={14} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
