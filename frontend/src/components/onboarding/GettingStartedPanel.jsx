import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CheckCircle, ArrowRight, X, ChevronDown, ChevronUp } from 'lucide-react'

const STORAGE_KEY = 'hakuna_getting_started'

const STEPS = [
  {
    id: 'findings',
    title: 'Review your top findings',
    description: 'Prioritized by real-world risk, not just CVSS.',
    cta: 'View Findings',
    path: '/findings?sort_by=priority_score&order=desc',
    emoji: '\u{1F50D}',
  },
  {
    id: 'campaign',
    title: 'Create a remediation campaign',
    description: 'Start with a template like "Quick Wins" or "Patch Tuesday".',
    cta: 'Create Campaign',
    path: '/campaigns',
    emoji: '\u{1F3AF}',
  },
  {
    id: 'assets',
    title: 'Set asset criticality',
    description: 'Tag servers so risk scores reflect your real priorities.',
    cta: 'View Assets',
    path: '/assets',
    emoji: '\u{1F3F7}\uFE0F',
  },
  {
    id: 'integration',
    title: 'Connect your ticketing system',
    description: 'Push findings to Jira or ServiceNow automatically.',
    cta: 'Set up',
    path: '/settings?tab=integrations',
    emoji: '\u{1F517}',
  },
  {
    id: 'team',
    title: 'Invite your team',
    description: 'Add analysts and stakeholders to assign findings.',
    cta: 'Invite',
    path: '/settings?tab=team',
    emoji: '\u{1F465}',
  },
]

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : { completed: [], dismissed: false }
  } catch {
    return { completed: [], dismissed: false }
  }
}

function saveState(s) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)) } catch {}
}

// Circular progress ring
function ProgressRing({ pct, done }) {
  const r = 18
  const circ = 2 * Math.PI * r
  const offset = circ - (pct / 100) * circ
  return (
    <svg width={44} height={44} style={{ transform: 'rotate(-90deg)', flexShrink: 0 }}>
      <circle cx={22} cy={22} r={r} fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth={3} />
      <circle
        cx={22} cy={22} r={r} fill="none"
        stroke={done ? '#4ade80' : '#fff'}
        strokeWidth={3}
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.4s ease' }}
      />
    </svg>
  )
}

export default function GettingStartedPanel() {
  const navigate = useNavigate()
  const [state, setState] = useState(loadState)
  const [collapsed, setCollapsed] = useState(() => loadState().completed.length > 0)

  if (state.dismissed) return null

  const { completed } = state
  const completedCount = completed.length
  const totalCount = STEPS.length
  const allDone = completedCount === totalCount
  const progressPct = Math.round((completedCount / totalCount) * 100)

  const update = (nextState) => { setState(nextState); saveState(nextState) }

  const toggleStep = (id) => {
    const next = completed.includes(id) ? completed.filter(s => s !== id) : [...completed, id]
    update({ ...state, completed: next })
  }

  const handleStepCta = (step) => {
    if (!completed.includes(step.id)) toggleStep(step.id)
    navigate(step.path)
  }

  return (
    <div style={{
      position: 'sticky',
      top: 0,
      zIndex: 50,
      margin: '-18px -18px 16px -18px',
      boxShadow: '0 4px 24px rgba(0,0,0,0.18)',
    }}>
      {/* ── Gradient header ────────────────────────────────── */}
      <div
        onClick={() => setCollapsed(c => !c)}
        style={{
          background: allDone
            ? 'linear-gradient(135deg, #15803d, #16a34a)'
            : 'linear-gradient(135deg, #4f46e5, #7c3aed)',
          padding: '12px 20px',
          cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: 14,
        }}
      >
        {/* Progress ring */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <ProgressRing pct={progressPct} done={allDone} />
          <div style={{
            position: 'absolute', inset: 0, display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            fontSize: 10, fontWeight: 800, color: '#fff',
          }}>
            {completedCount}/{totalCount}
          </div>
        </div>

        {/* Title */}
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: '#fff', marginBottom: 2 }}>
            {allDone ? 'You\'re all set!' : 'Get started with Hakuna'}
          </div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)' }}>
            {allDone
              ? 'All setup steps completed.'
              : `${totalCount - completedCount} step${totalCount - completedCount !== 1 ? 's' : ''} left to complete your setup`}
          </div>
        </div>

        {/* Collapse + dismiss */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <button
            onClick={e => { e.stopPropagation(); setCollapsed(c => !c) }}
            style={{
              background: 'rgba(255,255,255,0.15)', border: 'none', borderRadius: 7,
              color: '#fff', cursor: 'pointer', padding: '4px 6px',
              display: 'flex', alignItems: 'center',
            }}
          >
            {collapsed ? <ChevronDown size={15} /> : <ChevronUp size={15} />}
          </button>
          <button
            onClick={e => { e.stopPropagation(); update({ ...state, dismissed: true }) }}
            style={{
              background: 'rgba(255,255,255,0.15)', border: 'none', borderRadius: 7,
              color: '#fff', cursor: 'pointer', padding: '4px 6px',
              display: 'flex', alignItems: 'center',
            }}
            title="Dismiss"
          >
            <X size={15} />
          </button>
        </div>
      </div>

      {/* ── Steps grid ─────────────────────────────────────── */}
      {!collapsed && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: 1,
          backgroundColor: 'var(--border)',
        }}>
          {STEPS.map((step) => {
            const done = completed.includes(step.id)
            return (
              <StepCard
                key={step.id}
                step={step}
                done={done}
                onCheck={() => toggleStep(step.id)}
                onCta={() => handleStepCta(step)}
              />
            )
          })}
        </div>
      )}
    </div>
  )
}

function StepCard({ step, done, onCheck, onCta }) {
  const [hovered, setHovered] = useState(false)

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: done
          ? 'var(--bg-secondary)'
          : hovered ? 'var(--bg-secondary)' : 'var(--bg-primary)',
        padding: '16px 18px',
        display: 'flex', flexDirection: 'column', gap: 8,
        transition: 'background 0.15s',
        position: 'relative',
      }}
    >
      {/* Top row: emoji + check */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 20, lineHeight: 1 }}>{step.emoji}</span>
        <button
          onClick={onCheck}
          title={done ? 'Mark incomplete' : 'Mark complete'}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            padding: 0, display: 'flex', alignItems: 'center',
            opacity: done ? 1 : 0.3,
            transition: 'opacity 0.15s',
          }}
          onMouseEnter={e => e.currentTarget.style.opacity = '1'}
          onMouseLeave={e => e.currentTarget.style.opacity = done ? '1' : '0.3'}
        >
          <CheckCircle size={18} color={done ? '#16a34a' : 'var(--text-muted)'} />
        </button>
      </div>

      {/* Title */}
      <div style={{
        fontWeight: 700, fontSize: 13, lineHeight: 1.4,
        color: done ? 'var(--text-muted)' : 'var(--text-primary)',
        textDecoration: done ? 'line-through' : 'none',
      }}>
        {step.title}
      </div>

      {/* Description */}
      {!done && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5, flex: 1 }}>
          {step.description}
        </div>
      )}

      {/* CTA */}
      {!done && (
        <button
          onClick={onCta}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            marginTop: 4, padding: '6px 0',
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--accent)', fontWeight: 700, fontSize: 12,
            textDecoration: hovered ? 'underline' : 'none',
          }}
        >
          {step.cta} <ArrowRight size={12} />
        </button>
      )}

      {/* Done indicator */}
      {done && (
        <div style={{ fontSize: 12, color: '#16a34a', fontWeight: 600 }}>
          Done
        </div>
      )}
    </div>
  )
}
