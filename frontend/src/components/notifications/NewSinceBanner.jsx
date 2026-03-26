import React from 'react'
import { useTranslation } from 'react-i18next'
import { Sparkles, X } from 'lucide-react'
import { useNewSince } from '../../utils/useNewSince'

/**
 * A dismissable banner showing "X new items since your last visit".
 * @param {{ pageKey: string, labelKey?: string }} props
 */
export default function NewSinceBanner({ pageKey, labelKey = 'notifications.newSince' }) {
  const { t } = useTranslation()
  const { count, dismiss } = useNewSince(pageKey)

  if (!count) return null

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '8px 14px', marginBottom: 12,
      background: 'var(--accent-bg, rgba(37,99,235,0.08))',
      border: '1px solid var(--accent, #2563eb)30',
      borderRadius: 8, fontSize: 13, color: 'var(--accent, #2563eb)',
      fontWeight: 500,
    }}>
      <Sparkles size={15} />
      <span style={{ flex: 1 }}>
        {t(labelKey, { count, defaultValue: `${count} new since your last visit` })}
      </span>
      <button
        onClick={dismiss}
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--accent, #2563eb)', padding: 2, display: 'flex',
        }}
      >
        <X size={14} />
      </button>
    </div>
  )
}
