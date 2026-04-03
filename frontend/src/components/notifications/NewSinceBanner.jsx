import React from 'react'
import { useTranslation } from 'react-i18next'
import { Sparkles, X, Filter } from 'lucide-react'
import { useNewSince } from '../../utils/useNewSince'

/**
 * A dismissable banner showing "X new items since your last visit" with an optional
 * CTA to filter the list to only new items.
 * @param {{ pageKey: string, labelKey?: string, onFilter?: (since: string|null) => void, filtering?: boolean }} props
 */
export default function NewSinceBanner({ pageKey, labelKey = 'notifications.newSince', onFilter, filtering }) {
  const { t } = useTranslation()
  const { count, since, dismiss } = useNewSince(pageKey)

  if (!count) return null

  const btnBase = {
    border: 'none',
    borderRadius: 6,
    padding: '3px 10px',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: 4,
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '8px 14px', marginBottom: 12,
      background: filtering ? 'var(--accent-bg, rgba(37,99,235,0.12))' : 'var(--accent-bg, rgba(37,99,235,0.08))',
      border: '1px solid var(--accent, #2563eb)30',
      borderRadius: 8, fontSize: 13, color: 'var(--accent, #2563eb)',
      fontWeight: 500,
    }}>
      <Sparkles size={15} />
      <span style={{ flex: 1 }}>
        {filtering
          ? t('notifications.showingNew', { count, defaultValue: `Showing ${count} new since your last visit` })
          : t(labelKey, { count, defaultValue: `${count} new since your last visit` })
        }
      </span>
      {onFilter && since && !filtering && (
        <button
          onClick={() => onFilter(since)}
          style={{ ...btnBase, background: 'var(--accent, #2563eb)', color: '#fff' }}
        >
          <Filter size={12} />
          {t('notifications.showNew', { defaultValue: 'Show new' })}
        </button>
      )}
      {filtering && onFilter && (
        <button
          onClick={() => onFilter(null)}
          style={{ ...btnBase, background: 'transparent', color: 'var(--accent, #2563eb)', border: '1px solid var(--accent, #2563eb)' }}
        >
          {t('notifications.showAll', { defaultValue: 'Show all' })}
        </button>
      )}
      {!filtering && (
        <button
          onClick={dismiss}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--accent, #2563eb)', padding: 2, display: 'flex',
          }}
        >
          <X size={14} />
        </button>
      )}
    </div>
  )
}
