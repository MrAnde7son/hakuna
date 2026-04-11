import React, { useEffect, useMemo, useState } from 'react'
import { Edit2, Save, X, Zap } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  listCustomFieldDefinitions,
  setAssetCustomFields,
  setFindingCustomFields,
} from '../../api.js'
import { Card, Button, Input, Select, useToast } from './ui.jsx'

/**
 * Card that renders + inline-edits user-defined custom fields on an Asset or Finding.
 *
 * Props:
 *   entityType: 'asset' | 'finding'
 *   entityId:   number
 *   values:     object — the entity.custom_fields dict
 *   onChange:   optional callback (newValues) after a successful save
 */
export default function CustomAttributesCard({ entityType, entityId, values, onChange }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [definitions, setDefinitions] = useState([])
  const [loading, setLoading] = useState(true)
  const [editingKey, setEditingKey] = useState(null)
  const [draftValue, setDraftValue] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    listCustomFieldDefinitions(entityType)
      .then(r => { if (!cancelled) setDefinitions(r || []) })
      .catch(() => { if (!cancelled) setDefinitions([]) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [entityType])

  const activeDefs = useMemo(
    () => (definitions || []).filter(d => d.is_active),
    [definitions],
  )

  if (loading) return null
  if (activeDefs.length === 0) return null

  const formatValue = (definition, raw) => {
    if (raw === null || raw === undefined || raw === '') return '—'
    if (definition.data_type === 'boolean') {
      if (typeof raw === 'boolean') return raw ? '✓' : '✗'
      return String(raw).toLowerCase() === 'true' ? '✓' : '✗'
    }
    if (typeof raw === 'object') return JSON.stringify(raw)
    return String(raw)
  }

  const beginEdit = (definition, currentValue) => {
    setEditingKey(definition.key)
    setDraftValue(currentValue === null || currentValue === undefined ? '' : String(currentValue))
  }

  const cancelEdit = () => {
    setEditingKey(null)
    setDraftValue('')
  }

  const save = async (definition) => {
    setSaving(true)
    try {
      let parsed = draftValue
      if (definition.data_type === 'number') {
        parsed = draftValue === '' ? null : Number(draftValue)
        if (Number.isNaN(parsed)) throw new Error(t('customFields.errors.notANumber', 'Not a number'))
      } else if (definition.data_type === 'boolean') {
        parsed = draftValue === 'true'
      } else if (draftValue === '') {
        parsed = null
      }
      const payload = { [definition.key]: parsed }
      let updated
      if (entityType === 'asset') {
        updated = await setAssetCustomFields(entityId, payload)
      } else {
        updated = await setFindingCustomFields(entityId, payload)
      }
      toast.success(t('customFields.saved', 'Saved'))
      if (onChange && updated && updated.custom_fields) {
        onChange(updated.custom_fields)
      }
      cancelEdit()
    } catch (e) {
      toast.error(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card style={{ marginBottom: 14, padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
        <Zap size={14} color="var(--accent)" />
        <h4 style={{ margin: 0, fontSize: 13, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-muted)' }}>
          {t('customFields.attributesTitle', 'Custom attributes')}
        </h4>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(140px, 1fr) 2fr', gap: '8px 16px', fontSize: 13 }}>
        {activeDefs.map(def => {
          const current = values?.[def.key]
          const isEditing = editingKey === def.key
          const isManual = def.source_type === 'manual'
          return (
            <React.Fragment key={def.id}>
              <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span title={def.description || undefined}>{def.label}</span>
                {!isManual && (
                  <span
                    style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--secondary)', color: 'var(--text-muted)' }}
                    title={
                      def.source_type === 'mapping'
                        ? t('customFields.computedFromSource', 'Computed from source: {{src}}', { src: def.mapping_source })
                        : t('customFields.computedFromFormula', 'Computed from formula')
                    }
                  >
                    auto
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {isEditing ? (
                  <>
                    {def.data_type === 'boolean' ? (
                      <Select
                        value={draftValue}
                        onChange={v => setDraftValue(v ?? '')}
                        options={[
                          { value: 'true', label: 'True' },
                          { value: 'false', label: 'False' },
                        ]}
                        placeholder="—"
                      />
                    ) : def.data_type === 'enum' ? (
                      <Select
                        value={draftValue}
                        onChange={v => setDraftValue(v ?? '')}
                        options={(def.enum_values || []).map(v => ({ value: v, label: v }))}
                        placeholder="—"
                      />
                    ) : (
                      <Input value={draftValue} onChange={setDraftValue} />
                    )}
                    <Button onClick={() => save(def)} size="sm" disabled={saving}>
                      <Save size={11} />
                    </Button>
                    <Button onClick={cancelEdit} size="sm" variant="ghost">
                      <X size={11} />
                    </Button>
                  </>
                ) : (
                  <>
                    <span style={{ color: 'var(--text-primary)', flex: 1 }}>
                      {formatValue(def, current)}
                    </span>
                    {isManual && (
                      <button
                        onClick={() => beginEdit(def, current)}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--text-muted)', padding: 2, opacity: 0.7,
                        }}
                        title={t('common.edit', 'Edit')}
                      >
                        <Edit2 size={12} />
                      </button>
                    )}
                  </>
                )}
              </div>
            </React.Fragment>
          )
        })}
      </div>
    </Card>
  )
}
