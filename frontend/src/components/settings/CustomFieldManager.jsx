import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Plus, Trash2, Edit2, X, Save, RefreshCw, Server, AlertTriangle, Code, Hand } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  listCustomFieldDefinitions, createCustomFieldDefinition,
  updateCustomFieldDefinition, deleteCustomFieldDefinition,
  backfillCustomFieldDefinition, previewCustomField,
  getAssetSources, getFindingSources,
  getAssets, getFindings,
} from '../../api.js'
import { Card, PageHeader, Button, Input, Select, Spinner, EmptyState, useToast, useConfirm } from '../shared/ui.jsx'

const DATA_TYPES = [
  { value: 'string', label: 'String' },
  { value: 'number', label: 'Number' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'date', label: 'Date' },
  { value: 'enum', label: 'Enum' },
]

const SOURCE_TYPES = [
  { value: 'mapping', label: 'Source mapping', icon: Server, help: 'Extract a value from the raw source observation using a dot-path.' },
  { value: 'formula', label: 'Formula', icon: Code, help: 'Compute the value with an expression over the merged entity.' },
  { value: 'manual', label: 'Manual', icon: Hand, help: 'Users enter the value directly on the asset/finding detail page.' },
]

function formatValue(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function DefinitionRow({ definition, onEdit, onDelete, onBackfill }) {
  const { t } = useTranslation()
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '10px 12px', border: '1px solid var(--border)',
      borderRadius: 6, marginBottom: 6, background: 'var(--card)',
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <strong style={{ fontSize: 13 }}>{definition.label}</strong>
          <code style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--secondary)', padding: '1px 6px', borderRadius: 3 }}>
            {definition.key}
          </code>
          <span style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
            {definition.data_type}
          </span>
          <span style={{ fontSize: 10, color: 'var(--accent)' }}>{definition.source_type}</span>
          {definition.show_in_list && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>· in list</span>
          )}
          {!definition.is_active && (
            <span style={{ fontSize: 10, color: 'var(--warning)' }}>· inactive</span>
          )}
        </div>
        {definition.source_type === 'mapping' && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            source: <code>{definition.mapping_source}</code>
            {definition.mapping_source_system && <> · {definition.mapping_source_system}</>}
          </div>
        )}
        {definition.source_type === 'formula' && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, fontFamily: 'monospace' }}>
            {definition.formula_expression}
          </div>
        )}
        {definition.description && (
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            {definition.description}
          </div>
        )}
      </div>
      {definition.source_type !== 'manual' && (
        <button
          onClick={() => onBackfill(definition)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
          title={t('customFields.backfill', 'Re-run backfill')}
        ><RefreshCw size={14} /></button>
      )}
      <button
        onClick={() => onEdit(definition)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
        title={t('common.edit', 'Edit')}
      ><Edit2 size={14} /></button>
      <button
        onClick={() => onDelete(definition)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 4 }}
        title={t('common.delete', 'Delete')}
      ><Trash2 size={14} /></button>
    </div>
  )
}

function EntityPicker({ entityType, selected, onSelect, disabled }) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const debounceRef = useRef(null)
  const containerRef = useRef(null)
  const PAGE_SIZE = 10

  // Close on outside click
  useEffect(() => {
    const handler = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const runSearch = useCallback(async (searchQuery, nextPage = 1) => {
    setLoading(true)
    try {
      if (entityType === 'asset') {
        const data = await getAssets({
          page: nextPage,
          page_size: PAGE_SIZE,
          search: searchQuery || undefined,
          sort_by: 'last_seen',
          order: 'desc',
        })
        setResults(data.assets || [])
        setTotal(data.total || 0)
      } else {
        const data = await getFindings({
          page: nextPage,
          page_size: PAGE_SIZE,
          search: searchQuery || undefined,
        })
        setResults(data.findings || [])
        setTotal(data.total || 0)
      }
      setPage(nextPage)
    } catch (e) {
      setResults([])
    } finally {
      setLoading(false)
    }
  }, [entityType])

  // Debounced search when query changes
  useEffect(() => {
    if (!open) return
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => runSearch(query, 1), 200)
    return () => debounceRef.current && clearTimeout(debounceRef.current)
  }, [query, open, runSearch])

  // Initial load when opened
  useEffect(() => {
    if (open && results.length === 0 && !query) {
      runSearch('', 1)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const renderItemLabel = (item) => {
    if (entityType === 'asset') {
      return item.hostname || item.fqdn || item.ip || `asset:${item.id}`
    }
    return item.plugin_name || `finding:${item.id}`
  }

  const renderItemSub = (item) => {
    if (entityType === 'asset') {
      const parts = [item.ip, item.os].filter(Boolean).join(' · ')
      return parts
    }
    return `${item.asset_hostname || item.asset_ip || '—'} · ${item.severity_label || ''}`
  }

  const selectedLabel = selected ? renderItemLabel(selected) : ''
  const totalPages = Math.ceil(total / PAGE_SIZE) || 1

  return (
    <div ref={containerRef} style={{ position: 'relative', flex: 1, minWidth: 220 }}>
      <input
        type="text"
        value={open ? query : selectedLabel}
        onChange={e => { setQuery(e.target.value); if (!open) setOpen(true) }}
        onFocus={() => setOpen(true)}
        disabled={disabled}
        placeholder={entityType === 'asset'
          ? t('customFields.pickAsset', 'Search assets by hostname, IP, FQDN…')
          : t('customFields.pickFinding', 'Search findings by plugin name…')}
        style={{
          width: '100%', padding: '6px 10px', fontSize: 12,
          background: 'var(--card)', border: '1px solid var(--border)',
          borderRadius: 4, color: 'var(--text-primary)', outline: 'none',
        }}
      />
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
          background: 'var(--popover)', border: '1px solid var(--border)',
          borderRadius: 6, boxShadow: 'var(--shadow)', zIndex: 100000,
          maxHeight: 320, overflowY: 'auto',
        }}>
          {loading && results.length === 0 ? (
            <div style={{ padding: 10, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
              {t('common.loading', 'Loading…')}
            </div>
          ) : results.length === 0 ? (
            <div style={{ padding: 10, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
              {t('customFields.noEntityResults', 'No matches')}
            </div>
          ) : (
            <>
              {results.map(item => (
                <button
                  key={item.id}
                  onClick={() => { onSelect(item); setOpen(false); setQuery('') }}
                  style={{
                    display: 'block', width: '100%', textAlign: 'left',
                    padding: '8px 10px', background: 'transparent', border: 'none',
                    borderBottom: '1px solid var(--border)', cursor: 'pointer',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)' }}>
                    {renderItemLabel(item)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    #{item.id}{renderItemSub(item) ? ` · ${renderItemSub(item)}` : ''}
                  </div>
                </button>
              ))}
              {total > PAGE_SIZE && (
                <div style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '6px 10px', fontSize: 10, color: 'var(--text-muted)',
                }}>
                  <button
                    onClick={() => page > 1 && runSearch(query, page - 1)}
                    disabled={page <= 1}
                    style={{
                      background: 'transparent', border: 'none', cursor: page > 1 ? 'pointer' : 'not-allowed',
                      color: page > 1 ? 'var(--accent)' : 'var(--text-muted)', fontSize: 11, padding: 0,
                    }}
                  >← {t('common.prev', 'Prev')}</button>
                  <span>{t('customFields.pageOf', 'Page {{page}} / {{total}}', { page, total: totalPages })}</span>
                  <button
                    onClick={() => page < totalPages && runSearch(query, page + 1)}
                    disabled={page >= totalPages}
                    style={{
                      background: 'transparent', border: 'none', cursor: page < totalPages ? 'pointer' : 'not-allowed',
                      color: page < totalPages ? 'var(--accent)' : 'var(--text-muted)', fontSize: 11, padding: 0,
                    }}
                  >{t('common.next', 'Next')} →</button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}


function DefinitionForm({ definition, defaultEntityType, onSave, onCancel }) {
  const { t } = useTranslation()
  const toast = useToast()
  const isEdit = !!definition
  const [entityType, setEntityType] = useState(definition?.entity_type || defaultEntityType || 'asset')
  const [key, setKey] = useState(definition?.key || '')
  const [label, setLabel] = useState(definition?.label || '')
  const [description, setDescription] = useState(definition?.description || '')
  const [dataType, setDataType] = useState(definition?.data_type || 'string')
  const [enumValuesText, setEnumValuesText] = useState((definition?.enum_values || []).join(', '))
  const [sourceType, setSourceType] = useState(definition?.source_type || 'mapping')
  const [mappingSource, setMappingSource] = useState(definition?.mapping_source || '')
  const [mappingSourceSystem, setMappingSourceSystem] = useState(definition?.mapping_source_system || '')
  const [formulaExpression, setFormulaExpression] = useState(definition?.formula_expression || '')
  const [showInList, setShowInList] = useState(definition?.show_in_list || false)
  const [isActive, setIsActive] = useState(definition?.is_active !== false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [preview, setPreview] = useState(null)
  const [sampleText, setSampleText] = useState('{\n  "easm_data": {\n    "cloudflare_dns": { "ttl": 1 }\n  }\n}')
  const [selectedSampleEntity, setSelectedSampleEntity] = useState(null)
  const [loadingSample, setLoadingSample] = useState(false)

  const normalizedKey = key.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_')

  const loadSampleFromEntity = async (entity) => {
    if (!entity) return
    setLoadingSample(true)
    setPreview(null)
    try {
      const sources = entityType === 'asset'
        ? await getAssetSources(entity.id)
        : await getFindingSources(entity.id)
      if (!sources || sources.length === 0) {
        setPreview({ error: t('customFields.errors.noSources', 'No observations found for this {{entity}}', { entity: entityType }) })
        return
      }
      // Prefer the mapping_source_system if set, else the most recent observation
      const match = mappingSourceSystem
        ? sources.find(s => s.source_system === mappingSourceSystem) || sources[0]
        : sources[0]
      setSampleText(JSON.stringify(match.raw_fields || {}, null, 2))
    } catch (e) {
      setPreview({ error: e.message })
    } finally {
      setLoadingSample(false)
    }
  }

  const handleEntitySelect = (entity) => {
    setSelectedSampleEntity(entity)
    loadSampleFromEntity(entity)
  }

  const runPreview = async () => {
    setPreview(null)
    let sample
    try {
      sample = sampleText.trim() ? JSON.parse(sampleText) : {}
    } catch (e) {
      setPreview({ error: `Invalid JSON: ${e.message}` })
      return
    }
    try {
      const result = await previewCustomField({
        entity_type: entityType,
        source_type: sourceType,
        data_type: dataType,
        mapping_source: mappingSource || null,
        formula_expression: formulaExpression || null,
        sample_record: sample,
      })
      setPreview(result)
    } catch (e) {
      setPreview({ error: e.message })
    }
  }

  const submit = async () => {
    setError(null)
    if (!label.trim()) { setError(t('customFields.errors.labelRequired', 'Label is required')); return }
    if (!isEdit && !normalizedKey) { setError(t('customFields.errors.keyRequired', 'Key is required')); return }
    if (sourceType === 'mapping' && !mappingSource.trim()) {
      setError(t('customFields.errors.mappingSourceRequired', 'Mapping source path is required')); return
    }
    if (sourceType === 'formula' && !formulaExpression.trim()) {
      setError(t('customFields.errors.formulaRequired', 'Formula expression is required')); return
    }
    if (dataType === 'enum' && !enumValuesText.trim()) {
      setError(t('customFields.errors.enumValuesRequired', 'Enum values are required')); return
    }

    const payload = {
      ...(isEdit ? {} : { entity_type: entityType, key: normalizedKey }),
      label: label.trim(),
      description: description.trim() || null,
      data_type: dataType,
      enum_values: dataType === 'enum'
        ? enumValuesText.split(',').map(s => s.trim()).filter(Boolean)
        : null,
      source_type: sourceType,
      mapping_source: sourceType === 'mapping' ? mappingSource.trim() : null,
      mapping_source_system: sourceType === 'mapping' ? (mappingSourceSystem.trim() || null) : null,
      formula_expression: sourceType === 'formula' ? formulaExpression.trim() : null,
      show_in_list: showInList,
      is_active: isActive,
    }

    setSaving(true)
    try {
      if (isEdit) {
        await updateCustomFieldDefinition(definition.id, payload)
        toast.success(t('customFields.updated', 'Custom field updated'))
      } else {
        await createCustomFieldDefinition(payload)
        toast.success(t('customFields.created', 'Custom field created'))
      }
      onSave()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const modalStyle = {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 99999,
  }
  const panelStyle = {
    background: 'var(--card)', borderRadius: 12, padding: 24,
    width: 'min(720px, 90vw)', maxHeight: '90vh', overflowY: 'auto',
    border: '1px solid var(--border)', boxShadow: 'var(--shadow)',
  }
  const labelStyle = { fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4, display: 'block' }

  return createPortal(
    <div style={modalStyle} onClick={onCancel}>
      <div style={panelStyle} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 16 }}>
            {isEdit ? t('customFields.editTitle', 'Edit custom field') : t('customFields.newTitle', 'New custom field')}
          </h3>
          <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <X size={18} />
          </button>
        </div>

        {error && (
          <div style={{ padding: 10, background: 'var(--danger-subtle)', color: 'var(--danger)', borderRadius: 4, marginBottom: 12, fontSize: 12 }}>
            <AlertTriangle size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />
            {error}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={labelStyle}>{t('customFields.entity', 'Entity')}</label>
            {isEdit ? (
              <div style={{
                padding: '7px 12px', background: 'var(--secondary)',
                border: '1px solid var(--border)', borderRadius: 6, fontSize: 13,
                color: 'var(--text-muted)', textTransform: 'capitalize',
              }}>{entityType}</div>
            ) : (
              <Select
                value={entityType}
                onChange={v => setEntityType(v || 'asset')}
                options={[
                  { value: 'asset', label: t('customFields.asset', 'Asset') },
                  { value: 'finding', label: t('customFields.finding', 'Finding') },
                ]}
              />
            )}
          </div>
          <div>
            <label style={labelStyle}>{t('customFields.dataType', 'Data type')}</label>
            <Select
              value={dataType}
              onChange={v => setDataType(v || 'string')}
              options={DATA_TYPES}
            />
          </div>
          <div>
            <label style={labelStyle}>{t('customFields.key', 'Key')}</label>
            {isEdit ? (
              <div style={{
                padding: '7px 12px', background: 'var(--secondary)',
                border: '1px solid var(--border)', borderRadius: 6, fontSize: 13,
                color: 'var(--text-muted)', fontFamily: 'monospace',
              }}>{key}</div>
            ) : (
              <Input
                value={key}
                onChange={setKey}
                placeholder="data_center"
              />
            )}
            {!isEdit && key && key !== normalizedKey && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                → {normalizedKey}
              </div>
            )}
          </div>
          <div>
            <label style={labelStyle}>{t('customFields.label', 'Label')}</label>
            <Input value={label} onChange={setLabel} placeholder="Data Center" />
          </div>
        </div>

        <div style={{ marginBottom: 12 }}>
          <label style={labelStyle}>{t('customFields.description', 'Description')}</label>
          <Input
            value={description}
            onChange={setDescription}
            placeholder={t('customFields.descriptionPlaceholder', 'Shown as a tooltip in the UI')}
          />
        </div>

        {dataType === 'enum' && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>{t('customFields.enumValues', 'Enum values (comma-separated)')}</label>
            <Input value={enumValuesText} onChange={setEnumValuesText} placeholder="prod, staging, dev" />
          </div>
        )}

        <div style={{ marginBottom: 12 }}>
          <label style={labelStyle}>{t('customFields.sourceType', 'Value source')}</label>
          <div style={{ display: 'flex', gap: 8 }}>
            {SOURCE_TYPES.map(st => {
              const Icon = st.icon
              const selected = sourceType === st.value
              return (
                <button
                  key={st.value}
                  onClick={() => setSourceType(st.value)}
                  style={{
                    flex: 1, padding: 10,
                    background: selected ? 'rgba(99,102,241,0.12)' : 'var(--secondary)',
                    border: `1px solid ${selected ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: 4, cursor: 'pointer', textAlign: 'left',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <Icon size={14} />
                    <strong style={{ fontSize: 12 }}>{st.label}</strong>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{st.help}</div>
                </button>
              )
            })}
          </div>
        </div>

        {sourceType === 'mapping' && (
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <label style={labelStyle}>{t('customFields.mappingSource', 'Source path')}</label>
              <Input
                value={mappingSource}
                onChange={setMappingSource}
                placeholder="easm_data.cloudflare_dns.ttl"
              />
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                {t(
                  'customFields.mappingHelp',
                  'Dot-path starting from the observation root. E.g. easm_data.cloudflare_dns.ttl, asset_attributes.zone_name, or plugin_output.details.version.',
                )}
              </div>
            </div>
            <div>
              <label style={labelStyle}>{t('customFields.sourceSystem', 'Restrict to source (optional)')}</label>
              <Input
                value={mappingSourceSystem}
                onChange={setMappingSourceSystem}
                placeholder="crowdstrike"
              />
            </div>
          </div>
        )}

        {sourceType === 'formula' && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>{t('customFields.formula', 'Expression')}</label>
            <textarea
              value={formulaExpression}
              onChange={e => setFormulaExpression(e.target.value)}
              rows={3}
              style={{
                width: '100%', padding: 8, fontFamily: 'monospace', fontSize: 12,
                background: 'var(--secondary)', border: '1px solid var(--border)',
                borderRadius: 4, color: 'var(--text-primary)', resize: 'vertical',
              }}
              placeholder="'prod' if record['environment_tag'] == 'production' else 'non-prod'"
            />
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
              {t('customFields.formulaHelp', 'Sandboxed Python expression. Access merged columns via record["field_name"].')}
            </div>
          </div>
        )}

        {sourceType !== 'manual' && (
          <Card style={{ marginBottom: 12, padding: 12 }}>
            <div style={{ marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                {t('customFields.preview', 'Preview')}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
              <EntityPicker
                entityType={entityType}
                selected={selectedSampleEntity}
                onSelect={handleEntitySelect}
                disabled={loadingSample}
              />
              <Button onClick={runPreview} variant="ghost" size="sm">
                {t('customFields.runPreview', 'Run preview')}
              </Button>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6 }}>
              {t(
                'customFields.previewHint',
                'Pick a real {{entity}} to load its raw observation as the sample. Paths are resolved from the root — e.g. easm_data.cloudflare_dns.ttl.',
                { entity: entityType },
              )}
              {loadingSample && <span style={{ marginLeft: 8 }}>· {t('common.loading', 'Loading…')}</span>}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <textarea
                value={sampleText}
                onChange={e => setSampleText(e.target.value)}
                rows={8}
                style={{
                  width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 11,
                  background: 'var(--secondary)', border: '1px solid var(--border)',
                  borderRadius: 4, color: 'var(--text-primary)', resize: 'vertical',
                }}
                placeholder="Paste a sample record as JSON"
              />
              <div style={{
                padding: 6, fontFamily: 'monospace', fontSize: 11,
                background: 'var(--secondary)', border: '1px solid var(--border)',
                borderRadius: 4, minHeight: 80,
              }}>
                {preview ? (
                  preview.error ? (
                    <span style={{ color: 'var(--danger)' }}>{preview.error}</span>
                  ) : (
                    <>
                      <div style={{ color: 'var(--text-muted)', fontSize: 9, marginBottom: 2 }}>COERCED</div>
                      <div style={{ wordBreak: 'break-word' }}>{formatValue(preview.coerced_value)}</div>
                      {preview.raw_value !== preview.coerced_value && (
                        <>
                          <div style={{ color: 'var(--text-muted)', fontSize: 9, marginTop: 6, marginBottom: 2 }}>RAW</div>
                          <div style={{ wordBreak: 'break-word', opacity: 0.7 }}>{formatValue(preview.raw_value)}</div>
                        </>
                      )}
                    </>
                  )
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>{t('customFields.noPreview', 'Click Run preview')}</span>
                )}
              </div>
            </div>
          </Card>
        )}

        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={showInList} onChange={e => setShowInList(e.target.checked)} />
            {t('customFields.showInList', 'Show as column in list view')}
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={isActive} onChange={e => setIsActive(e.target.checked)} />
            {t('customFields.active', 'Active')}
          </label>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button onClick={onCancel} variant="ghost">{t('common.cancel', 'Cancel')}</Button>
          <Button onClick={submit} disabled={saving}>
            <Save size={14} style={{ marginRight: 4, verticalAlign: 'middle' }} />
            {saving ? t('common.saving', 'Saving…') : t('common.save', 'Save')}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  )
}

export default function CustomFieldManager() {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()
  const [definitions, setDefinitions] = useState([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(null)
  const [creatingFor, setCreatingFor] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await listCustomFieldDefinitions()
      setDefinitions(result || [])
    } catch (e) {
      toast.error(e.message)
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  const grouped = useMemo(() => {
    const assets = definitions.filter(d => d.entity_type === 'asset')
    const findings = definitions.filter(d => d.entity_type === 'finding')
    return { asset: assets, finding: findings }
  }, [definitions])

  const handleDelete = async (definition) => {
    const ok = await confirm(
      t(
        'customFields.deleteMessage',
        'This will remove "{{label}}" from all {{entity}} rows.',
        { label: definition.label, entity: definition.entity_type },
      ),
      {
        title: t('customFields.deleteTitle', 'Delete custom field?'),
        confirmLabel: t('common.delete', 'Delete'),
        destructive: true,
      },
    )
    if (!ok) return
    try {
      await deleteCustomFieldDefinition(definition.id)
      toast.success(t('customFields.deleted', 'Custom field deleted'))
      load()
    } catch (e) {
      toast.error(e.message)
    }
  }

  const handleBackfill = async (definition) => {
    try {
      const result = await backfillCustomFieldDefinition(definition.id)
      toast.success(t('customFields.backfillDone', 'Backfilled {{n}} rows', { n: result.processed }))
    } catch (e) {
      toast.error(e.message)
    }
  }

  const handleSave = () => {
    setEditing(null)
    setCreatingFor(null)
    load()
  }

  if (loading) return <Spinner />

  return (
    <div>
      <PageHeader
        title={t('customFields.pageTitle', 'Custom Fields')}
        subtitle={t('customFields.pageSubtitle', 'Define user-specific fields on assets and findings, populated from source data, formulas, or manual entry.')}
      />

      {['asset', 'finding'].map(entity => (
        <Card key={entity} style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h4 style={{ margin: 0, fontSize: 14, textTransform: 'capitalize' }}>
              {t(`customFields.${entity}`, entity)} {t('customFields.fields', 'fields')}
            </h4>
            <Button onClick={() => setCreatingFor(entity)} size="sm">
              <Plus size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />
              {t('customFields.addField', 'Add field')}
            </Button>
          </div>
          {grouped[entity].length === 0 ? (
            <EmptyState
              title={t('customFields.empty', 'No custom fields defined')}
              sub={t('customFields.emptyHelp', 'Click Add field to create your first {{entity}} custom field.', { entity })}
            />
          ) : (
            <div>
              {grouped[entity].map(def => (
                <DefinitionRow
                  key={def.id}
                  definition={def}
                  onEdit={setEditing}
                  onDelete={handleDelete}
                  onBackfill={handleBackfill}
                />
              ))}
            </div>
          )}
        </Card>
      ))}

      {(editing || creatingFor) && (
        <DefinitionForm
          definition={editing}
          defaultEntityType={creatingFor}
          onSave={handleSave}
          onCancel={() => { setEditing(null); setCreatingFor(null) }}
        />
      )}
    </div>
  )
}
