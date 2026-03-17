import { useState } from 'react'
import { ArrowRight, Wand2, X, ChevronDown, ChevronRight } from 'lucide-react'
import { Button, Spinner } from '../../shared/ui.jsx'

const TRANSFORM_TYPES = [
  { value: '', label: 'None' },
  { value: 'map', label: 'Value Map' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'float', label: 'Float' },
  { value: 'integer', label: 'Integer' },
  { value: 'datetime', label: 'DateTime' },
  { value: 'expression', label: 'Expression' },
]

export default function StepFieldMapper({
  detectedPaths, sampleRecords, schema, fieldMap, onFieldMapChange,
  onAutoSuggest, suggestions, loading, onNext,
}) {
  const [sourceFilter, setSourceFilter] = useState('')
  const [selectedSource, setSelectedSource] = useState(null)
  const [editingTransform, setEditingTransform] = useState(null) // index of mapping being edited

  const mappedTargets = new Set(fieldMap.map(m => m.target))
  const mappedSources = new Set(fieldMap.map(m => m.source))
  const requiredUnmapped = schema.filter(f => f.required && !mappedTargets.has(f.name))

  const handleClickSource = (path) => {
    setSelectedSource(path)
  }

  const handleClickTarget = (targetName) => {
    if (selectedSource) {
      // Create mapping
      const existing = fieldMap.findIndex(m => m.target === targetName)
      const newMap = [...fieldMap]
      if (existing >= 0) {
        newMap[existing] = { ...newMap[existing], source: selectedSource }
      } else {
        newMap.push({ source: selectedSource, target: targetName })
      }
      onFieldMapChange(newMap)
      setSelectedSource(null)
    }
  }

  const handleRemoveMapping = (index) => {
    const newMap = fieldMap.filter((_, i) => i !== index)
    onFieldMapChange(newMap)
  }

  const handleSetTransform = (index, transform) => {
    const newMap = [...fieldMap]
    newMap[index] = { ...newMap[index], transform: transform || undefined }
    onFieldMapChange(newMap)
  }

  const handleTargetSourceChange = (targetName, sourcePath) => {
    const existing = fieldMap.findIndex(m => m.target === targetName)
    const newMap = [...fieldMap]
    if (!sourcePath) {
      // Remove mapping
      if (existing >= 0) newMap.splice(existing, 1)
    } else if (existing >= 0) {
      newMap[existing] = { ...newMap[existing], source: sourcePath }
    } else {
      newMap.push({ source: sourcePath, target: targetName })
    }
    onFieldMapChange(newMap)
  }

  const filteredPaths = detectedPaths.filter(p =>
    !sourceFilter || p.path.toLowerCase().includes(sourceFilter.toLowerCase())
  )

  // Group schema by group
  const schemaGroups = {}
  schema.forEach(f => {
    const g = f.group || 'Other'
    if (!schemaGroups[g]) schemaGroups[g] = []
    schemaGroups[g].push(f)
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Map Fields</h3>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {requiredUnmapped.length > 0 && (
            <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 600 }}>
              {requiredUnmapped.length} required field{requiredUnmapped.length > 1 ? 's' : ''} unmapped
            </span>
          )}
          <Button
            onClick={onAutoSuggest}
            disabled={loading}
            style={{ background: 'transparent', color: 'var(--accent)', border: '1px solid var(--accent)', padding: '4px 12px', fontSize: 12 }}
          >
            <Wand2 size={12} style={{ marginRight: 4 }} /> Auto-map
          </Button>
        </div>
      </div>

      {selectedSource && (
        <div style={{ padding: '6px 12px', background: 'var(--accent)15', borderRadius: 6, fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>Mapping from: <b>{selectedSource}</b></span>
          <span style={{ color: 'var(--text-muted)' }}>→ Click a Hakuna field to complete the mapping</span>
          <button onClick={() => setSelectedSource(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <X size={14} />
          </button>
        </div>
      )}

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Left: Source fields */}
        <div style={{ width: '45%' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
            Source Fields ({detectedPaths.length} detected)
          </div>
          <input
            placeholder="Filter fields..."
            value={sourceFilter}
            onChange={e => setSourceFilter(e.target.value)}
            style={{ ...inputStyle, marginBottom: 8 }}
          />
          <div style={{ maxHeight: 500, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
            {filteredPaths.map((p, i) => {
              const isMapped = mappedSources.has(p.path)
              const isSelected = selectedSource === p.path
              return (
                <div
                  key={i}
                  onClick={() => handleClickSource(p.path)}
                  style={{
                    padding: '6px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                    borderBottom: '1px solid var(--border)',
                    background: isSelected ? 'var(--accent)20' : isMapped ? '#22c55e08' : 'transparent',
                  }}
                >
                  {isMapped && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', flexShrink: 0 }} />}
                  <span style={{ fontSize: 12, fontFamily: 'var(--mono)', flex: 1 }}>{p.path}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', background: 'var(--border)', padding: '1px 4px', borderRadius: 3 }}>
                    {p.inferred_type}
                  </span>
                  {p.sample_value !== null && p.sample_value !== undefined && typeof p.sample_value !== 'object' && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {String(p.sample_value).substring(0, 30)}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Right: Hakuna fields */}
        <div style={{ width: '45%' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
            Hakuna Fields
          </div>
          <div style={{ maxHeight: 540, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
            {Object.entries(schemaGroups).map(([group, fields]) => (
              <GroupSection key={group} title={group.toUpperCase()}>
                {fields.map(f => {
                  const mappingIdx = fieldMap.findIndex(m => m.target === f.name)
                  const mapping = mappingIdx >= 0 ? fieldMap[mappingIdx] : null
                  const isRequired = f.required
                  return (
                    <div
                      key={f.name}
                      onClick={() => handleClickTarget(f.name)}
                      style={{
                        padding: '6px 10px', display: 'flex', alignItems: 'center', gap: 6,
                        borderBottom: '1px solid var(--border)',
                        cursor: selectedSource ? 'crosshair' : 'default',
                        background: selectedSource ? 'var(--bg-card)' : 'transparent',
                      }}
                    >
                      {mapping && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', flexShrink: 0 }} />}
                      {!mapping && isRequired && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />}
                      <span style={{ fontSize: 12, flex: 1 }}>
                        {f.name}
                        {isRequired && <span style={{ color: '#ef4444', marginLeft: 2 }}>*</span>}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{f.type}</span>

                      {/* Source dropdown */}
                      <select
                        value={mapping?.source || ''}
                        onChange={e => handleTargetSourceChange(f.name, e.target.value)}
                        onClick={e => e.stopPropagation()}
                        style={{
                          width: 140, fontSize: 10, padding: '2px 4px',
                          background: 'var(--bg)', border: '1px solid var(--border)',
                          borderRadius: 4, color: 'var(--text)',
                        }}
                      >
                        <option value="">— unmapped —</option>
                        {detectedPaths.map((p, i) => (
                          <option key={i} value={p.path}>{p.path}</option>
                        ))}
                      </select>

                      {/* Transform button */}
                      {mapping && (
                        <button
                          onClick={e => { e.stopPropagation(); setEditingTransform(editingTransform === mappingIdx ? null : mappingIdx) }}
                          style={{
                            fontSize: 9, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                            background: mapping.transform ? 'var(--accent)20' : 'var(--border)',
                            border: mapping.transform ? '1px solid var(--accent)' : '1px solid var(--border)',
                            color: mapping.transform ? 'var(--accent)' : 'var(--text-muted)',
                          }}
                        >
                          {mapping.transform?.type || 'fx'}
                        </button>
                      )}

                      {mapping && (
                        <button
                          onClick={e => { e.stopPropagation(); handleRemoveMapping(mappingIdx) }}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
                        >
                          <X size={12} />
                        </button>
                      )}
                    </div>
                  )
                })}
              </GroupSection>
            ))}
          </div>
        </div>
      </div>

      {/* Transform editor */}
      {editingTransform !== null && fieldMap[editingTransform] && (
        <TransformEditor
          mapping={fieldMap[editingTransform]}
          onSave={(transform) => { handleSetTransform(editingTransform, transform); setEditingTransform(null) }}
          onClose={() => setEditingTransform(null)}
        />
      )}

      <Button onClick={onNext} disabled={loading || requiredUnmapped.length > 0}>
        {loading ? <Spinner /> : 'Preview Mapping'}
        <ArrowRight size={14} style={{ marginLeft: 4 }} />
      </Button>
    </div>
  )
}

function GroupSection({ title, children }) {
  const [open, setOpen] = useState(true)
  return (
    <div>
      <div
        onClick={() => setOpen(!open)}
        style={{
          padding: '6px 10px', background: 'var(--bg)', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: 4,
          fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
          textTransform: 'uppercase', letterSpacing: '0.05em',
          borderBottom: '1px solid var(--border)',
        }}
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {title}
      </div>
      {open && children}
    </div>
  )
}

function TransformEditor({ mapping, onSave, onClose }) {
  const [type, setType] = useState(mapping.transform?.type || '')
  const [config, setConfig] = useState(mapping.transform || {})

  const handleSave = () => {
    if (!type) { onSave(null); return }
    onSave({ ...config, type })
  }

  return (
    <div style={{
      padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 12,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Transform: {mapping.source} → {mapping.target}</span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
          <X size={14} />
        </button>
      </div>

      <select value={type} onChange={e => { setType(e.target.value); setConfig({ type: e.target.value }) }}
        style={inputStyle}>
        {TRANSFORM_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
      </select>

      {type === 'map' && (
        <textarea
          placeholder='{"sourceValue": "targetValue", "4": "critical", "3": "high"}'
          value={JSON.stringify(config.mapping || {}, null, 2)}
          onChange={e => { try { setConfig({ ...config, mapping: JSON.parse(e.target.value) }) } catch {} }}
          style={{ ...inputStyle, fontFamily: 'var(--mono)', minHeight: 80 }}
        />
      )}

      {type === 'boolean' && (
        <input
          placeholder='Truthy values (comma-separated): Yes,yes,true,1'
          value={(config.truthy || []).join(',')}
          onChange={e => setConfig({ ...config, truthy: e.target.value.split(',').map(s => s.trim()) })}
          style={inputStyle}
        />
      )}

      {type === 'expression' && (
        <input
          placeholder="e.g. 'critical' if value > 9 else 'high' if value > 7 else 'medium'"
          value={config.expr || ''}
          onChange={e => setConfig({ ...config, expr: e.target.value })}
          style={{ ...inputStyle, fontFamily: 'var(--mono)' }}
        />
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <Button onClick={handleSave} style={{ padding: '4px 16px', fontSize: 12 }}>Apply</Button>
        <Button onClick={() => { onSave(null); }} style={{ padding: '4px 16px', fontSize: 12, background: 'transparent', color: 'var(--text)', border: '1px solid var(--border)' }}>Remove</Button>
      </div>
    </div>
  )
}

const inputStyle = {
  width: '100%', padding: '6px 10px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text)', fontSize: 12, boxSizing: 'border-box',
}
