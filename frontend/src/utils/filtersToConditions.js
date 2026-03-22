/**
 * filtersToConditions — converts AssetInventory / FindingExplorer filter state
 * into the unified RuleEngine condition format: [{ field, op, value }]
 *
 * type: 'asset' | 'finding'
 *
 * Fields mapped to rule_engine.CONDITION_CATALOG:
 *   Asset:   hostname, environment_tag, criticality, risk_score, critical_count, high_count, tag
 *   Finding: finding.plugin_name, finding.severity, finding.plugin_family,
 *            finding.exploit, finding.cve, finding.effort, finding.product,
 *            finding.cpe, tag
 *
 * Unmappable filters (isKev, ransomwareLinked, trendingInNews, slaStatus,
 * assetId, groupBy, page, sort*) are silently skipped.
 */

function tagConditions(tagFilter) {
  if (!Array.isArray(tagFilter)) return []
  return tagFilter.map(t => ({
    field: 'tag',
    op: 'has_tag',
    value: t.label || `${t.category}:${t.value}`,
  }))
}

export function filtersToConditions(filters, type) {
  const conds = []

  if (type === 'asset') {
    const { search, env, criticality, minRisk, maxRisk, minCritical, minHigh, tagFilter } = filters

    if (search)       conds.push({ field: 'hostname',         op: 'contains', value: search })
    if (env)          conds.push({ field: 'environment_tag',  op: 'eq',       value: env })
    if (criticality)  conds.push({ field: 'criticality',      op: 'gte',      value: Number(criticality) })
    if (minRisk)      conds.push({ field: 'risk_score',       op: 'gte',      value: Number(minRisk) })
    if (maxRisk)      conds.push({ field: 'risk_score',       op: 'lte',      value: Number(maxRisk) })
    if (minCritical)  conds.push({ field: 'critical_count',   op: 'gte',      value: Number(minCritical) })
    if (minHigh)      conds.push({ field: 'high_count',       op: 'gte',      value: Number(minHigh) })
    conds.push(...tagConditions(tagFilter))

  } else if (type === 'finding') {
    const { search, severity, family, hasExploit, cveFilter, effortLevel, tagFilter, productFilter, cpeFilter } = filters

    if (search)               conds.push({ field: 'finding.plugin_name',   op: 'contains', value: search })
    if (severity !== null && severity !== undefined)
                              conds.push({ field: 'finding.severity',       op: 'eq',       value: Number(severity) })
    if (family)               conds.push({ field: 'finding.plugin_family',  op: 'eq',       value: family })
    if (hasExploit === true)  conds.push({ field: 'finding.exploit',        op: 'is_true',  value: null })
    if (cveFilter)            conds.push({ field: 'finding.cve',            op: 'contains', value: cveFilter })
    if (effortLevel)          conds.push({ field: 'finding.effort',         op: 'eq',       value: effortLevel })
    if (productFilter)        conds.push({ field: 'finding.product',        op: 'contains', value: productFilter })
    if (cpeFilter)            conds.push({ field: 'finding.cpe',            op: 'contains', value: cpeFilter })
    conds.push(...tagConditions(tagFilter))
  }

  return conds
}
