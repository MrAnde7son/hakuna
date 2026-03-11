/**
 * Self-service Report Builder
 * Drag-and-drop (via up/down controls) widget canvas with live data previews.
 * Reports are saved to localStorage.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart2, PieChart as PieChartIcon, Table2, Hash, AlignLeft, Wrench,
  Shield, Users, Server, Bug, Plus, Trash2, ChevronUp, ChevronDown,
  Save, Eye, EyeOff, ArrowLeft, Copy, Settings2, GripVertical,
  CheckCircle, LayoutGrid, Maximize2, Minimize2, X, PenLine,
  TrendingUp, Zap, Clock, Home, Upload, GitCompare, Activity
} from 'lucide-react'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid, LineChart, Line,
  AreaChart, Area
} from 'recharts'
import { useScan } from '../App.jsx'
import {
  getSummary, getAssets, getFindings, getRemediationQueue, getPluginFamilies,
  getTrending, getSLASummary, getAutomateClicks, getScanDeltaTimeline, getMetricsTimeline,
  getTemporalSummary, getRemediationVelocity,
  getReportTemplates, createReportTemplate, updateReportTemplate, deleteReportTemplate as apiDeleteTemplate,
  exportConfig,
  getRiskByTags,
  getInventorySummary, getInventoryUsers, getInventoryGroups, getInventoryServices,
  getInventoryNetconns, getInventoryTasks, getInventoryPatches, getInventoryLoggedOn,
  getInventoryShares, getInventorySoftware, getInventorySecurityControls, getInventoryComputers,
  getInventoryPasswordPolicies, getInventoryCertificates, getInventoryAITools, getInventoryProcesses,
} from '../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, EffortBadge, OwnerBadge, Button, Pill, ExportImportButtons } from './ui.jsx'

// ─── Storage helpers ─────────────────────────────────────────────────────────

const STORAGE_KEY = 'nessus_custom_reports'
const MIGRATED_KEY = 'nessus_reports_migrated'
const LANDING_KEY = 'nessus_landing_report'
const DEFAULT_REPORT_ID = 'default-security-overview'

function loadLandingId() {
  return localStorage.getItem(LANDING_KEY) || DEFAULT_REPORT_ID
}
function saveLandingId(id) {
  localStorage.setItem(LANDING_KEY, id)
}
function uid() {
  return Math.random().toString(36).slice(2, 10)
}

/** One-time migration: push localStorage reports to API, then clear. */
async function migrateLocalStorageReports() {
  if (localStorage.getItem(MIGRATED_KEY)) return
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const local = JSON.parse(raw)
      for (const r of local) {
        try {
          await createReportTemplate({
            name: r.name || 'Untitled Report',
            description: r.description || null,
            config: { widgets: r.widgets || [], createdAt: r.createdAt },
          })
        } catch { /* skip duplicates */ }
      }
    }
  } catch { /* ignore */ }
  localStorage.setItem(MIGRATED_KEY, '1')
}

/** Convert API template to the internal report format used by Builder. */
function templateToReport(t) {
  return {
    id: t.id,
    name: t.name,
    description: t.description,
    widgets: t.config?.widgets || [],
    createdAt: t.config?.createdAt || t.created_at,
    updatedAt: t.updated_at,
    is_default: t.is_default,
  }
}
// ─── Data layer ──────────────────────────────────────────────────────────────

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']
const PALETTE = ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#0ea5e9', '#22c55e', '#ef4444', '#14b8a6']

const DATA_SOURCES = {
  summary:            (scanId, f) => getSummary(scanId),
  sla:                (scanId, f) => getSLASummary(scanId),
  trending:           (scanId, f) => getTrending(),
  metrics_timeline:   (scanId, f) => getMetricsTimeline(),
  delta_timeline:     (scanId, f) => getScanDeltaTimeline(),
  velocity:           (scanId, f) => getRemediationVelocity(f?.period || 'month'),
  temporal:           (scanId, f) => getTemporalSummary(scanId),
  assets:             (scanId, f) => getAssets({ scan_id: scanId, search: f?.search, min_risk: f?.min_risk, max_risk: f?.max_risk, environment: f?.environment, min_critical: f?.min_critical, min_high: f?.min_high, has_findings: f?.has_findings, sort_by: f?.sort_by || 'risk_score', order: f?.order || 'desc', tags: f?.tags, tag_logic: f?.tag_logic }),
  findings:           (scanId, f) => getFindings({ scan_id: scanId, severity: f?.severity, plugin_family: f?.plugin_family, has_exploit: f?.has_exploit, effort_level: f?.effort_level, sla_status: f?.sla_status, search: f?.search, sort_by: f?.sort_by || 'priority_score', order: f?.order || 'desc', page_size: f?.page_size || 50, tags: f?.tags, tag_logic: f?.tag_logic }),
  remediation_queue:  (scanId, f) => getRemediationQueue({ scan_id: scanId, effort: f?.effort, owner: f?.owner, min_severity: f?.min_severity, limit: f?.limit || 20 }),
  automation_wishlist:(scanId, f) => getAutomateClicks(),
  risk_by_tags:       (scanId, f) => getRiskByTags({ scan_id: scanId, category: f?.category }),
  plugin_families:    (scanId, f) => getPluginFamilies(scanId),
  inv_summary:        (scanId, f) => getInventorySummary(scanId),
  inv_users:          (scanId, f) => getInventoryUsers({ scan_id: scanId, user_type: f?.user_type, is_admin: f?.is_admin, is_domain_admin: f?.is_domain_admin, is_privileged: f?.is_privileged, search: f?.search }),
  inv_groups:         (scanId, f) => getInventoryGroups({ scan_id: scanId, is_privileged: f?.is_privileged }),
  inv_services:       (scanId, f) => getInventoryServices({ scan_id: scanId, search: f?.search }),
  inv_netconns:       (scanId, f) => getInventoryNetconns({ scan_id: scanId, state: f?.state }),
  inv_tasks:          (scanId, f) => getInventoryTasks({ scan_id: scanId }),
  inv_patches:        (scanId, f) => getInventoryPatches({ scan_id: scanId }),
  inv_logged_on:      (scanId, f) => getInventoryLoggedOn({ scan_id: scanId }),
  inv_shares:         (scanId, f) => getInventoryShares({ scan_id: scanId, is_writeable: f?.is_writeable }),
  inv_software:       (scanId, f) => getInventorySoftware({ scan_id: scanId, search: f?.search }),
  inv_security_ctrls: (scanId, f) => getInventorySecurityControls({ scan_id: scanId, control_type: f?.control_type }),
  inv_computers:      (scanId, f) => getInventoryComputers({ scan_id: scanId, is_dc: f?.is_dc, search: f?.search }),
  inv_pw_policies:    (scanId, f) => getInventoryPasswordPolicies({ scan_id: scanId }),
  inv_certificates:   (scanId, f) => getInventoryCertificates({ scan_id: scanId, expired_only: f?.expired_only, expiring_days: f?.expiring_days, self_signed_only: f?.self_signed_only }),
  inv_ai_tools:       (scanId, f) => getInventoryAITools({ scan_id: scanId, category: f?.category }),
  inv_processes:      (scanId, f) => getInventoryProcesses({ scan_id: scanId, search: f?.search }),
}

// Filter definitions per source — drives ConfigPanel filter UI
const SOURCE_FILTERS = {
  findings: [
    { key: 'severity', label: 'Severity', type: 'select', options: [{ value: '', label: 'All' }, { value: '4', label: 'Critical' }, { value: '3', label: 'High' }, { value: '2', label: 'Medium' }, { value: '1', label: 'Low' }, { value: '0', label: 'Info' }] },
    { key: 'has_exploit', label: 'Has Exploit', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }] },
    { key: 'effort_level', label: 'Effort', type: 'select', options: [{ value: '', label: 'All' }, { value: 'quick_win', label: 'Quick Win' }, { value: 'medium', label: 'Medium' }, { value: 'complex', label: 'Complex' }] },
    { key: 'sla_status', label: 'SLA Status', type: 'select', options: [{ value: '', label: 'All' }, { value: 'on_track', label: 'On Track' }, { value: 'at_risk', label: 'At Risk' }, { value: 'breached', label: 'Breached' }] },
    { key: 'plugin_family', label: 'Plugin Family', type: 'text', placeholder: 'e.g. Windows' },
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Keyword...' },
  ],
  assets: [
    { key: 'environment', label: 'Environment', type: 'text', placeholder: 'e.g. production' },
    { key: 'min_risk', label: 'Min Risk Score', type: 'number', placeholder: '0' },
    { key: 'max_risk', label: 'Max Risk Score', type: 'number', placeholder: '10' },
    { key: 'min_critical', label: 'Min Critical Count', type: 'number', placeholder: '0' },
    { key: 'has_findings', label: 'Has Findings', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }] },
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Hostname, IP...' },
  ],
  remediation_queue: [
    { key: 'effort', label: 'Effort', type: 'select', options: [{ value: '', label: 'All' }, { value: 'quick_win', label: 'Quick Win' }, { value: 'medium', label: 'Medium' }, { value: 'complex', label: 'Complex' }] },
    { key: 'owner', label: 'Owner', type: 'select', options: [{ value: '', label: 'All' }, { value: 'IT', label: 'IT' }, { value: 'DevOps', label: 'DevOps' }, { value: 'SecOps', label: 'SecOps' }, { value: 'AppSec', label: 'AppSec' }] },
    { key: 'min_severity', label: 'Min Severity', type: 'select', options: [{ value: '', label: 'Medium+ (default)' }, { value: '4', label: 'Critical only' }, { value: '3', label: 'High+' }, { value: '1', label: 'Low+' }] },
  ],
  risk_by_tags: [
    { key: 'category', label: 'Tag Category', type: 'text', placeholder: 'e.g. business_unit (blank = all)' },
  ],
  velocity: [
    { key: 'period', label: 'Period', type: 'select', options: [{ value: 'month', label: 'Monthly' }, { value: 'week', label: 'Weekly' }] },
  ],
  inv_users: [
    { key: 'user_type', label: 'User Type', type: 'select', options: [{ value: '', label: 'All' }, { value: 'domain_user', label: 'Domain User' }, { value: 'local_user', label: 'Local User' }, { value: 'computer_account', label: 'Computer Account' }, { value: 'service_account', label: 'Service Account' }] },
    { key: 'is_admin', label: 'Local Admin', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }] },
    { key: 'is_domain_admin', label: 'Domain Admin', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
    { key: 'is_privileged', label: 'Privileged', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Username...' },
  ],
  inv_groups: [
    { key: 'is_privileged', label: 'Privileged Only', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
  ],
  inv_services: [
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Service name...' },
  ],
  inv_netconns: [
    { key: 'state', label: 'State', type: 'select', options: [{ value: '', label: 'All' }, { value: 'ESTABLISHED', label: 'Established' }, { value: 'LISTEN', label: 'Listening' }, { value: 'TIME_WAIT', label: 'Time Wait' }] },
  ],
  inv_shares: [
    { key: 'is_writeable', label: 'Writeable', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
  ],
  inv_software: [
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Software name...' },
  ],
  inv_security_ctrls: [
    { key: 'control_type', label: 'Type', type: 'select', options: [{ value: '', label: 'All' }, { value: 'antivirus', label: 'Antivirus' }, { value: 'firewall', label: 'Firewall' }, { value: 'edr', label: 'EDR' }] },
  ],
  inv_computers: [
    { key: 'is_dc', label: 'Domain Controllers', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Computer name...' },
  ],
  inv_certificates: [
    { key: 'expired_only', label: 'Expired Only', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
    { key: 'expiring_days', label: 'Expiring Within (days)', type: 'number', placeholder: 'e.g. 30' },
    { key: 'self_signed_only', label: 'Self-Signed Only', type: 'select', options: [{ value: '', label: 'All' }, { value: 'true', label: 'Yes' }] },
  ],
  inv_ai_tools: [
    { key: 'category', label: 'Category', type: 'text', placeholder: 'e.g. chatbot' },
  ],
  inv_processes: [
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Process name...' },
  ],
}

const DATA_PRESETS = {
  // ── Metrics (card) ──
  critical_count:   { label: 'Critical Findings', group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.severity_breakdown?.critical ?? 0, color: '#dc2626' },
  high_count:       { label: 'High Findings',     group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.severity_breakdown?.high ?? 0, color: '#ea580c' },
  medium_count:     { label: 'Medium Findings',    group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.severity_breakdown?.medium ?? 0, color: '#d97706' },
  low_count:        { label: 'Low Findings',       group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.severity_breakdown?.low ?? 0, color: '#65a30d' },
  info_count:       { label: 'Info Findings',      group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.severity_breakdown?.info ?? 0, color: '#0ea5e9' },
  total_findings:   { label: 'Total Findings',     group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.total_findings ?? 0, color: 'var(--text-primary)' },
  excepted_findings:{ label: 'Excepted Findings',  group: 'Severity',  source: 'summary', type: 'metric', extract: d => d?.excepted_findings ?? 0, color: '#a78bfa' },
  total_assets:     { label: 'Total Assets',       group: 'Assets & Findings', source: 'summary', type: 'metric', extract: d => d?.total_assets ?? 0, color: '#6366f1' },
  exploit_count:    { label: 'Known Exploits',     group: 'Risk',      source: 'summary', type: 'metric', extract: d => d?.exploit_count ?? 0, color: '#f59e0b' },
  high_priority:    { label: 'High Priority',      group: 'Risk',      source: 'summary', type: 'metric', extract: d => d?.high_priority_count ?? 0, color: '#ea580c' },
  sla_compliance:   { label: 'SLA Compliance',     group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.compliance_pct ?? 0, format: 'pct', color: '#16a34a' },
  sla_breached:     { label: 'SLA Breached',       group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.breached ?? 0, color: '#dc2626' },
  sla_on_track:     { label: 'SLA On Track',       group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.on_track ?? 0, color: '#16a34a' },
  sla_at_risk:      { label: 'SLA At Risk',        group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.at_risk ?? 0, color: '#d97706' },
  quick_wins:       { label: 'Quick Wins',         group: 'SLA & Ops', source: 'summary', type: 'metric', extract: d => d?.effort_breakdown?.quick_win ?? 0, color: '#16a34a' },
  complex_findings: { label: 'Complex Findings',   group: 'SLA & Ops', source: 'summary', type: 'metric', extract: d => d?.effort_breakdown?.complex ?? 0, color: '#dc2626' },
  zombie_count:     { label: 'Zombie Vulns',       group: 'Temporal',  source: 'temporal', type: 'metric', extract: d => d?.zombie_count ?? 0, color: '#7c3aed' },
  regression_count: { label: 'Regressions',        group: 'Temporal',  source: 'temporal', type: 'metric', extract: d => d?.regression_count ?? 0, color: '#ef4444' },
  finding_count_filtered: { label: 'Finding Count', group: 'Filtered', source: 'findings', type: 'metric', extract: d => d?.total ?? d?.findings?.length ?? 0, color: '#6366f1' },
  asset_count_filtered:   { label: 'Asset Count',   group: 'Filtered', source: 'assets',   type: 'metric', extract: d => Array.isArray(d) ? d.length : 0, color: '#6366f1' },
  // ── Inventory metrics ──
  inv_domain_admins:      { label: 'Domain Admins',        group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.domain_admins ?? 0, color: '#dc2626' },
  inv_local_admins:       { label: 'Local Admins',         group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.local_admins_count ?? 0, color: '#ea580c' },
  inv_kerberoastable:     { label: 'Kerberoastable',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.kerberoastable_accounts ?? 0, color: '#f59e0b' },
  inv_pw_never_expires:   { label: 'Password Never Expires', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.password_never_expires_count ?? 0, color: '#d97706' },
  inv_pw_never_changed:   { label: 'Never Changed Password', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.never_changed_password_count ?? 0, color: '#ea580c' },
  inv_lateral_paths:      { label: 'Lateral Movement Paths', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.lateral_movement_paths ?? 0, color: '#ef4444' },
  inv_established_conns:  { label: 'Established Connections', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.established_connections ?? 0, color: '#6366f1' },
  inv_logged_on_count:    { label: 'Logged On Users',      group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.logged_on_users ?? 0, color: '#8b5cf6' },
  inv_writeable_shares:   { label: 'Writeable Shares',     group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.writeable_shares ?? 0, color: '#f59e0b' },
  inv_hosts_with_av:      { label: 'Hosts with AV',        group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.hosts_with_av ?? 0, color: '#16a34a' },
  inv_weak_pw_policies:   { label: 'Weak Password Policies', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.weak_password_policies ?? 0, color: '#dc2626' },
  inv_domain_controllers: { label: 'Domain Controllers',   group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.domain_controllers ?? 0, color: '#7c3aed' },
  inv_expired_certs:      { label: 'Expired Certificates', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.expired_certs ?? 0, color: '#dc2626' },
  inv_expiring_certs:     { label: 'Expiring Soon Certs',  group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.expiring_soon_certs ?? 0, color: '#d97706' },
  inv_self_signed_certs:  { label: 'Self-Signed Certs',    group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.self_signed_certs ?? 0, color: '#f59e0b' },
  inv_sensitive_env_vars: { label: 'Sensitive Env Vars',   group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.sensitive_env_vars ?? 0, color: '#ef4444' },
  inv_total_users:        { label: 'Total Users',          group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.users ?? 0, color: '#6366f1' },
  inv_total_services:     { label: 'Total Services',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.services ?? 0, color: '#0ea5e9' },
  inv_total_software:     { label: 'Total Software',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.software ?? 0, color: '#14b8a6' },
  inv_total_processes:    { label: 'Total Processes',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.processes ?? 0, color: '#8b5cf6' },
  inv_total_computers:    { label: 'Total Computers',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.computers ?? 0, color: '#6366f1' },
  inv_total_certificates: { label: 'Total Certificates',    group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.certificates ?? 0, color: '#f59e0b' },

  // ── Categories (pie/donut/bar) ──
  severity_breakdown: {
    label: 'Severity Breakdown', group: 'Severity', source: 'summary', type: 'categories',
    extract: d => {
      const s = d?.severity_breakdown || {}
      return ['Info', 'Low', 'Medium', 'High', 'Critical'].map((n, i) => ({ name: n, value: s[n.toLowerCase()] || 0, color: SEV_COLORS[i] })).filter(r => r.value > 0)
    },
  },
  effort_breakdown: {
    label: 'Effort Distribution', group: 'SLA & Ops', source: 'summary', type: 'categories',
    extract: d => {
      const e = d?.effort_breakdown || {}
      return [
        { name: 'Quick Win', value: e.quick_win || 0, color: '#16a34a' },
        { name: 'Medium', value: e.medium || 0, color: '#d97706' },
        { name: 'Complex', value: e.complex || 0, color: '#dc2626' },
      ].filter(r => r.value > 0)
    },
  },
  owner_breakdown: {
    label: 'Owner Breakdown', group: 'Assets & Findings', source: 'summary', type: 'categories',
    extract: d => (d?.owner_breakdown || []).map(o => ({ name: o.owner || 'Unknown', value: o.count })),
  },
  sla_status: {
    label: 'SLA Status', group: 'SLA & Ops', source: 'sla', type: 'categories',
    extract: d => {
      if (!d) return []
      return [
        { name: 'On Track', value: d.on_track || 0, color: '#16a34a' },
        { name: 'At Risk', value: d.at_risk || 0, color: '#d97706' },
        { name: 'Breached', value: d.breached || 0, color: '#dc2626' },
        { name: 'Resolved', value: d.resolved || 0, color: '#6366f1' },
      ].filter(r => r.value > 0)
    },
  },
  family_breakdown: {
    label: 'Plugin Families', group: 'Assets & Findings', source: 'summary', type: 'categories',
    extract: d => (d?.top_plugin_families || []).slice(0, 10).map(f => ({ name: f.family || 'Unknown', value: f.count })),
  },
  risk_by_tags: {
    label: 'Risk by Tags', group: 'Tags', source: 'risk_by_tags', type: 'categories',
    extract: d => (d?.groups || []).filter(g => g.asset_count > 0).map(g => ({
      name: g.category ? `${g.category}: ${g.value}` : g.value,
      value: parseFloat(g.avg_risk_score) || 0,
      color: g.color || (g.avg_risk_score > 6 ? '#ef4444' : g.avg_risk_score > 4 ? '#f97316' : '#22c55e'),
    })),
  },
  tag_finding_count: {
    label: 'Findings by Tag', group: 'Tags', source: 'risk_by_tags', type: 'categories',
    extract: d => (d?.groups || []).filter(g => g.finding_count > 0).map(g => ({
      name: g.category ? `${g.category}: ${g.value}` : g.value,
      value: g.finding_count,
      color: g.color || PALETTE[(d?.groups || []).indexOf(g) % PALETTE.length],
    })),
  },
  tag_asset_count: {
    label: 'Assets by Tag', group: 'Tags', source: 'risk_by_tags', type: 'categories',
    extract: d => (d?.groups || []).filter(g => g.asset_count > 0).map(g => ({
      name: g.category ? `${g.category}: ${g.value}` : g.value,
      value: g.asset_count,
      color: g.color || PALETTE[(d?.groups || []).indexOf(g) % PALETTE.length],
    })),
  },
  age_distribution: {
    label: 'Finding Age Distribution', group: 'Temporal', source: 'temporal', type: 'categories',
    extract: d => {
      const a = d?.age_distribution || {}
      return [
        { name: '< 30 days', value: a.under_30d || 0, color: '#22c55e' },
        { name: '30-90 days', value: a['30_90d'] || 0, color: '#eab308' },
        { name: '90-180 days', value: a['90_180d'] || 0, color: '#f97316' },
        { name: '> 180 days', value: a.over_180d || 0, color: '#ef4444' },
      ].filter(r => r.value > 0)
    },
  },
  sla_breached_by_sev: {
    label: 'SLA Breached by Severity', group: 'SLA & Ops', source: 'sla', type: 'categories',
    extract: d => {
      const b = d?.breached_by_severity || {}
      return [
        { name: 'Critical', value: b.critical || 0, color: '#dc2626' },
        { name: 'High', value: b.high || 0, color: '#ea580c' },
        { name: 'Medium', value: b.medium || 0, color: '#d97706' },
        { name: 'Low', value: b.low || 0, color: '#65a30d' },
      ].filter(r => r.value > 0)
    },
  },
  mttr_by_severity: {
    label: 'Avg MTTR by Severity', group: 'SLA & Ops', source: 'sla', type: 'categories',
    extract: d => {
      const m = d?.avg_mttr_days || {}
      return [
        { name: 'Critical', value: m.critical || 0, color: '#dc2626' },
        { name: 'High', value: m.high || 0, color: '#ea580c' },
        { name: 'Medium', value: m.medium || 0, color: '#d97706' },
        { name: 'Low', value: m.low || 0, color: '#65a30d' },
      ].filter(r => r.value > 0)
    },
  },
  os_breakdown: {
    label: 'OS Distribution', group: 'Assets & Findings', source: 'assets', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(a => { const os = a.os || 'Unknown'; counts[os] = (counts[os] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  // ── Inventory categories ──
  inv_user_type_breakdown: {
    label: 'User Types', group: 'Inventory', source: 'inv_users', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(u => { const t = u.user_type || 'unknown'; counts[t] = (counts[t] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name: name.replace(/_/g, ' '), value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_attack_surface: {
    label: 'Attack Surface', group: 'Inventory', source: 'inv_summary', type: 'categories',
    extract: d => {
      const a = d?.attack_surface || {}
      return [
        { name: 'Domain Admins', value: a.domain_admins || 0, color: '#dc2626' },
        { name: 'Local Admins', value: a.local_admins_count || 0, color: '#ea580c' },
        { name: 'Kerberoastable', value: a.kerberoastable_accounts || 0, color: '#f59e0b' },
        { name: 'Pwd Never Expires', value: a.password_never_expires_count || 0, color: '#d97706' },
        { name: 'Lateral Paths', value: a.lateral_movement_paths || 0, color: '#ef4444' },
        { name: 'Writeable Shares', value: a.writeable_shares || 0, color: '#8b5cf6' },
      ].filter(r => r.value > 0)
    },
  },
  inv_entity_counts: {
    label: 'Inventory Entity Counts', group: 'Inventory', source: 'inv_summary', type: 'categories',
    extract: d => {
      const c = d?.counts || {}
      return Object.entries(c).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({
        name: name.replace(/_/g, ' '), value, color: PALETTE[i % PALETTE.length],
      }))
    },
  },
  inv_netconn_states: {
    label: 'Connection States', group: 'Inventory', source: 'inv_netconns', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(c => { const s = c.state || 'UNKNOWN'; counts[s] = (counts[s] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_software_vendors: {
    label: 'Top Software Vendors', group: 'Inventory', source: 'inv_software', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(s => { const v = s.vendor || 'Unknown'; counts[v] = (counts[v] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_security_ctrl_types: {
    label: 'Security Control Types', group: 'Inventory', source: 'inv_security_ctrls', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(c => { const t = c.control_type || 'unknown'; counts[t] = (counts[t] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_cert_status: {
    label: 'Certificate Status', group: 'Inventory', source: 'inv_certificates', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      let expired = 0, expiring = 0, valid = 0, selfSigned = 0
      d.forEach(c => {
        if (c.is_expired) expired++
        else if (c.days_until_expiry != null && c.days_until_expiry <= 30) expiring++
        else valid++
        if (c.is_self_signed) selfSigned++
      })
      return [
        { name: 'Expired', value: expired, color: '#dc2626' },
        { name: 'Expiring <30d', value: expiring, color: '#f59e0b' },
        { name: 'Valid', value: valid, color: '#16a34a' },
        { name: 'Self-Signed', value: selfSigned, color: '#8b5cf6' },
      ].filter(r => r.value > 0)
    },
  },
  inv_ai_tool_categories: {
    label: 'AI Tool Categories', group: 'Inventory', source: 'inv_ai_tools', type: 'categories',
    extract: d => {
      if (!Array.isArray(d)) return []
      const counts = {}
      d.forEach(t => { const c = t.category || 'unknown'; counts[c] = (counts[c] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },

  // ── Series (line/area/bar-over-time) ──
  severity_trend: {
    label: 'Severity Trend', group: 'Severity', source: 'trending', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['critical', 'high', 'medium', 'low'],
    colors: { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d' },
  },
  risk_trend: {
    label: 'Risk Score Trend', group: 'Risk', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['avg_risk_score', 'max_risk_score'],
    colors: { avg_risk_score: '#ef4444', max_risk_score: '#dc2626' },
  },
  sla_trend: {
    label: 'SLA Compliance Trend', group: 'SLA & Ops', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['sla_compliance_pct'],
    colors: { sla_compliance_pct: '#16a34a' },
  },
  scan_delta: {
    label: 'Scan Delta', group: 'SLA & Ops', source: 'delta_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d.map(r => ({ ...r, fixed_count: -(r.fixed_count || 0) })) : [],
    xField: 'scan_name', fields: ['new_count', 'fixed_count'],
    colors: { new_count: '#ef4444', fixed_count: '#22c55e' },
  },
  velocity_trend: {
    label: 'Remediation Velocity', group: 'SLA & Ops', source: 'velocity', type: 'series',
    extract: d => (d?.buckets || []).slice(-8),
    xField: 'period_label', fields: ['resolved', 'critical', 'high'],
    colors: { resolved: '#6366f1', critical: '#dc2626', high: '#ea580c' },
  },
  metrics_overview: {
    label: 'Metrics Overview', group: 'Risk', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['total_findings', 'actionable_findings', 'exploit_count'],
    colors: { total_findings: '#6366f1', actionable_findings: '#8b5cf6', exploit_count: '#f59e0b' },
  },
  workflow_trend: {
    label: 'Workflow States', group: 'SLA & Ops', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['workflow_open', 'workflow_in_progress', 'workflow_resolved'],
    colors: { workflow_open: '#6b7280', workflow_in_progress: '#3b82f6', workflow_resolved: '#22c55e' },
  },
  critical_trend: {
    label: 'Critical Trend', group: 'Severity', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['critical'],
    colors: { critical: '#dc2626' },
  },
  high_trend: {
    label: 'High Trend', group: 'Severity', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['high'],
    colors: { high: '#ea580c' },
  },
  exploit_trend: {
    label: 'Exploit Count Trend', group: 'Risk', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['exploit_count'],
    colors: { exploit_count: '#f59e0b' },
  },
  asset_count_trend: {
    label: 'Asset Count Trend', group: 'Assets & Findings', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['total_assets'],
    colors: { total_assets: '#6366f1' },
  },
  finding_count_trend: {
    label: 'Finding Count Trend', group: 'Assets & Findings', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['total_findings', 'actionable_findings'],
    colors: { total_findings: '#6366f1', actionable_findings: '#8b5cf6' },
  },
  sla_breakdown_trend: {
    label: 'SLA Breakdown Trend', group: 'SLA & Ops', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['sla_on_track', 'sla_at_risk', 'sla_breached'],
    colors: { sla_on_track: '#16a34a', sla_at_risk: '#d97706', sla_breached: '#dc2626' },
  },
  mttr_trend: {
    label: 'MTTR Trend (days)', group: 'SLA & Ops', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d.filter(r => r.avg_mttr_days != null) : [],
    xField: 'scan_name', fields: ['avg_mttr_days'],
    colors: { avg_mttr_days: '#8b5cf6' },
  },
  full_severity_trend: {
    label: 'Full Severity Trend', group: 'Severity', source: 'metrics_timeline', type: 'series',
    extract: d => Array.isArray(d) ? d : [],
    xField: 'scan_name', fields: ['critical', 'high', 'medium', 'low', 'info'],
    colors: { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d', info: '#0ea5e9' },
  },

  // ── Tables ──
  top_assets: {
    label: 'Top Risky Assets', group: 'Assets & Findings', source: 'summary', type: 'table',
    extract: d => (d?.top_risky_assets || []),
    columns: [
      { key: 'hostname', label: 'Asset' },
      { key: 'os', label: 'OS' },
      { key: 'critical_count', label: 'C' },
      { key: 'high_count', label: 'H' },
      { key: 'medium_count', label: 'M' },
      { key: 'risk_score', label: 'Risk', render: v => v?.toFixed?.(1) },
    ],
  },
  tag_benchmark: {
    label: 'Tag Benchmark', group: 'Tags', source: 'risk_by_tags', type: 'table',
    extract: d => (d?.groups || []).filter(g => g.asset_count > 0),
    columns: [
      { key: 'rank', label: '#' },
      { key: 'value', label: 'Group' },
      { key: 'grade', label: 'Grade' },
      { key: 'avg_risk_score', label: 'Risk' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'finding_count', label: 'Findings' },
      { key: 'finding_density', label: 'Density' },
      { key: 'sla_compliance', label: 'SLA', render: v => v != null ? `${v}%` : 'N/A' },
    ],
  },
  remediation_queue_data: {
    label: 'Remediation Queue', group: 'Assets & Findings', source: 'remediation_queue', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'plugin_name', label: 'Finding' },
      { key: 'severity_label', label: 'Sev' },
      { key: 'asset_hostname', label: 'Asset', fallback: 'asset_ip' },
      { key: 'effort_level', label: 'Effort' },
      { key: 'priority_score', label: 'Priority', render: v => v?.toFixed?.(1) },
    ],
  },
  findings_list: {
    label: 'Findings List', group: 'Assets & Findings', source: 'findings', type: 'table',
    extract: d => d?.findings || [],
    columns: [
      { key: 'severity_label', label: 'Sev' },
      { key: 'plugin_name', label: 'Plugin' },
      { key: 'asset_hostname', label: 'Asset', fallback: 'asset_ip' },
      { key: 'priority_score', label: 'Priority', render: v => v?.toFixed?.(1) },
    ],
  },
  scan_delta_history: {
    label: 'Scan Delta History', group: 'SLA & Ops', source: 'delta_timeline', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'scan_name', label: 'Scan' },
      { key: 'scan_date', label: 'Date', render: v => v ? new Date(v).toLocaleDateString() : '—' },
      { key: 'new_count', label: 'New' },
      { key: 'fixed_count', label: 'Fixed' },
      { key: 'recurring_count', label: 'Recurring' },
      { key: 'net_change', label: 'Net' },
    ],
  },
  automation_wishlist: {
    label: 'Automation Wishlist', group: 'SLA & Ops', source: 'automation_wishlist', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'plugin_name', label: 'Finding' },
      { key: 'click_count', label: 'Requests' },
      { key: 'severity_label', label: 'Severity' },
      { key: 'plugin_family', label: 'Family' },
    ],
  },
  asset_list: {
    label: 'Asset List', group: 'Assets & Findings', source: 'assets', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'hostname', label: 'Hostname', fallback: 'ip' },
      { key: 'os', label: 'OS' },
      { key: 'environment_tag', label: 'Env' },
      { key: 'critical_count', label: 'C' },
      { key: 'high_count', label: 'H' },
      { key: 'risk_score', label: 'Risk', render: v => v?.toFixed?.(1) },
    ],
  },
  // ── Inventory tables ──
  inv_users_table: {
    label: 'Users', group: 'Inventory', source: 'inv_users', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'username', label: 'Username' },
      { key: 'domain', label: 'Domain' },
      { key: 'user_type', label: 'Type' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
      { key: 'is_local_admin', label: 'Admin', render: v => v ? 'Yes' : '' },
      { key: 'is_domain_admin', label: 'DA', render: v => v ? 'Yes' : '' },
      { key: 'is_privileged', label: 'Priv', render: v => v ? 'Yes' : '' },
    ],
  },
  inv_groups_table: {
    label: 'Groups', group: 'Inventory', source: 'inv_groups', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'group_name', label: 'Group' },
      { key: 'domain', label: 'Domain' },
      { key: 'is_privileged', label: 'Privileged', render: v => v ? 'Yes' : '' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
      { key: 'members', label: 'Members', render: v => Array.isArray(v) ? v.length : 0 },
    ],
  },
  inv_services_table: {
    label: 'Services', group: 'Inventory', source: 'inv_services', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'display_name', label: 'Service', fallback: 'service_name' },
      { key: 'is_running', label: 'Running', render: v => v ? 'Yes' : 'No' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_software_table: {
    label: 'Software', group: 'Inventory', source: 'inv_software', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'name', label: 'Name' },
      { key: 'version', label: 'Version' },
      { key: 'vendor', label: 'Vendor' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_logged_on_table: {
    label: 'Logged On Users', group: 'Inventory', source: 'inv_logged_on', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'username', label: 'Username' },
      { key: 'domain', label: 'Domain' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_netconns_table: {
    label: 'Network Connections', group: 'Inventory', source: 'inv_netconns', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'local_addr', label: 'Local' },
      { key: 'local_port', label: 'Port' },
      { key: 'remote_addr', label: 'Remote' },
      { key: 'remote_port', label: 'R.Port' },
      { key: 'state', label: 'State' },
      { key: 'proto', label: 'Proto' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_patches_table: {
    label: 'Missing Patches', group: 'Inventory', source: 'inv_patches', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'kb_id', label: 'KB' },
      { key: 'vuln_count', label: 'Vulns' },
      { key: 'description', label: 'Description' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_shares_table: {
    label: 'Network Shares', group: 'Inventory', source: 'inv_shares', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'share_name', label: 'Share' },
      { key: 'path', label: 'Path' },
      { key: 'is_writeable', label: 'Writeable', render: v => v ? 'Yes' : '' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_tasks_table: {
    label: 'Scheduled Tasks', group: 'Inventory', source: 'inv_tasks', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'task_uri', label: 'Task' },
      { key: 'command', label: 'Command' },
      { key: 'run_as_user', label: 'Run As', fallback: 'run_as_sid' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_computers_table: {
    label: 'Computers', group: 'Inventory', source: 'inv_computers', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'computer_name', label: 'Name' },
      { key: 'os', label: 'OS' },
      { key: 'is_domain_controller', label: 'DC', render: v => v ? 'Yes' : '' },
      { key: 'is_disabled', label: 'Disabled', render: v => v ? 'Yes' : '' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_certificates_table: {
    label: 'Certificates', group: 'Inventory', source: 'inv_certificates', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'subject_cn', label: 'Subject' },
      { key: 'issuer_cn', label: 'Issuer' },
      { key: 'not_after', label: 'Expires', render: v => v ? new Date(v).toLocaleDateString() : '—' },
      { key: 'is_expired', label: 'Expired', render: v => v ? 'Yes' : '' },
      { key: 'is_self_signed', label: 'Self-Signed', render: v => v ? 'Yes' : '' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_pw_policies_table: {
    label: 'Password Policies', group: 'Inventory', source: 'inv_pw_policies', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'domain', label: 'Domain' },
      { key: 'min_length', label: 'Min Len' },
      { key: 'max_age_days', label: 'Max Age' },
      { key: 'complexity_enabled', label: 'Complexity', render: v => v ? 'Yes' : 'No' },
      { key: 'lockout_threshold', label: 'Lockout' },
      { key: 'is_weak', label: 'Weak', render: v => v ? 'Yes' : '' },
    ],
  },
  inv_security_ctrls_table: {
    label: 'Security Controls', group: 'Inventory', source: 'inv_security_ctrls', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'product_name', label: 'Product' },
      { key: 'control_type', label: 'Type' },
      { key: 'is_enabled', label: 'Enabled', render: v => v ? 'Yes' : 'No' },
      { key: 'is_up_to_date', label: 'Updated', render: v => v ? 'Yes' : 'No' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_ai_tools_table: {
    label: 'AI Tools', group: 'Inventory', source: 'inv_ai_tools', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'tool_name', label: 'Tool' },
      { key: 'category', label: 'Category' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_processes_table: {
    label: 'Processes', group: 'Inventory', source: 'inv_processes', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    columns: [
      { key: 'process_name', label: 'Process' },
      { key: 'pid', label: 'PID' },
      { key: 'parent_name', label: 'Parent' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_top_patches: {
    label: 'Top Missing Patches', group: 'Inventory', source: 'inv_summary', type: 'table',
    extract: d => (d?.attack_surface?.top_missing_patches || []),
    columns: [
      { key: 'kb_id', label: 'KB' },
      { key: 'vuln_count', label: 'Vulns' },
      { key: 'affected_hosts', label: 'Hosts' },
    ],
  },
}

const PRESET_GROUPS = ['Severity', 'Risk', 'Temporal', 'SLA & Ops', 'Tags', 'Assets & Findings', 'Inventory', 'Filtered']

// ─── Widget catalogue ────────────────────────────────────────────────────────

const WIDGET_CATALOGUE = [
  {
    category: 'Charts',
    items: [
      { type: 'bar_chart',  label: 'Bar Chart',  icon: BarChart2,    desc: 'Vertical or horizontal bars', defaultWidth: 'full',  defaultConfig: { preset: 'severity_breakdown' } },
      { type: 'line_chart', label: 'Line Chart',  icon: TrendingUp,   desc: 'Line or area over time',      defaultWidth: 'full',  defaultConfig: { preset: 'severity_trend' } },
      { type: 'pie_chart',  label: 'Pie / Donut', icon: PieChartIcon, desc: 'Proportional breakdown',      defaultWidth: 'half',  defaultConfig: { preset: 'severity_breakdown', donut: true } },
    ],
  },
  {
    category: 'Data',
    items: [
      { type: 'card',    label: 'Metric Card', icon: Hash,     desc: 'Single number highlight', defaultWidth: 'quarter', defaultConfig: { preset: 'critical_count' } },
      { type: 'table',   label: 'Data Table',  icon: Table2,   desc: 'Tabular data view',       defaultWidth: 'full',    defaultConfig: { preset: 'top_assets', limit: 10 } },
      { type: 'heatmap', label: 'Heatmap',     icon: LayoutGrid, desc: 'Severity by family matrix', defaultWidth: 'full', defaultConfig: {} },
    ],
  },
  {
    category: 'Layout',
    items: [
      { type: 'header',  label: 'Header',  icon: PenLine,   desc: 'Section title & subtitle', defaultWidth: 'full', defaultConfig: { title: 'Section Title', subtitle: '' } },
      { type: 'divider', label: 'Divider',  icon: AlignLeft, desc: 'Horizontal rule',          defaultWidth: 'full', defaultConfig: {} },
      { type: 'image',   label: 'Image',    icon: Upload,    desc: 'Embed an image via URL',   defaultWidth: 'half', defaultConfig: { url: '' } },
    ],
  },
]

const WIDTH_OPTIONS = [
  { value: 'quarter', label: '1/4 Width' },
  { value: 'third', label: '1/3 Width' },
  { value: 'half', label: '1/2 Width' },
  { value: 'two-thirds', label: '2/3 Width' },
  { value: 'full', label: 'Full Width' },
]
const WIDTH_COL = { quarter: 1, third: 1, half: 2, 'two-thirds': 3, full: 4 }

// ─── OOTB templates ──────────────────────────────────────────────────────────

const DEFAULT_DASHBOARD = {
  id: DEFAULT_REPORT_ID,
  name: 'Security Overview',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'dw1', type: 'card',      title: 'Critical',              width: 'quarter', config: { preset: 'critical_count' } },
    { id: 'dw2', type: 'card',      title: 'High',                  width: 'quarter', config: { preset: 'high_count' } },
    { id: 'dw3', type: 'card',      title: 'With Exploit',          width: 'quarter', config: { preset: 'exploit_count' } },
    { id: 'dw4', type: 'card',      title: 'Assets',                width: 'quarter', config: { preset: 'total_assets' } },
    { id: 'dw5', type: 'pie_chart', title: 'Severity Breakdown',    width: 'half',    config: { preset: 'severity_breakdown', donut: true } },
    { id: 'dw6', type: 'line_chart',title: 'Vulnerability Trend',   width: 'half',    config: { preset: 'severity_trend' } },
    { id: 'dw7', type: 'bar_chart', title: 'Top Plugin Families',   width: 'full',    config: { preset: 'family_breakdown' } },
    { id: 'dw8', type: 'line_chart',title: 'Risk Score Trend',      width: 'full',    config: { preset: 'risk_trend' } },
    { id: 'dw9', type: 'pie_chart', title: 'Effort Distribution',   width: 'half',    config: { preset: 'effort_breakdown', donut: true } },
    { id: 'dw10',type: 'pie_chart', title: 'SLA Status',            width: 'half',    config: { preset: 'sla_status', donut: true } },
    { id: 'dw11',type: 'table',     title: 'Top Risky Assets',      width: 'full',    config: { preset: 'top_assets', limit: 10 } },
    { id: 'dw12',type: 'table',     title: 'Remediation Queue',     width: 'full',    config: { preset: 'remediation_queue_data', limit: 10 } },
  ],
}

const EXECUTIVE_DASHBOARD = {
  id: 'default-executive-overview',
  name: 'Executive Overview',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'ex1', type: 'card',      title: 'Critical',              width: 'quarter', config: { preset: 'critical_count' } },
    { id: 'ex2', type: 'card',      title: 'SLA Compliance',        width: 'quarter', config: { preset: 'sla_compliance' } },
    { id: 'ex3', type: 'card',      title: 'Exploitable',           width: 'quarter', config: { preset: 'exploit_count' } },
    { id: 'ex4', type: 'card',      title: 'Quick Wins',            width: 'quarter', config: { preset: 'quick_wins' } },
    { id: 'ex5', type: 'pie_chart', title: 'Severity Distribution', width: 'half',    config: { preset: 'severity_breakdown', donut: true } },
    { id: 'ex6', type: 'pie_chart', title: 'SLA Status',            width: 'half',    config: { preset: 'sla_status', donut: true } },
    { id: 'ex7', type: 'bar_chart', title: 'Risk by Business Unit', width: 'full',    config: { preset: 'risk_by_tags', horizontal: true } },
    { id: 'ex8', type: 'table',     title: 'Business Unit Benchmark', width: 'full',  config: { preset: 'tag_benchmark' } },
    { id: 'ex9', type: 'line_chart',title: 'Risk Score Trend',      width: 'half',    config: { preset: 'risk_trend' } },
    { id: 'ex10',type: 'line_chart',title: 'SLA Compliance Trend',  width: 'half',    config: { preset: 'sla_trend', areaFill: true } },
    { id: 'ex11',type: 'bar_chart', title: 'Remediation Velocity',  width: 'half',    config: { preset: 'velocity_trend', stacked: true } },
    { id: 'ex12',type: 'line_chart',title: 'Severity Trend',        width: 'half',    config: { preset: 'severity_trend' } },
  ],
}

// ─── Live widget renderers ────────────────────────────────────────────────────

function useWidgetData(sourceId, scanId, filters) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const filtersKey = JSON.stringify(filters || {})

  useEffect(() => {
    if (!sourceId || !DATA_SOURCES[sourceId]) { setLoading(false); return }
    setLoading(true)
    let cancelled = false
    DATA_SOURCES[sourceId](scanId, filters)
      .then(d => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [sourceId, scanId, filtersKey])

  return { data, loading }
}

const TOOLTIP_STYLE = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }
const TICK_STYLE = { fill: 'var(--text-muted)', fontSize: 11 }

function truncLabel(s, max = 18) { return (s || '').length > max ? s.slice(0, max) + '...' : s || '' }

function WidgetRenderer({ widget, scanId, preview }) {
  const cfg = widget.config || {}
  const preset = DATA_PRESETS[cfg.preset]
  const sourceId = preset?.source || null
  const filters = { ...(cfg.filters || {}), category: cfg.category, period: cfg.period }
  const { data, loading } = useWidgetData(sourceId, scanId, filters)

  // Layout widgets — no data needed
  if (widget.type === 'header') {
    return (
      <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 14 }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{cfg.title || 'Section'}</div>
        {cfg.subtitle && <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{cfg.subtitle}</div>}
      </div>
    )
  }
  if (widget.type === 'divider') {
    return <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />
  }
  if (widget.type === 'image') {
    return cfg.url
      ? <img src={cfg.url} alt={widget.title || 'Image'} style={{ maxWidth: '100%', borderRadius: 8 }} />
      : <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Set an image URL in widget config</div>
  }

  // Data widgets
  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 100 }}><Spinner /></div>
  if (!data || !preset) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No data available</div>

  const extracted = preset.extract(data)

  switch (widget.type) {
    case 'card': {
      const val = typeof extracted === 'number' ? extracted : 0
      const display = preset.format === 'pct' ? `${val}%` : val.toLocaleString()
      const color = preset.color || 'var(--text-primary)'
      return (
        <div style={{ textAlign: 'center', padding: '8px 0' }}>
          <div style={{ fontSize: 48, fontWeight: 800, color, lineHeight: 1 }}>{display}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>{cfg.label || preset.label}</div>
        </div>
      )
    }

    case 'pie_chart': {
      if (!Array.isArray(extracted) || extracted.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No data</div>
      const items = extracted.map((d, i) => ({ ...d, color: d.color || PALETTE[i % PALETTE.length] }))
      return (
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={items} cx="50%" cy="50%" innerRadius={cfg.donut ? 50 : 0} outerRadius={70} paddingAngle={2} dataKey="value">
              {items.map((e, i) => <Cell key={i} fill={e.color} />)}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend iconType="circle" iconSize={9} formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
          </PieChart>
        </ResponsiveContainer>
      )
    }

    case 'bar_chart': {
      if (preset.type === 'categories') {
        const items = Array.isArray(extracted) ? extracted : []
        if (items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No data</div>
        const colored = items.map((d, i) => ({ ...d, color: d.color || PALETTE[i % PALETTE.length] }))
        if (cfg.horizontal) {
          return (
            <ResponsiveContainer width="100%" height={Math.max(160, colored.length * 30)}>
              <BarChart data={colored} layout="vertical" margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                <XAxis type="number" tick={TICK_STYLE} />
                <YAxis type="category" dataKey="name" tick={{ ...TICK_STYLE, fontSize: 11 }} width={140} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {colored.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )
        }
        return (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={colored}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={TICK_STYLE} />
              <YAxis tick={TICK_STYLE} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {colored.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )
      }
      // series type
      const rows = Array.isArray(extracted) ? extracted : []
      if (rows.length < 2) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need 2+ data points</div>
      const fields = preset.fields || []
      const chartData = rows.map(r => ({ name: truncLabel(r[preset.xField]), ...Object.fromEntries(fields.map(f => [f, r[f] ?? null])) }))
      return (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={chartData} stackOffset={cfg.stacked ? 'sign' : 'none'}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ ...TICK_STYLE, fontSize: 10 }} />
            <YAxis tick={TICK_STYLE} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
            {fields.map(f => (
              <Bar key={f} dataKey={f} fill={preset.colors?.[f] || PALETTE[fields.indexOf(f) % PALETTE.length]} radius={[3, 3, 0, 0]} stackId={cfg.stacked ? 'a' : undefined} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      )
    }

    case 'line_chart': {
      const rows = Array.isArray(extracted) ? extracted : []
      if (rows.length < 2) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need 2+ data points</div>
      const fields = preset.fields || []
      const chartData = rows.map(r => ({ name: truncLabel(r[preset.xField]), ...Object.fromEntries(fields.map(f => [f, r[f] ?? null])) }))
      const ChartComp = cfg.areaFill ? AreaChart : LineChart
      return (
        <ResponsiveContainer width="100%" height={220}>
          <ChartComp data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ ...TICK_STYLE, fontSize: 10 }} />
            <YAxis tick={TICK_STYLE} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
            {fields.map(f => {
              const color = preset.colors?.[f] || PALETTE[fields.indexOf(f) % PALETTE.length]
              return cfg.areaFill
                ? <Area key={f} type="monotone" dataKey={f} stroke={color} fill={color} fillOpacity={0.15} strokeWidth={2} dot={{ fill: color, r: 3 }} connectNulls />
                : <Line key={f} type="monotone" dataKey={f} stroke={color} strokeWidth={2} dot={{ fill: color, r: 3 }} connectNulls />
            })}
          </ChartComp>
        </ResponsiveContainer>
      )
    }

    case 'table': {
      const rows = Array.isArray(extracted) ? extracted : []
      const limit = parseInt(cfg.limit || 10)
      const display = rows.slice(0, limit)
      const cols = preset.columns || []
      if (display.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No data</div>
      return (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {cols.map(c => (
                  <th key={c.key} style={{ padding: '6px 8px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{c.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {display.map((row, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  {cols.map(c => {
                    const raw = row[c.key] ?? (c.fallback ? row[c.fallback] : null) ?? ''
                    const val = c.render ? c.render(raw) : raw
                    return (
                      <td key={c.key} style={{ padding: '6px 8px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val}</td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }

    case 'heatmap': {
      // Simple severity x family matrix
      const families = data?.top_plugin_families || []
      const sevLabels = ['Critical', 'High', 'Medium', 'Low']
      const sevKeys = ['critical', 'high', 'medium', 'low']
      const heatColors = ['#dc2626', '#ea580c', '#d97706', '#65a30d']
      if (families.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No family data</div>
      return (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead>
              <tr>
                <th style={{ padding: '6px 8px', textAlign: 'left', color: 'var(--text-muted)' }}>Family</th>
                {sevLabels.map(s => <th key={s} style={{ padding: '6px 8px', textAlign: 'center', color: 'var(--text-muted)' }}>{s}</th>)}
              </tr>
            </thead>
            <tbody>
              {families.slice(0, 10).map((f, i) => (
                <tr key={i}>
                  <td style={{ padding: '6px 8px', fontWeight: 500, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.family}</td>
                  {sevKeys.map((s, si) => {
                    const v = f[s] || 0
                    return (
                      <td key={s} style={{ padding: '6px 8px', textAlign: 'center' }}>
                        {v > 0 && <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 4, background: `${heatColors[si]}20`, color: heatColors[si], fontWeight: 600, fontSize: 11 }}>{v}</span>}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }

    default:
      return <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Unknown widget type: {widget.type}</div>
  }
}

// ─── Widget config panel ──────────────────────────────────────────────────────

function ConfigPanel({ widget, onUpdate, onClose }) {
  const cfg = widget.config || {}
  const set = (key, val) => onUpdate({ ...widget, config: { ...cfg, [key]: val } })
  const setTitle = (t) => onUpdate({ ...widget, title: t })
  const setWidth = (w) => onUpdate({ ...widget, width: w })

  const Field = ({ label, children }) => (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>{label}</div>
      {children}
    </div>
  )
  const Select = ({ value, onChange, options }) => (
    <select value={value || ''} onChange={e => onChange(e.target.value)}
      style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
  const TextInput = ({ value, onChange, placeholder }) => (
    <input value={value || ''} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, boxSizing: 'border-box' }} />
  )
  const Toggle = ({ checked, onChange, label }) => (
    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
      <input type="checkbox" checked={!!checked} onChange={e => onChange(e.target.checked)} />
      {label}
    </label>
  )

  const presetType = widget.type === 'card' ? 'metric'
    : widget.type === 'pie_chart' ? 'categories'
    : widget.type === 'bar_chart' ? null // categories or series
    : widget.type === 'line_chart' ? 'series'
    : widget.type === 'table' ? 'table'
    : null

  const compatiblePresets = presetType
    ? Object.entries(DATA_PRESETS).filter(([, p]) => p.type === presetType)
    : widget.type === 'bar_chart'
      ? Object.entries(DATA_PRESETS).filter(([, p]) => p.type === 'categories' || p.type === 'series')
      : []

  const presetOptions = (() => {
    const grouped = {}
    for (const [id, p] of compatiblePresets) {
      const g = p.group || 'Other'
      if (!grouped[g]) grouped[g] = []
      grouped[g].push({ value: id, label: p.label })
    }
    const result = []
    for (const g of PRESET_GROUPS) {
      if (grouped[g]) {
        result.push({ value: `__group_${g}`, label: `── ${g} ──`, disabled: true })
        result.push(...grouped[g])
      }
    }
    return result
  })()

  const isDataWidget = ['card', 'pie_chart', 'bar_chart', 'line_chart', 'table'].includes(widget.type)

  return (
    <div style={{ width: 260, flexShrink: 0, background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Settings2 size={14} color="var(--accent)" /> Widget Config
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <X size={14} />
        </button>
      </div>

      <Field label="Widget Title">
        <TextInput value={widget.title} onChange={setTitle} placeholder="Widget title..." />
      </Field>
      <Field label="Width">
        <Select value={widget.width} onChange={setWidth} options={WIDTH_OPTIONS} />
      </Field>

      {isDataWidget && presetOptions.length > 0 && (
        <Field label="Data Preset">
          <select value={cfg.preset || ''} onChange={e => set('preset', e.target.value)}
            style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            {presetOptions.map(o => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
          </select>
        </Field>
      )}

      {widget.type === 'card' && (
        <Field label="Display Label">
          <TextInput value={cfg.label} onChange={v => set('label', v)} placeholder={DATA_PRESETS[cfg.preset]?.label || 'Label'} />
        </Field>
      )}

      {widget.type === 'pie_chart' && (
        <Field label="Donut">
          <Toggle checked={cfg.donut} onChange={v => set('donut', v)} label="Donut hole" />
        </Field>
      )}

      {widget.type === 'bar_chart' && (
        <>
          <Field label="Horizontal">
            <Toggle checked={cfg.horizontal} onChange={v => set('horizontal', v)} label="Horizontal layout" />
          </Field>
          {DATA_PRESETS[cfg.preset]?.type === 'series' && (
            <Field label="Stacked">
              <Toggle checked={cfg.stacked} onChange={v => set('stacked', v)} label="Stack bars" />
            </Field>
          )}
        </>
      )}

      {widget.type === 'line_chart' && (
        <Field label="Area Fill">
          <Toggle checked={cfg.areaFill} onChange={v => set('areaFill', v)} label="Fill area under lines" />
        </Field>
      )}

      {widget.type === 'table' && (
        <Field label="Row Limit">
          <Select value={String(cfg.limit || 10)} onChange={v => set('limit', v)}
            options={[{ value: '5', label: '5 rows' }, { value: '10', label: '10 rows' }, { value: '20', label: '20 rows' }, { value: '50', label: '50 rows' }]} />
        </Field>
      )}

      {widget.type === 'header' && (
        <>
          <Field label="Title">
            <TextInput value={cfg.title} onChange={v => set('title', v)} placeholder="Section title" />
          </Field>
          <Field label="Subtitle">
            <TextInput value={cfg.subtitle} onChange={v => set('subtitle', v)} placeholder="Optional subtitle" />
          </Field>
        </>
      )}

      {widget.type === 'image' && (
        <Field label="Image URL">
          <TextInput value={cfg.url} onChange={v => set('url', v)} placeholder="https://..." />
        </Field>
      )}

      {/* Dynamic filters based on data source */}
      {(() => {
        const preset = DATA_PRESETS[cfg.preset]
        const sourceFilters = preset ? SOURCE_FILTERS[preset.source] : null
        if (!sourceFilters || sourceFilters.length === 0) return null
        const filters = cfg.filters || {}
        const setFilter = (key, val) => set('filters', { ...filters, [key]: val || undefined })
        return (
          <>
            <div style={{ height: 1, background: 'var(--border)', margin: '10px 0 14px' }} />
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>Filters</div>
            {sourceFilters.map(f => (
              <Field key={f.key} label={f.label}>
                {f.type === 'select' ? (
                  <Select value={filters[f.key] || ''} onChange={v => setFilter(f.key, v)} options={f.options} />
                ) : f.type === 'number' ? (
                  <input type="number" value={filters[f.key] || ''} onChange={e => setFilter(f.key, e.target.value)} placeholder={f.placeholder}
                    style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, boxSizing: 'border-box' }} />
                ) : (
                  <TextInput value={filters[f.key] || ''} onChange={v => setFilter(f.key, v)} placeholder={f.placeholder} />
                )}
              </Field>
            ))}
          </>
        )
      })()}
    </div>
  )
}

// ─── Widget library sidebar ───────────────────────────────────────────────────

function WidgetLibrary({ onAdd }) {
  return (
    <div style={{ width: 220, flexShrink: 0, background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)', overflowY: 'auto', padding: '12px 0' }}>
      <div style={{ padding: '0 14px 10px', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Widget Library</div>
      {WIDGET_CATALOGUE.map(cat => (
        <div key={cat.category}>
          <div style={{ padding: '8px 14px 6px', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', opacity: 0.6 }}>{cat.category}</div>
          {cat.items.map(w => {
            const Icon = w.icon
            return (
              <div
                key={w.type}
                onClick={() => onAdd(w)}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 14px',
                  cursor: 'pointer', transition: 'background 0.1s', borderRadius: 0,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <div style={{ width: 28, height: 28, borderRadius: 8, background: '#6366f122', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Icon size={14} color="#818cf8" />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{w.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>{w.desc}</div>
                </div>
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}

// ─── Main canvas widget card ──────────────────────────────────────────────────

function CanvasWidget({ widget, index, total, scanId, isSelected, onSelect, onUpdate, onDelete, onMoveUp, onMoveDown, preview }) {
  const col = WIDTH_COL[widget.width] || 4

  return (
    <div
      style={{
        gridColumn: `span ${col}`,
        background: 'var(--bg-card)',
        border: `1px solid ${isSelected && !preview ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 10,
        overflow: 'hidden',
        boxShadow: isSelected && !preview ? '0 0 0 2px rgba(99,102,241,0.2)' : 'none',
        transition: 'border-color 0.15s, box-shadow 0.15s',
        position: 'relative',
      }}
      onClick={() => !preview && onSelect()}
    >
      {/* Widget header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        background: isSelected && !preview ? 'rgba(99,102,241,0.05)' : 'transparent',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {!preview && <GripVertical size={14} color="var(--text-muted)" style={{ cursor: 'grab' }} />}
          <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{widget.title}</span>
        </div>
        {!preview && (
          <div style={{ display: 'flex', gap: 4 }} onClick={e => e.stopPropagation()}>
            <button onClick={() => onMoveUp()} disabled={index === 0} title="Move up"
              style={{ background: 'none', border: 'none', color: index === 0 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: index === 0 ? 'default' : 'pointer', padding: 3 }}>
              <ChevronUp size={14} />
            </button>
            <button onClick={() => onMoveDown()} disabled={index === total - 1} title="Move down"
              style={{ background: 'none', border: 'none', color: index === total - 1 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: index === total - 1 ? 'default' : 'pointer', padding: 3 }}>
              <ChevronDown size={14} />
            </button>
            <button onClick={() => onDelete()} title="Remove widget"
              style={{ background: 'none', border: 'none', color: '#dc2626', cursor: 'pointer', padding: 3, opacity: 0.7 }}>
              <Trash2 size={13} />
            </button>
          </div>
        )}
      </div>

      {/* Widget content */}
      <div style={{ padding: 16 }}>
        <WidgetRenderer widget={widget} scanId={scanId} preview={preview} />
      </div>
    </div>
  )
}

// ─── Builder view ─────────────────────────────────────────────────────────────

function Builder({ report, onSave, onBack, isLanding, onSetLanding }) {
  const { activeScanId, scans } = useScan()
  const navigate = useNavigate()
  const [widgets, setWidgets] = useState(report.widgets || [])
  const [name, setName] = useState(report.name || 'Untitled Report')
  const [selectedId, setSelectedId] = useState(null)
  const [preview, setPreview] = useState(true)
  const [saved, setSaved] = useState(false)
  const [editingName, setEditingName] = useState(false)

  const selectedWidget = widgets.find(w => w.id === selectedId)

  const addWidget = (catalogItem) => {
    const newWidget = {
      id: uid(),
      type: catalogItem.type,
      title: catalogItem.label,
      width: catalogItem.defaultWidth || 'full',
      config: { ...catalogItem.defaultConfig },
    }
    setWidgets(prev => [...prev, newWidget])
    setSelectedId(newWidget.id)
  }

  const updateWidget = (updated) => {
    setWidgets(prev => prev.map(w => w.id === updated.id ? updated : w))
  }

  const deleteWidget = (id) => {
    setWidgets(prev => prev.filter(w => w.id !== id))
    if (selectedId === id) setSelectedId(null)
  }

  const moveWidget = (id, dir) => {
    setWidgets(prev => {
      const idx = prev.findIndex(w => w.id === id)
      const next = [...prev]
      if (dir === 'up' && idx > 0) {
        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]]
      } else if (dir === 'down' && idx < next.length - 1) {
        [next[idx], next[idx + 1]] = [next[idx + 1], next[idx]]
      }
      return next
    })
  }

  const handleSave = () => {
    onSave({ ...report, name, widgets })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px',
        background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', flexShrink: 0,
      }}>
        <button onClick={onBack} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, padding: '4px 8px', borderRadius: 6 }}>
          <ArrowLeft size={15} /> Reports
        </button>

        <div style={{ width: 1, height: 20, background: 'var(--border)' }} />

        {/* Editable report name */}
        {editingName ? (
          <input
            autoFocus
            value={name}
            onChange={e => setName(e.target.value)}
            onBlur={() => setEditingName(false)}
            onKeyDown={e => e.key === 'Enter' && setEditingName(false)}
            style={{
              background: 'var(--bg-card)', border: '1px solid var(--accent)', color: 'var(--text-primary)',
              borderRadius: 6, padding: '4px 10px', fontSize: 14, fontWeight: 600, width: 240,
            }}
          />
        ) : (
          <div
            onClick={() => setEditingName(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '4px 8px', borderRadius: 6 }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <span style={{ fontWeight: 700, fontSize: 14 }}>{name}</span>
            <PenLine size={12} color="var(--text-muted)" />
          </div>
        )}

        <div style={{ flex: 1 }} />

        <button
          onClick={() => setPreview(p => !p)}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: preview ? '#6366f122' : 'transparent', border: '1px solid var(--border)', color: preview ? '#818cf8' : 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 500 }}
        >
          {preview ? <><EyeOff size={14} /> Edit</> : <><Eye size={14} /> Preview</>}
        </button>

        <button
          onClick={isLanding ? undefined : onSetLanding}
          title={isLanding ? 'This is your landing page' : 'Set as landing page'}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: isLanding ? '#16a34a22' : 'transparent', border: `1px solid ${isLanding ? '#16a34a' : 'var(--border)'}`, color: isLanding ? '#16a34a' : 'var(--text-secondary)', borderRadius: 6, cursor: isLanding ? 'default' : 'pointer', fontSize: 13, fontWeight: 500 }}
        >
          <Home size={14} /> {isLanding ? 'Landing' : 'Set as Home'}
        </button>

        <button
          onClick={handleSave}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', background: saved ? '#16a34a' : 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600, transition: 'background 0.2s' }}
        >
          {saved ? <><CheckCircle size={14} /> Saved!</> : <><Save size={14} /> Save</>}
        </button>
      </div>

      {/* Body */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Widget library */}
        {!preview && <WidgetLibrary onAdd={addWidget} />}

        {/* Canvas */}
        <div
          style={{ flex: 1, overflowY: 'auto', padding: 20, background: preview ? 'var(--bg-primary)' : '#0d0f1a' }}
          onClick={() => setSelectedId(null)}
        >
          {preview && (
            <div style={{ maxWidth: 900, margin: '0 auto 20px', textAlign: 'center' }}>
              <h1 style={{ fontSize: 24, fontWeight: 800 }}>{name}</h1>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>Custom Security Report · Generated {new Date().toLocaleDateString()}</div>
            </div>
          )}

          {preview && (!scans || scans.length === 0) && (
            <div style={{
              maxWidth: 560, margin: '0 auto 28px', padding: '32px 28px',
              background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.06))',
              border: '1px solid rgba(99,102,241,0.25)', borderRadius: 14,
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, textAlign: 'center',
            }}>
              <div style={{
                width: 52, height: 52, borderRadius: 14,
                background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Upload size={26} color="#818cf8" />
              </div>
              <div>
                <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)' }}>Upload your first scan</div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.5 }}>
                  Import a Nessus scan (.nessus, .csv, or .html) to populate your dashboard with vulnerability data, asset inventory, and remediation priorities.
                </div>
              </div>
              <button
                onClick={() => navigate('/upload')}
                style={{
                  marginTop: 4, padding: '10px 24px', background: 'var(--accent)', border: 'none',
                  color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}
              >
                <Upload size={16} /> Upload Scan
              </button>
            </div>
          )}

          {widgets.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, color: 'var(--text-muted)', gap: 12 }}>
              <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>Canvas is empty</div>
              <div style={{ fontSize: 13, textAlign: 'center', maxWidth: 280 }}>Click any widget from the library on the left to add it to your report</div>
            </div>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 14,
              maxWidth: preview ? 1000 : 'none',
              margin: preview ? '0 auto' : 0,
            }}
              onClick={e => e.stopPropagation()}
            >
              {widgets.map((widget, i) => (
                <CanvasWidget
                  key={widget.id}
                  widget={widget}
                  index={i}
                  total={widgets.length}
                  scanId={activeScanId}
                  isSelected={selectedId === widget.id}
                  preview={preview}
                  onSelect={() => setSelectedId(widget.id === selectedId ? null : widget.id)}
                  onUpdate={updateWidget}
                  onDelete={() => deleteWidget(widget.id)}
                  onMoveUp={() => moveWidget(widget.id, 'up')}
                  onMoveDown={() => moveWidget(widget.id, 'down')}
                />
              ))}
            </div>
          )}
        </div>

        {/* Config panel */}
        {!preview && selectedWidget && (
          <ConfigPanel
            widget={selectedWidget}
            onUpdate={updateWidget}
            onClose={() => setSelectedId(null)}
          />
        )}
      </div>
    </div>
  )
}

// ─── Report list (landing) ────────────────────────────────────────────────────

function ReportList({ reports, onCreate, onOpen, onDelete, onDuplicate, landingId, onSetLanding, onRefresh }) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Reports</h2>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>Build and save custom dashboards — set any as your landing page</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ExportImportButtons
            configType="report_template"
            exportFn={() => exportConfig('report_template')}
            onImported={onRefresh}
            label="Report Templates"
          />
          <button
            onClick={onCreate}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 18px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14 }}
          >
            <Plus size={16} /> New Report
          </button>
        </div>
      </div>

      {reports.length === 0 ? (
        <div style={{
          border: '2px dashed var(--border)', borderRadius: 14, padding: '60px 24px',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, textAlign: 'center',
        }}>
          <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>No custom reports yet</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 320 }}>
            Create your first report by clicking "New Report". Mix and match widgets — stat cards, charts, tables, and text — and save for reuse.
          </div>
          <button
            onClick={onCreate}
            style={{ marginTop: 4, padding: '9px 20px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={15} /> Create first report
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {reports.map(report => {
            const isHome = report.id === landingId
            return (
              <div key={report.id} style={{ background: 'var(--bg-card)', border: `1px solid ${isHome ? '#16a34a55' : 'var(--border)'}`, borderRadius: 12, overflow: 'hidden' }}>
                {/* Preview strip */}
                <div style={{ height: 80, background: 'linear-gradient(135deg, #1e2235 0%, #252840 100%)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {(report.widgets || []).slice(0, 4).map((w, i) => {
                      const catItem = WIDGET_CATALOGUE.flatMap(c => c.items).find(x => x.type === w.type)
                      const Icon = catItem?.icon || LayoutGrid
                      return (
                        <div key={i} style={{ width: 32, height: 32, borderRadius: 8, background: '#6366f133', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Icon size={15} color="#818cf8" />
                        </div>
                      )
                    })}
                    {(report.widgets || []).length > 4 && (
                      <div style={{ fontSize: 12, color: '#818cf8', fontWeight: 600 }}>+{report.widgets.length - 4}</div>
                    )}
                    {(report.widgets || []).length === 0 && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Empty report</div>
                    )}
                  </div>
                  {isHome && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: '#16a34a', background: '#16a34a22', padding: '4px 8px', borderRadius: 6 }}>
                      <Home size={11} /> Landing
                    </div>
                  )}
                </div>

                <div style={{ padding: '14px 16px' }}>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{report.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                    {(report.widgets || []).length} widget{(report.widgets || []).length !== 1 ? 's' : ''} ·
                    Created {new Date(report.createdAt).toLocaleDateString()}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => onOpen(report)} style={{ flex: 1, padding: '7px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontWeight: 600, fontSize: 13 }}>
                      Open
                    </button>
                    {!isHome && (
                      <button onClick={() => onSetLanding(report.id)} title="Set as landing page" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                        <Home size={14} />
                      </button>
                    )}
                    <button onClick={() => onDuplicate(report)} title="Duplicate" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                      <Copy size={14} />
                    </button>
                    <button onClick={() => onDelete(report.id)} title="Delete" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: '#dc2626', borderRadius: 6, cursor: 'pointer' }}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Root export ──────────────────────────────────────────────────────────────

export default function ReportBuilder() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [landingId, setLandingId] = useState(loadLandingId)
  const [activeReport, setActiveReport] = useState(null)

  const loadFromApi = useCallback(async () => {
    try {
      await migrateLocalStorageReports()
      let templates = await getReportTemplates()
      let needsReload = false

      // Ensure default dashboards exist and stay up-to-date
      const ootb = [DEFAULT_DASHBOARD, EXECUTIVE_DASHBOARD]
      for (const dash of ootb) {
        const fingerprint = dash.widgets.map(w => `${w.id}:${w.type}:${w.config?.preset || ''}`).join('|')
        const existing = templates.find(t => t.name === dash.name)
        if (!existing) {
          await createReportTemplate({
            name: dash.name,
            config: { widgets: dash.widgets, createdAt: dash.createdAt, _fp: fingerprint },
            is_default: true,
          })
          needsReload = true
        } else if (existing.config?._fp !== fingerprint) {
          // Widget definitions changed — update the template
          await updateReportTemplate(existing.id, {
            name: dash.name,
            config: { widgets: dash.widgets, createdAt: dash.createdAt, _fp: fingerprint },
          })
          needsReload = true
        }
      }

      if (needsReload) {
        templates = await getReportTemplates()
      }
      const mapped = templates.map(templateToReport)
      setReports(mapped)
      // Auto-open landing report on first load
      if (!activeReport) {
        const lid = loadLandingId()
        const found = mapped.find(r => String(r.id) === String(lid)) || mapped[0] || null
        setActiveReport(found)
      }
    } catch (e) {
      console.error('Failed to load report templates', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadFromApi() }, [loadFromApi])

  const setLanding = (id) => {
    setLandingId(id)
    saveLandingId(id)
  }

  const createReport = () => {
    const report = { id: null, name: 'Untitled Report', createdAt: new Date().toISOString(), widgets: [] }
    setActiveReport(report)
  }

  const openReport = (report) => setActiveReport(report)

  const saveReport = async (updated) => {
    try {
      if (updated.id) {
        await updateReportTemplate(updated.id, {
          name: updated.name,
          config: { widgets: updated.widgets || [], createdAt: updated.createdAt },
        })
      } else {
        const result = await createReportTemplate({
          name: updated.name,
          config: { widgets: updated.widgets || [], createdAt: updated.createdAt },
        })
        updated = { ...updated, id: result.id }
      }
      setActiveReport(updated)
      loadFromApi()
    } catch (e) {
      console.error('Failed to save report', e)
    }
  }

  const deleteReport = async (id) => {
    if (!confirm('Delete this report?')) return
    try {
      await apiDeleteTemplate(id)
      const next = reports.filter(r => r.id !== id)
      setReports(next)
      if (activeReport?.id === id) setActiveReport(null)
      if (String(landingId) === String(id)) {
        const fallback = next[0]?.id || DEFAULT_REPORT_ID
        setLanding(fallback)
      }
    } catch (e) {
      console.error('Failed to delete report', e)
    }
  }

  const duplicateReport = async (report) => {
    try {
      const result = await createReportTemplate({
        name: `${report.name} (copy)`,
        config: { widgets: (report.widgets || []).map(w => ({ ...w, id: uid() })), createdAt: new Date().toISOString() },
      })
      loadFromApi()
    } catch (e) {
      console.error('Failed to duplicate report', e)
    }
  }

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /> Loading reports...</div>

  if (activeReport) {
    return (
      <div style={{ margin: '-24px', height: 'calc(100vh - 49px)', display: 'flex', flexDirection: 'column' }}>
        <Builder
          report={activeReport}
          onSave={saveReport}
          onBack={() => setActiveReport(null)}
          isLanding={activeReport.id === landingId}
          onSetLanding={() => setLanding(activeReport.id)}
        />
      </div>
    )
  }

  return (
    <ReportList
      reports={reports}
      onCreate={createReport}
      onOpen={openReport}
      onDelete={deleteReport}
      onDuplicate={duplicateReport}
      landingId={landingId}
      onSetLanding={setLanding}
      onRefresh={loadFromApi}
    />
  )
}
