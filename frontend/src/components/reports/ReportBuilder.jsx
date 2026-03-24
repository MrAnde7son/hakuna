/**
 * Self-service Report Builder
 * Drag-and-drop (via up/down controls) widget canvas with live data previews.
 * Reports are saved to localStorage.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams } from 'react-router-dom'
import {
  BarChart2, PieChart as PieChartIcon, Table2, Hash, AlignLeft, Wrench,
  Shield, Users, Server, Bug, Plus, Trash2, ChevronUp, ChevronDown,
  Save, Eye, EyeOff, ArrowLeft, Copy, Settings2, GripVertical,
  CheckCircle, LayoutGrid, Maximize2, Minimize2, X, PenLine,
  TrendingUp, Zap, Clock, Home, Upload, GitCompare,
  Download, FileImage, FileText, FileBarChart2, Sparkles, Filter,
  Crosshair, TreePine, Gauge, Search
} from 'lucide-react'
import NLPReportBuilder from './NLPReportBuilder.jsx'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid, LineChart, Line,
  AreaChart, Area,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Treemap as RechartsTreemap,
  RadialBarChart, RadialBar,
} from 'recharts'
import { useScan } from '../../App.jsx'
import {
  getSummary, getAssets, getFindings, getRemediationQueue, getPluginFamilies,
  getTrending, getSLASummary, getAutomateClicks, getScanDeltaTimeline, getMetricsTimeline,
  getTemporalSummary, getRemediationVelocity,
  getReportTemplates, createReportTemplate, updateReportTemplate, deleteReportTemplate as apiDeleteTemplate,
  exportConfig,
  getRiskByTags, getOwnerRiskSummary, getTags, getBenchmarks, getOsSoftwareSummary,
  getInventorySummary, getInventoryUsers, getInventoryGroups, getInventoryServices,
  getInventoryNetconns, getInventoryTasks, getInventoryPatches, getInventoryLoggedOn,
  getInventoryShares, getInventorySoftware, getInventorySecurityControls, getInventoryComputers,
  getInventoryPasswordPolicies, getInventoryCertificates, getInventoryAITools, getInventoryProcesses,
  getInventoryCredentials,
  getFunnel,
  getRiskGrade,
  getAggregatedSolutions,
  getEasmStatus,
  getEasmAssets,
  getEasmEvents,
  getEasmBreaches,
  getEasmSubsidiaries,
} from '../../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, EffortBadge, OwnerBadge, Button, Pill, ExportImportButtons, ErrorBanner, SkeletonCard } from '../shared/ui.jsx'

// ─── Storage helpers ─────────────────────────────────────────────────────────

const STORAGE_KEY = 'nessus_custom_reports'
const MIGRATED_KEY = 'nessus_reports_migrated'
const LANDING_KEY = 'nessus_landing_report'
const DEFAULT_REPORT_ID = 'default-executive-overview'

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
  summary:            (scanId, f) => getSummary(scanId, f?.tags, f?.tag_logic),
  sla:                (scanId, f) => getSLASummary(scanId),
  trending:           (scanId, f) => getTrending(),
  metrics_timeline:   (scanId, f) => getMetricsTimeline(),
  delta_timeline:     (scanId, f) => getScanDeltaTimeline(),
  velocity:           (scanId, f) => getRemediationVelocity(f?.period || 'month'),
  temporal:           (scanId, f) => getTemporalSummary(scanId),
  assets:             (scanId, f) => getAssets({ scan_id: scanId, search: f?.search, min_risk: f?.min_risk, max_risk: f?.max_risk, environment: f?.environment, min_critical: f?.min_critical, min_high: f?.min_high, has_findings: f?.has_findings, sort_by: f?.sort_by || 'risk_score', order: f?.order || 'desc', tags: f?.tags, tag_logic: f?.tag_logic, page_size: 0 }),
  findings:           (scanId, f) => getFindings({ scan_id: scanId, severity: f?.severity, plugin_family: f?.plugin_family, has_exploit: f?.has_exploit, effort_level: f?.effort_level, sla_status: f?.sla_status, search: f?.search, sort_by: f?.sort_by || 'priority_score', order: f?.order || 'desc', page_size: f?.page_size || 50, tags: f?.tags, tag_logic: f?.tag_logic }),
  remediation_queue:  (scanId, f) => getRemediationQueue({ scan_id: scanId, effort: f?.effort, owner: f?.owner, min_severity: f?.min_severity, limit: f?.limit || 20 }),
  automation_wishlist:(scanId, f) => getAutomateClicks(),
  risk_by_tags:       (scanId, f) => getRiskByTags({ scan_id: scanId, category: f?.category }),
  owner_risk:         (scanId, f) => getOwnerRiskSummary({ scan_id: scanId }),
  plugin_families:    (scanId, f) => getPluginFamilies(scanId, f?.tags, f?.tag_logic),
  inv_summary:        (scanId, f) => getInventorySummary(scanId),
  inv_users:          (scanId, f) => getInventoryUsers({ scan_id: scanId, user_type: f?.user_type, is_admin: f?.is_admin, is_domain_admin: f?.is_domain_admin, is_privileged: f?.is_privileged, search: f?.search, page_size: 0 }),
  inv_groups:         (scanId, f) => getInventoryGroups({ scan_id: scanId, is_privileged: f?.is_privileged, page_size: 0 }),
  inv_services:       (scanId, f) => getInventoryServices({ scan_id: scanId, search: f?.search, page_size: 0 }),
  inv_netconns:       (scanId, f) => getInventoryNetconns({ scan_id: scanId, state: f?.state, page_size: 0 }),
  inv_tasks:          (scanId, f) => getInventoryTasks({ scan_id: scanId, page_size: 0 }),
  inv_patches:        (scanId, f) => getInventoryPatches({ scan_id: scanId, page_size: 0 }),
  inv_logged_on:      (scanId, f) => getInventoryLoggedOn({ scan_id: scanId, page_size: 0 }),
  inv_shares:         (scanId, f) => getInventoryShares({ scan_id: scanId, is_writeable: f?.is_writeable, page_size: 0 }),
  inv_software:       (scanId, f) => getInventorySoftware({ scan_id: scanId, search: f?.search, page_size: 0 }),
  inv_security_ctrls: (scanId, f) => getInventorySecurityControls({ scan_id: scanId, control_type: f?.control_type, page_size: 0 }),
  inv_computers:      (scanId, f) => getInventoryComputers({ scan_id: scanId, is_dc: f?.is_dc, search: f?.search, page_size: 0 }),
  inv_pw_policies:    (scanId, f) => getInventoryPasswordPolicies({ scan_id: scanId, page_size: 0 }),
  inv_certificates:   (scanId, f) => getInventoryCertificates({ scan_id: scanId, expired_only: f?.expired_only, expiring_days: f?.expiring_days, self_signed_only: f?.self_signed_only, page_size: 0 }),
  inv_ai_tools:       (scanId, f) => getInventoryAITools({ scan_id: scanId, category: f?.category, page_size: 0 }),
  inv_processes:      (scanId, f) => getInventoryProcesses({ scan_id: scanId, search: f?.search, page_size: 0 }),
  inv_credentials:    (scanId, f) => getInventoryCredentials({ scan_id: scanId, credential_type: f?.credential_type, protocol: f?.protocol, severity: f?.severity, search: f?.search, page_size: 0 }),
  risk_grade:              (scanId, f) => getRiskGrade(scanId, f?.tags, f?.tag_logic),
  aggregated_solutions:    (scanId, f) => getAggregatedSolutions({ scan_id: scanId }),
  os_sw_summary:           (scanId, f) => getOsSoftwareSummary(scanId),
  easm_status:             (scanId, f) => getEasmStatus(),
  easm_assets:             (scanId, f) => getEasmAssets(),
  easm_events:             (scanId, f) => getEasmEvents(null, f?.limit || 100),
  easm_breaches:           (scanId, f) => getEasmBreaches().catch(() => []),
  easm_subsidiaries:       (scanId, f) => getEasmSubsidiaries().catch(() => []),
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
  inv_credentials: [
    { key: 'credential_type', label: 'Type', type: 'select', options: [{ value: '', label: 'All' }, { value: 'default_account', label: 'Default Account' }, { value: 'cleartext', label: 'Cleartext' }, { value: 'brute_forceable', label: 'Brute Forceable' }, { value: 'weak_config', label: 'Weak Config' }] },
    { key: 'protocol', label: 'Protocol', type: 'text', placeholder: 'e.g. ssh, ftp' },
    { key: 'severity', label: 'Severity', type: 'select', options: [{ value: '', label: 'All' }, { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }] },
    { key: 'search', label: 'Search', type: 'text', placeholder: 'Plugin name, username...' },
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
  risk_grade:       { label: 'Risk Grade',          group: 'Risk',      source: 'risk_grade', type: 'grade', extract: d => d },
  exploit_count:    { label: 'Known Exploits',     group: 'Risk',      source: 'summary', type: 'metric', extract: d => d?.exploit_count ?? 0, color: '#f59e0b' },
  high_priority:    { label: 'High Priority',      group: 'Risk',      source: 'summary', type: 'metric', extract: d => d?.high_priority_count ?? 0, color: '#ea580c' },
  sla_compliance:   { label: 'SLA Compliance',     group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.compliance_pct ?? 0, format: 'pct', color: '#16a34a' },
  sla_breached:     { label: 'SLA Breached',       group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.breached ?? 0, color: '#dc2626' },
  sla_on_track:     { label: 'SLA On Track',       group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.on_track ?? 0, color: '#16a34a' },
  sla_at_risk:      { label: 'SLA At Risk',        group: 'SLA & Ops', source: 'sla',     type: 'metric', extract: d => d?.at_risk ?? 0, color: '#d97706' },
  quick_wins:       { label: 'Quick Wins',         group: 'SLA & Ops', source: 'summary', type: 'metric', extract: d => d?.effort_breakdown?.quick_win ?? 0, color: '#16a34a' },
  coverage_pct:     { label: 'Assessment Coverage', group: 'Coverage', source: 'summary', type: 'metric', extract: d => d?.coverage?.coverage_pct ?? 0, format: 'pct', color: '#16a34a' },
  credentialed_count: { label: 'Credentialed Assets', group: 'Coverage', source: 'summary', type: 'metric', extract: d => d?.coverage?.credentialed_count ?? 0, color: '#16a34a' },
  uncredentialed_count: { label: 'Uncredentialed Assets', group: 'Coverage', source: 'summary', type: 'metric', extract: d => d?.coverage?.uncredentialed_count ?? 0, color: '#dc2626' },
  complex_findings: { label: 'Complex Findings',   group: 'SLA & Ops', source: 'summary', type: 'metric', extract: d => d?.effort_breakdown?.complex ?? 0, color: '#dc2626' },
  zombie_count:     { label: 'Zombie Vulns',       group: 'Temporal',  source: 'temporal', type: 'metric', extract: d => d?.zombie_count ?? 0, color: '#7c3aed' },
  regression_count: { label: 'Regressions',        group: 'Temporal',  source: 'temporal', type: 'metric', extract: d => d?.regression_count ?? 0, color: '#ef4444' },
  finding_count_filtered: { label: 'Finding Count', group: 'Filtered', source: 'findings', type: 'metric', extract: d => d?.total ?? d?.findings?.length ?? 0, color: '#6366f1' },
  asset_count_filtered:   { label: 'Asset Count',   group: 'Filtered', source: 'assets',   type: 'metric', extract: d => d?.total ?? (d?.assets?.length ?? 0), color: '#6366f1' },
  // ── Inventory metrics ──
  inv_domain_admins:      { label: 'Domain Admins',        group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => { const v = d?.attack_surface?.domain_admins; return Array.isArray(v) ? v.length : (v ?? 0) }, color: '#dc2626' },
  inv_local_admins:       { label: 'Local Admins',         group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.local_admins_count ?? 0, color: '#ea580c' },
  inv_kerberoastable:     { label: 'Kerberoastable',       group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => { const v = d?.attack_surface?.kerberoastable_accounts; return Array.isArray(v) ? v.length : (v ?? 0) }, color: '#f59e0b' },
  inv_pw_never_expires:   { label: 'Password Never Expires', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.password_never_expires_count ?? 0, color: '#d97706' },
  inv_pw_never_changed:   { label: 'Never Changed Password', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.never_changed_password_count ?? 0, color: '#ea580c' },
  inv_lateral_paths:      { label: 'Lateral Movement Paths', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => { const v = d?.attack_surface?.lateral_movement_paths; return Array.isArray(v) ? v.length : (v ?? 0) }, color: '#ef4444' },
  inv_established_conns:  { label: 'Established Connections', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.established_connections ?? 0, color: '#6366f1' },
  inv_logged_on_count:    { label: 'Logged On Users',      group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => { const v = d?.attack_surface?.logged_on_users; return Array.isArray(v) ? v.length : (v ?? 0) }, color: '#8b5cf6' },
  inv_writeable_shares:   { label: 'Writeable Shares',     group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.writeable_shares ?? 0, color: '#f59e0b' },
  inv_hosts_with_av:      { label: 'Hosts with AV',        group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.hosts_with_av ?? 0, color: '#16a34a' },
  inv_weak_pw_policies:   { label: 'Weak Password Policies', group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.weak_password_policies ?? 0, color: '#dc2626' },
  inv_domain_controllers: { label: 'Domain Controllers',   group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => { const v = d?.attack_surface?.domain_controllers; return Array.isArray(v) ? v.length : (v ?? 0) }, color: '#7c3aed' },
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
  inv_total_ai_tools:         { label: 'AI Tools Count',          group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.counts?.ai_tools ?? 0, color: '#8b5cf6' },
  inv_credential_exposures:   { label: 'Credential Exposures',    group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.credential_exposures ?? 0, color: '#ef4444' },
  inv_default_accounts:       { label: 'Default Accounts',        group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.default_accounts ?? 0, color: '#dc2626' },
  inv_cleartext_credentials:  { label: 'Cleartext Credentials',   group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.cleartext_credentials ?? 0, color: '#ea580c' },
  inv_brute_forceable:        { label: 'Brute Forceable',         group: 'Inventory', source: 'inv_summary', type: 'metric', extract: d => d?.attack_surface?.brute_forceable ?? 0, color: '#f59e0b' },

  // ── EASM metrics ──
  easm_total_assets:    { label: 'Discovered Assets',    group: 'EASM', source: 'easm_status', type: 'metric', extract: d => d?.stats?.total ?? 0, color: '#6366f1' },
  easm_with_open_ports: { label: 'With Open Ports',      group: 'EASM', source: 'easm_status', type: 'metric', extract: d => d?.stats?.with_open_ports ?? 0, color: '#ea580c' },
  easm_with_http:       { label: 'HTTP Services',        group: 'EASM', source: 'easm_status', type: 'metric', extract: d => d?.stats?.with_http ?? 0, color: '#0ea5e9' },
  easm_with_cdn:        { label: 'Behind CDN',           group: 'EASM', source: 'easm_status', type: 'metric', extract: d => d?.stats?.with_cdn ?? 0, color: '#16a34a' },
  easm_expired_certs:   { label: 'Expired Certificates', group: 'EASM', source: 'easm_status', type: 'metric', extract: d => d?.stats?.with_expired_cert ?? 0, color: '#dc2626' },
  easm_breach_count:    { label: 'Known Breaches',       group: 'EASM', source: 'easm_breaches', type: 'metric', extract: d => (Array.isArray(d) ? d : []).length, color: '#7c3aed' },

  // ── EASM categories ──
  easm_asset_liveness: {
    label: 'Asset Liveness', group: 'EASM', source: 'easm_assets', type: 'categories',
    extract: d => {
      const arr = Array.isArray(d) ? d : (d?.assets ?? [])
      const counts = {}
      arr.forEach(a => { const s = a.liveness_state || 'unknown'; counts[s] = (counts[s] || 0) + 1 })
      const colors = { confirmed_alive: '#16a34a', unconfirmed: '#d97706', likely_dead: '#dc2626', unknown: '#94a3b8' }
      return Object.entries(counts).map(([name, value]) => ({ name: name.replace(/_/g, ' '), value, color: colors[name] || '#6366f1' }))
    },
  },
  easm_tech_stack: {
    label: 'Technology Stack', group: 'EASM', source: 'easm_assets', type: 'categories',
    extract: d => {
      const arr = Array.isArray(d) ? d : (d?.assets ?? [])
      const counts = {}
      arr.forEach(a => { (a.tech_stack || []).forEach(t => { const name = typeof t === 'string' ? t : (t?.name || ''); if (name) counts[name] = (counts[name] || 0) + 1 }) })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  easm_open_ports: {
    label: 'Top Open Ports', group: 'EASM', source: 'easm_assets', type: 'categories',
    extract: d => {
      const arr = Array.isArray(d) ? d : (d?.assets ?? [])
      const counts = {}
      arr.forEach(a => { (a.open_ports || []).forEach(p => { counts[p] = (counts[p] || 0) + 1 }) })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([name, value], i) => ({ name: `Port ${name}`, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  easm_cdn_providers: {
    label: 'CDN/WAF Providers', group: 'EASM', source: 'easm_assets', type: 'categories',
    extract: d => {
      const arr = Array.isArray(d) ? d : (d?.assets ?? [])
      const counts = {}
      arr.forEach(a => { const cdn = a.cdn_provider; if (cdn) counts[cdn] = (counts[cdn] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  easm_event_types: {
    label: 'Change Events', group: 'EASM', source: 'easm_events', type: 'categories',
    extract: d => {
      const arr = Array.isArray(d) ? d : (d?.events ?? [])
      const counts = {}
      arr.forEach(e => { const t = e.event_type || 'unknown'; counts[t] = (counts[t] || 0) + 1 })
      const colors = { new_asset: '#16a34a', ip_change: '#d97706', port_change: '#ea580c', tech_change: '#6366f1', cert_expiring: '#dc2626' }
      return Object.entries(counts).map(([name, value]) => ({ name: name.replace(/_/g, ' '), value, color: colors[name] || '#8b5cf6' }))
    },
  },

  // ── EASM tables ──
  easm_assets_table: {
    label: 'EASM Assets', group: 'EASM', source: 'easm_assets', type: 'table',
    columns: [
      { key: 'hostname', label: 'Hostname' },
      { key: 'ip', label: 'IP' },
      { key: 'http_status', label: 'HTTP' },
      { key: 'http_title', label: 'Title' },
      { key: 'cdn_provider', label: 'CDN' },
      { key: 'open_ports', label: 'Ports', render: v => (v || []).join(', ') },
    ],
    extract: d => (Array.isArray(d) ? d : (d?.assets ?? [])).slice(0, 50),
    rowDrillDown: row => row?.hostname ? `/inventory?tab=easm_assets&search=${encodeURIComponent(row.hostname)}` : '/inventory?tab=easm_assets',
  },
  easm_events_table: {
    label: 'Recent Changes', group: 'EASM', source: 'easm_events', type: 'table',
    columns: [
      { key: 'event_type', label: 'Event', render: v => (v || '').replace(/_/g, ' ') },
      { key: 'created_at', label: 'When', render: v => v ? new Date(v).toLocaleDateString() : '' },
      { key: 'payload', label: 'Details', render: v => typeof v === 'object' ? JSON.stringify(v).slice(0, 80) : '' },
    ],
    extract: d => (Array.isArray(d) ? d : (d?.events ?? [])).slice(0, 30),
    rowDrillDown: row => row?.hostname ? `/inventory?tab=easm_assets&search=${encodeURIComponent(row.hostname)}` : '/inventory?tab=easm_assets',
  },
  easm_breaches_table: {
    label: 'Breach Exposure', group: 'EASM', source: 'easm_breaches', type: 'table',
    columns: [
      { key: 'title', label: 'Breach' },
      { key: 'breach_date', label: 'Date' },
      { key: 'exposed_count', label: 'Exposed Accounts', render: v => (v || 0).toLocaleString() },
      { key: 'data_classes', label: 'Data Types', render: v => (v || []).slice(0, 3).join(', ') },
    ],
    extract: d => (Array.isArray(d) ? d : []).filter(b => b.is_verified !== false).slice(0, 20),
    rowDrillDown: row => row?.title ? `/inventory?tab=easm_breaches&search=${encodeURIComponent(row.title)}` : '/inventory?tab=easm_breaches',
  },

  // ── Categories (pie/donut/bar) ──
  severity_breakdown: {
    label: 'Severity Breakdown', group: 'Severity', source: 'summary', type: 'categories',
    extract: d => {
      const s = d?.severity_breakdown || {}
      return ['Info', 'Low', 'Medium', 'High', 'Critical'].map((n, i) => ({ name: n, value: s[n.toLowerCase()] || 0, color: SEV_COLORS[i] })).filter(r => r.value > 0)
    },
  },
  severity_breakdown_filtered: {
    label: 'Severity Breakdown (Filtered)', group: 'Severity', source: 'findings', type: 'categories',
    extract: d => {
      const findings = d?.findings || []
      const sevMap = { 0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' }
      const counts = { Info: 0, Low: 0, Medium: 0, High: 0, Critical: 0 }
      findings.forEach(f => { const name = sevMap[f.severity] || 'Info'; counts[name]++ })
      return ['Info', 'Low', 'Medium', 'High', 'Critical'].map((n, i) => ({ name: n, value: counts[n], color: SEV_COLORS[i] })).filter(r => r.value > 0)
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
  coverage_breakdown: {
    label: 'Assessment Coverage', group: 'Coverage', source: 'summary', type: 'categories',
    extract: d => {
      const c = d?.coverage || {}
      return [
        { name: 'Credentialed', value: c.credentialed_count || 0, color: '#16a34a' },
        { name: 'Uncredentialed', value: c.uncredentialed_count || 0, color: '#dc2626' },
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
  owner_risk_bar: {
    label: 'Owner Risk Score', group: 'Ownership', source: 'owner_risk', type: 'categories',
    extract: d => (d?.owners || []).map(o => ({
      name: o.owner,
      value: parseFloat(o.avg_priority_score) || 0,
      color: o.rag === 'red' ? '#ef4444' : o.rag === 'amber' ? '#f59e0b' : '#22c55e',
    })),
  },
  owner_finding_count: {
    label: 'Owner Finding Count', group: 'Ownership', source: 'owner_risk', type: 'categories',
    extract: d => (d?.owners || []).map(o => ({
      name: o.owner,
      value: o.total,
      color: o.rag === 'red' ? '#ef4444' : o.rag === 'amber' ? '#f59e0b' : '#22c55e',
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
  mttr_overall: {
    label: 'Overall MTTR (days)', group: 'SLA & Ops', source: 'sla', type: 'metric',
    extract: d => {
      const m = d?.avg_mttr_days || {}
      const vals = [m.critical, m.high, m.medium, m.low].filter(v => v && v > 0)
      return vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : 0
    },
    color: '#8b5cf6',
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
      const arr = d?.assets ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(a => { const os = a.os || 'Unknown'; counts[os] = (counts[os] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  // ── Inventory categories ──
  inv_user_type_breakdown: {
    label: 'User Types', group: 'Inventory', source: 'inv_users', type: 'categories',
    extract: d => {
      const arr = d?.users ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(u => { const t = u.user_type || 'unknown'; counts[t] = (counts[t] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name: name.replace(/_/g, ' '), value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_attack_surface: {
    label: 'Attack Surface', group: 'Inventory', source: 'inv_summary', type: 'categories',
    extract: d => {
      const a = d?.attack_surface || {}
      const len = v => Array.isArray(v) ? v.length : (v || 0)
      return [
        { name: 'Domain Admins', value: len(a.domain_admins), color: '#dc2626' },
        { name: 'Local Admins', value: a.local_admins_count || 0, color: '#ea580c' },
        { name: 'Kerberoastable', value: len(a.kerberoastable_accounts), color: '#f59e0b' },
        { name: 'Pwd Never Expires', value: a.password_never_expires_count || 0, color: '#d97706' },
        { name: 'Lateral Paths', value: len(a.lateral_movement_paths), color: '#ef4444' },
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
      const arr = d?.netconns ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(c => { const s = c.state || 'UNKNOWN'; counts[s] = (counts[s] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_software_vendors: {
    label: 'Top Software Vendors', group: 'Inventory', source: 'inv_software', type: 'categories',
    extract: d => {
      const arr = d?.software ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(s => { const v = s.vendor || 'Unknown'; counts[v] = (counts[v] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_security_ctrl_types: {
    label: 'Security Control Types', group: 'Inventory', source: 'inv_security_ctrls', type: 'categories',
    extract: d => {
      const arr = d?.controls ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(c => { const t = c.control_type || 'unknown'; counts[t] = (counts[t] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_cert_status: {
    label: 'Certificate Status', group: 'Inventory', source: 'inv_certificates', type: 'categories',
    extract: d => {
      const arr = d?.certificates ?? (Array.isArray(d) ? d : [])
      let expired = 0, expiring = 0, valid = 0, selfSigned = 0
      arr.forEach(c => {
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
      const arr = d?.ai_tools ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(t => { const c = t.category || 'unknown'; counts[c] = (counts[c] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value], i) => ({ name, value, color: PALETTE[i % PALETTE.length] }))
    },
  },
  inv_credential_type_breakdown: {
    label: 'Credential Types', group: 'Inventory', source: 'inv_credentials', type: 'categories',
    extract: d => {
      const arr = d?.credentials ?? (Array.isArray(d) ? d : [])
      const labels = { default_account: 'Default Account', cleartext: 'Cleartext', brute_forceable: 'Brute Forceable', weak_config: 'Weak Config', shared_credential: 'Shared' }
      const colors = { default_account: '#dc2626', cleartext: '#ea580c', brute_forceable: '#f59e0b', weak_config: '#d97706', shared_credential: '#8b5cf6' }
      const counts = {}
      arr.forEach(c => { const t = c.credential_type || 'other'; counts[t] = (counts[t] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({
        name: labels[name] || name, value, color: colors[name] || '#94a3b8',
      }))
    },
  },
  inv_credential_protocol_breakdown: {
    label: 'Credentials by Protocol', group: 'Inventory', source: 'inv_credentials', type: 'categories',
    extract: d => {
      const arr = d?.credentials ?? (Array.isArray(d) ? d : [])
      const counts = {}
      arr.forEach(c => { const p = (c.protocol || 'unknown').toUpperCase(); counts[p] = (counts[p] || 0) + 1 })
      return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, value], i) => ({
        name, value, color: ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#0ea5e9', '#22c55e', '#ef4444', '#14b8a6'][i % 8],
      }))
    },
  },

  // ── OS & Software (from /api/tags/os-software-summary) ──
  os_family_breakdown: {
    label: 'OS Families', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => {
      const colors = { 'Windows Server': '#0078d4', 'Windows Desktop': '#00a4ef', 'Windows': '#0078d4', 'Ubuntu': '#e95420', 'Debian': '#a80030', 'CentOS': '#932279', 'Red Hat': '#ee0000', 'SUSE': '#73ba25', 'Linux': '#fcc624', 'macOS': '#a2aaad', 'FreeBSD': '#ab2b28', 'VMware ESXi': '#696566', 'Other': '#94a3b8' }
      return (d?.os_families || []).map((r, i) => ({ name: r.name, value: r.count, color: colors[r.name] || PALETTE[i % PALETTE.length] }))
    },
  },
  os_detail_breakdown: {
    label: 'OS Versions (detailed)', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.os_detail || []).slice(0, 15).map((r, i) => ({ name: r.os, value: r.count, color: PALETTE[i % PALETTE.length] })),
  },
  device_type_breakdown: {
    label: 'Device Types', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => {
      const colors = { server: '#6366f1', workstation: '#0ea5e9', router: '#14b8a6', switch: '#22c55e', firewall: '#f59e0b', printer: '#94a3b8', hypervisor: '#8b5cf6' }
      return (d?.device_types || []).map((r, i) => ({ name: r.name, value: r.count, color: colors[r.name] || PALETTE[i % PALETTE.length] }))
    },
  },
  top_software_products: {
    label: 'Top Software Products', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.software || []).slice(0, 15).map((r, i) => ({ name: r.name, value: r.asset_count, color: PALETTE[i % PALETTE.length] })),
  },
  software_category_breakdown: {
    label: 'Software Categories', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.software_categories || []).map((r, i) => ({ name: r.name, value: r.count, color: PALETTE[i % PALETTE.length] })),
  },
  inv_total_os_families: { label: 'OS Families Count', group: 'OS & Software', source: 'os_sw_summary', type: 'metric', extract: d => d?.os_families?.length ?? 0, color: '#0078d4' },
  inv_total_device_types: { label: 'Device Types Count', group: 'OS & Software', source: 'os_sw_summary', type: 'metric', extract: d => d?.device_types?.length ?? 0, color: '#6366f1' },
  inv_total_sw_products: { label: 'Unique Software Products', group: 'OS & Software', source: 'os_sw_summary', type: 'metric', extract: d => d?.software?.length ?? 0, color: '#14b8a6' },

  // ── OS & Software tables ──
  os_detail_table: {
    label: 'OS Versions', group: 'OS & Software', source: 'os_sw_summary', type: 'table',
    extract: d => (d?.os_detail || []).map(r => ({ ...r, name: r.os })),
    columns: [
      { key: 'os', label: 'Operating System' },
      { key: 'family', label: 'Family' },
      { key: 'count', label: 'Assets' },
    ],
  },
  top_software_table: {
    label: 'Top Software', group: 'OS & Software', source: 'os_sw_summary', type: 'table',
    extract: d => d?.software || [],
    columns: [
      { key: 'name', label: 'Software' },
      { key: 'vendor', label: 'Vendor' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'install_count', label: 'Installs' },
    ],
  },

  // ── OS & Software risk tables ──
  os_risk_table: {
    label: 'Riskiest OS Families', group: 'OS & Software', source: 'os_sw_summary', type: 'table',
    extract: d => d?.os_risk || [],
    columns: [
      { key: 'name', label: 'OS Family' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'vuln_count', label: 'Vulns' },
      { key: 'critical', label: 'Critical' },
      { key: 'high', label: 'High' },
      { key: 'medium', label: 'Medium' },
    ],
    rowDrillDown: row => row?.name ? `/findings?search=${encodeURIComponent(row.name)}` : null,
  },
  os_risk_chart: {
    label: 'OS Risk by Severity', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.os_risk || []).slice(0, 10).map((r, i) => ({ name: r.name, value: r.vuln_count, color: r.critical > 0 ? '#dc2626' : r.high > 0 ? '#ea580c' : '#d97706' })),
  },
  software_risk_table: {
    label: 'Riskiest Software', group: 'OS & Software', source: 'os_sw_summary', type: 'table',
    extract: d => d?.software_risk || [],
    columns: [
      { key: 'name', label: 'Software' },
      { key: 'vendor', label: 'Vendor' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'vuln_count', label: 'CVEs' },
      { key: 'max_severity', label: 'Max Sev', render: v => ['Info', 'Low', 'Medium', 'High', 'Critical'][v] || '—' },
      { key: 'max_cvss', label: 'Max CVSS', render: v => v != null ? v.toFixed(1) : '—' },
    ],
    rowDrillDown: row => row?.name ? `/findings?product=${encodeURIComponent(row.name)}` : null,
  },
  software_risk_chart: {
    label: 'Riskiest Software (CVE count)', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.software_risk || []).slice(0, 10).map((r, i) => {
      const colors = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']
      return { name: r.name, value: r.vuln_count, color: colors[r.max_severity] || '#94a3b8' }
    }),
  },
  os_risk_vuln_count: { label: 'OS-Related Vulns', group: 'OS & Software', source: 'os_sw_summary', type: 'metric', extract: d => (d?.os_risk || []).reduce((s, r) => s + r.vuln_count, 0), color: '#dc2626' },
  sw_risk_vuln_count: { label: 'Software-Related CVEs', group: 'OS & Software', source: 'os_sw_summary', type: 'metric', extract: d => (d?.software_risk || []).reduce((s, r) => s + r.vuln_count, 0), color: '#ea580c' },
  family_risk_chart: {
    label: 'Vulns by Plugin Family', group: 'OS & Software', source: 'os_sw_summary', type: 'categories',
    extract: d => (d?.family_risk || []).slice(0, 10).map((r, i) => ({
      name: r.name, value: r.vuln_count,
      color: r.critical > 0 ? '#dc2626' : r.high > 0 ? '#ea580c' : '#d97706',
    })),
  },
  family_risk_table: {
    label: 'Risk by Plugin Family', group: 'OS & Software', source: 'os_sw_summary', type: 'table',
    extract: d => d?.family_risk || [],
    columns: [
      { key: 'name', label: 'Plugin Family' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'vuln_count', label: 'Vulns' },
      { key: 'critical', label: 'Critical' },
      { key: 'high', label: 'High' },
      { key: 'medium', label: 'Medium' },
    ],
    rowDrillDown: row => row?.name ? `/findings?family=${encodeURIComponent(row.name)}` : null,
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
  // Dynamic composable series — metrics & grouping set via widget config
  custom_series: {
    label: 'Custom Time Series', group: 'Severity', source: 'metrics_timeline', type: 'series',
    dynamic: true,
    extract: (d, cfg) => {
      const rows = Array.isArray(d) ? d : []
      return aggregateByTimePeriod(rows, cfg?.time_group || 'scan')
    },
    xField: 'scan_name',
    fields: [],   // filled dynamically from cfg.metrics
    colors: {},   // filled dynamically from cfg.metrics
  },

  // ── Tables ──
  top_assets: {
    label: 'Top Risky Assets', group: 'Assets & Findings', source: 'summary', type: 'table',
    extract: d => (d?.top_risky_assets || []),
    rowDrillDown: row => row?.id ? `/assets/${row.id}` : null,
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
  owner_risk_table: {
    label: 'Owner Risk (Hall of Shame)', group: 'Ownership', source: 'owner_risk', type: 'table',
    extract: d => (d?.owners || []),
    columns: [
      { key: 'rank', label: '#' },
      { key: 'owner', label: 'Owner' },
      { key: 'rag', label: 'Status', render: v => {
        const cfg = { red: ['#ef4444', '●'], amber: ['#f59e0b', '●'], green: ['#22c55e', '●'] }
        const [color, icon] = cfg[v] || ['#94a3b8', '●']
        return <span style={{ color, fontWeight: 700, fontSize: 18 }} title={v}>{icon}</span>
      }},
      { key: 'critical', label: 'Crit', render: v => v > 0 ? <span style={{ color: '#ef4444', fontWeight: 700 }}>{v}</span> : v },
      { key: 'high', label: 'High' },
      { key: 'total', label: 'Total' },
      { key: 'exploit_count', label: 'Exploits', render: v => v > 0 ? <span style={{ color: '#f97316', fontWeight: 600 }}>{v}</span> : v },
      { key: 'avg_priority_score', label: 'Avg Priority', render: v => v?.toFixed?.(1) },
      { key: 'sla_compliance', label: 'SLA', render: v => v != null ? `${v}%` : 'N/A' },
      { key: 'quick_wins', label: 'Quick Wins' },
    ],
  },
  quick_wins_table: {
    label: 'Quick Wins', group: 'Assets & Findings', source: 'summary', type: 'table',
    extract: d => (d?.quick_wins || []),
    rowDrillDown: row => row?.id ? `/findings/${row.id}` : null,
    columns: [
      { key: 'plugin_name', label: 'Finding' },
      { key: 'host', label: 'Asset' },
      { key: 'plugin_family', label: 'Family' },
      { key: 'priority_score', label: 'Priority', render: v => v?.toFixed?.(1) },
    ],
  },
  remediation_queue_data: {
    label: 'Remediation Queue', group: 'Assets & Findings', source: 'remediation_queue', type: 'table',
    extract: d => Array.isArray(d) ? d : [],
    rowDrillDown: row => row?.id ? `/findings/${row.id}` : null,
    columns: [
      { key: 'plugin_name', label: 'Finding' },
      { key: 'severity_label', label: 'Sev' },
      { key: 'asset_hostname', label: 'Asset', fallback: 'asset_ip' },
      { key: 'effort_level', label: 'Effort' },
      { key: 'priority_score', label: 'Priority', render: v => v?.toFixed?.(1) },
    ],
  },
  aggregated_solutions_table: {
    label: 'Top Remediation Actions', group: 'Risk', source: 'aggregated_solutions', type: 'table',
    extract: d => [...(d?.solutions ?? (Array.isArray(d) ? d : []))].sort((a, b) => (b.risk_reduction ?? 0) - (a.risk_reduction ?? 0)),
    rowDrillDown: row => row?.id ? `/aggregated-solutions?highlight=${row.id}` : null,
    columns: [
      { key: 'title', label: 'Action' },
      { key: 'affected_component', label: 'Component' },
      { key: 'asset_count', label: 'Assets' },
      { key: 'finding_count', label: 'Findings' },
      { key: 'risk_reduction', label: 'Risk Reduction', render: v => v != null ? `${v.toFixed(1)}%` : '—' },
      { key: 'effort_level', label: 'Effort' },
      { key: 'owner_suggestion', label: 'Owner' },
    ],
  },
  findings_list: {
    label: 'Findings List', group: 'Assets & Findings', source: 'findings', type: 'table',
    extract: d => d?.findings || [],
    rowDrillDown: row => row?.id ? `/findings/${row.id}` : null,
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
    extract: d => d?.assets ?? (Array.isArray(d) ? d : []),
    rowDrillDown: row => row?.id ? `/assets/${row.id}` : null,
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
    extract: d => d?.users ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.groups ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.services ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'display_name', label: 'Service', fallback: 'service_name' },
      { key: 'is_running', label: 'Running', render: v => v ? 'Yes' : 'No' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_software_table: {
    label: 'Software', group: 'Inventory', source: 'inv_software', type: 'table',
    extract: d => d?.software ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'name', label: 'Name' },
      { key: 'version', label: 'Version' },
      { key: 'vendor', label: 'Vendor' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_logged_on_table: {
    label: 'Logged On Users', group: 'Inventory', source: 'inv_logged_on', type: 'table',
    extract: d => d?.logged_on ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'username', label: 'Username' },
      { key: 'domain', label: 'Domain' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_netconns_table: {
    label: 'Network Connections', group: 'Inventory', source: 'inv_netconns', type: 'table',
    extract: d => d?.netconns ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.patches ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'kb_id', label: 'KB' },
      { key: 'vuln_count', label: 'Vulns' },
      { key: 'description', label: 'Description' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_shares_table: {
    label: 'Network Shares', group: 'Inventory', source: 'inv_shares', type: 'table',
    extract: d => d?.shares ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'share_name', label: 'Share' },
      { key: 'path', label: 'Path' },
      { key: 'is_writeable', label: 'Writeable', render: v => v ? 'Yes' : '' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_tasks_table: {
    label: 'Scheduled Tasks', group: 'Inventory', source: 'inv_tasks', type: 'table',
    extract: d => d?.tasks ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'task_uri', label: 'Task' },
      { key: 'command', label: 'Command' },
      { key: 'run_as_user', label: 'Run As', fallback: 'run_as_sid' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_computers_table: {
    label: 'Computers', group: 'Inventory', source: 'inv_computers', type: 'table',
    extract: d => d?.computers ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.certificates ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.policies ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.controls ?? (Array.isArray(d) ? d : []),
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
    extract: d => d?.ai_tools ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'tool_name', label: 'Tool' },
      { key: 'category', label: 'Category' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },
  inv_processes_table: {
    label: 'Processes', group: 'Inventory', source: 'inv_processes', type: 'table',
    extract: d => d?.processes ?? (Array.isArray(d) ? d : []),
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
  inv_credentials_table: {
    label: 'Credentials', group: 'Inventory', source: 'inv_credentials', type: 'table',
    extract: d => d?.credentials ?? (Array.isArray(d) ? d : []),
    columns: [
      { key: 'credential_type', label: 'Type' },
      { key: 'protocol', label: 'Protocol' },
      { key: 'severity', label: 'Severity' },
      { key: 'username', label: 'Username' },
      { key: 'port', label: 'Port' },
      { key: 'plugin_name', label: 'Finding' },
      { key: 'asset_label', label: 'Asset', fallback: 'asset_ip' },
    ],
  },

  // ── Radar (multi-axis comparison) ──
  radar_risk_dimensions: {
    label: 'Risk Dimensions', group: 'Risk', source: 'summary', type: 'radar',
    extract: d => {
      const s = d?.severity_breakdown || {}
      const total = (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0) + (s.info || 0) || 1
      return [
        { axis: 'Critical', value: Math.min(100, ((s.critical || 0) / total) * 100 * 5) },
        { axis: 'Exploitable', value: Math.min(100, ((d?.exploit_count || 0) / (total || 1)) * 100 * 3) },
        { axis: 'High', value: Math.min(100, ((s.high || 0) / total) * 100 * 3) },
        { axis: 'Exposure', value: Math.min(100, (d?.total_assets || 0) > 0 ? ((d?.high_priority_count || 0) / (d?.total_assets || 1)) * 100 : 0) },
        { axis: 'Patch Gap', value: Math.min(100, ((s.medium || 0) + (s.low || 0)) / total * 100) },
        { axis: 'Complexity', value: Math.min(100, ((d?.effort_breakdown?.complex || 0) / total) * 100 * 5) },
      ]
    },
  },
  radar_sla_posture: {
    label: 'SLA Posture', group: 'SLA & Ops', source: 'sla', type: 'radar',
    extract: d => {
      if (!d) return []
      const total = (d.on_track || 0) + (d.at_risk || 0) + (d.breached || 0) + (d.resolved || 0) || 1
      return [
        { axis: 'Compliance', value: d.compliance_pct || 0 },
        { axis: 'On Track', value: ((d.on_track || 0) / total) * 100 },
        { axis: 'Resolution', value: ((d.resolved || 0) / total) * 100 },
        { axis: 'At Risk', value: 100 - ((d.at_risk || 0) / total) * 100 },
        { axis: 'Breach Free', value: 100 - ((d.breached || 0) / total) * 100 },
      ]
    },
  },
  radar_attack_surface: {
    label: 'Attack Surface', group: 'Inventory', source: 'inv_summary', type: 'radar',
    extract: d => {
      const a = d?.attack_surface || {}
      const len = v => Array.isArray(v) ? v.length : (v || 0)
      const maxVal = Math.max(len(a.domain_admins), a.local_admins_count || 0, len(a.kerberoastable_accounts), a.password_never_expires_count || 0, len(a.lateral_movement_paths), a.writeable_shares || 0, 1)
      return [
        { axis: 'Domain Admins', value: (len(a.domain_admins) / maxVal) * 100 },
        { axis: 'Local Admins', value: ((a.local_admins_count || 0) / maxVal) * 100 },
        { axis: 'Kerberoastable', value: (len(a.kerberoastable_accounts) / maxVal) * 100 },
        { axis: 'Pwd Never Expires', value: ((a.password_never_expires_count || 0) / maxVal) * 100 },
        { axis: 'Lateral Paths', value: (len(a.lateral_movement_paths) / maxVal) * 100 },
        { axis: 'Writeable Shares', value: ((a.writeable_shares || 0) / maxVal) * 100 },
      ]
    },
  },

  // ── Gauge (single metric as radial dial) ──
  gauge_risk_score: {
    label: 'Risk Score', group: 'Risk', source: 'summary', type: 'gauge',
    extract: d => {
      const assets = d?.top_risky_assets || []
      const scores = assets.map(a => a.risk_score || 0)
      const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0
      return { value: Math.round(avg * 10) / 10, max: 10, label: 'Avg Risk' }
    },
  },
  gauge_sla_compliance: {
    label: 'SLA Compliance', group: 'SLA & Ops', source: 'sla', type: 'gauge',
    extract: d => ({ value: Math.round(d?.compliance_pct || 0), max: 100, label: 'SLA %', suffix: '%' }),
  },
  gauge_exploit_ratio: {
    label: 'Exploit Ratio', group: 'Risk', source: 'summary', type: 'gauge',
    extract: d => {
      const total = d?.total_findings || 0
      const exploits = d?.exploit_count || 0
      return { value: total > 0 ? Math.round((exploits / total) * 100) : 0, max: 100, label: 'Exploitable', suffix: '%' }
    },
  },
  gauge_critical_ratio: {
    label: 'Critical Ratio', group: 'Severity', source: 'summary', type: 'gauge',
    extract: d => {
      const total = d?.total_findings || 0
      const crit = d?.severity_breakdown?.critical || 0
      return { value: total > 0 ? Math.round((crit / total) * 100) : 0, max: 100, label: 'Critical', suffix: '%' }
    },
  },

  // ── Treemap (hierarchical area) ──
  treemap_family_severity: {
    label: 'Families by Severity', group: 'Assets & Findings', source: 'summary', type: 'treemap',
    extract: d => {
      const families = d?.top_plugin_families || []
      return families.slice(0, 15).map(f => ({
        name: f.family || 'Unknown',
        size: f.count || 0,
        critical: f.critical || 0,
        high: f.high || 0,
      }))
    },
  },
  treemap_severity: {
    label: 'Severity Treemap', group: 'Severity', source: 'summary', type: 'treemap',
    extract: d => {
      const s = d?.severity_breakdown || {}
      return [
        { name: 'Critical', size: s.critical || 0, color: '#dc2626' },
        { name: 'High', size: s.high || 0, color: '#ea580c' },
        { name: 'Medium', size: s.medium || 0, color: '#d97706' },
        { name: 'Low', size: s.low || 0, color: '#65a30d' },
        { name: 'Info', size: s.info || 0, color: '#0ea5e9' },
      ].filter(r => r.size > 0)
    },
  },
  treemap_owner: {
    label: 'Findings by Owner', group: 'Assets & Findings', source: 'summary', type: 'treemap',
    extract: d => (d?.owner_breakdown || []).map(o => ({
      name: o.owner || 'Unknown',
      size: o.count || 0,
    })).filter(r => r.size > 0),
  },
}

const PRESET_GROUPS = ['Severity', 'Risk', 'Temporal', 'SLA & Ops', 'Tags', 'Assets & Findings', 'Inventory', 'Filtered']

// ── Composable time-series metric catalogue ──────────────────────────────────
// Each metric maps to a field returned by metrics_timeline (or trending/velocity)
const SERIES_METRICS = [
  { id: 'critical',             label: 'Critical',              group: 'Severity',          color: '#dc2626' },
  { id: 'high',                 label: 'High',                  group: 'Severity',          color: '#ea580c' },
  { id: 'medium',               label: 'Medium',                group: 'Severity',          color: '#d97706' },
  { id: 'low',                  label: 'Low',                   group: 'Severity',          color: '#65a30d' },
  { id: 'info',                 label: 'Info',                  group: 'Severity',          color: '#0ea5e9' },
  { id: 'total_findings',       label: 'Total Findings',        group: 'Counts',            color: '#6366f1' },
  { id: 'actionable_findings',  label: 'Actionable Findings',   group: 'Counts',            color: '#8b5cf6' },
  { id: 'total_assets',         label: 'Total Assets',          group: 'Counts',            color: '#14b8a6' },
  { id: 'exploit_count',        label: 'Exploitable',           group: 'Counts',            color: '#f59e0b' },
  { id: 'sla_compliance_pct',   label: 'SLA Compliance %',      group: 'SLA & Workflow',    color: '#16a34a' },
  { id: 'sla_on_track',         label: 'SLA On Track',          group: 'SLA & Workflow',    color: '#16a34a' },
  { id: 'sla_at_risk',          label: 'SLA At Risk',           group: 'SLA & Workflow',    color: '#d97706' },
  { id: 'sla_breached',         label: 'SLA Breached',          group: 'SLA & Workflow',    color: '#dc2626' },
  { id: 'workflow_open',        label: 'Workflow Open',         group: 'SLA & Workflow',    color: '#6b7280' },
  { id: 'workflow_in_progress', label: 'Workflow In Progress',  group: 'SLA & Workflow',    color: '#3b82f6' },
  { id: 'workflow_resolved',    label: 'Workflow Resolved',     group: 'SLA & Workflow',    color: '#22c55e' },
  { id: 'avg_risk_score',       label: 'Avg Risk Score',        group: 'Risk',              color: '#ef4444' },
  { id: 'max_risk_score',       label: 'Max Risk Score',        group: 'Risk',              color: '#dc2626' },
  { id: 'avg_mttr_days',        label: 'MTTR (days)',           group: 'Risk',              color: '#8b5cf6' },
]
const SERIES_METRIC_GROUPS = ['Severity', 'Counts', 'SLA & Workflow', 'Risk']
const SERIES_METRIC_MAP = Object.fromEntries(SERIES_METRICS.map(m => [m.id, m]))

const TIME_GROUP_OPTIONS = [
  { value: 'scan', label: 'Per Scan' },
  { value: 'day',  label: 'Daily' },
  { value: 'week', label: 'Weekly' },
  { value: 'month',label: 'Monthly' },
  { value: 'year', label: 'Yearly' },
]

// Helper: aggregate metrics_timeline data by time period
function aggregateByTimePeriod(data, groupBy) {
  if (!Array.isArray(data) || data.length === 0 || groupBy === 'scan') return data
  const buckets = {}
  const numFields = ['critical','high','medium','low','info','total_findings','actionable_findings','total_assets','exploit_count',
    'sla_on_track','sla_at_risk','sla_breached','sla_compliance_pct','workflow_open','workflow_in_progress','workflow_resolved',
    'avg_risk_score','max_risk_score','avg_mttr_days']
  for (const row of data) {
    const dateStr = row.scan_date || ''
    let key
    if (groupBy === 'day') key = dateStr.slice(0, 10)
    else if (groupBy === 'week') {
      const d = new Date(dateStr)
      if (isNaN(d)) { key = dateStr; } else {
        const day = d.getDay()
        const diff = d.getDate() - day + (day === 0 ? -6 : 1)
        const monday = new Date(d.setDate(diff))
        key = monday.toISOString().slice(0, 10)
      }
    } else if (groupBy === 'month') key = dateStr.slice(0, 7)
    else if (groupBy === 'year') key = dateStr.slice(0, 4)
    else key = row.scan_name || dateStr
    if (!key) key = row.scan_name || `scan_${row.scan_id}`
    if (!buckets[key]) buckets[key] = { _label: key, _count: 0 }
    buckets[key]._count++
    for (const f of numFields) {
      if (row[f] != null) {
        buckets[key][f] = (buckets[key][f] || 0) + row[f]
      }
    }
  }
  // Average the rate/score fields instead of summing
  const avgFields = ['sla_compliance_pct', 'avg_risk_score', 'max_risk_score', 'avg_mttr_days']
  return Object.values(buckets).map(b => {
    const out = { scan_name: b._label }
    for (const f of numFields) {
      if (b[f] != null) {
        out[f] = avgFields.includes(f) ? Math.round((b[f] / b._count) * 10) / 10 : b[f]
      }
    }
    return out
  })
}

// ─── Widget catalogue ────────────────────────────────────────────────────────

const WIDGET_CATALOGUE = [
  {
    category: 'Charts',
    items: [
      { type: 'bar_chart',  label: 'Bar Chart',  icon: BarChart2,    desc: 'Vertical or horizontal bars', defaultWidth: 'full',  defaultConfig: { preset: 'severity_breakdown' } },
      { type: 'line_chart', label: 'Line Chart',  icon: TrendingUp,   desc: 'Line or area over time',      defaultWidth: 'full',  defaultConfig: { preset: 'custom_series', metrics: ['critical', 'high', 'medium', 'low'], time_group: 'scan' } },
      { type: 'pie_chart',  label: 'Pie / Donut', icon: PieChartIcon, desc: 'Proportional breakdown',      defaultWidth: 'half',  defaultConfig: { preset: 'severity_breakdown', donut: true } },
      { type: 'funnel',     label: 'Funnel',      icon: Filter,       desc: 'Progressive filter funnel', defaultWidth: 'half',  defaultConfig: { base_entity: 'findings', steps: [
        { label: 'Step 1', filters: {} },
      ] } },
      { type: 'radar',     label: 'Radar',       icon: Crosshair,    desc: 'Multi-axis comparison',     defaultWidth: 'half',  defaultConfig: { preset: 'radar_risk_dimensions' } },
      { type: 'gauge',     label: 'Gauge',       icon: Gauge,        desc: 'Single metric dial',        defaultWidth: 'quarter', defaultConfig: { preset: 'gauge_sla_compliance' } },
      { type: 'treemap',   label: 'Treemap',     icon: TreePine,     desc: 'Hierarchical area chart',   defaultWidth: 'half',  defaultConfig: { preset: 'treemap_family_severity' } },
    ],
  },
  {
    category: 'Data',
    items: [
      { type: 'card',    label: 'Metric Card', icon: Hash,     desc: 'Single number highlight', defaultWidth: 'quarter', defaultConfig: { preset: 'critical_count' } },
      { type: 'risk_grade', label: 'Risk Grade', icon: Shield, desc: 'Composite A-F risk grade', defaultWidth: 'half', defaultConfig: { preset: 'risk_grade' } },
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
    { id: 'dw13',type: 'table',     title: 'Quick Wins',            width: 'full',    config: { preset: 'quick_wins_table', limit: 5 } },
    { id: 'dw12',type: 'table',     title: 'Remediation Queue',     width: 'full',    config: { preset: 'remediation_queue_data', limit: 10 } },
    { id: 'dw14',type: 'card',      title: 'Zombie Vulns',          width: 'quarter', config: { preset: 'zombie_count' } },
    { id: 'dw15',type: 'card',      title: 'Regressions',           width: 'quarter', config: { preset: 'regression_count' } },
    { id: 'dw16',type: 'bar_chart', title: 'Finding Age',           width: 'half',    config: { preset: 'age_distribution' } },
    { id: 'dw17',type: 'risk_grade', title: 'How to Improve Risk Score', width: 'full', config: { preset: 'risk_grade', show_tips: true } },
    { id: 'dw18',type: 'table',      title: 'Top Remediation Actions',   width: 'full', config: { preset: 'aggregated_solutions_table', limit: 10 } },
  ],
}

const EXECUTIVE_DASHBOARD = {
  id: 'default-executive-overview',
  name: 'Executive Overview',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'ex0', type: 'risk_grade', title: 'Organization Risk Grade', width: 'half', config: { preset: 'risk_grade', show_benchmark: true } },
    { id: 'ex5', type: 'pie_chart', title: 'Severity Distribution', width: 'half',    config: { preset: 'severity_breakdown', donut: true } },
    { id: 'ex1', type: 'card',      title: 'Critical',              width: 'quarter', config: { preset: 'critical_count', show_benchmark: true } },
    { id: 'ex2', type: 'card',      title: 'SLA Compliance',        width: 'quarter', config: { preset: 'sla_compliance', show_benchmark: true } },
    { id: 'ex3', type: 'card',      title: 'SLA Breached',          width: 'quarter', config: { preset: 'sla_breached' } },
    { id: 'ex4', type: 'card',      title: 'Quick Wins',            width: 'quarter', config: { preset: 'quick_wins' } },
    { id: 'ex16',type: 'card',      title: 'Mean Time to Remediate', width: 'quarter', config: { preset: 'mttr_overall', label: 'days', show_benchmark: true } },
    { id: 'ex13',type: 'card',      title: 'Assessment Coverage',   width: 'quarter', config: { preset: 'coverage_pct', show_benchmark: true } },
    { id: 'ex14',type: 'card',      title: 'Credentialed Assets',   width: 'quarter', config: { preset: 'credentialed_count' } },
    { id: 'ex15',type: 'pie_chart', title: 'Scan Coverage',         width: 'quarter', config: { preset: 'coverage_breakdown', donut: true } },
    { id: 'ex6', type: 'pie_chart', title: 'SLA Status',            width: 'half',    config: { preset: 'sla_status', donut: true } },
    { id: 'ex17',type: 'bar_chart', title: 'MTTR by Severity',     width: 'half',    config: { preset: 'mttr_by_severity' } },
    { id: 'ex18',type: 'line_chart',title: 'MTTR Trend',            width: 'half',    config: { preset: 'mttr_trend' } },
    { id: 'ex10',type: 'line_chart',title: 'SLA Compliance Trend',  width: 'half',    config: { preset: 'sla_trend', areaFill: true } },
    { id: 'ex9', type: 'line_chart',title: 'Risk Score Trend',      width: 'half',    config: { preset: 'risk_trend' } },
    { id: 'ex12',type: 'line_chart',title: 'Severity Trend',        width: 'half',    config: { preset: 'severity_trend' } },
    { id: 'ex11',type: 'bar_chart', title: 'Remediation Velocity',  width: 'full',    config: { preset: 'velocity_trend', stacked: true } },
    { id: 'ex7', type: 'bar_chart', title: 'Risk by Business Unit', width: 'full',    config: { preset: 'risk_by_tags', horizontal: true } },
    { id: 'ex8', type: 'table',     title: 'Business Unit Benchmark', width: 'full',  config: { preset: 'tag_benchmark' } },
  ],
}

const IDENTITY_ACCESS_DASHBOARD = {
  id: 'default-identity-access',
  name: 'Identity & Access Risk',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'ia1', type: 'card',      title: 'Domain Admins',          width: 'quarter', config: { preset: 'inv_domain_admins' } },
    { id: 'ia2', type: 'card',      title: 'Local Admins',           width: 'quarter', config: { preset: 'inv_local_admins' } },
    { id: 'ia3', type: 'card',      title: 'Kerberoastable',         width: 'quarter', config: { preset: 'inv_kerberoastable' } },
    { id: 'ia4', type: 'card',      title: 'Password Never Expires', width: 'quarter', config: { preset: 'inv_pw_never_expires' } },
    { id: 'ia5', type: 'pie_chart', title: 'Attack Surface',         width: 'half',    config: { preset: 'inv_attack_surface', donut: true } },
    { id: 'ia6', type: 'pie_chart', title: 'User Types',             width: 'half',    config: { preset: 'inv_user_type_breakdown', donut: true } },
    { id: 'ia7', type: 'card',      title: 'Never Changed Password', width: 'quarter', config: { preset: 'inv_pw_never_changed' } },
    { id: 'ia8', type: 'card',      title: 'Logged On Users',        width: 'quarter', config: { preset: 'inv_logged_on_count' } },
    { id: 'ia9', type: 'card',      title: 'Weak Password Policies', width: 'quarter', config: { preset: 'inv_weak_pw_policies' } },
    { id: 'ia10',type: 'card',      title: 'Domain Controllers',     width: 'quarter', config: { preset: 'inv_domain_controllers' } },
    { id: 'ia11',type: 'table',     title: 'Privileged Users',       width: 'full',    config: { preset: 'inv_users_table', filters: { is_privileged: 'true' } } },
    { id: 'ia12',type: 'table',     title: 'Privileged Groups',      width: 'full',    config: { preset: 'inv_groups_table', filters: { is_privileged: 'true' } } },
    { id: 'ia13',type: 'table',     title: 'Password Policies',      width: 'full',    config: { preset: 'inv_pw_policies_table' } },
    { id: 'ia14',type: 'table',     title: 'Logged On Users',        width: 'full',    config: { preset: 'inv_logged_on_table' } },
  ],
}

const ATTACK_SURFACE_DASHBOARD = {
  id: 'default-attack-surface',
  name: 'Attack Surface & Hygiene',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'as1', type: 'card',      title: 'Expired Certificates',    width: 'quarter', config: { preset: 'inv_expired_certs' } },
    { id: 'as2', type: 'card',      title: 'Expiring Soon',           width: 'quarter', config: { preset: 'inv_expiring_certs' } },
    { id: 'as3', type: 'card',      title: 'Self-Signed Certs',       width: 'quarter', config: { preset: 'inv_self_signed_certs' } },
    { id: 'as4', type: 'card',      title: 'Writeable Shares',        width: 'quarter', config: { preset: 'inv_writeable_shares' } },
    { id: 'as5', type: 'card',      title: 'Lateral Movement Paths',  width: 'quarter', config: { preset: 'inv_lateral_paths' } },
    { id: 'as6', type: 'card',      title: 'Established Connections', width: 'quarter', config: { preset: 'inv_established_conns' } },
    { id: 'as7', type: 'card',      title: 'Hosts with AV',           width: 'quarter', config: { preset: 'inv_hosts_with_av' } },
    { id: 'as8', type: 'card',      title: 'Sensitive Env Vars',      width: 'quarter', config: { preset: 'inv_sensitive_env_vars' } },
    { id: 'as9', type: 'pie_chart', title: 'Security Controls',       width: 'half',    config: { preset: 'inv_security_ctrl_types', donut: true } },
    { id: 'as10',type: 'pie_chart', title: 'Certificate Status',      width: 'half',    config: { preset: 'inv_cert_status', donut: true } },
    { id: 'as11',type: 'pie_chart', title: 'Connection States',       width: 'half',    config: { preset: 'inv_netconn_states', donut: true } },
    { id: 'as12',type: 'bar_chart', title: 'Top Software Vendors',    width: 'half',    config: { preset: 'inv_software_vendors' } },
    { id: 'as13',type: 'table',     title: 'Missing Patches',         width: 'full',    config: { preset: 'inv_patches_table' } },
    { id: 'as14',type: 'table',     title: 'Network Shares',          width: 'full',    config: { preset: 'inv_shares_table' } },
    { id: 'as15',type: 'table',     title: 'Certificates',            width: 'full',    config: { preset: 'inv_certificates_table' } },
  ],
}

const REMEDIATION_DASHBOARD = {
  id: 'default-remediation-progress',
  name: 'Remediation Progress',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'rp1', type: 'risk_grade', title: 'Organization Risk Grade', width: 'half', config: { preset: 'risk_grade' } },
    { id: 'rp2', type: 'pie_chart', title: 'SLA Status',              width: 'half',    config: { preset: 'sla_status', donut: true } },
    { id: 'rp3', type: 'card',      title: 'Mean Time to Remediate',  width: 'quarter', config: { preset: 'mttr_overall', label: 'days' } },
    { id: 'rp4', type: 'card',      title: 'SLA Breached',            width: 'quarter', config: { preset: 'sla_breached' } },
    { id: 'rp5', type: 'card',      title: 'Zombie Vulns',            width: 'quarter', config: { preset: 'zombie_count' } },
    { id: 'rp6', type: 'card',      title: 'Regressions',             width: 'quarter', config: { preset: 'regression_count' } },
    { id: 'rp7', type: 'bar_chart', title: 'MTTR by Severity',        width: 'half',    config: { preset: 'mttr_by_severity' } },
    { id: 'rp8', type: 'line_chart',title: 'MTTR Trend',              width: 'half',    config: { preset: 'mttr_trend' } },
    { id: 'rp9', type: 'bar_chart', title: 'Remediation Velocity',    width: 'half',    config: { preset: 'velocity_trend', stacked: true } },
    { id: 'rp10',type: 'pie_chart', title: 'Effort Distribution',     width: 'half',    config: { preset: 'effort_breakdown', donut: true } },
    { id: 'rp11',type: 'bar_chart', title: 'Finding Age',             width: 'full',    config: { preset: 'age_distribution' } },
    { id: 'rp12',type: 'table',     title: 'Remediation Queue',       width: 'full',    config: { preset: 'remediation_queue_data', limit: 15 } },
    { id: 'rp13',type: 'table',     title: 'Quick Wins',              width: 'full',    config: { preset: 'quick_wins_table', limit: 10 } },
  ],
}

const AI_ML_ATTACK_SURFACE_DASHBOARD = {
  id: 'default-ai-ml-attack-surface',
  name: 'AI/ML Attack Surface',
  createdAt: new Date(0).toISOString(),
  widgets: [
    // Header
    { id: 'ai1', type: 'header', title: 'AI/ML Attack Surface Report', width: 'full', config: { title: 'AI/ML Attack Surface Report', subtitle: 'Shadow AI, LLM endpoints, and emerging ML risks across your environment' } },
    // Key metrics row
    { id: 'ai2', type: 'card', title: 'AI Tools Detected', width: 'quarter', config: { preset: 'inv_total_ai_tools' } },
    { id: 'ai3', type: 'card', title: 'Critical Findings', width: 'quarter', config: { preset: 'finding_count_filtered', filters: { plugin_family: 'Artificial Intelligence', severity: '4' } } },
    { id: 'ai4', type: 'card', title: 'High Findings', width: 'quarter', config: { preset: 'finding_count_filtered', filters: { plugin_family: 'Artificial Intelligence', severity: '3' } } },
    { id: 'ai5', type: 'card', title: 'Total AI Findings', width: 'quarter', config: { preset: 'finding_count_filtered', filters: { plugin_family: 'Artificial Intelligence' } } },
    // AI tool breakdown
    { id: 'ai6', type: 'pie_chart', title: 'AI Tool Categories', width: 'half', config: { preset: 'inv_ai_tool_categories', donut: true } },
    { id: 'ai7', type: 'bar_chart', title: 'AI Findings by Severity', width: 'half', config: { preset: 'severity_breakdown_filtered', filters: { plugin_family: 'Artificial Intelligence', page_size: 0 } } },
    // Findings table
    { id: 'ai8', type: 'table', title: 'AI/ML Vulnerability Findings', width: 'full', config: { preset: 'findings_list', limit: 20, filters: { plugin_family: 'Artificial Intelligence', sort_by: 'priority_score', order: 'desc' } } },
    // Inventory detail
    { id: 'ai9', type: 'table', title: 'Detected AI Tools & Extensions', width: 'full', config: { preset: 'inv_ai_tools_table', limit: 50 } },
  ],
}

const OS_DISTRIBUTION_DASHBOARD = {
  id: 'default-os-distribution',
  name: 'OS Distribution',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'os1', type: 'header', title: 'Operating System Distribution', width: 'full', config: { title: 'Operating System Distribution', subtitle: 'Asset inventory breakdown by OS family, version, and device type' } },
    { id: 'os2', type: 'card',      title: 'Total Assets',     width: 'quarter', config: { preset: 'total_assets' } },
    { id: 'os3', type: 'card',      title: 'OS Families',      width: 'quarter', config: { preset: 'inv_total_os_families' } },
    { id: 'os4', type: 'card',      title: 'Device Types',     width: 'quarter', config: { preset: 'inv_total_device_types' } },
    { id: 'os5', type: 'card',      title: 'Unique Software',  width: 'quarter', config: { preset: 'inv_total_sw_products' } },
    { id: 'os6', type: 'pie_chart', title: 'OS Family Distribution', width: 'half', config: { preset: 'os_family_breakdown', donut: true } },
    { id: 'os7', type: 'pie_chart', title: 'Device Types',          width: 'half', config: { preset: 'device_type_breakdown', donut: true } },
    { id: 'os8', type: 'bar_chart', title: 'OS Versions',           width: 'full', config: { preset: 'os_detail_breakdown' } },
    { id: 'os9', type: 'table',     title: 'OS Version Details',    width: 'full', config: { preset: 'os_detail_table' } },
    { id: 'os10', type: 'header', title: 'OS Risk Analysis', width: 'full', config: { title: 'OS Risk Analysis', subtitle: 'Vulnerability exposure by operating system family and plugin family' } },
    { id: 'os11', type: 'card',      title: 'OS-Related Vulns',   width: 'quarter', config: { preset: 'os_risk_vuln_count' } },
    { id: 'os12', type: 'bar_chart', title: 'OS Risk by Severity', width: 'two-thirds', config: { preset: 'os_risk_chart', horizontal: true } },
    { id: 'os13', type: 'table',     title: 'Riskiest OS Families', width: 'full', config: { preset: 'os_risk_table' } },
    { id: 'os14', type: 'bar_chart', title: 'Vulnerabilities by Plugin Family', width: 'full', config: { preset: 'family_risk_chart', horizontal: true } },
    { id: 'os15', type: 'table',     title: 'Risk by Plugin Family', width: 'full', config: { preset: 'family_risk_table' } },
  ],
}

const SOFTWARE_INVENTORY_DASHBOARD = {
  id: 'default-software-inventory',
  name: 'Software Inventory',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'sw1', type: 'header', title: 'Software Inventory Report', width: 'full', config: { title: 'Software Inventory Report', subtitle: 'Installed software across the environment — products, vendors, and categories' } },
    { id: 'sw2', type: 'card',      title: 'Total Software',     width: 'quarter', config: { preset: 'inv_total_software' } },
    { id: 'sw3', type: 'card',      title: 'Unique Products',    width: 'quarter', config: { preset: 'inv_total_sw_products' } },
    { id: 'sw4', type: 'card',      title: 'Total Assets',       width: 'quarter', config: { preset: 'total_assets' } },
    { id: 'sw5', type: 'card',      title: 'OS Families',        width: 'quarter', config: { preset: 'inv_total_os_families' } },
    { id: 'sw6', type: 'pie_chart', title: 'Software Categories',     width: 'half', config: { preset: 'software_category_breakdown', donut: true } },
    { id: 'sw7', type: 'bar_chart', title: 'Top Software by Vendor',  width: 'half', config: { preset: 'inv_software_vendors' } },
    { id: 'sw8', type: 'bar_chart', title: 'Most Installed Software', width: 'full', config: { preset: 'top_software_products' } },
    { id: 'sw9', type: 'table',     title: 'Software Details',        width: 'full', config: { preset: 'top_software_table' } },
    { id: 'sw10',type: 'table',     title: 'All Installed Software',  width: 'full', config: { preset: 'inv_software_table' } },
    { id: 'sw11', type: 'header', title: 'Software Risk Analysis', width: 'full', config: { title: 'Software Risk Analysis', subtitle: 'Vulnerability exposure by plugin family and detected software' } },
    { id: 'sw12', type: 'bar_chart', title: 'Vulnerabilities by Plugin Family', width: 'full', config: { preset: 'family_risk_chart', horizontal: true } },
    { id: 'sw13', type: 'table',     title: 'Risk by Plugin Family', width: 'full', config: { preset: 'family_risk_table' } },
    { id: 'sw14', type: 'card',      title: 'Software CVEs',          width: 'quarter', config: { preset: 'sw_risk_vuln_count' } },
    { id: 'sw15', type: 'bar_chart', title: 'Riskiest Software (SBOM)', width: 'two-thirds', config: { preset: 'software_risk_chart', horizontal: true } },
    { id: 'sw16', type: 'table',     title: 'Software Vulnerability Details', width: 'full', config: { preset: 'software_risk_table' } },
  ],
}

const EASM_DASHBOARD = {
  id: 'default-easm',
  name: 'External Attack Surface',
  createdAt: new Date(0).toISOString(),
  widgets: [
    // Header
    { id: 'ea1', type: 'header', title: 'External Attack Surface', width: 'full', config: { title: 'External Attack Surface', subtitle: 'Discovered assets, services, certificates, and change events from EASM scanning' } },
    // Key metrics
    { id: 'ea2', type: 'card',      title: 'Discovered Assets',    width: 'quarter', config: { preset: 'easm_total_assets' } },
    { id: 'ea3', type: 'card',      title: 'With Open Ports',      width: 'quarter', config: { preset: 'easm_with_open_ports' } },
    { id: 'ea4', type: 'card',      title: 'HTTP Services',        width: 'quarter', config: { preset: 'easm_with_http' } },
    { id: 'ea5', type: 'card',      title: 'Expired Certificates', width: 'quarter', config: { preset: 'easm_expired_certs' } },
    // Asset overview
    { id: 'ea6', type: 'pie_chart', title: 'Asset Liveness',       width: 'half',    config: { preset: 'easm_asset_liveness', donut: true } },
    { id: 'ea7', type: 'pie_chart', title: 'Change Events',        width: 'half',    config: { preset: 'easm_event_types', donut: true } },
    // Technology & ports
    { id: 'ea8', type: 'bar_chart', title: 'Technology Stack',     width: 'half',    config: { preset: 'easm_tech_stack' } },
    { id: 'ea9', type: 'bar_chart', title: 'Top Open Ports',       width: 'half',    config: { preset: 'easm_open_ports' } },
    // CDN
    { id: 'ea10',type: 'pie_chart', title: 'CDN / WAF Providers',  width: 'half',    config: { preset: 'easm_cdn_providers', donut: true } },
    { id: 'ea11',type: 'card',      title: 'Behind CDN',           width: 'quarter', config: { preset: 'easm_with_cdn' } },
    { id: 'ea12',type: 'card',      title: 'Known Breaches',       width: 'quarter', config: { preset: 'easm_breach_count' } },
    // Tables
    { id: 'ea13',type: 'table',     title: 'Discovered Assets',    width: 'full',    config: { preset: 'easm_assets_table', limit: 50 } },
    { id: 'ea14',type: 'table',     title: 'Recent Changes',       width: 'full',    config: { preset: 'easm_events_table', limit: 30 } },
    { id: 'ea15',type: 'table',     title: 'Breach Exposure',      width: 'full',    config: { preset: 'easm_breaches_table', limit: 20 } },
  ],
}

const OWNER_ACCOUNTABILITY_DASHBOARD = {
  id: 'default-owner-accountability',
  name: 'Owner Accountability',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'oa0',  type: 'header',    title: 'Owner Accountability',            width: 'full',    config: { title: 'Owner Accountability Report', subtitle: 'Risk posture and remediation workload broken down by responsible owner — red means action required now' } },
    { id: 'oa1',  type: 'card',      title: 'Total Findings',                  width: 'quarter', config: { preset: 'total_findings' } },
    { id: 'oa2',  type: 'card',      title: 'Critical',                        width: 'quarter', config: { preset: 'critical_count' } },
    { id: 'oa3',  type: 'card',      title: 'SLA Breached',                    width: 'quarter', config: { preset: 'sla_breached' } },
    { id: 'oa4',  type: 'card',      title: 'With Exploit',                    width: 'quarter', config: { preset: 'exploit_count' } },
    { id: 'oa5',  type: 'bar_chart', title: 'Risk Score by Owner',             width: 'full',    config: { preset: 'owner_risk_bar', horizontal: true } },
    { id: 'oa6',  type: 'bar_chart', title: 'Open Findings by Owner',          width: 'half',    config: { preset: 'owner_finding_count', horizontal: true } },
    { id: 'oa7',  type: 'pie_chart', title: 'Severity Distribution',           width: 'half',    config: { preset: 'severity_breakdown', donut: true } },
    { id: 'oa8',  type: 'table',     title: 'Owner Risk Scorecard',            width: 'full',    config: { preset: 'owner_risk_table' } },
    { id: 'oa9',  type: 'table',     title: 'Remediation Queue',               width: 'full',    config: { preset: 'remediation_queue_data', limit: 20 } },
    { id: 'oa10', type: 'table',     title: 'Quick Wins (Assign to Owner)',    width: 'full',    config: { preset: 'quick_wins_table', limit: 10 } },
  ],
}

// ─── Live widget renderers ────────────────────────────────────────────────────

// In-flight deduplication: multiple widgets requesting the same source+params share one fetch.
// Cache entries expire after 10s so filter changes always get fresh data.
const _fetchCache = new Map() // key → { promise, ts }
const _FETCH_TTL = 10_000

function _cachedFetch(key, fetchFn) {
  const now = Date.now()
  const entry = _fetchCache.get(key)
  if (entry && now - entry.ts < _FETCH_TTL) return entry.promise
  const promise = fetchFn()
  _fetchCache.set(key, { promise, ts: now })
  promise.catch(() => _fetchCache.delete(key)) // evict on error so retries work
  return promise
}

function useWidgetData(sourceId, scanId, filters, globalTags, globalTagLogic) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  // Merge global tag filter into per-widget filters (global takes precedence if widget has no tags set)
  const mergedFilters = globalTags
    ? { ...filters, tags: filters?.tags || globalTags, tag_logic: filters?.tag_logic || globalTagLogic || 'AND' }
    : filters
  const filtersKey = JSON.stringify(mergedFilters || {})

  useEffect(() => {
    if (!sourceId || !DATA_SOURCES[sourceId]) { setLoading(false); return }
    setLoading(true)
    let cancelled = false
    const cacheKey = `${sourceId}|${scanId || ''}|${filtersKey}`
    _cachedFetch(cacheKey, () => DATA_SOURCES[sourceId](scanId, mergedFilters))
      .then(d => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [sourceId, scanId, filtersKey])

  return { data, loading }
}

const TOOLTIP_STYLE = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }
const TICK_STYLE = { fill: 'var(--text-muted)', fontSize: 11 }

function truncLabel(s, max = 18) { return (s || '').length > max ? s.slice(0, max) + '...' : s || '' }

// ─── Drill-down URL map ───────────────────────────────────────────────────────
// For 'card' presets: a string URL or () => url
// For 'categories' presets: a (name) => url function
const DRILL_DOWN = {
  // Cards → findings filtered by severity
  critical_count:   '/findings?severity=4',
  high_count:       '/findings?severity=3',
  medium_count:     '/findings?severity=2',
  low_count:        '/findings?severity=1',
  info_count:       '/findings?severity=0',
  total_findings:   '/findings',
  exploit_count:    '/findings?exploit=true',
  high_priority:    '/findings?sort=priority_score',
  quick_wins:       '/findings?effort_level=quick_win',
  complex_findings: '/findings?effort_level=complex',
  sla_breached:     '/findings?sla_status=breached',
  sla_on_track:     '/findings?sla_status=on_track',
  sla_at_risk:      '/findings?sla_status=at_risk',
  total_assets:     '/assets',
  sla_compliance:   '/findings?sla_status=on_track',
  coverage_pct:     '/assets',
  credentialed_count: '/assets',
  mttr_overall:     '/findings',
  zombie_count:     '/findings',
  regression_count: '/findings',
  // Inventory cards
  inv_domain_admins:   '/inventory?tab=users&is_domain_admin=true',
  inv_local_admins:    '/inventory?tab=users&is_admin=true',
  inv_kerberoastable:  '/inventory?tab=users',
  inv_writeable_shares:'/inventory?tab=shares&is_writeable=true',
  inv_expired_certs:   '/inventory?tab=certs&expired_only=true',
  inv_total_users:     '/inventory?tab=users',
  inv_total_services:  '/inventory?tab=services',
  inv_total_software:  '/inventory?tab=software',
  inv_total_computers: '/inventory?tab=computers',
  inv_total_certificates: '/inventory?tab=certs',
  inv_logged_on_count: '/inventory?tab=logged-on',
  inv_pw_never_expires: '/inventory?tab=users',
  inv_pw_never_changed: '/inventory?tab=users',
  inv_domain_controllers: '/inventory?tab=computers&is_dc=true',
  inv_lateral_paths:   '/inventory?tab=users',
  inv_established_conns: '/inventory?tab=netconns&state=ESTABLISHED',
  inv_weak_pw_policies: '/inventory?tab=password-policies',
  inv_hosts_with_av:   '/inventory?tab=security-controls',
  inv_expiring_certs:  '/inventory?tab=certs',
  inv_self_signed_certs: '/inventory?tab=certs',
  inv_sensitive_env_vars: '/inventory?tab=env-vars',
  // EASM cards
  easm_total_assets:   '/inventory?tab=easm_assets',
  easm_with_open_ports:'/inventory?tab=easm_assets',
  easm_with_http:      '/inventory?tab=easm_assets',
  easm_with_cdn:       '/inventory?tab=easm_assets',
  easm_expired_certs:  '/inventory?tab=certs&source=easm',
  easm_breach_count:   '/inventory?tab=easm_breaches',
  // EASM categories
  easm_asset_liveness: name => `/inventory?tab=easm_assets&search=${encodeURIComponent(name)}`,
  easm_tech_stack:     name => `/inventory?tab=easm_assets&search=${encodeURIComponent(name)}`,
  easm_open_ports:     name => `/inventory?tab=easm_assets&search=${encodeURIComponent(name)}`,
  easm_cdn_providers:  name => `/inventory?tab=easm_assets&search=${encodeURIComponent(name)}`,
  easm_event_types:    name => `/inventory?tab=easm_assets&search=${encodeURIComponent(name)}`,
  // AI / ML
  inv_total_ai_tools:  '/inventory?tab=ai-tools',
  // OS & Software risk
  os_risk_vuln_count:  '/findings',
  sw_risk_vuln_count:  '/findings',
  os_risk_chart: name => `/findings?search=${encodeURIComponent(name)}`,
  software_risk_chart: name => `/findings?product=${encodeURIComponent(name)}`,

  // Categories (pie/bar) → function(name) => url
  severity_breakdown: name => {
    const map = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }
    const sev = map[name]
    return sev != null ? `/findings?severity=${sev}` : '/findings'
  },
  sla_status: name => {
    const slug = name.toLowerCase().replace(/\s+/g, '_')
    return `/findings?sla_status=${slug}`
  },
  effort_breakdown: name => {
    const map = { 'Quick Win': 'quick_win', Medium: 'medium', Complex: 'complex' }
    return map[name] ? `/findings?effort_level=${map[name]}` : '/findings'
  },
  sla_breached_by_sev: name => {
    const map = { Critical: 4, High: 3, Medium: 2, Low: 1 }
    const sev = map[name]
    return sev != null ? `/findings?severity=${sev}&sla_status=breached` : '/findings?sla_status=breached'
  },
  family_breakdown: name => `/findings?family=${encodeURIComponent(name)}`,
  inv_user_type_breakdown: name => `/inventory?tab=users&user_type=${name.replace(/\s+/g, '_')}`,
  inv_netconn_states: name => `/inventory?tab=netconns&state=${name}`,
  inv_ai_tool_categories: name => `/inventory?tab=ai-tools&category=${encodeURIComponent(name)}`,
  severity_breakdown_filtered: name => {
    const map = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }
    const sev = map[name]
    return sev != null ? `/findings?severity=${sev}&family=Artificial+Intelligence` : '/findings?family=Artificial+Intelligence'
  },
}

// ─── Benchmark overlay for existing widgets ──────────────────────────────────

const BENCHMARK_RATING_COLORS = {
  excellent: '#16a34a',
  good: '#65a30d',
  fair: '#d97706',
  poor: '#dc2626',
}

const BENCHMARK_RATING_LABELS = {
  excellent: 'Excellent',
  good: 'Good',
  fair: 'Fair',
  poor: 'Poor',
}

// Map widget presets → benchmark metric keys
const PRESET_TO_BENCHMARK = {
  // Cards
  critical_count:   'critical_density',
  sla_compliance:   'sla_compliance',
  sla_breached:     'sla_compliance',
  sla_on_track:     'sla_compliance',
  coverage_pct:     'assessment_coverage',
  credentialed_count: 'assessment_coverage',
  exploit_count:    'exploit_exposure',
  mttr_overall:     'mttr_critical',
  // Risk grade
  risk_grade:       'risk_grade',
  // Gauge
  gauge_sla_compliance: 'sla_compliance',
  gauge_coverage:   'assessment_coverage',
  // MTTR
  mttr_by_severity: 'mttr_critical',
}

/** Hook: fetch benchmark data only when show_benchmark is enabled */
function useBenchmarkData(enabled, scanId, filters) {
  const [data, setData] = useState(null)
  const industry = filters?.benchmark_industry || ''
  const orgSize = filters?.benchmark_org_size || ''
  const source = filters?.benchmark_source || ''
  const key = `${enabled}|${scanId}|${industry}|${orgSize}|${source}`

  useEffect(() => {
    if (!enabled) { setData(null); return }
    let cancelled = false
    getBenchmarks(scanId, industry || undefined, orgSize || undefined, source || undefined)
      .then(d => { if (!cancelled) setData(d) })
      .catch(() => { if (!cancelled) setData(null) })
    return () => { cancelled = true }
  }, [key])

  return data
}

/** Find the matching benchmark metric for a given preset */
function findBenchmark(benchmarkData, presetKey) {
  if (!benchmarkData?.metrics) return null
  const metricKey = PRESET_TO_BENCHMARK[presetKey]
  if (!metricKey) return null
  return benchmarkData.metrics.find(m => m.metric === metricKey) || null
}

/** Compact inline benchmark bar — shown below a card/gauge value */
function BenchmarkInline({ bm }) {
  if (!bm || !bm.benchmark) return null
  const ratingColor = BENCHMARK_RATING_COLORS[bm.rating] || '#94a3b8'
  const markerPos = Math.max(2, Math.min(98, bm.percentile_rank ?? 50))
  const hib = bm.higher_is_better
  const sourceLabel = bm.effective_source === 'platform'
    ? `Platform (${bm.platform_benchmark?.population_size || '?'} orgs)`
    : bm.benchmark?.industry && bm.benchmark.industry !== 'all'
      ? `Industry: ${bm.benchmark.industry}`
      : 'Industry Benchmark'

  return (
    <div style={{ marginTop: 8, padding: '6px 8px', background: 'var(--bg-hover)', borderRadius: 6 }}>
      {/* Percentile label */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{sourceLabel}</span>
        <span style={{ fontSize: 10, fontWeight: 600, color: ratingColor }}>
          {BENCHMARK_RATING_LABELS[bm.rating]} — P{bm.percentile_rank}
        </span>
      </div>
      {/* Mini gauge bar */}
      <div style={{ position: 'relative', height: 10, borderRadius: 3, overflow: 'hidden', background: 'var(--bg-secondary)' }}>
        <div style={{ position: 'absolute', inset: 0, display: 'flex' }}>
          <div style={{ width: '25%', background: hib ? '#dc262615' : '#16a34a15' }} />
          <div style={{ width: '25%', background: hib ? '#d9770615' : '#65a30d15' }} />
          <div style={{ width: '25%', background: hib ? '#65a30d15' : '#d9770615' }} />
          <div style={{ width: '25%', background: hib ? '#16a34a15' : '#dc262615' }} />
        </div>
        {[25, 50, 75].map(p => (
          <div key={p} style={{ position: 'absolute', left: `${p}%`, top: 0, bottom: 0, width: 1, background: 'var(--border)', opacity: 0.5 }} />
        ))}
        <div style={{
          position: 'absolute', left: `${markerPos}%`, top: 1, bottom: 1,
          width: 8, marginLeft: -4, borderRadius: 2,
          background: ratingColor, boxShadow: `0 0 3px ${ratingColor}50`,
        }} />
      </div>
      {/* P25/P50/P75 labels */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 2 }}>
        <span style={{ fontSize: 9, color: 'var(--text-muted)', opacity: 0.7 }}>P25</span>
        <span style={{ fontSize: 9, color: 'var(--text-muted)', opacity: 0.7 }}>Median</span>
        <span style={{ fontSize: 9, color: 'var(--text-muted)', opacity: 0.7 }}>P75</span>
      </div>
    </div>
  )
}

/** Full benchmark bar — for risk_grade component rows */
function BenchmarkGaugeBar({ label, benchmark, unit, higherIsBetter, percentileRank, rating, effectiveSource, populationSize }) {
  const ratingColor = BENCHMARK_RATING_COLORS[rating] || '#94a3b8'
  const formatVal = (v) => {
    if (v == null) return '—'
    if (unit === 'percent') return `${Math.round(v)}%`
    if (unit === 'days') return `${v.toFixed?.(1) ?? v}d`
    if (unit === 'score') return Math.round(v)
    return v.toLocaleString?.() ?? v
  }
  const markerPos = Math.max(2, Math.min(98, percentileRank ?? 50))

  return (
    <div style={{ marginTop: 10, padding: '6px 10px', background: 'var(--bg-hover)', borderRadius: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{effectiveSource === 'platform' ? `vs Platform (${populationSize || '?'} orgs)` : 'vs Industry'}</span>
        <span style={{ fontSize: 11, fontWeight: 600, color: ratingColor }}>
          {BENCHMARK_RATING_LABELS[rating]} — P{percentileRank}
        </span>
      </div>
      <div style={{ position: 'relative', height: 10, borderRadius: 3, overflow: 'hidden', background: 'var(--bg-secondary)' }}>
        <div style={{ position: 'absolute', inset: 0, display: 'flex' }}>
          <div style={{ width: '25%', background: higherIsBetter ? '#dc262615' : '#16a34a15' }} />
          <div style={{ width: '25%', background: higherIsBetter ? '#d9770615' : '#65a30d15' }} />
          <div style={{ width: '25%', background: higherIsBetter ? '#65a30d15' : '#d9770615' }} />
          <div style={{ width: '25%', background: higherIsBetter ? '#16a34a15' : '#dc262615' }} />
        </div>
        {[25, 50, 75].map(p => (
          <div key={p} style={{ position: 'absolute', left: `${p}%`, top: 0, bottom: 0, width: 1, background: 'var(--border)', opacity: 0.5 }} />
        ))}
        <div style={{
          position: 'absolute', left: `${markerPos}%`, top: 1, bottom: 1,
          width: 8, marginLeft: -4, borderRadius: 2,
          background: ratingColor, boxShadow: `0 0 3px ${ratingColor}50`,
        }} />
      </div>
      {benchmark && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 2 }}>
          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>P25: {formatVal(benchmark.p25)}</span>
          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>P50: {formatVal(benchmark.p50)}</span>
          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>P75: {formatVal(benchmark.p75)}</span>
        </div>
      )}
    </div>
  )
}

function WidgetRenderer({ widget, scanId, preview, globalTags, globalTagLogic }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const cfg = widget.config || {}
  const preset = DATA_PRESETS[cfg.preset]
  const sourceId = preset?.source || null
  const filters = { ...(cfg.filters || {}), category: cfg.category, period: cfg.period }
  const { data, loading } = useWidgetData(sourceId, scanId, filters, globalTags, globalTagLogic)

  // Benchmark overlay — fetches benchmark data when show_benchmark is toggled on
  const benchmarkData = useBenchmarkData(!!cfg.show_benchmark, scanId, cfg.filters)
  const bm = cfg.show_benchmark ? findBenchmark(benchmarkData, cfg.preset) : null

  const drillDown = DRILL_DOWN[cfg.preset]
  // Auto-build drill-down for filtered findings presets (e.g. finding_count_filtered with plugin_family)
  const autoDrillUrl = !drillDown && preset?.source === 'findings' && cfg.filters
    ? '/findings?' + new URLSearchParams(Object.entries(cfg.filters).filter(([k, v]) => v && !['sort_by', 'order', 'page_size'].includes(k)).map(([k, v]) => [k === 'plugin_family' ? 'family' : k, v])).toString()
    : null
  const handleCardClick = (drillDown || autoDrillUrl) ? () => {
    const url = drillDown ? (typeof drillDown === 'function' ? drillDown() : drillDown) : autoDrillUrl
    navigate(url)
  } : null
  const handleSliceClick = (entry) => {
    if (drillDown && typeof drillDown === 'function') { navigate(drillDown(entry?.name)); return }
    if (autoDrillUrl) { navigate(autoDrillUrl); return }
  }

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
      : <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.setImageUrl')}</div>
  }
  if (widget.type === 'funnel') {
    return <FunnelWidget widget={widget} scanId={scanId} />
  }

  // Data widgets
  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 100 }}><Spinner /></div>
  if (!data || !preset) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noDataAvailable')}</div>

  const extracted = preset.dynamic ? preset.extract(data, cfg) : preset.extract(data)

  // For custom_series, resolve fields/colors dynamically from cfg.metrics
  const resolvedPreset = (() => {
    if (cfg.preset === 'custom_series' && Array.isArray(cfg.metrics) && cfg.metrics.length > 0) {
      const fields = cfg.metrics.filter(m => SERIES_METRIC_MAP[m])
      const colors = Object.fromEntries(fields.map(f => [f, SERIES_METRIC_MAP[f]?.color || PALETTE[0]]))
      return { ...preset, fields, colors }
    }
    return preset
  })()

  switch (widget.type) {
    case 'card': {
      const val = typeof extracted === 'number' ? extracted : 0
      const display = preset.format === 'pct' ? `${val}%` : val.toLocaleString()
      const color = preset.color || 'var(--text-primary)'
      return (
        <div
          onClick={handleCardClick || undefined}
          style={{
            textAlign: 'center', padding: '8px 0',
            cursor: handleCardClick ? 'pointer' : 'default',
            borderRadius: 8,
            transition: 'background 0.15s',
          }}
          onMouseEnter={handleCardClick ? e => { e.currentTarget.style.background = 'var(--bg-hover)' } : undefined}
          onMouseLeave={handleCardClick ? e => { e.currentTarget.style.background = 'transparent' } : undefined}
        >
          <div style={{ fontSize: 48, fontWeight: 800, color, lineHeight: 1 }}>{display}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>{cfg.label || preset.label}</div>
          {handleCardClick && !bm && <div style={{ fontSize: 11, color: 'var(--accent)', marginTop: 6, opacity: 0.7 }}>{t('findings.clickToDrillDown')}</div>}
          {bm && <BenchmarkInline bm={bm} />}
        </div>
      )
    }

    case 'risk_grade': {
      const grade = extracted?.grade ?? null
      const score = extracted?.score ?? null
      const gradeColor = extracted?.grade_color ?? '#94a3b8'
      const hasData = grade != null && score != null
      const components = extracted?.components || {}
      const weights = extracted?.weights || {}
      const compLabels = {
        severity_mix: 'Severity Mix',
        sla_compliance: 'SLA Compliance',
        remediation_velocity: 'Remediation Speed',
        assessment_coverage: 'Assessment Coverage',
        exploit_exposure: 'Exploit Exposure',
      }
      const compOrder = ['severity_mix', 'sla_compliance', 'remediation_velocity', 'assessment_coverage', 'exploit_exposure']
      if (!hasData) return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 32, padding: '8px 0' }}>
          <div style={{
            width: 96, height: 96, borderRadius: '50%', flexShrink: 0,
            background: '#94a3b818', border: '3px solid #94a3b8',
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          }}>
            <div style={{ fontSize: 44, fontWeight: 800, color: '#94a3b8', lineHeight: 1 }}>—</div>
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>{t('findingDetail.noDataAvailable')}</div>
        </div>
      )
      return (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 32, padding: '8px 0' }}>
            {/* Big grade circle */}
            <div style={{
              width: 96, height: 96, borderRadius: '50%', flexShrink: 0,
              background: gradeColor + '18', border: `3px solid ${gradeColor}`,
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            }}>
              <div style={{ fontSize: 44, fontWeight: 800, color: gradeColor, lineHeight: 1 }}>{grade}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: gradeColor, opacity: 0.8 }}>{score}/100</div>
            </div>
            {/* Component breakdown bars */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {compOrder.map(key => {
                const val = components[key] ?? 0
                const w = weights[key] ?? 0
                const barColor = val >= 80 ? '#16a34a' : val >= 60 ? '#d97706' : '#dc2626'
                return (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 130, fontSize: 11, color: 'var(--text-muted)', textAlign: 'right', flexShrink: 0 }}>
                      {compLabels[key] || key} <span style={{ opacity: 0.5 }}>({Math.round(w * 100)}%)</span>
                    </div>
                    <div style={{ flex: 1, height: 8, background: 'var(--bg-hover)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{ width: `${val}%`, height: '100%', background: barColor, borderRadius: 4, transition: 'width 0.5s' }} />
                    </div>
                    <div style={{ width: 30, fontSize: 11, fontWeight: 600, color: barColor, textAlign: 'right' }}>{Math.round(val)}</div>
                  </div>
                )
              })}
            </div>
          </div>
          {bm && (
            <BenchmarkGaugeBar
              label={bm.label}
              benchmark={bm.benchmark}
              unit={bm.unit}
              higherIsBetter={bm.higher_is_better}
              percentileRank={bm.percentile_rank}
              rating={bm.rating}
              effectiveSource={bm.effective_source}
              populationSize={bm.platform_benchmark?.population_size}
            />
          )}
          {cfg.show_tips && (() => {
            const ctx = extracted?.context || {}
            const buildTip = (key) => {
              switch (key) {
                case 'severity_mix': {
                  const c = ctx.critical_count ?? 0, h = ctx.high_count ?? 0, total = ctx.total_non_info ?? 0
                  const ratio = total > 0 ? Math.round((c + h) / total * 100) : 0
                  return {
                    label: 'Severity Mix', color: '#dc2626',
                    action: `${c} critical, ${h} high out of ${total} findings (${ratio}%) — remediate to reduce ratio`,
                    drillUrl: '/findings?severity=4',
                  }
                }
                case 'exploit_exposure': {
                  const e = ctx.exploit_count ?? 0, total = ctx.total_non_info ?? 0
                  return {
                    label: 'Exploit Exposure', color: '#ea580c',
                    action: `${e} of ${total} findings have known exploits — patch these first`,
                    drillUrl: '/findings?has_exploit=true',
                  }
                }
                case 'remediation_velocity': {
                  const mttr = ctx.avg_mttr_days
                  return {
                    label: 'Remediation Speed', color: '#f59e0b',
                    action: mttr != null
                      ? `Avg MTTR is ${mttr}d (target <7d) — use Quick Wins to reduce it`
                      : 'No resolved findings yet — start closing Quick Wins',
                    drillUrl: '/findings?effort_level=quick_win',
                  }
                }
                case 'sla_compliance': {
                  const breached = ctx.sla_breached ?? 0, atRisk = ctx.sla_at_risk ?? 0
                  return {
                    label: 'SLA Compliance', color: '#d97706',
                    action: `${breached} findings SLA-breached, ${atRisk} at risk — resolve immediately`,
                    drillUrl: '/findings?sla_status=breached',
                  }
                }
                case 'assessment_coverage': {
                  const cred = ctx.credentialed_assets ?? 0, total = ctx.total_assets ?? 0
                  const uncred = total - cred
                  return {
                    label: 'Coverage', color: '#6366f1',
                    action: `${cred}/${total} assets credentialed — run credentialed scans on ${uncred} more`,
                    drillUrl: '/assets',
                  }
                }
                default: return null
              }
            }
            const tipsOrder = ['severity_mix', 'exploit_exposure', 'remediation_velocity', 'sla_compliance', 'assessment_coverage']
            const weakest = [...tipsOrder].sort((a, b) => (components[a] ?? 0) - (components[b] ?? 0)).filter(k => (components[k] ?? 0) < 80).slice(0, 3)
            if (weakest.length === 0) return null
            return (
              <div style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>Top improvements</div>
                {weakest.map((key, rank) => {
                  const val = Math.round(components[key] ?? 0)
                  const tip = buildTip(key)
                  if (!tip) return null
                  const valColor = val >= 60 ? '#d97706' : '#dc2626'
                  return (
                    <div
                      key={key}
                      onClick={() => navigate(tip.drillUrl)}
                      style={{ display: 'grid', gridTemplateColumns: '10px 1fr auto auto', alignItems: 'center', gap: 8, padding: '5px 6px', borderRadius: 5, cursor: 'pointer', transition: 'background 0.1s' }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-hover)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                    >
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: tip.color, opacity: 1 - rank * 0.2, flexShrink: 0 }} />
                      <span style={{ fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <span style={{ fontWeight: 700, color: 'var(--text-primary)', marginRight: 4 }}>{tip.label}:</span>
                        {tip.action}
                      </span>
                      <span style={{ fontSize: 10, fontWeight: 700, color: valColor, flexShrink: 0, background: `${tip.color}18`, borderRadius: 4, padding: '1px 5px' }}>{val}/100</span>
                      <span style={{ fontSize: 10, fontWeight: 700, color: '#16a34a', flexShrink: 0, background: '#16a34a18', borderRadius: 4, padding: '1px 5px', whiteSpace: 'nowrap' }}>
                        +{Math.round((80 - val) * (weights[key] ?? 0))} pts
                      </span>
                    </div>
                  )
                })}
              </div>
            )
          })()}
        </div>
      )
    }

    case 'pie_chart': {
      if (!Array.isArray(extracted) || extracted.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noData')}</div>
      const items = extracted.map((d, i) => ({ ...d, color: d.color || PALETTE[i % PALETTE.length] }))
      const hasDrill = drillDown && typeof drillDown === 'function'
      return (
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={items} cx="50%" cy="50%"
              innerRadius={cfg.donut ? 50 : 0} outerRadius={70} paddingAngle={2} dataKey="value"
              onClick={hasDrill ? (data) => handleSliceClick(data) : undefined}
              cursor={hasDrill ? 'pointer' : 'default'}
            >
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
        if (items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noData')}</div>
        const colored = items.map((d, i) => ({ ...d, color: d.color || PALETTE[i % PALETTE.length] }))
        const hasDrill = drillDown && typeof drillDown === 'function'
        const onBarClick = hasDrill ? (data) => handleSliceClick(data) : undefined
        if (cfg.horizontal) {
          return (
            <ResponsiveContainer width="100%" height={Math.max(160, colored.length * 30)}>
              <BarChart data={colored} layout="vertical" margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                <XAxis type="number" tick={TICK_STYLE} />
                <YAxis type="category" dataKey="name" tick={{ ...TICK_STYLE, fontSize: 11 }} width={140} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} onClick={onBarClick} cursor={hasDrill ? 'pointer' : 'default'}>
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
              <Bar dataKey="value" radius={[4, 4, 0, 0]} onClick={onBarClick} cursor={hasDrill ? 'pointer' : 'default'}>
                {colored.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )
      }
      // series type
      const rows = Array.isArray(extracted) ? extracted : []
      if (rows.length < 2) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.needDataPoints')}</div>
      const fields = resolvedPreset.fields || []
      if (fields.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.selectMetrics')}</div>
      const chartData = rows.map(r => ({ name: truncLabel(r[resolvedPreset.xField]), ...Object.fromEntries(fields.map(f => [f, r[f] ?? null])) }))
      return (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={chartData} stackOffset={cfg.stacked ? 'sign' : 'none'}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ ...TICK_STYLE, fontSize: 10 }} />
            <YAxis tick={TICK_STYLE} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{SERIES_METRIC_MAP[v]?.label || v}</span>} />
            {fields.map(f => (
              <Bar key={f} dataKey={f} fill={resolvedPreset.colors?.[f] || PALETTE[fields.indexOf(f) % PALETTE.length]} radius={[3, 3, 0, 0]} stackId={cfg.stacked ? 'a' : undefined} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      )
    }

    case 'line_chart': {
      const rows = Array.isArray(extracted) ? extracted : []
      if (rows.length < 2) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.needDataPoints')}</div>
      const fields = resolvedPreset.fields || []
      if (fields.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.selectMetrics')}</div>
      const chartData = rows.map(r => ({ name: truncLabel(r[resolvedPreset.xField]), ...Object.fromEntries(fields.map(f => [f, r[f] ?? null])) }))
      const ChartComp = cfg.areaFill ? AreaChart : LineChart
      return (
        <ResponsiveContainer width="100%" height={220}>
          <ChartComp data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ ...TICK_STYLE, fontSize: 10 }} />
            <YAxis tick={TICK_STYLE} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{SERIES_METRIC_MAP[v]?.label || v}</span>} />
            {fields.map(f => {
              const color = resolvedPreset.colors?.[f] || PALETTE[fields.indexOf(f) % PALETTE.length]
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
      const rowDrill = preset.rowDrillDown
      if (display.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noData')}</div>
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
              {display.map((row, i) => {
                const drillUrl = rowDrill ? rowDrill(row) : null
                return (
                  <tr
                    key={i}
                    style={{ borderBottom: '1px solid var(--border)', cursor: drillUrl ? 'pointer' : 'default', transition: 'background 0.1s' }}
                    onClick={drillUrl ? () => navigate(drillUrl) : undefined}
                    onMouseEnter={drillUrl ? e => { e.currentTarget.style.background = 'var(--bg-hover)' } : undefined}
                    onMouseLeave={drillUrl ? e => { e.currentTarget.style.background = 'transparent' } : undefined}
                  >
                    {cols.map(c => {
                      const raw = row[c.key] ?? (c.fallback ? row[c.fallback] : null) ?? ''
                      const val = c.render ? c.render(raw) : raw
                      return (
                        <td key={c.key} style={{ padding: '6px 8px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val}</td>
                      )
                    })}
                  </tr>
                )
              })}
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
      if (families.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noFamilyData')}</div>
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

    case 'radar': {
      const items = Array.isArray(extracted) ? extracted : []
      if (items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noData')}</div>
      return (
        <ResponsiveContainer width="100%" height={250}>
          <RadarChart data={items} cx="50%" cy="50%" outerRadius="70%">
            <PolarGrid stroke="var(--border)" />
            <PolarAngleAxis dataKey="axis" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
            <PolarRadiusAxis angle={90} domain={[0, 100]} tick={false} axisLine={false} />
            <Radar dataKey="value" stroke="#6366f1" fill="#6366f1" fillOpacity={0.25} strokeWidth={2} />
            <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v) => `${Math.round(v)}`} />
          </RadarChart>
        </ResponsiveContainer>
      )
    }

    case 'gauge': {
      const gaugeData = extracted || {}
      const val = gaugeData.value ?? 0
      const max = gaugeData.max || 100
      const pct = Math.min(val / max, 1)
      const color = pct > 0.75 ? '#16a34a' : pct > 0.5 ? '#d97706' : pct > 0.25 ? '#ea580c' : '#dc2626'
      // For metrics where high = bad (risk, exploits), invert the color logic
      const isInverted = (cfg.preset || '').includes('risk') || (cfg.preset || '').includes('exploit') || (cfg.preset || '').includes('critical')
      const displayColor = isInverted ? (pct > 0.75 ? '#dc2626' : pct > 0.5 ? '#ea580c' : pct > 0.25 ? '#d97706' : '#16a34a') : color
      const chartData = [{ name: gaugeData.label || 'Value', value: val, fill: displayColor }]
      return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '8px 0' }}>
          <ResponsiveContainer width="100%" height={140}>
            <RadialBarChart
              cx="50%" cy="100%"
              innerRadius="60%"
              outerRadius="90%"
              startAngle={180}
              endAngle={0}
              barSize={14}
              data={chartData}
            >
              <RadialBar
                background={{ fill: 'var(--bg-hover)' }}
                dataKey="value"
                cornerRadius={7}
                max={max}
              />
            </RadialBarChart>
          </ResponsiveContainer>
          <div style={{ marginTop: -30, textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: displayColor, lineHeight: 1 }}>
              {val}{gaugeData.suffix || ''}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              {gaugeData.label || 'Value'} / {max}{gaugeData.suffix || ''}
            </div>
          </div>
          {bm && <div style={{ width: '100%', padding: '0 8px' }}><BenchmarkInline bm={bm} /></div>}
        </div>
      )
    }

    case 'treemap': {
      const items = Array.isArray(extracted) ? extracted.filter(d => d.size > 0) : []
      if (items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.noData')}</div>
      const colored = items.map((d, i) => ({
        ...d,
        fill: d.color || (() => {
          if (d.critical > 0) return '#dc2626'
          if (d.high > 0) return '#ea580c'
          return PALETTE[i % PALETTE.length]
        })(),
      }))
      const TreemapContent = ({ x, y, width, height, name, size, fill }) => {
        if (width < 30 || height < 20) return null
        return (
          <g>
            <rect x={x} y={y} width={width} height={height} rx={4} fill={fill} fillOpacity={0.85} stroke="var(--bg-card)" strokeWidth={2} />
            {width > 50 && height > 30 && (
              <>
                <text x={x + 6} y={y + 16} fill="#fff" fontSize={11} fontWeight={600}>
                  {name?.length > Math.floor(width / 7) ? name.slice(0, Math.floor(width / 7)) + '...' : name}
                </text>
                <text x={x + 6} y={y + 30} fill="#ffffffcc" fontSize={10}>
                  {size?.toLocaleString?.() ?? size}
                </text>
              </>
            )}
          </g>
        )
      }
      return (
        <ResponsiveContainer width="100%" height={220}>
          <RechartsTreemap
            data={colored}
            dataKey="size"
            aspectRatio={4 / 3}
            content={<TreemapContent />}
          >
            <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v) => v?.toLocaleString?.()} />
          </RechartsTreemap>
        </ResponsiveContainer>
      )
    }

    default:
      return <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>{t('reports.unknownWidget')}: {widget.type}</div>
  }
}

// ─── Funnel widget (self-contained data fetching) ─────────────────────────────

const FUNNEL_COLORS = ['#6366f1', '#818cf8', '#a5b4fc', '#c7d2fe', '#e0e7ff', '#93c5fd', '#60a5fa', '#3b82f6']

function FunnelWidget({ widget, scanId }) {
  const { t } = useTranslation()
  const cfg = widget.config || {}
  const [funnelData, setFunnelData] = useState(null)
  const [loading, setLoading] = useState(true)
  const stepsKey = JSON.stringify(cfg.steps || [])

  useEffect(() => {
    if (!cfg.steps || cfg.steps.length === 0) { setLoading(false); return }
    setLoading(true)
    getFunnel({ base_entity: cfg.base_entity || 'findings', scan_id: scanId || undefined, steps: cfg.steps })
      .then(d => { setFunnelData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [cfg.base_entity, stepsKey, scanId])

  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 100 }}><Spinner /></div>
  if (!funnelData?.steps?.length) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>{t('reports.configureFunnel')}</div>

  const steps = funnelData.steps
  const maxCount = steps[0]?.count || 1

  return (
    <div style={{ padding: '4px 0' }}>
      {steps.map((step, i) => {
        const widthPct = Math.max(15, (step.count / maxCount) * 100)
        const color = FUNNEL_COLORS[i % FUNNEL_COLORS.length]
        const prevCount = i > 0 ? steps[i - 1].count : null
        const dropPct = prevCount ? Math.round((1 - step.count / prevCount) * 100) : null
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <div style={{ width: 130, flexShrink: 0, textAlign: 'right', fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>
              {step.label}
            </div>
            <div style={{ flex: 1, position: 'relative' }}>
              <div style={{
                width: `${widthPct}%`,
                margin: '0 auto',
                background: `linear-gradient(135deg, ${color}, ${color}cc)`,
                borderRadius: 6,
                padding: '8px 12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                minHeight: 32,
                transition: 'width 0.4s ease',
              }}>
                <span style={{ color: '#fff', fontWeight: 700, fontSize: 14 }}>
                  {step.count.toLocaleString()}
                </span>
              </div>
            </div>
            <div style={{ width: 60, flexShrink: 0, fontSize: 11, color: dropPct != null ? (dropPct > 50 ? '#dc2626' : '#d97706') : 'transparent', fontWeight: 600 }}>
              {dropPct != null ? `−${dropPct}%` : ''}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Funnel step filter options ───────────────────────────────────────────────

const FUNNEL_FINDING_FILTERS = [
  // Severity & scoring
  { key: 'severity', label: 'Severity =', type: 'select', options: [{ value: '', label: '—' }, { value: '4', label: 'Critical' }, { value: '3', label: 'High' }, { value: '2', label: 'Medium' }, { value: '1', label: 'Low' }, { value: '0', label: 'Info' }] },
  { key: 'min_severity', label: 'Min Severity ≥', type: 'select', options: [{ value: '', label: '—' }, { value: '4', label: 'Critical' }, { value: '3', label: 'High' }, { value: '2', label: 'Medium' }, { value: '1', label: 'Low' }] },
  { key: 'min_cvss3', label: 'CVSS v3 ≥', type: 'number', placeholder: 'e.g. 9.0' },
  { key: 'min_cvss4', label: 'CVSS v4 ≥', type: 'number', placeholder: 'e.g. 9.0' },
  { key: 'min_vpr', label: 'VPR Score ≥', type: 'number', placeholder: 'e.g. 7.0' },
  { key: 'min_epss', label: 'EPSS ≥', type: 'number', placeholder: 'e.g. 0.5' },
  // Threat intel
  { key: 'is_kev', label: 'In CISA KEV', type: 'toggle' },
  { key: 'has_exploit', label: 'Has Exploit', type: 'toggle' },
  { key: 'ransomware_linked', label: 'Ransomware Linked', type: 'toggle' },
  { key: 'trending_in_news', label: 'Trending in News', type: 'toggle' },
  { key: 'zero_day', label: 'Zero-Day', type: 'toggle' },
  { key: 'exploit_maturity', label: 'Exploit Maturity', type: 'select', options: [{ value: '', label: '—' }, { value: 'weaponized', label: 'Weaponized' }, { value: 'functional', label: 'Functional' }, { value: 'poc', label: 'PoC' }, { value: 'unproven', label: 'Unproven' }] },
  // ATT&CK
  { key: 'has_ttps', label: 'Has ATT&CK TTPs', type: 'toggle' },
  { key: 'tactic', label: 'ATT&CK Tactic', type: 'select', options: [{ value: '', label: '—' }, { value: 'initial-access', label: 'Initial Access' }, { value: 'execution', label: 'Execution' }, { value: 'persistence', label: 'Persistence' }, { value: 'privilege-escalation', label: 'Privilege Escalation' }, { value: 'defense-evasion', label: 'Defense Evasion' }, { value: 'credential-access', label: 'Credential Access' }, { value: 'discovery', label: 'Discovery' }, { value: 'lateral-movement', label: 'Lateral Movement' }, { value: 'collection', label: 'Collection' }, { value: 'command-and-control', label: 'C2' }, { value: 'exfiltration', label: 'Exfiltration' }, { value: 'impact', label: 'Impact' }] },
  { key: 'technique_id', label: 'ATT&CK Technique', type: 'text', placeholder: 'e.g. T1059' },
  // Asset context
  { key: 'on_critical_assets', label: 'On Critical Assets', type: 'toggle' },
  { key: 'on_internet_facing', label: 'Internet Exposed', type: 'toggle' },
  { key: 'asset_min_risk', label: 'Asset Risk ≥', type: 'number', placeholder: 'e.g. 7' },
  // Workflow & SLA
  { key: 'workflow_status', label: 'Workflow Status', type: 'select', options: [{ value: '', label: '—' }, { value: 'open', label: 'Open' }, { value: 'in_progress', label: 'In Progress' }, { value: 'resolved', label: 'Resolved' }, { value: 'accepted_risk', label: 'Accepted Risk' }, { value: 'false_positive', label: 'False Positive' }, { value: 'compensating_control', label: 'Compensating Control' }] },
  { key: 'vulnerability_state', label: 'Vulnerability State', type: 'select', options: [{ value: '', label: '—' }, { value: 'Active', label: 'Active' }, { value: 'New', label: 'New' }, { value: 'Resurfaced', label: 'Resurfaced' }, { value: 'Fixed', label: 'Fixed' }] },
  { key: 'sla_status', label: 'SLA Status', type: 'select', options: [{ value: '', label: '—' }, { value: 'breached', label: 'Breached' }, { value: 'at_risk', label: 'At Risk' }, { value: 'on_track', label: 'On Track' }] },
  { key: 'is_regression', label: 'Is Regression', type: 'toggle' },
  { key: 'has_exception', label: 'Has Exception', type: 'toggle' },
  // Effort & ownership
  { key: 'effort_level', label: 'Effort', type: 'select', options: [{ value: '', label: '—' }, { value: 'quick_win', label: 'Quick Win' }, { value: 'medium', label: 'Medium' }, { value: 'complex', label: 'Complex' }] },
  { key: 'owner_suggestion', label: 'Owner', type: 'select', options: [{ value: '', label: '—' }, { value: 'IT', label: 'IT' }, { value: 'DevOps', label: 'DevOps' }, { value: 'SecOps', label: 'SecOps' }, { value: 'AppSec', label: 'AppSec' }] },
  // Plugin details
  { key: 'plugin_family', label: 'Plugin Family', type: 'text', placeholder: 'e.g. Windows' },
  { key: 'plugin_name', label: 'Plugin Name Contains', type: 'text', placeholder: 'e.g. SSL' },
  { key: 'port', label: 'Port =', type: 'number', placeholder: 'e.g. 443' },
  { key: 'protocol', label: 'Protocol', type: 'select', options: [{ value: '', label: '—' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }] },
  { key: 'cve', label: 'CVE Contains', type: 'text', placeholder: 'e.g. CVE-2021-44228' },
  { key: 'risk_factor', label: 'Risk Factor', type: 'select', options: [{ value: '', label: '—' }, { value: 'Critical', label: 'Critical' }, { value: 'High', label: 'High' }, { value: 'Medium', label: 'Medium' }, { value: 'Low', label: 'Low' }, { value: 'None', label: 'None' }] },
  { key: 'search', label: 'Keyword', type: 'text', placeholder: 'Search...' },
]

const FUNNEL_ASSET_FILTERS = [
  // Asset properties
  { key: 'criticality', label: 'Criticality ≥', type: 'number', placeholder: 'e.g. 8' },
  { key: 'min_risk', label: 'Risk Score ≥', type: 'number', placeholder: 'e.g. 7' },
  { key: 'os', label: 'OS Contains', type: 'text', placeholder: 'e.g. Windows Server' },
  { key: 'environment', label: 'Environment', type: 'select', options: [{ value: '', label: '—' }, { value: 'external', label: 'External' }, { value: 'internet', label: 'Internet' }, { value: 'dmz', label: 'DMZ' }, { value: 'internal', label: 'Internal' }, { value: 'cloud', label: 'Cloud' }, { value: 'ot', label: 'OT' }] },
  // Exposure & role
  { key: 'is_internet_facing', label: 'Internet Facing', type: 'toggle' },
  { key: 'is_domain_controller', label: 'Is Domain Controller', type: 'toggle' },
  { key: 'is_database_server', label: 'Is Database Server', type: 'toggle' },
  { key: 'is_web_server', label: 'Is Web Server', type: 'toggle' },
  { key: 'is_dns_server', label: 'Is DNS Server', type: 'toggle' },
  { key: 'is_mail_server', label: 'Is Mail Server', type: 'toggle' },
  // Severity counts
  { key: 'min_critical', label: 'Critical Findings ≥', type: 'number', placeholder: 'e.g. 1' },
  { key: 'min_high', label: 'High Findings ≥', type: 'number', placeholder: 'e.g. 1' },
  { key: 'min_medium', label: 'Medium Findings ≥', type: 'number', placeholder: 'e.g. 5' },
  { key: 'has_findings', label: 'Has Any Findings', type: 'toggle' },
  // Finding-based
  { key: 'has_critical_cves', label: 'Has Critical CVEs', type: 'toggle' },
  { key: 'has_kev_findings', label: 'Has KEV Findings', type: 'toggle' },
  { key: 'has_exploitable', label: 'Has Exploitable Vulns', type: 'toggle' },
  { key: 'has_ransomware_findings', label: 'Has Ransomware-Linked Findings', type: 'toggle' },
  // Identity & access
  { key: 'has_domain_admin_logged_on', label: 'Domain Admin Logged In', type: 'toggle' },
  { key: 'has_privileged_user', label: 'Privileged User Logged In', type: 'toggle' },
  { key: 'has_kerberoastable', label: 'Kerberoastable User Present', type: 'toggle' },
  { key: 'has_writeable_share', label: 'Has Writeable Share', type: 'toggle' },
  // Security controls
  { key: 'lacks_security_controls', label: 'No Security Controls', type: 'toggle' },
  { key: 'lacks_av', label: 'No Antivirus', type: 'toggle' },
  { key: 'lacks_edr', label: 'No EDR', type: 'toggle' },
  { key: 'lacks_firewall', label: 'No Firewall', type: 'toggle' },
  { key: 'search', label: 'Keyword', type: 'text', placeholder: 'Hostname, IP...' },
]

function FunnelConfigPanel({ cfg, set, Field, Select, TextInput }) {
  const { t } = useTranslation()
  const steps = cfg.steps || []
  const baseEntity = cfg.base_entity || 'findings'
  const filterDefs = baseEntity === 'assets' ? FUNNEL_ASSET_FILTERS : FUNNEL_FINDING_FILTERS

  const setSteps = (newSteps) => set('steps', newSteps)
  const updateStep = (idx, updates) => {
    const copy = steps.map((s, i) => i === idx ? { ...s, ...updates } : s)
    setSteps(copy)
  }
  const removeStep = (idx) => setSteps(steps.filter((_, i) => i !== idx))
  const addStep = () => setSteps([...steps, { label: `Step ${steps.length + 1}`, filters: {} }])
  const moveStep = (idx, dir) => {
    const copy = [...steps]
    const target = idx + dir
    if (target < 0 || target >= copy.length) return
    ;[copy[idx], copy[target]] = [copy[target], copy[idx]]
    setSteps(copy)
  }

  const inputStyle = { width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, boxSizing: 'border-box' }

  return (
    <>
      <div style={{ height: 1, background: 'var(--border)', margin: '10px 0 14px' }} />
      <Field label={t('reports.funnel.baseEntity')}>
        <Select value={baseEntity} onChange={v => set('base_entity', v)} options={[
          { value: 'findings', label: 'Findings' },
          { value: 'assets', label: 'Assets' },
        ]} />
      </Field>

      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>
        {t('reports.funnel.steps')} ({steps.length})
      </div>

      {steps.map((step, i) => (
        <div key={i} style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8, padding: 10, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', minWidth: 16 }}>{i + 1}.</span>
            <input value={step.label || ''} onChange={e => updateStep(i, { label: e.target.value })}
              placeholder={t('reports.funnel.stepLabel')} style={{ ...inputStyle, flex: 1, padding: '5px 8px', fontSize: 12 }} />
            <button onClick={() => moveStep(i, -1)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }} title={t('reports.funnel.moveUp')}><ChevronUp size={12} /></button>
            <button onClick={() => moveStep(i, 1)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }} title={t('reports.funnel.moveDown')}><ChevronDown size={12} /></button>
            <button onClick={() => removeStep(i)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626', padding: 2 }} title={t('reports.funnel.remove')}><X size={12} /></button>
          </div>
          <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>{t('reports.funnel.addFilter')}</div>
          <select
            value=""
            onChange={e => {
              const key = e.target.value
              if (!key) return
              const def = filterDefs.find(f => f.key === key)
              const defaultVal = def?.type === 'toggle' ? 'true' : ''
              updateStep(i, { filters: { ...step.filters, [key]: defaultVal } })
            }}
            style={{ ...inputStyle, fontSize: 11, marginBottom: 6 }}
          >
            <option value="">{t('reports.funnel.addFilterOption')}</option>
            {filterDefs.filter(fd => !(fd.key in (step.filters || {}))).map(fd => (
              <option key={fd.key} value={fd.key}>{fd.label}</option>
            ))}
          </select>
          {Object.entries(step.filters || {}).map(([fKey, fVal]) => {
            const def = filterDefs.find(f => f.key === fKey)
            if (!def) return null
            return (
              <div key={fKey} style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)', minWidth: 80, flexShrink: 0 }}>{def.label}</span>
                {def.type === 'toggle' ? (
                  <span style={{ fontSize: 11, color: '#16a34a', fontWeight: 600 }}>Yes</span>
                ) : def.type === 'select' ? (
                  <select value={fVal || ''} onChange={e => updateStep(i, { filters: { ...step.filters, [fKey]: e.target.value } })}
                    style={{ ...inputStyle, flex: 1, padding: '4px 6px', fontSize: 11 }}>
                    {def.options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                ) : (
                  <input value={fVal || ''} onChange={e => updateStep(i, { filters: { ...step.filters, [fKey]: e.target.value } })}
                    placeholder={def.placeholder} type={def.type === 'number' ? 'number' : 'text'}
                    style={{ ...inputStyle, flex: 1, padding: '4px 6px', fontSize: 11 }} />
                )}
                <button onClick={() => {
                  const { [fKey]: _, ...rest } = step.filters
                  updateStep(i, { filters: rest })
                }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626', padding: 2 }}><X size={10} /></button>
              </div>
            )
          })}
        </div>
      ))}

      <button onClick={addStep} style={{
        width: '100%', background: 'var(--bg-primary)', border: '1px dashed var(--border)',
        borderRadius: 8, padding: '8px 0', fontSize: 12, color: 'var(--accent)',
        cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
      }}>
        <Plus size={12} /> {t('reports.funnel.addStep')}
      </button>
    </>
  )
}

// ─── Widget config panel ──────────────────────────────────────────────────────

const CfgField = ({ label, children }) => (
  <div style={{ marginBottom: 14 }}>
    <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>{label}</div>
    {children}
  </div>
)
const CfgSelect = ({ value, onChange, options }) => (
  <select value={value || ''} onChange={e => onChange(e.target.value)}
    style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
    {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
  </select>
)
const CfgTextInput = ({ value, onChange, placeholder }) => (
  <input value={value || ''} onChange={e => onChange(e.target.value)} placeholder={placeholder}
    style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, boxSizing: 'border-box' }} />
)
const CfgToggle = ({ checked, onChange, label }) => (
  <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
    <input type="checkbox" checked={!!checked} onChange={e => onChange(e.target.checked)} />
    {label}
  </label>
)

function ConfigPanel({ widget, onUpdate, onClose }) {
  const { t } = useTranslation()
  const cfg = widget.config || {}
  const set = (key, val) => onUpdate({ ...widget, config: { ...cfg, [key]: val } })
  const setTitle = (t) => onUpdate({ ...widget, title: t })
  const setWidth = (w) => onUpdate({ ...widget, width: w })

  const Field = CfgField
  const Select = CfgSelect
  const TextInput = CfgTextInput
  const Toggle = CfgToggle

  // Determine if this is a series-type (time series) chart
  const isSeriesChart = widget.type === 'line_chart' || (widget.type === 'bar_chart' && (cfg.preset === 'custom_series' || DATA_PRESETS[cfg.preset]?.type === 'series'))
  const isCustomSeries = cfg.preset === 'custom_series'

  const presetType = widget.type === 'card' ? 'metric'
    : widget.type === 'pie_chart' ? 'categories'
    : widget.type === 'bar_chart' ? null // categories or series
    : widget.type === 'line_chart' ? 'series'
    : widget.type === 'table' ? 'table'
    : widget.type === 'risk_grade' ? 'grade'
    : widget.type === 'radar' ? 'radar'
    : widget.type === 'gauge' ? 'gauge'
    : widget.type === 'treemap' ? 'treemap'
    : null

  const compatiblePresets = presetType
    ? Object.entries(DATA_PRESETS).filter(([, p]) => p.type === presetType && !p.dynamic)
    : widget.type === 'bar_chart'
      ? Object.entries(DATA_PRESETS).filter(([, p]) => (p.type === 'categories' || p.type === 'series') && !p.dynamic)
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

  const isDataWidget = ['card', 'pie_chart', 'bar_chart', 'line_chart', 'table', 'risk_grade', 'radar', 'gauge', 'treemap'].includes(widget.type)

  // For line/bar charts: determine if user wants custom time-series or a fixed preset
  const showSeriesBuilder = (widget.type === 'line_chart' || widget.type === 'bar_chart') && isCustomSeries

  return (
    <div style={{ width: 260, flexShrink: 0, background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Settings2 size={14} color="var(--accent)" /> {t('reports.widgetConfig')}
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <X size={14} />
        </button>
      </div>

      <Field label={t('reports.widgetTitle')}>
        <TextInput value={widget.title} onChange={setTitle} placeholder={t('reports.widgetTitlePlaceholder')} />
      </Field>
      <Field label={t('reports.width')}>
        <Select value={widget.width} onChange={setWidth} options={[
          { value: 'quarter', label: t('reports.widthOptions.quarter') },
          { value: 'third', label: t('reports.widthOptions.third') },
          { value: 'half', label: t('reports.widthOptions.half') },
          { value: 'two-thirds', label: t('reports.widthOptions.twoThirds') },
          { value: 'full', label: t('reports.widthOptions.full') },
        ]} />
      </Field>

      {/* For line_chart and bar_chart: show mode selector (Custom Time Series vs preset) */}
      {(widget.type === 'line_chart' || widget.type === 'bar_chart') && (
        <Field label={t('reports.dataSource')}>
          <select
            value={isCustomSeries ? 'custom_series' : 'preset'}
            onChange={e => {
              if (e.target.value === 'custom_series') {
                set('preset', 'custom_series')
              } else {
                // Switch back to first compatible preset
                const first = compatiblePresets[0]
                if (first) set('preset', first[0])
              }
            }}
            style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}
          >
            <option value="custom_series">{t('reports.customTimeSeries')}</option>
            <option value="preset">{t('reports.fixedPreset')}</option>
          </select>
        </Field>
      )}

      {/* Fixed preset dropdown — shown for non-chart widgets, or chart widgets in preset mode */}
      {isDataWidget && presetOptions.length > 0 && !showSeriesBuilder && !(widget.type === 'line_chart' && isCustomSeries) && (
        <Field label={t('reports.dataPreset')}>
          <select value={cfg.preset || ''} onChange={e => set('preset', e.target.value)}
            style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            {presetOptions.map(o => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
          </select>
        </Field>
      )}

      {/* ── Custom Time Series: X / Y axis selectors ── */}
      {showSeriesBuilder && (
        <>
          <Field label={t('reports.xAxis')}>
            <Select value={cfg.time_group || 'scan'} onChange={v => set('time_group', v)} options={TIME_GROUP_OPTIONS} />
          </Field>

          <Field label={t('reports.yAxis')}>
            <select
              value=""
              onChange={e => {
                if (!e.target.value) return
                const current = cfg.metrics || []
                if (!current.includes(e.target.value)) set('metrics', [...current, e.target.value])
              }}
              style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}
            >
              <option value="">{t('reports.addMetric')}</option>
              {SERIES_METRIC_GROUPS.map(group => (
                <optgroup key={group} label={group}>
                  {SERIES_METRICS.filter(m => m.group === group && !(cfg.metrics || []).includes(m.id)).map(m => (
                    <option key={m.id} value={m.id}>{m.label}</option>
                  ))}
                </optgroup>
              ))}
            </select>
          </Field>

          {(cfg.metrics || []).length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
              {(cfg.metrics || []).map(id => {
                const m = SERIES_METRIC_MAP[id]
                if (!m) return null
                return (
                  <span key={id} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 8px',
                    background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11,
                  }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: m.color, flexShrink: 0 }} />
                    <span style={{ color: 'var(--text-primary)' }}>{m.label}</span>
                    <button
                      onClick={() => set('metrics', (cfg.metrics || []).filter(x => x !== id))}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0, lineHeight: 1, fontSize: 13 }}
                    >&times;</button>
                  </span>
                )
              })}
            </div>
          )}
        </>
      )}

      {widget.type === 'card' && (
        <Field label={t('reports.displayLabel')}>
          <TextInput value={cfg.label} onChange={v => set('label', v)} placeholder={DATA_PRESETS[cfg.preset]?.label || 'Label'} />
        </Field>
      )}

      {widget.type === 'pie_chart' && (
        <Field label={t('reports.donut')}>
          <Toggle checked={cfg.donut} onChange={v => set('donut', v)} label={t('reports.donutHole')} />
        </Field>
      )}

      {widget.type === 'bar_chart' && (
        <>
          <Field label={t('reports.horizontal')}>
            <Toggle checked={cfg.horizontal} onChange={v => set('horizontal', v)} label={t('reports.horizontalLayout')} />
          </Field>
          {isSeriesChart && (
            <Field label={t('reports.stacked')}>
              <Toggle checked={cfg.stacked} onChange={v => set('stacked', v)} label={t('reports.stackBars')} />
            </Field>
          )}
        </>
      )}

      {widget.type === 'line_chart' && (
        <Field label={t('reports.areaFill')}>
          <Toggle checked={cfg.areaFill} onChange={v => set('areaFill', v)} label={t('reports.fillArea')} />
        </Field>
      )}

      {widget.type === 'table' && (
        <Field label={t('reports.rowLimit')}>
          <Select value={String(cfg.limit || 10)} onChange={v => set('limit', v)}
            options={[{ value: '5', label: `5 ${t('reports.rows')}` }, { value: '10', label: `10 ${t('reports.rows')}` }, { value: '20', label: `20 ${t('reports.rows')}` }, { value: '50', label: `50 ${t('reports.rows')}` }]} />
        </Field>
      )}

      {widget.type === 'header' && (
        <>
          <Field label={t('reports.sectionTitle')}>
            <TextInput value={cfg.title} onChange={v => set('title', v)} placeholder={t('reports.sectionTitle')} />
          </Field>
          <Field label={t('reports.subtitle2')}>
            <TextInput value={cfg.subtitle} onChange={v => set('subtitle', v)} placeholder={t('reports.optionalSubtitle')} />
          </Field>
        </>
      )}

      {widget.type === 'image' && (
        <Field label={t('reports.imageUrl')}>
          <TextInput value={cfg.url} onChange={v => set('url', v)} placeholder="https://..." />
        </Field>
      )}

      {widget.type === 'funnel' && <FunnelConfigPanel cfg={cfg} set={set} Field={Field} Select={Select} TextInput={TextInput} />}

      {/* Improvement tips toggle — only for risk_grade widgets */}
      {widget.type === 'risk_grade' && (
        <>
          <div style={{ height: 1, background: 'var(--border)', margin: '10px 0 14px' }} />
          <Field label="Improvement Tips">
            <Toggle checked={cfg.show_tips} onChange={v => set('show_tips', v)} label="Show how to improve each component" />
          </Field>
        </>
      )}

      {/* Benchmark overlay toggle — available when a benchmark mapping exists for this preset */}
      {PRESET_TO_BENCHMARK[cfg.preset] && ['card', 'gauge', 'risk_grade'].includes(widget.type) && (
        <>
          <div style={{ height: 1, background: 'var(--border)', margin: '10px 0 14px' }} />
          <Field label="Benchmark">
            <Toggle checked={cfg.show_benchmark} onChange={v => set('show_benchmark', v)} label="Compare vs peers" />
          </Field>
          {cfg.show_benchmark && (
            <>
              <Field label="Source">
                <Select value={cfg.filters?.benchmark_source || ''} onChange={v => set('filters', { ...(cfg.filters || {}), benchmark_source: v || undefined })} options={[
                  { value: '', label: 'Auto (platform if available)' },
                  { value: 'platform', label: 'Platform peers' },
                  { value: 'industry', label: 'Industry reference' },
                ]} />
              </Field>
              {(cfg.filters?.benchmark_source || '') !== 'platform' && (
                <Field label="Industry">
                  <Select value={cfg.filters?.benchmark_industry || ''} onChange={v => set('filters', { ...(cfg.filters || {}), benchmark_industry: v || undefined })} options={[
                    { value: '', label: 'All Industries' },
                    { value: 'financial', label: 'Financial' },
                    { value: 'healthcare', label: 'Healthcare' },
                    { value: 'technology', label: 'Technology' },
                    { value: 'government', label: 'Government' },
                  ]} />
                </Field>
              )}
            </>
          )}
        </>
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
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>{t('common.filters')}</div>
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
  const { t } = useTranslation()
  return (
    <div style={{ width: 220, flexShrink: 0, background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)', overflowY: 'auto', padding: '12px 0' }}>
      <div style={{ padding: '0 14px 10px', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{t('reports.widgetLibrary')}</div>
      {WIDGET_CATALOGUE.map(cat => (
        <div key={cat.category}>
          <div style={{ padding: '8px 14px 6px', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', opacity: 0.6 }}>{t(`reports.${cat.category.toLowerCase()}`)}</div>
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

function CanvasWidget({ widget, index, total, scanId, isSelected, onSelect, onUpdate, onDelete, onMoveUp, onMoveDown, preview, globalTags, globalTagLogic }) {
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
        <WidgetRenderer widget={widget} scanId={scanId} preview={preview} globalTags={globalTags} globalTagLogic={globalTagLogic} />
      </div>
    </div>
  )
}

// ─── Export helpers ───────────────────────────────────────────────────────────

// Hakuna logo as inline SVG data URL
const HAKUNA_LOGO_SVG = `<svg width="120" height="30" viewBox="0 0 120 30" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20.8261 2.94922L18.1513 13.1034H20.6441V17.2414H17.0615L15.2401 24.1568C14.3323 27.6033 11.2616 30 7.7539 30C2.65812 29.9999 -1.05054 25.0831 0.268355 20.0761L0.455063 19.3649C1.42801 15.6715 4.71864 13.1035 8.47756 13.1034H13.9404L16.8973 1.87837L20.8261 2.94922ZM36.2455 0C41.3413 0 45.0506 4.9169 43.7317 9.9239L43.5443 10.6351C42.5713 14.3283 39.2813 16.8964 35.5225 16.8966H30.0596L27.1027 28.1216L23.1732 27.0508L25.8481 16.8966H23.356V12.7586H26.9379L28.7599 5.84321C29.6678 2.39676 32.7379 0.000139001 36.2455 0ZM8.47756 17.2414C6.55972 17.2414 4.88092 18.552 4.38455 20.4364L4.19718 21.147C3.57055 23.5258 5.33285 25.862 7.7539 25.8621C9.42045 25.8621 10.8793 24.7234 11.3106 23.0859L12.8506 17.2414H8.47756ZM36.2455 4.13793C34.5791 4.13807 33.1207 5.27671 32.6894 6.91406L31.1494 12.7586H35.5225C37.4402 12.7585 39.1191 11.4479 39.6155 9.56358L39.8022 8.85304C40.4288 6.47413 38.6666 4.13793 36.2455 4.13793Z" fill="#590202"/><path d="M112.264 24.3C111.484 24.3 110.824 24.1533 110.284 23.86C109.744 23.56 109.334 23.1633 109.054 22.67C108.78 22.1767 108.644 21.6333 108.644 21.04C108.644 20.52 108.73 20.0533 108.904 19.64C109.077 19.22 109.344 18.86 109.704 18.56C110.064 18.2533 110.53 18.0033 111.104 17.81C111.537 17.67 112.044 17.5433 112.624 17.43C113.21 17.3167 113.844 17.2133 114.524 17.12C115.21 17.02 115.927 16.9133 116.674 16.8L115.814 17.29C115.82 16.5433 115.654 15.9933 115.314 15.64C114.974 15.2867 114.4 15.11 113.594 15.11C113.107 15.11 112.637 15.2233 112.184 15.45C111.73 15.6767 111.414 16.0667 111.234 16.62L109.034 15.93C109.3 15.0167 109.807 14.2833 110.554 13.73C111.307 13.1767 112.32 12.9 113.594 12.9C114.554 12.9 115.397 13.0567 116.124 13.37C116.857 13.6833 117.4 14.1967 117.754 14.91C117.947 15.29 118.064 15.68 118.104 16.08C118.144 16.4733 118.164 16.9033 118.164 17.37V24H116.054V21.66L116.404 22.04C115.917 22.82 115.347 23.3933 114.694 23.76C114.047 24.12 113.237 24.3 112.264 24.3ZM112.744 22.38C113.29 22.38 113.757 22.2833 114.144 22.09C114.53 21.8967 114.837 21.66 115.064 21.38C115.297 21.1 115.454 20.8367 115.534 20.59C115.66 20.2833 115.73 19.9333 115.744 19.54C115.764 19.14 115.774 18.8167 115.774 18.57L116.514 18.79C115.787 18.9033 115.164 19.0033 114.644 19.09C114.124 19.1767 113.677 19.26 113.304 19.34C112.93 19.4133 112.6 19.4967 112.314 19.59C112.034 19.69 111.797 19.8067 111.604 19.94C111.41 20.0733 111.26 20.2267 111.154 20.4C111.054 20.5733 111.004 20.7767 111.004 21.01C111.004 21.2767 111.07 21.5133 111.204 21.72C111.337 21.92 111.53 22.08 111.784 22.2C112.044 22.32 112.364 22.38 112.744 22.38Z" fill="#590202"/><path d="M104.194 24V18.8C104.194 18.46 104.171 18.0833 104.124 17.67C104.077 17.2567 103.967 16.86 103.794 16.48C103.627 16.0933 103.374 15.7767 103.034 15.53C102.701 15.2833 102.247 15.16 101.674 15.16C101.367 15.16 101.064 15.21 100.764 15.31C100.464 15.41 100.191 15.5833 99.9441 15.83C99.7041 16.07 99.5108 16.4033 99.3641 16.83C99.2174 17.25 99.1441 17.79 99.1441 18.45L97.7141 17.84C97.7141 16.92 97.8908 16.0867 98.2441 15.34C98.6041 14.5933 99.1308 14 99.8241 13.56C100.517 13.1133 101.371 12.89 102.384 12.89C103.184 12.89 103.844 13.0233 104.364 13.29C104.884 13.5567 105.297 13.8967 105.604 14.31C105.911 14.7233 106.137 15.1633 106.284 15.63C106.431 16.0967 106.524 16.54 106.564 16.96C106.611 17.3733 106.634 17.71 106.634 17.97V24H104.194ZM96.7041 24V13.2H98.8541V16.55H99.1441V24H96.7041Z" fill="#590202"/><path d="M88.2546 24.31C87.4546 24.31 86.7946 24.1767 86.2746 23.91C85.7546 23.6433 85.3413 23.3033 85.0346 22.89C84.728 22.4767 84.5013 22.0367 84.3546 21.57C84.208 21.1033 84.1113 20.6633 84.0646 20.25C84.0246 19.83 84.0046 19.49 84.0046 19.23V13.2H86.4446V18.4C86.4446 18.7333 86.468 19.11 86.5146 19.53C86.5613 19.9433 86.668 20.3433 86.8346 20.73C87.008 21.11 87.2613 21.4233 87.5946 21.67C87.9346 21.9167 88.3913 22.04 88.9646 22.04C89.2713 22.04 89.5746 21.99 89.8746 21.89C90.1746 21.79 90.4446 21.62 90.6846 21.38C90.9313 21.1333 91.128 20.7967 91.2746 20.37C91.4213 19.9433 91.4946 19.4033 91.4946 18.75L92.9246 19.36C92.9246 20.28 92.7446 21.1133 92.3846 21.86C92.0313 22.6067 91.508 23.2033 90.8146 23.65C90.1213 24.09 89.268 24.31 88.2546 24.31ZM91.7846 24V20.65H91.4946V13.2H93.9146V24H91.7846Z" fill="#590202"/><path d="M73.4229 24L73.4429 9.6H75.8829V18.4L79.8329 13.2H82.8428L78.6529 18.6L83.2029 24H80.0129L75.8829 18.8V24H73.4229Z" fill="#590202"/><path d="M64.9396 24.3C64.1596 24.3 63.4996 24.1533 62.9596 23.86C62.4196 23.56 62.0096 23.1633 61.7296 22.67C61.4562 22.1767 61.3196 21.6333 61.3196 21.04C61.3196 20.52 61.4062 20.0533 61.5796 19.64C61.7529 19.22 62.0196 18.86 62.3796 18.56C62.7396 18.2533 63.2062 18.0033 63.7796 17.81C64.2129 17.67 64.7196 17.5433 65.2996 17.43C65.8862 17.3167 66.5196 17.2133 67.1996 17.12C67.8862 17.02 68.6029 16.9133 69.3496 16.8L68.4896 17.29C68.4962 16.5433 68.3296 15.9933 67.9896 15.64C67.6496 15.2867 67.0762 15.11 66.2696 15.11C65.7829 15.11 65.3129 15.2233 64.8596 15.45C64.4062 15.6767 64.0896 16.0667 63.9096 16.62L61.7096 15.93C61.9762 15.0167 62.4829 14.2833 63.2296 13.73C63.9829 13.1767 64.9962 12.9 66.2696 12.9C67.2296 12.9 68.0729 13.0567 68.7996 13.37C69.5329 13.6833 70.0762 14.1967 70.4296 14.91C70.6229 15.29 70.7396 15.68 70.7796 16.08C70.8196 16.4733 70.8396 16.9033 70.8396 17.37V24H68.7296V21.66L69.0796 22.04C68.5929 22.82 68.0229 23.3933 67.3696 23.76C66.7229 24.12 65.9129 24.3 64.9396 24.3ZM65.4196 22.38C65.9662 22.38 66.4329 22.2833 66.8196 22.09C67.2062 21.8967 67.5129 21.66 67.7396 21.38C67.9729 21.1 68.1296 20.8367 68.2096 20.59C68.3362 20.2833 68.4062 19.9333 68.4196 19.54C68.4396 19.14 68.4496 18.8167 68.4496 18.57L69.1896 18.79C68.4629 18.9033 67.8396 19.0033 67.3196 19.09C66.7996 19.1767 66.3529 19.26 65.9796 19.34C65.6062 19.4133 65.2762 19.4967 64.9896 19.59C64.7096 19.69 64.4729 19.8067 64.2796 19.94C64.0862 20.0733 63.9362 20.2267 63.8296 20.4C63.7296 20.5733 63.6796 20.7767 63.6796 21.01C63.6796 21.2767 63.7462 21.5133 63.8796 21.72C64.0129 21.92 64.2062 22.08 64.4596 22.2C64.7196 22.32 65.0396 22.38 65.4196 22.38Z" fill="#590202"/><path d="M56.8699 24V18.8C56.8699 18.46 56.8465 18.0833 56.7999 17.67C56.7532 17.2567 56.6432 16.86 56.4699 16.48C56.3032 16.0933 56.0499 15.7767 55.7099 15.53C55.3765 15.2833 54.9232 15.16 54.3499 15.16C54.0432 15.16 53.7399 15.21 53.4399 15.31C53.1399 15.41 52.8665 15.5833 52.6199 15.83C52.3799 16.07 52.1865 16.4033 52.0399 16.83C51.8932 17.25 51.8199 17.79 51.8199 18.45L50.3899 17.84C50.3899 16.92 50.5665 16.0867 50.9199 15.34C51.2799 14.5933 51.8065 14 52.4999 13.56C53.1932 13.1133 54.0465 12.89 55.0599 12.89C55.8599 12.89 56.5199 13.0233 57.0399 13.29C57.5599 13.5567 57.9732 13.8967 58.2799 14.31C58.5865 14.7233 58.8132 15.1633 58.9599 15.63C59.1066 16.0967 59.1999 16.54 59.2399 16.96C59.2865 17.3733 59.3099 17.71 59.3099 17.97V24H56.8699ZM49.3799 24V9.6H51.5299V17.18H51.8199V24H49.3799Z" fill="#590202"/></svg>`

const HAKUNA_LOGO_DATA_URL = `data:image/svg+xml;base64,${btoa(HAKUNA_LOGO_SVG)}`
const CURRENT_YEAR = new Date().getFullYear()
const EXPORT_FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'

// Load the logo as an Image element (returns a Promise<HTMLImageElement>)
function loadLogoImage() {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => resolve(img)
    img.onerror = () => resolve(null)
    img.src = HAKUNA_LOGO_DATA_URL
  })
}

/**
 * Captures the live canvas element with html2canvas, then composites
 * a light-themed branded header + footer around it on a new <canvas>.
 * This approach avoids DOM cloning so CSS variables resolve correctly.
 */
async function buildBrandedCanvas(ref, reportName) {
  const html2canvas = (await import('html2canvas')).default
  const S = 2  // retina scale

  // 1. Capture the live dashboard (preserves dark theme & CSS vars)
  const dashCanvas = await html2canvas(ref, {
    backgroundColor: '#0d1117',
    scale: S,
    useCORS: true,
    logging: false,
  })

  const [logoImg, dateStr, year] = [
    await loadLogoImage(),
    new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
    new Date().getFullYear(),
  ]

  // Layout constants (all in physical px at scale S)
  const W        = dashCanvas.width
  const HEADER_H = 72 * S
  const PAD_V    = 16 * S   // vertical padding around dashboard
  const FOOTER_H = 36 * S
  const TOTAL_H  = HEADER_H + PAD_V + dashCanvas.height + PAD_V + FOOTER_H

  const out = document.createElement('canvas')
  out.width  = W
  out.height = TOTAL_H
  const ctx  = out.getContext('2d')

  // ── Background ────────────────────────────────────────────────────────────
  ctx.fillStyle = '#f1f5f9'
  ctx.fillRect(0, 0, W, TOTAL_H)

  // ── Header ────────────────────────────────────────────────────────────────
  ctx.fillStyle = '#ffffff'
  ctx.fillRect(0, 0, W, HEADER_H)

  // Red top accent bar
  ctx.fillStyle = '#590202'
  ctx.fillRect(0, 0, W, 4 * S)

  // Header bottom border
  ctx.fillStyle = '#e2e8f0'
  ctx.fillRect(0, HEADER_H - S, W, S)

  // Logo
  if (logoImg) {
    const LOGO_H = 28 * S
    const LOGO_W = (120 / 30) * LOGO_H  // preserve aspect ratio
    ctx.drawImage(logoImg, 20 * S, (HEADER_H - LOGO_H) / 2, LOGO_W, LOGO_H)
  }

  // Report name
  ctx.fillStyle = '#0f172a'
  ctx.font = `bold ${15 * S}px ${EXPORT_FONT}`
  ctx.textAlign = 'right'
  ctx.textBaseline = 'middle'
  ctx.fillText(reportName || 'Security Report', W - 20 * S, HEADER_H / 2 - 9 * S)

  // Date subtitle
  ctx.fillStyle = '#64748b'
  ctx.font = `${11 * S}px ${EXPORT_FONT}`
  ctx.fillText(`Generated ${dateStr}`, W - 20 * S, HEADER_H / 2 + 9 * S)

  // ── Dashboard screenshot ──────────────────────────────────────────────────
  // Subtle shadow / inset border around the screenshot
  ctx.shadowColor = 'rgba(0,0,0,0.18)'
  ctx.shadowBlur = 8 * S
  ctx.shadowOffsetY = 2 * S
  ctx.drawImage(dashCanvas, 0, HEADER_H + PAD_V)
  ctx.shadowColor = 'transparent'
  ctx.shadowBlur = 0
  ctx.shadowOffsetY = 0

  // ── Footer ────────────────────────────────────────────────────────────────
  const footerY = HEADER_H + PAD_V + dashCanvas.height + PAD_V
  ctx.fillStyle = '#ffffff'
  ctx.fillRect(0, footerY, W, FOOTER_H)

  ctx.fillStyle = '#e2e8f0'
  ctx.fillRect(0, footerY, W, S)

  const footerMidY = footerY + FOOTER_H / 2

  ctx.fillStyle = '#94a3b8'
  ctx.font = `${10 * S}px ${EXPORT_FONT}`
  ctx.textAlign = 'left'
  ctx.textBaseline = 'middle'
  ctx.fillText(`© ${year} Hakuna Security Platform. All rights reserved.`, 20 * S, footerMidY)

  ctx.textAlign = 'right'
  ctx.font = `italic ${10 * S}px ${EXPORT_FONT}`
  ctx.fillText('CONFIDENTIAL — For authorized recipients only', W - 20 * S, footerMidY)

  return out
}

async function exportAsPNG(ref, name) {
  const canvas = await buildBrandedCanvas(ref, name)
  const link = document.createElement('a')
  link.download = `${name || 'report'}.png`
  link.href = canvas.toDataURL('image/png')
  link.click()
}

async function exportAsPDF(ref, name) {
  const canvas = await buildBrandedCanvas(ref, name)
  const { jsPDF } = await import('jspdf')
  const imgData = canvas.toDataURL('image/png')
  const pdfW = 297   // A4 landscape width mm
  const pdfH = Math.round((canvas.height / canvas.width) * pdfW)
  const pageH = 210  // A4 landscape height mm
  const pdf = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' })
  let yOffset = 0
  while (yOffset < pdfH) {
    if (yOffset > 0) pdf.addPage()
    pdf.addImage(imgData, 'PNG', 0, -yOffset, pdfW, pdfH)
    yOffset += pageH
  }
  pdf.save(`${name || 'report'}.pdf`)
}

async function exportAsPPT(ref, name) {
  const PptxGenJS = (await import('pptxgenjs')).default
  const [dashRaw, logoImg, dateStr] = await Promise.all([
    (async () => {
      const html2canvas = (await import('html2canvas')).default
      return html2canvas(ref, { backgroundColor: '#0d1117', scale: 2, useCORS: true, logging: false })
    })(),
    loadLogoImage(),
    Promise.resolve(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })),
  ])
  const dashImg = dashRaw.toDataURL('image/png')

  const pptx = new PptxGenJS()
  pptx.defineLayout({ name: 'WIDE', width: 13.33, height: 7.5 })
  pptx.layout = 'WIDE'

  // ── Slide ─────────────────────────────────────────────────────────────────
  const slide = pptx.addSlide()
  slide.background = { color: 'f1f5f9' }   // light background

  // Top red accent bar
  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0, w: 13.33, h: 0.06,
    fill: { color: '590202' }, line: { color: '590202' },
  })

  // White header band
  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0.06, w: 13.33, h: 0.82,
    fill: { color: 'ffffff' }, line: { color: 'e2e8f0', pt: 0.5 },
  })

  // Logo
  slide.addImage({ data: HAKUNA_LOGO_DATA_URL, x: 0.22, y: 0.13, w: 1.5, h: 0.38 })

  // Report title + date (right side of header)
  slide.addText(name || 'Security Report', {
    x: 5.5, y: 0.1, w: 7.6, h: 0.36,
    fontSize: 15, bold: true, color: '0f172a', align: 'right',
  })
  slide.addText(`Generated ${dateStr}`, {
    x: 5.5, y: 0.46, w: 7.6, h: 0.24,
    fontSize: 9, color: '64748b', align: 'right',
  })

  // Dashboard screenshot (fills remaining space)
  const dashAspect = dashRaw.height / dashRaw.width
  const imgX = 0.15
  const imgW = 13.33 - imgX * 2
  const imgH = Math.min(imgW * dashAspect, 5.9)
  const imgY = 0.06 + 0.82 + 0.08   // below header + small gap
  slide.addImage({ data: dashImg, x: imgX, y: imgY, w: imgW, h: imgH })

  // White footer band
  const footerY = 7.5 - 0.36
  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: footerY, w: 13.33, h: 0.36,
    fill: { color: 'ffffff' }, line: { color: 'e2e8f0', pt: 0.5 },
  })
  slide.addText(`© ${CURRENT_YEAR} Hakuna Security Platform. All rights reserved.`, {
    x: 0.22, y: footerY + 0.08, w: 7, h: 0.2,
    fontSize: 7.5, color: '94a3b8',
  })
  slide.addText('CONFIDENTIAL — For authorized recipients only', {
    x: 6.5, y: footerY + 0.08, w: 6.6, h: 0.2,
    fontSize: 7.5, color: '94a3b8', align: 'right', italic: true,
  })

  await pptx.writeFile({ fileName: `${name || 'report'}.pptx` })
}

// ─── Export dropdown button ───────────────────────────────────────────────────

function ExportDropdown({ canvasRef, reportName, disabled }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [exporting, setExporting] = useState(null)
  const ref = useRef()

  useEffect(() => {
    if (!open) return
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const run = async (format) => {
    setOpen(false)
    setExporting(format)
    try {
      if (format === 'png') await exportAsPNG(canvasRef.current, reportName)
      else if (format === 'pdf') await exportAsPDF(canvasRef.current, reportName)
      else if (format === 'ppt') await exportAsPPT(canvasRef.current, reportName)
    } catch (e) {
      console.error('Export failed', e)
      alert(t('reports.exportFailed') + ': ' + e.message)
    } finally {
      setExporting(null)
    }
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <button
        onClick={() => setOpen(o => !o)}
        disabled={!!exporting || disabled}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px',
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--text-secondary)', borderRadius: 6, cursor: exporting || disabled ? 'not-allowed' : 'pointer',
          fontSize: 13, fontWeight: 500, opacity: exporting || disabled ? 0.6 : 1,
        }}
      >
        {exporting
          ? <span style={{ width: 14, height: 14, border: '2px solid var(--border)', borderTopColor: 'var(--text-secondary)', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />
          : <Download size={14} />}
        {exporting ? t('reports.exporting', { format: exporting.toUpperCase() }) : t('common.export')}
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 100,
          background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
          minWidth: 160, padding: 4, boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
        }}>
          {[
            { fmt: 'png', icon: FileImage, label: t('reports.exportAsPng') },
            { fmt: 'pdf', icon: FileText, label: t('reports.exportAsPdf') },
            { fmt: 'ppt', icon: FileBarChart2, label: t('reports.exportAsPpt') },
          ].map(({ fmt, icon: Icon, label }) => (
            <button
              key={fmt}
              onClick={() => run(fmt)}
              style={{
                display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 12px',
                background: 'none', border: 'none', color: 'var(--text-primary)', cursor: 'pointer',
                fontSize: 13, borderRadius: 6, textAlign: 'left',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
            >
              <Icon size={15} color="var(--text-muted)" /> {label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Global tag filter bar ────────────────────────────────────────────────────

function GlobalTagFilterBar({ globalTags, setGlobalTags, globalTagLogic, setGlobalTagLogic, tagInputDraft, setTagInputDraft, availableTags }) {
  const { t } = useTranslation()
  const [showSuggestions, setShowSuggestions] = useState(false)
  const lastWord = tagInputDraft.split(',').pop().trim()
  const suggestions = lastWord.length >= 1
    ? availableTags.filter(t => t.toLowerCase().includes(lastWord.toLowerCase()) && !tagInputDraft.split(',').map(s => s.trim()).includes(t))
    : []

  const applySuggestion = (tag) => {
    const parts = tagInputDraft.split(',').map(s => s.trim()).filter(Boolean)
    parts[parts.length - 1] = tag
    setTagInputDraft(parts.join(','))
    setShowSuggestions(false)
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '6px 16px',
      background: 'var(--bg-primary)', borderBottom: '1px solid var(--border)', flexShrink: 0,
    }}>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{t('reports.tagFilter')}</span>
      <div style={{ position: 'relative', flex: 1, maxWidth: 480 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-secondary)', border: `1px solid ${globalTags ? '#6366f1' : 'var(--border)'}`, borderRadius: 6, padding: '3px 8px' }}>
          <input
            value={tagInputDraft}
            onChange={e => { setTagInputDraft(e.target.value); setShowSuggestions(true) }}
            onFocus={() => setShowSuggestions(true)}
            onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
            onKeyDown={e => { if (e.key === 'Enter') { setGlobalTags(tagInputDraft.trim()); setShowSuggestions(false) } }}
            placeholder={t('reports.tagPlaceholder')}
            style={{ flex: 1, background: 'none', border: 'none', color: 'var(--text-primary)', fontSize: 12, outline: 'none', minWidth: 0 }}
          />
          {tagInputDraft && tagInputDraft.trim() !== globalTags && (
            <button onClick={() => { setGlobalTags(tagInputDraft.trim()); setShowSuggestions(false) }} style={{ background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 4, padding: '2px 8px', fontSize: 11, cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>Apply</button>
          )}
          {globalTags && (
            <button onClick={() => { setGlobalTags(''); setTagInputDraft('') }} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2, display: 'flex', alignItems: 'center' }}><X size={13} /></button>
          )}
        </div>
        {showSuggestions && suggestions.length > 0 && (
          <div style={{
            position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 999,
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6,
            boxShadow: '0 4px 16px rgba(0,0,0,0.3)', maxHeight: 160, overflowY: 'auto', marginTop: 2,
          }}>
            {suggestions.slice(0, 10).map(t => (
              <div
                key={t}
                onMouseDown={() => applySuggestion(t)}
                style={{ padding: '6px 10px', fontSize: 12, cursor: 'pointer', color: 'var(--text-primary)' }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >{t}</div>
            ))}
          </div>
        )}
      </div>
      <select
        value={globalTagLogic}
        onChange={e => setGlobalTagLogic(e.target.value)}
        title="Match ALL tags (AND) or ANY tag (OR)"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '4px 8px', fontSize: 12, cursor: 'pointer' }}
      >
        <option value="AND">AND</option>
        <option value="OR">OR</option>
      </select>
      {globalTags && (
        <span style={{ fontSize: 11, color: '#818cf8', background: '#6366f122', border: '1px solid #6366f144', borderRadius: 20, padding: '2px 10px', whiteSpace: 'nowrap' }}>
          {t('reports.filtering')}: {globalTags}
        </span>
      )}
    </div>
  )
}

// ─── Builder view ─────────────────────────────────────────────────────────────

function Builder({ report, onSave, onBack, isLanding, onSetLanding }) {
  const { t } = useTranslation()
  const { activeScanId, scans, scansLoaded } = useScan()
  const navigate = useNavigate()
  const [widgets, setWidgets] = useState(report.widgets || [])
  const [name, setName] = useState(report.name || t('reports.untitledReport'))
  const [selectedId, setSelectedId] = useState(null)
  const [preview, setPreview] = useState(true)
  const [saved, setSaved] = useState(false)
  const [editingName, setEditingName] = useState(false)
  const [globalTags, setGlobalTags] = useState('')
  const [globalTagLogic, setGlobalTagLogic] = useState('AND')
  const [tagInputDraft, setTagInputDraft] = useState('')
  const [availableTags, setAvailableTags] = useState([])
  const canvasRef = useRef()

  useEffect(() => {
    getTags().then(d => setAvailableTags((d || []).map(t => `${t.category}:${t.value}`))).catch(() => {})
  }, [])

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
          <ArrowLeft size={15} /> {t('reports.title')}
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
          {preview ? <><EyeOff size={14} /> {t('common.edit')}</> : <><Eye size={14} /> {t('reports.preview')}</>}
        </button>

        <button
          onClick={isLanding ? undefined : onSetLanding}
          title={isLanding ? t('reports.thisIsLanding') : t('reports.setAsLanding')}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: isLanding ? '#16a34a22' : 'transparent', border: `1px solid ${isLanding ? '#16a34a' : 'var(--border)'}`, color: isLanding ? '#16a34a' : 'var(--text-secondary)', borderRadius: 6, cursor: isLanding ? 'default' : 'pointer', fontSize: 13, fontWeight: 500 }}
        >
          <Home size={14} /> {isLanding ? t('reports.landing') : t('reports.setAsHome')}
        </button>

        <button
          onClick={handleSave}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', background: saved ? '#16a34a' : 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600, transition: 'background 0.2s' }}
        >
          {saved ? <><CheckCircle size={14} /> {t('reports.saved')}</> : <><Save size={14} /> {t('common.save')}</>}
        </button>

        <ExportDropdown canvasRef={canvasRef} reportName={name} disabled={widgets.length === 0} />
      </div>

      {/* Global tag filter bar */}
      <GlobalTagFilterBar
        globalTags={globalTags}
        setGlobalTags={setGlobalTags}
        globalTagLogic={globalTagLogic}
        setGlobalTagLogic={setGlobalTagLogic}
        tagInputDraft={tagInputDraft}
        setTagInputDraft={setTagInputDraft}
        availableTags={availableTags}
      />

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
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{t('reports.customReport', { date: new Date().toLocaleDateString() })}</div>
            </div>
          )}

          {preview && scansLoaded && (!scans || scans.length === 0) && (
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
                <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)' }}>{t('reports.uploadFirstScan')}</div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.5 }}>
                  {t('reports.uploadFirstScanDesc')}
                </div>
              </div>
              <button
                onClick={() => navigate('/settings?tab=upload')}
                style={{
                  marginTop: 4, padding: '10px 24px', background: 'var(--accent)', border: 'none',
                  color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}
              >
                <Upload size={16} /> {t('reports.uploadScan')}
              </button>
            </div>
          )}

          {widgets.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, color: 'var(--text-muted)', gap: 12 }}>
              <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>{t('reports.canvasEmpty')}</div>
              <div style={{ fontSize: 13, textAlign: 'center', maxWidth: 280 }}>{t('reports.canvasEmptyHint')}</div>
            </div>
          ) : (
            <div ref={canvasRef} style={{
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
                  globalTags={globalTags || undefined}
                  globalTagLogic={globalTagLogic}
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
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { scans, scansLoaded } = useScan()
  const [search, setSearch] = useState('')
  const filtered = search.trim()
    ? reports.filter(r => r.name.toLowerCase().includes(search.trim().toLowerCase()))
    : reports
  return (
    <div>
      {scansLoaded && scans.length === 0 && (
        <div style={{
          maxWidth: '100%', marginBottom: 24, padding: '20px 28px',
          background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.06))',
          border: '1px solid rgba(99,102,241,0.25)', borderRadius: 14,
          display: 'flex', alignItems: 'center', gap: 20,
        }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12, flexShrink: 0,
            background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Upload size={22} color="#818cf8" />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 3 }}>{t('reports.uploadFirstScan')}</div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>{t('reports.uploadFirstScanDesc')}</div>
          </div>
          <button
            onClick={() => navigate('/settings?tab=upload')}
            style={{
              flexShrink: 0, padding: '9px 20px', background: 'var(--accent)', border: 'none',
              color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14,
              display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            <Upload size={15} /> {t('reports.uploadScan')}
          </button>
        </div>
      )}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>{t('reports.title')}</h2>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{t('reports.subtitle')}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ExportImportButtons
            configType="report_template"
            exportFn={() => exportConfig('report_template')}
            onImported={onRefresh}
            label={t('reports.reportTemplates')}
          />
          <button
            onClick={onCreate}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 18px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14 }}
          >
            <Plus size={16} /> {t('reports.newReport')}
          </button>
        </div>
      </div>

      {reports.length > 0 && (
        <div style={{ position: 'relative', marginBottom: 16 }}>
          <Search size={15} color="var(--text-muted)" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('reports.searchPlaceholder')}
            style={{
              width: '100%', padding: '9px 12px 9px 36px',
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 8, fontSize: 13, color: 'var(--text-primary)',
              outline: 'none',
            }}
          />
        </div>
      )}

      {filtered.length === 0 && reports.length > 0 ? (
        <div style={{
          border: '1px solid var(--border)', borderRadius: 14, padding: '40px 24px',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, textAlign: 'center',
        }}>
          <Search size={32} color="var(--text-muted)" style={{ opacity: 0.4 }} />
          <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>{t('reports.noSearchResults')}</div>
        </div>
      ) : reports.length === 0 ? (
        <div style={{
          border: '2px dashed var(--border)', borderRadius: 14, padding: '60px 24px',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, textAlign: 'center',
        }}>
          <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>{t('reports.noReportsYet')}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 320 }}>
            {t('reports.noReportsDesc')}
          </div>
          <button
            onClick={onCreate}
            style={{ marginTop: 4, padding: '9px 20px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={15} /> {t('reports.createFirst')}
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {filtered.map(report => {
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
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{t('reports.emptyReport')}</div>
                    )}
                  </div>
                  {isHome && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: '#16a34a', background: '#16a34a22', padding: '4px 8px', borderRadius: 6 }}>
                      <Home size={11} /> {t('reports.landing')}
                    </div>
                  )}
                </div>

                <div style={{ padding: '14px 16px' }}>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{report.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                    {(report.widgets || []).length} {(report.widgets || []).length !== 1 ? t('reports.widgets') : t('reports.widget')} ·
                    {t('reports.created')} {new Date(report.createdAt).toLocaleDateString()}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => onOpen(report)} style={{ flex: 1, padding: '7px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontWeight: 600, fontSize: 13 }}>
                      {t('reports.open')}
                    </button>
                    {!isHome && (
                      <button onClick={() => onSetLanding(report.id)} title={t('reports.setAsLanding')} style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                        <Home size={14} />
                      </button>
                    )}
                    <button onClick={() => onDuplicate(report)} title={t('reports.duplicate')} style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                      <Copy size={14} />
                    </button>
                    <button onClick={() => onDelete(report.id)} title={t('common.delete')} style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: '#dc2626', borderRadius: 6, cursor: 'pointer' }}>
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

function TabBar({ active, onChange }) {
  const { t } = useTranslation()
  const tabs = [
    { id: 'reports', label: t('reports.title'), icon: BarChart2 },
    { id: 'ai-query', label: t('reports.aiQuery'), icon: Sparkles },
  ]
  return (
    <div style={{
      display: 'flex', gap: 4,
      borderBottom: '1px solid var(--border)',
      padding: '0 18px',
      background: 'var(--bg)',
    }}>
      {tabs.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          onClick={() => onChange(id)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '10px 14px', border: 'none', background: 'transparent',
            fontSize: 13, fontWeight: 600, cursor: 'pointer',
            color: active === id ? '#6366f1' : 'var(--muted)',
            borderBottom: active === id ? '2px solid #6366f1' : '2px solid transparent',
            marginBottom: -1,
            transition: 'color 0.15s',
          }}
        >
          <Icon size={15} />
          {label}
        </button>
      ))}
    </div>
  )
}

export default function ReportBuilder() {
  const { t } = useTranslation()
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [landingId, setLandingId] = useState(loadLandingId)
  const [activeReport, setActiveReport] = useState(null)
  const [activeTab, setActiveTab] = useState('reports')
  const [fetchError, setFetchError] = useState(null)
  const { reportId: urlReportId } = useParams()
  const navigate = useNavigate()
  const initialLoadRef = useRef(true)

  // Sync activeReport → URL
  useEffect(() => {
    if (activeReport?.id) {
      const target = `/reports/${activeReport.id}`
      if (window.location.pathname !== target) {
        navigate(target, { replace: false })
      }
    } else if (activeReport === null && window.location.pathname.startsWith('/reports/')) {
      navigate('/', { replace: false })
    }
  }, [activeReport])

  const loadFromApi = useCallback(async () => {
    setFetchError(null)
    try {
      await migrateLocalStorageReports()
      let templates = await getReportTemplates()
      let needsReload = false

      // Ensure default dashboards exist and stay up-to-date
      const ootb = [EXECUTIVE_DASHBOARD, DEFAULT_DASHBOARD, IDENTITY_ACCESS_DASHBOARD, ATTACK_SURFACE_DASHBOARD, REMEDIATION_DASHBOARD, AI_ML_ATTACK_SURFACE_DASHBOARD, OS_DISTRIBUTION_DASHBOARD, SOFTWARE_INVENTORY_DASHBOARD, EASM_DASHBOARD, OWNER_ACCOUNTABILITY_DASHBOARD]
      for (const dash of ootb) {
        const fingerprint = dash.widgets.map(w => `${w.id}:${w.type}:${w.config?.preset || ''}:${w.config?.show_benchmark ? 'bm' : ''}`).join('|')
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
      // Auto-open: URL report ID takes priority, then landing report (only on initial load)
      if (!activeReport) {
        if (urlReportId) {
          const found = mapped.find(r => String(r.id) === String(urlReportId))
          if (found) setActiveReport(found)
        } else if (initialLoadRef.current) {
          const targetId = loadLandingId()
          const found = targetId
            ? (mapped.find(r => String(r.id) === String(targetId)) || mapped.find(r => r.name === 'Executive Overview'))
            : mapped.find(r => r.name === 'Executive Overview')
          if (found) setActiveReport(found)
        }
      }
      initialLoadRef.current = false
    } catch (e) {
      console.error('Failed to load report templates', e)
      setFetchError('Failed to load report data.')
    } finally {
      setLoading(false)
    }
  }, [urlReportId])

  useEffect(() => { loadFromApi() }, [loadFromApi])

  // Sync URL → activeReport (browser back/forward)
  useEffect(() => {
    if (!reports.length) return
    if (urlReportId) {
      if (String(activeReport?.id) !== String(urlReportId)) {
        const found = reports.find(r => String(r.id) === String(urlReportId))
        if (found) setActiveReport(found)
      }
    } else if (window.location.pathname === '/') {
      if (activeReport !== null) setActiveReport(null)
    }
  }, [urlReportId, reports])

  const setLanding = (id) => {
    setLandingId(id)
    saveLandingId(id)
  }

  const createReport = () => {
    const report = { id: null, name: t('reports.untitledReport'), createdAt: new Date().toISOString(), widgets: [] }
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
    if (!confirm(t('reports.deleteConfirm'))) return
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

  if (loading) return <div style={{ padding: 40 }}><SkeletonCard lines={4} /></div>

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
    <div style={{ margin: '-18px', display: 'flex', flexDirection: 'column', minHeight: 'calc(100vh - 32px)' }}>
      <ErrorBanner error={fetchError} onRetry={loadFromApi} onDismiss={() => setFetchError(null)} />
      <TabBar active={activeTab} onChange={setActiveTab} />
      <div style={{ flex: 1, padding: 18, overflowY: 'auto' }}>
        {activeTab === 'ai-query' ? (
          <NLPReportBuilder />
        ) : (
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
        )}
      </div>
    </div>
  )
}
