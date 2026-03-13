import React from 'react'
import { X, Zap, Lock } from 'lucide-react'
import { logAutomateClick } from '../../api.js'
import { Button } from '../shared/ui.jsx'

export default function AutomateModal({ finding, onClose }) {
  const handleContact = async () => {
    if (finding) {
      await logAutomateClick(finding.id).catch(() => {})
    }
    // In production, this would open a contact/sales form or Calendly
    alert('Request logged! Our team will reach out to discuss autonomous remediation for your environment.')
    onClose()
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
    }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
          padding: 32, maxWidth: 500, width: '100%', position: 'relative',
          boxShadow: '0 25px 60px rgba(0,0,0,0.5)',
        }}
      >
        {/* Close */}
        <button onClick={onClose} style={{
          position: 'absolute', top: 16, right: 16, background: 'none', border: 'none',
          color: 'var(--text-muted)', cursor: 'pointer'
        }}>
          <X size={18} />
        </button>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12, background: '#6366f133',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Zap size={24} color="#6366f1" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 18 }}>Autonomous Remediation</div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Lock size={11} /> Enterprise feature
            </div>
          </div>
        </div>

        {/* Finding context */}
        {finding && (
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '12px 14px', marginBottom: 20, fontSize: 13
          }}>
            <div style={{ color: 'var(--text-muted)', fontSize: 11, marginBottom: 4 }}>Finding to automate</div>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{finding.plugin_name}</div>
            <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>
              {finding.asset_hostname || finding.asset_ip} · Plugin {finding.plugin_id}
            </div>
          </div>
        )}

        {/* Description */}
        <div style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6, marginBottom: 20 }}>
          Autonomous remediation uses secure, policy-gated playbooks to fix vulnerabilities automatically —
          without manual intervention. Our agent connects to your infrastructure, applies the fix, and
          validates success in a single workflow.
        </div>

        {/* Features */}
        <div style={{ marginBottom: 24 }}>
          {[
            'Policy-gated execution — always ask before acting',
            'Rollback support built in',
            'Works with Windows, Linux, cloud, and network devices',
            'Full audit trail for compliance',
          ].map(item => (
            <div key={item} style={{ display: 'flex', gap: 8, padding: '6px 0', fontSize: 13, color: 'var(--text-secondary)' }}>
              <span style={{ color: '#6366f1', flexShrink: 0 }}>✓</span>
              {item}
            </div>
          ))}
        </div>

        {/* CTA */}
        <div style={{ display: 'flex', gap: 10 }}>
          <Button onClick={handleContact} style={{ flex: 1, justifyContent: 'center', fontSize: 14, padding: '10px 16px' }}>
            <Zap size={16} /> Contact Us to Enable
          </Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  )
}
