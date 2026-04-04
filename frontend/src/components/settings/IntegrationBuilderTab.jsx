/**
 * Integration Builder tab — embedded in Settings.
 * Manages its own sub-navigation: list → builder → detail, plus relay agents.
 */
import { useState } from 'react'
import { Blocks, Server } from 'lucide-react'
import IntegrationList from '../integrations/IntegrationList.jsx'
import IntegrationBuilder from '../integrations/IntegrationBuilder.jsx'
import IntegrationDetail from '../integrations/IntegrationDetail.jsx'
import RelayAgentManager from '../integrations/relay/RelayAgentManager.jsx'

const SUB_TABS = [
  { id: 'integrations', label: 'Integrations', icon: Blocks },
  { id: 'relay-agents', label: 'Relay Agents', icon: Server },
]

export default function IntegrationBuilderTab() {
  const [subTab, setSubTab] = useState('integrations')
  const [view, setView] = useState({ page: 'list' }) // { page: 'list' | 'new' | 'edit' | 'detail', id? }

  return (
    <div style={{ margin: '-24px', minHeight: 600 }}>
      {/* Sub-tab bar */}
      <div style={{
        display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
        padding: '0 24px', background: 'var(--bg)',
      }}>
        {SUB_TABS.map(tab => {
          const Icon = tab.icon
          const active = subTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => { setSubTab(tab.id); setView({ page: 'list' }) }}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '10px 16px', fontSize: 13, fontWeight: active ? 600 : 400,
                border: 'none', borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                background: 'transparent', cursor: 'pointer',
                color: active ? 'var(--accent)' : 'var(--text-muted)',
              }}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Content */}
      <div style={{ padding: 24 }}>
        {subTab === 'integrations' && (
          <>
            {view.page === 'list' && (
              <IntegrationList
                embedded
                onNew={() => setView({ page: 'new' })}
                onEdit={(id) => setView({ page: 'edit', id })}
                onDetail={(id) => setView({ page: 'detail', id })}
              />
            )}
            {view.page === 'new' && (
              <IntegrationBuilder
                embedded
                onBack={() => setView({ page: 'list' })}
                onDone={() => setView({ page: 'list' })}
              />
            )}
            {view.page === 'edit' && (
              <IntegrationBuilder
                embedded
                editId={view.id}
                onBack={() => setView({ page: 'list' })}
                onDone={() => setView({ page: 'list' })}
              />
            )}
            {view.page === 'detail' && (
              <IntegrationDetail
                embedded
                integrationId={view.id}
                onBack={() => setView({ page: 'list' })}
                onEdit={(id) => setView({ page: 'edit', id })}
              />
            )}
          </>
        )}

        {subTab === 'relay-agents' && <RelayAgentManager />}
      </div>
    </div>
  )
}
