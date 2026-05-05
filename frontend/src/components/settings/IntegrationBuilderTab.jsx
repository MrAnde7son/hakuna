/**
 * Integration Builder tab — embedded in Settings.
 * Manages its own sub-navigation: list → builder → detail.
 */
import { useState } from 'react'
import IntegrationList from '../integrations/IntegrationList.jsx'
import IntegrationBuilder from '../integrations/IntegrationBuilder.jsx'
import IntegrationDetail from '../integrations/IntegrationDetail.jsx'

export default function IntegrationBuilderTab() {
  const [view, setView] = useState({ page: 'list' }) // { page: 'list' | 'new' | 'edit' | 'detail', id? }

  return (
    <div style={{ minHeight: 600 }}>
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
    </div>
  )
}
