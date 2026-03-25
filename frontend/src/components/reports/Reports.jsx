import { useState, useRef } from 'react'
import ReportBuilder from './ReportBuilder.jsx'
import FirstScanOnboarding from '../onboarding/FirstScanOnboarding.jsx'
import GettingStartedPanel from '../onboarding/GettingStartedPanel.jsx'
import { useScan } from '../../App.jsx'

export default function Reports() {
  const { scans, scansLoaded } = useScan()
  // Track whether we started in onboarding mode — set once, never flipped back by refreshScans()
  const initializedRef = useRef(false)
  const [onboardingMode, setOnboardingMode] = useState(false)

  if (scansLoaded && !initializedRef.current) {
    initializedRef.current = true
    if (scans.length === 0) setOnboardingMode(true)
  }

  if (!scansLoaded) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <div style={{ width: 28, height: 28, border: '3px solid var(--border)', borderTop: '3px solid var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  )

  if (onboardingMode) {
    return <FirstScanOnboarding onComplete={() => setOnboardingMode(false)} />
  }

  return (
    <>
      <GettingStartedPanel />
      <ReportBuilder />
    </>
  )
}
