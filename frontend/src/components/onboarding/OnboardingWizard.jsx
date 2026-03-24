import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Upload, BarChart3, Target, Rocket, Check, ChevronRight, X, Bot, ArrowRight } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  getOnboardingStatus, completeOnboardingStep, completeOnboarding, skipOnboarding,
  uploadScan, getScans, createCampaign,
} from '../../api.js'

const STEPS = [
  { key: 'scan_uploaded', icon: Upload, color: '#6366f1' },
  { key: 'priorities_reviewed', icon: BarChart3, color: '#f59e0b' },
  { key: 'campaign_created', icon: Target, color: '#10b981' },
]

export default function OnboardingWizard() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { user, refreshUser } = useAuth()
  const [currentStep, setCurrentStep] = useState(0)
  const [state, setState] = useState({})
  const [loading, setLoading] = useState(true)
  const [scanResult, setScanResult] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState(null)
  const [scans, setScans] = useState([])
  const [creatingCampaign, setCreatingCampaign] = useState(false)
  const [campaignResult, setCampaignResult] = useState(null)
  const [finishing, setFinishing] = useState(false)

  useEffect(() => {
    getOnboardingStatus().then(data => {
      setState(data.state || {})
      if (data.state?.scan_uploaded) setCurrentStep(data.state.priorities_reviewed ? 2 : 1)
      if (data.has_scans) {
        getScans().then(s => setScans(s)).catch(() => {})
      }
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const handleFileUpload = useCallback(async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setUploadError(null)
    try {
      const result = await uploadScan(file)
      setScanResult(result)
      await completeOnboardingStep('scan_uploaded')
      setState(prev => ({ ...prev, scan_uploaded: true }))
      const s = await getScans()
      setScans(s)
      setCurrentStep(1)
    } catch (err) {
      setUploadError(err.message || t('onboarding.uploadError'))
    } finally {
      setUploading(false)
    }
  }, [t])

  const handleReviewPriorities = useCallback(async () => {
    await completeOnboardingStep('priorities_reviewed').catch(() => {})
    setState(prev => ({ ...prev, priorities_reviewed: true }))
    setCurrentStep(2)
  }, [])

  const handleCreateCampaign = useCallback(async () => {
    setCreatingCampaign(true)
    try {
      const scanId = scans[0]?.id
      const result = await createCampaign({
        name: t('onboarding.firstCampaignName'),
        description: t('onboarding.firstCampaignDesc'),
        scan_id: scanId,
        query: [
          { field: 'finding.severity', op: 'gte', value: 3 },
          { field: 'finding.exploit', op: 'is_true', value: true },
        ],
        query_logic: 'AND',
        status: 'active',
      })
      setCampaignResult(result)
      await completeOnboardingStep('campaign_created')
      setState(prev => ({ ...prev, campaign_created: true }))
      if (result?.id) window.open(`/campaigns/${result.id}`, '_blank')
    } catch (err) {
      setCampaignResult({ error: err.message })
    } finally {
      setCreatingCampaign(false)
    }
  }, [scans, t])

  const handleFinish = useCallback(async () => {
    setFinishing(true)
    await completeOnboarding().catch(() => {})
    await refreshUser()
    navigate('/')
  }, [navigate, refreshUser])

  const handleSkip = useCallback(async () => {
    await skipOnboarding().catch(() => {})
    await refreshUser()
    navigate('/')
  }, [navigate, refreshUser])

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: 'var(--bg-muted)' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>{t('app.loading')}</div>
      </div>
    )
  }

  const allDone = state.scan_uploaded && state.priorities_reviewed && state.campaign_created

  return (
    <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 20px' }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{
          width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px',
          boxShadow: '0 4px 12px rgba(99,102,241,0.3)',
        }}>
          <Rocket size={28} color="#fff" />
        </div>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text)', margin: '0 0 8px' }}>
          {t('onboarding.welcome', { name: user?.display_name?.split(' ')[0] || '' })}
        </h1>
        <p style={{ fontSize: 15, color: 'var(--text-muted)', margin: 0, maxWidth: 480, marginInline: 'auto' }}>
          {t('onboarding.subtitle')}
        </p>
        <button
          onClick={handleSkip}
          style={{
            marginTop: 12, background: 'none', border: 'none', color: 'var(--text-muted)',
            fontSize: 13, cursor: 'pointer', textDecoration: 'underline', padding: '4px 8px',
          }}
        >
          {t('onboarding.skipSetup')}
        </button>
      </div>

      {/* Progress bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 32, padding: '0 20px' }}>
        {STEPS.map((step, i) => {
          const done = !!state[step.key]
          const active = i === currentStep
          return (
            <React.Fragment key={step.key}>
              {i > 0 && (
                <div style={{
                  flex: 1, height: 2,
                  background: done || (state[STEPS[i - 1]?.key]) ? step.color : 'var(--border)',
                  borderRadius: 1, transition: 'background 0.3s',
                }} />
              )}
              <div style={{
                width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
                background: done ? step.color : active ? `${step.color}20` : 'var(--bg-card)',
                border: `2px solid ${done || active ? step.color : 'var(--border)'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.3s',
              }}>
                {done ? <Check size={16} color="#fff" /> : <span style={{ fontSize: 13, fontWeight: 600, color: active ? step.color : 'var(--text-muted)' }}>{i + 1}</span>}
              </div>
            </React.Fragment>
          )
        })}
      </div>

      {/* Step cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Step 1: Upload Scan */}
        <StepCard
          step={STEPS[0]}
          index={0}
          currentStep={currentStep}
          done={!!state.scan_uploaded}
          title={t('onboarding.step1Title')}
          description={t('onboarding.step1Desc')}
          t={t}
        >
          {!state.scan_uploaded ? (
            <div>
              <label
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                  padding: '14px 24px', borderRadius: 10,
                  border: '2px dashed var(--border)', cursor: uploading ? 'default' : 'pointer',
                  background: 'var(--bg-muted)', transition: 'border-color 0.2s',
                  opacity: uploading ? 0.6 : 1,
                }}
              >
                <Upload size={20} color="var(--accent)" />
                <span style={{ fontSize: 14, color: 'var(--text)' }}>
                  {uploading ? t('onboarding.uploading') : t('onboarding.chooseFile')}
                </span>
                <input
                  type="file"
                  accept=".nessus,.csv,.html,.htm"
                  onChange={handleFileUpload}
                  disabled={uploading}
                  style={{ display: 'none' }}
                />
              </label>
              {uploadError && <p style={{ color: 'var(--critical)', fontSize: 13, marginTop: 8 }}>{uploadError}</p>}
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
                {t('onboarding.supportedFormats')}
              </p>
            </div>
          ) : (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px',
              background: 'rgba(16,185,129,0.08)', borderRadius: 10,
            }}>
              <Check size={18} color="#10b981" />
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>
                  {t('onboarding.scanUploaded')}
                </div>
                {scanResult && (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                    {t('onboarding.scanStats', { assets: scanResult.assets || 0, findings: scanResult.findings || 0 })}
                  </div>
                )}
              </div>
            </div>
          )}
        </StepCard>

        {/* Step 2: Review Priorities */}
        <StepCard
          step={STEPS[1]}
          index={1}
          currentStep={currentStep}
          done={!!state.priorities_reviewed}
          title={t('onboarding.step2Title')}
          description={t('onboarding.step2Desc')}
          t={t}
        >
          {currentStep >= 1 && !state.priorities_reviewed ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>
                {t('onboarding.step2Hint')}
              </p>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={() => window.open('/findings', '_blank')}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 18px', borderRadius: 8, border: 'none',
                    background: '#f59e0b', color: '#fff', fontSize: 13, fontWeight: 600,
                    cursor: 'pointer', transition: 'opacity 0.15s',
                  }}
                >
                  <BarChart3 size={16} /> {t('onboarding.viewFindings')}
                </button>
                <button
                  onClick={handleReviewPriorities}
                  style={{
                    padding: '10px 18px', borderRadius: 8,
                    border: '1px solid var(--border)', background: 'var(--bg)',
                    color: 'var(--text)', fontSize: 13, cursor: 'pointer',
                  }}
                >
                  {t('onboarding.markReviewed')}
                </button>
              </div>
            </div>
          ) : state.priorities_reviewed ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#10b981', fontSize: 14 }}>
              <Check size={16} /> {t('onboarding.prioritiesReviewed')}
            </div>
          ) : null}
        </StepCard>

        {/* Step 3: Create Campaign */}
        <StepCard
          step={STEPS[2]}
          index={2}
          currentStep={currentStep}
          done={!!state.campaign_created}
          title={t('onboarding.step3Title')}
          description={t('onboarding.step3Desc')}
          t={t}
        >
          {currentStep >= 2 && !state.campaign_created ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>
                {t('onboarding.step3Hint')}
              </p>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={handleCreateCampaign}
                  disabled={creatingCampaign}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 18px', borderRadius: 8, border: 'none',
                    background: '#10b981', color: '#fff', fontSize: 13, fontWeight: 600,
                    cursor: creatingCampaign ? 'default' : 'pointer',
                    opacity: creatingCampaign ? 0.6 : 1, transition: 'opacity 0.15s',
                  }}
                >
                  <Target size={16} />
                  {creatingCampaign ? t('onboarding.creating') : t('onboarding.createCampaign')}
                </button>
                <button
                  onClick={() => window.open('/campaigns', '_blank')}
                  style={{
                    padding: '10px 18px', borderRadius: 8,
                    border: '1px solid var(--border)', background: 'var(--bg)',
                    color: 'var(--text)', fontSize: 13, cursor: 'pointer',
                  }}
                >
                  {t('onboarding.customCampaign')}
                </button>
              </div>
            </div>
          ) : state.campaign_created ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#10b981', fontSize: 14 }}>
              <Check size={16} /> {t('onboarding.campaignCreated')}
              {campaignResult && !campaignResult.error && (
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  — {campaignResult.finding_count || 0} {t('onboarding.findingsMatched')}
                </span>
              )}
            </div>
          ) : null}
        </StepCard>
      </div>

      {/* Completion / AI Agent CTA */}
      {allDone && (
        <div style={{
          marginTop: 24, padding: 24, borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.08))',
          border: '1px solid rgba(99,102,241,0.2)',
          textAlign: 'center',
        }}>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text)', margin: '0 0 8px' }}>
            {t('onboarding.allDone')}
          </h3>
          <p style={{ fontSize: 14, color: 'var(--text-muted)', margin: '0 0 20px' }}>
            {t('onboarding.allDoneDesc')}
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              onClick={handleFinish}
              disabled={finishing}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '12px 24px', borderRadius: 10, border: 'none',
                background: 'var(--accent)', color: '#fff', fontSize: 14, fontWeight: 600,
                cursor: 'pointer', transition: 'opacity 0.15s',
              }}
            >
              <ArrowRight size={18} /> {t('onboarding.goToDashboard')}
            </button>
            <button
              onClick={async () => { await completeOnboarding().catch(() => {}); await refreshUser(); navigate('/agents') }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '12px 24px', borderRadius: 10,
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: 'var(--text)', fontSize: 14, fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Bot size={18} /> {t('onboarding.tryAgent')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function StepCard({ step, index, currentStep, done, title, description, children, t }) {
  const active = index === currentStep
  const locked = index > currentStep && !done
  const Icon = step.icon

  return (
    <div style={{
      padding: 20, borderRadius: 14,
      background: 'var(--bg-card)',
      border: `1px solid ${active ? step.color + '40' : 'var(--border)'}`,
      boxShadow: active ? `0 2px 12px ${step.color}15` : '0 1px 3px rgba(0,0,0,0.04)',
      opacity: locked ? 0.5 : 1,
      transition: 'all 0.3s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: children && !locked ? 14 : 0 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10, flexShrink: 0,
          background: done ? step.color : `${step.color}15`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon size={18} color={done ? '#fff' : step.color} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>{title}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>{description}</div>
        </div>
        {done && (
          <div style={{
            width: 24, height: 24, borderRadius: '50%', background: '#10b981',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <Check size={14} color="#fff" />
          </div>
        )}
      </div>
      {children && !locked && <div style={{ marginLeft: 48 }}>{children}</div>}
    </div>
  )
}
