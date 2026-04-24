// PostHog product analytics — identify, capture, group, session replay.
//
// No-ops when VITE_POSTHOG_KEY is not set (dev, tests, self-hosted without
// analytics). Session replay masks all inputs + sensitive selectors so
// passwords, API keys, and customer asset data never leave the browser.

import posthog from 'posthog-js'

let initialized = false

export function initAnalytics() {
  if (initialized) return
  const key = import.meta.env.VITE_POSTHOG_KEY
  if (!key) return
  posthog.init(key, {
    api_host: import.meta.env.VITE_POSTHOG_HOST || 'https://us.i.posthog.com',
    person_profiles: 'identified_only',
    capture_pageview: true,
    capture_pageleave: true,
    autocapture: true,
    // Session replay with aggressive masking — Hakuna sees customer asset
    // names, IPs, credentials. Never ship those to a third-party recorder.
    session_recording: {
      maskAllInputs: true,
      maskTextSelector: '[data-ph-mask], input, textarea, .asset-name, .credential, .secret',
      maskInputOptions: {
        password: true,
        email: false,
      },
    },
    loaded: (ph) => {
      if (import.meta.env.DEV) ph.debug(false)
    },
  })
  initialized = true
}

export function identifyUser(user, org) {
  if (!initialized || !user) return
  posthog.identify(String(user.id), {
    email: user.email,
    name: user.display_name,
    role: user.role,
    locale: user.locale,
    email_verified: user.email_verified !== false,
    org_id: org?.id,
    org_name: org?.name,
  })
  if (org?.id) {
    posthog.group('company', String(org.id), {
      name: org.name,
      slug: org.slug,
      org_type: org.org_type,
      subscription_tier: org.subscription_tier || 'free',
      subscription_status: org.subscription_status,
    })
  }
}

export function resetAnalytics() {
  if (!initialized) return
  posthog.reset()
}

export function capture(event, properties) {
  if (!initialized) return
  posthog.capture(event, properties || {})
}

export function isAnalyticsEnabled() {
  return initialized
}
