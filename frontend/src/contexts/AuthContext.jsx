import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import * as Sentry from '@sentry/react'
import { useTranslation } from 'react-i18next'
import {
  authMe, authLogin, authRegister, authGoogleLogin,
  setStoredToken, clearStoredToken, getStoredToken,
  setOrgContext, getOrgContext,
} from '../api.js'
import { identifyUser, resetAnalytics, capture } from '../utils/analytics.js'

const AuthContext = createContext(null)

export const useAuth = () => useContext(AuthContext)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [org, setOrg] = useState(null)
  const [accessibleOrgs, setAccessibleOrgs] = useState([])
  const [effectivePermissions, setEffectivePermissions] = useState({})
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const { i18n } = useTranslation()

  // Attempt to restore session from stored token
  useEffect(() => {
    const token = getStoredToken()
    if (!token) {
      setIsLoading(false)
      return
    }
    authMe()
      .then(data => {
        setUser(data)
        setOrg(data.org)
        setAccessibleOrgs(data.accessible_orgs || [data.org])
        setEffectivePermissions(data.effective_permissions || {})
        setIsAuthenticated(true)
        Sentry.setUser({ id: data.id, email: data.email })
        identifyUser(data, data.org)
        // Sync UI language with user's stored locale preference
        if (data.locale && data.locale !== i18n.language) {
          i18n.changeLanguage(data.locale)
        }
      })
      .catch((err) => {
        // Only clear the token when the server explicitly rejects it (401/403).
        // Network errors or 5xx during startup should not log the user out.
        const isAuthError = err?.message === 'Authentication required' || err?.message === 'Authentication failed'
        if (isAuthError) clearStoredToken()
      })
      .finally(() => setIsLoading(false))
  }, [])

  const login = useCallback(async (email, password) => {
    const data = await authLogin({ email, password })
    setStoredToken(data.access_token)
    setUser(data.user)
    setOrg(data.user.org)
    setIsAuthenticated(true)
    identifyUser(data.user, data.user.org)
    capture('user_logged_in', { method: 'password' })
    // Fetch full user info (includes accessible_orgs for MSSP)
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
      identifyUser(me, me.org)
    } catch {}
    return data
  }, [])

  const register = useCallback(async (orgName, email, password, displayName) => {
    const data = await authRegister({ org_name: orgName, email, password, display_name: displayName })
    setStoredToken(data.access_token)
    setUser(data.user)
    setOrg(data.user.org)
    setAccessibleOrgs([data.user.org])
    setIsAuthenticated(true)
    identifyUser(data.user, data.user.org)
    capture('user_registered', { method: 'password', org_name: orgName })
    // Fetch full user info (includes effective_permissions for nav visibility)
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
      identifyUser(me, me.org)
    } catch {}
    return data
  }, [])

  const googleLogin = useCallback(async (credential) => {
    const data = await authGoogleLogin(credential)
    setStoredToken(data.access_token)
    setUser(data.user)
    setOrg(data.user.org)
    setIsAuthenticated(true)
    identifyUser(data.user, data.user.org)
    capture('user_logged_in', { method: 'google' })
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
      identifyUser(me, me.org)
    } catch {}
    return data
  }, [])

  const refreshAuth = useCallback(async () => {
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
      return me
    } catch {
      return null
    }
  }, [])

  const logout = useCallback(() => {
    clearStoredToken()
    Sentry.setUser(null)
    capture('user_logged_out')
    resetAnalytics()
    setUser(null)
    setOrg(null)
    setAccessibleOrgs([])
    setEffectivePermissions({})
    setIsAuthenticated(false)
  }, [])

  const switchOrg = useCallback((orgId) => {
    setOrgContext(orgId || null)
    // Reload the page to re-fetch all data with new org context
    window.location.reload()
  }, [])

  const currentOrgContext = getOrgContext()

  const hasPermission = useCallback((key) => !!effectivePermissions[key], [effectivePermissions])
  const hasAnyPermission = useCallback((...keys) => keys.some(k => !!effectivePermissions[k]), [effectivePermissions])
  const canAccessPage = useCallback((pageKey) => !!effectivePermissions[pageKey], [effectivePermissions])

  return (
    <AuthContext.Provider value={{
      user,
      org,
      accessibleOrgs,
      effectivePermissions,
      isLoading,
      isAuthenticated,
      login,
      register,
      googleLogin,
      logout,
      refreshAuth,
      switchOrg,
      currentOrgContext,
      hasPermission,
      hasAnyPermission,
      canAccessPage,
      isMSSP: org?.org_type === 'mssp',
      isSuperadmin: user?.role === 'superadmin',
      isAdmin: user?.role === 'org_admin' || user?.role === 'superadmin',
      isViewer: user?.role === 'viewer',
      emailVerified: user?.email_verified !== false,
      isCustomRole: user?.role === 'custom',
      subscriptionTier: org?.subscription_tier || 'free',
      subscriptionStatus: org?.subscription_status,
      isPro: (org?.subscription_tier === 'pro') && (org?.subscription_status === 'active' || org?.subscription_status === 'trialing'),
    }}>
      {children}
    </AuthContext.Provider>
  )
}
