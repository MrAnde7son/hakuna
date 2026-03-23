import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  authMe, authLogin, authRegister, authGoogleLogin,
  setStoredToken, clearStoredToken, getStoredToken,
  setOrgContext, getOrgContext,
} from '../api.js'

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
    // Fetch full user info (includes accessible_orgs for MSSP)
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
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
    // Fetch full user info (includes effective_permissions for nav visibility)
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
    } catch {}
    return data
  }, [])

  const googleLogin = useCallback(async (credential) => {
    const data = await authGoogleLogin(credential)
    setStoredToken(data.access_token)
    setUser(data.user)
    setOrg(data.user.org)
    setIsAuthenticated(true)
    try {
      const me = await authMe()
      setUser(me)
      setOrg(me.org)
      setAccessibleOrgs(me.accessible_orgs || [me.org])
      setEffectivePermissions(me.effective_permissions || {})
    } catch {}
    return data
  }, [])

  const logout = useCallback(() => {
    clearStoredToken()
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
      switchOrg,
      currentOrgContext,
      hasPermission,
      hasAnyPermission,
      canAccessPage,
      isMSSP: org?.org_type === 'mssp',
      isSuperadmin: user?.role === 'superadmin',
      isAdmin: user?.role === 'org_admin' || user?.role === 'superadmin',
      isViewer: user?.role === 'viewer',
      isCustomRole: user?.role === 'custom',
      subscriptionTier: org?.subscription_tier || 'free',
      subscriptionStatus: org?.subscription_status,
      isPro: (org?.subscription_tier === 'pro') && (org?.subscription_status === 'active' || org?.subscription_status === 'trialing'),
    }}>
      {children}
    </AuthContext.Provider>
  )
}
