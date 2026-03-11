import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import {
  authMe, authLogin, authRegister,
  setStoredToken, clearStoredToken, getStoredToken,
  setOrgContext, getOrgContext,
} from '../api.js'

const AuthContext = createContext(null)

export const useAuth = () => useContext(AuthContext)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [org, setOrg] = useState(null)
  const [accessibleOrgs, setAccessibleOrgs] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

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
        setIsAuthenticated(true)
      })
      .catch(() => {
        clearStoredToken()
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
    return data
  }, [])

  const logout = useCallback(() => {
    clearStoredToken()
    setUser(null)
    setOrg(null)
    setAccessibleOrgs([])
    setIsAuthenticated(false)
  }, [])

  const switchOrg = useCallback((orgId) => {
    setOrgContext(orgId || null)
    // Reload the page to re-fetch all data with new org context
    window.location.reload()
  }, [])

  const currentOrgContext = getOrgContext()

  return (
    <AuthContext.Provider value={{
      user,
      org,
      accessibleOrgs,
      isLoading,
      isAuthenticated,
      login,
      register,
      logout,
      switchOrg,
      currentOrgContext,
      isMSSP: org?.org_type === 'mssp',
      isSuperadmin: user?.role === 'superadmin',
      isAdmin: user?.role === 'org_admin' || user?.role === 'superadmin',
      isViewer: user?.role === 'viewer',
    }}>
      {children}
    </AuthContext.Provider>
  )
}
