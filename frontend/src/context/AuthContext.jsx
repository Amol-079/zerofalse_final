import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useAuth as useClerkAuth, useUser } from '@clerk/clerk-react';
import client, { setClerkTokenGetter } from '../api/client';

export const AuthContext = createContext({
  isAuthenticated: false,
  isLoading: true,
  isProvisioning: false,
  clerkUser: null,
  user: null,
  org: null,
  refreshUser: async () => {},
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const isProvisioningErr = (err) => {
  const status = err?.response?.status;
  const detail = err?.response?.data?.detail || '';
  return (status === 503 || status === 401) && detail.includes('provisioning');
};

export function AuthProvider({ children }) {
  const { isSignedIn, isLoaded, getToken } = useClerkAuth();
  const { user: clerkUser } = useUser();
  const [dbUser, setDbUser] = useState(null);
  const [org, setOrg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isProvisioning, setProvisioning] = useState(false);

  // Keep token getter current — set ONCE here, not duplicated in App.js
  useEffect(() => { setClerkTokenGetter(getToken); }, [getToken]);

  const loadUser = useCallback(async () => {
    setProvisioning(false);
    // Retry up to 8 times with growing delay to handle Clerk webhook race condition
    for (let i = 0; i < 8; i++) {
      try {
        const res = await client.get('/api/v1/auth/me');
        setDbUser(res.data.user ?? null);
        setOrg(res.data.org ?? null);
        setLoading(false);
        setProvisioning(false);
        return;
      } catch (err) {
        if (isProvisioningErr(err) && i < 7) {
          setProvisioning(true);
          await sleep(1000 * Math.min(i + 1, 4));
          continue;
        }
        console.warn('[AuthContext] /auth/me failed:', err?.response?.status);
        setLoading(false);
        setProvisioning(false);
        return;
      }
    }
    setLoading(false);
    setProvisioning(false);
  }, []);

  useEffect(() => {
    if (!isLoaded) return;
    if (!isSignedIn) {
      setDbUser(null);
      setOrg(null);
      setProvisioning(false);
      setLoading(false);
      return;
    }
    setLoading(true);
    loadUser();
  }, [isSignedIn, isLoaded, loadUser]);

  const refreshUser = useCallback(async () => {
    try {
      const res = await client.get('/api/v1/auth/me');
      setDbUser(res.data.user ?? null);
      setOrg(res.data.org ?? null);
    } catch (e) {
      console.warn('[AuthContext] refreshUser failed:', e?.message);
    }
  }, []);

  return (
    <AuthContext.Provider value={{
      isAuthenticated: !!isSignedIn,
      isLoading: !isLoaded || loading,
      isProvisioning,
      clerkUser,
      user: dbUser,
      org,
      refreshUser,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAppAuth = () => useContext(AuthContext);
