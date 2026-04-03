import React, { useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { useUser, useAuth } from '@clerk/clerk-react';
import { setNavigateFn } from './api/client';
import { ThemeProvider } from './hooks/useTheme';
import { Layout } from './components/Layout';
import Landing from './pages/Landing';
import Onboarding from './pages/Onboarding';
import Dashboard from './pages/Dashboard';
import ScanLogs from './pages/ScanLogs';
import Alerts from './pages/Alerts';
import APIKeys from './pages/APIKeys';
import Settings from './pages/Settings';
import Docs from './pages/Docs';

/**
 * ProtectedRoute:
 *  - isLoaded=false → null (Clerk initialising — do NOT redirect yet)
 *  - isLoaded=true, isSignedIn=false → redirect /
 *  - isLoaded=true, isSignedIn=true → render children
 * The null return while loading prevents the infinite loop.
 */
const ProtectedRoute = ({ children }) => {
  const { isSignedIn, isLoaded } = useUser();
  if (!isLoaded) return null;
  if (!isSignedIn) return <Navigate to="/" replace />;
  return children;
};

function AppRoutes() {
  const { getToken } = useAuth();
  const navigate = useNavigate();
  const done = useRef(false);

  // setNavigateFn only — token getter is set inside AuthContext
  useEffect(() => {
    if (!done.current) {
      setNavigateFn(navigate);
      done.current = true;
    }
  }, [navigate]);

  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/onboarding" element={<ProtectedRoute><Onboarding /></ProtectedRoute>} />
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan-logs" element={<ScanLogs />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/keys" element={<APIKeys />} />
        <Route path="/docs" element={<Docs />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </ThemeProvider>
  );
}
