import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar }  from './Topbar';
import { setNavigateFn } from '../api/client';
import client from '../api/client';

export const Layout = () => {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [openAlerts, setOpenAlerts]   = useState(0);
  const pollRef = useRef(null);

  // Wire navigate — do NOT null it on unmount (causes window.location fallback)
  useEffect(() => { setNavigateFn(navigate); }, [navigate]);

  const fetchAlerts = useCallback(async () => {
    if (document.hidden) return;
    try {
      const r = await client.get('/api/v1/dashboard/stats');
      setOpenAlerts(r.data.open_alerts || 0);
    } catch { /* non-fatal */ }
  }, []);

  useEffect(() => {
    fetchAlerts();
    pollRef.current = setInterval(fetchAlerts, 30_000);
    const onShow = () => { if (!document.hidden) fetchAlerts(); };
    document.addEventListener('visibilitychange', onShow);
    return () => { clearInterval(pollRef.current); document.removeEventListener('visibilitychange', onShow); };
  }, [fetchAlerts]);

  return (
    <div style={{ display:'flex', height:'100vh', overflow:'hidden', backgroundColor:'var(--color-bg)' }}>
      {sidebarOpen && (
        <div style={{ position:'fixed',inset:0,background:'rgba(0,0,0,0.5)',zIndex:40 }}
             onClick={() => setSidebarOpen(false)} />
      )}
      <div style={{ flexShrink:0 }}>
        <Sidebar onClose={() => setSidebarOpen(false)} alertCount={openAlerts} />
      </div>
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <Topbar onMenuClick={() => setSidebarOpen(v => !v)} openAlerts={openAlerts} />
        <main style={{ flex:1, overflowY:'auto', padding:'24px', backgroundColor:'var(--color-bg)' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};
export default Layout;
