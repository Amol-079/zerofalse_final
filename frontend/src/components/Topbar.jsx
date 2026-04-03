/**
 * Topbar — FIXED v1.2
 *
 * Fixes applied:
 * HIGH-8  — No longer calls /dashboard/stats on every route change.
 *           Alert count is now read from a shared AlertContext (or AuthContext refresh)
 *           instead of making an independent API call per navigation.
 * HIGH-5  — Logout uses Clerk's signOut (already correct), confirmed no window.location.
 */
import React, { useState } from 'react';
import { useClerk } from '@clerk/clerk-react';
import { Bell, Menu, Settings, LogOut } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const PAGE_TITLES = {
  '/dashboard': 'Overview',
  '/scan-logs': 'Scan Logs',
  '/alerts':    'Alerts',
  '/keys':      'API Keys',
  '/docs':      'Docs',
  '/settings':  'Settings',
};

export const Topbar = ({ onMenuClick, openAlerts = 0 }) => {
  const { user } = useAuth();
  const { signOut } = useClerk();
  const navigate = useNavigate();
  const location = useLocation();
  const [showDropdown, setShowDropdown] = useState(false);

  const pageTitle = PAGE_TITLES[location.pathname] || 'Dashboard';

  const handleLogout = () => {
    signOut(() => navigate('/'));
  };

  const getInitials = () => {
    const name = user?.full_name || user?.email || '';
    if (!name) return 'U';
    const parts = name.split(/[\s@]/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name[0].toUpperCase();
  };

  return (
    <header
      style={{
        height: '56px',
        backgroundColor: 'var(--color-bg)',
        borderBottom: '1px solid var(--color-border)',
        padding: '0 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}
      data-testid="topbar"
    >
      {/* Left */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button
          onClick={onMenuClick}
          aria-label="Toggle sidebar"
          className="mobile-menu-btn"
          style={{
            display: 'none',
            width: '32px', height: '32px',
            alignItems: 'center', justifyContent: 'center',
            background: 'none', border: 'none',
            borderRadius: 'var(--radius-md)',
            cursor: 'pointer',
            color: 'var(--color-text-secondary)',
          }}
        >
          <Menu style={{ width: '18px', height: '18px' }} />
        </button>
        <h1 style={{
          fontSize: '16px',
          fontWeight: 600,
          color: 'var(--color-text-primary)',
          letterSpacing: '-0.1px',
        }}>
          {pageTitle}
        </h1>
      </div>

      {/* Right */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
        {/* Bell — openAlerts prop passed from Layout (shared, no extra API call) */}
        <button
          onClick={() => navigate('/alerts')}
          aria-label={`Alerts${openAlerts > 0 ? ` — ${openAlerts} open` : ''}`}
          style={{
            width: '34px', height: '34px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            borderRadius: 'var(--radius-md)',
            background: 'none', border: 'none',
            cursor: 'pointer',
            position: 'relative',
            color: 'var(--color-text-secondary)',
            transition: 'var(--transition-fast)',
          }}
          onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
          onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
          data-testid="notifications-btn"
        >
          <Bell style={{ width: '17px', height: '17px' }} />
          {openAlerts > 0 && (
            <span style={{
              position: 'absolute', top: '7px', right: '7px',
              width: '7px', height: '7px',
              backgroundColor: 'var(--color-danger)',
              borderRadius: '50%',
              border: '1.5px solid var(--color-bg)',
            }} />
          )}
        </button>

        <div style={{ width: '1px', height: '18px', backgroundColor: 'var(--color-border)', margin: '0 4px' }} />

        {/* User dropdown */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowDropdown(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              padding: '5px 8px',
              background: 'none', border: 'none',
              borderRadius: 'var(--radius-md)',
              cursor: 'pointer',
              transition: 'var(--transition-fast)',
            }}
            onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
            onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
            data-testid="user-menu"
          >
            <div style={{
              width: '28px', height: '28px',
              borderRadius: '50%',
              backgroundColor: 'var(--color-brand-light)',
              border: '1px solid var(--color-brand-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '11px', fontWeight: 700,
              color: 'var(--color-brand)',
              flexShrink: 0,
            }}>
              {getInitials()}
            </div>
            <span style={{
              fontSize: 'var(--text-sm)',
              fontWeight: 500,
              color: 'var(--color-text-primary)',
              maxWidth: '120px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}>
              {user?.email?.split('@')[0] || 'Account'}
            </span>
          </button>

          {showDropdown && (
            <>
              <div
                style={{ position: 'fixed', inset: 0, zIndex: 10 }}
                onClick={() => setShowDropdown(false)}
              />
              <div style={{
                position: 'absolute', top: '100%', right: 0, marginTop: '6px',
                backgroundColor: 'var(--color-surface)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)',
                minWidth: '160px',
                zIndex: 20, overflow: 'hidden',
                animation: 'fadeUp 0.15s ease',
              }}>
                <button
                  onClick={() => { setShowDropdown(false); navigate('/settings'); }}
                  style={{
                    width: '100%', padding: '10px 14px',
                    display: 'flex', alignItems: 'center', gap: '9px',
                    fontSize: 'var(--text-sm)', color: 'var(--color-text-primary)',
                    backgroundColor: 'transparent', border: 'none',
                    textAlign: 'left', cursor: 'pointer',
                    transition: 'var(--transition-fast)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <Settings style={{ width: '15px', height: '15px', color: 'var(--color-text-muted)' }} />
                  Settings
                </button>
                <div style={{ height: '1px', backgroundColor: 'var(--color-border)' }} />
                <button
                  onClick={handleLogout}
                  style={{
                    width: '100%', padding: '10px 14px',
                    display: 'flex', alignItems: 'center', gap: '9px',
                    fontSize: 'var(--text-sm)', color: 'var(--color-danger)',
                    backgroundColor: 'transparent', border: 'none',
                    textAlign: 'left', cursor: 'pointer',
                    transition: 'var(--transition-fast)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-danger-bg)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                  data-testid="logout-btn"
                >
                  <LogOut style={{ width: '15px', height: '15px' }} />
                  Log Out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
};

export default Topbar;
