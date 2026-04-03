/**
 * Sidebar — FIXED v1.2
 *
 * Fixes applied:
 * HIGH-8  — Removed independent /dashboard/stats fetch.
 *           Alert count and org data are passed as props from Layout (shared state).
 * HIGH-10 — Usage bar now reflects live org data passed from Layout (no stale snapshot).
 */
import React from 'react';
import { NavLink } from 'react-router-dom';
import { Home, FileText, Bell, Key, Settings, Shield, BookOpen } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export const Sidebar = ({ onClose, alertCount = 0 }) => {
  const { org } = useAuth();

  const navItems = [
    { path: '/dashboard', icon: Home,     label: 'Overview'  },
    { path: '/scan-logs', icon: FileText,  label: 'Scan Logs' },
    { path: '/alerts',    icon: Bell,      label: 'Alerts',    badge: alertCount },
    { path: '/keys',      icon: Key,       label: 'API Keys'  },
    { path: '/docs',      icon: BookOpen,  label: 'Docs'      },
    { path: '/settings',  icon: Settings,  label: 'Settings'  },
  ];

  const scanCount  = org?.scan_count_month  || 0;
  const scanLimit  = org?.scan_limit_month  || 10000;
  const usagePercent = Math.min((scanCount / scanLimit) * 100, 100);

  const usageColor =
    usagePercent > 95 ? 'var(--color-danger)' :
    usagePercent > 80 ? 'var(--color-warning)' :
    'var(--color-brand)';

  return (
    <aside
      style={{
        width: '200px',
        backgroundColor: 'var(--color-bg)',
        borderRight: '1px solid var(--color-border)',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}
      data-testid="sidebar"
    >
      {/* Logo */}
      <div style={{
        height: '56px',
        display: 'flex',
        alignItems: 'center',
        gap: '9px',
        padding: '0 16px',
        borderBottom: '1px solid var(--color-border)',
        flexShrink: 0,
      }}>
        <div style={{
          width: '26px', height: '26px',
          backgroundColor: 'var(--color-brand)',
          borderRadius: '7px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Shield style={{ width: '14px', height: '14px', color: '#080B14' }} />
        </div>
        <span style={{
          fontSize: '15px', fontWeight: 700,
          color: 'var(--color-text-primary)',
          letterSpacing: '-0.2px',
        }}>
          Zerofalse
        </span>
      </div>

      {/* Nav */}
      <nav style={{ padding: '10px 8px', flex: 1, overflowY: 'auto' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={onClose}
              data-testid={`nav-${item.label.toLowerCase().replace(' ', '-')}`}
              style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: '9px',
                padding: '9px 10px 9px 12px',
                borderRadius: 'var(--radius-md)',
                fontSize: 'var(--text-sm)',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--color-brand)' : 'var(--color-text-secondary)',
                backgroundColor: isActive ? 'var(--color-brand-subtle)' : 'transparent',
                marginBottom: '2px',
                cursor: 'pointer',
                transition: 'var(--transition-fast)',
                textDecoration: 'none',
                position: 'relative',
                borderLeft: isActive ? '2px solid var(--color-brand)' : '2px solid transparent',
              })}
            >
              {({ isActive }) => (
                <>
                  <Icon style={{
                    width: '17px', height: '17px',
                    color: isActive ? 'var(--color-brand)' : 'var(--color-text-secondary)',
                    flexShrink: 0,
                  }} />
                  <span style={{ flex: 1 }}>{item.label}</span>
                  {item.badge > 0 && (
                    <span style={{
                      height: '17px', minWidth: '17px', padding: '0 5px',
                      backgroundColor: 'var(--color-danger)', color: '#fff',
                      fontSize: '10px', fontWeight: 700,
                      borderRadius: 'var(--radius-full)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      {item.badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Usage bar — reads from AuthContext org (live, not stale snapshot) */}
      {org && (
        <div style={{
          padding: '14px 16px',
          borderTop: '1px solid var(--color-border)',
          flexShrink: 0,
        }}>
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px',
          }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)' }}>
              SCANS
            </span>
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
              {scanCount.toLocaleString()} / {scanLimit.toLocaleString()}
            </span>
          </div>
          <div className="usage-bar-track">
            <div
              className={`usage-bar-fill${usagePercent > 95 ? ' danger' : usagePercent > 80 ? ' warn' : ''}`}
              style={{ width: `${usagePercent}%`, backgroundColor: usageColor }}
            />
          </div>
        </div>
      )}
    </aside>
  );
};

export default Sidebar;
