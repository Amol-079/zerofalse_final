import React, { useState, useEffect } from 'react';
import { Search, X, ChevronDown } from 'lucide-react';
import client from '../api/client';

// ─── Demo data — only shown when API returns 0 alerts ────────────────────
const DEMO_ALERTS = [
  {
    id: 'da1', title: 'Shell injection blocked', severity: 'critical', status: 'open',
    description: 'A shell injection pattern was detected in run_command arguments. Execution was stopped before any damage occurred.',
    tool_name: 'run_command', risk_score: 94, created_at: null,
  },
  {
    id: 'da2', title: 'Prompt injection attempt', severity: 'high', status: 'open',
    description: 'Instruction-override language detected in send_email tool arguments.',
    tool_name: 'send_email', risk_score: 76, created_at: null,
  },
  {
    id: 'da3', title: 'Path traversal blocked', severity: 'medium', status: 'acknowledged',
    description: 'Path traversal pattern (../../) detected in write_file path argument.',
    tool_name: 'write_file', risk_score: 55, created_at: null,
  },
];

const DEMO_TIMES = ['2m ago', '8m ago', '23m ago'];

const severityColor = s => {
  if (s === 'critical' || s === 'high') return 'var(--color-danger)';
  if (s === 'medium') return 'var(--color-warning)';
  return 'var(--color-info)';
};

const statusColor = s => {
  if (s === 'open')         return 'var(--color-danger)';
  if (s === 'acknowledged') return 'var(--color-warning)';
  return 'var(--color-success)';
};

const Alerts = () => {
  const [alerts, setAlerts]         = useState([]);
  const [isLoading, setIsLoading]   = useState(true);
  const [isDemo, setIsDemo]         = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus]     = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [selectedAlert, setSelectedAlert]   = useState(null);
  const [showStatusDD, setShowStatusDD]     = useState(false);
  const [showSeverityDD, setShowSeverityDD] = useState(false);

  useEffect(() => { fetchAlerts(); }, [filterStatus, filterSeverity]);

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (filterStatus !== 'all')   params.append('status',   filterStatus);
      if (filterSeverity !== 'all') params.append('severity', filterSeverity);

      const res = await client.get(`/api/v1/alerts/?${params}`);

      // Backend returns plain array directly (not {alerts: []})
      const data = Array.isArray(res.data) ? res.data : (res.data.alerts || []);

      if (data.length === 0) {
        setIsDemo(true);
        setAlerts(DEMO_ALERTS);
      } else {
        setIsDemo(false);
        setAlerts(data);
      }
    } catch {
      setIsDemo(true);
      setAlerts(DEMO_ALERTS);
    } finally {
      setIsLoading(false);
    }
  };

  // ── Status update — uses the correct backend endpoints ───────────────────
  // Real backend has: PATCH /api/v1/alerts/{id}/acknowledge
  //                   PATCH /api/v1/alerts/{id}/resolve
  // There is no generic PATCH /{id} with a status body.
  const updateStatus = async (id, newStatus) => {
    // Optimistically update UI immediately
    const update = prev => prev.map(a => a.id === id ? { ...a, status: newStatus } : a);
    setAlerts(update);
    if (selectedAlert?.id === id) setSelectedAlert(prev => ({ ...prev, status: newStatus }));

    if (isDemo) return; // demo mode — don't hit API

    try {
      if (newStatus === 'acknowledged') {
        await client.patch(`/api/v1/alerts/${id}/acknowledge`);
      } else if (newStatus === 'resolved') {
        await client.patch(`/api/v1/alerts/${id}/resolve`);
      }
      // 'open' has no dedicated endpoint — refetch to sync
      if (newStatus === 'open') fetchAlerts();
    } catch {
      // If API fails, refetch to get real state
      fetchAlerts();
    }
  };

  const filtered = alerts.filter(a => {
    if (filterStatus   !== 'all' && a.status   !== filterStatus)   return false;
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (a.title || '').toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q);
  });

  const stats = {
    open:         alerts.filter(a => a.status === 'open').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved:     alerts.filter(a => a.status === 'resolved').length,
  };

  const Dropdown = ({ show, setShow, value, setValue, label, options }) => (
    <div style={{ position: 'relative' }}>
      <button onClick={() => setShow(v => !v)} className="btn-secondary" style={{ padding: '8px 12px', gap: '6px', fontSize: 'var(--text-xs)', fontWeight: 600 }}>
        {label}: {value === 'all' ? 'All' : value.charAt(0).toUpperCase() + value.slice(1)}
        <ChevronDown style={{ width: '12px', height: '12px' }} />
      </button>
      {show && (
        <>
          <div style={{ position: 'fixed', inset: 0, zIndex: 10 }} onClick={() => setShow(false)} />
          <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: '4px', backgroundColor: 'var(--color-elevated)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', minWidth: '150px', zIndex: 20, overflow: 'hidden', animation: 'fadeUp 0.15s ease' }}>
            {options.map(opt => (
              <button key={opt} onClick={() => { setValue(opt); setShow(false); }} style={{ width: '100%', padding: '9px 14px', backgroundColor: value === opt ? 'var(--color-brand-subtle)' : 'transparent', color: value === opt ? 'var(--color-brand)' : 'var(--color-text-primary)', border: 'none', fontSize: 'var(--text-sm)', textAlign: 'left', cursor: 'pointer', textTransform: 'capitalize', transition: 'var(--transition-fast)' }}
                onMouseEnter={e => { if (value !== opt) e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)'; }}
                onMouseLeave={e => { if (value !== opt) e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                {opt === 'all' ? `All ${label}s` : opt}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );

  return (
    <div className="page-transition" data-testid="alerts-page">

      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '3px' }}>Alerts</h1>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>Security incidents requiring attention</p>
      </div>

      {/* Demo banner */}
      {isDemo && (
        <div className="demo-banner" style={{ marginBottom: '16px' }}>
          <span>⚡</span> Demo data — connect your agent to see real alerts
        </div>
      )}

      {/* Metrics strip */}
      <div id="alerts-top" style={{ display: 'flex', alignItems: 'center', gap: '32px', padding: '14px 20px', backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', marginBottom: '16px', flexWrap: 'wrap' }}>
        {[
          { label: 'OPEN',         value: stats.open,         color: 'var(--color-danger)'  },
          { label: 'ACKNOWLEDGED', value: stats.acknowledged, color: 'var(--color-warning)' },
          { label: 'RESOLVED',     value: stats.resolved,     color: 'var(--color-success)' },
        ].map(({ label, value, color }, i) => (
          <React.Fragment key={label}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <span style={{ fontSize: '22px', fontWeight: 800, color, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>{value}</span>
              <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</span>
            </div>
            {i < 2 && <div style={{ width: '1px', height: '20px', backgroundColor: 'var(--color-border)' }} />}
          </React.Fragment>
        ))}
      </div>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ flex: 1, minWidth: '200px', position: 'relative' }}>
          <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '15px', height: '15px', color: 'var(--color-text-muted)' }} />
          <input type="text" placeholder="Search alerts…" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} style={{ paddingLeft: '36px' }} data-testid="search-alerts" />
        </div>
        <Dropdown show={showStatusDD}   setShow={setShowStatusDD}   value={filterStatus}   setValue={setFilterStatus}   label="Status"   options={['all','open','acknowledged','resolved']} />
        <Dropdown show={showSeverityDD} setShow={setShowSeverityDD} value={filterSeverity} setValue={setFilterSeverity} label="Severity" options={['all','critical','high','medium','low']} />
      </div>

      {/* Alerts */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {isLoading ? (
          [1,2,3].map(i => <div key={i} className="skeleton" style={{ height: '90px', borderRadius: '10px' }} />)
        ) : filtered.length === 0 ? (
          <div style={{ padding: '56px 24px', textAlign: 'center', backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>No active threats</div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
              {searchQuery || filterStatus !== 'all' || filterSeverity !== 'all' ? 'Try adjusting your filters' : 'Your agent activity is currently safe.'}
            </div>
          </div>
        ) : filtered.map((alert, idx) => (
          <div key={alert.id || idx} id="alert-row"
            className={`alert-${alert.severity}`}
            style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', padding: '16px 20px' }}
            data-testid={`alert-row-${idx}`}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: severityColor(alert.severity), textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    [{(alert.severity || 'unknown').toUpperCase()}]
                  </span>
                  <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>{alert.title || 'Untitled Alert'}</span>
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: '10px', lineHeight: 1.5 }}>
                  {alert.description || 'No description provided'}
                </p>
                <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {alert.tool_name  && <span>tool: <span style={{ color: 'var(--color-text-secondary)' }}>{alert.tool_name}</span></span>}
                  {alert.risk_score && <span>risk: <span style={{ color: severityColor(alert.severity) }}>{alert.risk_score}%</span></span>}
                  <span style={{ fontFamily: 'var(--font-sans)', color: 'var(--color-text-muted)' }}>
                    {alert.created_at ? new Date(alert.created_at).toLocaleString() : (isDemo ? (DEMO_TIMES[idx] || '1h ago') : '—')}
                  </span>
                </div>
              </div>
              <span style={{ fontSize: '11px', fontWeight: 700, color: statusColor(alert.status), textTransform: 'uppercase', letterSpacing: '0.06em', flexShrink: 0 }}>
                {alert.status}
              </span>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '8px', marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--color-border)' }}>
              <button onClick={() => setSelectedAlert(alert)} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '12px' }}>View</button>
              {alert.status !== 'acknowledged' && (
                <button onClick={() => updateStatus(alert.id, 'acknowledged')} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '12px' }}>Acknowledge</button>
              )}
              {alert.status !== 'resolved' && (
                <button onClick={() => updateStatus(alert.id, 'resolved')} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '12px', color: 'var(--color-success)' }}>Resolve</button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Detail modal */}
      {selectedAlert && (
        <>
          <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.65)', zIndex: 50 }} onClick={() => setSelectedAlert(null)} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: '90%', maxWidth: '560px', maxHeight: '80vh', backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-xl)', zIndex: 51, overflow: 'hidden', animation: 'fadeUp 0.15s ease' }}>
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '6px' }}>{selectedAlert.title}</h2>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <span className={`badge badge-${selectedAlert.severity}`}>{selectedAlert.severity}</span>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: statusColor(selectedAlert.status), textTransform: 'uppercase' }}>{selectedAlert.status}</span>
                </div>
              </div>
              <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--color-text-muted)' }}>
                <X style={{ width: '18px', height: '18px' }} />
              </button>
            </div>
            <div style={{ padding: '20px 24px', overflowY: 'auto', maxHeight: 'calc(80vh - 140px)' }}>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: '20px' }}>
                {selectedAlert.description || 'No description provided'}
              </p>
              <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '10px' }}>
                Update Status
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {['open','acknowledged','resolved'].map(s => (
                  <button key={s} onClick={() => updateStatus(selectedAlert.id, s)} style={{ padding: '8px 16px', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)', fontWeight: 500, cursor: 'pointer', backgroundColor: selectedAlert.status === s ? 'var(--color-brand)' : 'var(--color-elevated)', color: selectedAlert.status === s ? '#080B14' : 'var(--color-text-primary)', border: selectedAlert.status === s ? 'none' : '1px solid var(--color-border)', textTransform: 'capitalize', transition: 'var(--transition-fast)' }}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Alerts;
