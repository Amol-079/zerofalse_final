/**
 * Dashboard — FIXED v1.2
 *
 * Fixes applied:
 * HIGH-9  — Polling pauses when tab is hidden (document.visibilityState check).
 * MIN-12  — fetch errors now set an error state visible to the user.
 * MIN-14  — eslint-disable removed; feedRows useEffect dependency fixed properly.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight, Copy, Check, ArrowRight, AlertCircle } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../hooks/useAuth';

const DEMO_FEED = [
  { tool: 'run_command',    d: 'block', risk: 0.94 },
  { tool: 'fetch_url',      d: 'allow', risk: 0.08 },
  { tool: 'execute_query',  d: 'warn',  risk: 0.41 },
  { tool: 'send_email',     d: 'allow', risk: 0.12 },
  { tool: 'delete_records', d: 'block', risk: 0.91 },
  { tool: 'search_docs',    d: 'allow', risk: 0.06 },
  { tool: 'write_file',     d: 'warn',  risk: 0.38 },
  { tool: 'query_crm',      d: 'allow', risk: 0.09 },
  { tool: 'exec_shell',     d: 'block', risk: 0.97 },
  { tool: 'read_config',    d: 'allow', risk: 0.04 },
  { tool: 'send_webhook',   d: 'warn',  risk: 0.45 },
  { tool: 'list_files',     d: 'allow', risk: 0.07 },
  { tool: 'run_command',    d: 'block', risk: 0.88 },
  { tool: 'fetch_url',      d: 'allow', risk: 0.11 },
  { tool: 'update_record',  d: 'allow', risk: 0.05 },
];

const DEMO_DISPLAY = {
  total_scans_today: 128,
  blocked_today:     7,
  open_alerts:       1,
  active_agents:     2,
};

const tsNow = () =>
  new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

const D_CFG = {
  block:   { color: 'var(--color-danger)',  label: 'BLOCK' },
  warn:    { color: 'var(--color-warning)', label: 'WARN'  },
  allow:   { color: 'var(--color-success)', label: 'ALLOW' },
  blocked: { color: 'var(--color-danger)',  label: 'BLOCK' },
  flagged: { color: 'var(--color-warning)', label: 'WARN'  },
  allowed: { color: 'var(--color-success)', label: 'ALLOW' },
};

const DecisionText = ({ d }) => {
  const cfg = D_CFG[(d || '').toLowerCase()] || D_CFG.allow;
  return (
    <span style={{ color: cfg.color, fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
      {cfg.label}
    </span>
  );
};

const CopyBtn = ({ text }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1800); }}
      style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', background: 'none', border: 'none', cursor: 'pointer', fontSize: '11px', padding: '4px 8px', borderRadius: '6px', color: copied ? 'var(--color-brand)' : 'var(--color-text-muted)', transition: 'var(--transition-fast)', fontFamily: 'var(--font-sans)' }}
      onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.06)'}
      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
    >
      {copied ? <Check style={{ width: '12px', height: '12px' }} /> : <Copy style={{ width: '12px', height: '12px' }} />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
};

const Dashboard = () => {
  const navigate    = useNavigate();
  const { org }     = useAuth();

  const [stats, setStats]             = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [isLoading, setIsLoading]     = useState(true);
  const [fetchError, setFetchError]   = useState(false);  // MIN-12 FIX
  const [feedRows, setFeedRows]       = useState([]);
  const [newRowIds, setNewRowIds]     = useState(new Set());
  const [flashIds, setFlashIds]       = useState(new Set());

  const demoIdx    = useRef(0);
  const pollRef    = useRef(null);
  const lastScanId = useRef(null);

  const fetchData = useCallback(async () => {
    // HIGH-9 FIX: Don't poll when tab is hidden
    if (document.hidden) return;
    try {
      const [sRes, hRes] = await Promise.all([
        client.get('/api/v1/dashboard/stats'),
        client.get('/api/v1/scan/history?limit=20'),
      ]);
      setStats(sRes.data);
      setRecentScans(hRes.data.scans || []);
      setFetchError(false);
    } catch {
      setFetchError(true);  // MIN-12 FIX: track error
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    pollRef.current = setInterval(fetchData, 8000);

    // HIGH-9 FIX: Resume polling when tab becomes visible
    const onVisibility = () => { if (!document.hidden) fetchData(); };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      clearInterval(pollRef.current);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [fetchData]);

  const isDemo = isLoading ? false : (!stats || (stats.total_scans_month ?? 0) === 0);

  const display = isDemo ? DEMO_DISPLAY : {
    total_scans_today: stats?.total_scans_today ?? 0,
    blocked_today:     stats?.blocked_today      ?? 0,
    open_alerts:       stats?.open_alerts        ?? 0,
    active_agents:     stats?.active_agents      ?? 0,
  };

  // MIN-14 FIX: Proper dependency array — seed feed when both loading+demo are stable
  useEffect(() => {
    if (isLoading) return;
    if (isDemo) {
      setFeedRows(DEMO_FEED.slice(0, 8).map((item, i) => ({ id: `ds-${i}`, ...item, time: tsNow() })));
    } else {
      setFeedRows(recentScans.slice(0, 8).map((s, i) => ({
        id:   s.id || `rs-${i}`,
        tool: s.tool_name || 'unknown',
        d:    s.decision  || 'allow',
        risk: typeof s.risk_score === 'number' ? s.risk_score : 0,
        time: s.created_at ? new Date(s.created_at).toLocaleTimeString('en-US', { hour12: false }) : tsNow(),
      })));
    }
  }, [isLoading, isDemo, recentScans]); // MIN-14 FIX: recentScans included

  // Demo ticker
  useEffect(() => {
    if (!isDemo || isLoading) return;
    const id = setInterval(() => {
      const item = DEMO_FEED[demoIdx.current % DEMO_FEED.length];
      demoIdx.current++;
      const rid = `dl-${Date.now()}`;
      setFeedRows(prev => [{ id: rid, ...item, time: tsNow() }, ...prev.slice(0, 13)]);
      setNewRowIds(prev => new Set([...prev, rid]));
      if (item.d === 'block') {
        setFlashIds(prev => new Set([...prev, rid]));
        setTimeout(() => setFlashIds(prev => { const n = new Set(prev); n.delete(rid); return n; }), 800);
      }
      setTimeout(() => setNewRowIds(prev => { const n = new Set(prev); n.delete(rid); return n; }), 300);
    }, 1500);
    return () => clearInterval(id);
  }, [isDemo, isLoading]);

  // Real ticker
  useEffect(() => {
    if (isDemo || !recentScans.length) return;
    const newest = recentScans[0];
    if (!newest?.id || newest.id === lastScanId.current) return;
    lastScanId.current = newest.id;
    setFeedRows(prev => {
      if (prev.find(r => r.id === newest.id)) return prev;
      return [
        { id: newest.id, tool: newest.tool_name || 'unknown', d: newest.decision || 'allow', risk: newest.risk_score || 0, time: newest.created_at ? new Date(newest.created_at).toLocaleTimeString('en-US', { hour12: false }) : tsNow() },
        ...prev.slice(0, 13),
      ];
    });
    setNewRowIds(prev => new Set([...prev, newest.id]));
    setTimeout(() => setNewRowIds(prev => { const n = new Set(prev); n.delete(newest.id); return n; }), 300);
  }, [recentScans, isDemo]);

  const decisions = (isDemo ? DEMO_FEED : recentScans.map(s => ({ tool: s.tool_name, d: (s.decision||'allow').toLowerCase(), risk: s.risk_score || 0 })))
    .filter(s => s.d === 'block' || s.d === 'warn')
    .slice(0, 5);

  if (isLoading) {
    return (
      <div className="page-transition" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {[44, 280, 200].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 10 }} />)}
      </div>
    );
  }

  return (
    <div className="page-transition" data-testid="dashboard-page" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

      {/* MIN-12 FIX: Backend error banner */}
      {fetchError && !isDemo && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          padding: '12px 16px',
          backgroundColor: 'var(--color-warning-bg)', border: '1px solid var(--color-warning-border)',
          borderRadius: 'var(--radius-lg)',
        }}>
          <AlertCircle style={{ width: '16px', height: '16px', color: 'var(--color-warning)', flexShrink: 0 }} />
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-warning)' }}>
            Unable to reach the backend — showing last known data. Retrying…
          </span>
        </div>
      )}

      {/* STATUS BAR */}
      <div id="status-final" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '11px 16px', flexWrap: 'wrap', gap: '10px', backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0, backgroundColor: 'var(--color-success)', display: 'inline-block', animation: 'pulseDot 2s ease-in-out infinite' }} />
          <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-brand)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>ACTIVE</span>
          <span style={{ color: 'var(--color-border)' }}>·</span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
            {isDemo ? 'Connect your agent to start' : `Protecting ${display.active_agents} agent${display.active_agents !== 1 ? 's' : ''}`}
          </span>
        </div>
        {!isDemo && (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            {display.total_scans_today.toLocaleString()} scans today
          </span>
        )}
      </div>

      {/* DEMO BANNER */}
      {isDemo && (
        <div className="demo-banner" id="demo-final">
          <span>⚡</span> Demo data — connect your agent to see live results
        </div>
      )}

      {/* LIVE FEED */}
      <div id="live-feed-final" style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr 72px 68px', padding: '8px 16px', borderBottom: '1px solid var(--color-border)', backgroundColor: 'var(--color-bg)' }}>
          {['TIME','TOOL','DECISION','RISK'].map(h => (
            <span key={h} style={{ fontSize: '10px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>{h}</span>
          ))}
        </div>
        <div style={{ minHeight: '260px' }}>
          {feedRows.map(row => (
            <div key={row.id} style={{
              display: 'grid', gridTemplateColumns: '90px 1fr 72px 68px',
              padding: '7px 16px', alignItems: 'center',
              borderBottom: '1px solid rgba(255,255,255,0.03)',
              animation: newRowIds.has(row.id) ? 'fadeUp 0.2s ease forwards' : 'none',
              backgroundColor: flashIds.has(row.id) ? 'rgba(239,68,68,0.07)' : 'transparent',
              transition: 'background-color 0.5s ease',
            }}>
              <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>[{row.time}]</span>
              <span style={{ fontSize: '12px', color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.tool}</span>
              <DecisionText d={row.d} />
              <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>{typeof row.risk === 'number' ? row.risk.toFixed(2) : '0.00'}</span>
            </div>
          ))}
          {feedRows.length === 0 && (
            <div style={{ padding: '48px 16px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>Waiting for scan events…</div>
          )}
        </div>
      </div>

      {/* DECISIONS + METRICS */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>

        {/* Recent Decisions */}
        <div id="decisions-final" style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--color-border)' }}>
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Recent Decisions</span>
            <button onClick={() => navigate('/scan-logs')} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '11px', color: 'var(--color-brand)', display: 'flex', alignItems: 'center', gap: '3px', fontFamily: 'var(--font-sans)' }}>
              View all <ArrowRight style={{ width: '12px', height: '12px' }} />
            </button>
          </div>
          <div>
            {decisions.length === 0 ? (
              <div style={{ padding: '28px 16px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>No blocked or warned calls yet</div>
            ) : decisions.map((item, i) => (
              <div key={i} onClick={() => navigate('/scan-logs')} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '9px 16px', borderBottom: i < decisions.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none', cursor: 'pointer', transition: 'var(--transition-fast)' }}
                onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.03)'}
                onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <span style={{ flex: 1, fontSize: '12px', color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.tool}</span>
                <DecisionText d={item.d} />
                <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', minWidth: '40px', textAlign: 'right' }}>{typeof item.risk === 'number' ? item.risk.toFixed(2) : '0.00'}</span>
                <ChevronRight style={{ width: '13px', height: '13px', color: 'var(--color-text-muted)', flexShrink: 0 }} />
              </div>
            ))}
          </div>
        </div>

        {/* Metrics */}
        <div id="metrics-final" style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Metrics</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            {[
              { label: 'SCANS TODAY',     value: (display.total_scans_today ?? 0).toLocaleString(), color: 'var(--color-text-primary)' },
              { label: 'THREATS BLOCKED', value: (display.blocked_today     ?? 0).toLocaleString(), color: 'var(--color-danger)'       },
              { label: 'OPEN ALERTS',     value: (display.open_alerts       ?? 0).toLocaleString(), color: 'var(--color-warning)'      },
              { label: 'ACTIVE AGENTS',   value: (display.active_agents     ?? 0).toLocaleString(), color: 'var(--color-brand)'        },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <div style={{ fontSize: 'clamp(20px,2.5vw,28px)', fontWeight: 800, color, fontFamily: 'var(--font-mono)', letterSpacing: '-0.5px', lineHeight: 1 }}>{value}</div>
                <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: '4px', fontWeight: 600 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ACTIVATION BLOCK — only when isDemo */}
      {isDemo && (
        <div style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-brand-border)', borderRadius: 'var(--radius-lg)', padding: '24px' }}>
          <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>Start protecting your agent</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
            {[
              { n: '1', label: 'Install',        code: 'pip install zerofalse',             codeColor: 'var(--color-success)' },
              { n: '2', label: 'Wrap your tool', code: '@guard_tool(agent_id="my-agent")',  codeColor: 'var(--color-brand)'   },
              { n: '3', label: 'Run your agent', code: "# That's it — you're protected",    codeColor: 'var(--color-text-muted)', noCopy: true },
            ].map(step => (
              <div key={step.n} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{ width: '20px', height: '20px', borderRadius: '50%', flexShrink: 0, backgroundColor: 'var(--color-brand-light)', border: '1px solid var(--color-brand-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '10px', fontWeight: 700, color: 'var(--color-brand)', marginTop: '2px' }}>
                  {step.n}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>{step.label}</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', backgroundColor: 'var(--color-elevated)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: '7px 12px' }}>
                    <code style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: step.codeColor }}>{step.code}</code>
                    {!step.noCopy && <CopyBtn text={step.code} />}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <button onClick={() => navigate('/keys')} className="btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: '7px' }}>
            Create API Key <ArrowRight style={{ width: '15px', height: '15px' }} />
          </button>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
