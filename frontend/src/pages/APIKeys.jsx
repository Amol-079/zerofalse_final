/**
 * APIKeys page — FIXED v1.3
 *
 * Fixes applied:
 * HIGH-11 — Error states shown inline for create and delete failures.
 * BUG-FETCH — fetchKeys() silently swallowed errors (console.error only).
 *             User saw infinite spinner on network failure. Now shows inline error.
 */
import React, { useState, useEffect } from 'react';
import { Key, Plus, Copy, Trash2, Eye, EyeOff, Check, AlertCircle, Clock, Shield, X } from 'lucide-react';
import client from '../api/client';

const APIKeys = () => {
  const [keys, setKeys]                 = useState([]);
  const [isLoading, setIsLoading]       = useState(true);
  const [fetchError, setFetchError]     = useState('');     // BUG-FETCH fix
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(null);
  const [newKeyName, setNewKeyName]     = useState('');
  const [createdKey, setCreatedKey]     = useState(null);
  const [copiedId, setCopiedId]         = useState(null);
  const [isCreating, setIsCreating]     = useState(false);
  const [visibleKeys, setVisibleKeys]   = useState({});
  const [createError, setCreateError]   = useState('');
  const [deleteError, setDeleteError]   = useState('');

  useEffect(() => { fetchKeys(); }, []);

  const fetchKeys = async () => {
    setIsLoading(true);
    setFetchError('');
    try {
      const response = await client.get('/api/v1/keys/');
      setKeys(Array.isArray(response.data) ? response.data : (response.data.keys || []));
    } catch (error) {
      // BUG-FETCH FIX: Show error to user instead of silent console.error
      setFetchError(error.response?.data?.detail || 'Failed to load API keys. Please refresh.');
    } finally {
      setIsLoading(false);
    }
  };

  const createKey = async () => {
    if (!newKeyName.trim()) return;
    setIsCreating(true);
    setCreateError('');
    try {
      const response = await client.post('/api/v1/keys/', { name: newKeyName });
      setCreatedKey(response.data);
      setNewKeyName('');
      fetchKeys();
    } catch (error) {
      setCreateError(error.response?.data?.detail || 'Failed to create key. Please try again.');
    } finally {
      setIsCreating(false);
    }
  };

  const deleteKey = async (keyId) => {
    setDeleteError('');
    try {
      await client.delete(`/api/v1/keys/${keyId}`);
      setKeys(prev => prev.filter(k => k.id !== keyId));
      setShowDeleteModal(null);
    } catch (error) {
      setDeleteError(error.response?.data?.detail || 'Failed to revoke key. Please try again.');
    }
  };

  const copyToClipboard = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {}
  };

  const maskKey = (key) => {
    if (!key) return '••••••••••••••••';
    return key.substring(0, 8) + '••••••••••••••••';
  };

  return (
    <div className="page-transition" data-testid="api-keys-page">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>API Keys</h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>Manage your API keys for authentication</p>
        </div>
        <button
          onClick={() => { setShowCreateModal(true); setCreateError(''); }}
          style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 18px', backgroundColor: 'var(--color-brand)', color: '#080B14', border: 'none', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)', fontWeight: 600, cursor: 'pointer' }}
          data-testid="create-key-btn"
        >
          <Plus style={{ width: '18px', height: '18px' }} />
          Create New Key
        </button>
      </div>

      {/* Info Banner */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '16px 20px', backgroundColor: 'var(--color-info-bg)', borderRadius: 'var(--radius-lg)', border: '1px solid rgba(59,130,246,0.2)', marginBottom: '24px' }}>
        <Shield style={{ width: '20px', height: '20px', color: 'var(--color-info)', flexShrink: 0, marginTop: '2px' }} />
        <div>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>Keep your API keys secure</div>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
            API keys grant access to your organization's scan data. Never share keys in public repositories or client-side code.
          </p>
        </div>
      </div>

      {/* Fetch error */}
      {fetchError && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 16px', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger-border)', borderRadius: 'var(--radius-md)', marginBottom: '16px', color: 'var(--color-danger)', fontSize: 'var(--text-sm)' }}>
          <AlertCircle style={{ width: '16px', height: '16px', flexShrink: 0 }} />
          {fetchError}
          <button onClick={fetchKeys} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--color-brand)', cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600 }}>Retry</button>
        </div>
      )}

      {/* Keys List */}
      <div style={{ backgroundColor: 'var(--color-bg)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--color-border)', overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: '48px', textAlign: 'center' }}>
            <div style={{ width: '32px', height: '32px', border: '3px solid var(--color-border)', borderTopColor: 'var(--color-brand)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto' }} />
          </div>
        ) : keys.length === 0 && !fetchError ? (
          <div style={{ padding: '64px 24px', textAlign: 'center' }}>
            <Key style={{ width: '48px', height: '48px', color: 'var(--color-text-muted)', margin: '0 auto 16px' }} />
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '8px' }}>No API keys yet</h3>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', maxWidth: '300px', margin: '0 auto 24px' }}>Create your first API key to start scanning tool calls</p>
            <button onClick={() => { setShowCreateModal(true); setCreateError(''); }} style={{ padding: '10px 20px', backgroundColor: 'var(--color-brand)', color: '#080B14', border: 'none', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)', fontWeight: 600, cursor: 'pointer' }}>
              Create API Key
            </button>
          </div>
        ) : (
          <div>
            {keys.map((key, idx) => (
              <div key={key.id} style={{ padding: '16px 20px', borderBottom: idx < keys.length - 1 ? '1px solid var(--color-border)' : 'none', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)' }}>{key.name}</span>
                    <span style={{ fontSize: 'var(--text-xs)', padding: '2px 8px', backgroundColor: key.is_active ? 'var(--color-success-bg)' : 'var(--color-danger-bg)', color: key.is_active ? 'var(--color-success)' : 'var(--color-danger)', borderRadius: 'var(--radius-full)', fontWeight: 600 }}>
                      {key.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <code style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {visibleKeys[key.id] ? key.key_prefix : maskKey(key.key_prefix)}
                    </code>
                    <button onClick={() => setVisibleKeys(p => ({ ...p, [key.id]: !p[key.id] }))} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)', padding: '2px' }}>
                      {visibleKeys[key.id] ? <EyeOff style={{ width: '12px', height: '12px' }} /> : <Eye style={{ width: '12px', height: '12px' }} />}
                    </button>
                  </div>
                  <div style={{ display: 'flex', gap: '16px', marginTop: '4px' }}>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Clock style={{ width: '11px', height: '11px' }} />
                      Created {key.created_at ? new Date(key.created_at).toLocaleDateString() : 'N/A'}
                    </span>
                    {key.total_calls !== undefined && (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                        {key.total_calls.toLocaleString()} calls
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                  <button
                     title="Full key only shown at creation time"
                     disabled
                     style={{ padding: '6px 10px', background: 'none', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', cursor: 'not-allowed', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: 'var(--text-xs)', opacity: 0.4 }}
                     >
                   <Copy style={{ width: '12px', height: '12px' }} />
                 </button>
                  {key.is_active && (
                    <button
                      onClick={() => { setShowDeleteModal(key.id); setDeleteError(''); }}
                      style={{ padding: '6px 10px', background: 'none', border: '1px solid var(--color-danger-border)', borderRadius: 'var(--radius-sm)', cursor: 'pointer', color: 'var(--color-danger)', display: 'flex', alignItems: 'center' }}
                    >
                      <Trash2 style={{ width: '12px', height: '12px' }} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.6)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
          <div style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-xl)', padding: '24px', width: '100%', maxWidth: '440px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                {createdKey ? 'API Key Created' : 'Create API Key'}
              </h3>
              <button onClick={() => { setShowCreateModal(false); setCreatedKey(null); setNewKeyName(''); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)' }}>
                <X style={{ width: '20px', height: '20px' }} />
              </button>
            </div>

            {!createdKey ? (
              <>
                {createError && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 12px', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger-border)', borderRadius: 'var(--radius-sm)', marginBottom: '16px', color: 'var(--color-danger)', fontSize: 'var(--text-sm)' }}>
                    <AlertCircle style={{ width: '14px', height: '14px', flexShrink: 0 }} />
                    {createError}
                  </div>
                )}
                <label style={{ display: 'block', fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '8px' }}>Key Name</label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={e => setNewKeyName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && newKeyName.trim() && !isCreating) createKey(); }}
                  placeholder="e.g. Production Key"
                  autoFocus
                  style={{ width: '100%', padding: '10px 14px', backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', color: 'var(--color-text-primary)', fontSize: 'var(--text-sm)', outline: 'none', boxSizing: 'border-box', marginBottom: '16px' }}
                />
                <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                  <button onClick={() => setShowCreateModal(false)} style={{ padding: '8px 16px', background: 'none', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', color: 'var(--color-text-secondary)', cursor: 'pointer', fontSize: 'var(--text-sm)' }}>Cancel</button>
                  <button onClick={createKey} disabled={!newKeyName.trim() || isCreating} style={{ padding: '8px 16px', backgroundColor: 'var(--color-brand)', border: 'none', borderRadius: 'var(--radius-md)', color: '#080B14', fontWeight: 600, cursor: newKeyName.trim() && !isCreating ? 'pointer' : 'not-allowed', opacity: !newKeyName.trim() || isCreating ? 0.6 : 1, fontSize: 'var(--text-sm)' }}>
                    {isCreating ? 'Creating…' : 'Create Key'}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div style={{ padding: '12px', backgroundColor: 'var(--color-warning-bg)', border: '1px solid var(--color-warning-border)', borderRadius: 'var(--radius-md)', marginBottom: '16px', fontSize: 'var(--text-sm)', color: 'var(--color-warning)' }}>
                  ⚠ Copy this key now — it won't be shown again.
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', marginBottom: '16px' }}>
                  <code style={{ flex: 1, fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>{createdKey.full_key}</code>
                  <button onClick={() => copyToClipboard(createdKey.full_key, 'new')} style={{ flexShrink: 0, padding: '6px', background: 'none', border: 'none', cursor: 'pointer', color: copiedId === 'new' ? 'var(--color-brand)' : 'var(--color-text-muted)' }}>
                    {copiedId === 'new' ? <Check style={{ width: '16px', height: '16px' }} /> : <Copy style={{ width: '16px', height: '16px' }} />}
                  </button>
                </div>
                <button onClick={() => { setShowCreateModal(false); setCreatedKey(null); }} style={{ width: '100%', padding: '10px', backgroundColor: 'var(--color-brand)', border: 'none', borderRadius: 'var(--radius-md)', color: '#080B14', fontWeight: 600, cursor: 'pointer', fontSize: 'var(--text-sm)' }}>Done</button>
              </>
            )}
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.6)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
          <div style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-xl)', padding: '24px', width: '100%', maxWidth: '380px' }}>
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '12px' }}>Revoke API Key?</h3>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginBottom: '16px' }}>This action cannot be undone. Any integrations using this key will stop working immediately.</p>
            {deleteError && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 12px', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger-border)', borderRadius: 'var(--radius-sm)', marginBottom: '12px', color: 'var(--color-danger)', fontSize: 'var(--text-sm)' }}>
                <AlertCircle style={{ width: '14px', height: '14px' }} />
                {deleteError}
              </div>
            )}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button onClick={() => { setShowDeleteModal(null); setDeleteError(''); }} style={{ padding: '8px 16px', background: 'none', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', color: 'var(--color-text-secondary)', cursor: 'pointer', fontSize: 'var(--text-sm)' }}>Cancel</button>
              <button onClick={() => deleteKey(showDeleteModal)} style={{ padding: '8px 16px', backgroundColor: 'var(--color-danger)', border: 'none', borderRadius: 'var(--radius-md)', color: 'white', fontWeight: 600, cursor: 'pointer', fontSize: 'var(--text-sm)' }}>Revoke Key</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APIKeys;
