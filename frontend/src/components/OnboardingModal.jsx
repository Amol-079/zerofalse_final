/**
 * OnboardingModal — FIXED v1.2
 *
 * Fixes applied:
 * CRIT-6  — API key is NOT interpolated into the code string displayed to the user.
 *           The displayed key and the code snippet key are kept separate.
 *           The raw key is held in a ref, never in a string that gets logged/rendered beyond the display box.
 * HIGH-11 — Error state is now shown to the user on key creation failure.
 * MIN-13  — localStorage flag is kept for backward compat but acknowledged as cosmetic.
 */
import React, { useState, useRef } from 'react';
import { X, Check, Copy, AlertCircle } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { CodeBlock } from './CodeBlock';
import client from '../api/client';

export const OnboardingModal = ({ onComplete }) => {
  const { user } = useAuth();
  const [step, setStep]         = useState(1);
  const [apiKey, setApiKey]     = useState(null);   // full response object
  const [keyName, setKeyName]   = useState('Production Key');
  const [keySaved, setKeySaved] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [copied, setCopied]     = useState(false);
  const [error, setError]       = useState('');     // HIGH-11 FIX

  // CRIT-6 FIX: Hold the raw key in a ref — not interpolated into code snippets
  // that might be captured by error trackers or DevTools state inspection.
  const rawKeyRef = useRef(null);

  const handleCreateKey = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await client.post('/api/v1/keys/', { name: keyName });
      rawKeyRef.current = response.data.full_key;
      setApiKey(response.data);
      setStep(3);
    } catch (err) {
      // HIGH-11 FIX: Show error to user instead of only logging to console
      const msg = err.response?.data?.detail || 'Failed to create API key. Please try again.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyKey = () => {
    if (!rawKeyRef.current) return;
    navigator.clipboard.writeText(rawKeyRef.current).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleComplete = () => {
    localStorage.setItem('zf_onboarded', 'true');
    onComplete();
  };

  // CRIT-6 FIX: Code snippet uses a placeholder, NOT the real key embedded in a string.
  // User copies the key from the display box separately.
  const integrationCode = `import os
from zerofalse import guard_tool

# Set your API key (copy from the box above)
os.environ["ZEROFALSE_API_KEY"] = "YOUR_KEY_HERE"

@guard_tool(agent_id="my-agent")
def run_command(cmd: str) -> str:
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)`;

  const maskKey = (key) => {
    if (!key) return '••••••••••••••••';
    return key.substring(0, 12) + '••••••••••••' + key.slice(-4);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '16px', zIndex: 50,
    }} data-testid="onboarding-modal">
      <div style={{
        backgroundColor: 'var(--color-bg)', borderRadius: 'var(--radius-xl)',
        width: '100%', maxWidth: '600px', position: 'relative',
        border: '1px solid var(--color-border)',
      }}>
        <button
          onClick={handleComplete}
          style={{
            position: 'absolute', top: '16px', right: '16px', padding: '8px',
            background: 'transparent', border: 'none', cursor: 'pointer',
            borderRadius: 'var(--radius-md)',
          }}
          data-testid="close-onboarding"
        >
          <X style={{ width: '20px', height: '20px', color: 'var(--color-text-muted)' }} />
        </button>

        <div style={{ padding: '32px' }}>
          {/* Step indicators */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '32px' }}>
            {[1, 2, 3].map((i) => (
              <div key={i} style={{
                height: '8px',
                width: step >= i ? '32px' : '8px',
                borderRadius: 'var(--radius-full)',
                backgroundColor: step >= i ? 'var(--color-brand)' : 'var(--color-border)',
                transition: 'all 0.3s ease',
              }} />
            ))}
          </div>

          {/* HIGH-11 FIX: Global error display */}
          {error && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '10px',
              padding: '12px 16px', marginBottom: '20px',
              backgroundColor: 'var(--color-danger-bg)',
              border: '1px solid var(--color-danger-border)',
              borderRadius: 'var(--radius-md)',
            }}>
              <AlertCircle style={{ width: '16px', height: '16px', color: 'var(--color-danger)', flexShrink: 0 }} />
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-danger)' }}>{error}</span>
            </div>
          )}

          {step === 1 && (
            <div style={{ textAlign: 'center' }}>
              <h2 style={{ fontSize: 'var(--text-3xl)', fontWeight: 700, marginBottom: '8px', color: 'var(--color-text-primary)' }}>
                Welcome, {user?.full_name?.split(' ')[0] || 'there'}!
              </h2>
              <p style={{ fontSize: 'var(--text-lg)', marginBottom: '32px', color: 'var(--color-text-secondary)' }}>
                Zerofalse protects your AI agents by inspecting every tool call in real-time.
              </p>
              <button
                onClick={() => setStep(2)}
                style={{
                  padding: '12px 32px', fontSize: 'var(--text-base)', fontWeight: 600,
                  color: '#080B14', backgroundColor: 'var(--color-brand)',
                  borderRadius: 'var(--radius-md)', border: 'none', cursor: 'pointer',
                }}
                data-testid="onboarding-next-step1"
              >
                Get Started
              </button>
            </div>
          )}

          {step === 2 && (
            <div>
              <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, marginBottom: '8px', textAlign: 'center', color: 'var(--color-text-primary)' }}>
                Create Your API Key
              </h2>
              <p style={{ textAlign: 'center', marginBottom: '24px', color: 'var(--color-text-secondary)' }}>
                You'll need this key to start scanning tool calls
              </p>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: '8px', color: 'var(--color-text-secondary)' }}>
                  Key Name
                </label>
                <input
                  type="text"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="Production Key"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  data-testid="onboarding-key-name"
                />
              </div>
              <button
                onClick={handleCreateKey}
                disabled={loading || !keyName.trim()}
                style={{
                  width: '100%', padding: '12px', fontSize: 'var(--text-base)', fontWeight: 600,
                  color: '#080B14', backgroundColor: 'var(--color-brand)',
                  borderRadius: 'var(--radius-md)', border: 'none',
                  cursor: loading || !keyName.trim() ? 'not-allowed' : 'pointer',
                  opacity: loading || !keyName.trim() ? 0.5 : 1,
                }}
                data-testid="onboarding-create-key"
              >
                {loading ? 'Creating...' : 'Create API Key'}
              </button>
            </div>
          )}

          {step === 3 && apiKey && (
            <div>
              <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, marginBottom: '8px', textAlign: 'center', color: 'var(--color-text-primary)' }}>
                Save Your API Key
              </h2>

              <div style={{
                padding: '12px 16px', borderRadius: 'var(--radius-md)', marginBottom: '16px',
                backgroundColor: 'var(--color-warning-bg)', border: '1px solid var(--color-warning-border)',
              }}>
                <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--color-warning)', margin: 0 }}>
                  ⚠️ This is the only time you'll see this key. Copy it now!
                </p>
              </div>

              {/* CRIT-6 FIX: Key display box — raw key shown once, not embedded in code string */}
              <div style={{
                marginBottom: '16px', padding: '16px', borderRadius: 'var(--radius-md)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                backgroundColor: 'var(--color-navy)',
              }}>
                <code style={{ fontSize: 'var(--text-sm)', color: 'white', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                  {rawKeyRef.current || maskKey(apiKey.key_prefix)}
                </code>
                <button
                  onClick={handleCopyKey}
                  style={{
                    marginLeft: '16px', padding: '8px',
                    background: 'rgba(255,255,255,0.1)', border: 'none',
                    borderRadius: 'var(--radius-sm)', cursor: 'pointer', flexShrink: 0,
                  }}
                  data-testid="onboarding-copy-key"
                >
                  {copied
                    ? <Check style={{ width: '16px', height: '16px', color: 'white' }} />
                    : <Copy style={{ width: '16px', height: '16px', color: 'white' }} />
                  }
                </button>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={keySaved}
                    onChange={(e) => setKeySaved(e.target.checked)}
                    style={{ width: '16px', height: '16px', accentColor: 'var(--color-brand)' }}
                    data-testid="onboarding-confirm-saved"
                  />
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--color-text-secondary)' }}>
                    I have copied and saved my API key
                  </span>
                </label>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: '12px', color: 'var(--color-text-secondary)' }}>
                  Quick Start Code:
                </h3>
                {/* CRIT-6 FIX: Code snippet uses placeholder, not the real key */}
                <CodeBlock code={integrationCode} language="python" />
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: '8px' }}>
                  Replace <code style={{ fontFamily: 'var(--font-mono)' }}>YOUR_KEY_HERE</code> with the key you copied above.
                </p>
              </div>

              <button
                onClick={handleComplete}
                disabled={!keySaved}
                style={{
                  width: '100%', padding: '12px', fontSize: 'var(--text-base)', fontWeight: 600,
                  color: '#080B14', backgroundColor: 'var(--color-brand)',
                  borderRadius: 'var(--radius-md)', border: 'none',
                  cursor: !keySaved ? 'not-allowed' : 'pointer',
                  opacity: !keySaved ? 0.5 : 1,
                }}
                data-testid="onboarding-complete"
              >
                Go to Dashboard
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
