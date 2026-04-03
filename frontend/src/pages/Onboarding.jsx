/**
 * Onboarding — 3-step flow.
 * FIX: navigate('/dashboard') is now called after user confirms key saved.
 * FIX: API key is NOT embedded in code snippet (uses placeholder).
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Key, Code, CheckCircle, Copy, Check, AlertCircle } from 'lucide-react';
import client from '../api/client';
import { CodeBlock } from '../components/CodeBlock';

export default function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [apiKey, setApiKey] = useState(null);
  const [keyName, setKeyName] = useState('Production Key');
  const [copied, setCopied] = useState(false);
  const [keySaved, setKeySaved] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleCreateKey = async () => {
    if (!keyName.trim()) return;
    setLoading(true);
    setError('');
    try {
      const res = await client.post('/api/v1/keys/', { name: keyName.trim() });
      setApiKey(res.data);
      setStep(3);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create API key. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyKey = () => {
    if (!apiKey?.full_key) return;
    navigator.clipboard.writeText(apiKey.full_key).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFinish = () => {
    navigate('/dashboard');
  };

  // Placeholder — never embed real key in code snippets
  const integrationCode = `import os
from zerofalse import guard_tool

# Set your API key from the box above
os.environ["ZEROFALSE_API_KEY"] = "YOUR_KEY_HERE"

@guard_tool(agent_id="my-agent")
def execute_shell(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True, text=True)`;

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-2xl mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Syne, sans-serif' }}>
            Welcome to Zerofalse
          </h1>
          <p className="text-gray-600">Let's get you set up in 3 easy steps</p>
        </div>

        <div className="flex items-center justify-center gap-2 mb-8">
          {[1, 2, 3].map((i) => (
            <React.Fragment key={i}>
              <div className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold text-sm ${step >= i ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-500'}`}>{i}</div>
              {i < 3 && <div className={`w-12 h-1 rounded ${step > i ? 'bg-blue-600' : 'bg-gray-200'}`} />}
            </React.Fragment>
          ))}
        </div>

        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-8">
          {step === 1 && (
            <div className="text-center" data-testid="onboarding-step-1">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-6">
                <Shield className="w-8 h-8 text-blue-600" />
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Protect Your AI Agents</h2>
              <p className="text-gray-600 mb-8 max-w-lg mx-auto">
                Zerofalse inspects every tool call your AI agents make in real-time, blocking attacks before they cause damage.
              </p>
              <button
                onClick={() => setStep(2)}
                className="px-8 py-3 text-base font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                data-testid="onboarding-next-btn"
              >
                Let's Get Started
              </button>
            </div>
          )}

          {step === 2 && (
            <div data-testid="onboarding-step-2">
              <div className="text-center mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
                  <Key className="w-8 h-8 text-blue-600" />
                </div>
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Create Your API Key</h2>
                <p className="text-gray-600">You'll use this key to authenticate the SDK</p>
              </div>

              {error && (
                <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg mb-6">
                  <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
                  <span className="text-sm text-red-700">{error}</span>
                </div>
              )}

              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">Key Name</label>
                <input
                  type="text"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="e.g. Production Key"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  data-testid="key-name-input"
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setStep(1)}
                  className="px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={handleCreateKey}
                  disabled={loading || !keyName.trim()}
                  className="flex-1 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white font-semibold rounded-lg transition-colors"
                  data-testid="create-key-btn"
                >
                  {loading ? 'Creating...' : 'Create API Key'}
                </button>
              </div>
            </div>
          )}

          {step === 3 && apiKey && (
            <div data-testid="onboarding-step-3">
              <div className="text-center mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
                  <CheckCircle className="w-8 h-8 text-green-600" />
                </div>
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Your API Key is Ready</h2>
                <p className="text-gray-600">Copy it now — it won't be shown again</p>
              </div>

              <div className="bg-gray-900 rounded-lg p-4 mb-6">
                <div className="flex items-center justify-between gap-3">
                  <code className="text-green-400 text-sm font-mono break-all">{apiKey.full_key}</code>
                  <button
                    onClick={handleCopyKey}
                    className="flex-shrink-0 flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md transition-colors"
                    data-testid="copy-key-btn"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                  <Code className="w-4 h-4" /> Quick Start
                </h3>
                <CodeBlock code={integrationCode} language="python" />
              </div>

              <div className="flex items-center gap-3 mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <input
                  type="checkbox"
                  id="keySaved"
                  checked={keySaved}
                  onChange={(e) => setKeySaved(e.target.checked)}
                  className="w-4 h-4 accent-blue-600"
                />
                <label htmlFor="keySaved" className="text-sm text-yellow-800 cursor-pointer">
                  I've saved my API key in a secure location
                </label>
              </div>

              <button
                onClick={handleFinish}
                disabled={!keySaved}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white font-semibold rounded-lg transition-colors"
                data-testid="finish-onboarding-btn"
              >
                Go to Dashboard
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
