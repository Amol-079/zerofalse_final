import React, { useState, useEffect, useRef } from 'react';
import { Check, Copy, ChevronRight } from 'lucide-react';

const Docs = () => {
  const [activeSection, setActiveSection] = useState('what-is-zerofalse');
  const [copiedCode, setCopiedCode] = useState(null);
  const contentRef = useRef(null);

  const tocSections = [
    {
      title: 'Getting Started',
      items: [
        { id: 'what-is-zerofalse', label: 'What is Zerofalse?' },
        { id: 'why-you-need-it', label: 'Why you need it' },
        { id: 'quick-start', label: 'Quick start (5 min)' }
      ]
    },
    {
      title: 'Integration',
      items: [
        { id: 'python-sdk', label: 'Python SDK' },
        { id: 'langchain', label: 'LangChain integration' },
        { id: 'crewai', label: 'CrewAI integration' },
        { id: 'autogen', label: 'AutoGen integration' },
        { id: 'rest-api', label: 'REST API' }
      ]
    },
    {
      title: 'Detection',
      items: [
        { id: 'prompt-injection', label: 'Prompt injection' },
        { id: 'credential-scanning', label: 'Credential scanning' },
        { id: 'tool-inspection', label: 'Tool call inspection' },
        { id: 'memory-protection', label: 'Memory protection' }
      ]
    },
    {
      title: 'Dashboard',
      items: [
        { id: 'overview', label: 'Overview' },
        { id: 'scan-logs', label: 'Scan logs' },
        { id: 'alerts', label: 'Alerts' },
        { id: 'api-keys-docs', label: 'API keys' },
        { id: 'ai-configuration', label: 'AI configuration' }
      ]
    },
    {
      title: 'Reference',
      items: [
        { id: 'api-endpoints', label: 'API endpoints' },
        { id: 'sdk-methods', label: 'SDK methods' },
        { id: 'decision-types', label: 'Decision types' },
        { id: 'faq', label: 'FAQ' }
      ]
    }
  ];

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      { rootMargin: '-20% 0px -70% 0px' }
    );

    document.querySelectorAll('[data-section]').forEach(section => {
      observer.observe(section);
    });

    return () => observer.disconnect();
  }, []);

  const copyCode = async (code, id) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(null), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  const CodeBlock = ({ code, id, language = 'python' }) => (
    <div style={{
      background: '#0f172a',
      borderRadius: '10px',
      padding: '20px 24px',
      position: 'relative',
      marginBottom: '20px',
      overflow: 'auto'
    }}>
      <button
        onClick={() => copyCode(code, id)}
        style={{
          position: 'absolute',
          top: '12px',
          right: '12px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          background: 'rgba(255,255,255,0.1)',
          border: 'none',
          borderRadius: '6px',
          color: 'white',
          fontSize: '12px',
          cursor: 'pointer'
        }}
      >
        {copiedCode === id ? (
          <><Check style={{ width: '14px', height: '14px' }} /> Copied!</>
        ) : (
          <><Copy style={{ width: '14px', height: '14px' }} /> Copy</>
        )}
      </button>
      <pre style={{
        margin: 0,
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        lineHeight: 1.8,
        color: '#e2e8f0'
      }}>
        {code}
      </pre>
    </div>
  );

  const Callout = ({ children, type = 'info' }) => {
    const colors = {
      info: { border: '#1a56ff', bg: '#eff4ff' },
      success: { border: '#10b981', bg: '#ecfdf5' },
      warning: { border: '#f59e0b', bg: '#fffbeb' }
    };
    const c = colors[type];
    return (
      <div style={{
        borderLeft: `3px solid ${c.border}`,
        background: c.bg,
        padding: '16px 20px',
        borderRadius: '8px',
        margin: '20px 0',
        fontSize: '15px',
        color: 'var(--color-text-primary)',
        lineHeight: 1.7
      }}>
        {children}
      </div>
    );
  };

  return (
    <div className="page-transition" data-testid="docs-page" style={{ display: 'flex', gap: '48px' }}>
      {/* Table of Contents Sidebar */}
      <div style={{
        width: '220px',
        flexShrink: 0,
        position: 'sticky',
        top: '80px',
        maxHeight: 'calc(100vh - 100px)',
        overflowY: 'auto',
        borderRight: '1px solid var(--color-border)',
        paddingRight: '24px'
      }}>
        {tocSections.map((section, i) => (
          <div key={i} style={{ marginBottom: '16px' }}>
            <div style={{
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
              color: 'var(--color-text-muted)',
              fontWeight: 600,
              marginBottom: '6px',
              marginTop: i > 0 ? '16px' : 0
            }}>
              {section.title}
            </div>
            {section.items.map(item => (
              <a
                key={item.id}
                href={`#${item.id}`}
                onClick={(e) => {
                  e.preventDefault();
                  document.getElementById(item.id)?.scrollIntoView({ behavior: 'smooth' });
                }}
                style={{
                  display: 'block',
                  fontSize: '14px',
                  color: activeSection === item.id ? 'var(--color-brand)' : 'var(--color-text-muted)',
                  fontWeight: activeSection === item.id ? 500 : 400,
                  background: activeSection === item.id ? 'var(--color-brand-light)' : 'transparent',
                  padding: '5px 10px',
                  borderRadius: '6px',
                  textDecoration: 'none',
                  marginBottom: '2px',
                  transition: 'all 0.15s ease'
                }}
                data-testid={`toc-${item.id}`}
              >
                {item.label}
              </a>
            ))}
          </div>
        ))}
      </div>

      {/* Main Content */}
      <div ref={contentRef} style={{ flex: 1, maxWidth: '720px', paddingBottom: '100px' }}>
        {/* What is Zerofalse? */}
        <section id="what-is-zerofalse" data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px' }}>
            What is Zerofalse?
          </h1>
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '24px' }}>
            Zerofalse is a runtime security platform for AI agents. It sits between your agent and the tools it calls, 
            inspecting every action before execution and blocking attacks in real time.
          </p>

          <h2 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            The core idea
          </h2>
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '16px' }}>
            Every AI agent operates by calling tools — functions that interact with the real world. An agent might call 
            <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--color-surface)', padding: '2px 6px', borderRadius: '4px' }}>search_web</code> to find information, 
            <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--color-surface)', padding: '2px 6px', borderRadius: '4px' }}>send_email</code> to communicate, 
            or <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--color-surface)', padding: '2px 6px', borderRadius: '4px' }}>execute_sql</code> to query a database. 
            These tool calls are powerful, but they are also the exact point where attacks become real damage.
          </p>

          <Callout type="info">
            Zerofalse intercepts every tool call before execution. If the call looks malicious, it gets blocked. 
            If it looks safe, it passes through. This all happens in under 2ms.
          </Callout>

          <h2 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px', marginTop: '32px' }}>
            What Zerofalse detects
          </h2>
          <ol style={{ paddingLeft: '20px', marginBottom: '24px' }}>
            {[
              { title: 'Prompt Injection', desc: 'Hidden instructions embedded in external content that attempt to override your agent\'s behavior. This is OWASP\'s #1 LLM risk.' },
              { title: 'Credential Leakage', desc: 'API keys, passwords, and tokens accidentally included in tool call arguments or outputs.' },
              { title: 'Shell Injection', desc: 'Dangerous shell commands like rm -rf or network exfiltration commands passed as tool arguments.' },
              { title: 'Memory Poisoning', desc: 'Tampered memory values that corrupt your agent\'s context and decision-making.' },
              { title: 'Cross-Agent Attacks', desc: 'Unauthorized agent-to-agent delegation in multi-agent pipelines.' }
            ].map((item, i) => (
              <li key={i} style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '12px' }}>
                <strong style={{ color: 'var(--color-text-primary)' }}>{item.title}</strong> — {item.desc}
              </li>
            ))}
          </ol>
        </section>

        {/* Quick Start */}
        <section id="quick-start" data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px' }}>
            Quick Start
          </h1>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Step 1 — Install
          </h2>
          <CodeBlock id="install" code="pip install zerofalse" />

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Step 2 — Get your API key
          </h2>
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '20px' }}>
            Go to <strong>API Keys</strong> in the sidebar and create your first key. You will see it only once — copy it immediately.
          </p>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Step 3 — Wrap your tools
          </h2>
          <CodeBlock 
            id="wrap-tools"
            code={`from zerofalse import ZerofalseClient, guard_tool

# Initialize with your API key
client = ZerofalseClient(api_key="zf_live_your_key_here")

# Protect any tool with one decorator
@guard_tool(client, agent_id="my-research-agent")
def search_web(query: str) -> str:
    # Your existing tool logic
    return search_engine.query(query)

@guard_tool(client, agent_id="my-research-agent")
def send_email(to: str, subject: str, body: str) -> bool:
    # Zerofalse intercepts this before it runs
    return email_client.send(to, subject, body)`}
          />

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Step 4 — Test it
          </h2>
          <CodeBlock 
            id="test-it"
            code={`# Try a safe call — this will ALLOW
result = search_web("latest AI security news")

# Try a dangerous call — this will BLOCK
# (Zerofalse raises ZerofalseSecurity exception)
try:
    run_command("rm -rf /important_data")
except ZerofalseSecurity as e:
    print(f"Blocked: {e.decision.title}")
    # Blocked: Shell Injection Detected (CRITICAL)`}
          />

          <Callout type="success">
            That's it. Your agent is now protected. Check the Overview page in your dashboard to see the scan events.
          </Callout>
        </section>

        {/* Python SDK */}
        <section id="python-sdk" data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px' }}>
            Python SDK
          </h1>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Installation
          </h2>
          <CodeBlock id="sdk-install" code="pip install zerofalse" />
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '24px' }}>
            Supports Python 3.8+. Only requires httpx — no heavy dependencies.
          </p>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            ZerofalseClient
          </h2>
          <CodeBlock 
            id="client"
            code={`from zerofalse import ZerofalseClient

client = ZerofalseClient(
    api_key="zf_live_...",      # Required
    auto_block=True,             # Raise exception on BLOCK (default: True)
    timeout=5,                   # HTTP timeout in seconds (default: 5)
    dry_run=False                # If True, scan but never block (default: False)
)`}
          />

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            @guard_tool decorator
          </h2>
          <CodeBlock 
            id="decorator"
            code={`from zerofalse import guard_tool

@guard_tool(client, agent_id="agent-name")
def my_tool(arg1: str, arg2: int) -> str:
    return do_something(arg1, arg2)`}
          />
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '24px' }}>
            The decorator intercepts the call, sends tool name and arguments to the detection API, 
            and either allows execution or raises <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--color-surface)', padding: '2px 6px', borderRadius: '4px' }}>ZerofalseSecurity</code>.
          </p>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            scan_context() manager
          </h2>
          <CodeBlock 
            id="context"
            code={`with client.scan_context("my-agent", "session-123") as ctx:
    
    # Scan a tool call manually
    result = ctx.before_tool_call("delete_file", {"path": "/data/users.db"})
    print(result.decision)    # ALLOW, WARN, or BLOCK
    print(result.risk_score)  # 0.0 to 1.0
    print(result.evidence)    # List of detected patterns
    
    if not result.blocked:
        delete_file("/data/users.db")
    
    # Scan a prompt
    prompt_result = ctx.scan_input("Ignore all previous instructions...")
    
    # Protect memory writes
    ctx.write_memory("user_context", {"role": "admin"})`}
          />

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            ScanDecision object
          </h2>
          <div style={{
            background: 'var(--color-bg)',
            border: '1px solid var(--color-border)',
            borderRadius: '10px',
            overflow: 'hidden'
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--color-surface)' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Attribute</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Type</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['decision', 'str', '"ALLOW", "WARN", or "BLOCK"'],
                  ['safe', 'bool', 'True if decision is ALLOW'],
                  ['risk_score', 'float', '0.0 to 1.0 risk probability'],
                  ['severity', 'str', '"critical", "high", "medium", "low", "info"'],
                  ['threat_type', 'str | None', 'Type of threat detected'],
                  ['title', 'str', 'Human-readable threat title'],
                  ['evidence', 'list[str]', 'Matched patterns and evidence'],
                  ['blocked', 'bool', 'True if call was blocked']
                ].map((row, i) => (
                  <tr key={i} style={{ borderTop: '1px solid var(--color-border)' }}>
                    <td style={{ padding: '12px 16px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{row[0]}</td>
                    <td style={{ padding: '12px 16px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>{row[1]}</td>
                    <td style={{ padding: '12px 16px', fontSize: '14px', color: 'var(--color-text-secondary)' }}>{row[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* API Reference */}
        <section id="api-endpoints" data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px' }}>
            API Reference
          </h1>

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            Authentication
          </h2>
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '16px' }}>
            All API requests require an <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--color-surface)', padding: '2px 6px', borderRadius: '4px' }}>X-API-Key</code> header with your Zerofalse API key.
          </p>
          <CodeBlock 
            id="curl-auth"
            code={`curl -X POST https://api.zerofalse.io/api/v1/threats/scan/tool-call \\
  -H "X-API-Key: zf_live_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "tool_name": "search_web",
    "arguments": {"query": "AI news"},
    "agent_id": "my-agent",
    "session_id": "sess_001"
  }'`}
          />

          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
            POST /api/v1/threats/scan/tool-call
          </h2>
          <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75, marginBottom: '16px' }}>
            Inspect a tool call before execution.
          </p>

          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '12px' }}>Request Body</h3>
          <div style={{
            background: 'var(--color-bg)',
            border: '1px solid var(--color-border)',
            borderRadius: '10px',
            overflow: 'hidden',
            marginBottom: '20px'
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--color-surface)' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Field</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Type</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-muted)' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['tool_name', 'string', 'Required. Name of the tool being called'],
                  ['arguments', 'object', 'Required. Tool arguments as a JSON object'],
                  ['agent_id', 'string', 'Required. Identifier for the calling agent'],
                  ['session_id', 'string', 'Optional. Session identifier for grouping'],
                  ['caller_agent_id', 'string', 'Optional. For cross-agent calls']
                ].map((row, i) => (
                  <tr key={i} style={{ borderTop: '1px solid var(--color-border)' }}>
                    <td style={{ padding: '12px 16px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{row[0]}</td>
                    <td style={{ padding: '12px 16px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>{row[1]}</td>
                    <td style={{ padding: '12px 16px', fontSize: '14px', color: 'var(--color-text-secondary)' }}>{row[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '12px' }}>Response</h3>
          <CodeBlock 
            id="response"
            code={`{
  "scan_id": "uuid",
  "decision": "BLOCK",
  "risk_score": 0.97,
  "severity": "critical",
  "threat_type": "tool_misuse",
  "title": "Shell Injection Detected (CRITICAL)",
  "description": "Dangerous shell command detected.",
  "evidence": [
    "[CRITICAL] Dangerous argument pattern: rm -rf",
    "[HIGH] High-risk tool called: run_command"
  ],
  "latency_ms": 1,
  "timestamp": "2026-03-12T10:22:01Z"
}`}
          />
        </section>

        {/* Decision Types */}
        <section id="decision-types" data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px' }}>
            Decision Types
          </h1>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ borderLeft: '3px solid #10b981', background: '#ecfdf5', padding: '16px 20px', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#10b981', marginBottom: '8px' }}>ALLOW</h3>
              <p style={{ fontSize: '15px', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                The tool call passed all security checks. Risk score below 0.45. Execution proceeds normally.
              </p>
            </div>
            <div style={{ borderLeft: '3px solid #f59e0b', background: '#fffbeb', padding: '16px 20px', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#f59e0b', marginBottom: '8px' }}>WARN</h3>
              <p style={{ fontSize: '15px', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                The tool call has suspicious patterns but is not definitively malicious. Risk score 0.45–0.74. 
                Execution proceeds but event is logged and flagged.
              </p>
            </div>
            <div style={{ borderLeft: '3px solid #ef4444', background: '#fef2f2', padding: '16px 20px', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#ef4444', marginBottom: '8px' }}>BLOCK</h3>
              <p style={{ fontSize: '15px', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                The tool call contains dangerous patterns. Risk score 0.75+. Execution is prevented. 
                <code style={{ fontFamily: 'var(--font-mono)', background: 'rgba(239,68,68,0.1)', padding: '2px 6px', borderRadius: '4px' }}>ZerofalseSecurity</code> exception raised if auto_block=True.
              </p>
            </div>
          </div>
        </section>

        {/* Additional placeholder sections */}
        {['why-you-need-it', 'langchain', 'crewai', 'autogen', 'rest-api', 'prompt-injection', 'credential-scanning', 'tool-inspection', 'memory-protection', 'overview', 'scan-logs', 'alerts', 'api-keys-docs', 'ai-configuration', 'sdk-methods', 'faq'].map(id => (
          <section key={id} id={id} data-section style={{ scrollMarginTop: '24px', marginBottom: '48px' }}>
            <h1 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '20px', textTransform: 'capitalize' }}>
              {id.replace(/-/g, ' ')}
            </h1>
            <p style={{ fontSize: '16px', color: 'var(--color-text-secondary)', lineHeight: 1.75 }}>
              Documentation for this section is being written. Check back soon for detailed guides and examples.
            </p>
          </section>
        ))}
      </div>
    </div>
  );
};

export default Docs;
