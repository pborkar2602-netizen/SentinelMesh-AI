import React, { useState, useEffect } from 'react';
import { DashboardStats } from '../types';

const WATERFALL_ROWS = [
  {
    name: 'Untrusted taint',
    weight: 38,
    color: 'var(--am)',
    evidence: 'resume.pdf -> source: document · trust: UNTRUSTED (assigned server-side)',
  },
  {
    name: 'Sensitive data',
    weight: 15,
    color: 'var(--vi)',
    evidence: 'db_query(salary, ssn) -> sensitive PII columns outside declared task scope',
  },
  {
    name: 'External destination',
    weight: 25,
    color: 'var(--ro)',
    evidence: 'recruiter@ext-hiring.com not in approved email domain list',
  },
  {
    name: 'Rule findings',
    weight: 22,
    color: 'var(--cy)',
    evidence: 'Overt instruction override pattern flagged by injection detector',
  },
];

interface ArchitecturePageProps {
  stats: DashboardStats | null;
}

export const ArchitecturePage: React.FC<ArchitecturePageProps> = ({ stats }) => {
  const [waterfallOpen, setWaterfallOpen] = useState<Record<number, boolean>>({});
  const [mcpStatus, setMcpStatus] = useState<any | null>(null);
  const [policyConfig, setPolicyConfig] = useState<any | null>(null);

  useEffect(() => {
    fetch('/api/v1/mcp/status')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setMcpStatus(d))
      .catch(() => {});
    fetch('/api/v1/policies/config')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setPolicyConfig(d))
      .catch(() => {});
  }, []);

  return (
    <div className="page-shell">
      <div className="w space-y-10" data-testid="architecture-page">
        <div className="border-b border-white/10 pb-5">
          <div className="eb" style={{ marginBottom: '8px' }}>System Architecture</div>
          <h2 style={{ fontSize: 'clamp(26px, 3.2vw, 40px)' }}>
            Six Independent Layers. Deterministic Inline Interception.
          </h2>
          <p className="text-sm text-slate-400 mt-2 max-w-3xl font-sans">
            No single detector has to be infallible. SentinelMesh combines provenance taint tracking,
            SQL AST verification, AES-GCM tokenization, behavioral MAD baselines, and HMAC approvals.
          </p>
        </div>

        {/* 6-Layer Bento Stack */}
        <div className="bn" id="arch-layers">
          <div className="card c4">
            <div className="ico">01</div>
            <h3>Taint tracking</h3>
            <p>
              Untrusted context sources permanently taint the active session and record literal
              values into an LRU provenance index. Agents cannot clear server-side trust labels.
            </p>
            <div className="code">
              <span className="am">read_doc</span>(resume.pdf) → session{' '}
              <span className="ro">TAINTED</span>
              <br />
              <span className="am">send_email</span>(ext) → <span className="ro">BLOCK</span> risk 100
            </div>
          </div>

          <div className="card c2">
            <div className="ico">02</div>
            <h3>Policy gateway</h3>
            <p>Allow, redact, hold for approval, or block synchronously prior to tool side effects.</p>
            <div className="code">
              <span className="gr">allow</span> · <span className="cy">redact</span> ·{' '}
              <span className="am">approve</span> · <span className="ro">block</span>
            </div>
          </div>

          <div className="card c2">
            <div className="ico">03</div>
            <h3>Privacy vault</h3>
            <p>PII is tokenized before persistence. Raw decryption requires Privacy Officer JWT RBAC.</p>
            <div className="code">
              [EMAIL_1] [PERSON_2]
              <br />
              [SALARY_1]
            </div>
          </div>

          <div className="card c4">
            <div className="ico">04</div>
            <h3>Hash-chained audit</h3>
            <p>
              Every decision appends an immutable SHA-256 digest linked to the prior block. Any
              post-hoc mutation breaks verification at that exact sequence number.
            </p>
            <div className="code">
              0000…a91f → 7c2e…b04d → 51d8…0e3a
              <br />
              <span className="gr">chain valid</span> · {stats?.chain_verification?.events_verified ?? stats?.total_audit_events ?? 0} events verified
            </div>
          </div>

          <div className="card c3">
            <div className="ico">05</div>
            <h3>Learned baseline</h3>
            <p>
              Row counts, call timing, and external destinations are scored against per-agent MAD profiles.
            </p>
            <div className="code">
              rows 9004 vs median 667
              <br />
              <span className="am">anomaly</span> · off-hours · new destination
            </div>
          </div>

          <div className="card c3">
            <div className="ico">06</div>
            <h3>Signed approvals</h3>
            <p>
              Privileged writes require a single-use HMAC token bound to the canonical tool call hash.
            </p>
            <div className="code">
              forged · expired · replayed · wrong-action
              <br />→ <span className="ro">all blocked</span>
            </div>
          </div>
        </div>

        {/* Interception Flow + Signal Waterfall */}
        <div className="xs">
          <div className="g2">
            <div className="card">
              <h3>Pre-execution interception point</h3>
              <svg
                viewBox="0 0 640 290"
                width="100%"
                role="img"
                aria-label="Data flow from untrusted file to agent, gateway, then database or email"
              >
                <path className="pa" d="M118 150H192" />
                <path className="pa" d="M268 150H348" />
                <path className="pa" d="M432 150C480 150 495 70 528 70" />
                <path className="pa" d="M432 150C480 150 495 230 528 230" />
                <g className="nd">
                  <rect x="12" y="122" width="106" height="56" rx="14" style={{ stroke: 'var(--am)' }} />
                  <text x="65" y="146" textAnchor="middle" fontSize="11">resume.pdf</text>
                  <text x="65" y="162" textAnchor="middle" fontSize="9" style={{ fill: 'var(--am)' }}>untrusted</text>

                  <rect x="192" y="122" width="76" height="56" rx="14" />
                  <text x="230" y="154" textAnchor="middle" fontSize="11">hr-agent</text>

                  <rect className="nb" x="528" y="42" width="104" height="56" rx="14" />
                  <text x="580" y="66" textAnchor="middle" fontSize="11">payroll DB</text>
                  <text className="ns" x="580" y="82" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                    idle (0 exposed)
                  </text>

                  <rect className="nm" x="528" y="202" width="104" height="56" rx="14" />
                  <text x="580" y="226" textAnchor="middle" fontSize="11">outside email</text>
                  <text className="nl" x="580" y="242" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                    never reached
                  </text>
                </g>
                <circle className="rg" cx="390" cy="150" r="40" />
                <circle className="gw" cx="390" cy="150" r="40" />
                <text x="390" y="146" textAnchor="middle" fontSize="10" style={{ fontWeight: 700 }}>SENTINEL</text>
                <text x="390" y="160" textAnchor="middle" fontSize="9" style={{ fill: 'var(--cy)' }}>gateway</text>
                <text
                  className="stt"
                  x="390"
                  y="214"
                  textAnchor="middle"
                  fontSize="12"
                  style={{ fontWeight: 700, fill: 'var(--gr)' }}
                >
                  HELD AT READ
                </text>
              </svg>
            </div>

            <div className="card">
              <h3>Composite risk scoring (0–100)</h3>
              <p>Select any signal to inspect its attribution evidence.</p>
              <div id="wf">
                {WATERFALL_ROWS.map((row, idx) => {
                  const leftAccum = WATERFALL_ROWS.slice(0, idx).reduce((sum, r) => sum + r.weight, 0);
                  const isOpen = !!waterfallOpen[idx];
                  return (
                    <div
                      key={row.name}
                      className={`wf ${isOpen ? 'o' : ''}`}
                      onClick={() =>
                        setWaterfallOpen((prev) => ({ ...prev, [idx]: !prev[idx] }))
                      }
                    >
                      <span>{row.name}</span>
                      <div className="tr">
                        <i
                          style={{
                            left: `${leftAccum}%`,
                            width: `${row.weight}%`,
                            background: row.color,
                          }}
                        />
                      </div>
                      <b>+{row.weight}</b>
                      <div className="ev">{row.evidence}</div>
                    </div>
                  );
                })}
              </div>
              <div className="big">100</div>
            </div>
          </div>
        </div>

        {/* Live MCP Proxy & Declarative Policy Spec */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="card space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">Model Context Protocol (MCP) Proxy</h3>
              <span className="t-badge gr">
                {mcpStatus ? `v${mcpStatus.protocol_version} · ${mcpStatus.mode}` : 'JSON-RPC 2.0'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              Intercepts <code>tools/call</code> and <code>tools/list</code> over HTTP and stdio.
              When <code>SENTINEL_MCP_UPSTREAM_URL</code> is configured, allowed or vaulted calls
              forward transparently while blocked calls halt fail-closed prior to upstream execution.
            </p>
            <pre className="code text-[11px] overflow-x-auto text-slate-300">
{`POST /api/v1/mcp
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "db_query", "arguments": { "query": "SELECT ..." } } }`}
            </pre>
          </div>

          <div className="card space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">Active Declarative Policy Pack</h3>
              <span className="t-badge cy">
                {policyConfig ? `${policyConfig.policy_pack} v${policyConfig.version}` : 'policies_config.json'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              Email domains, API allowlists, anomaly thresholds, and sensitivity escalation actions are
              loaded declaratively from <code>backend/app/policies_config.json</code>.
            </p>
            <div className="code text-[11px] text-slate-300 space-y-1">
              <div>Email allowlist: {(policyConfig?.approved_email_domains || []).length || 6} domains</div>
              <div>API allowlist: {(policyConfig?.approved_api_domains || []).length || 11} hosts</div>
              <div>High-sensitivity external action: {policyConfig?.high_sensitivity_external_action || 'require_approval'}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
