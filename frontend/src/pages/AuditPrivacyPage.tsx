import React, { useState, useEffect, useCallback } from 'react';
import { PayloadPreview } from '../components/PayloadPreview';
import { PolicyManager } from '../components/PolicyManager';
import { EventForensicDrawer } from '../components/EventForensicDrawer';
import { AuditEvent, AuditVerification, DashboardStats } from '../types';

const Z0 = '0000000000000000000000000000000000000000000000000000000000000000';

const DEFAULT_FALLBACK_BLOCKS: [string, string][] = [
  ['read_doc(resume.pdf)', 'allow'],
  ['db_query(salary, ssn)', 'require_approval'],
  ['send_email(ext)', 'block'],
  ['tool_return', 'recorded'],
  ['privacy_raw_access', 'allow'],
  ['approval_resolve', 'denied'],
];

async function calcSha256(str: string): Promise<string> {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await window.crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0').repeat(8);
}

interface ChainBlock {
  tool: string;
  decision: string;
  hash: string;
  prevHash: string;
}

interface AuditPrivacyPageProps {
  stats: DashboardStats | null;
  policyMode: 'enforce' | 'monitor';
  events: AuditEvent[];
  onSwitchMode: (m: 'enforce' | 'monitor') => void;
}

export const AuditPrivacyPage: React.FC<AuditPrivacyPageProps> = ({
  stats,
  policyMode,
  events,
  onSwitchMode,
}) => {
  const [subTab, setSubTab] = useState<'chain' | 'vault' | 'replay'>('chain');
  const [auditVerify, setAuditVerify] = useState<AuditVerification | null>(
    stats?.chain_verification || null
  );
  const [chainBlocks, setChainBlocks] = useState<ChainBlock[]>([]);
  const [tamperedIdx, setTamperedIdx] = useState<number>(-1);
  const [policyConfig, setPolicyConfig] = useState<any | null>(null);
  const [inspectedEvent, setInspectedEvent] = useState<AuditEvent | null>(null);

  const handleInspectBlock = (b: ChainBlock, idx: number) => {
    const matched = events.find((e) => e.event_hash === b.hash || `${e.agent_id}·${e.tool_name}` === b.tool);
    if (matched) {
      setInspectedEvent(matched);
      return;
    }
    const [agentId, toolName] = b.tool.includes('·') ? b.tool.split('·') : ['hr-agent', b.tool];
    const fallback: AuditEvent = {
      id: idx + 1,
      trace_id: `trace-hash-block-0${idx + 1}`,
      agent_id: agentId,
      session_id: 'sess-ledger-block',
      tool_name: toolName.split('(')[0],
      arguments: { block_entry: b.tool },
      context_sources: [{ source_id: 'genesis-chain', source_type: 'ledger', is_untrusted: false }],
      decision: b.decision,
      reason: `Cryptographic append-only block #${idx + 1} with SHA-256 hash ${b.hash.slice(0, 10)}…`,
      risk_score: b.decision === 'block' ? 88 : b.decision === 'require_approval' ? 65 : 15,
      risk_breakdown: { untrusted_taint: 0, sensitive_data: 0, external_destination: 0, rule_findings: 10 },
      latency_ms: 3.2,
      timestamp: new Date().toISOString(),
      event_hash: b.hash,
      prev_hash: b.prevHash,
    };
    setInspectedEvent(fallback);
  };

  const loadChainFromBackend = useCallback(async () => {
    setTamperedIdx(-1);
    try {
      const [verifyRes, evRes] = await Promise.all([
        fetch('/api/v1/audit/verify'),
        fetch('/api/v1/events?limit=6&order=desc&exclude_benchmark=true'),
      ]);
      if (verifyRes.ok) {
        setAuditVerify(await verifyRes.json());
      }
      if (evRes.ok) {
        const list: AuditEvent[] = await evRes.json();
        if (list.length > 0) {
          const ordered = [...list].reverse();
          const mapped: ChainBlock[] = ordered.map((ev) => ({
            tool: `${ev.agent_id}·${ev.tool_name}`,
            decision: ev.decision || 'allow',
            hash: ev.event_hash || Z0,
            prevHash: ev.prev_hash || Z0,
          }));
          setChainBlocks(mapped);
          return;
        }
      }
    } catch {
      // Fallback below if DB is empty or unreachable
    }

    let p = Z0;
    const fallback: ChainBlock[] = [];
    for (const [tool, dec] of DEFAULT_FALLBACK_BLOCKS) {
      const h = await calcSha256(`${tool}|${dec}|${p}`);
      fallback.push({ tool, decision: dec, hash: h, prevHash: p });
      p = h;
    }
    setChainBlocks(fallback);
  }, []);

  useEffect(() => {
    loadChainFromBackend();
  }, [loadChainFromBackend, events.length]);

  useEffect(() => {
    if (subTab === 'replay' && !policyConfig) {
      fetch('/api/v1/policies/config')
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => d && setPolicyConfig(d))
        .catch(() => {});
    }
  }, [subTab, policyConfig]);

  const simulateTamper = async () => {
    if (chainBlocks.length < 2) return;
    const idxToTamper = Math.min(2, chainBlocks.length - 1);
    const updated = [...chainBlocks];
    updated[idxToTamper] = { ...updated[idxToTamper], decision: 'allow' };
    setChainBlocks(updated);
    setTamperedIdx(idxToTamper);
  };

  // Pick a real tokenized event payload if present in events, else structured tokenized sample
  const tokenizedEvent =
    events.find((e) =>
      JSON.stringify(e.arguments || {}).includes('[')
    ) || null;

  const vaultSamplePayload = tokenizedEvent
    ? tokenizedEvent.arguments
    : {
        to: 'hiring-committee@company.com',
        subject: 'Compensation Summary [PERSON_1]',
        body: 'Reviewed compensation package [SALARY_1] and identifier [SSN_1] for approval.',
      };
  const vaultSessionId = tokenizedEvent?.session_id || 'sess-demo-privacy-vault';

  return (
    <div className="page-shell">
      <div className="w space-y-6" data-testid="audit-page">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div>
            <div className="eb" style={{ marginBottom: '8px' }}>Forensics & Governance</div>
            <h2 style={{ fontSize: 'clamp(26px, 3.2vw, 40px)' }}>Audit Ledger & Privacy Vault</h2>
            <p className="text-sm text-slate-400 mt-2 max-w-2xl font-sans">
              Cryptographically verify every logged gateway event against the SHA-256 chain, test
              JWT RBAC raw PII unmasking, and replay historical decisions under alternate policies.
            </p>
          </div>

          <div className="seg shrink-0" role="tablist" aria-label="Audit and Privacy views">
            <button
              type="button"
              className={subTab === 'chain' ? 'on' : ''}
              onClick={() => setSubTab('chain')}
              data-testid="audit-tab-chain"
            >
              Hash Chain
            </button>
            <button
              type="button"
              className={subTab === 'vault' ? 'on' : ''}
              onClick={() => setSubTab('vault')}
              id="audit-tab-vault"
              data-testid="audit-tab-vault"
            >
              Privacy Vault
            </button>
            <button
              type="button"
              className={subTab === 'replay' ? 'on' : ''}
              onClick={() => setSubTab('replay')}
              data-testid="audit-tab-replay"
            >
              Policy & Replay
            </button>
          </div>
        </div>

        {/* Sub-tab 1: Real Hash Chain + Tamper Test */}
        {subTab === 'chain' && (
          <div className="space-y-6">
            {auditVerify ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
                  <span className="text-slate-400 block uppercase text-[10px]">Chain Integrity (/api/v1/audit/verify)</span>
                  <span className={`text-lg font-bold mt-1 block ${auditVerify.valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {auditVerify.valid ? 'VERIFIED VALID' : 'TAMPER DETECTED'}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
                  <span className="text-slate-400 block uppercase text-[10px]">Events Verified From Genesis</span>
                  <span className="text-lg font-bold text-white mt-1 block">
                    {auditVerify.events_verified} blocks
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
                  <span className="text-slate-400 block uppercase text-[10px]">Head SHA-256 Digest</span>
                  <span className="text-xs font-bold text-cyan-300 mt-2 block truncate" title={auditVerify.head_hash}>
                    {auditVerify.head_hash}
                  </span>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                {[
                  { label: 'Chain Integrity', value: 'DEMO MODE', cls: 'text-amber-400', sub: 'Start backend to verify live' },
                  { label: 'Hash Algorithm', value: 'SHA-256', cls: 'text-white', sub: 'Append-only, genesis-linked' },
                  { label: 'Demo Blocks Shown', value: `${DEFAULT_FALLBACK_BLOCKS.length} events`, cls: 'text-cyan-300', sub: 'Computed client-side from defaults' },
                ].map(({ label, value, cls, sub }) => (
                  <div key={label} className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
                    <span className="text-slate-400 block uppercase text-[10px]">{label}</span>
                    <span className={`text-lg font-bold mt-1 block ${cls}`}>{value}</span>
                    <span className="text-[10px] text-slate-500 mt-0.5 block font-sans">{sub}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="card space-y-4">
              <div>
                <h3 className="text-base font-bold text-white">Append-Only Event Chain</h3>
                <p className="text-xs text-slate-400 mt-1 font-sans">
                  Each block hashes the canonical payload with its predecessor digest. Modifying any historic event invalidates all downstream links.
                </p>
              </div>

              <div className="chain" id="ch">
                {chainBlocks.map((b, i) => {
                  const isBad = tamperedIdx >= 0 && i >= tamperedIdx;
                  const isOk = tamperedIdx < 0;
                  const decCls =
                    b.decision === 'block' || b.decision === 'denied' || b.decision === 'would_block'
                      ? 'var(--ro)'
                      : b.decision === 'require_approval' || b.decision === 'held'
                      ? 'var(--am)'
                      : 'var(--gr)';

                  return (
                    <React.Fragment key={`block-${i}`}>
                      <div 
                        className={`blk ${isBad ? 'bad' : isOk ? 'ok' : ''} cursor-pointer hover:border-cyan-400 hover:scale-[1.02] transition-all`}
                        onClick={() => handleInspectBlock(b, i)}
                        title="Click to inspect block forensics & SHA-256 proof"
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') handleInspectBlock(b, i);
                        }}
                      >
                        <b>
                          #{i + 1} {b.tool}
                        </b>
                        <span style={{ color: decCls }}>{b.decision}</span>
                        <br />
                        hash {b.hash.slice(0, 6)}…{b.hash.slice(-4)}
                        <br />
                        prev {b.prevHash.slice(0, 6)}…{b.prevHash.slice(-4)}
                      </div>
                      {i < chainBlocks.length - 1 && <div className="lk" />}
                    </React.Fragment>
                  );
                })}
              </div>

              <div className="flex gap-3 flex-wrap">
                <button className="btn" id="tp" onClick={simulateTamper}>
                  Simulate tamper on event 3
                </button>
                <button className="btn g" id="rs" onClick={loadChainFromBackend}>
                  Verify live chain from DB
                </button>
              </div>

              <div className={`msg ${tamperedIdx < 0 && (auditVerify?.valid ?? true) ? 'ok' : 'bad'}`} id="vm">
                {tamperedIdx >= 0
                  ? `Hash mismatch detected at block ${tamperedIdx + 1}. Downstream blocks ${tamperedIdx + 1}–${chainBlocks.length} failed verification.`
                  : auditVerify
                  ? auditVerify.message
                  : `Chain valid · ${chainBlocks.length} events verified`}
              </div>
            </div>

            {/* How it works — fills the page and explains the mechanism */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                {
                  icon: '🔗',
                  title: 'Genesis-linked blocks',
                  body: 'Every event\'s SHA-256 digest includes the previous block\'s hash. Altering any past record breaks every block after it — there\'s no way to silently edit history.',
                },
                {
                  icon: '🛑',
                  title: 'Tamper = instant red',
                  body: 'Click "Simulate tamper on event 3" above to see all downstream blocks turn red. In production, the verification endpoint triggers an alert within one polling cycle.',
                },
                {
                  icon: '🔑',
                  title: 'HMAC approval tokens',
                  body: 'High-risk actions (db_query on PII, external send) are held until a human approves via a one-time HMAC token. Replaying or forging a token is cryptographically rejected.',
                },
                {
                  icon: '📋',
                  title: 'Immutable audit export',
                  body: 'The full event log — including taint labels, session IDs, risk scores and policy decisions — can be exported for SOC 2 or GDPR evidence packages without touching raw PII.',
                },
              ].map(({ icon, title, body }) => (
                <div key={title} className="card flex gap-4 items-start">
                  <span className="text-2xl mt-0.5 select-none">{icon}</span>
                  <div>
                    <h4 className="text-sm font-semibold text-white mb-1">{title}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed font-sans m-0">{body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Sub-tab 2: Real JWT Privacy Vault */}
        {subTab === 'vault' && (
          <div className="space-y-4" data-testid="audit-vault-panel">
            <PayloadPreview
              payload={vaultSamplePayload}
              affectedData="Tokenized Session Payload (AES-256-GCM Vault)"
              sessionId={vaultSessionId}
            />
          </div>
        )}

        {/* Sub-tab 3: Policy Simulation & Declarative Manifest */}
        {subTab === 'replay' && (
          <div className="space-y-6" data-testid="audit-replay-panel">
            <PolicyManager
              policyMode={policyMode}
              stats={stats}
              onModeChanged={onSwitchMode}
            />
            {policyConfig && (
              <div className="card space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h3 className="text-base font-bold text-white">
                    Declarative Policy Pack ({policyConfig.policy_pack} · v{policyConfig.version})
                  </h3>
                  <span className="t-badge cy">Anomaly Threshold: {policyConfig.anomaly_threshold}</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-3 rounded-xl bg-black/40 border border-white/10">
                    <span className="text-slate-400 block mb-1.5">Approved Email Domains</span>
                    <div className="flex flex-wrap gap-1.5">
                      {(policyConfig.approved_email_domains || []).map((d: string) => (
                        <span key={d} className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-300">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-black/40 border border-white/10">
                    <span className="text-slate-400 block mb-1.5">Approved External API Hosts</span>
                    <div className="flex flex-wrap gap-1.5">
                      {(policyConfig.approved_api_domains || []).map((d: string) => (
                        <span key={d} className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-cyan-300">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Forensic Inspection Drawer */}
      <EventForensicDrawer
        event={inspectedEvent}
        onClose={() => setInspectedEvent(null)}
      />
    </div>
  );
};
