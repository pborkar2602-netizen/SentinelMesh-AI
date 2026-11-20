import React, { useState, useEffect } from 'react';
import { 
  X, 
  Copy, 
  Check, 
  ShieldCheck, 
  FileText, 
  Database, 
  Mail, 
  Terminal, 
  Clock, 
  Lock
} from 'lucide-react';
import { AuditEvent } from '../types';

interface EventForensicDrawerProps {
  event: AuditEvent | null;
  onClose: () => void;
}

export const EventForensicDrawer: React.FC<EventForensicDrawerProps> = ({ event, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'payload' | 'context' | 'crypto'>('overview');
  const [copied, setCopied] = useState(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const dec = (event.decision || '').toLowerCase();
  const isBlocked = dec === 'block';
  const isHeld = dec === 'require_approval';
  const isWouldBlock = dec === 'would_block';

  const decBadgeColor = isBlocked
    ? 'text-rose-400 bg-rose-500/15 border-rose-500/30'
    : isHeld
    ? 'text-amber-400 bg-amber-500/15 border-amber-500/30'
    : isWouldBlock
    ? 'text-amber-300 bg-amber-500/20 border-amber-500/40'
    : 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30';

  const riskScore = event.risk_score ?? 0;
  const riskBadgeColor = riskScore >= 70
    ? 'text-rose-400 border-rose-500/40 bg-rose-500/10'
    : riskScore >= 35
    ? 'text-amber-400 border-amber-500/40 bg-amber-500/10'
    : 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10';

  const toolIcon = () => {
    if (event.tool_name === 'read_doc') return <FileText className="w-4 h-4 text-cyan-400" />;
    if (event.tool_name === 'db_query') return <Database className="w-4 h-4 text-violet-400" />;
    if (event.tool_name === 'send_email') return <Mail className="w-4 h-4 text-rose-400" />;
    return <Terminal className="w-4 h-4 text-emerald-400" />;
  };

  const rawArgs = event.arguments || {};
  const argsJson = JSON.stringify(rawArgs, null, 2);
  const hasTokenizedPii = argsJson.includes('[SALARY_') || argsJson.includes('[SSN_') || argsJson.includes('[PERSON_') || argsJson.includes('[EMAIL_');

  const bd = (event.risk_breakdown || {}) as Record<string, any>;
  const untrustedTaint = bd.untrusted_taint ?? 0;
  const sensitiveData = bd.sensitive_data ?? 0;
  const externalDest = bd.external_destination ?? 0;
  const ruleFindings = bd.rule_findings ?? 0;

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 transition-opacity animate-fadeIn"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside 
        className="fixed inset-y-0 right-0 z-50 w-full sm:w-[580px] lg:w-[640px] bg-[#070a14] border-l border-white/10 shadow-2xl flex flex-col transform transition-transform duration-300 ease-out"
        role="dialog"
        aria-label="Event Forensics Details"
        data-testid="forensic-drawer"
      >
        {/* Top Header */}
        <div className="p-5 border-b border-white/10 bg-[#0a0e1a]/80 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-white/5 border border-white/10">
                {toolIcon()}
              </span>
              <div>
                <span className="text-[11px] font-mono text-cyan-400 tracking-wider uppercase block">
                  Event Forensics · #{event.id}
                </span>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>{event.agent_id}</span>
                  <span className="text-slate-500 font-normal">→</span>
                  <span className="font-mono text-cyan-300">{event.tool_name}</span>
                </h3>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyJson}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-all text-xs flex items-center gap-1 font-mono"
                title="Copy raw event JSON"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="hidden sm:inline">{copied ? 'Copied' : 'JSON'}</span>
              </button>
              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white transition-all"
                aria-label="Close drawer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono">
            <span className={`px-2.5 py-0.5 rounded-full border font-semibold uppercase ${decBadgeColor}`}>
              Decision: {event.decision}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full border font-semibold ${riskBadgeColor}`}>
              Risk: {riskScore}/100
            </span>
            {event.latency_ms && (
              <span className="px-2 py-0.5 rounded-full border border-white/10 bg-white/5 text-slate-400 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {event.latency_ms.toFixed(1)}ms
              </span>
            )}
            <span className="text-[10px] text-slate-500 truncate max-w-[200px]" title={event.session_id}>
              {event.session_id}
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-white/10 bg-[#070a14] px-4 text-xs font-mono">
          {[
            { id: 'overview', label: 'Overview & Rules' },
            { id: 'payload', label: 'Payload & PII' },
            { id: 'context', label: 'Taint Lineage' },
            { id: 'crypto', label: 'Hash Chain Proof' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              data-testid={`forensic-tab-${tab.id}`}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-3 px-3 border-b-2 font-medium transition-all ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs font-sans">
          {/* TAB 1: OVERVIEW & RULES */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              {/* Decision Rationale */}
              <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Gateway Policy Rationale
                </span>
                <p className="text-sm font-sans text-slate-200 leading-relaxed m-0">
                  {event.reason || 'Inline policy inspection executed without specific finding overrides.'}
                </p>
              </div>

              {/* 4 Attribution Signal Bars */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Signal Attribution Breakdown
                </span>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-white/[0.02] border border-white/10">
                    <span className="text-slate-400 text-[10px] block">Untrusted Taint</span>
                    <strong className={`text-sm mt-0.5 block ${untrustedTaint > 0 ? 'text-amber-400' : 'text-slate-500'}`}>
                      +{untrustedTaint} pts
                    </strong>
                    <span className="text-[10px] text-slate-500 mt-0.5 block">
                      {untrustedTaint > 0 ? 'Tainted by untrusted input' : 'Clean session state'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-white/[0.02] border border-white/10">
                    <span className="text-slate-400 text-[10px] block">Sensitive PII / Columns</span>
                    <strong className={`text-sm mt-0.5 block ${sensitiveData > 0 ? 'text-violet-400' : 'text-slate-500'}`}>
                      +{sensitiveData} pts
                    </strong>
                    <span className="text-[10px] text-slate-500 mt-0.5 block">
                      {sensitiveData > 0 ? 'Salary / national_id identified' : 'No sensitive columns'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-white/[0.02] border border-white/10">
                    <span className="text-slate-400 text-[10px] block">External Egress</span>
                    <strong className={`text-sm mt-0.5 block ${externalDest > 0 ? 'text-rose-400' : 'text-slate-500'}`}>
                      +{externalDest} pts
                    </strong>
                    <span className="text-[10px] text-slate-500 mt-0.5 block">
                      {externalDest > 0 ? 'Target outside company domain' : 'Internal / Local'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-white/[0.02] border border-white/10">
                    <span className="text-slate-400 text-[10px] block">Rule Engine Findings</span>
                    <strong className={`text-sm mt-0.5 block ${ruleFindings > 0 ? 'text-cyan-400' : 'text-slate-500'}`}>
                      +{ruleFindings} pts
                    </strong>
                    <span className="text-[10px] text-slate-500 mt-0.5 block">
                      {event.findings?.length ?? 0} rules triggered
                    </span>
                  </div>
                </div>
              </div>

              {/* Triggered Rule Findings */}
              {event.findings && event.findings.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                    Triggered Detection Rules ({event.findings.length})
                  </span>
                  <div className="space-y-2">
                    {event.findings.map((f, i) => (
                      <div key={i} className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-1">
                        <div className="flex items-center justify-between">
                          <strong className="text-white font-mono text-xs">{f.name}</strong>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 uppercase">
                            {f.severity}
                          </span>
                        </div>
                        <p className="text-xs text-rose-200/90 font-sans m-0">
                          {f.owasp_category} · Evidence: <code className="font-mono text-amber-200">{f.evidence}</code>
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: PAYLOAD & PII */}
          {activeTab === 'payload' && (
            <div className="space-y-4">
              {hasTokenizedPii && (
                <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-start gap-2.5">
                  <Lock className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-cyan-300 font-mono text-xs block">
                      Format-Preserving Vault Tokenization Active
                    </strong>
                    <p className="text-slate-300 text-xs mt-0.5 font-sans leading-relaxed m-0">
                      Sensitive identities and compensation figures are tokenized with AES-256-GCM before entering telemetry. Raw decryption requires Privacy Officer approval.
                    </p>
                  </div>
                </div>
              )}

              <div className="space-y-1.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Tool Arguments Payload ({event.tool_name})
                </span>
                <pre className="p-3.5 rounded-xl bg-black/60 border border-white/10 text-cyan-300 font-mono text-xs overflow-x-auto leading-relaxed">
                  {argsJson}
                </pre>
              </div>

              <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-1.5 font-mono text-xs">
                <div className="flex justify-between text-slate-400">
                  <span>Agent Scope:</span>
                  <span className="text-white">{event.agent_id}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Session Key:</span>
                  <span className="text-cyan-300">{event.session_id}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Trace Identifier:</span>
                  <span className="text-slate-300">{event.trace_id}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: TAINT LINEAGE & CONTEXT */}
          {activeTab === 'context' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Session Context Sources ({event.context_sources?.length || 0})
                </span>

                {(!event.context_sources || event.context_sources.length === 0) ? (
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 text-slate-400 text-center">
                    No external context documents attached to this invocation.
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {event.context_sources.map((src, i) => (
                      <div 
                        key={i} 
                        className={`p-3.5 rounded-xl border ${
                          src.is_untrusted 
                            ? 'bg-amber-500/10 border-amber-500/30' 
                            : 'bg-white/[0.02] border-white/10'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5 font-mono text-xs">
                          <span className="font-semibold text-white">{src.source_id}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-semibold ${
                            src.is_untrusted 
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' 
                              : 'bg-emerald-500/20 text-emerald-300'
                          }`}>
                            {src.is_untrusted ? 'Untrusted Taint Vector' : 'Trusted Source'}
                          </span>
                        </div>

                        {src.snippet && (
                          <div className="mt-2 p-2.5 rounded bg-black/40 border border-white/5 font-mono text-xs text-amber-200/90 leading-relaxed">
                            <span className="text-[10px] text-slate-500 block mb-1 uppercase">Source Excerpt</span>
                            {src.snippet}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-1 font-sans text-xs text-slate-400">
                <strong className="text-white font-mono block">Dynamic Taint Tracking</strong>
                <p className="leading-relaxed m-0">
                  When untrusted documents are ingested by an agent, the session context is flagged. Subsequent calls touching sensitive endpoints (financial tables, employee rosters, egress webhooks) require human verification or are terminated inline.
                </p>
              </div>
            </div>
          )}

          {/* TAB 4: HASH CHAIN PROOF */}
          {activeTab === 'crypto' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-start gap-2.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="text-emerald-300 font-mono text-xs block">
                    Append-Only SHA-256 Digest Verified
                  </strong>
                  <p className="text-slate-300 text-xs mt-0.5 font-sans leading-relaxed m-0">
                    This audit block is cryptographically bound to its predecessor. Any retroactive modification to arguments, decision, or reason invalidates the entire chain.
                  </p>
                </div>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-1">
                  <span className="text-[10px] text-slate-400 block uppercase">Event SHA-256 Digest</span>
                  <span className="text-cyan-300 break-all select-all block">
                    {event.event_hash || '0000000000000000000000000000000000000000000000000000000000000000'}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-1">
                  <span className="text-[10px] text-slate-400 block uppercase">Predecessor Digest (prev_hash)</span>
                  <span className="text-slate-400 break-all select-all block">
                    {event.prev_hash || '0000000000000000000000000000000000000000000000000000000000000000'}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1.5">
                  <div className="flex justify-between text-slate-400">
                    <span>Audit Sequence ID:</span>
                    <span className="text-white">#{event.id}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Canonical Timestamp:</span>
                    <span className="text-white">{event.timestamp}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Logging Source:</span>
                    <span className="text-cyan-300">{event.source || 'gateway_proxy'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Bottom Footer Actions */}
        <div className="p-4 border-t border-white/10 bg-[#0a0e1a]/80 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            Press <kbd className="px-1.5 py-0.5 rounded bg-white/10 text-slate-300">Esc</kbd> to dismiss
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-white font-mono text-xs transition-all"
          >
            Close Inspector
          </button>
        </div>
      </aside>
    </>
  );
};
