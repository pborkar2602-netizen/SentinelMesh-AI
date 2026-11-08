import React, { useState } from 'react';
import { Terminal, ChevronDown, ChevronRight, AlertTriangle, Clock, Hash, ShieldCheck, ShieldAlert } from 'lucide-react';
import { AuditEvent } from '../types';

interface EventFeedProps {
  events: AuditEvent[];
  selectedAgent: string | null;
}

export const EventFeed: React.FC<EventFeedProps> = ({ events, selectedAgent }) => {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const filteredEvents = selectedAgent
    ? events.filter((e) => e.agent_id === selectedAgent)
    : events;

  const toggleExpand = (id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision?.toLowerCase()) {
      case 'allow':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-gr/15 text-gr border border-gr/30">
            ALLOW
          </span>
        );
      case 'block':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rd/15 text-rd border border-rd/30">
            BLOCK
          </span>
        );
      case 'would_block':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-am/20 text-am border border-am/40">
            WOULD BLOCK
          </span>
        );
      case 'redact':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-am/15 text-am border border-am/30">
            REDACT
          </span>
        );
      case 'require_approval':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-vi/15 text-vi border border-vi/30">
            APPROVE
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-mut/20 text-mut border border-line">
            {decision?.toUpperCase() || 'UNKNOWN'}
          </span>
        );
    }
  };

  const getRiskScoreBadge = (score: number = 0, breakdown?: Record<string, number>) => {
    let colorClass = "bg-gr/15 text-gr border-gr/30";
    if (score >= 70) colorClass = "bg-rd/15 text-rd border-rd/30";
    else if (score >= 30) colorClass = "bg-am/15 text-am border-am/30";

    const titleStr = breakdown
      ? `Risk Score: ${score}/100\n• Taint: +${breakdown.untrusted_taint || 0}\n• Rules: +${breakdown.rule_findings || 0}\n• External: +${breakdown.external_destination || 0}\n• Sensitive: +${breakdown.sensitive_data || 0}`
      : `Risk Score: ${score}/100`;

    return (
      <span
        className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${colorClass} cursor-help`}
        title={titleStr}
      >
        RISK {score}
      </span>
    );
  };

  const formatTime = (isoString: string) => {
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col h-full">
      <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cy" />
          <h2 className="text-sm font-semibold tracking-wide text-ink uppercase">
            Live Tool Call Decision Feed
          </h2>
          {selectedAgent && (
            <span className="text-xs font-mono text-cy bg-cy/10 px-2 py-0.5 rounded border border-cy/20">
              Filtered: {selectedAgent}
            </span>
          )}
        </div>
        <div className="text-xs font-mono text-mut">
          Showing {filteredEvents.length} events
        </div>
      </div>

      <div className="space-y-2 overflow-y-auto pr-1 flex-1 font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-mut text-center p-6 border border-dashed border-line rounded-lg">
            <Terminal className="w-8 h-8 mb-2 text-mut/50" />
            <p className="font-semibold text-ink/70">No tool calls intercepted yet</p>
            <p className="text-[11px] text-mut mt-1">
              Run the demo agent (<code className="text-cy">python run_demo.py</code>) to see live calls appear.
            </p>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isExpanded = expandedId === ev.id;
            const hasUntrusted = ev.context_sources?.some((c) => c.is_untrusted);
            const isBlocked = ev.decision === 'block';
            const isWouldBlock = ev.decision === 'would_block';

            return (
              <div
                key={ev.id}
                className={`p-2.5 rounded-lg bg-bg2/90 border transition-colors ${
                  isBlocked
                    ? 'border-rd/40 bg-rd/5'
                    : isWouldBlock
                    ? 'border-am/40 bg-am/5'
                    : 'border-line hover:border-cy/40'
                }`}
              >
                <div
                  className="flex items-center justify-between gap-2 cursor-pointer select-none"
                  onClick={() => toggleExpand(ev.id)}
                >
                  <div className="flex items-center gap-2 flex-wrap min-w-0">
                    <button className="text-mut hover:text-ink">
                      {isExpanded ? (
                        <ChevronDown className="w-3.5 h-3.5 text-cy" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5" />
                      )}
                    </button>

                    <span className="text-[11px] text-mut">
                      {formatTime(ev.timestamp)}
                    </span>

                    {getDecisionBadge(ev.decision)}
                    {getRiskScoreBadge(ev.risk_score, ev.risk_breakdown)}

                    <span className="font-semibold text-cy font-mono">
                      {ev.agent_id}
                    </span>

                    <span className="text-mut">→</span>

                    <span className="text-ink font-bold">
                      {ev.tool_name}
                    </span>

                    {hasUntrusted && (
                      <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.2 rounded bg-am/15 text-am border border-am/30">
                        <AlertTriangle className="w-2.5 h-2.5" /> Untrusted Context
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-[10px] text-mut flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" /> {ev.latency_ms} ms
                    </span>
                  </div>
                </div>

                <div className="mt-1 pl-5 text-[11px] text-mut truncate">
                  {ev.reason}
                </div>

                {isExpanded && (
                  <div className="mt-2.5 pl-5 pt-2 border-t border-line/60 text-[11px] space-y-2.5">
                    {/* Risk Breakdown Pills */}
                    {ev.risk_breakdown && (
                      <div>
                        <div className="text-mut text-[10px] uppercase font-semibold mb-1">
                          Risk Score Breakdown:
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="px-2 py-0.5 rounded bg-bg border border-line text-[10px]">
                            Taint: <strong className={ev.risk_breakdown.untrusted_taint ? 'text-am' : 'text-mut'}>+{ev.risk_breakdown.untrusted_taint || 0}</strong>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-bg border border-line text-[10px]">
                            Rules: <strong className={ev.risk_breakdown.rule_findings ? 'text-rd' : 'text-mut'}>+{ev.risk_breakdown.rule_findings || 0}</strong>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-bg border border-line text-[10px]">
                            External Dest: <strong className={ev.risk_breakdown.external_destination ? 'text-am' : 'text-mut'}>+{ev.risk_breakdown.external_destination || 0}</strong>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-bg border border-line text-[10px]">
                            Sensitive Data: <strong className={ev.risk_breakdown.sensitive_data ? 'text-rd' : 'text-mut'}>+{ev.risk_breakdown.sensitive_data || 0}</strong>
                          </span>
                        </div>
                      </div>
                    )}

                    {/* Detected Findings */}
                    {ev.findings && ev.findings.length > 0 && (
                      <div>
                        <div className="text-mut text-[10px] uppercase font-semibold mb-1 flex items-center gap-1 text-rd">
                          <ShieldAlert className="w-3 h-3" /> Security Findings ({ev.findings.length}):
                        </div>
                        <div className="space-y-1">
                          {ev.findings.map((f, idx) => (
                            <div key={idx} className="p-1.5 rounded bg-rd/10 border border-rd/30 text-ink text-[10px]">
                              <div className="flex items-center justify-between font-bold text-rd">
                                <span>{f.name.replace(/_/g, ' ').toUpperCase()}</span>
                                <span className="uppercase text-[9px] px-1 rounded bg-rd/20">{f.severity}</span>
                              </div>
                              <p className="mt-0.5 text-mut">{f.evidence}</p>
                              <div className="mt-0.5 text-[9px] text-cy font-mono">{f.owasp_category}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Arguments Payload */}
                    <div>
                      <div className="text-mut text-[10px] uppercase font-semibold mb-1">
                        Tool Call Arguments:
                      </div>
                      <pre className="p-2 rounded bg-bg border border-line text-ink overflow-x-auto text-[10px]">
                        {JSON.stringify(ev.arguments, null, 2)}
                      </pre>
                    </div>

                    {/* Context Sources */}
                    {ev.context_sources && ev.context_sources.length > 0 && (
                      <div>
                        <div className="text-mut text-[10px] uppercase font-semibold mb-1">
                          Context Sources & Trust Labeling:
                        </div>
                        <div className="space-y-1">
                          {ev.context_sources.map((ctx, idx) => (
                            <div
                              key={idx}
                              className={`p-1.5 rounded border text-[10px] ${
                                ctx.is_untrusted
                                  ? 'bg-am/10 border-am/30 text-am'
                                  : 'bg-bg border-line text-mut'
                              }`}
                            >
                              <div className="flex items-center justify-between font-bold">
                                <span>{ctx.source_id} ({ctx.source_type})</span>
                                <span>{ctx.is_untrusted ? 'UNTRUSTED SOURCE' : 'TRUSTED SOURCE'}</span>
                              </div>
                              {ctx.snippet && (
                                <div className="mt-1 text-ink/80 truncate">
                                  {ctx.snippet}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Hash Chain & Metadata */}
                    <div className="pt-2 border-t border-line/40 flex items-center justify-between text-[10px] text-mut flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span className="flex items-center gap-1 text-cy">
                          <Hash className="w-2.5 h-2.5" />
                          Hash: <code title={ev.event_hash}>{ev.event_hash ? `${ev.event_hash.slice(0, 12)}...` : 'genesis'}</code>
                        </span>
                        <span className="text-gr inline-flex items-center gap-0.5">
                          <ShieldCheck className="w-2.5 h-2.5" /> Chain Verified
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span>Trace: <code className="text-cy">{ev.trace_id}</code></span>
                        <span>Session: <code className="text-ink">{ev.session_id}</code></span>
                        <span>Event #{ev.id}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
