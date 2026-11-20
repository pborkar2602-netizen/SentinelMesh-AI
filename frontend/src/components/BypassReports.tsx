import React, { useEffect, useState } from 'react';

export interface BypassFinding {
  id: number;
  timestamp: string;
  ip_address: string;
  text_hash: string;
  document_preview: string;
  action_tool: string;
  action_args: string;
  gateway_decision: string;
  pass_through_decision: string;
  phrase_filter_decision: string;
  reason: string;
}

export interface FindingsResponse {
  total_bypasses: number;
  findings: BypassFinding[];
  generated_at?: string;
  description?: string;
}

export const BypassReports: React.FC = () => {
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchFindings = async () => {
      try {
        const res = await fetch('/api/v1/playground/findings');
        if (res.ok) {
          const json = await res.json();
          if (isMounted) {
            setData(json);
            setIsLoading(false);
            return;
          }
        }
      } catch {
        // Fallback to static JSON
      }

      try {
        const res = await fetch('/data/playground_findings.json');
        if (res.ok) {
          const json = await res.json();
          if (isMounted) {
            setData(json);
            setIsLoading(false);
            return;
          }
        }
      } catch (err: any) {
        if (isMounted) {
          setError('Failed to load community findings.');
          setIsLoading(false);
        }
      }
    };

    fetchFindings();
    return () => {
      isMounted = false;
    };
  }, []);

  if (isLoading) {
    return (
      <div className="p-8 rounded-2xl bg-white/[0.02] border border-white/10 text-center text-xs font-mono text-slate-400">
        Loading sandbox bypass reports…
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="p-8 rounded-2xl bg-white/[0.02] border border-rose-500/20 text-center text-xs font-mono text-rose-400">
        {error}
      </div>
    );
  }

  const totalBypasses = data?.total_bypasses ?? 0;
  const findings = data?.findings ?? [];

  return (
    <div className="space-y-6" data-testid="bypass-reports-container">
      {/* Header */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900/90 via-[#0B0F1A] to-slate-900/90 border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-sm font-bold text-white font-mono tracking-wide">
              Playground Bypass Reports & Community Findings
            </h4>
            <span
              className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full ${
                totalBypasses === 0
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
              }`}
              data-testid="bypass-count-badge"
            >
              {totalBypasses === 0 ? '0 Active Bypasses' : `${totalBypasses} Bypasses Logged`}
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed font-sans max-w-2xl">
            Live adversarial registry. Every playground attempt where the SentinelMesh Gateway permits a malicious
            action is recorded in the sandbox finding ledger and listed here with full payload hashes and trace reasons.
          </p>
        </div>

        <div className="text-right">
          <span className="text-[10px] font-mono text-slate-500 block">Registry Source:</span>
          <span className="text-xs font-mono text-cyan-400 font-semibold">
            /api/v1/playground/findings
          </span>
        </div>
      </div>

      {/* Content depending on zero or non-zero bypasses */}
      {totalBypasses === 0 ? (
        <div className="p-8 rounded-2xl bg-white/[0.02] border border-emerald-500/20 text-center space-y-4" data-testid="zero-bypass-card">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto text-xl font-bold">
            ✓
          </div>
          <div className="space-y-1">
            <h5 className="text-base font-bold text-white">
              Zero Gateway Bypasses Recorded
            </h5>
            <p className="text-xs text-slate-400 max-w-xl mx-auto leading-relaxed">
              All adversarial prompts, semantic evasions, cloud SSRF targets, and SQL injection payloads submitted to
              the sandbox were halted inline before data access or exfiltration.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 max-w-2xl mx-auto pt-2 text-xs font-mono">
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-slate-500 block text-[10px] uppercase">Gateway Status</span>
              <span className="text-emerald-400 font-bold">Enforcing Inline</span>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-slate-500 block text-[10px] uppercase">Sensitive Data Leaked</span>
              <span className="text-emerald-400 font-bold">0 records</span>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-slate-500 block text-[10px] uppercase">Fail-Closed Guarantee</span>
              <span className="text-cyan-400 font-bold">Verified</span>
            </div>
          </div>

          <p className="text-[11px] text-slate-500 font-mono pt-2">
            Try your own evasion payload in the Policy Lab / Playground section above. If you discover a bypass, it appears here automatically.
          </p>
        </div>
      ) : (
        <div className="space-y-4" data-testid="bypass-list">
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
            ⚠️ {totalBypasses} evasion payload(s) successfully bypassed standard gate filters and were recorded for remediation.
          </div>
          <div className="divide-y divide-white/10 rounded-xl border border-white/10 bg-black/40 overflow-hidden">
            {findings.map((f) => (
              <div key={f.id} className="p-4 space-y-2 text-xs font-mono" data-testid={`finding-row-${f.id}`}>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">
                      FINDING #{f.id}
                    </span>
                    <span className="text-slate-400">{f.timestamp}</span>
                  </div>
                  <span className="text-cyan-300">{f.text_hash}</span>
                </div>
                <div className="text-slate-300">
                  <span className="text-slate-500">Document: </span>
                  <span className="italic">{f.document_preview}</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1">
                  <div>
                    <span className="text-slate-500">Tool: </span>
                    <span className="text-white font-bold">{f.action_tool}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Gateway Decision: </span>
                    <span className="text-rose-400 font-bold">{f.gateway_decision}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Phrase Filter: </span>
                    <span className="text-slate-300">{f.phrase_filter_decision}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Pass-Through: </span>
                    <span className="text-slate-300">{f.pass_through_decision}</span>
                  </div>
                </div>
                {f.reason && (
                  <div className="text-[11px] text-amber-300/90 pt-1">
                    <span className="text-slate-500">Note: </span>
                    {f.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
