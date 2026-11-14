import React from 'react';
import { Incident } from '../types';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

interface AttackChainPanelProps {
  incident: Incident | null;
}

export const AttackChainPanel: React.FC<AttackChainPanelProps> = ({ incident }) => {
  if (!incident) {
    return (
      <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col justify-center items-center text-center h-80 md:h-96">
        <ShieldCheck className="w-10 h-10 text-gr mb-2 opacity-80" />
        <h3 className="text-sm font-bold text-ink">No Active Security Incidents</h3>
        <p className="text-xs text-mut max-w-sm mt-1">
          The mesh is operating safely. Run the attack simulation (<code className="text-cy">ATK-001</code>) to trigger inline threat blocking and live attack chain reconstruction.
        </p>
      </div>
    );
  }

  const isBlocked = incident.status === 'BLOCKED';
  const isWouldBlock = incident.status === 'WOULD_BLOCK';

  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col h-full font-mono">
      {/* Incident Header */}
      <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className={`w-4 h-4 ${isBlocked ? 'text-rd' : 'text-am'}`} />
          <h2 className="text-sm font-semibold tracking-wide text-ink uppercase">
            Attack Chain, Rebuilt Live
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
            isBlocked
              ? 'bg-rd/15 text-rd border-rd/40'
              : 'bg-am/15 text-am border-am/40'
          }`}>
            {incident.status}
          </span>
          <span className="text-[10px] text-mut">{incident.id}</span>
        </div>
      </div>

      {/* Chronological Step-by-Step Chain */}
      <div className="space-y-4 my-2 flex-1 overflow-y-auto pr-1">
        {incident.chain_steps.map((step, idx) => {
          const isLast = idx === incident.chain_steps.length - 1;
          const isTainted = step.status === 'TAINTED_INGEST';
          const isRead = step.status === 'SENSITIVE_READ';
          const isAttack = step.status === 'BLOCKED_ATTACK' || step.status === 'WOULD_BLOCK';

          return (
            <div key={idx} className="relative flex items-start gap-3">
              {/* Connecting vertical line */}
              {!isLast && (
                <div className="absolute left-4 top-8 bottom-0 w-0.5 bg-line" />
              )}

              {/* Step Icon Badge */}
              <div className={`relative z-10 w-8 h-8 rounded-lg flex items-center justify-center text-sm border ${
                isAttack
                  ? 'bg-rd/20 border-rd text-rd shadow-[0_0_12px_rgba(229,72,77,0.4)]'
                  : isRead
                  ? 'bg-vi/20 border-vi text-vi'
                  : isTainted
                  ? 'bg-am/20 border-am text-am shadow-[0_0_10px_rgba(217,164,65,0.3)]'
                  : 'bg-bg2 border-line text-ink'
              }`}>
                {step.icon || '⚡'}
              </div>

              {/* Step Info */}
              <div className="flex-1 min-w-0 pb-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-bold text-xs text-ink">{step.title}</span>
                  <span className={`px-1.5 py-0.2 rounded text-[9px] uppercase font-bold border ${
                    isAttack
                      ? 'bg-rd/15 text-rd border-rd/30'
                      : isTainted
                      ? 'bg-am/15 text-am border-am/30'
                      : 'bg-bg2 text-mut border-line'
                  }`}>
                    {(step.status || step.decision || '').replace(/_/g, ' ')}
                  </span>
                </div>

                <div className="text-[11px] text-cy mt-0.5 font-bold">
                  tool: {step.tool_name}
                </div>

                {step.reason && (
                  <p className="text-[10px] text-mut mt-1 truncate">
                    {step.reason}
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Plain Language Summary Box */}
      <div className="mt-3 p-3 rounded-lg bg-bg2/90 border border-line text-xs">
        <div className="text-[10px] text-mut uppercase font-bold mb-1 flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3 text-am" />
          Attack Analysis & Impact Summary
        </div>
        <p className="text-ink/90 leading-relaxed text-[11px] font-sans">
          {incident.summary}
        </p>
        <div className="mt-2 pt-2 border-t border-line/60 flex items-center justify-between text-[10px] text-mut">
          <span>Targeted Data: <strong className="text-ink">{incident.affected_data}</strong></span>
          <span>Entry: <code className="text-cy">{incident.entry_point}</code></span>
        </div>
      </div>

      {/* Final Verdict Banner */}
      <div className={`mt-3 p-2.5 rounded-lg border text-center font-bold text-xs ${
        isBlocked
          ? 'bg-rd/15 border-rd/40 text-rd'
          : isWouldBlock
          ? 'bg-am/15 border-am/40 text-am'
          : 'bg-gr/15 border-gr/40 text-gr'
      }`}>
        {isBlocked
          ? '🛡️ ATTACK BLOCKED INLINE BY POLICY GATEWAY'
          : '⚠️ ACTION FLAGGED: WOULD BLOCK IN ENFORCE MODE'}
      </div>
    </div>
  );
};
