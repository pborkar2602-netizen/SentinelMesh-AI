import React, { useState, useEffect } from 'react';

interface LimitationItem {
  id: string;
  title: string;
  failure_mode: string;
  empirical_evidence: string;
  label?: string;
}

export const LimitationsCards: React.FC = () => {
  const [limitations, setLimitations] = useState<LimitationItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/limitations.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load limitations');
        return res.json();
      })
      .then((data: LimitationItem[]) => {
        setLimitations(data);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/data/limitations.json')
          .then((res) => res.json())
          .then((data: LimitationItem[]) => {
            setLimitations(data);
            setLoading(false);
          })
          .catch(() => {
            setLoading(false);
          });
      });
  }, []);

  return (
    <div
      className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6"
      data-testid="limitations-cards"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-rose-400 font-semibold">
              Failure Boundaries
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400">
              docs/limitations.md specification
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            Where SentinelMesh Fails: Verified Attack Boundaries
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Honest accounting of missed attacks, structural edge cases, and hardware performance thresholds
          </p>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Documented Failure Modes: <b className="text-rose-400">{loading ? '...' : limitations.length}</b>
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading failure boundary cards from docs/limitations.md...
        </div>
      ) : limitations.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400">
          Failure modes not evaluated
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {limitations.map((lim, idx) => (
            <div
              key={lim.id || idx}
              className="bg-white/[0.02] border border-white/5 hover:border-rose-500/30 p-4 rounded-xl flex flex-col justify-between space-y-3 transition-all duration-150 group"
            >
              <div>
                <div className="flex flex-col gap-1.5 mb-3">
                  <h4 className="text-xs font-mono font-bold text-white group-hover:text-rose-300 transition-colors leading-snug">
                    {lim.title || 'not evaluated'}
                  </h4>
                  {lim.label && (
                    <div>
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/25 text-rose-400 inline-block">
                        {lim.label}
                      </span>
                    </div>
                  )}
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 text-slate-300">
                    <span className="text-slate-400 font-bold block mb-1">Failure Mechanism:</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {lim.failure_mode || 'not evaluated'}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/40 border border-rose-500/10 text-slate-300">
                    <span className="text-rose-400 font-bold block mb-1">Empirical Evidence:</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {lim.empirical_evidence || 'not evaluated'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Boundary Type:</span>
                <span className="text-amber-400/90 font-semibold">{lim.label || 'Documented Blindspot'}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
