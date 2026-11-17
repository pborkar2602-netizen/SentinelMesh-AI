import React, { useState, useEffect } from 'react';

interface HeadlineCounter {
  id: string;
  title: string;
  value: number | null;
  total?: number | null;
  percentage?: number | null;
  formatted_display?: string;
  suffix?: string;
  label?: string;
  ci_95?: [number, number] | null;
  source_report?: string;
}

export const HeadlineCounters: React.FC = () => {
  const [counters, setCounters] = useState<HeadlineCounter[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/headline_counters.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load headline counters');
        return res.json();
      })
      .then((data: HeadlineCounter[]) => {
        setCounters(data);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/data/headline_counters.json')
          .then((res) => res.json())
          .then((data: HeadlineCounter[]) => {
            setCounters(data);
            setLoading(false);
          })
          .catch(() => {
            setLoading(false);
          });
      });
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 animate-pulse">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="bg-[#0b0f19]/80 border border-white/10 rounded-2xl p-6 h-36" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="headline-counters">
      {/* 4 Cards Grid - Reference .rs layout */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {counters.map((c) => {
          const displayVal = c.formatted_display ?? (c.value !== null && c.value !== undefined ? String(c.value) : 'not evaluated');
          const isNotEvaluated = displayVal === 'not evaluated';

          return (
            <div
              key={c.id}
              className="bg-[#0b0f19]/85 border border-white/10 hover:border-emerald-500/30 rounded-2xl p-5 shadow-lg backdrop-blur-md relative overflow-hidden transition-all duration-200 group flex flex-col justify-between"
            >
              <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500/40 via-teal-400/40 to-sky-500/40 opacity-70 group-hover:opacity-100 transition-opacity" />
              
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold truncate">
                    {c.title}
                  </span>
                  {c.source_report && (
                    <span className="text-[9px] font-mono text-slate-500 shrink-0">
                      {c.source_report.replace('.json', '')}
                    </span>
                  )}
                </div>

                <div className="flex items-baseline gap-2">
                  <span
                    className={`font-mono font-extrabold tracking-tight ${
                      isNotEvaluated
                        ? 'text-slate-500 text-xl'
                        : 'text-white text-3xl md:text-4xl'
                    }`}
                    data-testid={`counter-${c.id}`}
                  >
                    {displayVal}
                  </span>
                  {c.percentage !== undefined && c.percentage !== null && !isNotEvaluated && (
                    <span className="text-xs font-mono text-emerald-400 font-bold">
                      {c.percentage.toFixed(1)}%
                    </span>
                  )}
                </div>

                {c.ci_95 && (
                  <p className="text-[11px] text-slate-400 font-mono mt-1">
                    Cluster 95% CI: [{c.ci_95[0].toFixed(1)}%, {c.ci_95[1].toFixed(1)}%]
                  </p>
                )}
              </div>

              <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                  {c.label ?? 'not evaluated'}
                </span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/60" />
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-xs text-slate-400 font-mono leading-relaxed px-1">
        <b className="text-slate-300">Honest Scope:</b> All headline metrics are dynamically read from generated JSON reports in <code className="text-emerald-400">benchmark/reports/</code>. Zero hand-typed constants. If a report field is missing, it displays &ldquo;not evaluated&rdquo;.
      </p>
    </div>
  );
};
