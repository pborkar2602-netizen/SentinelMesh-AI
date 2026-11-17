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
  source_report?: string;
}

export const ProofBar: React.FC<{ onJumpToEvidence?: () => void }> = ({ onJumpToEvidence }) => {
  const [counters, setCounters] = useState<HeadlineCounter[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch headline counters from static JSON or API
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
        // Fallback to API if static fetch fails
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

  return (
    <div
      className="w-full border-y border-white/10 bg-[#070b14]/90 backdrop-blur-md py-4 px-4 shadow-lg relative z-20"
      data-testid="proof-bar"
    >
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Left Rigor Tag */}
        <div className="flex items-center gap-2.5 shrink-0">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]" />
          <span className="text-xs font-mono uppercase tracking-widest text-slate-300 font-semibold">
            Empirical Proof Bar
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            zero hand-typed metrics
          </span>
        </div>

        {/* 4 Proof Metric Items */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 md:gap-8 w-full md:w-auto">
          {loading ? (
            <div className="col-span-4 text-center text-xs font-mono text-slate-400 py-1">
              Loading benchmark report metrics...
            </div>
          ) : counters.length === 0 ? (
            <div className="col-span-4 text-center text-xs font-mono text-slate-400 py-1">
              Metrics not evaluated
            </div>
          ) : (
            counters.map((c) => {
              const displayVal = c.formatted_display ?? (c.value !== null && c.value !== undefined ? String(c.value) : 'not evaluated');
              return (
                <div key={c.id} className="flex flex-col">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-lg md:text-xl font-bold font-mono text-white tracking-tight">
                      {displayVal}
                    </span>
                    {c.percentage !== undefined && c.percentage !== null && (
                      <span className="text-[11px] font-mono text-emerald-400 font-semibold">
                        ({c.percentage.toFixed(1)}%)
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 mt-0.5">
                    <span className="text-[11px] text-slate-400 capitalize">{c.title}</span>
                    {c.label && (
                      <span
                        className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white/5 border border-white/10 text-slate-400 truncate max-w-[130px]"
                        title={c.label}
                      >
                        {c.label}
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right CTA to Jump to Evidence */}
        <div className="shrink-0">
          <a
            href="#results"
            onClick={(e) => {
              if (onJumpToEvidence) {
                e.preventDefault();
                onJumpToEvidence();
              }
            }}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400 hover:text-emerald-300 transition-colors py-1.5 px-3 rounded-lg bg-emerald-500/10 border border-emerald-500/25 hover:border-emerald-500/40"
          >
            <span>Evidence showcase</span>
            <span>↓</span>
          </a>
        </div>
      </div>
    </div>
  );
};
