import React, { useState, useEffect } from 'react';

interface KnownIssue {
  id: string;
  title: string;
  finding: string;
  resolution: string;
  label?: string;
  commit?: string;
}

export const KnownIssuesList: React.FC = () => {
  const [issues, setIssues] = useState<KnownIssue[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/known_issues.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load known issues');
        return res.json();
      })
      .then((data: KnownIssue[]) => {
        setIssues(data);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/data/known_issues.json')
          .then((res) => res.json())
          .then((data: KnownIssue[]) => {
            setIssues(data);
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
      data-testid="known-issues-list"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400 font-semibold">
              Scientific Audit Trail
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">
              zero suppression of errors
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            Mistakes We Found & How We Fixed Them
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent record of methodological bugs, adapter fixes, and statistical adjustments identified during audit rounds
          </p>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Documented Findings: <b className="text-amber-400">{loading ? '...' : issues.length}</b>
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading audit findings from docs/known_issues.md...
        </div>
      ) : issues.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400">
          Audit issues not evaluated
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {issues.map((issue, idx) => (
            <div
              key={issue.id || idx}
              className="bg-white/[0.02] border border-white/5 hover:border-amber-500/30 p-4 rounded-xl flex flex-col justify-between space-y-3 transition-all duration-150 group"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <h4 className="text-xs font-mono font-bold text-white group-hover:text-amber-300 transition-colors">
                    {idx + 1}. {issue.title || 'not evaluated'}
                  </h4>
                  {issue.label && (
                    <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/25 text-amber-300 shrink-0">
                      {issue.label}
                    </span>
                  )}
                </div>

                <div className="space-y-2 text-xs font-mono text-slate-300">
                  <div className="p-2.5 rounded-lg bg-black/40 border border-rose-500/20 text-slate-300">
                    <span className="text-rose-400 font-bold block mb-1">Audit Finding:</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {issue.finding || 'not evaluated'}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/40 border border-emerald-500/20 text-slate-300">
                    <span className="text-emerald-400 font-bold block mb-1">Resolution:</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {issue.resolution || 'not evaluated'}
                    </p>
                  </div>
                </div>
              </div>

              {issue.commit && (
                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span>Resolved in commit:</span>
                  <code className="text-slate-300 bg-white/5 px-1.5 py-0.5 rounded">
                    {issue.commit}
                  </code>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
