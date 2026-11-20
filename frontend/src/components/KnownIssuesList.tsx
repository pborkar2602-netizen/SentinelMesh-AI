import React, { useState, useEffect } from 'react';
import { ArrowRight, ChevronDown, ChevronRight } from 'lucide-react';

interface KnownIssue {
  id: string;
  title: string;
  before?: string;
  after?: string;
  summary?: string;
  finding: string;
  resolution: string;
  label?: string;
  commit?: string;
}

function renderInlineCode(text: string): React.ReactNode {
  if (!text) return null;
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return (
        <code
          key={i}
          className="px-1.5 py-0.5 mx-0.5 rounded bg-white/10 text-cyan-300 font-mono text-[11px]"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <React.Fragment key={i}>{part}</React.Fragment>;
  });
}

export const KnownIssuesList: React.FC = () => {
  const [issues, setIssues] = useState<KnownIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

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

  const toggleExpand = (id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div
      id="known-issues-list"
      className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6"
      data-testid="known-issues-list"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400 font-semibold">
              Audit Trail
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">
              zero error suppression
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            Methodology Corrections & Evaluation Errata
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Scan Before → After deltas at a glance; expand any card for full technical mechanics
          </p>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Corrections Logged: <b className="text-amber-400">{loading ? '...' : issues.length}</b>
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading evaluation errata from docs/known_issues.md...
        </div>
      ) : issues.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400">
          Audit issues not evaluated
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {issues.map((issue, idx) => {
            const key = issue.id || String(idx);
            const isOpen = !!expanded[key];
            return (
              <div
                key={key}
                className="bg-white/[0.02] border border-white/10 hover:border-cyan-500/30 p-5 rounded-xl flex flex-col justify-between space-y-3.5 transition-all duration-150"
              >
                <div className="space-y-3">
                  {/* Top Title + Label + Commit */}
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="text-sm font-semibold text-white leading-snug">
                      <span className="font-mono text-amber-400 mr-1.5">{idx + 1}.</span>
                      {issue.title || 'not evaluated'}
                    </h4>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {issue.label && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/25 text-amber-300">
                          {issue.label}
                        </span>
                      )}
                      {issue.commit && (
                        <code className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                          {issue.commit}
                        </code>
                      )}
                    </div>
                  </div>

                  {/* Visual Before -> After Delta Strip */}
                  {(issue.before || issue.after) && (
                    <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2 p-2.5 rounded-lg bg-black/50 border border-white/10">
                      <div className="min-w-0">
                        <span className="block text-[9px] font-mono uppercase tracking-wider text-rose-400 mb-0.5">
                          Before
                        </span>
                        <span className="block font-mono text-[11px] text-rose-200 truncate" title={issue.before}>
                          {issue.before || 'not evaluated'}
                        </span>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-500 shrink-0" />
                      <div className="min-w-0">
                        <span className="block text-[9px] font-mono uppercase tracking-wider text-emerald-400 mb-0.5">
                          After
                        </span>
                        <span className="block font-mono text-[11px] text-emerald-300 truncate" title={issue.after}>
                          {issue.after || 'not evaluated'}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Plain-language 1-line summary */}
                  <p className="text-sm text-slate-300 font-sans leading-relaxed">
                    {renderInlineCode(issue.summary || issue.finding)}
                  </p>
                </div>

                {/* Expandable Technical Detail Toggle */}
                <div className="pt-2 border-t border-white/5">
                  <button
                    type="button"
                    onClick={() => toggleExpand(key)}
                    className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                    data-testid={`issue-detail-toggle-${key}`}
                  >
                    {isOpen ? (
                      <ChevronDown className="w-3.5 h-3.5" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5" />
                    )}
                    <span>{isOpen ? 'Hide technical detail' : 'Technical detail'}</span>
                  </button>

                  {isOpen && (
                    <div className="mt-3 space-y-2.5 text-xs font-sans">
                      <div className="p-3 rounded-lg bg-black/40 border border-rose-500/20">
                        <span className="text-rose-400 font-mono text-[10px] uppercase font-bold block mb-1">
                          Root Cause
                        </span>
                        <p className="text-slate-300 leading-relaxed">
                          {renderInlineCode(issue.finding || 'not evaluated')}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-black/40 border border-emerald-500/20">
                        <span className="text-emerald-400 font-mono text-[10px] uppercase font-bold block mb-1">
                          Fix Applied
                        </span>
                        <p className="text-slate-300 leading-relaxed">
                          {renderInlineCode(issue.resolution || 'not evaluated')}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
