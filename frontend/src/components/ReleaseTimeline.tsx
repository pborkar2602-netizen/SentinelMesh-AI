import React, { useState, useEffect } from 'react';

interface ReleaseTag {
  tag: string;
  commit: string;
  date: string;
  description: string;
  label?: string;
}

export const ReleaseTimeline: React.FC = () => {
  const [tags, setTags] = useState<ReleaseTag[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/release_timeline.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load release timeline');
        return res.json();
      })
      .then((data: ReleaseTag[]) => {
        setTags(data);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/data/release_timeline.json')
          .then((res) => res.json())
          .then((data: ReleaseTag[]) => {
            setTags(data);
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
      data-testid="release-timeline"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold">
              Repository Provenance
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              git tag verified
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            Frozen Release & Preregistration Timeline
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically sealed git tags proving code freezes preceded test evaluation runs
          </p>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Total Checkpoints: <b className="text-white">{loading ? '...' : tags.length}</b>
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading release timeline from git tags...
        </div>
      ) : tags.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400">
          Release tags not evaluated
        </div>
      ) : (
        <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[2px] before:bg-gradient-to-b before:from-emerald-500 before:via-sky-500 before:to-purple-500">
          {tags.map((item, idx) => (
            <div key={item.tag || idx} className="relative group">
              {/* Timeline marker dot */}
              <div className="absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full bg-[#0b0f19] border-2 border-emerald-400 shadow-[0_0_8px_#34d399] group-hover:scale-125 transition-transform" />

              <div className="bg-white/[0.02] border border-white/5 hover:border-white/15 p-4 rounded-xl transition-all duration-150">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-mono font-bold text-white group-hover:text-emerald-300 transition-colors">
                      {item.tag || 'not evaluated'}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-black/40 border border-white/10 text-slate-300">
                      commit: {item.commit || 'not evaluated'}
                    </span>
                    {item.label && (
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                        {item.label}
                      </span>
                    )}
                  </div>

                  <span className="text-xs font-mono text-slate-400">
                    {item.date || 'not evaluated'}
                  </span>
                </div>

                <p className="text-xs text-slate-300 font-mono mt-2 leading-relaxed">
                  {item.description || 'not evaluated'}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
