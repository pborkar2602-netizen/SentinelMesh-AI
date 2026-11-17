import React, { useState, useEffect } from 'react';

interface SystemSummary {
  system: string;
  label_note?: string;
  total_evaluated?: number;
  total_prevented?: number;
  prevention_rate_pct?: number;
  dh_prevention_pct?: number;
  ds_prevention_pct?: number;
  benign_fp_pct?: number;
  cluster_bootstrap_ci?: [number, number];
  wilson_ci?: [number, number];
}

interface SettingData {
  setting: string;
  run_status: string;
  total_test_cases: number;
  unique_clusters: number;
  summary: SystemSummary[];
}

interface InjecAgentBothSettings {
  base?: SettingData;
  enhanced?: SettingData;
}

export const WordingCrossoverChart: React.FC = () => {
  const [activeSetting, setActiveSetting] = useState<'base' | 'enhanced'>('base');
  const [data, setData] = useState<InjecAgentBothSettings | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/reports/v3_injecagent_both_settings.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load v3_injecagent_both_settings.json');
        return res.json();
      })
      .then((json: InjecAgentBothSettings) => {
        setData(json);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/reports/v3_injecagent_both_settings.json')
          .then((res) => res.json())
          .then((json: InjecAgentBothSettings) => {
            setData(json);
            setLoading(false);
          })
          .catch(() => {
            setLoading(false);
          });
      });
  }, []);

  const currentSettingData = data ? data[activeSetting] : null;

  return (
    <div
      className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6"
      data-testid="wording-crossover-chart"
    >
      {/* Header and Toggle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold">
              InjecAgent Benchmark · Zhan et al. (ACL 2024)
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">
              adapter fixed after seeing results
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            The Wording-Crossover Phenomenon
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Test partition: N = 748 cases across 44 attacker clusters · 95% cluster-bootstrap confidence intervals
          </p>
        </div>

        {/* Base vs Enhanced Setting Toggle Buttons */}
        <div className="flex items-center bg-black/40 p-1 rounded-xl border border-white/10 shrink-0">
          <button
            onClick={() => setActiveSetting('base')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all duration-150 ${
              activeSetting === 'base'
                ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
            data-testid="toggle-base-setting"
          >
            Base Prompts (Organic)
          </button>
          <button
            onClick={() => setActiveSetting('enhanced')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all duration-150 ${
              activeSetting === 'enhanced'
                ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
            data-testid="toggle-enhanced-setting"
          >
            Enhanced (Overt Hacking)
          </button>
        </div>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading InjecAgent dual-setting benchmark data...
        </div>
      ) : !currentSettingData ? (
        <div className="py-12 text-center text-xs font-mono text-slate-400">
          Report data not evaluated
        </div>
      ) : (
        <div className="space-y-5">
          {/* Crossover Status Banner */}
          <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Active Setting:</span>
              <span className="text-white font-semibold uppercase">{activeSetting} Hacking Prompt</span>
              <span className="text-slate-500">·</span>
              <span className="text-emerald-400">
                {activeSetting === 'base'
                  ? 'B2 Regex 0.0% vs SentinelMesh 95.5%'
                  : 'B2 Regex jumps to 100.0% vs SentinelMesh steady at 95.5%'}
              </span>
            </div>
            <span className="text-[11px] text-slate-400">
              Unique Clusters: <b className="text-slate-200">{currentSettingData.unique_clusters ?? 'not evaluated'}</b>
            </span>
          </div>

          {/* Systems Chart Rows */}
          <div className="space-y-4">
            {currentSettingData.summary.map((sys) => {
              const prevRate = sys.prevention_rate_pct;
              const hasPrevRate = prevRate !== undefined && prevRate !== null;
              const ci = sys.cluster_bootstrap_ci;
              const isB4 = sys.system.includes('B4:');
              const isB2 = sys.system.includes('B2:');
              const isHF = sys.system.includes('HuggingFace');
              const isLayered = sys.system.includes('Exploratory');

              // Determine system label
              let systemLabel = sys.label_note?.replace(/[\[\]]/g, '').trim() || '';
              if (isHF) {
                systemLabel = `small sample (${systemLabel || 'N=64 empirical'})`;
              } else if (!systemLabel) {
                if (isB4) systemLabel = 'adapter fixed after seeing results';
                else if (isLayered) systemLabel = 'exploratory: designed after seeing results';
                else systemLabel = 'baseline';
              }

              return (
                <div
                  key={sys.system}
                  className={`p-3.5 rounded-xl border transition-all duration-200 ${
                    isB4
                      ? 'bg-emerald-500/[0.04] border-emerald-500/30 shadow-[0_0_15px_rgba(52,211,153,0.05)]'
                      : isB2
                      ? 'bg-amber-500/[0.03] border-amber-500/20'
                      : 'bg-white/[0.015] border-white/5'
                  }`}
                  data-testid={`system-row-${sys.system.split(':')[0].trim().replace(/\s+/g, '-').toLowerCase()}`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono font-semibold ${isB4 ? 'text-emerald-300' : 'text-white'}`}>
                        {sys.system}
                      </span>
                      {systemLabel && (
                        <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-white/5 border border-white/10 text-slate-400">
                          {systemLabel}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs font-mono shrink-0">
                      {sys.dh_prevention_pct !== undefined && sys.dh_prevention_pct !== null && (
                        <span className="text-slate-400">
                          DH: <b className="text-slate-200">{sys.dh_prevention_pct.toFixed(1)}%</b>
                        </span>
                      )}
                      {sys.ds_prevention_pct !== undefined && sys.ds_prevention_pct !== null && (
                        <span className="text-slate-400">
                          DS: <b className="text-slate-200">{sys.ds_prevention_pct.toFixed(1)}%</b>
                        </span>
                      )}
                      <span
                        className={`text-sm font-bold font-mono ${
                          isB4 ? 'text-emerald-400' : hasPrevRate && prevRate > 50 ? 'text-white' : 'text-slate-400'
                        }`}
                      >
                        {hasPrevRate ? `${prevRate.toFixed(1)}%` : 'not evaluated'}
                      </span>
                    </div>
                  </div>

                  {/* Animated Bar & 95% Confidence Interval Line */}
                  <div className="relative pt-1 pb-1">
                    {/* Background track */}
                    <div className="w-full h-3.5 bg-black/50 rounded-full overflow-hidden border border-white/5 relative">
                      {hasPrevRate && (
                        <div
                          className={`h-full rounded-full transition-all duration-500 ease-out ${
                            isB4
                              ? 'bg-gradient-to-r from-emerald-500 to-teal-400 shadow-[0_0_12px_rgba(52,211,153,0.4)]'
                              : isB2
                              ? 'bg-gradient-to-r from-amber-500 to-rose-400'
                              : isHF
                              ? 'bg-gradient-to-r from-sky-500 to-indigo-500'
                              : 'bg-slate-600'
                          }`}
                          style={{ width: `${Math.min(100, Math.max(0, prevRate))}%` }}
                        />
                      )}
                    </div>

                    {/* 95% Cluster-Bootstrap Interval Whisker Line */}
                    {ci && ci.length === 2 && (
                      <div className="mt-1.5 space-y-1">
                        {/* Connecting whisker line & brackets */}
                        <div className="relative h-2 w-full">
                          {/* Horizontal line */}
                          <div
                            className="absolute h-[2px] bg-slate-400/80 top-1/2 -translate-y-1/2"
                            style={{
                              left: `${Math.min(100, Math.max(0, ci[0]))}%`,
                              width: `${Math.max(1, Math.min(100 - ci[0], ci[1] - ci[0]))}%`,
                            }}
                          />
                          {/* Left tick */}
                          <div
                            className="absolute w-[2px] h-2.5 bg-slate-300 top-1/2 -translate-y-1/2"
                            style={{ left: `${Math.min(100, Math.max(0, ci[0]))}%` }}
                          />
                          {/* Right tick */}
                          <div
                            className="absolute w-[2px] h-2.5 bg-slate-300 top-1/2 -translate-y-1/2"
                            style={{ left: `${Math.min(100, Math.max(0, ci[1]))}%` }}
                          />
                        </div>
                        {/* Separate Label Row underneath (no overlap) */}
                        <div className="flex justify-between items-center text-[10px] font-mono text-slate-400">
                          <span className="text-slate-500">cluster bootstrap interval</span>
                          <span className="text-slate-300">
                            95% CI: [{ci[0].toFixed(1)}%, {ci[1].toFixed(1)}%]
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Rigor Explanatory Callout */}
          <div className="p-4 rounded-xl bg-emerald-500/[0.03] border border-emerald-500/20 text-xs font-mono text-slate-300 space-y-1.5 leading-relaxed">
            <div className="text-emerald-400 font-bold flex items-center gap-1.5">
              <span>Why the Wording Crossover Occurs:</span>
            </div>
            <p>
              In the <b>Base Setting</b>, indirect prompt injections use natural language phrasing without explicit attack tokens. As a result, static regex (B2) completely fails (<b>0.0%</b> prevention).
            </p>
            <p>
              In the <b>Enhanced Setting</b>, the injection prompts include explicit adversarial trigger strings (&ldquo;IMPORTANT SYSTEM OVERRIDE...&rdquo;). Static regex (B2) abruptly jumps from <b>0.0% to 100.0%</b> simply due to lexical keyword matching.
            </p>
            <p className="text-white">
              <b>SentinelMesh (B4) is invariant to prompt phrasing:</b> It maintains exactly <b>95.5%</b> prevention across both settings because data provenance tracks where the data came from, rather than guessing what the words mean.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
