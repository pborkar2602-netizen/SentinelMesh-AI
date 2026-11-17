import React, { useState } from 'react';
import { LayerRadarChart } from './LayerRadarChart';
import { HeadlineCounters } from './HeadlineCounters';
import { WordingCrossoverChart } from './WordingCrossoverChart';
import { ReleaseTimeline } from './ReleaseTimeline';
import { KnownIssuesList } from './KnownIssuesList';
import { DatasetsTable } from './DatasetsTable';
import { LimitationsCards } from './LimitationsCards';

export const EvidenceSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'crossover' | 'timeline' | 'mistakes' | 'datasets' | 'limitations' | 'cluster_stats' | 'provenance'>('crossover');

  return (
    <div className="space-y-10" data-testid="evidence-section">
      {/* 1. Four Headline Counters (Dynamic from reports) */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
            Headline Scientific Proof Metrics
          </h3>
          <span className="text-[11px] font-mono text-emerald-400">
            Dynamically loaded from benchmark/reports/*.json
          </span>
        </div>
        <HeadlineCounters />
      </div>

      {/* 2. 5-Axis Defense Layer Radar Chart */}
      <LayerRadarChart />

      {/* 3. Deep-Dive Rigor Tabs */}
      <div className="space-y-6">
        {/* Tab Selection Navigation */}
        <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3">
          <button
            onClick={() => setActiveTab('crossover')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'crossover'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-crossover"
          >
            1. Wording-Crossover Chart
          </button>
          <button
            onClick={() => setActiveTab('mistakes')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'mistakes'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-mistakes"
          >
            2. Mistakes We Found
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'timeline'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-timeline"
          >
            3. Git Release Timeline
          </button>
          <button
            onClick={() => setActiveTab('datasets')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'datasets'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-datasets"
          >
            4. Datasets Registry
          </button>
          <button
            onClick={() => setActiveTab('limitations')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'limitations'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-limitations"
          >
            5. Where It Fails (Limitations)
          </button>
          <button
            onClick={() => setActiveTab('cluster_stats')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'cluster_stats'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-cluster-stats"
          >
            6. Cluster Significance
          </button>
          <button
            onClick={() => setActiveTab('provenance')}
            className={`text-xs font-mono px-3.5 py-2 rounded-xl transition-all duration-150 ${
              activeTab === 'provenance'
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
            }`}
            data-testid="tab-provenance"
          >
            7. Provenance Granularity
          </button>
        </div>

        {/* Tab 1: Wording-Crossover Chart */}
        {activeTab === 'crossover' && (
          <div className="animate-in fade-in duration-200">
            <WordingCrossoverChart />
          </div>
        )}

        {/* Tab 2: Mistakes We Found */}
        {activeTab === 'mistakes' && (
          <div className="animate-in fade-in duration-200">
            <KnownIssuesList />
          </div>
        )}

        {/* Tab 3: Git Release Timeline */}
        {activeTab === 'timeline' && (
          <div className="animate-in fade-in duration-200">
            <ReleaseTimeline />
          </div>
        )}

        {/* Tab 4: Datasets Registry */}
        {activeTab === 'datasets' && (
          <div className="animate-in fade-in duration-200">
            <DatasetsTable />
          </div>
        )}

        {/* Tab 5: Where It Fails */}
        {activeTab === 'limitations' && (
          <div className="animate-in fade-in duration-200">
            <LimitationsCards />
          </div>
        )}

        {/* Tab 6: Cluster Permutation Significance */}
        {activeTab === 'cluster_stats' && (
          <div className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-4 animate-in fade-in duration-200">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-4">
              <div>
                <h3 className="text-base md:text-lg font-bold text-white">
                  Paired Cluster-Level Permutation Tests (44 Clusters, N=748)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  100,000 sign-flip permutation resamples with exact Holm-Bonferroni family-wise error rate control
                </p>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                replaces unclustered McNemar
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-white/10 text-slate-400 uppercase tracking-wider">
                    <th className="py-3 px-3">Paired Comparison (vs B4)</th>
                    <th className="py-3 px-3">Discordant Clusters</th>
                    <th className="py-3 px-3">Score &Delta; (Mean Diff)</th>
                    <th className="py-3 px-3">Permutation p-value</th>
                    <th className="py-3 px-3">Exact Holm &alpha;</th>
                    <th className="py-3 px-3">Cluster Bootstrap 95% CI</th>
                    <th className="py-3 px-3 text-emerald-400">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  <tr className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-semibold text-white">B4 (SentinelMesh) vs B0 (No Defense)</td>
                    <td className="py-3 px-3">42 / 44 clusters</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">+0.9545</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">&lt; 1.00 &times; 10<sup>-5</sup></td>
                    <td className="py-3 px-3">0.0100</td>
                    <td className="py-3 px-3 text-slate-400">[88.6%, 100.0%] vs [0.0%, 0.0%]</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">Reject Null (p &lt; &alpha;)</td>
                  </tr>
                  <tr className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-semibold text-white">B4 (SentinelMesh) vs B1 (Domain Allowlist)</td>
                    <td className="py-3 px-3">14 / 44 clusters</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">+0.3182</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">1.30 &times; 10<sup>-4</sup></td>
                    <td className="py-3 px-3">0.0125</td>
                    <td className="py-3 px-3 text-slate-400">[88.6%, 100.0%] vs [50.0%, 77.3%]</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">Reject Null (p &lt; &alpha;)</td>
                  </tr>
                  <tr className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-semibold text-white">B4 (SentinelMesh) vs B2 (Static Regex, Base)</td>
                    <td className="py-3 px-3">42 / 44 clusters</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">+0.9545</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">&lt; 1.00 &times; 10<sup>-5</sup></td>
                    <td className="py-3 px-3">0.0167</td>
                    <td className="py-3 px-3 text-slate-400">[88.6%, 100.0%] vs [0.0%, 0.0%]</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">Reject Null (p &lt; &alpha;)</td>
                  </tr>
                  <tr className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-semibold text-white">B4 (SentinelMesh) vs B3 (Taint Disabled Ablation)</td>
                    <td className="py-3 px-3">41 / 44 clusters</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">+0.9318</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">&lt; 1.00 &times; 10<sup>-5</sup></td>
                    <td className="py-3 px-3">0.0250</td>
                    <td className="py-3 px-3 text-slate-400">[88.6%, 100.0%] vs [0.0%, 6.8%]</td>
                    <td className="py-3 px-3 font-bold text-emerald-400">Reject Null (p &lt; &alpha;)</td>
                  </tr>
                  <tr className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-semibold text-white">B4 (SentinelMesh) vs HF DeBERTa-v3 Classifier <span className="text-[10px] text-slate-400 font-normal">[N=64 empirical]</span></td>
                    <td className="py-3 px-3">N/A (N=64 sample)</td>
                    <td className="py-3 px-3 text-slate-300">+0.0639</td>
                    <td className="py-3 px-3 text-slate-300">Empirical Sample</td>
                    <td className="py-3 px-3">0.0500</td>
                    <td className="py-3 px-3 text-slate-400">[88.6%, 100.0%] vs [79.1%, 94.6%]</td>
                    <td className="py-3 px-3 font-bold text-slate-400">Wilson CIs overlap</td>
                  </tr>
                  <tr className="hover:bg-white/[0.02] opacity-60">
                    <td className="py-3 px-3 font-semibold text-slate-400">B5: LLM Safety Judge</td>
                    <td className="py-3 px-3" colSpan={5}>
                      Judge not evaluated (no recorded LLM API verdicts; stub removed per preregistered protocol)
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">Not Evaluated</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 7: Provenance Granularity */}
        {activeTab === 'provenance' && (
          <div className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-4 animate-in fade-in duration-200">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-4">
              <div>
                <h3 className="text-base md:text-lg font-bold text-white">
                  Provenance Granularity Ablation (10,000 Simulated Sessions)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Comparison between coarse session-level taint tracking and SentinelMesh value-level data provenance
                </p>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                0.0% false positive rate
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-500/[0.03] space-y-2">
                <h4 className="text-sm font-bold text-rose-400 font-mono">
                  Session-Level Coarse Taint
                </h4>
                <div className="space-y-1.5 text-xs font-mono text-slate-300">
                  <div className="flex justify-between">
                    <span>Benign Actions in Tainted Session:</span>
                    <span className="text-rose-400 font-bold">100.0% False Positive Rate</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Usability Impact:</span>
                    <span className="text-rose-300">Completely halts multi-task agents</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Lookup Complexity:</span>
                    <span className="text-slate-400">O(1) bool lookup</span>
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 pt-2 border-t border-rose-500/10 leading-relaxed">
                  Once a session ingests an untrusted document, all subsequent independent benign actions
                  (e.g., querying public tables or emailing colleagues) are incorrectly blocked.
                </p>
              </div>

              <div className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.03] space-y-2">
                <h4 className="text-sm font-bold text-emerald-400 font-mono">
                  SentinelMesh Value-Level Provenance
                </h4>
                <div className="space-y-1.5 text-xs font-mono text-slate-300">
                  <div className="flex justify-between">
                    <span>Benign Actions in Tainted Session:</span>
                    <span className="text-emerald-400 font-bold">0.0% False Positive Rate</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Usability Impact:</span>
                    <span className="text-emerald-300">Allows safe actions; blocks tainted flow</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Graph Traversal Complexity:</span>
                    <span className="text-slate-400">O(V + E) sub-millisecond DAG trace</span>
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 pt-2 border-t border-emerald-500/10 leading-relaxed">
                  Taint follows specific ingested tokens into variables and arguments. Independent benign actions
                  continue unhindered, preserving agent utility.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
