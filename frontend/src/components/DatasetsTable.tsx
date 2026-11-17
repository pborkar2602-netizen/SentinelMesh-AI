import React, { useState, useEffect } from 'react';

interface DatasetItem {
  name: string;
  source: string;
  commit: string;
  license: string;
  format?: string;
  size?: string;
  target_capability?: string;
  label?: string;
}

export const DatasetsTable: React.FC = () => {
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/datasets.json')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load datasets');
        return res.json();
      })
      .then((data: DatasetItem[]) => {
        setDatasets(data);
        setLoading(false);
      })
      .catch(() => {
        fetch('/api/v1/data/datasets.json')
          .then((res) => res.json())
          .then((data: DatasetItem[]) => {
            setDatasets(data);
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
      data-testid="datasets-table"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-sky-400 font-semibold">
              Evaluation Corpora
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/30 text-sky-400">
              docs/datasets.md registry
            </span>
          </div>
          <h3 className="text-lg md:text-xl font-bold text-white mt-1">
            External Benchmark Datasets & Partitioning
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Stratified 30% adapter-dev / 70% holdout test partitions committed before test evaluation
          </p>
        </div>

        <span className="text-xs font-mono text-slate-400">
          Incorporated Benchmarks: <b className="text-sky-400">{loading ? '...' : datasets.length}</b>
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
          Loading datasets registry from docs/datasets.md...
        </div>
      ) : datasets.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-400">
          Datasets not evaluated
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-[11px] font-mono border-collapse table-fixed">
            <thead>
              <tr className="border-b border-white/10 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="py-3 px-2.5 w-[14%]">Dataset Name</th>
                <th className="py-3 px-2.5 w-[22%]">Source / Reference</th>
                <th className="py-3 px-2.5 w-[10%]">Commit SHA</th>
                <th className="py-3 px-2.5 w-[11%]">License</th>
                <th className="py-3 px-2.5 w-[9%]">Volume / Size</th>
                <th className="py-3 px-2.5 w-[22%]">Target Capability</th>
                <th className="py-3 px-2.5 w-[12%]">Label</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {datasets.map((d, idx) => (
                <tr key={d.name || idx} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-3.5 px-2.5 font-semibold text-white truncate">
                    {d.name || 'not evaluated'}
                  </td>
                  <td className="py-3.5 px-2.5 text-slate-300 break-words leading-snug">
                    {d.source || 'not evaluated'}
                  </td>
                  <td className="py-3.5 px-2.5 text-slate-400">
                    <code className="bg-black/40 px-1.5 py-0.5 rounded text-[10px]">
                      {d.commit ? d.commit.substring(0, 10) : 'not evaluated'}
                    </code>
                  </td>
                  <td className="py-3.5 px-2.5 text-slate-400 truncate">
                    {d.license || 'not evaluated'}
                  </td>
                  <td className="py-3.5 px-2.5 text-slate-200 font-medium">
                    {d.size || 'not evaluated'}
                  </td>
                  <td className="py-3.5 px-2.5 text-slate-300 text-[10px] leading-relaxed break-words">
                    {d.target_capability || 'not evaluated'}
                  </td>
                  <td className="py-3.5 px-2.5">
                    <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/20 text-sky-400 inline-block truncate max-w-full">
                      {d.label ?? 'incorporated test split'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
