import React from 'react';
import { Eye, ShieldAlert, CheckCircle2, Clock } from 'lucide-react';
import { AuditEvent } from '../types';

interface QuickStatsProps {
  events: AuditEvent[];
  agentCount: number;
}

export const QuickStats: React.FC<QuickStatsProps> = ({ events }) => {
  const totalInspected = events.length;
  const totalAllowed = events.filter((e) => e.decision === 'allow').length;
  const totalBlocked = events.filter((e) => e.decision === 'block').length;

  const latencies = events
    .map((e) => e.latency_ms)
    .filter((l): l is number => typeof l === 'number' && !isNaN(l));
  latencies.sort((a, b) => a - b);
  const p95Latency =
    latencies.length > 0
      ? latencies[Math.floor(latencies.length * 0.95)] ?? latencies[latencies.length - 1] ?? 0.8
      : 0.8;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      <div className="p-3.5 rounded-xl bg-pan border border-line backdrop-blur">
        <div className="flex items-center justify-between text-mut text-xs mb-1">
          <span>Actions Inspected</span>
          <Eye className="w-4 h-4 text-cy" />
        </div>
        <div className="text-2xl font-bold font-mono text-cy">
          {totalInspected}
        </div>
      </div>

      <div className="p-3.5 rounded-xl bg-pan border border-line backdrop-blur">
        <div className="flex items-center justify-between text-mut text-xs mb-1">
          <span>Decisions Allowed</span>
          <CheckCircle2 className="w-4 h-4 text-gr" />
        </div>
        <div className="text-2xl font-bold font-mono text-gr">
          {totalAllowed}
        </div>
      </div>

      <div className="p-3.5 rounded-xl bg-pan border border-line backdrop-blur">
        <div className="flex items-center justify-between text-mut text-xs mb-1">
          <span>Threats Blocked</span>
          <ShieldAlert className="w-4 h-4 text-rd" />
        </div>
        <div className="text-2xl font-bold font-mono text-rd">
          {totalBlocked}
        </div>
      </div>

      <div className="p-3.5 rounded-xl bg-pan border border-line backdrop-blur">
        <div className="flex items-center justify-between text-mut text-xs mb-1">
          <span>Gateway Latency (p95)</span>
          <Clock className="w-4 h-4 text-mut" />
        </div>
        <div className="text-2xl font-bold font-mono text-ink">
          {p95Latency.toFixed(1)} <span className="text-xs font-normal text-mut">ms</span>
        </div>
      </div>
    </div>
  );
};
