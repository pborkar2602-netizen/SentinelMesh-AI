import React from 'react';
import { Incident } from '../types';
import { ChevronRight, Activity } from 'lucide-react';

interface IncidentListProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
}

export const IncidentList: React.FC<IncidentListProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
}) => {
  if (incidents.length === 0) {
    return null;
  }

  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur font-mono mb-6">
      <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-rd" />
          <h2 className="text-sm font-semibold tracking-wide text-ink uppercase flex items-center gap-2">
            Reconstructed Incidents ({incidents.length})
          </h2>
        </div>
        <span className="text-[10px] text-mut">Select an incident to view attack chain</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {incidents.map((inc) => {
          const isSelected = selectedIncidentId === inc.id;
          const isBlocked = inc.status === 'BLOCKED';

          return (
            <div
              key={inc.id}
              onClick={() => onSelectIncident(inc.id)}
              className={`p-3 rounded-lg border cursor-pointer select-none transition-all ${
                isSelected
                  ? 'border-cy bg-cy/10 shadow-[0_0_12px_rgba(79,179,199,0.2)]'
                  : 'border-line bg-bg2/80 hover:border-cy/40'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                  isBlocked
                    ? 'bg-rd/15 text-rd border-rd/30'
                    : 'bg-am/15 text-am border-am/30'
                }`}>
                  {inc.status}
                </span>

                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${
                  inc.severity === 'CRITICAL'
                    ? 'bg-rd/20 text-rd border-rd/40'
                    : 'bg-am/20 text-am border-am/40'
                }`}>
                  {inc.severity}
                </span>

                <span className="text-[10px] font-bold text-ink">
                  RISK {inc.risk_score}
                </span>
              </div>

              <div className="font-bold text-xs text-ink truncate mb-1">
                {inc.title}
              </div>

              <div className="text-[10px] text-mut flex items-center justify-between pt-1 border-t border-line/40">
                <span>{inc.agent_id}</span>
                <span className="text-cy flex items-center">
                  {inc.id} <ChevronRight className="w-3 h-3 inline" />
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
