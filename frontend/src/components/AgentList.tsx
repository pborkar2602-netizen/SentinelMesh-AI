import React from 'react';
import { Bot, Wrench, CheckCircle } from 'lucide-react';
import { Agent } from '../types';

interface AgentListProps {
  agents: Agent[];
  selectedAgent: string | null;
  onSelectAgent: (agentId: string | null) => void;
}

export const AgentList: React.FC<AgentListProps> = ({
  agents,
  selectedAgent,
  onSelectAgent,
}) => {
  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col h-full">
      <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-cy" />
          <h2 className="text-sm font-semibold tracking-wide text-ink uppercase">
            Monitored Agents ({agents.length})
          </h2>
        </div>
        {selectedAgent && (
          <button
            onClick={() => onSelectAgent(null)}
            className="text-[11px] text-cy hover:underline font-mono"
          >
            Show All
          </button>
        )}
      </div>

      <div className="space-y-2.5 overflow-y-auto pr-1 flex-1">
        {agents.map((agent) => {
          const isSelected = selectedAgent === agent.id;
          return (
            <div
              key={agent.id}
              onClick={() => onSelectAgent(isSelected ? null : agent.id)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-cy/10 border-cy text-ink shadow-[0_0_12px_rgba(79,179,199,0.15)]'
                  : 'bg-bg2/80 border-line hover:border-mut/50 text-ink/90'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-bold text-cy">
                  {agent.id}
                </span>
                <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-gr/15 text-gr border border-gr/30">
                  <CheckCircle className="w-2.5 h-2.5" /> Active
                </span>
              </div>

              <div className="text-xs font-semibold text-ink mb-1">
                {agent.name}
              </div>

              <p className="text-[11px] text-mut line-clamp-2 mb-2 leading-relaxed">
                {agent.declared_purpose}
              </p>

              <div className="flex flex-wrap gap-1">
                {agent.allowed_tools.map((tool) => (
                  <span
                    key={tool}
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg border border-line text-mut flex items-center gap-1"
                  >
                    <Wrench className="w-2.5 h-2.5 text-mut/80" />
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
