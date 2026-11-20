import React, { useState, useEffect, useCallback } from 'react';
import { AgentMesh } from '../components/AgentMesh';
import { ApprovalQueue } from '../components/ApprovalQueue';
import { IncidentList } from '../components/IncidentList';
import { AuditEvent, DashboardStats, Incident } from '../types';
import { TickerLine } from './OverviewPage';

export interface SimChainStep {
  num: string;
  title: string;
  desc: string;
  cls: string;
}

const SIGNAL_BARS: [string, string][] = [
  ['Untrusted taint', 'var(--am)'],
  ['Sensitive data', 'var(--vi)'],
  ['External destination', 'var(--ro)'],
  ['Rule findings', 'var(--cy)'],
];

interface ConsolePageProps {
  stats: DashboardStats | null;
  policyMode: 'enforce' | 'monitor';
  events: AuditEvent[];
  attackPulseTrigger: { blocked: boolean; seq: number } | null;
  feedLines: TickerLine[];
  showToolReturn: boolean;
  onToggleToolReturn: (v: boolean) => void;
  liveAttackRunning: boolean;
  chainSteps: SimChainStep[];
  stepActive: boolean[];
  stepClasses: string[];
  riskGauge: number;
  barWidths: number[];
  verdict: { show: boolean; ok: boolean; text: string };
  onSwitchMode: (m: 'enforce' | 'monitor') => void;
  onRunSimulation: () => void;
  onTriggerRealAttack: () => void;
  onRefreshStats: () => void;
}

export const ConsolePage: React.FC<ConsolePageProps> = ({
  stats,
  policyMode,
  events,
  attackPulseTrigger,
  feedLines,
  showToolReturn,
  onToggleToolReturn,
  liveAttackRunning,
  chainSteps,
  stepActive,
  stepClasses,
  riskGauge,
  barWidths,
  verdict,
  onSwitchMode,
  onRunSimulation,
  onTriggerRealAttack,
  onRefreshStats,
}) => {
  const [subTab, setSubTab] = useState<'interception' | 'approvals' | 'incidents'>('interception');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [loadingIncidents, setLoadingIncidents] = useState(false);

  const fetchIncidents = useCallback(async () => {
    setLoadingIncidents(true);
    try {
      const res = await fetch('/api/v1/incidents?limit=25&exclude_benchmark=true');
      if (res.ok) {
        const data: Incident[] = await res.json();
        setIncidents(data);
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].id);
        }
      }
    } catch {
      // Ignore offline errors cleanly
    } finally {
      setLoadingIncidents(false);
    }
  }, [selectedIncidentId]);

  useEffect(() => {
    if (subTab === 'incidents') {
      fetchIncidents();
    }
  }, [subTab, fetchIncidents]);

  const displayedFeed = showToolReturn
    ? feedLines
    : feedLines.filter((l) => !l.text.toLowerCase().includes('tool_return'));

  const selectedIncident = incidents.find((i) => i.id === selectedIncidentId) || null;

  return (
    <div className="page-shell">
      <div className="w space-y-6" data-testid="console-page">
        {/* Header + Sub-tabs */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div>
            <div className="eb" style={{ marginBottom: '8px' }}>Security Operations Console</div>
            <h2 style={{ fontSize: 'clamp(26px, 3.2vw, 40px)' }}>Live Gateway Control & Interception</h2>
            <p className="text-sm text-slate-400 mt-2 max-w-2xl font-sans">
              Inspect multi-step tool chains in Enforce or Monitor mode, adjudicate held actions with
              one-time HMAC approval tokens, and trace reconstructed incidents.
            </p>
          </div>

          <div className="seg shrink-0" role="tablist" aria-label="Console workspaces">
            <button
              type="button"
              className={subTab === 'interception' ? 'on' : ''}
              onClick={() => setSubTab('interception')}
              data-testid="console-tab-interception"
            >
              Live Interception
            </button>
            <button
              type="button"
              className={subTab === 'approvals' ? 'on' : ''}
              onClick={() => setSubTab('approvals')}
              data-testid="console-tab-approvals"
            >
              Approvals ({stats?.pending_approvals ?? 0})
            </button>
            <button
              type="button"
              className={subTab === 'incidents' ? 'on' : ''}
              onClick={() => setSubTab('incidents')}
              data-testid="console-tab-incidents"
            >
              Incidents ({stats?.active_incidents ?? incidents.length})
            </button>
          </div>
        </div>

        {/* Authoritative DB KPI Strip */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3" id="console-kpi-strip" data-testid="console-kpi-strip">
          <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
              Total Actions
            </span>
            <strong className="text-2xl font-mono font-bold text-white mt-1 block">
              {stats?.total_actions ?? 0}
            </strong>
          </div>
          <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
              Blocked Inline
            </span>
            <strong className="text-2xl font-mono font-bold text-rose-400 mt-1 block">
              {stats?.blocked_actions ?? 0}
            </strong>
          </div>
          <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
              Held for Approval
            </span>
            <strong className="text-2xl font-mono font-bold text-amber-400 mt-1 block">
              {stats?.held_for_approval_actions ?? 0}
            </strong>
          </div>
          <div className="p-4 rounded-2xl bg-[#0b0f19]/90 border border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
              Enforcement Mode
            </span>
            <strong
              className={`text-2xl font-mono font-bold uppercase mt-1 block ${
                policyMode === 'enforce' ? 'text-emerald-400' : 'text-amber-400'
              }`}
            >
              {policyMode}
            </strong>
          </div>
        </div>

        {/* Sub-tab 1: Live Interception */}
        {subTab === 'interception' && (
          <div className="con" id="demo">
            {/* Card A: 5-step Attack Chain */}
            <div className="card A" id="chain-card">
              <div className="hd">
                <div className="flex flex-col gap-1.5">
                  <div className="seg" id="mode-seg">
                    <button
                      id="mM"
                      className={policyMode === 'monitor' ? 'on' : ''}
                      onClick={() => onSwitchMode('monitor')}
                      title="Monitor: actions proceed but risky ones are logged as would_block — data can still leak"
                    >
                      Monitor
                    </button>
                    <button
                      id="mE"
                      className={policyMode === 'enforce' ? 'on' : ''}
                      onClick={() => onSwitchMode('enforce')}
                      title="Enforce: dangerous actions are stopped or held for approval before they execute"
                    >
                      Enforce
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-500 font-sans">
                    {policyMode === 'enforce'
                      ? '🛑 Enforce — dangerous actions blocked inline, 0 records leak'
                      : '👁 Monitor — actions proceed, risky ones logged as would_block'}
                  </p>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <button
                    className="btn s g"
                    id="run"
                    data-testid="run-attack-btn"
                    onClick={onTriggerRealAttack}
                    disabled={liveAttackRunning}
                    title="Runs ATK-001 (poisoned résumé) through the real gateway — requires backend server"
                  >
                    {liveAttackRunning ? 'Executing Scenario…' : 'Run Attack Scenario ▶'}
                  </button>
                </div>
              </div>

              <div id="chain">
                {chainSteps.map((s, i) => (
                  <div
                    key={s.num}
                    id={`s${i}`}
                    className={`st ${stepClasses[i]} ${stepActive[i] ? 'on' : ''}`}
                  >
                    <i>{s.num}</i>
                    <div>
                      <b>{s.title}</b>
                      <small id={`d${i}`}>{s.desc}</small>
                    </div>
                  </div>
                ))}
              </div>

              <div
                id="vd"
                className={`vd ${verdict.show ? 'show' : ''} ${verdict.ok ? 'ok' : 'bad'}`}
              >
                {verdict.text}
              </div>

              {/* Event-driven pipeline note */}
              <div className="px-1 pt-2">
                <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                  <span className="text-slate-400 font-semibold">Live Event Pipeline:</span> Steps, signal bars, and risk gauge update dynamically as real <code className="font-mono text-cyan-300">AUDIT_EVENT</code> frames arrive via WebSocket from the gateway. Switch mode to compare Enforce vs Monitor execution outcomes.
                </p>
              </div>
            </div>

            {/* Card B: Mini-mesh & Risk Gauge */}
            <div className="card B">
              <AgentMesh
                mode="console"
                canvasId="mc"
                className="w-full"
                events={events}
                attackPulseTrigger={attackPulseTrigger}
              />
              <div className="rw" id="gauge-box">
                <div className="ga">
                  <svg width="116" height="116" viewBox="0 0 116 116">
                    <circle cx="58" cy="58" r="50" stroke="var(--line)" />
                    <circle
                      className="fg"
                      id="fg"
                      cx="58"
                      cy="58"
                      r="50"
                      stroke={riskGauge > 70 ? 'var(--ro)' : riskGauge > 35 ? 'var(--am)' : 'var(--cy)'}
                      style={{ strokeDashoffset: 314 * (1 - riskGauge / 100) }}
                    />
                  </svg>
                  <div>
                    <strong id="sc">{riskGauge}</strong>
                    <span>risk</span>
                  </div>
                </div>

                <div id="bars">
                  {SIGNAL_BARS.map(([label, color], i) => (
                    <div key={label} className="br">
                      {label}
                      <u>
                        <i
                          id={`b${i}`}
                          style={{ background: color, width: `${barWidths[i]}%` }}
                        />
                      </u>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Card C: Terminal Feed */}
            <div className="card C mono">
              <div className="flex justify-between items-center pb-2 border-b border-white/10 mb-2 text-[11px]">
                <span className="text-slate-400">Live gateway event stream</span>
                <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={showToolReturn}
                    onChange={(e) => onToggleToolReturn(e.target.checked)}
                  />
                  <span>tool_return</span>
                </label>
              </div>
              <div className="fd" id="fd">
                {displayedFeed.map((line) => (
                  <div key={line.id} className="ln">
                    <b className={`t ${line.cls}`}>{line.badge}</b> {line.text}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Sub-tab 2: Real HMAC Approval Queue */}
        {subTab === 'approvals' && (
          <div data-testid="console-approvals-panel">
            <ApprovalQueue onApprovalResolved={onRefreshStats} />
          </div>
        )}

        {/* Sub-tab 3: Reconstructed Incidents */}
        {subTab === 'incidents' && (
          <div className="space-y-6" data-testid="console-incidents-panel">
            {loadingIncidents ? (
              <div className="card text-xs font-mono text-slate-400">
                Loading reconstructed incidents from gateway store...
              </div>
            ) : incidents.length === 0 ? (
              <div className="card text-center py-10 space-y-3">
                <p className="text-sm text-slate-300">
                  No reconstructed incidents recorded yet in this session.
                </p>
                <button
                  type="button"
                  className="btn s"
                  onClick={() => {
                    setSubTab('interception');
                    if (stats?.demo_mode) onTriggerRealAttack();
                    else onRunSimulation();
                  }}
                >
                  Trigger live attack scenario →
                </button>
              </div>
            ) : (
              <>
                <IncidentList
                  incidents={incidents}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncident={setSelectedIncidentId}
                />
                {selectedIncident && (
                  <div className="card space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
                      <div>
                        <span className="text-[11px] font-mono text-cyan-400 uppercase">
                          {selectedIncident.id} · {selectedIncident.agent_id}
                        </span>
                        <h3 className="text-lg font-bold text-white mt-0.5">{selectedIncident.title}</h3>
                      </div>
                      <span className="t-badge ro">RISK {selectedIncident.risk_score}/100</span>
                    </div>
                    <p className="text-xs text-slate-300 font-sans leading-relaxed">
                      {selectedIncident.summary}
                    </p>
                    <div className="space-y-2">
                      {(selectedIncident.chain_steps || []).map((st, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-xl bg-black/40 border border-white/10 text-xs font-mono flex flex-wrap items-center justify-between gap-2"
                        >
                          <div>
                            <span className="text-cyan-400 mr-2">#{st.step ?? st.step_number ?? idx + 1}</span>
                            <span className="text-white font-semibold">{st.title || st.tool_name}</span>
                            <span className="text-slate-400 block text-[11px] mt-0.5">
                              {st.description || st.reason}
                            </span>
                          </div>
                          <span className="t-badge cy">{st.decision}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
