import React, { useState, useEffect, useCallback, useRef } from 'react';
import { DashboardStats, SimulationStats } from '../types';

interface PolicyManagerProps {
  policyMode: 'enforce' | 'monitor';
  stats?: DashboardStats | null;
  onModeChanged?: (newMode: 'enforce' | 'monitor') => void;
}

export const PolicyManager: React.FC<PolicyManagerProps> = ({
  policyMode,
  stats: dashboardStats,
  onModeChanged,
}) => {
  const [mode, setMode] = useState<'enforce' | 'monitor'>(policyMode);
  const [simStats, setSimStats] = useState<SimulationStats | null>(null);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [updatingMode, setUpdatingMode] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null); // null = checking
  const [modeError, setModeError] = useState<string | null>(null);
  const [simError, setSimError] = useState<string | null>(null);
  const [modeJustChanged, setModeJustChanged] = useState(false);
  const simResultRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => { setMode(policyMode); }, [policyMode]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/policies/simulation/stats?exclude_benchmark=true');
      if (res.ok) {
        setSimStats(await res.json());
        setBackendOnline(true);
      } else {
        setBackendOnline(false);
      }
    } catch {
      setBackendOnline(false);
    }
  }, []);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  const handleToggleMode = async (newMode: 'enforce' | 'monitor') => {
    if (newMode === mode) return;
    setModeError(null);
    setUpdatingMode(true);
    try {
      const res = await fetch('/api/v1/policies/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      if (res.ok) {
        setMode(newMode);
        setModeJustChanged(true);
        setTimeout(() => setModeJustChanged(false), 2500);
        await fetchStats();
        if (onModeChanged) onModeChanged(newMode);
      } else {
        setModeError('Backend rejected mode change — check server logs.');
      }
    } catch {
      setModeError('Backend offline — start: uvicorn backend.app.main:app --reload');
    } finally {
      setUpdatingMode(false);
    }
  };

  const runSimulation = async (targetMode: 'enforce' | 'monitor') => {
    setSimulating(true);
    setSimError(null);
    setSimulationResult(null);
    try {
      const res = await fetch('/api/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 50, simulated_mode: targetMode }),
      });
      if (res.ok) {
        const data = await res.json();
        setSimulationResult(data);
        await fetchStats();
        setTimeout(() => {
          simResultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
      } else {
        setSimError('Simulation failed — backend returned an error.');
      }
    } catch {
      setSimError('Backend offline — replay requires the FastAPI server to be running.');
    } finally {
      setSimulating(false);
    }
  };

  const policyRules = [
    {
      num: '01',
      id: 'rule-taint',
      name: 'Untrusted Taint Isolation & Pre-Read Gate',
      desc: 'Marks sessions tainted when an agent reads untrusted documents and holds sensitive DB queries (salary, SSN, bank_routing) before any rows reach the agent.',
      category: 'Taint & Pre-Read Protection',
      owasp: 'LLM01 / LLM02',
      code: 'read_doc(resume.pdf) → TAINTED | db_query(salaries) → BLOCK',
    },
    {
      num: '02',
      id: 'rule-sql-writes',
      name: 'Tainted SQL Write & Sensitive Column Guard',
      desc: 'Parses SQL AST via sqlglot to intercept UPDATE/INSERT/DELETE statements modifying banking, role, or credential columns when tainted.',
      category: 'Database Integrity',
      owasp: 'LLM06: Excessive Agency',
      code: 'UPDATE vendor_master SET account_number=... → REQUIRE_APPROVAL',
    },
    {
      num: '03',
      id: 'rule-exploits',
      name: 'Inline SSRF, Path Traversal & Secret Egress Guard',
      desc: 'Blocks cloud metadata SSRF (169.254.169.254), private RFC1918 ranges, high-entropy API keys, and markdown image exfiltration.',
      category: 'Network & Secrets',
      owasp: 'LLM02 / SSRF',
      code: 'GET 169.254.169.254/latest/meta-data/iam → BLOCK (risk 98)',
    },
    {
      num: '04',
      id: 'rule-baseline',
      name: 'Learned Behavioral Baseline (Median + 3·MAD)',
      desc: 'Compares query row volume, off-hours execution, and destination novelty against each agent\'s learned historical profile.',
      category: 'Behavioral Anomaly',
      owasp: 'LLM10: Anomaly Detection',
      code: 'rows 45 vs hr-agent median 1 → off-hours bulk read flagged',
    },
    {
      num: '05',
      id: 'rule-privacy',
      name: 'AES-GCM Privacy Vault & Format-Preserving Masking',
      desc: 'Tokenizes raw PII ([SSN_1], [EMAIL_1], [SALARY_1]) prior to logging. Raw decryption requires Privacy Officer role and appends an audit event.',
      category: 'Privacy Vault',
      owasp: 'Zero-Trust Logging',
      code: 'ssn: "123-45-6789" → "[SSN_1]" (AES-256-GCM vault)',
    },
    {
      num: '06',
      id: 'rule-approvals',
      name: 'One-Time Action-Bound HMAC Approval Tokens',
      desc: 'Binds human approvals to the canonical SHA-256 hash of (tool_name, arguments, session_id) with strict nonce replay prevention.',
      category: 'Cryptographic Auth',
      owasp: 'Non-Repudiation',
      code: 'forged · expired · replayed · modified-args → ALL BLOCKED',
    },
  ];

  const totalEvaluated = dashboardStats?.total_actions ?? simStats?.total_events ?? 0;
  const blockedCount   = dashboardStats?.blocked_actions ?? simStats?.block_count ?? 0;
  const wouldBlockCount = dashboardStats?.would_block_actions ?? simStats?.would_block_count ?? 0;
  const approvalCount  = dashboardStats?.held_for_approval_actions ?? simStats?.require_approval_count ?? 0;

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="hd">
          <div>
            <div className="eb">Inline Policy Engine & Dry-Run Replay</div>
            <h2 className="sec-title" style={{ fontSize: 'clamp(24px, 3vw, 36px)' }}>
              Deterministic enforcement with shadow replay.
            </h2>
            <p className="text-sm text-mut mt-2 max-w-2xl">
              Switch the live gateway between <strong>Enforce</strong> (blocks and holds dangerous calls
              inline) and <strong>Monitor</strong> (logs{' '}
              <code className="mono">would_block</code> alerts without stopping execution), or replay
              stored audit events to preview decision changes.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="seg" role="group" aria-label="Gateway policy mode">
              <button
                disabled={updatingMode}
                className={mode === 'monitor' ? 'on' : ''}
                onClick={() => handleToggleMode('monitor')}
                title="Monitor mode: gateway logs would_block alerts but lets actions proceed — nothing is stopped"
              >
                Monitor
              </button>
              <button
                disabled={updatingMode}
                className={mode === 'enforce' ? 'on' : ''}
                onClick={() => handleToggleMode('enforce')}
                title="Enforce mode: gateway blocks or holds dangerous actions inline before they execute"
              >
                Enforce
              </button>
            </div>

            <button
              onClick={() => runSimulation(mode === 'enforce' ? 'monitor' : 'enforce')}
              disabled={simulating || backendOnline === false}
              className="btn s"
              title={
                backendOnline === false
                  ? 'Backend required to replay stored events'
                  : `Replay last 50 stored events under ${mode === 'enforce' ? 'Monitor' : 'Enforce'} mode and show which decisions would change`
              }
            >
              {simulating
                ? 'Replaying Audit Chain…'
                : `Simulate ${mode === 'enforce' ? 'Monitor' : 'Enforce'} Replay ▶`}
            </button>
          </div>
        </div>

        {/* Mode switch success feedback */}
        {modeJustChanged && (
          <div className="mt-3 px-3 py-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-xs font-mono text-emerald-400 flex items-center justify-between animate-fadeIn">
            <span>✓ Gateway policy mode switched to <strong>{mode.toUpperCase()}</strong>. Future agent calls will follow this enforcement policy.</span>
          </div>
        )}

        {/* Backend offline / online status */}
        {backendOnline === false && (
          <div className="mt-4 px-4 py-3 rounded-xl border border-amber-500/30 bg-amber-500/8 flex items-start gap-3">
            <span className="text-amber-400 text-base mt-0.5">⚠</span>
            <div>
              <p className="text-xs font-semibold text-amber-300 font-mono">Backend offline</p>
              <p className="text-xs text-slate-400 mt-0.5 font-sans">
                Mode switching and shadow replay require the FastAPI server.
                Run: <code className="text-cyan-300 font-mono">uvicorn backend.app.main:app --reload</code>
              </p>
            </div>
          </div>
        )}

        {/* Mode switch error */}
        {modeError && (
          <div className="mt-3 px-3 py-2 rounded-lg border border-rose-500/30 bg-rose-500/8 text-xs font-mono text-rose-400">
            {modeError}
          </div>
        )}

        {/* What each mode actually does — always visible */}
        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className={`p-4 rounded-2xl border transition-all duration-200 ${
            mode === 'enforce'
              ? 'border-emerald-500/50 bg-emerald-500/8'
              : 'border-white/10 bg-white/3 opacity-50'
          }`}>
            <div className="flex items-center gap-2 mb-2">
              <span className={`w-2 h-2 rounded-full ${mode === 'enforce' ? 'bg-emerald-400' : 'bg-slate-600'}`} />
              <span className="text-xs font-mono font-semibold text-white uppercase tracking-wider">Enforce mode</span>
              {mode === 'enforce' && <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/15 border border-emerald-500/30 px-1.5 py-0.5 rounded-full">ACTIVE</span>}
            </div>
            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              Dangerous actions are <strong className="text-white">stopped inline</strong> before they execute.
              A db_query on PII columns is held for human approval. An external email send is blocked outright.
              Zero records leak.
            </p>
          </div>

          <div className={`p-4 rounded-2xl border transition-all duration-200 ${
            mode === 'monitor'
              ? 'border-amber-500/50 bg-amber-500/8'
              : 'border-white/10 bg-white/3 opacity-50'
          }`}>
            <div className="flex items-center gap-2 mb-2">
              <span className={`w-2 h-2 rounded-full ${mode === 'monitor' ? 'bg-amber-400' : 'bg-slate-600'}`} />
              <span className="text-xs font-mono font-semibold text-white uppercase tracking-wider">Monitor mode</span>
              {mode === 'monitor' && <span className="text-[10px] font-mono text-amber-400 bg-amber-500/15 border border-amber-500/30 px-1.5 py-0.5 rounded-full">ACTIVE</span>}
            </div>
            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              Actions are <strong className="text-white">permitted to proceed</strong> but every risky one is
              logged as <code className="font-mono text-amber-300">would_block</code>. Used to audit exposure
              without disrupting operations — data can still leak.
            </p>
          </div>
        </div>

        {/* DB Counters */}
        <div className="rs mt-4">
          {[
            { label: 'Actions Blocked (Enforce)', value: blockedCount, cls: 'text-rose-400' },
            { label: 'Would Have Leaked (Monitor)', value: wouldBlockCount, cls: 'text-amber-400' },
            { label: 'Held for Human Approval', value: approvalCount, cls: 'text-cyan-400' },
            { label: 'Total Agent Actions Inspected', value: totalEvaluated, cls: 'text-white' },
          ].map(({ label, value, cls }) => (
            <div key={label} className="card" style={{ padding: '18px' }}>
              <div className={`n ${cls}`}>{value}</div>
              <p>{label}</p>
            </div>
          ))}
        </div>

        {/* Simulation error */}
        {simError && (
          <div className="mt-4 px-3 py-2 rounded-lg border border-rose-500/30 bg-rose-500/8 text-xs font-mono text-rose-400">
            {simError}
          </div>
        )}

        {/* Simulation result */}
        {simulationResult && (
          <div ref={simResultRef} className="mt-5 p-4 rounded-2xl border border-cy/40 bg-cy/5 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="font-display text-sm text-cy">
                Dry-Run Replay Complete — {simulationResult.events_replayed} stored actions re-evaluated under{' '}
                <strong>{simulationResult.simulated_mode.toUpperCase()}</strong> mode
              </span>
              <span className="t-badge cy">{simulationResult.decisions_changed} DECISION CHANGES</span>
            </div>
            <div className="flex flex-wrap gap-4 text-xs font-mono text-mut">
              <span>Allow: <strong className="text-gr">{simulationResult.simulated_distribution?.allow ?? 0}</strong></span>
              <span>Block: <strong className="text-ro">{simulationResult.simulated_distribution?.block ?? 0}</strong></span>
              <span>Would Block: <strong className="text-ro">{simulationResult.simulated_distribution?.would_block ?? 0}</strong></span>
              <span>Approval: <strong className="text-am">{simulationResult.simulated_distribution?.require_approval ?? 0}</strong></span>
            </div>
            {simulationResult.decision_changes?.length > 0 && (
              <div className="space-y-1.5 pt-1">
                <p className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">Changed decisions</p>
                {simulationResult.decision_changes.slice(0, 5).map((ch: any, i: number) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-xs font-mono py-1 border-t border-white/5">
                    <span className="text-slate-400">{ch.agent_id} · {ch.tool_name}</span>
                    <span className="text-rose-400">{ch.original_decision}</span>
                    <span className="text-slate-500">→</span>
                    <span className="text-emerald-400">{ch.simulated_decision}</span>
                  </div>
                ))}
                {simulationResult.decision_changes.length > 5 && (
                  <p className="text-[11px] font-mono text-slate-500">
                    +{simulationResult.decision_changes.length - 5} more changes
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Six Defense-in-Depth Rules */}
      <div className="bn">
        {policyRules.map((rule, idx) => {
          const spanClass = idx === 0 || idx === 3 ? 'c4' : idx === 1 || idx === 2 ? 'c2' : 'c3';
          return (
            <div key={rule.id} className={`card ${spanClass}`}>
              <div className="flex items-center justify-between">
                <div className="ico">{rule.num}</div>
                <span className="t-badge gr">ACTIVE · {rule.owasp}</span>
              </div>
              <h3>{rule.name}</h3>
              <p>{rule.desc}</p>
              <div className="code">{rule.code}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
