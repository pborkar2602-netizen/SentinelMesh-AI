import React, { useState, useEffect } from 'react';
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

  useEffect(() => {
    setMode(policyMode);
  }, [policyMode]);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/policies/simulation/stats?exclude_benchmark=true');
      if (res.ok) {
        const data = await res.json();
        setSimStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch policy simulation stats:', err);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleToggleMode = async (newMode: 'enforce' | 'monitor') => {
    setUpdatingMode(true);
    try {
      const res = await fetch('/api/v1/policies/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      if (res.ok) {
        setMode(newMode);
        await fetchStats();
        if (onModeChanged) onModeChanged(newMode);
      }
    } catch (err) {
      console.error('Failed to toggle policy mode:', err);
    } finally {
      setUpdatingMode(false);
    }
  };

  const runSimulation = async (targetMode: 'enforce' | 'monitor') => {
    setSimulating(true);
    try {
      const res = await fetch('/api/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          limit: 50,
          simulated_mode: targetMode,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSimulationResult(data);
        await fetchStats();
      }
    } catch (err) {
      console.error('Failed to run policy simulation:', err);
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
      desc: 'Compares query row volume, off-hours execution, and destination novelty against each agent’s learned historical profile.',
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
  const blockedCount = dashboardStats?.blocked_actions ?? simStats?.block_count ?? 0;
  const wouldBlockCount = dashboardStats?.would_block_actions ?? simStats?.would_block_count ?? 0;
  const approvalCount = dashboardStats?.held_for_approval_actions ?? simStats?.require_approval_count ?? 0;

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
              Switch the live gateway between <strong>Enforce</strong> (blocks and holds dangerous calls inline) and <strong>Monitor</strong> (logs <code className="mono">would_block</code> alerts without stopping execution), or replay stored audit events to preview decision changes.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="seg" role="group" aria-label="Gateway policy mode">
              <button
                disabled={updatingMode}
                className={mode === 'monitor' ? 'on' : ''}
                onClick={() => handleToggleMode('monitor')}
              >
                Monitor
              </button>
              <button
                disabled={updatingMode}
                className={mode === 'enforce' ? 'on' : ''}
                onClick={() => handleToggleMode('enforce')}
              >
                Enforce
              </button>
            </div>

            <button
              onClick={() => runSimulation(mode === 'enforce' ? 'monitor' : 'enforce')}
              disabled={simulating}
              className="btn s"
            >
              {simulating
                ? 'Replaying Audit Chain…'
                : `Simulate ${mode === 'enforce' ? 'Monitor' : 'Enforce'} Replay ▶`}
            </button>
          </div>
        </div>

        {/* Unified DB Counters */}
        <div className="rs mt-4">
          <div className="card" style={{ padding: '18px' }}>
            <div className="n">{blockedCount}</div>
            <p>Actions Blocked (Enforce)</p>
          </div>
          <div className="card" style={{ padding: '18px' }}>
            <div className="n">{wouldBlockCount}</div>
            <p>Would Have Leaked (Monitor)</p>
          </div>
          <div className="card" style={{ padding: '18px' }}>
            <div className="n">{approvalCount}</div>
            <p>Held for Human Approval</p>
          </div>
          <div className="card" style={{ padding: '18px' }}>
            <div className="n">{totalEvaluated}</div>
            <p>Total Agent Actions Inspected</p>
          </div>
        </div>

        {simulationResult && (
          <div className="mt-5 p-4 rounded-2xl border border-cy/40 bg-cy/5 space-y-2">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="font-display text-sm text-cy">
                Dry-Run Replay Complete ({simulationResult.events_replayed} stored actions re-evaluated under {simulationResult.simulated_mode.toUpperCase()} mode)
              </span>
              <span className="t-badge cy">
                {simulationResult.decisions_changed} DECISION CHANGES
              </span>
            </div>
            <div className="flex flex-wrap gap-4 text-xs font-mono text-mut pt-1">
              <span>
                Allow: <strong className="text-gr">{simulationResult.simulated_distribution?.allow ?? 0}</strong>
              </span>
              <span>
                Block: <strong className="text-ro">{simulationResult.simulated_distribution?.block ?? 0}</strong>
              </span>
              <span>
                Would Block: <strong className="text-ro">{simulationResult.simulated_distribution?.would_block ?? 0}</strong>
              </span>
              <span>
                Approval: <strong className="text-am">{simulationResult.simulated_distribution?.require_approval ?? 0}</strong>
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Six Defense-in-Depth Rules */}
      <div className="bn">
        {policyRules.map((rule, idx) => {
          const spanClass =
            idx === 0 || idx === 3 ? 'c4' : idx === 1 || idx === 2 ? 'c2' : 'c3';
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
