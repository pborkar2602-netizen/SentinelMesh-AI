import React, { useState, useEffect } from 'react';
import { SimulationStats } from '../types';

interface PolicyManagerProps {
  onModeChanged?: (newMode: string) => void;
}

export const PolicyManager: React.FC<PolicyManagerProps> = ({ onModeChanged }) => {
  const [mode, setMode] = useState<string>('enforce');
  const [stats, setStats] = useState<SimulationStats | null>(null);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [updatingMode, setUpdatingMode] = useState(false);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/policies/simulation/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
        if (data.current_mode) setMode(data.current_mode);
      }
    } catch (err) {
      console.error('Failed to fetch policy simulation stats:', err);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleMode = async (newMode: 'enforce' | 'monitor') => {
    setUpdatingMode(true);
    try {
      const res = await fetch('/api/v1/policies/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode })
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

  const runSimulation = async () => {
    setSimulating(true);
    try {
      const res = await fetch('/api/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          limit: 50,
          simulated_rules: {
            block_tainted_external: true,
            high_sensitivity_requires_approval: true,
            strict_intent_judge: true
          }
        })
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
      id: 'rule-taint',
      name: 'Untrusted Taint Isolation',
      desc: 'Strictly blocks data egress to unapproved external endpoints when session is tainted by untrusted input.',
      category: 'Data Exfiltration',
      enabled: true,
      owasp: 'LLM02: Sensitive Info Disclosure'
    },
    {
      id: 'rule-egress',
      name: 'High-Sensitivity External Egress Gate',
      desc: 'Escalates outgoing salary, national ID, and financial data transfers to human approval.',
      category: 'Privacy & Financial',
      enabled: true,
      owasp: 'LLM06: Excessive Agency'
    },
    {
      id: 'rule-exploits',
      name: 'Inline Exploit & Threat Detection',
      desc: 'Deterministic pattern matching for SSRF metadata IPs, SQL injection, path traversal, and credential leaks.',
      category: 'System Integrity',
      enabled: true,
      owasp: 'LLM01: Prompt Injection'
    },
    {
      id: 'rule-judge',
      name: 'Intent-vs-Action LLM Judge Divergence',
      desc: 'Evaluates stated session task vs pending sensitive tool call on masked payloads. Divergence (≥70) escalates to human approval.',
      category: 'Alignment',
      enabled: true,
      owasp: 'LLM08: Vector & Action Divergence'
    },
    {
      id: 'rule-baseline',
      name: 'Learned Behavioral Baseline Anomaly',
      desc: 'Flags off-hours execution, burst calls/min, and bulk database dumps based on learned median + 3*MAD distribution.',
      category: 'Behavioral Anomaly',
      enabled: true,
      owasp: 'LLM10: Unbounded Consumption'
    },
    {
      id: 'rule-privacy',
      name: 'AES-GCM Encrypted Token Vault & Masking',
      desc: 'Replaces raw PII in tool payloads and audit logs with format-preserving tokens. Access role-gated to Privacy Officer.',
      category: 'Privacy Engine',
      enabled: true,
      owasp: 'Privacy Compliance'
    }
  ];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg space-y-5">
      {/* Header & Mode Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-gray-800 gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-wide">Policy Engine & Simulation</h2>
            <span className={`px-2 py-0.5 text-xs font-semibold rounded ${
              mode === 'enforce' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-cyan-950 text-cyan-400 border border-cyan-800'
            }`}>
              Mode: {mode.toUpperCase()}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time policy enforcement with shadow simulation and dry-run re-evaluation
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center bg-gray-950 border border-gray-800 rounded-lg p-1">
            <button
              disabled={updatingMode}
              onClick={() => handleToggleMode('enforce')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                mode === 'enforce'
                  ? 'bg-red-700 text-white shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Enforce Mode
            </button>
            <button
              disabled={updatingMode}
              onClick={() => handleToggleMode('monitor')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                mode === 'monitor'
                  ? 'bg-cyan-700 text-white shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Monitor Mode
            </button>
          </div>

          <button
            onClick={runSimulation}
            disabled={simulating}
            className="px-3.5 py-1.5 bg-purple-700 hover:bg-purple-600 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow"
          >
            {simulating ? 'Simulating...' : 'Simulate Replay'}
          </button>
        </div>
      </div>

      {/* Shadow Simulation Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-gray-950 border border-gray-800/80 rounded-lg p-3">
          <div className="text-[11px] text-gray-400 font-medium uppercase tracking-wider">Shadow Blocks</div>
          <div className="text-2xl font-black text-amber-400 mt-1">
            {stats?.would_block_count ?? 0}
          </div>
          <div className="text-[10px] text-gray-500 mt-0.5">Would-block in Monitor Mode</div>
        </div>

        <div className="bg-gray-950 border border-gray-800/80 rounded-lg p-3">
          <div className="text-[11px] text-gray-400 font-medium uppercase tracking-wider">Active Blocks</div>
          <div className="text-2xl font-black text-red-400 mt-1">
            {stats?.block_count ?? 0}
          </div>
          <div className="text-[10px] text-gray-500 mt-0.5">Inline blocked actions</div>
        </div>

        <div className="bg-gray-950 border border-gray-800/80 rounded-lg p-3">
          <div className="text-[11px] text-gray-400 font-medium uppercase tracking-wider">Approvals Requested</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">
            {stats?.require_approval_count ?? 0}
          </div>
          <div className="text-[10px] text-gray-500 mt-0.5">Escalated to SecOps queue</div>
        </div>

        <div className="bg-gray-950 border border-gray-800/80 rounded-lg p-3">
          <div className="text-[11px] text-gray-400 font-medium uppercase tracking-wider">Total Evaluated</div>
          <div className="text-2xl font-black text-gray-300 mt-1">
            {stats?.total_events ?? 0}
          </div>
          <div className="text-[10px] text-gray-500 mt-0.5">Events recorded in audit chain</div>
        </div>
      </div>

      {/* Simulation Replay Results Banner */}
      {simulationResult && (
        <div className="p-3.5 bg-purple-950/40 border border-purple-800/70 rounded-lg text-xs space-y-2">
          <div className="flex items-center justify-between font-semibold text-purple-300">
            <span>Policy Replay Simulation Complete</span>
            <span>{simulationResult.events_replayed} Events Analyzed</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
            <div className="text-gray-300">Allow: {simulationResult.simulated_distribution?.allow ?? 0}</div>
            <div className="text-red-400">Block: {simulationResult.simulated_distribution?.block ?? 0}</div>
            <div className="text-cyan-400">Approval: {simulationResult.simulated_distribution?.require_approval ?? 0}</div>
            <div className="text-yellow-400">Redact: {simulationResult.simulated_distribution?.redact ?? 0}</div>
          </div>
          {simulationResult.decision_changes > 0 && (
            <div className="text-amber-300 text-[11px]">
              ⚠️ Policy modifications produced {simulationResult.decision_changes} decision changes compared to live verdicts.
            </div>
          )}
        </div>
      )}

      {/* Active Rules List */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Active Policy Rules</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {policyRules.map((rule) => (
            <div
              key={rule.id}
              className="bg-gray-950 border border-gray-800/80 hover:border-gray-700/80 transition-colors rounded-lg p-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-white">{rule.name}</span>
                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    Active
                  </span>
                </div>
                <p className="text-[11px] text-gray-400 leading-relaxed mb-2">{rule.desc}</p>
              </div>
              <div className="flex items-center justify-between text-[10px] text-gray-500 pt-2 border-t border-gray-900 font-mono">
                <span>{rule.category}</span>
                <span className="text-purple-400">{rule.owasp}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
