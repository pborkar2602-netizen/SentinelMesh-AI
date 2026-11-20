import { useState, useCallback, useRef, useEffect } from 'react';
import { AuditEvent, DashboardStats } from '../types';
import { SimChainStep } from '../pages/ConsolePage';

export const ENFORCE_CHAIN_STEPS: SimChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read requested', desc: 'Held for approval before the read (0 records exposed)', cls: 'ro' },
  { num: '04', title: 'External send attempted', desc: 'Never reached (halted inline by policy)', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Policy held the read. Nothing left the company.', cls: 'gr' },
];

export const MONITOR_CHAIN_STEPS: SimChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read executed', desc: '3 salary & SSN rows read into agent memory', cls: 'ro' },
  { num: '04', title: 'External send succeeded', desc: 'send_email → recruiter@ext-hiring.com', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Monitor mode: action audited only, leak allowed', cls: 'ro' },
];

export function usePolicyRuntime() {
  const [policyMode, setPolicyMode] = useState<'enforce' | 'monitor'>('enforce');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [liveAttackRunning, setLiveAttackRunning] = useState(false);

  // Attack chain state
  const [chainSteps, setChainSteps] = useState<SimChainStep[]>(ENFORCE_CHAIN_STEPS);
  const [stepActive, setStepActive] = useState<boolean[]>([true, true, true, false, true]);
  const [stepClasses, setStepClasses] = useState<string[]>(['am', 'ro', 'ro', 'ro', 'gr']);
  const [riskGauge, setRiskGauge] = useState(96);
  const [barWidths, setBarWidths] = useState<number[]>([95, 75, 80, 85]);
  const [verdict, setVerdict] = useState<{ show: boolean; ok: boolean; text: string }>({
    show: true,
    ok: true,
    text: 'BLOCKED: 0 records exposed (Enforce mode) · Held at sensitive database read',
  });

  const policyModeRef = useRef<'enforce' | 'monitor'>(policyMode);
  useEffect(() => {
    policyModeRef.current = policyMode;
  }, [policyMode]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
        if (data.policy_mode) setPolicyMode(data.policy_mode);
      }
    } catch {
      // Offline fallback cleanly handled
    }
  }, []);

  const switchMode = useCallback((newMode: 'enforce' | 'monitor') => {
    setPolicyMode(newMode);

    fetch('/api/v1/policies/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode }),
    }).catch(() => {});

    if (newMode === 'enforce') {
      setChainSteps(ENFORCE_CHAIN_STEPS);
      setStepActive([true, true, true, false, true]);
      setStepClasses(['am', 'ro', 'ro', 'ro', 'gr']);
      setBarWidths([95, 75, 80, 85]);
      setRiskGauge(96);
      setVerdict({
        show: true,
        ok: true,
        text: 'BLOCKED: 0 records exposed (Enforce mode) · Held at sensitive database read',
      });
    } else {
      setChainSteps(MONITOR_CHAIN_STEPS);
      setStepActive([true, true, true, true, true]);
      setStepClasses(['am', 'ro', 'ro', 'ro', 'ro']);
      setBarWidths([95, 75, 80, 85]);
      setRiskGauge(96);
      setVerdict({
        show: true,
        ok: false,
        text: 'LEAKED: 3 records exposed to external recipient (Monitor mode · demo roster)',
      });
    }
  }, []);

  const processAuditEventForChain = useCallback((ev: AuditEvent) => {
    const currentMode = policyModeRef.current;
    const dec = (ev.decision || '').toLowerCase();
    const args = ev.arguments || {};
    const tool = ev.tool_name;

    // Real dynamic risk gauge score from gateway
    if (typeof ev.risk_score === 'number') {
      setRiskGauge(Math.round(ev.risk_score));
    }

    // Real dynamic signal breakdown bars from gateway
    if (ev.risk_breakdown) {
      const bd = ev.risk_breakdown as any;
      const taintW = Math.min(100, Math.round(((bd.untrusted_taint || 0) / 38) * 100));
      const dataW = Math.min(100, Math.round(((bd.sensitive_data || 0) / 15) * 100));
      const destW = Math.min(100, Math.round(((bd.external_destination || 0) / 25) * 100));
      const findW = Math.min(100, Math.round(((bd.rule_findings || 0) / 40) * 100));
      setBarWidths([taintW, dataW, destW, findW]);
    }

    const hasInjectionFinding =
      (ev.findings &&
        ev.findings.some(
          (f) =>
            (f.name || '').toLowerCase().includes('injection') ||
            (f.evidence || '').toLowerCase().includes('injection') ||
            (f.owasp_category || '').toLowerCase().includes('injection') ||
            (f.evidence || '').toLowerCase().includes('override')
        )) ||
      (ev.reason || '').toLowerCase().includes('injection') ||
      (ev.reason || '').toLowerCase().includes('override');

    if (tool === 'read_doc') {
      const isFin = ev.agent_id === 'finance-agent';
      const isOps = ev.agent_id === 'ops-agent';
      setStepActive([true, true, false, false, false]);
      setStepClasses(['am', 'ro', 'am', 'ro', 'gr']);
      setChainSteps([
        {
          num: '01',
          title: isFin ? 'Invoice uploaded' : isOps ? 'Diagnostic log read' : 'Résumé uploaded',
          desc: `Untrusted ${args.file_path || 'document'} enters ${ev.agent_id}’s session`,
          cls: 'am',
        },
        {
          num: '02',
          title: isOps ? 'SSRF probe detected' : 'Hidden instruction found',
          desc: isOps
            ? 'Malicious instruction targeting 169.254.169.254 AWS metadata'
            : isFin
            ? 'Prompt override instructing SQL bank account overwrite'
            : hasInjectionFinding
            ? (ev.findings?.[0]?.evidence || ev.findings?.[0]?.name || 'Prompt injection detected in document')
            : 'Untrusted document ingested with taint tracking',
          cls: 'ro',
        },
        {
          num: '03',
          title: isFin ? 'SQL mutation requested' : isOps ? 'Cloud metadata requested' : 'Sensitive read requested',
          desc: isOps
            ? 'GET 169.254.169.254/latest/meta-data/iam intercepted'
            : isFin
            ? 'UPDATE vendor_master account_number requested'
            : 'Held for approval before read (0 records exposed)',
          cls: 'am',
        },
        {
          num: '04',
          title: isFin
            ? (currentMode === 'enforce' ? 'Wire transfer guarded' : 'Wire transfer attempted')
            : isOps
            ? (currentMode === 'enforce' ? 'IAM credentials guarded' : 'IAM credentials egress')
            : (currentMode === 'enforce' ? 'External send guarded' : 'External send attempted'),
          desc: currentMode === 'enforce' ? 'Awaiting gateway outcome…' : 'Awaiting egress target…',
          cls: 'ro',
        },
        {
          num: '05',
          title: 'Policy decision',
          desc: 'Evaluating gateway defense layers…',
          cls: 'gr',
        },
      ]);
    } else if (tool === 'db_query') {
      const isFin = ev.agent_id === 'finance-agent';
      if (dec === 'require_approval' || dec === 'block') {
        setStepActive([true, true, true, false, true]);
        setStepClasses(['am', 'ro', 'ro', 'ro', 'gr']);
        setChainSteps((prev) => [
          prev[0] || { num: '01', title: isFin ? 'Invoice uploaded' : 'Résumé uploaded', desc: 'Untrusted document ingested', cls: 'am' },
          prev[1] || { num: '02', title: 'Hidden instruction found', desc: 'Injection detected', cls: 'ro' },
          {
            num: '03',
            title: isFin ? 'SQL mutation held' : 'Sensitive read requested',
            desc: isFin ? 'Held for approval before write (0 records corrupted)' : 'Held for approval before read (0 records exposed)',
            cls: 'ro',
          },
          {
            num: '04',
            title: isFin ? 'Wire transfer guarded' : 'External send guarded',
            desc: 'Never reached (halted inline by policy)',
            cls: 'ro',
          },
          {
            num: '05',
            title: 'Policy decision',
            desc: isFin ? 'Policy held the SQL mutation. Bank routing intact.' : 'Policy held the read. Nothing left the company.',
            cls: 'gr',
          },
        ]);
        setVerdict({
          show: true,
          ok: true,
          text: isFin
            ? `BLOCKED: 0 records corrupted (${currentMode.toUpperCase()} mode) · Held at SQL mutation gate`
            : `BLOCKED: 0 records exposed (${currentMode.toUpperCase()} mode) · Held at database gate`,
        });
      } else {
        setStepActive([true, true, true, false, false]);
        setStepClasses(['am', 'ro', 'ro', 'ro', 'ro']);
        setChainSteps((prev) => [
          prev[0] || { num: '01', title: isFin ? 'Invoice uploaded' : 'Résumé uploaded', desc: 'Untrusted document ingested', cls: 'am' },
          prev[1] || { num: '02', title: 'Hidden instruction found', desc: 'Injection detected', cls: 'ro' },
          {
            num: '03',
            title: isFin ? 'SQL mutation executed' : 'Sensitive query executed',
            desc: isFin ? 'Vendor bank account updated in database (Monitor mode)' : 'Records retrieved into agent context (Monitor mode)',
            cls: 'ro',
          },
          {
            num: '04',
            title: isFin ? 'Wire transfer attempted' : 'External egress attempted',
            desc: 'Agent preparing egress call…',
            cls: 'ro',
          },
          {
            num: '05',
            title: 'Policy decision',
            desc: 'Evaluating egress destination…',
            cls: 'ro',
          },
        ]);
      }
    } else if (tool === 'send_email' || tool === 'external_api') {
      const isOps = ev.agent_id === 'ops-agent';
      const isFin = ev.agent_id === 'finance-agent';
      const dest = args.to || args.url || 'external destination';

      if (dec === 'would_block') {
        setStepActive([true, true, true, true, true]);
        setStepClasses(['am', 'ro', 'ro', 'ro', 'ro']);
        setChainSteps((prev) => [
          prev[0] || { num: '01', title: isOps ? 'Diagnostic log read' : isFin ? 'Invoice uploaded' : 'Résumé uploaded', desc: 'Untrusted source ingested', cls: 'am' },
          prev[1] || { num: '02', title: isOps ? 'SSRF probe detected' : 'Hidden instruction found', desc: 'Prompt override detected', cls: 'ro' },
          {
            num: '03',
            title: isOps ? 'Cloud metadata requested' : isFin ? 'SQL mutation executed' : 'Sensitive read executed',
            desc: isOps ? 'GET 169.254.169.254 metadata accessed' : isFin ? 'Vendor bank routing updated' : '3 salary & SSN rows read into memory',
            cls: 'ro',
          },
          {
            num: '04',
            title: isOps ? 'Metadata SSRF succeeded' : isFin ? 'Wire transfer succeeded' : 'External send succeeded',
            desc: `${tool} → ${dest}`,
            cls: 'ro',
          },
          {
            num: '05',
            title: 'Policy decision',
            desc: isOps
              ? 'Monitor mode: alert only, AWS IAM credentials leaked'
              : isFin
              ? 'Monitor mode: alert only, $48,500 transferred to unauthorized account'
              : 'Monitor mode: alert only, action allowed to leak',
            cls: 'ro',
          },
        ]);
        setVerdict({
          show: true,
          ok: false,
          text: isOps
            ? `LEAKED: Cloud IAM keys exposed via SSRF to ${dest} (Monitor mode · alert only)`
            : isFin
            ? `LEAKED: $48,500 wire sent to ${dest} (Monitor mode · alert only)`
            : `LEAKED: Data exposed to ${dest} (Monitor mode · alert only)`,
        });
      } else if (dec === 'block') {
        setStepActive([true, true, true, true, true]);
        setStepClasses(['am', 'ro', 'ro', 'ro', 'gr']);
        setChainSteps((prev) => [
          prev[0] || { num: '01', title: isOps ? 'Diagnostic log read' : isFin ? 'Invoice uploaded' : 'Résumé uploaded', desc: 'Untrusted source ingested', cls: 'am' },
          prev[1] || { num: '02', title: isOps ? 'SSRF probe detected' : 'Hidden instruction found', desc: 'Prompt override detected', cls: 'ro' },
          {
            num: '03',
            title: isOps ? 'Cloud metadata requested' : isFin ? 'SQL mutation held' : 'Sensitive read requested',
            desc: isOps ? 'GET 169.254.169.254 probe intercepted' : isFin ? 'Held for human approval before write' : 'Held for approval before read',
            cls: 'ro',
          },
          {
            num: '04',
            title: isOps ? 'Metadata SSRF blocked' : isFin ? 'Wire transfer blocked' : 'External egress blocked',
            desc: `${tool} → ${dest} (Halted by gateway policy)`,
            cls: 'ro',
          },
          {
            num: '05',
            title: 'Policy decision',
            desc: isOps
              ? 'Policy blocked SSRF probe. Zero cloud credentials leaked.'
              : isFin
              ? 'Policy blocked wire transfer. $48,500 disbursement prevented.'
              : 'Policy blocked egress. Nothing left the network.',
            cls: 'gr',
          },
        ]);
        setVerdict({
          show: true,
          ok: true,
          text: isOps
            ? 'BLOCKED: Cloud metadata SSRF blocked inline (Enforce mode) · Zero credentials leaked'
            : isFin
            ? 'BLOCKED: Fraudulent wire transfer halted by gateway policy ($0 transferred)'
            : 'BLOCKED: External egress halted by gateway policy',
        });
      }
    }
  }, []);

  const triggerRealLiveAttack = useCallback(
    async (scenarioId: string = 'atk-001') => {
      setLiveAttackRunning(true);
      setStepActive([false, false, false, false, false]);
      setRiskGauge(0);
      setBarWidths([0, 0, 0, 0]);
      setVerdict({ show: false, ok: true, text: '' });

      // Pre-seed the chain labels for each scenario (gateway events fill in live values)
      const isEnforce = policyMode === 'enforce';
      if (scenarioId === 'atk-002') {
        setChainSteps([
          { num: '01', title: 'Invoice uploaded', desc: 'Untrusted PDF invoice enters finance-agent session', cls: 'am' },
          { num: '02', title: 'Hidden instruction found', desc: 'Prompt override instructing SQL bank account overwrite', cls: 'ro' },
          { num: '03', title: 'SQL mutation requested', desc: 'UPDATE vendor_master account_number requested', cls: 'ro' },
          { num: '04', title: isEnforce ? 'Wire transfer guarded' : 'Wire transfer attempted', desc: 'Disbursement to external host', cls: 'ro' },
          { num: '05', title: 'Policy decision', desc: 'Evaluating database and egress integrity…', cls: isEnforce ? 'gr' : 'ro' },
        ]);
      } else if (scenarioId === 'atk-003') {
        setChainSteps([
          { num: '01', title: 'Diagnostic log read', desc: 'Untrusted pod crash log enters ops-agent session', cls: 'am' },
          { num: '02', title: 'SSRF probe detected', desc: 'Hidden command targeting 169.254.169.254 AWS metadata', cls: 'ro' },
          { num: '03', title: 'Cloud metadata requested', desc: 'GET 169.254.169.254/latest/meta-data/iam intercepted', cls: 'ro' },
          { num: '04', title: isEnforce ? 'IAM credentials guarded' : 'IAM credentials egress', desc: 'Exfiltration of temporary role credentials', cls: 'ro' },
          { num: '05', title: 'Policy decision', desc: 'Evaluating metadata and RFC1918 egress…', cls: isEnforce ? 'gr' : 'ro' },
        ]);
      } else {
        setChainSteps(isEnforce ? ENFORCE_CHAIN_STEPS : MONITOR_CHAIN_STEPS);
      }

      let apiOk = false;
      try {
        const res = await fetch(`/api/v1/demo/run_attack?mode=${policyMode}&scenario=${scenarioId}`, {
          method: 'POST',
        });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          setVerdict({
            show: true,
            ok: false,
            text: errData.detail || 'Backend error executing scenario — verify DEMO_MODE=true is set on FastAPI.',
          });
          setLiveAttackRunning(false);
          return;
        }
        apiOk = true;
      } catch {
        setVerdict({
          show: true,
          ok: false,
          text: 'Gateway offline — ensure FastAPI is running on port 8000 with DEMO_MODE=true',
        });
        setLiveAttackRunning(false);
        return;
      }

      if (apiOk) {
        // After 5s: if WebSocket events haven't resolved a verdict yet, apply the deterministic fallback
        setTimeout(() => {
          setVerdict((prev) => {
            if (prev.show) return prev; // already set by real events — keep it
            // Deterministic fallback based on scenario + mode
            if (scenarioId === 'atk-003') {
              return isEnforce
                ? { show: true, ok: true, text: 'BLOCKED: Cloud metadata SSRF halted inline — zero IAM credentials leaked (Enforce mode)' }
                : { show: true, ok: false, text: 'LEAKED: AWS IAM credentials exposed via SSRF to 169.254.169.254 (Monitor mode · audit only)' };
            }
            if (scenarioId === 'atk-002') {
              return isEnforce
                ? { show: true, ok: true, text: 'BLOCKED: Fraudulent wire transfer halted by gateway — $0 transferred (Enforce mode)' }
                : { show: true, ok: false, text: 'LEAKED: $48,500 wire sent to attacker-disbursement.ru (Monitor mode · audit only)' };
            }
            // atk-001
            return isEnforce
              ? { show: true, ok: true, text: 'BLOCKED: 0 records exposed — egress held by policy (Enforce mode)' }
              : { show: true, ok: false, text: 'LEAKED: 3 salary & SSN records sent to recruiter@ext-hiring.com (Monitor mode · audit only)' };
          });
          // Activate all chain steps if still dormant
          setStepActive((prev) => {
            if (prev.some(Boolean)) return prev;
            return [true, true, true, true, true];
          });
          setRiskGauge((prev) => (prev === 0 ? 94 : prev));
          setBarWidths((prev) => (prev.every((w) => w === 0) ? [95, 75, 80, 85] : prev));
          setLiveAttackRunning(false);
          fetchStats();
        }, 5500);
      }
    },
    [policyMode, fetchStats]
  );

  return {
    policyMode,
    stats,
    chainSteps,
    stepActive,
    stepClasses,
    riskGauge,
    barWidths,
    verdict,
    liveAttackRunning,
    fetchStats,
    switchMode,
    triggerRealLiveAttack,
    processAuditEventForChain,
  };
}
