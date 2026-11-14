export interface TourStep {
  targetId: string;
  title: string;
  description: string;
  badge?: string;
  position?: 'top' | 'bottom' | 'left' | 'right' | 'center';
}

export const TOUR_STEPS: TourStep[] = [
  {
    targetId: 'hd',
    title: 'The Multi-Agent Indirect Injection Problem',
    description: 'Autonomous AI agents ingest untrusted external context (résumés, web pages, third-party emails). Adversaries embed prompt injections that hijack agent decisions. SentinelMesh acts as a deterministic security perimeter.',
    badge: 'Step 1 / 9 · Problem',
    position: 'bottom',
  },
  {
    targetId: 'chain-card',
    title: 'Live 5-Step Incident Attack Chain',
    description: 'Trace indirect prompt injection step-by-step: untrusted résumé ingestion, instruction override, unauthorized payroll database query, and external exfiltration attempt.',
    badge: 'Step 2 / 9 · Live Attack',
    position: 'right',
  },
  {
    targetId: 'gauge-box',
    title: 'Multi-Signal Risk Scoring & Agent Mesh',
    description: 'Dynamic risk scoring synthesizing 6 independent defense signals: syntactic rules, privacy entity vault, provenance taint, behavioral baseline, and policy intent.',
    badge: 'Step 3 / 9 · Risk & Mesh',
    position: 'left',
  },
  {
    targetId: 'mode-seg',
    title: 'Where It Was Cut: Monitor vs. Enforce',
    description: 'In Enforce mode, the attack is halted inline at Step 3 before sensitive database execution (0 records exposed). In Monitor mode, the attack runs unhindered, exposing 45 payroll records.',
    badge: 'Step 4 / 9 · Where Cut',
    position: 'bottom',
  },
  {
    targetId: 'wf',
    title: 'Risk Waterfall & Attribution Evidence',
    description: 'Granular breakdown of why risk scored 100/100: untrusted document source (+35), unapproved sensitive database columns (+30), and unknown external email recipient (+35).',
    badge: 'Step 5 / 9 · Waterfall',
    position: 'bottom',
  },
  {
    targetId: 'sws',
    title: 'Policy Lab: All Defenses Active',
    description: 'Interactive sandbox testing the full defense-in-depth stack: value-level taint tracking, pre-read protection, domain/recipient rules, and behavioral anomaly profiling.',
    badge: 'Step 6 / 9 · Lab (All On)',
    position: 'right',
  },
  {
    targetId: 'f2',
    title: 'Policy Lab: Defense Layer Ablation',
    description: 'Toggle individual defense layers off to observe attack penetration and verify the necessity of each barrier under identical adversary payloads.',
    badge: 'Step 7 / 9 · Lab (All Off)',
    position: 'bottom',
  },
  {
    targetId: 'ch',
    title: 'Tamper-Evident Hash Chain Verification',
    description: 'Cryptographic SHA-256 HMAC ledger chaining every gateway action. Click "Tamper with event 3" to modify a client-side block and watch downstream integrity checks fail immediately.',
    badge: 'Step 8 / 9 · Audit Tamper',
    position: 'bottom',
  },
  {
    targetId: 'defense-radar-card',
    title: 'Scientific Evidence Dashboard & Defense Radar',
    description: 'Empirical benchmark results across InjecAgent, AgentDojo, and ai4privacy with 5-axis defense layer radar analysis. Rigorously documents statistical sample limits (N=1 anecdotal sample on AgentDojo, phone precision trade-offs).',
    badge: 'Step 9 / 9 · Evidence & Limits',
    position: 'bottom',
  },
];
