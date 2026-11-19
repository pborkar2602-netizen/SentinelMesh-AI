export interface TourStep {
  targetId: string;
  title: string;
  description: string;
  badge?: string;
  position?: 'top' | 'bottom' | 'left' | 'right' | 'center';
  levels?: ('simple' | 'story' | 'expert')[];
}

export const TOUR_STEPS: TourStep[] = [
  {
    targetId: 'hero-badge',
    title: 'The Multi-Agent Indirect Injection Problem',
    description: 'Autonomous AI agents ingest untrusted external context (résumés, web pages, third-party emails). Adversaries embed prompt injections that hijack agent decisions. SentinelMesh acts as a deterministic security perimeter.',
    badge: 'Problem',
    position: 'bottom',
    levels: ['simple', 'story', 'expert'],
  },
  {
    targetId: 'chain-card',
    title: 'Live 5-Step Incident Attack Chain',
    description: 'Trace indirect prompt injection step-by-step: untrusted résumé ingestion, instruction override, unauthorized payroll database query, and external exfiltration attempt.',
    badge: 'Live Attack',
    position: 'right',
    levels: ['story', 'expert'],
  },
  {
    targetId: 'gauge-box',
    title: 'Multi-Signal Risk Scoring & Agent Mesh',
    description: 'Dynamic risk scoring synthesizing 6 independent defense signals: syntactic rules, privacy entity vault, provenance taint, behavioral baseline, and policy intent.',
    badge: 'Risk & Mesh',
    position: 'left',
    levels: ['expert'],
  },
  {
    targetId: 'mode-seg',
    title: 'Where It Was Cut: Monitor vs. Enforce',
    description: 'In Enforce mode, the attack is halted inline at Step 3 before sensitive database execution (0 records exposed). In Monitor mode, the attack runs unhindered, exposing 3 payroll records.',
    badge: 'Where Cut',
    position: 'bottom',
    levels: ['story', 'expert'],
  },
  {
    targetId: 'explain',
    title: 'The Idea in 60 Seconds: Four Beats of Evidence',
    description: 'Understand the entire defense in four simple beats: untrusted ingestion, hidden injection, inline interception, and forensic evidence attribution.',
    badge: 'The Idea in 60s',
    position: 'bottom',
    levels: ['simple', 'story', 'expert'],
  },
  {
    targetId: 'sws',
    title: 'Policy Lab: All Defenses Active',
    description: 'Interactive sandbox testing the full defense-in-depth stack: value-level taint tracking, pre-read protection, domain/recipient rules, and behavioral anomaly profiling.',
    badge: 'Policy Lab',
    position: 'right',
    levels: ['story', 'expert'],
  },
  {
    targetId: 'f2',
    title: 'Policy Lab: Defense Layer Ablation',
    description: 'Toggle individual defense layers off to observe attack penetration and verify the necessity of each barrier under identical adversary payloads.',
    badge: 'Defense Ablation',
    position: 'bottom',
    levels: ['expert'],
  },
  {
    targetId: 'ch',
    title: 'Tamper-Evident Hash Chain Verification',
    description: 'Cryptographic SHA-256 HMAC ledger chaining every gateway action. Modify a client-side block and watch downstream integrity checks fail immediately.',
    badge: 'Audit Tamper',
    position: 'bottom',
    levels: ['story', 'expert'],
  },
  {
    targetId: 'results',
    title: 'Scientific Evidence Dashboard & Crossover Chart',
    description: 'Empirical benchmark results across InjecAgent, AgentDojo, and ai4privacy. Shows the wording-crossover chart with 95% cluster-bootstrap interval lines and zero hand-typed metrics.',
    badge: 'Evidence',
    position: 'bottom',
    levels: ['simple', 'story', 'expert'],
  },
];
