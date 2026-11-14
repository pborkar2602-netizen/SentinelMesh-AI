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
    title: 'Adaptive Floating Navigation',
    description: 'Auto-expanding top navigation with scroll spy, section shortcuts (Keys 1-7), and quick-access commands. Press N to toggle nav or T for this tour.',
    badge: 'Navigation · Key N',
    position: 'bottom',
  },
  {
    targetId: 'demo',
    title: 'Incident Hero & Attack Chain',
    description: 'Visualizes indirect prompt injection attacks step-by-step: untrusted ingestion, instruction override, unauthorized data read, and attempted exfiltration.',
    badge: 'Attack Chain · Section 2',
    position: 'bottom',
  },
  {
    targetId: 'fg',
    title: 'Multi-Signal Risk Gauge',
    description: 'Dynamic risk scoring synthesizing 6 independent defense layers: syntactic rules, privacy entity vault, provenance taint, behavioral baseline, and policy intent.',
    badge: 'Risk Engine',
    position: 'left',
  },
  {
    targetId: 'mE',
    title: 'Monitor vs. Enforce Controls',
    description: 'Toggle between Monitor mode (passive auditing with zero disruption) and Enforce mode (active prevention halting attacks inline with 0 records exposed).',
    badge: 'Policy Enforcement',
    position: 'bottom',
  },
  {
    targetId: 'lab',
    title: 'Interactive Policy Lab',
    description: 'Simulate arbitrary tool calls, arguments, and taint states in real time. Validate safety rules before deploying new agent tools to production.',
    badge: 'Sandbox · Section 4',
    position: 'top',
  },
  {
    targetId: 'audit',
    title: 'Tamper-Evident Hash Chain',
    description: 'Cryptographic SHA-256 audit ledger with continuous hash-chain integrity verification. Any historical modification is immediately detected.',
    badge: 'Forensics · Section 5',
    position: 'top',
  },
  {
    targetId: 'results',
    title: 'Scientific Evidence & Defense Radar',
    description: 'Empirical benchmark results across InjecAgent, AgentDojo, and ai4privacy with 5-axis defense layer radar analysis and McNemar paired significance tests.',
    badge: 'Empirical Results · Section 7',
    position: 'top',
  },
];
