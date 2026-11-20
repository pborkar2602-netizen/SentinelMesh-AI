export interface TourStep {
  route: string;
  targetId: string;
  title: string;
  description: string;
  badge?: string;
  position?: 'top' | 'bottom' | 'left' | 'right' | 'center';
}

export const TOUR_STEPS: TourStep[] = [
  {
    route: '/',
    targetId: 'hero-badge',
    title: 'Runtime Security Perimeter for AI Agents',
    description:
      'Autonomous agents ingest untrusted external context (résumés, web pages, third-party emails). SentinelMesh inspects every tool call inline before side effects occur.',
    badge: '1 · Overview',
    position: 'bottom',
  },
  {
    route: '/console',
    targetId: 'chain-card',
    title: 'Live Console: Enforce vs. Monitor Interception',
    description:
      'Compare Enforce mode (halts sensitive DB reads inline with 0 records exposed) against Monitor mode, inspect real WebSocket events, and review HMAC approval queues.',
    badge: '2 · Console',
    position: 'right',
  },
  {
    route: '/playground',
    targetId: 'sws',
    title: '3-Lane Adversarial Sandbox',
    description:
      'Run prompt injections, SSRF, SQLi, credential leaks, and benign workflows live against Pass-Through (B0), 6-Phrase Filter (B2), and SentinelMesh Gateway (B4).',
    badge: '3 · Playground',
    position: 'bottom',
  },
  {
    route: '/audit',
    targetId: 'ch',
    title: 'Cryptographic SHA-256 Hash Chain & Privacy Vault',
    description:
      'Every gateway decision links to its predecessor via SHA-256. Mutating any event invalidates downstream verification; PII remains tokenized unless a Privacy Officer authenticates via JWT.',
    badge: '4 · Audit & Vault',
    position: 'bottom',
  },
  {
    route: '/benchmarks',
    targetId: 'evidence-section',
    title: 'Holdout Benchmarks & Methodology Errata',
    description:
      'Metrics loaded dynamically from benchmark/reports/*.json with Base vs. Enhanced wording-crossover intervals, 44-cluster permutation tests, and Before → After audit corrections.',
    badge: '5 · Benchmarks',
    position: 'bottom',
  },
  {
    route: '/architecture',
    targetId: 'arch-layers',
    title: 'Six Independent Layers & MCP Proxy',
    description:
      'Provenance taint tracking, synchronous policy gateway, AES-GCM vault, hash-chained audit, MAD baseline profiling, and HMAC approvals backed by declarative policies.',
    badge: '6 · Architecture',
    position: 'bottom',
  },
];
