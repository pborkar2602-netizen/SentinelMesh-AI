export type RouteId =
  | 'overview'
  | 'console'
  | 'playground'
  | 'audit'
  | 'benchmarks'
  | 'architecture';

export interface RouteDef {
  id: RouteId;
  path: string;
  label: string;
  tagline: string;
}

export const ROUTES: RouteDef[] = [
  {
    id: 'overview',
    path: '/',
    label: 'Overview',
    tagline: 'Gateway overview, live telemetry ticker, and verified empirical proof bar',
  },
  {
    id: 'console',
    path: '/console',
    label: 'Console',
    tagline: 'Enforce/Monitor enforcement gate, live WebSocket stream, HMAC approvals, and incidents',
  },
  {
    id: 'playground',
    path: '/playground',
    label: 'Playground',
    tagline: 'Interactive 3-lane sandbox comparing Pass-Through, 6-Phrase Filter, and SentinelMesh',
  },
  {
    id: 'audit',
    path: '/audit',
    label: 'Audit & Vault',
    tagline: 'SHA-256 hash-chain verification, RBAC privacy vault unmasking, and policy replay',
  },
  {
    id: 'benchmarks',
    path: '/benchmarks',
    label: 'Benchmarks',
    tagline: 'Holdout evaluations, wording crossover, methodology errata, datasets, and bypass logs',
  },
  {
    id: 'architecture',
    path: '/architecture',
    label: 'Architecture',
    tagline: '6-layer interception pipeline, declarative policy manifest, and MCP proxy spec',
  },
];

export function normalizeRoute(pathname: string): string {
  const clean = (pathname || '/').replace(/\/+$/, '') || '/';
  const match = ROUTES.find((r) => r.path === clean);
  return match ? match.path : '/';
}

export function getRouteDef(pathname: string): RouteDef {
  const norm = normalizeRoute(pathname);
  return ROUTES.find((r) => r.path === norm) || ROUTES[0];
}
