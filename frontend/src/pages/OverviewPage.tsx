import React from 'react';
import { AgentMesh } from '../components/AgentMesh';
import { ProofBar } from '../components/ProofBar';
import { AuditEvent } from '../types';
import { ArrowRight, Terminal, FlaskConical, ShieldCheck, BarChart3, Layers } from 'lucide-react';

const THREAT_NAMES = [
  'LLM01 Prompt injection',
  'LLM02 Sensitive data disclosure',
  'LLM06 Excessive agency',
  'LLM07 System prompt leakage',
  'LLM08 Context poisoning',
  'LLM10 Unbounded consumption',
  'SSRF to cloud metadata',
  'Credential leakage',
  'Forged approval tokens',
  'Low-and-slow exfiltration',
  'Off-hours bulk reads',
  'Markdown image exfiltration',
];

export interface TickerLine {
  id: string;
  badge: string;
  cls: string;
  text: string;
}

interface OverviewPageProps {
  events: AuditEvent[];
  attackPulseTrigger: { blocked: boolean; seq: number } | null;
  tickerLines: TickerLine[];
  onNavigate: (path: string) => void;
  onStartTour: () => void;
}

const WORKSPACES = [
  {
    path: '/console',
    eyebrow: '01 · Operations',
    title: 'Security Console',
    desc: 'Toggle Enforce vs Monitor modes, stream live WebSocket decisions, resolve HMAC approvals, and inspect incident chains.',
    icon: Terminal,
    accent: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
  },
  {
    path: '/playground',
    eyebrow: '02 · Sandbox',
    title: 'Adversarial Playground',
    desc: 'Execute 6 attack and utility presets across Pass-Through, 6-Phrase Filter, and SentinelMesh in an isolated DB.',
    icon: FlaskConical,
    accent: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
  },
  {
    path: '/audit',
    eyebrow: '03 · Forensics',
    title: 'Audit & Privacy Vault',
    desc: 'Cryptographically verify the SHA-256 ledger, test RBAC raw PII unmasking via JWT, and replay policies.',
    icon: ShieldCheck,
    accent: 'text-purple-400 border-purple-500/30 bg-purple-500/10',
  },
  {
    path: '/benchmarks',
    eyebrow: '04 · Verification',
    title: 'Empirical Benchmarks',
    desc: 'Explore preregistered holdout results on InjecAgent & AgentDojo, cluster CIs, datasets, and methodology errata.',
    icon: BarChart3,
    accent: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
  },
  {
    path: '/architecture',
    eyebrow: '05 · System Spec',
    title: 'Architecture & MCP',
    desc: 'Inspect the 6 defense layers, AST + provenance taint pipeline, declarative policy pack, and MCP JSON-RPC proxy.',
    icon: Layers,
    accent: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
  },
];

export const OverviewPage: React.FC<OverviewPageProps> = ({
  events,
  attackPulseTrigger,
  tickerLines,
  onNavigate,
  onStartTour,
}) => {
  return (
    <div>
      {/* Hero */}
      <header className="hero" id="home">
        <div className="rays" aria-hidden="true" />
        <AgentMesh
          mode="hero"
          canvasId="hc"
          className="absolute inset-0 w-full h-full"
          events={events}
          attackPulseTrigger={attackPulseTrigger}
        />

        <div className="w">
          <span className="pill" id="hero-badge">
            <i />
            Autonomous, privacy-preserving security for AI agents
          </span>

          <h1>
            Every agent action, <span className="gt">inspected</span> before it happens.
          </h1>

          <p className="lead">
            SentinelMesh sits inline between LLM agents and enterprise tools, enforces
            provenance-aware policy gates before execution, and seals every decision in a hash chain.
          </p>

          <div className="cta">
            <button
              type="button"
              className="btn"
              id="go"
              onClick={() => onNavigate('/console')}
            >
              Open Console →
            </button>
            <button
              type="button"
              className="btn g"
              onClick={() => onNavigate('/playground')}
            >
              Try Playground
            </button>
            <button
              type="button"
              className="btn g"
              onClick={onStartTour}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
              data-testid="start-tour-btn"
            >
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#34d399' }} />
              Guided tour (T)
            </button>
          </div>

          {tickerLines.length > 0 && (
            <div className="tick mono" id="tick">
              {tickerLines.map((line) => (
                <div key={line.id} className="ln">
                  <b className={`t ${line.cls}`}>{line.badge}</b> {line.text}
                </div>
              ))}
            </div>
          )}
        </div>
      </header>

      {/* Threat Marquee */}
      <div className="mq" aria-hidden="true">
        <div id="m1">
          {THREAT_NAMES.concat(THREAT_NAMES).map((t, idx) => (
            <span key={`m1-${idx}`}>{t}</span>
          ))}
        </div>
        <div id="m2">
          {THREAT_NAMES.concat(THREAT_NAMES).map((t, idx) => (
            <span key={`m2-${idx}`}>{t}</span>
          ))}
        </div>
      </div>

      {/* Empirical Proof Bar */}
      <ProofBar onJumpToEvidence={() => onNavigate('/benchmarks')} />

      {/* Workspace Navigation Directory */}
      <section className="py-12">
        <div className="w">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-6">
            <div>
              <div className="eb" style={{ marginBottom: '8px' }}>Workspaces</div>
              <h2 style={{ fontSize: 'clamp(24px, 3vw, 36px)' }}>Inspect every subsystem directly.</h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Navigate via top dock or hotkeys <kbd className="px-1.5 py-0.5 rounded bg-white/10 text-slate-200">1</kbd>–<kbd className="px-1.5 py-0.5 rounded bg-white/10 text-slate-200">6</kbd>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" data-testid="workspaces-grid">
            {WORKSPACES.map((ws) => {
              const Icon = ws.icon;
              return (
                <button
                  key={ws.path}
                  type="button"
                  onClick={() => onNavigate(ws.path)}
                  className="card text-left hover:border-cyan-400/50 transition-all duration-150 group flex flex-col justify-between gap-4"
                  data-testid={`workspace-card-${ws.path.slice(1)}`}
                >
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                        {ws.eyebrow}
                      </span>
                      <span className={`p-2 rounded-lg border ${ws.accent}`}>
                        <Icon className="w-4 h-4" />
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition-colors">
                      {ws.title}
                    </h3>
                    <p className="text-xs text-slate-400 leading-relaxed font-sans m-0">
                      {ws.desc}
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 pt-2 border-t border-white/5 w-full">
                    <span>Open workspace</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
};
