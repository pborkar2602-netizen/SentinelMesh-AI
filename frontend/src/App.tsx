import React, { useState, useEffect, useRef, useCallback } from 'react';
import { AuditEvent, DashboardStats } from './types';
import { ROUTES, normalizeRoute, getRouteDef } from './routes';
import { TourOverlay } from './tour/TourOverlay';
import { OverviewPage, TickerLine } from './pages/OverviewPage';
import { ConsolePage, SimChainStep } from './pages/ConsolePage';
import { PlaygroundPage } from './pages/PlaygroundPage';
import { AuditPrivacyPage } from './pages/AuditPrivacyPage';
import { BenchmarksPage } from './pages/BenchmarksPage';
import { ArchitecturePage } from './pages/ArchitecturePage';

const ENFORCE_CHAIN_STEPS: SimChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read requested', desc: 'Held for approval before the read (0 records exposed)', cls: 'ro' },
  { num: '04', title: 'External send attempted', desc: 'Never reached (halted inline by policy)', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Policy held the read. Nothing left the company.', cls: 'gr' },
];

const MONITOR_CHAIN_STEPS: SimChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read executed', desc: '3 salary & SSN rows read into agent memory', cls: 'ro' },
  { num: '04', title: 'External send succeeded', desc: 'send_email → recruiter@ext-hiring.com', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Monitor mode: action audited only, leak allowed', cls: 'ro' },
];

function formatRelativeTime(isoString: string): string {
  const diffSec = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  return `${Math.floor(diffSec / 3600)}h ago`;
}

export function App() {
  const [currentPath, setCurrentPath] = useState<string>(() =>
    normalizeRoute(window.location.pathname)
  );
  const activeRoute = getRouteDef(currentPath);

  // Navigation pill & dock state (animation CSS preserved 100%)
  const [navOpen, setNavOpen] = useState(false);
  const [indicatorStyle, setIndicatorStyle] = useState<{ left: number; width: number }>({
    left: 0,
    width: 0,
  });

  // Live Telemetry & Policy State
  const [policyMode, setPolicyMode] = useState<'enforce' | 'monitor'>('enforce');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [feedLines, setFeedLines] = useState<TickerLine[]>([]);
  const [tickerLines, setTickerLines] = useState<TickerLine[]>([]);
  const [showToolReturn, setShowToolReturn] = useState(false);
  const [liveAttackRunning, setLiveAttackRunning] = useState(false);

  // Attack chain replay state
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
  const [attackPulseTrigger, setAttackPulseTrigger] = useState<{ blocked: boolean; seq: number } | null>(null);

  // Guided Tour state
  const [tourOpen, setTourOpen] = useState<boolean>(() => {
    return new URLSearchParams(window.location.search).get('tour') === '1';
  });

  // Refs
  const navCloseTimerRef = useRef<any>(null);
  const buttonsRef = useRef<Record<string, HTMLButtonElement | null>>({});
  const lastScrollYRef = useRef(0);
  const upAccumulatorRef = useRef(0);
  const animTimersRef = useRef<any[]>([]);

  // Indicator positioning
  const updateIndicator = useCallback((routeId: string) => {
    const btn = buttonsRef.current[routeId];
    if (btn) {
      setIndicatorStyle({ left: btn.offsetLeft, width: btn.offsetWidth });
    }
  }, []);

  const openNav = useCallback(() => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    setNavOpen(true);
    requestAnimationFrame(() => updateIndicator(activeRoute.id));
  }, [activeRoute.id, updateIndicator]);

  const closeNav = useCallback((delayMs = 0) => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    if (delayMs <= 0) {
      setNavOpen(false);
    } else {
      navCloseTimerRef.current = setTimeout(() => setNavOpen(false), delayMs);
    }
  }, []);

  // Client-side SPA Navigation
  const navigate = useCallback(
    (path: string) => {
      const target = normalizeRoute(path);
      if (target !== normalizeRoute(window.location.pathname)) {
        window.history.pushState({}, '', target);
      }
      setCurrentPath(target);
      window.scrollTo({ top: 0, behavior: 'auto' });
      const route = getRouteDef(target);
      requestAnimationFrame(() => updateIndicator(route.id));
      closeNav(220);
    },
    [closeNav, updateIndicator]
  );

  useEffect(() => {
    const onPopState = () => {
      const norm = normalizeRoute(window.location.pathname);
      setCurrentPath(norm);
      const route = getRouteDef(norm);
      requestAnimationFrame(() => updateIndicator(route.id));
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [updateIndicator]);

  useEffect(() => {
    requestAnimationFrame(() => updateIndicator(activeRoute.id));
  }, [activeRoute.id, navOpen, updateIndicator]);

  // Fetch initial telemetry from backend via Vite /api proxy
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

  const fetchEvents = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/events?limit=30&order=desc&exclude_benchmark=true');
      if (res.ok) {
        const data: AuditEvent[] = await res.json();
        setEvents(data);
        const lines = data.slice(0, 10).map((ev) => {
          let b = 'ALLOW';
          let cls = 'gr';
          const dec = (ev.decision || '').toLowerCase();
          if (dec === 'block') { b = 'BLOCK'; cls = 'ro'; }
          else if (dec === 'would_block') { b = 'WOULD LEAK'; cls = 'ro'; }
          else if (dec === 'require_approval') { b = 'APPROVAL'; cls = 'am'; }
          else if (dec === 'redact') { b = 'MASK'; cls = 'cy'; }

          let callText = `${ev.agent_id} · ${ev.tool_name}`;
          const args = ev.arguments || {};
          if (ev.tool_name === 'read_doc') callText = `${ev.agent_id} · read_doc(${args.file_path || 'doc'})`;
          if (ev.tool_name === 'db_query') callText = `${ev.agent_id} · db_query(${String(args.query || '').slice(0, 30)}…)`;
          if (ev.tool_name === 'send_email') callText = `${ev.agent_id} · send_email(${args.to || 'ext'})`;

          return {
            id: `ev-${ev.id}`,
            badge: b,
            cls,
            text: `${callText} (${formatRelativeTime(ev.timestamp)}${ev.latency_ms ? ` · ${ev.latency_ms.toFixed(1)}ms` : ''})`,
          };
        });
        setFeedLines(lines);
        setTickerLines(lines.slice(0, 4));
      }
    } catch {
      const initial = [
        { id: '1', badge: 'ALLOW', cls: 'gr', text: 'hr-agent · read_doc(policy.pdf) (just now · 4.2ms)' },
        { id: '2', badge: 'MASK', cls: 'cy', text: 'PII tokenized before logging [PERSON_1, SALARY_1]' },
        { id: '3', badge: 'ALLOW', cls: 'gr', text: 'finance-agent · db_query(invoices) (12s ago · 6.1ms)' },
      ];
      setFeedLines(initial);
      setTickerLines(initial);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchEvents();
  }, [fetchStats, fetchEvents]);

  // WebSocket live event stream
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${wsProto}://${window.location.host}/ws/events`);
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'AUDIT_EVENT' && msg.data) {
              const ev: AuditEvent = msg.data;
              setEvents((prev) => [ev, ...prev.slice(0, 49)]);

              let b = 'ALLOW';
              let cls = 'gr';
              const dec = (ev.decision || '').toLowerCase();
              if (dec === 'block') { b = 'BLOCK'; cls = 'ro'; }
              else if (dec === 'would_block') { b = 'WOULD LEAK'; cls = 'ro'; }
              else if (dec === 'require_approval') { b = 'APPROVAL'; cls = 'am'; }
              else if (dec === 'redact') { b = 'MASK'; cls = 'cy'; }

              let callText = `${ev.agent_id} · ${ev.tool_name}`;
              const args = ev.arguments || {};
              if (ev.tool_name === 'read_doc') callText = `${ev.agent_id} · read_doc(${args.file_path || 'doc'})`;
              if (ev.tool_name === 'db_query') callText = `${ev.agent_id} · db_query(${String(args.query || '').slice(0, 30)}…)`;
              if (ev.tool_name === 'send_email') callText = `${ev.agent_id} · send_email(${args.to || 'ext'})`;

              const newLine = {
                id: `ws-${Date.now()}-${Math.random()}`,
                badge: b,
                cls,
                text: `${callText} (${formatRelativeTime(ev.timestamp)}${ev.latency_ms ? ` · ${ev.latency_ms.toFixed(1)}ms` : ''})`,
              };

              setFeedLines((prev) => [newLine, ...prev.slice(0, 11)]);
              setTickerLines((prev) => [newLine, ...prev.slice(0, 3)]);

              if (dec === 'block' || dec === 'would_block') {
                setAttackPulseTrigger({ blocked: true, seq: Date.now() });
              } else if (dec === 'allow') {
                setAttackPulseTrigger({ blocked: false, seq: Date.now() });
              }
            }
          } catch {
            // Ignore malformed socket frames
          }
        };
        ws.onclose = () => {
          reconnectTimeout = setTimeout(connect, 3500);
        };
      } catch {
        reconnectTimeout = setTimeout(connect, 3500);
      }
    };

    connect();
    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // Cursor glow & card spotlight tracking
  useEffect(() => {
    const cur = document.getElementById('cur');
    const onMove = (e: PointerEvent) => {
      if (cur) cur.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
      const target = e.target as HTMLElement | null;
      const card = target?.closest?.('.card') as HTMLElement | null;
      if (card) {
        const r = card.getBoundingClientRect();
        card.style.setProperty('--mx', `${e.clientX - r.left}px`);
        card.style.setProperty('--my', `${e.clientY - r.top}px`);
      }
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => window.removeEventListener('pointermove', onMove);
  }, []);

  // Scroll progress line + upward-scroll nav auto-reveal
  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      const docHeight = Math.max(1, document.body.scrollHeight - window.innerHeight);
      const scrollFraction = Math.min(1, Math.max(0, y / docHeight));
      const pg = document.getElementById('pg');
      if (pg) pg.style.transform = `scaleX(${scrollFraction})`;

      if (y < lastScrollYRef.current) {
        upAccumulatorRef.current += lastScrollYRef.current - y;
      } else {
        upAccumulatorRef.current = 0;
      }
      if (upAccumulatorRef.current > 200 && y > 200) {
        openNav();
        closeNav(2200);
        upAccumulatorRef.current = 0;
      }
      lastScrollYRef.current = y;
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, [openNav, closeNav]);

  // Keyboard navigation hotkeys (N, T, 1-6, Escape)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (/INPUT|TEXTAREA|SELECT/.test((e.target as HTMLElement)?.tagName || '')) return;
      if (e.key === 'n' || e.key === 'N') {
        if (navOpen) closeNav(0);
        else openNav();
      }
      if (e.key === 't' || e.key === 'T') {
        setTourOpen((prev) => !prev);
      }
      if (e.key >= '1' && e.key <= '6') {
        const idx = parseInt(e.key, 10) - 1;
        if (ROUTES[idx]) navigate(ROUTES[idx].path);
      }
      if (e.key === 'Escape') {
        closeNav(0);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navOpen, openNav, closeNav, navigate]);

  // Console Attack Chain Replay
  const runAttackSimulation = useCallback(() => {
    animTimersRef.current.forEach(clearTimeout);
    animTimersRef.current = [];

    const initialSteps: SimChainStep[] = [
      { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
      { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
      { num: '03', title: 'Sensitive read requested', desc: 'salary and ssn are not part of the task', cls: 'am' },
      {
        num: '04',
        title: policyMode === 'enforce' ? 'External send guarded' : 'External send attempted',
        desc: policyMode === 'enforce' ? 'Awaiting database gate outcome…' : 'send_email → recruiter@ext-hiring.com',
        cls: 'ro',
      },
      { num: '05', title: 'Policy decision', desc: 'Evaluating gateway defense layers…', cls: 'gr' },
    ];

    setChainSteps(initialSteps);
    setStepActive([false, false, false, false, false]);
    setStepClasses(initialSteps.map((s) => s.cls));
    setBarWidths([0, 0, 0, 0]);
    setRiskGauge(0);
    setVerdict({ show: false, ok: true, text: '' });

    const at = (ms: number, fn: () => void) => {
      const t = setTimeout(fn, ms);
      animTimersRef.current.push(t);
    };

    at(150, () => {
      setStepActive([true, false, false, false, false]);
      setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'TAINT', cls: 'am', text: 'resume.pdf marked untrusted' }, ...prev.slice(0, 11)]);
      setBarWidths([38 * 2.6, 0, 0, 0]);
      setRiskGauge(26);
    });
    at(950, () => {
      setStepActive([true, true, false, false, false]);
      setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'INJECT', cls: 'ro', text: 'hidden instruction detected on page 2' }, ...prev.slice(0, 11)]);
      setBarWidths((prev) => [prev[0], 0, 25 * 2.6, 0]);
      setRiskGauge(48);
    });
    at(1800, () => {
      setStepActive([true, true, true, false, false]);
      setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'READ', cls: 'am', text: 'salary, ssn requested outside task scope' }, ...prev.slice(0, 11)]);
      setBarWidths((prev) => [prev[0], 15 * 2.6, prev[2], 0]);
      setRiskGauge(64);
      setAttackPulseTrigger({ blocked: policyMode === 'enforce', seq: Date.now() });
    });

    if (policyMode === 'enforce') {
      at(2500, () => {
        setStepClasses((prev) => [prev[0], prev[1], 'ro', prev[3], 'gr']);
        setStepActive([true, true, true, false, true]);
        setChainSteps((prev) => [
          prev[0],
          prev[1],
          { ...prev[2], desc: 'Held for approval before the read (0 records exposed)' },
          { ...prev[3], desc: 'Never reached (halted inline by policy)' },
          { ...prev[4], desc: 'Policy held the read. Nothing left the company.' },
        ]);
        setBarWidths((prev) => [prev[0], prev[1], prev[2], 22 * 2.6]);
        setRiskGauge(96);
        setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'HOLD', cls: 'ro', text: 'db_query held · 0 records exposed' }, ...prev.slice(0, 11)]);
        setVerdict({
          show: true,
          ok: true,
          text: 'BLOCKED: 0 records exposed (Enforce mode) · Held at sensitive database read',
        });
      });
    } else {
      at(2600, () => {
        setStepActive([true, true, true, true, false]);
        setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'SEND', cls: 'am', text: 'send_email → recruiter@ext-hiring.com' }, ...prev.slice(0, 11)]);
        setBarWidths((prev) => [prev[0], prev[1], prev[2], 22 * 2.6]);
        setRiskGauge(88);
      });
      at(3400, () => {
        setStepClasses((prev) => [prev[0], prev[1], prev[2], prev[3], 'ro']);
        setStepActive([true, true, true, true, true]);
        setChainSteps((prev) => [
          prev[0],
          prev[1],
          { ...prev[2], desc: '3 salary & SSN rows read into agent memory' },
          { ...prev[3], desc: 'send_email → recruiter@ext-hiring.com' },
          { ...prev[4], desc: 'Monitor mode: alert only, action allowed' },
        ]);
        setRiskGauge(98);
        setFeedLines((prev) => [{ id: `ln-${Date.now()}`, badge: 'LEAK', cls: 'ro', text: '3 records sent outside · alert only' }, ...prev.slice(0, 11)]);
        setVerdict({
          show: true,
          ok: false,
          text: 'LEAKED: 3 records exposed to external recipient (Monitor mode · demo roster)',
        });
      });
    }
  }, [policyMode]);

  const triggerRealLiveAttack = useCallback(async () => {
    setLiveAttackRunning(true);
    runAttackSimulation();
    try {
      await fetch(`/api/v1/demo/run_attack?mode=${policyMode}`, { method: 'POST' });
    } catch {
      // Offline fallback continues UI simulation
    } finally {
      setTimeout(() => {
        setLiveAttackRunning(false);
        fetchStats();
      }, 4500);
    }
  }, [policyMode, runAttackSimulation, fetchStats]);

  const switchMode = useCallback((newMode: 'enforce' | 'monitor') => {
    setPolicyMode(newMode);
    animTimersRef.current.forEach(clearTimeout);
    animTimersRef.current = [];

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

  return (
    <>
      <div className="cursor" id="cur" aria-hidden="true" />
      <div id="pg" aria-hidden="true" />
      <div id="hz" onMouseEnter={openNav} aria-hidden="true" />

      {/* Collapsible Floating Navigation (EXACT morph & animation preserved) */}
      <div id="nv" className={navOpen ? 'open' : ''}>
        <button
          id="hd"
          aria-label="Open navigation"
          onMouseEnter={openNav}
          onClick={openNav}
          data-testid="nav-pill"
        >
          <i />
          <span id="hl">{activeRoute.label}</span>
          <s>hover · N</s>
        </button>

        <nav
          id="bar"
          aria-label="Primary pages"
          onMouseEnter={() => {
            if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
          }}
          onMouseLeave={() => closeNav(650)}
        >
          <span
            className="ind"
            id="ind"
            style={{
              left: `${indicatorStyle.left}px`,
              width: `${indicatorStyle.width}px`,
            }}
          />
          {ROUTES.map((route, i) => (
            <button
              key={route.id}
              ref={(el) => {
                buttonsRef.current[route.id] = el;
              }}
              data-id={route.id}
              data-testid={`nav-link-${route.id}`}
              className={activeRoute.id === route.id ? 'on' : ''}
              style={{ '--i': i } as React.CSSProperties}
              onClick={() => navigate(route.path)}
            >
              {route.label}
              <kbd>{i + 1}</kbd>
            </button>
          ))}

          <div className="flex items-center pl-2 ml-1 border-l border-white/10">
            <button
              type="button"
              style={{ '--i': ROUTES.length } as React.CSSProperties}
              onClick={() => {
                closeNav(0);
                setTourOpen(true);
              }}
              data-testid="nav-tour-btn"
            >
              Tour
              <kbd>T</kbd>
            </button>
          </div>
        </nav>
      </div>

      {/* Active Route View */}
      <main key={currentPath} className="page-enter">
        {activeRoute.id === 'overview' && (
          <OverviewPage
            events={events}
            attackPulseTrigger={attackPulseTrigger}
            tickerLines={tickerLines}
            onNavigate={navigate}
            onStartTour={() => setTourOpen(true)}
          />
        )}
        {activeRoute.id === 'console' && (
          <ConsolePage
            stats={stats}
            policyMode={policyMode}
            events={events}
            attackPulseTrigger={attackPulseTrigger}
            feedLines={feedLines}
            showToolReturn={showToolReturn}
            onToggleToolReturn={setShowToolReturn}
            liveAttackRunning={liveAttackRunning}
            chainSteps={chainSteps}
            stepActive={stepActive}
            stepClasses={stepClasses}
            riskGauge={riskGauge}
            barWidths={barWidths}
            verdict={verdict}
            onSwitchMode={switchMode}
            onRunSimulation={runAttackSimulation}
            onTriggerRealAttack={triggerRealLiveAttack}
            onRefreshStats={fetchStats}
          />
        )}
        {activeRoute.id === 'playground' && <PlaygroundPage />}
        {activeRoute.id === 'audit' && (
          <AuditPrivacyPage
            stats={stats}
            policyMode={policyMode}
            events={events}
            onSwitchMode={switchMode}
          />
        )}
        {activeRoute.id === 'benchmarks' && <BenchmarksPage />}
        {activeRoute.id === 'architecture' && <ArchitecturePage stats={stats} />}
      </main>

      {/* Footer */}
      <div className="w">
        <footer>
          <span>
            <b>SentinelMesh AI</b> · Runtime Security Gateway for AI Agents
          </span>
          <span>Synthetic demo telemetry · Zero real personal data</span>
        </footer>
      </div>

      {/* Cross-Page Interactive Guided Tour */}
      <TourOverlay
        isOpen={tourOpen}
        currentRoute={currentPath}
        onNavigate={navigate}
        onClose={() => setTourOpen(false)}
      />
    </>
  );
}
export default App;
