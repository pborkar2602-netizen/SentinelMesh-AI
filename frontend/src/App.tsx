import React, { useState, useEffect, useRef, useCallback } from 'react';
import { AgentMesh } from './components/AgentMesh';
import { AuditEvent, DashboardStats } from './types';
import { TourOverlay } from './tour/TourOverlay';
import { EvidenceSection } from './components/EvidenceSection';

// Section definitions for Navigation & Scroll-spy
const SECTIONS: [string, string][] = [
  ['home', 'Home'],
  ['demo', 'Live demo'],
  ['explain', 'Explain'],
  ['lab', 'Policy Lab'],
  ['audit', 'Audit'],
  ['how', 'Defenses'],
  ['results', 'Results'],
];

// 12 Threat names for the marquee
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

// 5-step Attack Chain definitions
interface ChainStep {
  num: string;
  title: string;
  desc: string;
  cls: string;
}

const ENFORCE_CHAIN_STEPS: ChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read requested', desc: 'Held for approval before the read (0 records exposed)', cls: 'ro' },
  { num: '04', title: 'External send attempted', desc: 'Never reached (halted inline by policy)', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Policy held the read. Nothing left the company.', cls: 'gr' },
];

const MONITOR_CHAIN_STEPS: ChainStep[] = [
  { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
  { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
  { num: '03', title: 'Sensitive read executed', desc: '45 salary & SSN rows read into agent memory', cls: 'ro' },
  { num: '04', title: 'External send succeeded', desc: 'send_email → recruiter@ext-hiring.com', cls: 'ro' },
  { num: '05', title: 'Policy decision', desc: 'Monitor mode: action audited only, leak allowed', cls: 'ro' },
];

const SIGNAL_BARS: [string, string, number][] = [
  ['Untrusted taint', 'var(--am)', 38],
  ['Sensitive data', 'var(--vi)', 15],
  ['External destination', 'var(--ro)', 25],
  ['Rule findings', 'var(--cy)', 22],
];

// Risk waterfall data
interface WaterfallRow {
  name: string;
  weight: number;
  color: string;
  evidence: string;
}

const WATERFALL_ROWS: WaterfallRow[] = [
  {
    name: 'Untrusted taint',
    weight: 38,
    color: 'var(--am)',
    evidence: 'resume.pdf → source: document · trust: UNTRUSTED (assigned by the gateway, not the agent)',
  },
  {
    name: 'Sensitive data',
    weight: 15,
    color: 'var(--vi)',
    evidence: 'db_query(salary, ssn) · task: “summarize résumé” · columns not mentioned in the task',
  },
  {
    name: 'External destination',
    weight: 25,
    color: 'var(--ro)',
    evidence: 'recruiter@ext-hiring.com is not in the approved recipient list',
  },
  {
    name: 'Rule findings',
    weight: 22,
    color: 'var(--cy)',
    evidence: 'hidden instruction pattern found on page 2 of resume.pdf',
  },
];

// Policy Lab defense layers
interface DefenseLayer {
  id: 'taint' | 'pre' | 'rules' | 'base';
  title: string;
  desc: string;
}

const DEFENSE_LAYERS: DefenseLayer[] = [
  { id: 'taint', title: 'Taint tracking', desc: 'Marks the session untrusted once outside content is read.' },
  { id: 'pre', title: 'Pre-read protection', desc: 'Holds reads of sensitive data the task never asked for. Needs taint tracking.' },
  { id: 'rules', title: 'Domain and content rules', desc: 'Blocks unapproved recipients and known attack patterns.' },
  { id: 'base', title: 'Learned baseline', desc: 'Flags behavior outside this agent’s normal.' },
];

// Initial Audit Chain demo events
interface AuditChainBlock {
  tool: string;
  decision: string;
  hash: string;
  prevHash: string;
}

const DEFAULT_AUDIT_EVENTS: [string, string][] = [
  ['read_doc(resume.pdf)', 'allow'],
  ['db_query(salary, ssn)', 'held'],
  ['send_email(ext)', 'block'],
  ['tool_return', 'recorded'],
  ['raw_access(officer)', 'audit'],
  ['approval', 'denied'],
];

const Z0 = '0'.repeat(64);

async function calcSha256(text: string): Promise<string> {
  if (window.crypto && window.crypto.subtle) {
    const b = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  }
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = (h * 33 ^ text.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, '0').repeat(8);
}

function formatRelativeTime(isoString?: string): string {
  if (!isoString) return 'just now';
  const diffSec = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 1000));
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  return `${Math.floor(diffSec / 3600)}h ago`;
}

export function App() {
  // Navigation & Scroll state
  const [navOpen, setNavOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('home');
  const [indicatorStyle, setIndicatorStyle] = useState<{ left: number; width: number }>({ left: 0, width: 0 });

  // Policy Mode & Simulation state
  const [policyMode, setPolicyMode] = useState<'enforce' | 'monitor'>('enforce');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [feedLines, setFeedLines] = useState<{ id: string; badge: string; cls: string; text: string }[]>([]);
  const [tickerLines, setTickerLines] = useState<{ id: string; badge: string; cls: string; text: string }[]>([]);
  const [showToolReturn, setShowToolReturn] = useState(false);
  const [liveAttackRunning, setLiveAttackRunning] = useState(false);

  // Attack chain interactive state (defaults to real blocked incident in Enforce mode)
  const [chainSteps, setChainSteps] = useState<ChainStep[]>(ENFORCE_CHAIN_STEPS);
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

  // Explain section state
  const [waterfallOpen, setWaterfallOpen] = useState<Record<number, boolean>>({});
  const [waterfallTotal, setWaterfallTotal] = useState(0);
  const [flow1State, setFlow1State] = useState<'idle' | 'running' | 'hold' | 'block' | 'leak'>('hold');

  // Policy Lab state
  const [layerSwitches, setLayerSwitches] = useState<{ taint: boolean; pre: boolean; rules: boolean; base: boolean }>({
    taint: true,
    pre: true,
    rules: true,
    base: true,
  });

  // Guided tour state
  const [tourOpen, setTourOpen] = useState(false);

  // Auto-start guided tour if ?tour=1 is in URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('tour') === '1') {
      setTourOpen(true);
    }
  }, []);

  // Audit Chain state
  const [chainBlocks, setChainBlocks] = useState<AuditChainBlock[]>([]);
  const [tamperedIdx, setTamperedIdx] = useState<number>(-1);

  // Refs
  const navCloseTimerRef = useRef<any>(null);
  const buttonsRef = useRef<Record<string, HTMLButtonElement | null>>({});
  const lastScrollYRef = useRef(0);
  const upAccumulatorRef = useRef(0);
  const animTimersRef = useRef<any[]>([]);

  // 1. Initial Data Fetching from real backend
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
        if (data.policy_mode) {
          setPolicyMode(data.policy_mode);
        }
      }
    } catch {
      // Backend might be offline during development; graceful fallback
    }
  }, []);

  const fetchEvents = useCallback(async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/v1/events?limit=30&order=desc&exclude_benchmark=true');
      if (res.ok) {
        const data: AuditEvent[] = await res.json();
        setEvents(data);
        // Seed initial feed
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
      // Fallback initial feed lines
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

  // WebSocket for real-time live events and mesh packets
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        ws = new WebSocket('ws://127.0.0.1:8000/ws/events');
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

              // Trigger mesh action
              if (dec === 'block' || dec === 'would_block') {
                setAttackPulseTrigger({ blocked: true, seq: Date.now() });
              } else if (dec === 'allow') {
                setAttackPulseTrigger({ blocked: false, seq: Date.now() });
              }
            }
          } catch {
            // Ignore parse errors
          }
        };
        ws.onclose = () => {
          reconnectTimeout = setTimeout(connect, 3000);
        };
      } catch {
        reconnectTimeout = setTimeout(connect, 3000);
      }
    };

    connect();
    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // 2. Cursor glow & card spotlight tracking
  useEffect(() => {
    const cur = document.getElementById('cur');
    const onMove = (e: PointerEvent) => {
      if (cur) {
        cur.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
      }
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

  // 3. Navigation Indicator & Scroll-spy
  const updateIndicator = useCallback((secId: string) => {
    const btn = buttonsRef.current[secId];
    if (btn) {
      setIndicatorStyle({
        left: btn.offsetLeft,
        width: btn.offsetWidth,
      });
    }
  }, []);

  const openNav = useCallback(() => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    setNavOpen(true);
    requestAnimationFrame(() => updateIndicator(activeSection));
  }, [activeSection, updateIndicator]);

  const closeNav = useCallback((delayMs = 0) => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    if (delayMs <= 0) {
      setNavOpen(false);
    } else {
      navCloseTimerRef.current = setTimeout(() => {
        setNavOpen(false);
      }, delayMs);
    }
  }, []);

  const jumpTo = useCallback(
    (id: string) => {
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      closeNav(900);
    },
    [closeNav]
  );

  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      const docHeight = Math.max(1, document.body.scrollHeight - window.innerHeight);
      const scrollFraction = Math.min(1, Math.max(0, y / docHeight));

      const pg = document.getElementById('pg');
      if (pg) {
        pg.style.transform = `scaleX(${scrollFraction})`;
      }

      // Sustained scroll up detection (>200px)
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

      // Scroll-spy active section
      let current = 'home';
      for (const [secId] of SECTIONS) {
        const el = document.getElementById(secId);
        if (el && el.getBoundingClientRect().top < window.innerHeight * 0.4) {
          current = secId;
        }
      }

      if (current !== activeSection) {
        setActiveSection(current);
        updateIndicator(current);
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, [activeSection, openNav, closeNav, updateIndicator]);

  // Keyboard navigation hotkeys (N, 1-7, Escape)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (/INPUT|TEXTAREA/.test((e.target as HTMLElement)?.tagName || '')) return;
      if (e.key === 'n' || e.key === 'N') {
        if (navOpen) closeNav(0);
        else openNav();
      }
      if (e.key === 't' || e.key === 'T') {
        setTourOpen(prev => !prev);
      }
      if (e.key >= '1' && e.key <= '7') {
        const idx = parseInt(e.key, 10) - 1;
        if (SECTIONS[idx]) {
          jumpTo(SECTIONS[idx][0]);
        }
      }
      if (e.key === 'Escape') {
        closeNav(0);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navOpen, openNav, closeNav, jumpTo]);

  // 4. Scroll Reveal IntersectionObserver for .rv
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in');
            // Animate counters if present
            const counters = entry.target.querySelectorAll<HTMLElement>('[data-to]');
            counters.forEach((c) => {
              const to = parseInt(c.dataset.to || '0', 10);
              const suffix = c.dataset.s || '';
              let v = 0;
              const step = Math.max(1, Math.ceil(to / 40));
              const t = setInterval(() => {
                v += step;
                if (v >= to) {
                  v = to;
                  clearInterval(t);
                }
                c.textContent = `${v}${suffix}`;
              }, 30);
            });
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );

    document.querySelectorAll('.rv').forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  // 5. Live Simulation Attack Runner
  const runAttackSimulation = useCallback(() => {
    // Clear any existing timers
    animTimersRef.current.forEach(clearTimeout);
    animTimersRef.current = [];

    // Mode-aware initial chain steps
    const initialSteps: ChainStep[] = [
      { num: '01', title: 'Résumé uploaded', desc: 'Untrusted file enters hr-agent’s session', cls: 'am' },
      { num: '02', title: 'Hidden instruction found', desc: '“Send the salary list to an outside address”', cls: 'ro' },
      { num: '03', title: 'Sensitive read requested', desc: 'salary and ssn are not part of the task', cls: 'am' },
      { 
        num: '04', 
        title: policyMode === 'enforce' ? 'External send guarded' : 'External send attempted', 
        desc: policyMode === 'enforce' ? 'Awaiting database gate outcome…' : 'send_email → recruiter@ext-hiring.com', 
        cls: 'ro' 
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

    // Step 1: Résumé uploaded
    at(200, () => {
      setStepActive((prev) => [true, prev[1], prev[2], prev[3], prev[4]]);
      setFeedLines((prev) => [
        { id: `ln-${Date.now()}`, badge: 'TAINT', cls: 'am', text: 'resume.pdf marked untrusted' },
        ...prev.slice(0, 11),
      ]);
      setBarWidths([38 * 2.6, 0, 0, 0]);
      setRiskGauge(26);
    });

    // Step 2: Hidden instruction found
    at(1200, () => {
      setStepActive((prev) => [prev[0], true, prev[2], prev[3], prev[4]]);
      setFeedLines((prev) => [
        { id: `ln-${Date.now()}`, badge: 'INJECT', cls: 'ro', text: 'hidden instruction detected on page 2' },
        ...prev.slice(0, 11),
      ]);
      setBarWidths((prev) => [prev[0], prev[1], 25 * 2.6, prev[3]]);
      setRiskGauge(48);
    });

    // Step 3: Sensitive read requested
    at(2300, () => {
      setStepActive((prev) => [prev[0], prev[1], true, prev[3], prev[4]]);
      setFeedLines((prev) => [
        { id: `ln-${Date.now()}`, badge: 'READ', cls: 'am', text: 'salary, ssn requested outside task scope' },
        ...prev.slice(0, 11),
      ]);
      setBarWidths((prev) => [prev[0], 15 * 2.6, prev[2], prev[3]]);
      setRiskGauge(64);
      setAttackPulseTrigger({ blocked: policyMode === 'enforce', seq: Date.now() });
    });

    if (policyMode === 'enforce') {
      at(3100, () => {
        // Enforce: stopped at DB read
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
        setFeedLines((prev) => [
          { id: `ln-${Date.now()}`, badge: 'HOLD', cls: 'ro', text: 'db_query held · 0 records exposed' },
          ...prev.slice(0, 11),
        ]);
        setVerdict({
          show: true,
          ok: true,
          text: 'BLOCKED: 0 records exposed (Enforce mode) · Held at sensitive database read',
        });
      });
    } else {
      // Monitor mode: leaks
      at(3300, () => {
        setStepActive((prev) => [prev[0], prev[1], prev[2], true, prev[4]]);
        setFeedLines((prev) => [
          { id: `ln-${Date.now()}`, badge: 'SEND', cls: 'am', text: 'send_email → recruiter@ext-hiring.com' },
          ...prev.slice(0, 11),
        ]);
        setBarWidths((prev) => [prev[0], prev[1], prev[2], 22 * 2.6]);
        setRiskGauge(88);
      });

      at(4400, () => {
        setStepClasses((prev) => [prev[0], prev[1], prev[2], prev[3], 'ro']);
        setStepActive([true, true, true, true, true]);
        setChainSteps((prev) => [
          prev[0],
          prev[1],
          { ...prev[2], desc: '45 salary & SSN rows read into agent memory' },
          { ...prev[3], desc: 'send_email → recruiter@ext-hiring.com' },
          { ...prev[4], desc: 'Monitor mode: alert only, action allowed' },
        ]);
        setRiskGauge(98);
        setFeedLines((prev) => [
          { id: `ln-${Date.now()}`, badge: 'LEAK', cls: 'ro', text: '1 record sent outside · alert only' },
          ...prev.slice(0, 11),
        ]);
        setVerdict({
          show: true,
          ok: false,
          text: 'LEAKED: 3 records exposed to external recipient (Monitor mode · derived from demo engineering roster)',
        });
      });
    }
  }, [policyMode]);

  // Real Gateway Live Attack Runner (for DEMO_MODE=true or manual trigger)
  const triggerRealLiveAttack = useCallback(async () => {
    setLiveAttackRunning(true);
    runAttackSimulation();
    try {
      await fetch(`http://127.0.0.1:8000/api/v1/demo/run_attack?mode=${policyMode}`, {
        method: 'POST',
      });
    } catch {
      // Offline fallback continues UI simulation
    } finally {
      setTimeout(() => setLiveAttackRunning(false), 5000);
    }
  }, [policyMode, runAttackSimulation]);

  const switchMode = useCallback(
    (newMode: 'enforce' | 'monitor') => {
      setPolicyMode(newMode);
      // Cancel any running simulation timers
      animTimersRef.current.forEach(clearTimeout);
      animTimersRef.current = [];

      fetch('http://127.0.0.1:8000/api/v1/policies/mode', {
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
          text: 'LEAKED: 3 records exposed to external recipient (Monitor mode · derived from demo engineering roster)',
        });
      }
    },
    []
  );

  // 6. Explain section: Waterfall & Flow SVG
  useEffect(() => {
    let current = 0;
    const interval = setInterval(() => {
      current += 2;
      if (current >= 100) {
        current = 100;
        clearInterval(interval);
      }
      setWaterfallTotal(current);
    }, 22);
    return () => clearInterval(interval);
  }, []);

  const replayExplainFlow = useCallback(() => {
    setFlow1State('idle');
    setTimeout(() => setFlow1State('hold'), 100);
  }, []);

  // 7. Policy Lab logic
  const getLabOutcome = () => {
    const { taint, pre, rules, base } = layerSwitches;
    if (pre && taint) {
      return {
        type: 'hold' as const,
        recordsRead: 0,
        recordsLeft: 0,
        stoppedAt: 'read',
        title: 'Held at the database read',
        desc: 'The session was tainted and the task never mentioned salary or SSN, so the read never ran.',
        msgCls: 'ok',
      };
    }
    if (taint) {
      return {
        type: 'block' as const,
        recordsRead: 3,
        recordsLeft: 0,
        stoppedAt: 'send',
        title: 'Email blocked',
        desc: 'Three rows were read, then a tainted session was stopped from sending them to an unapproved address.',
        msgCls: 'ok',
      };
    }
    if (rules) {
      return {
        type: 'block' as const,
        recordsRead: 3,
        recordsLeft: 0,
        stoppedAt: 'send',
        title: 'Email blocked',
        desc: 'The domain rule blocked ext-hiring.com. A lookalike of an approved domain would have slipped past this layer alone.',
        msgCls: 'ok',
      };
    }
    if (base) {
      return {
        type: 'block' as const,
        recordsRead: 3,
        recordsLeft: 0,
        stoppedAt: 'send',
        title: 'Email flagged',
        desc: 'The destination was never seen for this agent, so the send was held for review.',
        msgCls: 'ok',
      };
    }
    return {
      type: 'leak' as const,
      recordsRead: 3,
      recordsLeft: 3,
      stoppedAt: 'never',
      title: 'Nothing stopped it',
      desc: 'No layer objected. Payroll rows left the company.',
      msgCls: 'bad',
    };
  };

  const toggleLayer = (layerId: 'taint' | 'pre' | 'rules' | 'base') => {
    setLayerSwitches((prev) => {
      const next = { ...prev, [layerId]: !prev[layerId] };
      if (!next.taint) {
        next.pre = false;
      }
      return next;
    });
  };

  // 8. Audit Chain Tamper Demo
  const initAuditChain = useCallback(async () => {
    let p = Z0;
    const blocks: AuditChainBlock[] = [];
    for (const [tool, dec] of DEFAULT_AUDIT_EVENTS) {
      const h = await calcSha256(`${tool}|${dec}|${p}`);
      blocks.push({ tool, decision: dec, hash: h, prevHash: p });
      p = h;
    }
    setChainBlocks(blocks);
    setTamperedIdx(-1);
  }, []);

  const tamperEvent3 = useCallback(async () => {
    if (chainBlocks.length < 3) return;
    const tampered = [...chainBlocks];
    tampered[2] = { ...tampered[2], decision: 'allow' };
    setChainBlocks(tampered);

    // Verify chain and locate mismatch
    setTimeout(async () => {
      let p = Z0;
      let bad = -1;
      for (let i = 0; i < tampered.length; i++) {
        const h = await calcSha256(`${tampered[i].tool}|${tampered[i].decision}|${p}`);
        if (h !== tampered[i].hash && bad < 0) {
          bad = i;
        }
        p = h;
      }
      setTamperedIdx(bad);
    }, 400);
  }, [chainBlocks]);

  useEffect(() => {
    initAuditChain();
  }, [initAuditChain]);

  // Compute live lab outcome
  const labOutcome = getLabOutcome();

  // Filtered feed events
  const displayedFeed = showToolReturn
    ? feedLines
    : feedLines.filter((l) => !l.text.toLowerCase().includes('tool_return'));

  return (
    <>
      {/* Ambient cursor glow */}
      <div className="cursor" id="cur" aria-hidden="true" />

      {/* Top 2px scroll progress line */}
      <div id="pg" aria-hidden="true" />

      {/* 58px top hover zone for nav expansion */}
      <div
        id="hz"
        onMouseEnter={openNav}
        aria-hidden="true"
      />

      {/* Collapsible Floating Navigation */}
      <div id="nv" className={navOpen ? 'open' : ''}>
        <button
          id="hd"
          aria-label="Open navigation"
          onClick={openNav}
        >
          <i />
          <span id="hl">
            {SECTIONS.find((s) => s[0] === activeSection)?.[1] || 'Home'}
          </span>
          <s>hover · N</s>
        </button>

        <nav
          id="bar"
          aria-label="Sections"
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
          {SECTIONS.map(([secId, label], i) => (
            <button
              key={secId}
              ref={(el) => {
                buttonsRef.current[secId] = el;
              }}
              data-id={secId}
              className={activeSection === secId ? 'on' : ''}
              style={{ '--i': i } as React.CSSProperties}
              onClick={() => jumpTo(secId)}
            >
              {label}
              <kbd>{i + 1}</kbd>
            </button>
          ))}
        </nav>
      </div>

      {/* 1. Hero Section */}
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
          <span className="pill">
            <i />
            Autonomous, privacy-preserving security for AI agents
          </span>

          <h1>
            Every agent action, <span className="gt">inspected</span> before it happens.
          </h1>

          <p className="lead">
            AI agents read documents, query databases and send email on your behalf.
            SentinelMesh sits in the middle, rebuilds the attack chain, and stops the action
            that should never run.
          </p>

          <div className="cta">
            <a
              className="btn"
              href="#demo"
              id="go"
              onClick={(e) => {
                e.preventDefault();
                jumpTo('demo');
                setTimeout(runAttackSimulation, 800);
              }}
            >
              Watch an attack get stopped →
            </a>
            <a
              className="btn g"
              href="#how"
              onClick={(e) => {
                e.preventDefault();
                jumpTo('how');
              }}
            >
              How it works
            </a>
            <button
              className="btn g"
              onClick={() => setTourOpen(true)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
            >
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#34d399' }} />
              Guided tour (T)
            </button>
          </div>

          <div className="tick mono" id="tick">
            {tickerLines.map((line) => (
              <div key={line.id} className="ln">
                <b className={`t ${line.cls}`}>{line.badge}</b> {line.text}
              </div>
            ))}
          </div>
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

      {/* 2. Live Simulation Section */}
      <section id="demo">
        <div className="w">
          <div className="eb rv">Live simulation</div>
          <h2 className="rv">Watch a poisoned résumé try to steal payroll.</h2>
          <p className="sub rv">
            Same attack, two modes. In Monitor the agent succeeds. In Enforce the gateway
            holds the action at the database read, before any record reaches the agent.
          </p>

          <div className="con rv">
            {/* Card A: 5-step Attack Chain */}
            <div className="card A" id="chain-card">
              <div className="hd">
                <div className="seg" id="mode-seg">
                  <button
                    id="mM"
                    className={policyMode === 'monitor' ? 'on' : ''}
                    onClick={() => switchMode('monitor')}
                  >
                    Monitor
                  </button>
                  <button
                    id="mE"
                    className={policyMode === 'enforce' ? 'on' : ''}
                    onClick={() => switchMode('enforce')}
                  >
                    Enforce
                  </button>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="btn s"
                    id="run"
                    onClick={runAttackSimulation}
                    title="Simulate 5-step chain animation"
                  >
                    Run attack ▶
                  </button>
                  {stats?.demo_mode && (
                    <button
                      className="btn s g"
                      onClick={triggerRealLiveAttack}
                      disabled={liveAttackRunning}
                      title="Execute real demo agents against real gateway"
                    >
                      {liveAttackRunning ? 'Executing…' : 'Run real agent ▶'}
                    </button>
                  )}
                </div>
              </div>

              <div id="chain">
                {chainSteps.map((s, i) => (
                  <div
                    key={s.num}
                    id={`s${i}`}
                    className={`st ${stepClasses[i]} ${stepActive[i] ? 'on' : ''}`}
                  >
                    <i>{s.num}</i>
                    <div>
                      <b>{s.title}</b>
                      <small id={`d${i}`}>{s.desc}</small>
                    </div>
                  </div>
                ))}
              </div>

              <div
                id="vd"
                className={`vd ${verdict.show ? 'show' : ''} ${verdict.ok ? 'ok' : 'bad'}`}
              >
                {verdict.text}
              </div>
            </div>

            {/* Card B: Mini-mesh & Risk Gauge */}
            <div className="card B">
              <AgentMesh
                mode="console"
                canvasId="mc"
                className="w-full"
                events={events}
                attackPulseTrigger={attackPulseTrigger}
              />
              <div className="rw" id="gauge-box">
                <div className="ga">
                  <svg width="116" height="116" viewBox="0 0 116 116">
                    <circle cx="58" cy="58" r="50" stroke="var(--line)" />
                    <circle
                      className="fg"
                      id="fg"
                      cx="58"
                      cy="58"
                      r="50"
                      stroke={riskGauge > 70 ? 'var(--ro)' : riskGauge > 35 ? 'var(--am)' : 'var(--cy)'}
                      style={{
                        strokeDashoffset: 314 * (1 - riskGauge / 100),
                      }}
                    />
                  </svg>
                  <div>
                    <strong id="sc">{riskGauge}</strong>
                    <span>risk</span>
                  </div>
                </div>

                <div id="bars">
                  {SIGNAL_BARS.map(([label, color], i) => (
                    <div key={label} className="br">
                      {label}
                      <u>
                        <i
                          id={`b${i}`}
                          style={{
                            background: color,
                            width: `${barWidths[i]}%`,
                          }}
                        />
                      </u>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Card C: Terminal Feed */}
            <div className="card C mono">
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  paddingBottom: '8px',
                  borderBottom: '1px solid var(--line)',
                  marginBottom: '8px',
                  fontSize: '11px',
                }}
              >
                <span style={{ color: 'var(--mut)' }}>Live gateway event stream</span>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={showToolReturn}
                    onChange={(e) => setShowToolReturn(e.target.checked)}
                  />
                  <span>tool_return</span>
                </label>
              </div>
              <div className="fd" id="fd">
                {displayedFeed.map((line) => (
                  <div key={line.id} className="ln">
                    <b className={`t ${line.cls}`}>{line.badge}</b> {line.text}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Explain Section */}
      <section id="explain" className="xs">
        <div className="w">
          <div className="eb rv">Explain</div>
          <h2 className="rv">Why was it held? Follow the evidence.</h2>
          <p className="sub rv">
            A file marked{' '}
            <span
              className="gl"
              data-tip="Taint: once an agent reads content from outside the company, everything it does next in that session is treated with suspicion."
            >
              untrusted
            </span>{' '}
            told hr-agent to read payroll and email it out. The{' '}
            <span
              className="gl"
              data-tip="Gateway: the checkpoint every agent tool call must pass through before it runs."
            >
              gateway
            </span>{' '}
            held the read, so nothing was exposed.
          </p>

          <div className="g2 rv">
            <div className="card">
              <h3>Where the attack was cut</h3>
              <div id="f1">
                <svg
                  viewBox="0 0 640 290"
                  width="100%"
                  role="img"
                  aria-label="Data flow from untrusted file to agent, gateway, then database or email"
                >
                  <path className="pa" d="M118 150H192" />
                  <path className="pa" d="M268 150H348" />
                  <path className="pa" d="M432 150C480 150 495 70 528 70" />
                  <path className="pa" d="M432 150C480 150 495 230 528 230" />
                  <g className="nd">
                    <rect x="12" y="122" width="106" height="56" rx="14" style={{ stroke: 'var(--am)' }} />
                    <text x="65" y="146" textAnchor="middle" fontSize="11">resume.pdf</text>
                    <text x="65" y="162" textAnchor="middle" fontSize="9" style={{ fill: 'var(--am)' }}>untrusted</text>

                    <rect x="192" y="122" width="76" height="56" rx="14" />
                    <text x="230" y="154" textAnchor="middle" fontSize="11">hr-agent</text>

                    <rect
                      className="nb"
                      x="528"
                      y="42"
                      width="104"
                      height="56"
                      rx="14"
                      style={{ stroke: flow1State === 'block' || flow1State === 'leak' ? 'var(--am)' : '' }}
                    />
                    <text x="580" y="66" textAnchor="middle" fontSize="11">payroll DB</text>
                    <text className="ns" x="580" y="82" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                      {flow1State === 'hold' ? 'idle (0 exposed)' : '3 rows read'}
                    </text>

                    <rect
                      className="nm"
                      x="528"
                      y="202"
                      width="104"
                      height="56"
                      rx="14"
                      style={{ stroke: flow1State === 'leak' ? 'var(--ro)' : '' }}
                    />
                    <text x="580" y="226" textAnchor="middle" fontSize="11">outside email</text>
                    <text className="nl" x="580" y="242" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                      {flow1State === 'leak' ? '3 rows received' : 'never reached'}
                    </text>
                  </g>
                  <circle className="rg" cx="390" cy="150" r="40" />
                  <circle className="gw" cx="390" cy="150" r="40" />
                  <text x="390" y="146" textAnchor="middle" fontSize="10" style={{ fontWeight: 700 }}>SENTINEL</text>
                  <text x="390" y="160" textAnchor="middle" fontSize="9" style={{ fill: 'var(--cy)' }}>gateway</text>
                  <text
                    className="stt"
                    x="390"
                    y="214"
                    textAnchor="middle"
                    fontSize="12"
                    style={{ fontWeight: 700, fill: flow1State === 'hold' ? 'var(--gr)' : 'var(--ro)' }}
                  >
                    {flow1State === 'hold' ? 'HELD AT READ' : 'DATA LEAKED'}
                  </text>
                </svg>
              </div>
              <button className="btn g" id="rp" onClick={replayExplainFlow}>
                Replay ↻
              </button>
            </div>

            <div className="card">
              <h3>Why it scored 100 / 100</h3>
              <p>Click a row to see the evidence behind it.</p>
              <div id="wf">
                {WATERFALL_ROWS.map((row, idx) => {
                  const leftAccum = WATERFALL_ROWS.slice(0, idx).reduce((sum, r) => sum + r.weight, 0);
                  const isOpen = !!waterfallOpen[idx];
                  return (
                    <div
                      key={row.name}
                      className={`wf ${isOpen ? 'o' : ''}`}
                      onClick={() =>
                        setWaterfallOpen((prev) => ({ ...prev, [idx]: !prev[idx] }))
                      }
                    >
                      <span>{row.name}</span>
                      <div className="tr">
                        <i
                          style={{
                            left: `${leftAccum}%`,
                            width: `${row.weight}%`,
                            background: row.color,
                          }}
                        />
                      </div>
                      <b>+{row.weight}</b>
                      <div className="ev">{row.evidence}</div>
                    </div>
                  );
                })}
              </div>
              <div className="big" id="tot">
                {waterfallTotal}
              </div>
            </div>
          </div>

          <div className="g3 rv">
            <div className="card">
              <h3>What happened</h3>
              <ul>
                <li>resume.pdf was read and marked untrusted by the gateway.</li>
                <li>Page 2 hid an instruction to email payroll data.</li>
                <li>hr-agent asked for salary and ssn.</li>
                <li>The read was held before it ran.</li>
              </ul>
            </div>

            <div className="card">
              <h3>Why SentinelMesh acted</h3>
              <p>
                Three independent signals agreed: untrusted input in the session, a read the
                task never asked for, and an unapproved destination. No single signal had to be perfect.
              </p>
            </div>

            <div className="card">
              <h3>Without SentinelMesh</h3>
              <p>
                hr-agent reads three salary rows and emails them to recruiter@ext-hiring.com.
                The email is delivered, and the only trace is an ordinary tool call.
              </p>
            </div>
          </div>

          <p className="note rv">
            Illustrative incident based on the poisoned-résumé benchmark scenario. Numbers are
            simulated in this prototype.
          </p>
        </div>
      </section>

      {/* 4. Policy Lab Section */}
      <section id="lab" className="xs">
        <div className="w">
          <div className="eb rv">Policy Lab</div>
          <h2 className="rv">Turn a defense off. Replay the same attack.</h2>
          <p className="sub rv">
            Each layer is independent. Switch them and watch where the attack is stopped, or whether
            it gets through.
          </p>

          <div className="g2 rv">
            <div className="card" id="sws">
              <h3>Defense layers</h3>
              {DEFENSE_LAYERS.map((l) => {
                const isOn = layerSwitches[l.id];
                const isDis = l.id === 'pre' && !layerSwitches.taint;
                return (
                  <div
                    key={l.id}
                    className={`sw ${isOn ? 'on' : ''} ${isDis ? 'dis' : ''}`}
                    onClick={() => !isDis && toggleLayer(l.id)}
                  >
                    <div className="tg" />
                    <div>
                      <b>{l.title}</b>
                      <p>{l.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="card">
              <h3>Same attack, your configuration</h3>
              <div id="f2">
                <svg
                  viewBox="0 0 640 290"
                  width="100%"
                  role="img"
                  aria-label="Interactive policy replay flow diagram"
                >
                  <path className="pa" d="M118 150H192" />
                  <path className="pa" d="M268 150H348" />
                  <path className="pa" d="M432 150C480 150 495 70 528 70" />
                  <path className="pa" d="M432 150C480 150 495 230 528 230" />
                  <g className="nd">
                    <rect x="12" y="122" width="106" height="56" rx="14" style={{ stroke: 'var(--am)' }} />
                    <text x="65" y="146" textAnchor="middle" fontSize="11">resume.pdf</text>
                    <text x="65" y="162" textAnchor="middle" fontSize="9" style={{ fill: 'var(--am)' }}>untrusted</text>

                    <rect x="192" y="122" width="76" height="56" rx="14" />
                    <text x="230" y="154" textAnchor="middle" fontSize="11">hr-agent</text>

                    <rect
                      className="nb"
                      x="528"
                      y="42"
                      width="104"
                      height="56"
                      rx="14"
                      style={{ stroke: labOutcome.recordsRead > 0 ? 'var(--am)' : '' }}
                    />
                    <text x="580" y="66" textAnchor="middle" fontSize="11">payroll DB</text>
                    <text className="ns" x="580" y="82" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                      {labOutcome.recordsRead > 0 ? `${labOutcome.recordsRead} rows read` : 'idle'}
                    </text>

                    <rect
                      className="nm"
                      x="528"
                      y="202"
                      width="104"
                      height="56"
                      rx="14"
                      style={{ stroke: labOutcome.recordsLeft > 0 ? 'var(--ro)' : '' }}
                    />
                    <text x="580" y="226" textAnchor="middle" fontSize="11">outside email</text>
                    <text className="nl" x="580" y="242" textAnchor="middle" fontSize="9" style={{ fill: 'var(--mut)' }}>
                      {labOutcome.recordsLeft > 0 ? `${labOutcome.recordsLeft} rows sent` : 'idle'}
                    </text>
                  </g>
                  <circle className="rg" cx="390" cy="150" r="40" />
                  <circle className="gw" cx="390" cy="150" r="40" />
                  <text x="390" y="146" textAnchor="middle" fontSize="10" style={{ fontWeight: 700 }}>SENTINEL</text>
                  <text x="390" y="160" textAnchor="middle" fontSize="9" style={{ fill: 'var(--cy)' }}>gateway</text>
                  <text
                    className="stt"
                    x="390"
                    y="214"
                    textAnchor="middle"
                    fontSize="12"
                    style={{
                      fontWeight: 700,
                      fill: labOutcome.msgCls === 'ok' ? 'var(--gr)' : 'var(--ro)',
                    }}
                  >
                    {labOutcome.title.toUpperCase()}
                  </text>
                </svg>
              </div>

              <div className="stat">
                <div>
                  <b id="x1">{labOutcome.recordsRead}</b>
                  <span>records the agent read</span>
                </div>
                <div>
                  <b id="x2">{labOutcome.recordsLeft}</b>
                  <span>records that left</span>
                </div>
                <div>
                  <b id="x3">{labOutcome.stoppedAt}</b>
                  <span>stopped at</span>
                </div>
              </div>

              <div className={`msg ${labOutcome.msgCls}`} id="mg">
                {labOutcome.title}
              </div>
              <p id="tx" style={{ marginTop: '12px' }}>
                {labOutcome.desc}
              </p>
            </div>
          </div>

          <p className="note rv">
            Simplified model of the measured ablation on the project’s benchmark. Real results
            depend on the scenario.
          </p>
        </div>
      </section>

      {/* 5. Audit Section */}
      <section id="audit" className="xs">
        <div className="w">
          <div className="eb rv">Audit</div>
          <h2 className="rv">Change one row. The chain tells on you.</h2>
          <p className="sub rv">
            Every decision is linked to the one before it with SHA-256. Edit history and every later
            link fails verification.
          </p>

          <div className="card rv">
            <div className="chain" id="ch">
              {chainBlocks.map((b, i) => {
                const isBad = tamperedIdx >= 0 && i >= tamperedIdx;
                const isOk = tamperedIdx < 0;
                const decCls =
                  b.decision === 'block' || b.decision === 'denied'
                    ? 'var(--ro)'
                    : b.decision === 'held'
                    ? 'var(--am)'
                    : 'var(--gr)';

                return (
                  <React.Fragment key={`block-${i}`}>
                    <div className={`blk ${isBad ? 'bad' : isOk ? 'ok' : ''}`}>
                      <b>
                        #{i + 1} {b.tool}
                      </b>
                      <span style={{ color: decCls }}>{b.decision}</span>
                      <br />
                      hash {b.hash.slice(0, 6)}…{b.hash.slice(-4)}
                      <br />
                      prev {b.prevHash.slice(0, 6)}…{b.prevHash.slice(-4)}
                    </div>
                    {i < chainBlocks.length - 1 && <div className="lk" />}
                  </React.Fragment>
                );
              })}
            </div>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', margin: '6px 0 14px' }}>
              <button className="btn" id="tp" onClick={tamperEvent3}>
                Tamper with event 3
              </button>
              <button className="btn g" id="rs" onClick={initAuditChain}>
                Restore
              </button>
            </div>

            <div className={`msg ${tamperedIdx < 0 ? 'ok' : 'bad'}`} id="vm">
              {tamperedIdx < 0
                ? `Chain valid · ${chainBlocks.length} events verified`
                : `Hash mismatch at event ${tamperedIdx + 1}. Events ${
                    tamperedIdx + 1
                  }–${chainBlocks.length} can no longer be trusted.`}
            </div>
          </div>
        </div>
      </section>

      {/* 6. Defenses Section */}
      <section id="how">
        <div className="w">
          <div className="eb rv">Defense in depth</div>
          <h2 className="rv">Six layers. No single point of trust.</h2>
          <p className="sub rv">
            Each layer is independent, measured, and can be switched off to show what it adds.
          </p>

          <div className="bn">
            <div className="card c4 rv">
              <div className="ico">01</div>
              <h3>Taint tracking</h3>
              <p>
                Anything an agent reads from outside marks the session as untrusted, and the
                gateway assigns that label itself. A lying agent cannot clear it.
              </p>
              <div className="code">
                <span className="am">read_doc</span>(resume.pdf) → session{' '}
                <span className="ro">TAINTED</span>
                <br />
                <span className="am">send_email</span>(ext) → <span className="ro">BLOCK</span> risk 100
              </div>
            </div>

            <div className="card c2 rv">
              <div className="ico">02</div>
              <h3>Policy gateway</h3>
              <p>Allow, redact, hold for approval or block, inline.</p>
              <div className="code">
                <span className="gr">allow</span> · <span className="cy">redact</span> ·{' '}
                <span className="am">approve</span> · <span className="ro">block</span>
              </div>
            </div>

            <div className="card c2 rv">
              <div className="ico">03</div>
              <h3>Privacy vault</h3>
              <p>PII is tokenized before logging. Raw access is role-gated and audited.</p>
              <div className="code">
                [EMAIL_1] [PERSON_2]
                <br />
                [SALARY_1]
              </div>
            </div>

            <div className="card c4 rv">
              <div className="ico">04</div>
              <h3>Hash-chained audit</h3>
              <p>
                Every decision joins a tamper-evident SHA-256 chain. Change one row and
                verification fails at that exact event.
              </p>
              <div className="code">
                0000…a91f → 7c2e…b04d → 51d8…0e3a
                <br />
                <span className="gr">chain valid</span> · {stats?.total_actions || 12} events verified
              </div>
            </div>

            <div className="card c3 rv">
              <div className="ico">05</div>
              <h3>Learned baseline</h3>
              <p>
                Volume, timing and destinations are compared with each agent’s own normal behavior.
              </p>
              <div className="code">
                rows 9004 vs median 667
                <br />
                <span className="am">anomaly</span> · off-hours · new destination
              </div>
            </div>

            <div className="card c3 rv">
              <div className="ico">06</div>
              <h3>Signed approvals</h3>
              <p>
                Privileged actions need a one-time HMAC token bound to the exact action.
              </p>
              <div className="code">
                forged · expired · replayed · wrong-action
                <br />→ <span className="ro">all blocked</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 7. Results Section */}
      <section id="results" className="xs">
        <div className="w">
          <div className="eb rv">Evidence</div>
          <h2 className="rv">Empirical Benchmark Evidence & Defense Radar</h2>
          <p className="sub rv" style={{ marginBottom: '24px' }}>
            Rigorous evaluation on holdout test partitions across InjecAgent, AgentDojo, and ai4privacy with exact McNemar paired significance tests.
          </p>

          <EvidenceSection />
        </div>
      </section>

      {/* Footer */}
      <div className="w">
        <footer>
          <span>
            <b>SentinelMesh AI</b> · internship project
          </span>
          <span>Simulated data only · no real personal information</span>
        </footer>
      </div>

      {/* Guided Interactive Product Tour */}
      <TourOverlay isOpen={tourOpen} onClose={() => setTourOpen(false)} />
    </>
  );
}
export default App;
