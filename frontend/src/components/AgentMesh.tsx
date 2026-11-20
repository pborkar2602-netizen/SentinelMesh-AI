import React, { useEffect, useRef } from 'react';
import { AuditEvent } from '../types';

interface AgentMeshProps {
  mode: 'hero' | 'console';
  events?: AuditEvent[];
  attackPulseTrigger?: { blocked: boolean; seq: number } | null;
  className?: string;
  canvasId?: string;
}

interface MeshNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  n: string | null;
  h: number;
  f?: number;
  e?: number;
}

interface MeshPacket {
  a: MeshNode;
  b: MeshNode;
  t: number;
  s: number;
  c: string;
  k?: number;
  bl?: boolean;
}

interface MeshSpark {
  x: number;
  y: number;
  vx: number;
  vy: number;
  l: number;
}

const AGENT_NAMES = ['hr-agent', 'finance-agent', 'support-agent', 'code-agent', 'ops-agent'];

export const AgentMesh: React.FC<AgentMeshProps> = ({
  mode,
  events = [],
  attackPulseTrigger,
  className = '',
  canvasId,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const triggerActionRef = useRef<((bl: boolean) => void) | null>(null);
  const lastEventIdRef = useRef<number | null>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const cx = cv.getContext('2d');
    if (!cx) return;

    const D = Math.min(window.devicePixelRatio || 1, 2);
    const isHero = mode === 'hero';

    // Density rule parameters
    // Hero: count = clamp(round(width * height / 3900), 90, 600)
    // Console: 30 nodes, labelled agents
    const o = isHero
      ? { n: 90, m: 1, d: 3900, max: 600, l: 0 }
      : { n: 30, m: 0, d: 0, max: 30, l: 1 };

    let W = 0;
    let H = 0;
    let N: MeshNode[] = [];
    let P: MeshPacket[] = [];
    let S: MeshSpark[] = [];
    let on = true;
    let rafId = 0;

    const getColors = () => {
      const g = (prop: string) =>
        getComputedStyle(document.documentElement).getPropertyValue(prop).trim();
      return {
        cy: g('--cy') || '#38e8ff',
        vi: g('--vi') || '#8b5cff',
        ro: g('--ro') || '#ff4d8d',
        am: g('--am') || '#ffb84d',
        gr: g('--gr') || '#3dffb0',
        mut: g('--mut') || '#8b93ad',
        ink: g('--ink') || '#eaf0ff',
      };
    };

    let K = getColors();

    const init = () => {
      K = getColors();
      const r = cv.getBoundingClientRect();
      W = r.width;
      H = r.height;
      cv.width = W * D;
      cv.height = H * D;
      cx.setTransform(D, 0, 0, D, 0, 0);
      N = [];

      // Density rule: count = clamp(round(width * height / 3900), 90, 600)
      const cnt = o.d
        ? Math.min(o.max || 600, Math.max(o.n, Math.round((W * H) / o.d)))
        : o.n;

      for (let i = 0; i < cnt; i++) {
        const hasLabel = Boolean(o.l && i < 5);
        const minX = hasLabel ? 20 : 0;
        const maxX = hasLabel ? Math.max(minX + 40, W - 120) : W;
        const minY = hasLabel ? 18 : 0;
        const maxY = hasLabel ? Math.max(minY + 30, H - 18) : H;
        N.push({
          x: minX + Math.random() * Math.max(1, maxX - minX),
          y: minY + Math.random() * Math.max(1, maxY - minY),
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          n: hasLabel ? AGENT_NAMES[i] : null,
          h: 0,
        });
      }

      if (o.l) {
        N[0].x = Math.max(24, W * 0.14);
        N[0].y = H * 0.5;
        N[0].f = 1;
        N.push({
          x: Math.max(120, Math.min(W * 0.84, W - 84)),
          y: H * 0.5,
          vx: 0,
          vy: 0,
          f: 1,
          e: 1,
          n: 'external',
          h: 0,
        });
      }

      // Store stats on canvas / window for verification
      const densityPer100k = W * H > 0 ? (N.length / (W * H)) * 100000 : 0;
      (cv as any).__meshStats = {
        nodeCount: N.length,
        width: W,
        height: H,
        area: W * H,
        densityPer100k,
      };
      if (isHero) {
        (window as any).__heroMeshStats = (cv as any).__meshStats;
      }
    };

    const burst = (x: number, y: number) => {
      for (let i = 0; i < 30; i++) {
        const a = Math.random() * 6.28;
        const s = 1 + Math.random() * 3;
        S.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s, l: 1 });
      }
    };

    const io = new IntersectionObserver((entries) => {
      on = entries[0].isIntersecting;
    });
    io.observe(cv);

    // Track mouse position
    const mp = { x: -9999, y: -9999 };
    const onPointerMove = (e: PointerEvent) => {
      mp.x = e.clientX;
      mp.y = e.clientY;
    };
    window.addEventListener('pointermove', onPointerMove, { passive: true });

    let lastFrameTime = performance.now();
    let frameTimes: number[] = [];

    const fr = () => {
      rafId = requestAnimationFrame(fr);
      if (!on) return;

      const now = performance.now();
      const dt = now - lastFrameTime;
      lastFrameTime = now;
      if (frameTimes.length > 60) frameTimes.shift();
      frameTimes.push(dt);
      if (isHero) {
        const avgDt = frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length;
        (window as any).__measuredFrameTimeMs = avgDt;
        (window as any).__measuredFps = avgDt > 0 ? 1000 / avgDt : 60;
      }

      cx.clearRect(0, 0, W, H);
      const r = cv.getBoundingClientRect();
      const mx = mp.x - r.left;
      const my = mp.y - r.top;
      const L = N.length;

      // Update positions
      for (const n of N) {
        if (!n.f) {
          n.x += n.vx;
          n.y += n.vy;
          const minX = o.l && n.n ? 14 : 0;
          const maxX = o.l && n.n ? Math.max(minX + 40, W - 115) : W;
          const minY = o.l && n.n ? 16 : 0;
          const maxY = o.l && n.n ? Math.max(minY + 20, H - 16) : H;
          if (n.x < minX) {
            n.x = minX;
            n.vx = Math.abs(n.vx);
          } else if (n.x > maxX) {
            n.x = maxX;
            n.vx = -Math.abs(n.vx);
          }
          if (n.y < minY) {
            n.y = minY;
            n.vy = Math.abs(n.vy);
          } else if (n.y > maxY) {
            n.y = maxY;
            n.vy = -Math.abs(n.vy);
          }
          if (o.m) {
            const dx = n.x - mx;
            const dy = n.y - my;
            const d = Math.hypot(dx, dy);
            if (d < 170 && d > 1) {
              const f = (170 - d) / 170;
              n.x += (dx / d) * f * 2.4;
              n.y += (dy / d) * f * 2.4;
            }
          }
        }
        n.h *= 0.96;
      }

      // Draw links using spatial grid
      cx.lineWidth = 1;
      cx.strokeStyle = K.cy;
      const CS = o.m ? 135 : 120;
      const G: Record<string, number[]> = {};
      for (let i = 0; i < L; i++) {
        const n = N[i];
        const k = ((n.x / CS) | 0) + ',' + ((n.y / CS) | 0);
        (G[k] = G[k] || []).push(i);
      }

      for (let i = 0; i < L; i++) {
        const a = N[i];
        const gx = (a.x / CS) | 0;
        const gy = (a.y / CS) | 0;
        for (let ox = -1; ox <= 1; ox++) {
          for (let oy = -1; oy <= 1; oy++) {
            const c = G[gx + ox + ',' + (gy + oy)];
            if (!c) continue;
            for (const j of c) {
              if (j <= i) continue;
              const b = N[j];
              const d = Math.hypot(a.x - b.x, a.y - b.y);
              if (d < CS) {
                cx.globalAlpha = (1 - d / 135) * 0.5;
                cx.beginPath();
                cx.moveTo(a.x, a.y);
                cx.lineTo(b.x, b.y);
                cx.stroke();
              }
            }
          }
        }
      }

      // Link to cursor
      if (o.m) {
        for (const n of N) {
          const d = Math.hypot(n.x - mx, n.y - my);
          if (d < 190) {
            cx.globalAlpha = (1 - d / 190) * 0.9;
            cx.strokeStyle = K.ro;
            cx.beginPath();
            cx.moveTo(n.x, n.y);
            cx.lineTo(mx, my);
            cx.stroke();
          }
        }
      }

      // Spawn idle packets scaled with node count
      for (let k = 0, mk = Math.max(1, Math.round(L / 90)); k < mk; k++) {
        if (Math.random() < 0.12) {
          const a = N[Math.floor(Math.random() * L)];
          const b = N.find((z) => z !== a && Math.hypot(a.x - z.x, a.y - z.y) < 135);
          if (b) {
            P.push({
              a,
              b,
              t: 0,
              s: 0.02 + Math.random() * 0.02,
              c: K.vi,
            });
          }
        }
      }

      // Update packets
      for (let i = P.length - 1; i >= 0; i--) {
        const p = P[i];
        p.t += p.s;
        const x = p.a.x + (p.b.x - p.a.x) * p.t;
        const y = p.a.y + (p.b.y - p.a.y) * p.t;

        if (p.k && p.bl && p.t > 0.5) {
          burst(x, y);
          if (N[0]) N[0].h = 1;
          P.splice(i, 1);
          continue;
        }

        if (p.t >= 1) {
          if (p.k) {
            burst(p.b.x, p.b.y);
            p.b.h = 1;
          }
          P.splice(i, 1);
          continue;
        }

        cx.globalAlpha = 1;
        cx.fillStyle = p.c;
        cx.shadowColor = p.c;
        cx.shadowBlur = p.k ? 20 : 9;
        cx.beginPath();
        cx.arc(x, y, p.k ? 4.5 : 2.2, 0, 6.28);
        cx.fill();
        cx.shadowBlur = 0;
      }

      // Update sparks
      for (let i = S.length - 1; i >= 0; i--) {
        const s = S[i];
        s.x += s.vx;
        s.y += s.vy;
        s.l -= 0.03;
        if (s.l <= 0) {
          S.splice(i, 1);
          continue;
        }
        cx.globalAlpha = s.l;
        cx.fillStyle = K.ro;
        cx.fillRect(s.x, s.y, 2.6, 2.6);
      }

      // Draw nodes
      cx.globalAlpha = 1;
      cx.font = '11px "JetBrains Mono"';
      for (const n of N) {
        const big = n.n;
        const c = n.e ? K.ro : big ? K.cy : K.mut;
        cx.fillStyle = c;
        cx.shadowColor = c;
        cx.shadowBlur = big ? 14 : 0;
        cx.beginPath();
        cx.arc(n.x, n.y, big ? 5 : 2, 0, 6.28);
        cx.fill();
        cx.shadowBlur = 0;

        // Expanding ring on hit
        if (n.h > 0.05) {
          cx.strokeStyle = K.ro;
          cx.lineWidth = 2;
          cx.globalAlpha = n.h;
          cx.beginPath();
          cx.arc(n.x, n.y, 6 + (1 - n.h) * 36, 0, 6.28);
          cx.stroke();
          cx.lineWidth = 1;
          cx.globalAlpha = 1;
        }

        if (big) {
          const label = n.n || '';
          const tw = cx.measureText(label).width;
          const labelX = n.x + 12 + tw > W - 8 ? Math.max(8, n.x - 9 - tw) : n.x + 9;
          const labelY = Math.max(14, Math.min(H - 8, n.y + 4));
          cx.fillStyle = K.ink;
          cx.globalAlpha = 0.85;
          cx.fillText(label, labelX, labelY);
          cx.globalAlpha = 1;
        }
      }
    };

    init();
    fr();
    window.addEventListener('resize', init);

    // Attack trigger dispatcher
    const atk = (bl: boolean) => {
      if (N.length >= 2) {
        const targetNode = N[N.length - 1]; // external or last node
        P.push({
          a: N[0],
          b: targetNode,
          t: 0,
          s: 0.013,
          k: 1,
          bl,
          c: K.ro,
        });
      }
    };
    triggerActionRef.current = atk;

    return () => {
      cancelAnimationFrame(rafId);
      io.disconnect();
      window.removeEventListener('resize', init);
      window.removeEventListener('pointermove', onPointerMove);
    };
  }, [mode]);

  // Handle explicit attack pulse triggers
  useEffect(() => {
    if (attackPulseTrigger && triggerActionRef.current) {
      triggerActionRef.current(attackPulseTrigger.blocked);
    }
  }, [attackPulseTrigger]);

  // Handle live incoming events driving packets on top
  useEffect(() => {
    if (!events || events.length === 0) return;
    const latest = events[0];
    if (latest && latest.id !== lastEventIdRef.current) {
      lastEventIdRef.current = latest.id;
      if (triggerActionRef.current) {
        const decision = (latest.decision || '').toLowerCase();
        if (decision === 'block' || decision === 'would_block') {
          triggerActionRef.current(true);
        } else if (decision === 'allow') {
          triggerActionRef.current(false);
        }
      }
    }
  }, [events]);

  return (
    <canvas
      id={canvasId}
      ref={canvasRef}
      className={className}
      style={{
        display: 'block',
        width: '100%',
        height: mode === 'console' ? '230px' : '100%',
      }}
    />
  );
};
