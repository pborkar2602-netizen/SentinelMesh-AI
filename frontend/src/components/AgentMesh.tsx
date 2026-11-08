import React, { useEffect, useRef } from 'react';
import { AuditEvent } from '../types';

interface AgentMeshProps {
  latestEvent?: AuditEvent | null;
}

export const AgentMesh: React.FC<AgentMeshProps> = ({ latestEvent }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const packetsRef = useRef<any[]>([]);
  const sparksRef = useRef<any[]>([]);
  const nodesRef = useRef<any[]>([]);

  const colors = {
    cy: '#4fb3c7',
    vi: '#7f8fd6',
    rd: '#e5484d',
    am: '#d9a441',
    gr: '#3fb68b',
    mut: '#8a94a3',
    ink: '#e6eaf0',
    line: '#262d39',
  };

  // 1. React to real WebSocket events by launching real packets across mesh
  useEffect(() => {
    if (!latestEvent || nodesRef.current.length === 0) return;

    const nodes = nodesRef.current;
    const packets = packetsRef.current;
    const sparks = sparksRef.current;

    // Find source node matching agent_id or primary
    const srcNode = nodes.find((n) => n.name === latestEvent.agent_id) || nodes[0];
    let dstNode = nodes[nodes.length - 1]; // default external sink

    if (latestEvent.tool_name === 'db_query') {
      // route to internal data store node
      dstNode = nodes[1] || nodes[0];
    } else if (latestEvent.tool_name === 'read_doc') {
      // route from document node to agent
      dstNode = srcNode;
    }

    const decision = latestEvent.decision;
    const packetColor =
      decision === 'block'
        ? colors.rd
        : decision === 'would_block'
        ? colors.am
        : decision === 'redact'
        ? colors.vi
        : colors.cy;

    srcNode.hot = 1;

    packets.push({
      a: srcNode,
      b: dstNode,
      t: 0,
      speed: 0.02,
      color: packetColor,
      isBlocked: decision === 'block',
      onComplete: () => {
        dstNode.hot = 1;
        if (decision === 'block') {
          // Trigger explosion sparks at intercept point
          for (let i = 0; i < 24; i++) {
            const angle = Math.random() * 6.28;
            const speed = 1 + Math.random() * 3;
            sparks.push({
              x: dstNode.x,
              y: dstNode.y,
              vx: Math.cos(angle) * speed,
              vy: Math.sin(angle) * speed,
              life: 1,
              color: colors.rd,
            });
          }
        }
      },
    });
  }, [latestEvent]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    let width = 0;
    let height = 0;

    const nodes = nodesRef.current;
    const packets = packetsRef.current;
    const sparks = sparksRef.current;
    const agentNames = ['hr-agent', 'finance-agent', 'support-agent', 'code-agent', 'ops-agent'];

    const resize = () => {
      const rect = canvas.parentElement?.getBoundingClientRect();
      width = rect?.width || 400;
      height = rect?.height || 360;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // Re-init nodes if empty
      if (nodes.length === 0) {
        for (let i = 0; i < 18; i++) {
          nodes.push({
            x: Math.random() * width,
            y: 35 + Math.random() * (height - 50),
            vx: (Math.random() - 0.5) * 0.15,
            vy: (Math.random() - 0.5) * 0.15,
            name: i < 5 ? agentNames[i] : null,
            hot: 0,
          });
        }
        // Fixed primary agent node
        nodes[0].x = width * 0.18;
        nodes[0].y = height * 0.52;
        nodes[0].fx = true;

        // Fixed external destination node
        nodes.push({
          x: width * 0.84,
          y: height * 0.52,
          vx: 0,
          vy: 0,
          name: 'external sink',
          isExternal: true,
          fx: true,
          hot: 0,
        });
      }
    };

    resize();
    window.addEventListener('resize', resize);

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Update nodes
      nodes.forEach((n) => {
        if (!n.fx) {
          n.x += n.vx;
          n.y += n.vy;
          if (n.x < 10 || n.x > width - 10) n.vx *= -1;
          if (n.y < 30 || n.y > height - 10) n.vy *= -1;
        }
        n.hot *= 0.95;
      });

      // Draw mesh links
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist < 110) {
            ctx.globalAlpha = (1 - dist / 110) * 0.25;
            ctx.strokeStyle = colors.cy;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // External exfiltration dashed line
      if (nodes.length > 1) {
        const primary = nodes[0];
        const ext = nodes[nodes.length - 1];
        ctx.globalAlpha = 0.3;
        ctx.setLineDash([4, 6]);
        ctx.strokeStyle = colors.am;
        ctx.beginPath();
        ctx.moveTo(primary.x, primary.y);
        ctx.lineTo(ext.x, ext.y);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      ctx.globalAlpha = 1;

      // Update & draw real event packets
      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i];
        p.t += p.speed;
        const x = p.a.x + (p.b.x - p.a.x) * p.t;
        const y = p.a.y + (p.b.y - p.a.y) * p.t;

        if (p.t >= 1) {
          if (p.onComplete) p.onComplete();
          packets.splice(i, 1);
          continue;
        }

        // Draw packet glowing dot
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(x, y, 3.5, 0, 6.28);
        ctx.fill();
      }

      // Update & draw sparks
      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx;
        s.y += s.vy;
        s.life -= 0.035;
        if (s.life <= 0) {
          sparks.splice(i, 1);
          continue;
        }
        ctx.globalAlpha = s.life;
        ctx.fillStyle = s.color;
        ctx.fillRect(s.x, s.y, 2.5, 2.5);
      }
      ctx.globalAlpha = 1;

      // Draw nodes
      nodes.forEach((n) => {
        const isExt = n.isExternal;
        const r = isExt ? 6 : n.name ? 5 : 3;

        // Outer glow on hot / active event
        if (n.hot > 0.05) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + 8 * n.hot, 0, 6.28);
          ctx.fillStyle = isExt ? 'rgba(229,72,77,0.2)' : 'rgba(79,179,199,0.25)';
          ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 6.28);
        ctx.fillStyle = isExt ? colors.rd : n.name ? colors.cy : colors.mut;
        ctx.fill();

        // Node label
        if (n.name) {
          ctx.font = '10px monospace';
          ctx.fillStyle = colors.ink;
          ctx.fillText(n.name, n.x - 20, n.y - 10);
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="bg-bg1 rounded-xl border border-line p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cy" />
          <h3 className="font-semibold text-sm text-ink font-sans">Real-time Agent Mesh</h3>
        </div>
        <span className="text-[11px] font-mono text-mut">Event-Driven Topology</span>
      </div>
      <div className="flex-1 w-full relative min-h-[300px]">
        <canvas ref={canvasRef} className="w-full h-full block rounded-lg bg-bg0/60" />
      </div>
    </div>
  );
};
