import { useState, useEffect, useCallback, useRef } from 'react';
import { AuditEvent } from '../types';
import { TickerLine } from '../pages/OverviewPage';

function formatRelativeTime(isoString: string): string {
  const diffSec = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  return `${Math.floor(diffSec / 3600)}h ago`;
}

interface UseGatewayEventsOptions {
  onAuditEvent?: (ev: AuditEvent) => void;
}

export function useGatewayEvents({ onAuditEvent }: UseGatewayEventsOptions = {}) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [feedLines, setFeedLines] = useState<TickerLine[]>([]);
  const [tickerLines, setTickerLines] = useState<TickerLine[]>([]);
  const [attackPulseTrigger, setAttackPulseTrigger] = useState<{ blocked: boolean; seq: number } | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const onAuditEventRef = useRef(onAuditEvent);

  useEffect(() => {
    onAuditEventRef.current = onAuditEvent;
  }, [onAuditEvent]);

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
            rawEvent: ev,
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

  // WebSocket Live Connection
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${wsProto}://${window.location.host}/ws/events`);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'AUDIT_EVENT') {
              const ev: AuditEvent = msg.data || msg;
              if (!ev || !ev.tool_name) return;

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

              const newLine: TickerLine = {
                id: `ws-${Date.now()}-${Math.random()}`,
                badge: b,
                cls,
                text: `${callText} (${formatRelativeTime(ev.timestamp)}${ev.latency_ms ? ` · ${ev.latency_ms.toFixed(1)}ms` : ''})`,
                rawEvent: ev,
              };

              setFeedLines((prev) => [newLine, ...prev.slice(0, 11)]);
              setTickerLines((prev) => [newLine, ...prev.slice(0, 3)]);

              if (dec === 'block' || dec === 'would_block') {
                setAttackPulseTrigger({ blocked: true, seq: Date.now() });
              } else if (dec === 'allow') {
                setAttackPulseTrigger({ blocked: false, seq: Date.now() });
              }

              // Notify runtime consumer
              if (onAuditEventRef.current) {
                onAuditEventRef.current(ev);
              }
            }
          } catch {
            // Ignore malformed socket frames
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connect, 3500);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connect, 3500);
      }
    };

    connect();
    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  return {
    events,
    feedLines,
    tickerLines,
    attackPulseTrigger,
    wsConnected,
    fetchEvents,
  };
}
