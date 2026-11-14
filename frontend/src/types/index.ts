export type DecisionType = 'allow' | 'block' | 'would_block' | 'redact' | 'require_approval' | 'recorded';

export interface AuditEvent {
  id: number;
  trace_id: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  arguments: Record<string, any>;
  context_sources: Array<{
    source_id: string;
    source_type: string;
    is_untrusted: boolean;
    snippet?: string;
  }>;
  decision: DecisionType | string;
  reason: string;
  risk_score: number;
  risk_breakdown: Record<string, any>;
  latency_ms: number;
  timestamp: string;
  prev_hash?: string;
  event_hash?: string;
  source?: string;
  findings?: Array<{
    name: string;
    severity: string;
    evidence: string;
    owasp_category: string;
  }>;
}

export interface Agent {
  id: string;
  name: string;
  role: string;
  declared_purpose: string;
  allowed_tools: string[];
  created_at: string;
}

export interface ChainStep {
  step?: number;
  step_number?: number;
  tool_name: string;
  title: string;
  icon?: string;
  arguments?: Record<string, any>;
  decision: string;
  status?: string;
  risk_score?: number;
  reason?: string;
  description?: string;
  details?: string;
  latency_ms?: number;
  timestamp: string;
}

export interface Incident {
  id: string;
  session_id: string;
  agent_id: string;
  title: string;
  status: 'BLOCKED' | 'WOULD_BLOCK' | 'OPEN' | string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | string;
  entry_point: string;
  affected_data: string;
  final_decision: string;
  risk_score: number;
  risk_breakdown: Record<string, any>;
  summary: string;
  chain_steps: ChainStep[];
  created_at: string;
}

export interface AuditVerification {
  valid: boolean;
  events_verified: number;
  head_hash: string;
  tampered_event_id: number | null;
  message: string;
}

export interface ApprovalRequest {
  id: string;
  trace_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  masked_arguments: Record<string, any>;
  action_hash: string;
  status: 'pending' | 'approved' | 'denied' | 'timed_out';
  reason?: string;
  reasons?: string[];
  risk_score: number;
  expires_at: string;
  resolved_by?: string;
  resolution_reason?: string;
  resolved_at?: string;
  created_at: string;
}

export interface SimulationStats {
  current_mode: string;
  total_events: number;
  would_block_count: number;
  block_count: number;
  blocked_count?: number;
  require_approval_count: number;
  redact_count: number;
  redacted_count?: number;
  allow_count: number;
  allowed_count?: number;
}

export interface DashboardStats {
  total_actions: number;
  total_audit_events: number;
  tool_return_events: number;
  allowed_actions: number;
  blocked_actions: number;
  would_block_actions: number;
  held_for_approval_actions: number;
  redacted_actions: number;
  pending_approvals: number;
  total_approvals: number;
  active_incidents: number;
  blocked_incidents: number;
  active_agents: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  latency_mean_ms: number | null;
  chain_verification: AuditVerification;
  policy_mode: 'enforce' | 'monitor';
  demo_mode: boolean;
}
