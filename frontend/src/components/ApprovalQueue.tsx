import React, { useState, useEffect } from 'react';
import { ApprovalRequest } from '../types';

let inMemoryJwtToken: string | null = null;

interface ApprovalQueueProps {
  onApprovalResolved?: () => void;
}

function formatRelativeTime(isoString: string): string {
  const diffSec = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  return `${Math.floor(diffSec / 3600)}h ago`;
}

export const ApprovalQueue: React.FC<ApprovalQueueProps> = ({ onApprovalResolved }) => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [filter, setFilter] = useState<'pending' | 'all'>('pending');
  const [loading, setLoading] = useState(true);
  const [resolvingLoading, setResolvingLoading] = useState(false);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [resolveReason, setResolveReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>('appr-vendor-5521');

  const fetchApprovals = async () => {
    try {
      const url =
        filter === 'pending'
          ? '/api/v1/approvals?status=pending&exclude_benchmark=true'
          : '/api/v1/approvals?exclude_benchmark=true';
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setApprovals(data);
      }
    } catch (err) {
      console.error('Failed to fetch approvals:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, 3000);
    return () => clearInterval(interval);
  }, [filter]);

  const handleResolve = async (approvalId: string, decision: 'approve' | 'deny') => {
    setResolvingLoading(true);
    setError(null);
    try {
      let token = inMemoryJwtToken;
      if (!token) {
        const loginRes = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'analyst', password: 'analyst123' }),
        });
        if (loginRes.ok) {
          const authData = await loginRes.json();
          token = authData.access_token;
          inMemoryJwtToken = token;
        }
      }

      const res = await fetch(`/api/v1/approvals/${approvalId}/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          decision,
          reason:
            resolveReason ||
            (decision === 'approve'
              ? 'Authorized by Security Analyst after out-of-band vendor verification'
              : 'Denied by Security Analyst: unverified vendor bank account change from tainted invoice note'),
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to resolve approval');
      }

      setResolvingId(null);
      setResolveReason('');
      await fetchApprovals();
      if (onApprovalResolved) onApprovalResolved();
    } catch (err: any) {
      setError(err.message || 'Error resolving approval request');
    } finally {
      setResolvingLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <span className="t-badge am">PENDING REVIEW</span>;
      case 'approved':
        return <span className="t-badge gr">APPROVED</span>;
      case 'denied':
        return <span className="t-badge ro">DENIED</span>;
      case 'timed_out':
        return <span className="t-badge cy">TIMED OUT</span>;
      default:
        return <span className="t-badge cy">{status}</span>;
    }
  };

  const pendingCount = approvals.filter((a) => a.status === 'pending').length;

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="hd">
          <div>
            <div className="eb">Signed Human-in-the-Loop Gate</div>
            <h2 className="sec-title" style={{ fontSize: 'clamp(24px, 3vw, 36px)' }}>
              Privileged actions held for SecOps review.
            </h2>
            <p className="text-sm text-mut mt-2 max-w-2xl">
              Every privileged or tainted state-changing action is cryptographically hashed (SHA-256) and held until a human reviewer issues a one-time, action-bound HMAC token. Forged, expired, or replayed tokens are blocked at the gateway.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <span className="t-badge am">{pendingCount} PENDING</span>
            <div className="seg">
              <button
                className={filter === 'pending' ? 'on' : ''}
                onClick={() => setFilter('pending')}
              >
                Pending ({pendingCount})
              </button>
              <button
                className={filter === 'all' ? 'on' : ''}
                onClick={() => setFilter('all')}
              >
                All History
              </button>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3.5 text-xs rounded-xl border border-ro bg-ro/10 text-ro font-mono">
            {error}
          </div>
        )}

        {loading ? (
          <div className="space-y-3 py-4">
            <div className="skeleton h-20 w-full" />
            <div className="skeleton h-20 w-full" />
          </div>
        ) : approvals.length === 0 ? (
          <div className="py-12 text-center border border-line rounded-2xl bg-bg/40">
            <div className="font-display text-lg text-ink mb-1">
              Zero {filter === 'pending' ? 'pending' : ''} approvals in queue
            </div>
            <p className="text-xs text-mut max-w-md mx-auto">
              All sensitive vendor bank changes and tainted write operations have been reviewed. Switch to "All History" or reset the demo seed to inspect the vendor bank change request.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line text-mut uppercase tracking-wider text-[11px] font-mono">
                  <th className="py-3 px-3">Request / Agent</th>
                  <th className="py-3 px-3">Intercepted Tool</th>
                  <th className="py-3 px-3">Risk & Escalation Reason</th>
                  <th className="py-3 px-3">Status & TTL</th>
                  <th className="py-3 px-3 text-right">SecOps Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line font-mono">
                {approvals.map((req) => {
                  const reasonText =
                    (req.reasons && req.reasons.length > 0 && req.reasons[0]) ||
                    req.reason ||
                    'Tainted sensitive write held for human verification';
                  return (
                    <React.Fragment key={req.id}>
                      <tr className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-4 px-3 align-top">
                          <div className="font-semibold text-cy">{req.id}</div>
                          <div className="text-ink font-sans font-semibold mt-0.5">{req.agent_id}</div>
                          <div className="text-[11px] text-mut mt-0.5">
                            {formatRelativeTime(req.created_at)}
                          </div>
                        </td>
                        <td className="py-4 px-3 align-top">
                          <span className="t-badge cy">{req.tool_name}</span>
                          <button
                            onClick={() => setExpandedId(expandedId === req.id ? null : req.id)}
                            className="block mt-2 text-[11px] text-cy hover:underline font-sans font-semibold"
                          >
                            {expandedId === req.id ? '▾ Hide Masked Payload' : '▸ Inspect Masked Payload'}
                          </button>
                        </td>
                        <td className="py-4 px-3 max-w-md font-sans align-top">
                          <div className="flex items-center gap-2 mb-1.5">
                            <span className={`t-badge ${req.risk_score >= 70 ? 'ro' : 'am'}`}>
                              RISK {req.risk_score}/100
                            </span>
                            <span className="text-[11px] font-mono text-mut">
                              trace: {req.trace_id}
                            </span>
                          </div>
                          <div className="text-ink text-xs leading-relaxed">{reasonText}</div>
                        </td>
                        <td className="py-4 px-3 align-top">
                          {getStatusBadge(req.status)}
                          {req.status === 'pending' && (
                            <div className="text-[11px] text-mut mt-1.5">
                              Default-deny TTL: {new Date(req.expires_at).toLocaleTimeString()}
                            </div>
                          )}
                        </td>
                        <td className="py-4 px-3 text-right align-top">
                          {req.status === 'pending' ? (
                            <div className="flex items-center justify-end gap-2 font-sans">
                              {resolvingId === req.id ? (
                                <div className="flex flex-col gap-2 items-end bg-bg/80 p-3 rounded-xl border border-line">
                                  <input
                                    type="text"
                                    placeholder="Audit justification..."
                                    value={resolveReason}
                                    onChange={(e) => setResolveReason(e.target.value)}
                                    className="px-3 py-1.5 bg-bg border border-line text-ink rounded-lg text-xs w-56 focus:border-cy outline-none"
                                  />
                                  <div className="flex gap-2">
                                    <button
                                      disabled={resolvingLoading}
                                      onClick={() => handleResolve(req.id, 'approve')}
                                      className="px-3 py-1 rounded-full bg-gr/20 border border-gr text-gr text-xs font-bold hover:bg-gr/30"
                                    >
                                      Issue Signed Token
                                    </button>
                                    <button
                                      disabled={resolvingLoading}
                                      onClick={() => handleResolve(req.id, 'deny')}
                                      className="px-3 py-1 rounded-full bg-ro/20 border border-ro text-ro text-xs font-bold hover:bg-ro/30"
                                    >
                                      Confirm Deny
                                    </button>
                                    <button
                                      onClick={() => setResolvingId(null)}
                                      className="px-2.5 py-1 rounded-full border border-line text-mut text-xs"
                                    >
                                      Cancel
                                    </button>
                                  </div>
                                </div>
                              ) : (
                                <>
                                  <button
                                    onClick={() => {
                                      setResolvingId(req.id);
                                      setResolveReason('');
                                    }}
                                    className="px-3.5 py-1.5 rounded-full bg-gr/15 hover:bg-gr/25 text-gr border border-gr/40 text-xs font-bold transition-all"
                                  >
                                    Approve
                                  </button>
                                  <button
                                    onClick={() => {
                                      setResolvingId(req.id);
                                      setResolveReason('');
                                    }}
                                    className="px-3.5 py-1.5 rounded-full bg-ro/15 hover:bg-ro/25 text-ro border border-ro/40 text-xs font-bold transition-all"
                                  >
                                    Deny
                                  </button>
                                </>
                              )}
                            </div>
                          ) : (
                            <div className="text-[11px] text-mut font-sans">
                              {req.resolved_by && (
                                <div>
                                  By: <strong className="text-ink">{req.resolved_by}</strong>
                                </div>
                              )}
                              {req.resolution_reason && (
                                <div className="text-mut mt-0.5 max-w-[200px] truncate">
                                  "{req.resolution_reason}"
                                </div>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                      {expandedId === req.id && (
                        <tr>
                          <td colSpan={5} className="p-4 bg-bg/60 border-b border-line">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[11px] text-cy font-mono uppercase tracking-wider">
                                Masked Action Arguments & Cryptographic Binding
                              </span>
                              <span className="text-[11px] text-mut font-mono">
                                SHA-256 Action Hash: {req.action_hash}
                              </span>
                            </div>
                            <pre className="code text-xs text-ink overflow-x-auto">
                              {JSON.stringify(req.masked_arguments, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
