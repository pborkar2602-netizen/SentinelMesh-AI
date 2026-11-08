import React, { useState, useEffect } from 'react';
import { ApprovalRequest } from '../types';

interface ApprovalQueueProps {
  onApprovalResolved?: () => void;
}

export const ApprovalQueue: React.FC<ApprovalQueueProps> = ({ onApprovalResolved }) => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [filter, setFilter] = useState<'pending' | 'all'>('pending');
  const [loading, setLoading] = useState(false);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [resolveReason, setResolveReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchApprovals = async () => {
    try {
      const url = filter === 'pending' ? '/api/v1/approvals?status=pending' : '/api/v1/approvals';
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setApprovals(data);
      }
    } catch (err) {
      console.error('Failed to fetch approvals:', err);
    }
  };

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, 3000);
    return () => clearInterval(interval);
  }, [filter]);

  const handleResolve = async (approvalId: string, decision: 'approve' | 'deny') => {
    setLoading(true);
    setError(null);
    try {
      // Login as analyst demo user if no token
      let token = localStorage.getItem('sentinel_jwt_token');
      if (!token) {
        const loginRes = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'analyst', password: 'analyst123' })
        });
        if (loginRes.ok) {
          const authData = await loginRes.json();
          token = authData.access_token;
          if (token) localStorage.setItem('sentinel_jwt_token', token);
        }
      }

      const res = await fetch(`/api/v1/approvals/${approvalId}/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          decision,
          reason: resolveReason || (decision === 'approve' ? 'Authorized by Security Analyst' : 'Denied by Security Analyst')
        })
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
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-900/60 text-amber-300 border border-amber-600/50 animate-pulse">Pending Review</span>;
      case 'approved':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300 border border-emerald-600/50">Approved</span>;
      case 'denied':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-900/60 text-red-300 border border-red-600/50">Denied</span>;
      case 'timed_out':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-gray-800 text-gray-400 border border-gray-700">Timed Out</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-gray-800 text-gray-300">{status}</span>;
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-gray-800 gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-wide">Human-in-the-Loop Approval Queue</h2>
            <span className="px-2 py-0.5 text-xs font-mono font-medium rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              {approvals.filter(a => a.status === 'pending').length} Pending
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Cryptographically bound tool calls requiring SecOps authorization
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFilter('pending')}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              filter === 'pending'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-gray-800 text-gray-400 hover:text-white'
            }`}
          >
            Pending
          </button>
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              filter === 'all'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-gray-800 text-gray-400 hover:text-white'
            }`}
          >
            All History
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-3 p-3 text-xs bg-red-950/70 border border-red-700 rounded-lg text-red-200">
          {error}
        </div>
      )}

      <div className="mt-4 overflow-x-auto">
        {approvals.length === 0 ? (
          <div className="py-12 text-center text-gray-500 text-sm">
            No {filter === 'pending' ? 'pending' : ''} approval requests in queue.
          </div>
        ) : (
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-3">ID / Agent</th>
                <th className="py-2.5 px-3">Tool Call</th>
                <th className="py-2.5 px-3">Risk & Reasons</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 font-mono">
              {approvals.map((req) => (
                <React.Fragment key={req.id}>
                  <tr className="hover:bg-gray-800/40 transition-colors">
                    <td className="py-3 px-3">
                      <div className="font-semibold text-cyan-400">{req.id}</div>
                      <div className="text-[11px] text-gray-400">{req.agent_id}</div>
                      <div className="text-[10px] text-gray-500">{new Date(req.created_at).toLocaleTimeString()}</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 text-xs rounded bg-purple-950/80 text-purple-300 border border-purple-800">
                        {req.tool_name}
                      </span>
                      <button
                        onClick={() => setExpandedId(expandedId === req.id ? null : req.id)}
                        className="block mt-1 text-[11px] text-gray-400 hover:text-cyan-400 underline font-sans"
                      >
                        {expandedId === req.id ? 'Hide Arguments' : 'View Masked Arguments'}
                      </button>
                    </td>
                    <td className="py-3 px-3 max-w-xs font-sans">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${
                          req.risk_score >= 70 ? 'bg-red-900/80 text-red-300' : 'bg-amber-900/80 text-amber-300'
                        }`}>
                          Risk: {req.risk_score}/100
                        </span>
                      </div>
                      <div className="text-gray-300 text-xs line-clamp-2">
                        {req.reasons && req.reasons.length > 0 ? req.reasons[0] : 'Sensitive action escalation'}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      {getStatusBadge(req.status)}
                      {req.status === 'pending' && (
                        <div className="text-[10px] text-gray-500 mt-1">
                          Expires: {new Date(req.expires_at).toLocaleTimeString()}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right">
                      {req.status === 'pending' && (
                        <div className="flex items-center justify-end gap-2 font-sans">
                          {resolvingId === req.id ? (
                            <div className="flex flex-col gap-1 items-end">
                              <input
                                type="text"
                                placeholder="Decision rationale..."
                                value={resolveReason}
                                onChange={(e) => setResolveReason(e.target.value)}
                                className="px-2 py-1 bg-gray-800 border border-gray-700 text-white rounded text-xs w-48"
                              />
                              <div className="flex gap-1">
                                <button
                                  disabled={loading}
                                  onClick={() => handleResolve(req.id, 'approve')}
                                  className="px-2 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-medium"
                                >
                                  Confirm Approve
                                </button>
                                <button
                                  disabled={loading}
                                  onClick={() => handleResolve(req.id, 'deny')}
                                  className="px-2 py-1 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-medium"
                                >
                                  Confirm Deny
                                </button>
                                <button
                                  onClick={() => setResolvingId(null)}
                                  className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs"
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          ) : (
                            <>
                              <button
                                onClick={() => { setResolvingId(req.id); setResolveReason(''); }}
                                className="px-2.5 py-1 bg-emerald-900/70 hover:bg-emerald-800 text-emerald-300 border border-emerald-700/60 rounded text-xs font-medium transition-colors"
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => { setResolvingId(req.id); setResolveReason(''); }}
                                className="px-2.5 py-1 bg-red-900/70 hover:bg-red-800 text-red-300 border border-red-700/60 rounded text-xs font-medium transition-colors"
                              >
                                Deny
                              </button>
                            </>
                          )}
                        </div>
                      )}
                      {req.status !== 'pending' && req.resolved_by && (
                        <div className="text-[11px] text-gray-500 font-sans">
                          Resolved by: <span className="text-gray-300">{req.resolved_by}</span>
                        </div>
                      )}
                    </td>
                  </tr>
                  {expandedId === req.id && (
                    <tr className="bg-gray-950/60 border-b border-gray-800/80">
                      <td colSpan={5} className="p-3">
                        <div className="text-[11px] text-gray-400 mb-1 font-mono">Masked Action Arguments Preview:</div>
                        <pre className="p-2 bg-gray-900 border border-gray-800 rounded text-[11px] text-cyan-300 font-mono overflow-x-auto">
                          {JSON.stringify(req.masked_arguments, null, 2)}
                        </pre>
                        <div className="mt-2 text-[10px] text-gray-500 font-mono">
                          Action Hash: {req.action_hash}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
