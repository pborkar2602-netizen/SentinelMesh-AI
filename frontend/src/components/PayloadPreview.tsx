import React, { useState } from 'react';
import { Eye, EyeOff, ShieldAlert, Lock, Unlock, AlertCircle } from 'lucide-react';

interface PayloadPreviewProps {
  payload?: Record<string, any>;
  affectedData?: string;
  sessionId?: string;
  apiBase?: string;
}

const ROLE_DEMO_CREDS: Record<'privacy_officer' | 'analyst' | 'viewer', { username: string; password: string }> = {
  privacy_officer: { username: 'privacy_officer', password: 'officer123' },
  analyst: { username: 'analyst', password: 'analyst123' },
  viewer: { username: 'viewer', password: 'viewer123' },
};

export const PayloadPreview: React.FC<PayloadPreviewProps> = ({
  payload = {},
  affectedData = 'Confidential Enterprise Data',
  sessionId = 'sess-active',
  apiBase = '',
}) => {
  const [unmaskedPayload, setUnmaskedPayload] = useState<Record<string, any> | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedRole, setSelectedRole] = useState<'privacy_officer' | 'analyst' | 'viewer'>('privacy_officer');
  const [reason, setReason] = useState('Compliance investigation for Data Subject Access Request #DSAR-883');
  const [accessId, setAccessId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const isUnmasked = unmaskedPayload !== null;
  const displayContent = isUnmasked ? unmaskedPayload : payload;

  const handleRequestRawAccess = async () => {
    setErrorMsg(null);
    setLoading(true);
    try {
      const creds = ROLE_DEMO_CREDS[selectedRole];
      const loginRes = await fetch(`${apiBase}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(creds),
      });
      const authData = await loginRes.json();
      if (!loginRes.ok || !authData.access_token) {
        throw new Error(authData.detail || `Authentication failed with HTTP ${loginRes.status}`);
      }

      const res = await fetch(`${apiBase}/api/v1/privacy/raw-access`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authData.access_token}`,
        },
        body: JSON.stringify({
          session_id: sessionId,
          masked_payload: payload,
          reason: reason,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Access denied with HTTP ${res.status}`);
      }

      setUnmaskedPayload(data.unmasked_payload || data.resolved || payload);
      setAccessId(data.access_id);
      setIsModalOpen(false);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to request raw PII access');
    } finally {
      setLoading(false);
    }
  };

  const handleReturnToMasked = () => {
    setUnmaskedPayload(null);
    setAccessId(null);
    setErrorMsg(null);
  };

  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col h-full font-mono">
      <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
        <h2 className="text-sm font-semibold tracking-wide text-ink uppercase flex items-center gap-2">
          {isUnmasked ? <Unlock className="w-4 h-4 text-rd" /> : <Lock className="w-4 h-4 text-cy" />}
          What the agent tried to send
        </h2>
        <span
          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
            isUnmasked
              ? 'bg-rd/15 text-rd border-rd/30'
              : 'bg-cy/15 text-cy border-cy/30'
          }`}
        >
          {isUnmasked ? 'UNMASKED (PRIVACY OFFICER)' : 'MASKED SAFE VIEW'}
        </span>
      </div>

      <div className="relative flex-1 min-h-[140px] flex flex-col">
        <pre
          className={`p-3 rounded-lg border text-xs overflow-x-auto flex-1 transition-colors ${
            isUnmasked
              ? 'bg-rd/5 border-rd/40 text-rd font-mono'
              : 'bg-bg2 border-line text-ink font-mono'
          }`}
        >
          {JSON.stringify(displayContent, null, 2)}
        </pre>

        {isUnmasked && (
          <div className="mt-2 text-[10px] text-rd flex items-center gap-1.5 font-bold">
            <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
            <span>
              Cryptographic Audit Log: Access ID <strong className="underline">{accessId}</strong> recorded to immutable hash chain.
            </span>
          </div>
        )}
      </div>

      {/* Role-gated raw access dialog */}
      {isModalOpen && (
        <div className="mt-3 p-3 rounded-lg bg-bg2 border border-line flex flex-col gap-2.5 text-xs animate-in fade-in">
          <div className="flex items-center justify-between">
            <span className="font-bold text-ink">Role-Gated Raw Access Verification</span>
            <button
              onClick={() => setIsModalOpen(false)}
              className="text-mut hover:text-ink text-[11px]"
            >
              Cancel
            </button>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-[11px] text-mut w-20">Your Role:</label>
            <select
              value={selectedRole}
              onChange={(e: any) => setSelectedRole(e.target.value)}
              className="bg-bg1 border border-line text-ink rounded px-2 py-1 text-xs focus:border-cy outline-none flex-1 font-mono"
            >
              <option value="privacy_officer">privacy_officer (Authorized)</option>
              <option value="analyst">analyst (Test 403 Forbidden)</option>
              <option value="viewer">viewer (Test 403 Forbidden)</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-[11px] text-mut w-20">Reason:</label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="bg-bg1 border border-line text-ink rounded px-2 py-1 text-xs focus:border-cy outline-none flex-1 font-mono"
              placeholder="Mandatory compliance / legal justification"
            />
          </div>

          {errorMsg && (
            <div className="text-[11px] text-rd flex items-center gap-1.5 bg-rd/10 p-2 rounded border border-rd/30">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <button
            onClick={handleRequestRawAccess}
            disabled={loading}
            className="w-full py-1.5 rounded bg-rd/20 hover:bg-rd/30 text-rd border border-rd/40 font-semibold transition-all"
          >
            {loading ? 'Authorizing & Decrypting Vault...' : 'Submit & Retrieve Raw PII (Audited)'}
          </button>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between flex-wrap gap-2 pt-2 border-t border-line/60">
        <span className="text-[11px] text-mut">
          Affected Asset: <strong className="text-ink">{affectedData}</strong>
        </span>

        {isUnmasked ? (
          <button
            onClick={handleReturnToMasked}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold bg-bg2 border-line text-ink hover:border-cy transition-all"
          >
            <EyeOff className="w-3.5 h-3.5" /> Return to Masked Safe View
          </button>
        ) : (
          !isModalOpen && (
            <button
              onClick={() => setIsModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold bg-rd/10 border-rd/40 text-rd hover:bg-rd/20 transition-all shadow-[0_0_10px_rgba(229,72,77,0.15)]"
            >
              <Eye className="w-3.5 h-3.5" /> Request Raw PII (Privacy Officer)
            </button>
          )
        )}
      </div>
    </div>
  );
};
