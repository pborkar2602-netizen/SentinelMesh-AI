import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Sliders, Hash, Play } from 'lucide-react';
import { AuditVerification } from '../types';

interface HeaderProps {
  connected: boolean;
  agentCount: number;
  policyMode: 'enforce' | 'monitor';
  onToggleMode: () => void;
  onRunSimulation?: () => void;
  apiBase: string;
}

export const Header: React.FC<HeaderProps> = ({
  connected,
  agentCount,
  policyMode,
  onToggleMode,
  onRunSimulation,
  apiBase,
}) => {
  const isEnforce = policyMode === 'enforce';
  const [auditInfo, setAuditInfo] = useState<AuditVerification | null>(null);
  const [verifying, setVerifying] = useState(false);

  const checkAuditChain = async () => {
    try {
      setVerifying(true);
      const res = await fetch(`${apiBase}/api/v1/audit/verify`);
      if (res.ok) {
        const data = await res.json();
        setAuditInfo(data);
      }
    } catch (err) {
      console.warn('Could not verify audit chain:', err);
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    checkAuditChain();
    const interval = setInterval(checkAuditChain, 10000);
    return () => clearInterval(interval);
  }, [apiBase]);

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-line mb-6 font-mono">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-cy/10 border border-cy/30 flex items-center justify-center text-cy">
          <ShieldCheck className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink flex items-center gap-2 font-sans">
            SentinelMesh AI
            <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-cy/15 text-cy border border-cy/30">
              Live Command Center
            </span>
          </h1>
          <p className="text-xs text-mut font-sans">Autonomous, privacy-preserving security for AI agents</p>
        </div>
      </div>

      <div className="flex items-center gap-2.5 flex-wrap">
        {/* Real Cryptographic Audit Hash Chain Badge */}
        <button
          onClick={checkAuditChain}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-all ${
            auditInfo?.valid
              ? 'bg-gr/10 border-gr/30 text-gr hover:bg-gr/20'
              : 'bg-bg2 border-line text-mut hover:border-cy'
          }`}
          title={
            auditInfo
              ? `Cryptographic SHA-256 Hash Chain Verified!\nTotal events verified: ${auditInfo.events_verified}\nHead hash: ${auditInfo.head_hash}\nStatus: ${auditInfo.message}`
              : 'Click to verify append-only audit chain integrity'
          }
        >
          <Hash className="w-3.5 h-3.5" />
          <span className="font-semibold">
            {verifying
              ? 'Verifying Chain...'
              : auditInfo?.valid
              ? `Chain Verified (${auditInfo.events_verified})`
              : 'Verify Chain'}
          </span>
        </button>

        {/* Policy Mode Enforce / Monitor Toggle */}
        <button
          onClick={onToggleMode}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${
            isEnforce
              ? 'bg-rd/15 border-rd/40 text-rd hover:bg-rd/25'
              : 'bg-am/15 border-am/40 text-am hover:bg-am/25'
          }`}
          title="Toggle between Enforce mode (blocks inline) and Monitor mode (logs would_block alerts without stopping agent)"
        >
          {isEnforce ? (
            <ShieldAlert className="w-3.5 h-3.5" />
          ) : (
            <Sliders className="w-3.5 h-3.5" />
          )}
          <span className="font-semibold">
            {isEnforce ? 'ENFORCE' : 'MONITOR'}
          </span>
        </button>

        {/* Run Simulation Button */}
        {onRunSimulation && (
          <button
            onClick={onRunSimulation}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cy bg-cy/15 text-ink hover:bg-cy/25 text-xs font-semibold transition-all shadow-[0_0_12px_rgba(79,179,199,0.2)]"
          >
            <Play className="w-3 h-3 text-cy fill-cy" />
            <span>Simulate ATK-001</span>
          </button>
        )}

        {/* Live Stream Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg2 border border-line text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              connected ? 'bg-gr live-pulse' : 'bg-rd'
            }`}
          />
          <span className={connected ? 'text-gr' : 'text-rd'}>
            {connected ? 'Live' : 'Connecting'}
          </span>
          <span className="text-mut">·</span>
          <span className="text-ink font-semibold">{agentCount} Protected</span>
        </div>
      </div>
    </header>
  );
};
