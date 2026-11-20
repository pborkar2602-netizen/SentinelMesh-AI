import React from 'react';
import { EvidenceSection } from '../components/EvidenceSection';

export const BenchmarksPage: React.FC = () => {
  return (
    <div className="page-shell" id="results">
      <div className="w space-y-6" data-testid="benchmarks-page">
        <div className="border-b border-white/10 pb-5">
          <div className="eb" style={{ marginBottom: '8px' }}>Empirical Benchmarks & Rigor</div>
          <h2 style={{ fontSize: 'clamp(26px, 3.2vw, 40px)' }}>
            Measured on Scenarios Frozen Before Rule Freeze
          </h2>
          <p className="text-sm text-slate-400 mt-2 max-w-3xl font-sans">
            Preregistered holdout test results across InjecAgent, AgentDojo, and ai4privacy with
            44-cluster sign-flip permutation tests, honest limitation accounting, and methodology errata.
          </p>
        </div>

        <EvidenceSection />
      </div>
    </div>
  );
};
