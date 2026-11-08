import React from 'react';
import { Scale, Activity } from 'lucide-react';

interface RiskGaugeProps {
  score: number;
  breakdown: Record<string, any>;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score = 0, breakdown = {} }) => {
  // SVG circle calculations: r = 54, circumference = 2 * PI * 54 ~= 339.29
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  let gaugeColor = '#3fb68b'; // green
  if (score >= 70) gaugeColor = '#e5484d'; // red
  else if (score >= 30) gaugeColor = '#d9a441'; // amber

  const taintVal = breakdown?.untrusted_taint || 0;
  const rulesVal = breakdown?.rule_findings || 0;
  const extVal = breakdown?.external_destination || 0;
  const sensVal = breakdown?.sensitive_data || 0;
  const privVal = breakdown?.privacy_score || 0;
  const privSummary = breakdown?.privacy_breakdown?.summary;

  // Milestone 5 Signals
  const anomalyScore = breakdown?.baseline_anomaly || 0;
  const anomalyReasons: string[] = breakdown?.anomaly_reasons || [];
  const judgeMismatch = breakdown?.judge_mismatch || 0;
  const judgeReasoning = breakdown?.judge_reasoning;
  const judgeLatency = breakdown?.judge_latency_ms;

  return (
    <div className="p-4 rounded-xl bg-pan border border-line backdrop-blur flex flex-col h-full font-mono">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold tracking-wide text-ink uppercase">
          Why this action is risky
        </h2>
        <div className="flex items-center gap-1.5 flex-wrap">
          {judgeMismatch >= 70 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-rd/15 text-rd border border-rd/30 font-bold flex items-center gap-1">
              <Scale className="w-3 h-3" /> Judge Mismatch
            </span>
          )}
          {anomalyScore >= 50 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-am/15 text-am border border-am/30 font-bold flex items-center gap-1">
              <Activity className="w-3 h-3" /> Baseline Anomaly
            </span>
          )}
          {privVal > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-vi/15 text-vi border border-vi/30 font-bold">
              PII Detected
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-12 gap-4 items-center flex-1">
        {/* Circular SVG Gauge */}
        <div className="sm:col-span-5 flex flex-col items-center justify-center relative">
          <div className="relative w-32 h-32 flex items-center justify-center">
            <svg className="w-32 h-32 -rotate-90" viewBox="0 0 120 120">
              <circle
                cx="60"
                cy="60"
                r={radius}
                className="stroke-line"
                strokeWidth="9"
                fill="none"
              />
              <circle
                cx="60"
                cy="60"
                r={radius}
                stroke={gaugeColor}
                strokeWidth="9"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="none"
                style={{ transition: 'stroke-dashoffset 1s ease-out' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-extrabold tracking-tight text-ink font-mono">
                {score}
              </span>
              <span className="text-[10px] text-mut uppercase">Risk Score</span>
            </div>
          </div>
        </div>

        {/* Signal Bars */}
        <div className="sm:col-span-7 space-y-1.5 text-xs">
          <div>
            <div className="flex justify-between text-[11px] mb-0.5">
              <span className="text-mut">Untrusted Taint</span>
              <span className={taintVal > 0 ? 'text-am font-bold' : 'text-mut'}>
                +{taintVal} pts
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-line overflow-hidden">
              <div
                className="h-full bg-am rounded-full transition-all duration-700"
                style={{ width: `${Math.min(100, (taintVal / 38) * 100)}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between text-[11px] mb-0.5">
              <span className="text-mut">Rule Findings</span>
              <span className={rulesVal > 0 ? 'text-rd font-bold' : 'text-mut'}>
                +{rulesVal} pts
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-line overflow-hidden">
              <div
                className="h-full bg-rd rounded-full transition-all duration-700"
                style={{ width: `${Math.min(100, (rulesVal / 40) * 100)}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between text-[11px] mb-0.5">
              <span className="text-mut">External Destination</span>
              <span className={extVal > 0 ? 'text-am font-bold' : 'text-mut'}>
                +{extVal} pts
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-line overflow-hidden">
              <div
                className="h-full bg-cy rounded-full transition-all duration-700"
                style={{ width: `${Math.min(100, (extVal / 25) * 100)}%` }}
              />
            </div>
          </div>

          {sensVal > 0 && (
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="text-mut">Sensitive Data Access</span>
                <span className="text-rd font-bold">
                  +{sensVal} pts
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-line overflow-hidden">
                <div
                  className="h-full bg-vi rounded-full transition-all duration-700"
                  style={{ width: `${Math.min(100, (sensVal / 15) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {anomalyScore > 0 && (
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="text-mut">Behavioral Baseline Anomaly</span>
                <span className="text-am font-bold">
                  +{anomalyScore} pts
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-line overflow-hidden">
                <div
                  className="h-full bg-am rounded-full transition-all duration-700"
                  style={{ width: `${Math.min(100, anomalyScore)}%` }}
                />
              </div>
            </div>
          )}

          {judgeMismatch > 0 && (
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="text-mut">Intent Judge Mismatch</span>
                <span className="text-rd font-bold">
                  +{judgeMismatch} pts
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-line overflow-hidden">
                <div
                  className="h-full bg-rd rounded-full transition-all duration-700"
                  style={{ width: `${Math.min(100, judgeMismatch)}%` }}
                />
              </div>
            </div>
          )}

          {privVal > 0 && (
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="text-mut">Privacy Risk Score</span>
                <span className="text-vi font-bold">
                  +{privVal} pts
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-line overflow-hidden">
                <div
                  className="h-full bg-vi rounded-full transition-all duration-700"
                  style={{ width: `${Math.min(100, privVal)}%` }}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Narrative signal annotations */}
      <div className="mt-3 pt-2 border-t border-line/60 space-y-1.5 text-[11px]">
        {judgeReasoning && (
          <div className="flex items-start gap-1.5 text-rd/90">
            <Scale className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-rd" />
            <span>
              <strong>Intent Judge ({judgeLatency}ms):</strong> {judgeReasoning}
            </span>
          </div>
        )}
        {anomalyReasons.length > 0 && (
          <div className="flex items-start gap-1.5 text-am/90">
            <Activity className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-am" />
            <span>
              <strong>Baseline Anomaly:</strong> {anomalyReasons.join('; ')}
            </span>
          </div>
        )}
        {privSummary && (
          <div className="flex items-center gap-1.5 text-mut">
            <span className="w-1.5 h-1.5 rounded-full bg-vi flex-shrink-0" />
            <span>
              Protected Data: <strong className="text-ink font-sans">{privSummary}</strong>
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
