from dataclasses import dataclass
from typing import Optional

@dataclass
class JudgeVerdict:
    is_aligned: bool
    mismatch_score: int          # 0 (fully aligned) to 100 (complete divergence / attack)
    reasoning: str
    risk_level: str              # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    latency_ms: float
    mode: str                    # "replay", "live", "record", "forced_aligned", "failsafe"

    def to_dict(self):
        return {
            "is_aligned": self.is_aligned,
            "mismatch_score": self.mismatch_score,
            "reasoning": self.reasoning,
            "risk_level": self.risk_level,
            "latency_ms": self.latency_ms,
            "mode": self.mode
        }
