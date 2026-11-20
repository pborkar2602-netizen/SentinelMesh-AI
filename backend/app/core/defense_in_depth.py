"""
backend/app/core/defense_in_depth.py

Robustness & Defense-in-Depth Layer for SentinelMesh:
1. Perimeter Agent Authentication (API Key / HMAC validation)
2. In-memory Token Bucket Rate Limiter (per agent and per session)
3. Payload Size & Complexity Caps (DoS prevention)
4. Prometheus Metrics Collector & Exporter (/metrics)
"""

import os
import time
import json
import threading
from typing import Dict, Any, Tuple, Optional
from fastapi import HTTPException, status

# Configurable limits
MAX_ARGUMENT_BYTES = int(os.getenv("SENTINEL_MAX_ARGUMENT_BYTES", "262144"))  # 256 KB
MAX_CONTEXT_SOURCES = int(os.getenv("SENTINEL_MAX_CONTEXT_SOURCES", "50"))
RATE_LIMIT_BURST = int(os.getenv("SENTINEL_RATE_LIMIT_BURST", "120"))  # tokens
RATE_LIMIT_REFILL_PER_SEC = float(os.getenv("SENTINEL_RATE_LIMIT_REFILL", "2.0"))  # 120 / min

# In-memory registered agent API keys (configurable via env or defaults)
REGISTERED_AGENT_KEYS = {
    "finance-agent": os.getenv("KEY_FINANCE_AGENT", "sk-agent-fin-782163901a"),
    "support-agent": os.getenv("KEY_SUPPORT_AGENT", "sk-agent-sup-449102832b"),
    "hr-agent": os.getenv("KEY_HR_AGENT", "sk-agent-hr-991204851c"),
    "ops-agent": os.getenv("KEY_OPS_AGENT", "sk-agent-ops-338192044d"),
    "code-agent": os.getenv("KEY_CODE_AGENT", "sk-agent-code-110293847e"),
    "general-agent": os.getenv("KEY_GENERAL_AGENT", "sk-agent-gen-559102938f"),
    "assistant-agent": os.getenv("KEY_ASSISTANT_AGENT", "sk-agent-ast-660192837g"),
}


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class RateLimiter:
    _instance = None
    _lock = threading.Lock()
    MAX_TRACKED_ENTITIES = 5000

    def __init__(self):
        self.buckets: Dict[str, TokenBucket] = {}

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def check_rate_limit(self, identifier: str) -> None:
        if os.environ.get("SENTINEL_BENCHMARK_MODE", "").lower() in ("true", "1", "yes"):
            return
        if os.environ.get("SENTINEL_DISABLE_RATE_LIMIT", "").lower() in ("true", "1", "yes"):
            return
        with self._lock:
            if identifier not in self.buckets:
                if len(self.buckets) >= self.MAX_TRACKED_ENTITIES:
                    # Evict oldest inactive 1000 buckets to bound memory
                    oldest = sorted(self.buckets.items(), key=lambda kv: kv[1].last_update)[:1000]
                    for k, _ in oldest:
                        self.buckets.pop(k, None)
                self.buckets[identifier] = TokenBucket(RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SEC)
            bucket = self.buckets[identifier]
        if not bucket.consume(1.0):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for entity: {identifier}. Try again later."
            )


def _resolve_agent_key(agent_id: str, demo_mode: bool) -> Optional[str]:
    env_var = f"KEY_{agent_id.upper().replace('-', '_')}"
    env_key = os.getenv(env_var)
    if env_key:
        return env_key
    keys_json = os.getenv("SENTINEL_AGENT_KEYS_JSON")
    if keys_json:
        try:
            mapping = json.loads(keys_json)
            if isinstance(mapping, dict) and agent_id in mapping:
                return str(mapping[agent_id])
        except Exception:
            pass
    if demo_mode:
        return REGISTERED_AGENT_KEYS.get(agent_id)
    return None


def verify_agent_perimeter_auth(agent_id: str, provided_key: Optional[str]) -> None:
    """
    Validates per-agent perimeter credentials.
    Fail-closed by default when DEMO_MODE=false (unless SENTINEL_GATEWAY_AUTH_REQUIRED explicitly false).
    """
    if not isinstance(provided_key, str):
        provided_key = None

    demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")
    auth_env = os.getenv("SENTINEL_GATEWAY_AUTH_REQUIRED")
    if auth_env is None or auth_env.strip() == "":
        auth_required = not demo_mode
    else:
        auth_required = auth_env.lower() in ("true", "1", "yes")

    if not auth_required and not provided_key:
        return  # Permitted in standard demo/internal benchmark mode

    if not provided_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Perimeter authentication required: Missing X-Agent-Key header for agent '{agent_id}'."
        )

    expected_key = _resolve_agent_key(agent_id, demo_mode=demo_mode)
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{agent_id}' is not registered or missing provisioned perimeter key."
        )

    import hmac
    if not hmac.compare_digest(provided_key.strip(), expected_key.strip()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Invalid API key provided for agent '{agent_id}'."
        )


def enforce_payload_caps(arguments: Dict[str, Any], context_sources: list) -> None:
    """Rejects oversized payloads to prevent memory exhaustion and DoS."""
    if len(context_sources) > MAX_CONTEXT_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload rejected: context_sources count ({len(context_sources)}) exceeds cap ({MAX_CONTEXT_SOURCES})."
        )

    try:
        raw_size = len(json.dumps(arguments).encode("utf-8"))
    except Exception:
        raw_size = sum(len(str(k)) + len(str(v)) for k, v in arguments.items())

    if raw_size > MAX_ARGUMENT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload rejected: arguments size ({raw_size} bytes) exceeds cap ({MAX_ARGUMENT_BYTES} bytes)."
        )


class PrometheusMetrics:
    """Thread-safe Prometheus metrics collector for SentinelMesh gateway."""
    _lock = threading.Lock()
    request_counts = {"allow": 0, "block": 0, "require_approval": 0, "would_block": 0, "redact": 0}
    latencies: list = []
    rule_hits: Dict[str, int] = {}
    active_taint_sessions: int = 0

    @classmethod
    def record_decision(cls, decision: str, latency_ms: float, findings: list):
        with cls._lock:
            cls.request_counts[decision] = cls.request_counts.get(decision, 0) + 1
            cls.latencies.append(latency_ms / 1000.0) # seconds
            if len(cls.latencies) > 2000:
                cls.latencies = cls.latencies[-1000:]
            for f in findings:
                fname = getattr(f, "name", str(f))
                cls.rule_hits[fname] = cls.rule_hits.get(fname, 0) + 1

    @classmethod
    def export_metrics(cls) -> str:
        with cls._lock:
            lines = [
                "# HELP sentinel_requests_total Total number of tool-call policy evaluations by decision.",
                "# TYPE sentinel_requests_total counter",
            ]
            for dec, count in cls.request_counts.items():
                lines.append(f'sentinel_requests_total{{decision="{dec}"}} {count}')

            lines.extend([
                "# HELP sentinel_rule_hits_total Number of times specific threat rules have fired.",
                "# TYPE sentinel_rule_hits_total counter",
            ])
            for rule, count in cls.rule_hits.items():
                lines.append(f'sentinel_rule_hits_total{{rule="{rule}"}} {count}')

            # Latency summary
            if cls.latencies:
                sorted_lat = sorted(cls.latencies)
                n = len(sorted_lat)
                p50 = sorted_lat[int(0.50 * (n - 1))]
                p95 = sorted_lat[int(0.95 * (n - 1))]
                p99 = sorted_lat[int(0.99 * (n - 1))]
                total_dur = sum(sorted_lat)
            else:
                p50 = p95 = p99 = total_dur = n = 0.0

            lines.extend([
                "# HELP sentinel_request_duration_seconds Gateway decision latency summary.",
                "# TYPE sentinel_request_duration_seconds summary",
                f'sentinel_request_duration_seconds{{quantile="0.5"}} {p50:.6f}',
                f'sentinel_request_duration_seconds{{quantile="0.95"}} {p95:.6f}',
                f'sentinel_request_duration_seconds{{quantile="0.99"}} {p99:.6f}',
                f'sentinel_request_duration_seconds_sum {total_dur:.6f}',
                f'sentinel_request_duration_seconds_count {n}',
            ])

            return "\n".join(lines) + "\n"
