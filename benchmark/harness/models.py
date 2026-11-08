from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Literal

@dataclass
class InputContextSource:
    source_id: str
    source_type: str
    is_untrusted: bool
    content: str

@dataclass
class ScriptedStep:
    step_index: int
    timestamp_offset_seconds: float
    event_type: Literal["tool_call", "inter_agent_message", "agent_output"]
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    records_accessed: int = 0
    is_external_destination: bool = False
    sender_agent: Optional[str] = None
    recipient_agent: Optional[str] = None
    message_body: Optional[str] = None
    output_content: Optional[str] = None
    expected_step_decision: str = "allow"
    expected_triggered_layers: List[str] = field(default_factory=list)

@dataclass
class BenchmarkScenario:
    id: str
    name: str
    category: Literal["attack", "benign"]
    split: Literal["dev", "held_out"]
    owasp_category: str
    target_agent: str
    agent_task: str
    scenario_start_datetime: str
    weekday: str
    input_context: List[InputContextSource]
    scripted_steps: List[ScriptedStep]
    expected_final_decision: str
    pass_fail_reason: str
    matched_pair_id: Optional[str] = None

@dataclass
class StepExecutionResult:
    step_index: int
    tool_name: str
    simulated_timestamp: str
    actual_decision: str
    expected_decision: str
    decision_match: bool
    latency_ms: float
    risk_score: int
    reason: str
    records_accessed: int
    records_leaked: int

@dataclass
class ScenarioExecutionResult:
    scenario_id: str
    scenario_name: str
    category: str
    split: str
    target_agent: str
    expected_decision: str
    actual_final_decision: str
    decision_match: bool
    detected: bool
    prevented: bool
    stopped_at_step: Optional[int]
    total_steps: int
    total_latency_ms: float
    step_latencies_ms: List[float]
    total_records_accessed: int
    total_records_leaked: int
    step_results: List[StepExecutionResult]
