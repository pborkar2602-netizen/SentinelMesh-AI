from datetime import datetime, timezone
from typing import Any, Literal
import uuid
from pydantic import BaseModel, Field, ConfigDict

DecisionType = Literal["allow", "block", "redact", "require_approval"]

class ContextSource(BaseModel):
    source_id: str
    source_type: str = "document"
    is_untrusted: bool = False
    snippet: str | None = None

class ToolCallRequest(BaseModel):
    agent_id: str = Field(..., description="ID of the agent initiating the call (e.g. hr-agent)")
    session_id: str = Field(..., description="Unique session/run ID")
    tool_name: str = Field(..., description="Name of the tool being called (e.g. read_doc, send_email)")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    context_sources: list[ContextSource] = Field(default_factory=list, description="Documents or prompts influencing this call")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of invocation")
    task_description: str | None = Field(default=None, description="Original stated task given to the agent")
    trace_id: str = Field(default_factory=lambda: f"trc-{uuid.uuid4().hex[:12]}", description="Distributed trace identifier")
    approval_token: str | None = Field(default=None, description="HMAC-signed approval token for pre-authorized or approved actions")
    tool_result: Any | None = Field(default=None, description="Actual tool response/result object measured by gateway")
    proxy_execution: bool | None = Field(default=None, description="When True, gateway runs the tool adapter and counts rows from the real result")

class GatewayDecisionResponse(BaseModel):
    trace_id: str
    agent_id: str
    session_id: str
    tool_name: str
    decision: DecisionType
    reason: str
    risk_score: int = 0
    risk_breakdown: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float
    timestamp: datetime
    prev_hash: str = ""
    event_hash: str = ""
    source: str | None = "demo"
    redacted_arguments: dict[str, Any] | None = None
    approval_id: str | None = None
    tool_output: Any | None = None
    measured_records_returned: int | None = None

class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    trace_id: str
    agent_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    context_sources: list[dict[str, Any]]
    decision: str
    reason: str
    risk_score: int
    risk_breakdown: dict[str, Any]
    latency_ms: float
    timestamp: datetime
    prev_hash: str = ""
    event_hash: str = ""
    source: str | None = "demo"

class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    role: str
    declared_purpose: str
    allowed_tools: list[str]
    created_at: datetime
