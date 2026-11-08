import os
import time
import uuid
import httpx
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

class ToolBlockedError(Exception):
    def __init__(self, reason: str, trace_id: str):
        super().__init__(f"Tool call blocked by SentinelMesh Gateway [trace: {trace_id}]: {reason}")
        self.reason = reason
        self.trace_id = trace_id

class GatewayClient:
    def __init__(
        self,
        gateway_url: Optional[str] = None,
        agent_id: str = "hr-agent",
        session_id: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
        async_http_client: Optional[httpx.AsyncClient] = None
    ):
        self.gateway_url = gateway_url or os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8000/api/v1/gateway/execute")
        self.agent_id = agent_id
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"
        self.http_client = http_client
        self.async_http_client = async_http_client

    def intercept_and_execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_func: Callable[..., Any],
        context_sources: Optional[List[Dict[str, Any]]] = None,
        task_description: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        approval_token: Optional[str] = None
    ) -> Any:
        """
        Synchronous tool call interception.
        """
        trace_id = f"trc-{uuid.uuid4().hex[:10]}"
        payload = {
            "trace_id": trace_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "context_sources": context_sources or [],
            "task_description": task_description or "Execute autonomous task",
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "approval_token": approval_token
        }

        try:
            if self.http_client is not None:
                response = self.http_client.post(self.gateway_url, json=payload)
            else:
                with httpx.Client(timeout=5.0) as client:
                    response = client.post(self.gateway_url, json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.ConnectError:
            raise ConnectionError(
                f"Could not connect to SentinelMesh Security Gateway at {self.gateway_url}. "
                "Ensure the gateway is running (e.g. 'docker compose up' or 'python -m uvicorn backend.app.main:app')."
            )
        except Exception as e:
            raise RuntimeError(f"Error communicating with SentinelMesh Gateway: {e}")

        decision = data.get("decision", "allow")
        reason = data.get("reason", "")
        risk_score = data.get("risk_score", 0)
        risk_bd = data.get("risk_breakdown", {})

        print(f"  [GATEWAY INTERCEPT] tool={tool_name} -> DECISION: {decision.upper()} | Risk: {risk_score}/100 | Latency: {data.get('latency_ms')}ms")
        if risk_score > 0 and risk_bd:
            print(f"    -> Signals: Taint={risk_bd.get('untrusted_taint', 0)}, Rules={risk_bd.get('rule_findings', 0)}, ExtDest={risk_bd.get('external_destination', 0)}, Sensitive={risk_bd.get('sensitive_data', 0)}")
        if reason:
            print(f"    -> Policy Note: {reason}")

        if decision == "block":
            raise ToolBlockedError(reason, trace_id)
        elif decision == "require_approval":
            print(f"  [GATEWAY ESCALATION] Action requires human approval: {reason}")
            return {
                "status": "pending_human_approval",
                "trace_id": trace_id,
                "reason": reason,
                "approval_id": data.get("approval_id")
            }
        elif decision == "redact":
            exec_args = data.get("redacted_arguments") or arguments
            print(f"  [GATEWAY REDACTION] Executing tool with privacy-redacted arguments: {exec_args}")
            return tool_func(**exec_args)

        return tool_func(**arguments)

    async def aintercept_and_execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_func: Callable[..., Any],
        context_sources: Optional[List[Dict[str, Any]]] = None,
        task_description: Optional[str] = None
    ) -> Any:
        """
        Asynchronous tool call interception for async pipelines and tests.
        """
        trace_id = f"trc-{uuid.uuid4().hex[:10]}"
        payload = {
            "trace_id": trace_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "context_sources": context_sources or [],
            "task_description": task_description or "Execute autonomous task",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.async_http_client is not None:
            response = await self.async_http_client.post(self.gateway_url, json=payload)
        else:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(self.gateway_url, json=payload)

        response.raise_for_status()
        data = response.json()
        decision = data.get("decision", "allow")
        reason = data.get("reason", "")

        if decision == "block":
            raise ToolBlockedError(reason, trace_id)
        elif decision == "require_approval":
            return {"status": "pending_human_approval", "trace_id": trace_id, "reason": reason}
        elif decision == "redact":
            exec_args = data.get("redacted_arguments") or arguments
            return tool_func(**exec_args)

        return tool_func(**arguments)
