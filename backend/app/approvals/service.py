import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from backend.app.db.database import (
    save_approval,
    get_approval,
    list_approvals,
    update_approval_status,
    expire_timed_out_approvals,
    save_audit_event
)
from backend.app.approvals.tokens import (
    canonical_action_hash,
    issue_signed_approval_token
)
from backend.app.privacy.masker import PrivacyEngine

logger = logging.getLogger(__name__)

class ApprovalService:
    @classmethod
    def create_approval_request(
        cls,
        session_id: str,
        trace_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
        risk_score: int = 50,
        ttl_seconds: int = 300
    ) -> Dict[str, Any]:
        """Creates a pending human approval request and records an append-only audit event."""
        approval_id = f"appr-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Mask arguments for privacy in preview
        masked_args, _ = PrivacyEngine.mask_payload(session_id, arguments)
        act_hash = canonical_action_hash(tool_name, arguments)

        # Ensure session exists in database to satisfy foreign key
        from backend.app.db.database import get_session, save_session
        sess = get_session(session_id)
        if not sess:
            save_session({
                "id": session_id,
                "agent_id": agent_id,
                "task_description": "Session approval request",
                "status": "ACTIVE",
                "is_tainted": False,
                "tainted_by": [],
                "started_at": now.isoformat()
            })

        approval_record = {
            "id": approval_id,
            "session_id": session_id,
            "trace_id": trace_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "masked_arguments": masked_args,
            "action_hash": act_hash,
            "status": "pending",
            "reason": reason,
            "risk_score": risk_score,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "resolved_by": None,
            "resolved_at": None,
            "resolution_reason": None,
            "approval_token": None
        }
        save_approval(approval_record)

        # Append to audit log hash chain
        try:
            save_audit_event({
                "trace_id": trace_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "arguments": masked_args,
                "context_sources": [],
                "decision": "require_approval",
                "reason": f"Approval requested [{approval_id}]: {reason}",
                "risk_score": risk_score,
                "risk_breakdown": {"approval_id": approval_id, "ttl_seconds": ttl_seconds},
                "latency_ms": 0.0,
                "timestamp": now.isoformat()
            })
        except Exception as e:
            logger.warning(f"Failed to write approval request audit event: {e}")

        return approval_record

    @classmethod
    def resolve_approval(
        cls,
        approval_id: str,
        decision: str,  # "approve" or "deny"
        resolved_by: str,
        resolution_reason: str,
        raw_arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Resolves a pending approval.
        If approved, issues an HMAC-signed approval token bound to the action.
        Records an append-only audit event in the hash chain.
        """
        # First process any timed-out approvals
        expire_timed_out_approvals()

        record = get_approval(approval_id)
        if not record:
            raise ValueError(f"Approval request '{approval_id}' not found.")

        if record["status"] != "pending":
            raise ValueError(f"Approval request '{approval_id}' is already {record['status']}.")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        decision_clean = decision.lower().strip()

        if decision_clean not in ["approve", "deny"]:
            raise ValueError("Decision must be 'approve' or 'deny'.")

        issued_token = None
        new_status = "approved" if decision_clean == "approve" else "denied"

        if decision_clean == "approve":
            # Issue signed token bound to the stored action hash
            issued_token = issue_signed_approval_token(
                tool_name=record["tool_name"],
                session_id=record["session_id"],
                ttl_seconds=300,
                action_hash=record["action_hash"]
            )

        update_approval_status(
            approval_id=approval_id,
            status=new_status,
            resolved_by=resolved_by,
            resolution_reason=resolution_reason,
            approval_token=issued_token
        )

        record = get_approval(approval_id)

        # Append resolution event to audit log hash chain
        try:
            save_audit_event({
                "trace_id": record["trace_id"],
                "agent_id": record["agent_id"],
                "session_id": record["session_id"],
                "tool_name": record["tool_name"],
                "arguments": record["masked_arguments"],
                "context_sources": [],
                "decision": "approval_granted" if new_status == "approved" else "approval_denied",
                "reason": f"Approval {new_status} by {resolved_by}: {resolution_reason}",
                "risk_score": record["risk_score"],
                "risk_breakdown": {"approval_id": approval_id, "resolved_by": resolved_by},
                "latency_ms": 0.0,
                "timestamp": now_iso
            })
        except Exception as e:
            logger.warning(f"Failed to write approval resolution audit event: {e}")

        return record

    @classmethod
    def check_and_expire(cls) -> List[str]:
        """Scans and marks expired approvals as timed_out (default deny)."""
        expired_ids = expire_timed_out_approvals()
        for app_id in expired_ids:
            rec = get_approval(app_id)
            if rec:
                try:
                    save_audit_event({
                        "trace_id": rec["trace_id"],
                        "agent_id": rec["agent_id"],
                        "session_id": rec["session_id"],
                        "tool_name": rec["tool_name"],
                        "arguments": rec["masked_arguments"],
                        "context_sources": [],
                        "decision": "approval_timed_out",
                        "reason": f"Approval {app_id} timed out without human review. Defaulted to deny.",
                        "risk_score": rec["risk_score"],
                        "risk_breakdown": {"approval_id": app_id, "timeout": True},
                        "latency_ms": 0.0,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                except Exception:
                    pass
        return expired_ids

    @classmethod
    def create_preapproved_token(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str,
        ttl_seconds: int = 3600
    ) -> str:
        """Issues an HMAC-signed pre-approved token for authorized privileged workflows."""
        return issue_signed_approval_token(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            ttl_seconds=ttl_seconds
        )
