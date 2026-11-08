from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from backend.app.db.database import list_approvals, get_approval
from backend.app.approvals.service import ApprovalService
from backend.app.api.auth import get_current_user_and_role
from backend.app.api.websocket import ws_manager

router = APIRouter(prefix="/approvals", tags=["Human Approvals"])

class ApprovalResolveRequest(BaseModel):
    decision: str = Field(..., description="'approve' or 'deny'")
    reason: str = Field(..., description="Justification provided by reviewer")

class PreApproveRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]
    session_id: str
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)

@router.get("", response_model=List[Dict[str, Any]])
def get_approvals(
    status: Optional[str] = Query(None, description="Filter by status: pending, approved, denied, timed_out"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    limit: int = Query(50, ge=1, le=200)
):
    """Lists approval requests with masked payload previews and remaining TTL."""
    # Run timeout sweep before listing
    ApprovalService.check_and_expire()
    return list_approvals(status=status, agent_id=agent_id, limit=limit)

@router.get("/{approval_id}", response_model=Dict[str, Any])
def get_single_approval(approval_id: str):
    ApprovalService.check_and_expire()
    record = get_approval(approval_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found."
        )
    return record

@router.post("/{approval_id}/resolve", response_model=Dict[str, Any])
def resolve_approval_endpoint(
    approval_id: str,
    req: ApprovalResolveRequest,
    user_and_role: tuple = Depends(get_current_user_and_role)
):
    """
    Resolves a pending human approval.
    Requires authenticated user with role 'analyst' or 'privacy_officer'.
    If approved, issues an HMAC-signed approval token bound to the action.
    """
    username, role = user_and_role
    if role not in ["analyst", "privacy_officer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized to approve or deny sensitive agent tool calls."
        )

    try:
        updated = ApprovalService.resolve_approval(
            approval_id=approval_id,
            decision=req.decision,
            resolved_by=f"{username} ({role})",
            resolution_reason=req.reason
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Broadcast notification to dashboard
    ws_manager.broadcast_sync({
        "type": "APPROVAL_RESOLVED",
        "approval": updated
    })

    return updated

@router.post("/tokens/preapprove", response_model=Dict[str, Any])
def create_preapproved_token_endpoint(
    req: PreApproveRequest,
    user_and_role: tuple = Depends(get_current_user_and_role)
):
    """
    Issues an HMAC-signed pre-approved token for an authorized privileged operation.
    Requires role 'analyst' or 'privacy_officer'.
    """
    username, role = user_and_role
    if role not in ["analyst", "privacy_officer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role not authorized to issue pre-approved action tokens."
        )

    token = ApprovalService.create_preapproved_token(
        tool_name=req.tool_name,
        arguments=req.arguments,
        session_id=req.session_id,
        ttl_seconds=req.ttl_seconds
    )
    return {
        "status": "issued",
        "tool_name": req.tool_name,
        "approval_token": token,
        "expires_in_seconds": req.ttl_seconds,
        "issued_by": f"{username} ({role})"
    }
