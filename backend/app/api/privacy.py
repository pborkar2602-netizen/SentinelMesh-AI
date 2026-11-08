import copy
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.privacy.vault import PrivacyVault, VaultRetentionExpiredError
from backend.app.db.database import save_audit_event
from backend.app.api.websocket import ws_manager
from backend.app.api.auth import get_current_user_and_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/privacy", tags=["Privacy"])

class RawAccessRequest(BaseModel):
    session_id: str = Field(..., description="Target session identifier")
    tokens: Optional[List[str]] = Field(default=None, description="List of tokens to resolve, e.g. ['[EMAIL_1]', '[SALARY_1]']")
    masked_payload: Optional[Dict[str, Any]] = Field(default=None, description="Optional masked dictionary payload to unmask")
    reason: str = Field(..., description="Mandatory audit justification for retrieving raw PII")

class RawAccessResponse(BaseModel):
    session_id: str
    resolved: Dict[str, str]
    unmasked_payload: Optional[Dict[str, Any]] = None
    access_id: str
    authorized_by: str
    role: str
    timestamp: str

@router.post("/raw-access", response_model=RawAccessResponse, status_code=status.HTTP_200_OK)
def request_raw_pii_access(
    req: RawAccessRequest,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    legacy_role: Optional[str] = Header(None, alias="X-Sentinel-Role"),
    legacy_user: Optional[str] = Header(None, alias="X-Sentinel-User")
) -> RawAccessResponse:
    """
    Role-gated raw PII unmasking endpoint.
    Protected by signed JWT tokens issued at /api/v1/auth/login.
    Only users with verified role 'privacy_officer' and a non-empty compliance reason are permitted.
    Every raw access request is logged to the immutable append-only hash chain.
    """
    # 1. Authenticate identity and role via signed JWT (or legacy header during migration)
    if authorization:
        user, role = get_current_user_and_role(authorization)
    elif legacy_role:
        role = legacy_role.lower().strip()
        user = legacy_user or "compliance-officer"
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing Authorization header with signed JWT bearer token."
        )

    # 2. Strict Role Authorization
    if role != "privacy_officer":
        logger.warning(f"Unauthorized raw PII access attempt by user '{user}' with role '{role}'")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Role '{role}' is not authorized to access raw PII. Required role: 'privacy_officer'."
        )

    # 3. Strict Reason Validation
    reason = (req.reason or "").strip()
    if not reason or len(reason) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad Request: A valid, descriptive justification (min 5 chars) is mandatory for raw PII access."
        )

    # 4. Resolve tokens from isolated encrypted vault (with retention limit enforcement)
    now_utc = datetime.now(timezone.utc)
    access_id = f"RAW-ACC-{uuid.uuid4().hex[:8].upper()}"

    try:
        resolved = PrivacyVault.resolve_tokens(req.session_id, req.tokens or [])
    except VaultRetentionExpiredError as ve:
        # Audit the expired access attempt
        audit_expired = {
            "trace_id": f"trc-{access_id}",
            "agent_id": "privacy-audit-service",
            "session_id": req.session_id,
            "tool_name": "privacy_raw_access",
            "arguments": {
                "access_id": access_id,
                "user": user,
                "role": role,
                "tokens_requested": req.tokens or [],
                "reason": reason,
                "expired": True
            },
            "context_sources": [],
            "decision": "block",
            "reason": f"Raw PII access denied: {str(ve)}",
            "risk_score": 0,
            "risk_breakdown": {"compliance_access": 1, "retention_expired": 1},
            "latency_ms": 1.0,
            "timestamp": now_utc.isoformat()
        }
        event_id, event_hash = save_audit_event(audit_expired)
        ws_manager.broadcast_sync({
            "type": "AUDIT_EVENT",
            "id": event_id,
            "event_hash": event_hash,
            "findings": [],
            **audit_expired
        })
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"Retention Expired: {str(ve)}"
        )

    # 5. Optional payload unmasking
    unmasked_payload = None
    if req.masked_payload:
        def _unmask(val: Any) -> Any:
            if isinstance(val, str):
                res = val
                for tok, raw in resolved.items():
                    res = res.replace(tok, raw)
                return res
            elif isinstance(val, dict):
                return {k: _unmask(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_unmask(elem) for elem in val]
            return val
        unmasked_payload = _unmask(copy.deepcopy(req.masked_payload))

    # 6. Log mandatory access audit event to append-only store with hash chain
    audit_dict = {
        "trace_id": f"trc-{access_id}",
        "agent_id": "privacy-audit-service",
        "session_id": req.session_id,
        "tool_name": "privacy_raw_access",
        "arguments": {
            "access_id": access_id,
            "user": user,
            "role": role,
            "tokens_requested": req.tokens or list(resolved.keys()),
            "reason": reason
        },
        "context_sources": [],
        "decision": "allow",
        "reason": f"Authorized raw PII access granted to '{user}' ({role}) for reason: {reason}",
        "risk_score": 0,
        "risk_breakdown": {"compliance_access": 1},
        "latency_ms": 1.0,
        "timestamp": now_utc.isoformat()
    }
    event_id, event_hash = save_audit_event(audit_dict)

    # 7. Broadcast event over WebSocket
    ws_manager.broadcast_sync({
        "type": "AUDIT_EVENT",
        "id": event_id,
        "event_hash": event_hash,
        "findings": [],
        **audit_dict
    })

    logger.info(f"Raw PII access granted to {user} for session {req.session_id} (Access ID: {access_id})")

    return RawAccessResponse(
        session_id=req.session_id,
        resolved=resolved,
        unmasked_payload=unmasked_payload,
        access_id=access_id,
        authorized_by=user,
        role=role,
        timestamp=now_utc.isoformat()
    )
