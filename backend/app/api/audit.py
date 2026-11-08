from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from backend.app.db.database import verify_chain_detailed

router = APIRouter(prefix="/audit", tags=["Audit"])

class AuditVerificationResponse(BaseModel):
    valid: bool
    events_verified: int
    head_hash: str
    tampered_event_id: Optional[int] = None
    message: str

@router.get("/verify", response_model=AuditVerificationResponse)
def get_audit_verification() -> AuditVerificationResponse:
    """
    Cryptographically verifies the append-only SHA-256 hash chain from genesis to head.
    """
    res = verify_chain_detailed()
    return AuditVerificationResponse(**res)
