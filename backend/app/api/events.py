from typing import List, Optional
from fastapi import APIRouter, Query

from backend.app.schemas.gateway import AuditEventRead
from backend.app.db.database import list_audit_events

router = APIRouter(prefix="/events", tags=["Events"])

@router.get("", response_model=List[AuditEventRead])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    agent_id: Optional[str] = None,
    order: str = Query("asc", pattern="^(asc|desc)$")
) -> List[AuditEventRead]:
    events = list_audit_events(limit=limit, agent_id=agent_id, order=order)
    return [AuditEventRead.model_validate(e) for e in events]
