from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.app.db.database import list_incidents, get_incident

router = APIRouter(prefix="/incidents", tags=["Incidents"])

class IncidentResponse(BaseModel):
    id: str
    session_id: str
    agent_id: str
    title: str
    status: str
    severity: str
    entry_point: str
    affected_data: str
    final_decision: str
    risk_score: int
    risk_breakdown: dict
    summary: str
    chain_steps: list
    created_at: str

@router.get("", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    exclude_benchmark: bool = Query(False, description="Hide benchmark/latency harness incidents")
) -> List[IncidentResponse]:
    """
    List reconstructed security incidents.
    """
    incidents = list_incidents(
        status=status,
        agent_id=agent_id,
        limit=limit,
        order=order,
        exclude_benchmark=exclude_benchmark,
    )
    return [IncidentResponse(**inc) for inc in incidents]

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident_by_id(incident_id: str) -> IncidentResponse:
    """
    Get full details and attack chain for a specific incident.
    """
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return IncidentResponse(**incident)
