from typing import List
from fastapi import APIRouter

from backend.app.schemas.gateway import AgentRead
from backend.app.db.database import list_agents

router = APIRouter(prefix="/agents", tags=["Agents"])

@router.get("", response_model=List[AgentRead])
def get_all_agents() -> List[AgentRead]:
    agents = list_agents()
    return [AgentRead.model_validate(a) for a in agents]
