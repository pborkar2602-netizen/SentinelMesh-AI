import os
import tempfile
import uuid
import urllib.parse
from typing import Generator, Any, Dict, List
import pytest

# Ensure DEMO_MODE=true is active by default for test suite
os.environ.setdefault("DEMO_MODE", "true")
os.environ.setdefault("SENTINEL_JWT_SECRET", "test-sentinel-jwt-secret-key-32bytes!")

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.core.policy_engine import PolicyEngine
from backend.app.schemas.gateway import ToolCallRequest
from backend.app.api.gateway import execute_tool_call
from backend.app.api.events import list_events
from backend.app.api.agents import get_all_agents
from backend.app.api.policies import get_policy_mode, set_policy_mode, ModeUpdate
from backend.app.api.incidents import get_incidents, get_incident_by_id
from backend.app.api.audit import get_audit_verification

class ApiResponse:
    def __init__(self, status_code: int, data: Any):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}: {self._data}")

class DirectClient:
    """
    Synchronous direct in-memory API test client that simulates HTTP requests
    by directly calling FastAPI routes, avoiding loopback socket binding (WinError 10013)
    in isolated/sandboxed environments.
    """
    def get(self, path: str):
        url = urllib.parse.urlparse(path)
        query = urllib.parse.parse_qs(url.query)
        clean_path = url.path

        if clean_path == "/health":
            return ApiResponse(200, {"status": "healthy", "service": "SentinelMesh AI Gateway", "version": "0.1.0"})
        elif clean_path == "/api/v1/events":
            agent_id = query.get("agent_id", [None])[0]
            order = query.get("order", ["desc"])[0]
            limit = int(query.get("limit", [50])[0])
            events = list_events(agent_id=agent_id, limit=limit, order=order)
            return ApiResponse(200, [e.model_dump() for e in events])
        elif clean_path == "/api/v1/agents":
            agents = get_all_agents()
            return ApiResponse(200, [a.model_dump() for a in agents])
        elif clean_path == "/api/v1/policies/mode":
            mode_data = get_policy_mode()
            return ApiResponse(200, mode_data)
        elif clean_path == "/api/v1/audit/verify":
            audit_res = get_audit_verification()
            return ApiResponse(200, audit_res.model_dump())
        elif clean_path == "/api/v1/incidents":
            status = query.get("status", [None])[0]
            agent_id = query.get("agent_id", [None])[0]
            limit = int(query.get("limit", [50])[0])
            order = query.get("order", ["desc"])[0]
            inc_list = get_incidents(status=status, agent_id=agent_id, limit=limit, order=order)
            return ApiResponse(200, [inc.model_dump() for inc in inc_list])
        elif clean_path.startswith("/api/v1/incidents/"):
            inc_id = clean_path.split("/")[-1]
            try:
                inc_detail = get_incident_by_id(inc_id)
                return ApiResponse(200, inc_detail.model_dump())
            except Exception as e:
                return ApiResponse(404, {"detail": str(e)})
        elif clean_path == "/api/v1/policies/simulation/stats":
            from backend.app.api.policies import get_simulation_stats
            return ApiResponse(200, get_simulation_stats())
        elif clean_path == "/api/v1/approvals":
            from backend.app.api.approvals import get_approvals
            status_val = query.get("status", [None])[0]
            agent_id = query.get("agent_id", [None])[0]
            res = get_approvals(status=status_val, agent_id=agent_id)
            return ApiResponse(200, res)
        elif clean_path.startswith("/api/v1/approvals/"):
            from backend.app.api.approvals import get_single_approval
            from fastapi import HTTPException
            appr_id = clean_path.split("/")[-1]
            try:
                res = get_single_approval(appr_id)
                return ApiResponse(200, res)
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
        return ApiResponse(404, {"detail": "Not Found"})

    def post(self, path: str, json: dict = None, headers: dict = None):
        url = urllib.parse.urlparse(path)
        clean_path = url.path
        if clean_path == "/api/v1/gateway/execute":
            try:
                req = ToolCallRequest(**(json or {}))
                res = execute_tool_call(req)
                return ApiResponse(200, res.model_dump())
            except Exception as e:
                return ApiResponse(422, {"detail": str(e)})
        elif clean_path == "/api/v1/policies/mode":
            try:
                req = ModeUpdate(**(json or {}))
                res = set_policy_mode(req)
                return ApiResponse(200, res)
            except Exception as e:
                return ApiResponse(422, {"detail": str(e)})
        elif clean_path == "/api/v1/auth/login":
            from backend.app.api.auth import login, LoginRequest
            from fastapi import HTTPException
            try:
                req = LoginRequest(**(json or {}))
                res = login(req)
                return ApiResponse(200, res.model_dump())
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
            except Exception as e:
                return ApiResponse(400, {"detail": str(e)})
        elif clean_path == "/api/v1/privacy/raw-access":
            from backend.app.api.privacy import request_raw_pii_access, RawAccessRequest
            from fastapi import HTTPException
            try:
                headers = headers or {}
                auth = headers.get("Authorization") or headers.get("authorization")
                role = headers.get("X-Sentinel-Role") or headers.get("x-sentinel-role")
                user = headers.get("X-Sentinel-User") or headers.get("x-sentinel-user")
                req = RawAccessRequest(**(json or {}))
                res = request_raw_pii_access(req=req, authorization=auth, legacy_role=role, legacy_user=user)
                return ApiResponse(200, res.model_dump())
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
            except Exception as e:
                return ApiResponse(400, {"detail": str(e)})
        elif clean_path.startswith("/api/v1/approvals/") and clean_path.endswith("/resolve"):
            from backend.app.api.approvals import resolve_approval_endpoint, ApprovalResolveRequest
            from backend.app.api.auth import get_current_user_and_role
            from fastapi import HTTPException
            try:
                headers = headers or {}
                auth = headers.get("Authorization") or headers.get("authorization")
                u_role = get_current_user_and_role(authorization=auth)
                appr_id = clean_path.split("/")[-2]
                req = ApprovalResolveRequest(**(json or {}))
                res = resolve_approval_endpoint(approval_id=appr_id, req=req, user_and_role=u_role)
                return ApiResponse(200, res)
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
            except Exception as e:
                return ApiResponse(400, {"detail": str(e)})
        elif clean_path == "/api/v1/approvals/tokens/preapprove":
            from backend.app.api.approvals import create_preapproved_token_endpoint, PreApproveRequest
            from backend.app.api.auth import get_current_user_and_role
            from fastapi import HTTPException
            try:
                headers = headers or {}
                auth = headers.get("Authorization") or headers.get("authorization")
                u_role = get_current_user_and_role(authorization=auth)
                req = PreApproveRequest(**(json or {}))
                res = create_preapproved_token_endpoint(req=req, user_and_role=u_role)
                return ApiResponse(200, res)
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
            except Exception as e:
                return ApiResponse(400, {"detail": str(e)})
        elif clean_path == "/api/v1/policies/simulate":
            from backend.app.api.policies import simulate_policy_reevaluation, SimulationRequest
            from fastapi import HTTPException
            try:
                req = SimulationRequest(**(json or {}))
                res = simulate_policy_reevaluation(req)
                return ApiResponse(200, res)
            except HTTPException as he:
                return ApiResponse(he.status_code, {"detail": he.detail})
            except Exception as e:
                return ApiResponse(400, {"detail": str(e)})
        return ApiResponse(404, {"detail": "Not Found"})

@pytest.fixture(scope="function")
def test_db() -> Generator[str, None, None]:
    """
    Creates a temporary SQLite database with a cross-platform file path
    compatible with Windows, macOS, and Linux.
    """
    temp_dir = tempfile.gettempdir()
    db_path = os.path.join(temp_dir, f"sentinel_test_{uuid.uuid4().hex[:8]}.db")
    old_db = settings.DATABASE_URL
    settings.DATABASE_URL = db_path
    
    # Initialize schema and seed default agents
    init_db(db_path)
    
    # Reset policy engine to enforce mode by default for tests
    PolicyEngine.set_mode("enforce")

    yield db_path

    # Restore settings and cleanup
    settings.DATABASE_URL = old_db
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except Exception:
        pass

@pytest.fixture(scope="function")
def client(test_db: str):
    """
    Direct in-memory synchronous client fixture.
    """
    return DirectClient()
