import os
import jwt
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/auth", tags=["Authentication"])

JWT_SECRET = os.environ.get("SENTINEL_JWT_SECRET", "sentinel-default-secure-jwt-secret-2026")
JWT_ALGORITHM = "HS256"
JWT_DEFAULT_EXPIRE_MINUTES = 60

DEMO_USERS: Dict[str, Dict[str, str]] = {
    "viewer": {"password": "viewer123", "role": "viewer"},
    "analyst": {"password": "analyst123", "role": "analyst"},
    "privacy_officer": {"password": "officer123", "role": "privacy_officer"}
}

class LoginRequest(BaseModel):
    username: str = Field(..., description="Username (e.g. viewer, analyst, privacy_officer)")
    password: str = Field(..., description="Password (e.g. viewer123, analyst123, officer123)")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    expires_in: int

def get_jwt_secret() -> str:
    """
    Returns active JWT signing secret.
    In production (DEMO_MODE=false), refuses to use the embedded fallback default.
    """
    env_secret = os.environ.get("SENTINEL_JWT_SECRET")
    if env_secret:
        return env_secret
    if not is_demo_mode():
        raise RuntimeError("SENTINEL_JWT_SECRET must be set when DEMO_MODE=false.")
    return JWT_SECRET

def create_access_token(
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Generates a cryptographically signed HMAC-SHA256 JWT token with expiry."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=JWT_DEFAULT_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def verify_token(token_str: str) -> Dict[str, Any]:
    """Decodes and cryptographically validates JWT signature and expiry."""
    try:
        payload = jwt.decode(token_str, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Token has expired."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or forged JWT token signature."
        )

def get_current_user_and_role(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    legacy_role_header: Optional[str] = Header(None, alias="X-Sentinel-Role")
) -> Tuple[str, str]:
    """
    Extracts and validates user identity and role.
    Requires signed Authorization: Bearer <token>.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing Authorization header with signed JWT bearer token."
        )

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Authorization header format must be 'Bearer <signed_jwt_token>'."
        )

    token = parts[1]
    payload = verify_token(token)
    username = payload.get("sub", "unknown")
    role = payload.get("role", "viewer")
    return username, role

def is_demo_mode() -> bool:
    return os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

def require_control_plane_auth(
    authorization: Optional[str] = None,
    allowed_roles: Tuple[str, ...] = ("analyst", "privacy_officer"),
) -> Optional[Tuple[str, str]]:
    """
    Enforces JWT + RBAC on mutating control-plane endpoints when DEMO_MODE=false
    or whenever an Authorization header is supplied.
    Note: handles FastAPI Header(None) sentinel objects cleanly if called directly in tests.
    """
    auth_header = authorization if isinstance(authorization, str) else None
    if not is_demo_mode() or auth_header:
        user, role = get_current_user_and_role(auth_header)
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Role '{role}' cannot access this control-plane endpoint."
            )
        return user, role
    return None

@router.post("/login", response_model=TokenResponse)
def login(creds: LoginRequest) -> TokenResponse:
    """
    Authenticates seeded demo users and returns signed JWT access tokens.
    In production mode (DEMO_MODE=false), default demo credentials are fully disabled.
    """
    if not is_demo_mode():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Default demo credentials are disabled outside DEMO_MODE. Configure enterprise identity provider."
        )

    user_info = DEMO_USERS.get(creds.username)
    if not user_info or user_info["password"] != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid username or password."
        )

    role = user_info["role"]
    token = create_access_token(creds.username, role)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=role,
        username=creds.username,
        expires_in=JWT_DEFAULT_EXPIRE_MINUTES * 60
    )
