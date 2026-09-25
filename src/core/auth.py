import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from pydantic import BaseModel
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.core.config import settings

security_bearer = HTTPBearer(auto_error=False)

class TokenPayload(BaseModel):
    sub: str  # User / Subject ID
    roles: List[str] = []
    scopes: List[str] = []
    tenant_id: Optional[str] = "default"
    exp: Optional[int] = None
    iss: Optional[str] = "sentinel-auth"

class UserPrincipal(BaseModel):
    user_id: str
    roles: List[str]
    scopes: List[str]
    tenant_id: str
    is_authenticated: bool = True

# Pre-registered API keys for service accounts and agents
KNOWN_API_KEYS: Dict[str, Dict[str, Any]] = {
    "sk_live_enterprise_agent_001": {
        "user_id": "service-agent-analytics",
        "roles": ["agent"],
        "scopes": ["mcp:read", "mcp:call", "api:read"],
        "tenant_id": "cbre-global",
    },
    "sk_live_admin_portal_999": {
        "user_id": "secops-admin",
        "roles": ["admin", "secops"],
        "scopes": ["*"],
        "tenant_id": "cbre-global",
    },
}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create signed JWT access token for OAuth 2.0 / OIDC workflows."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": int(expire.timestamp()),
        "iss": "sentinel-auth"
    })
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_token(token: str) -> TokenPayload:
    """Decode and validate signed JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return TokenPayload(**payload)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> UserPrincipal:
    """FastAPI dependency to extract and authenticate user/service identity."""
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token or API Key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = auth.credentials
    # Check if API Key scheme
    if token in KNOWN_API_KEYS:
        info = KNOWN_API_KEYS[token]
        return UserPrincipal(
            user_id=info["user_id"],
            roles=info["roles"],
            scopes=info["scopes"],
            tenant_id=info["tenant_id"],
        )
    
    # Otherwise validate JWT Bearer token
    payload = verify_token(token)
    return UserPrincipal(
        user_id=payload.sub,
        roles=payload.roles,
        scopes=payload.scopes,
        tenant_id=payload.tenant_id or "default",
    )

def require_roles(required_roles: List[str]):
    """Decorator / dependency factory enforcing Role-Based Access Control (RBAC)."""
    async def role_checker(user: UserPrincipal = Depends(get_current_user)) -> UserPrincipal:
        if "admin" in user.roles or "*" in user.scopes:
            return user
        if not any(r in user.roles for r in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Required roles {required_roles} not held by subject '{user.user_id}'",
            )
        return user
    return role_checker
