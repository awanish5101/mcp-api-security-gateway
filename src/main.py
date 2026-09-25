import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.core.config import settings
from src.core.auth import (
    create_access_token,
    get_current_user,
    require_roles,
    UserPrincipal
)
from src.gateway.rate_limiter import rate_limiter
from src.gateway.payload_inspector import payload_inspector
from src.gateway.bola_detector import bola_guard
from src.gateway.data_redaction import data_redactor
from src.mcp_security.mcp_proxy import mcp_proxy, JSONRPCRequest
from src.mcp_security.audit_logger import audit_logger

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade API Security Gateway & Model Context Protocol (MCP) Threat Inspector."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store of mock user resources for BOLA demonstrations
RESOURCES_DATABASE: Dict[str, Dict[str, Any]] = {
    "doc-101": {
        "id": "doc-101",
        "title": "Q3 Enterprise Security Audit Report",
        "owner_id": "user-alice",
        "tenant_id": "cbre-global",
        "content": "Confidential financial review. SSN: 123-45-6789. Card: 4111-2222-3333-4444"
    },
    "doc-102": {
        "id": "doc-102",
        "title": "Kubernetes Cluster Architecture Spec",
        "owner_id": "user-bob",
        "tenant_id": "cbre-global",
        "content": "Production cluster ingress keys. API_KEY: sk_live_internal_secret_token_12345"
    }
}

class LoginRequest(BaseModel):
    user_id: str
    password: str
    roles: Optional[List[str]] = ["developer"]
    tenant_id: Optional[str] = "cbre-global"

class DocumentCreateRequest(BaseModel):
    title: str
    content: str

# --- HEALTH & AUDIT METRICS ---
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "gateway": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mcp_security": "ENABLED",
        "owasp_guardrails": "ENFORCED"
    }

# --- AUTHENTICATION / OAUTH2 TOKEN ISSUANCE ---
@app.post("/v1/auth/token", tags=["Authentication"])
async def issue_token(request: LoginRequest):
    """Simulates enterprise OAuth 2.0 / OIDC identity token endpoint."""
    token = create_access_token(data={
        "sub": request.user_id,
        "roles": request.roles,
        "tenant_id": request.tenant_id,
        "scopes": ["api:read", "api:write", "mcp:read", "mcp:call"]
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# --- MCP JSON-RPC SECURITY GATEWAY ENDPOINT ---
@app.post("/v1/mcp", tags=["Model Context Protocol Security"])
async def mcp_endpoint(
    request: Request,
    rpc_req: JSONRPCRequest,
    user: UserPrincipal = Depends(get_current_user)
):
    """
    Model Context Protocol (MCP) Security Gateway.
    Enforces tool permission scoping, prompt injection detection, sampling guards,
    and response data redaction.
    """
    # Rate limit check per agent/user
    client_key = rate_limiter.get_client_identifier(request, user.user_id)
    rate_limiter.check_rate_limit(client_key, cost=1)

    # Process JSON-RPC through MCP security proxy
    res = await mcp_proxy.handle_jsonrpc(rpc_req, user)
    return res

# --- REST API: PROTECTED RESOURCE WITH BOLA/BFLA DEFENSE ---
@app.get("/v1/resources/{resource_id}", tags=["REST Security (BOLA Defense)"])
async def get_resource(
    resource_id: str,
    request: Request,
    user: UserPrincipal = Depends(get_current_user)
):
    """
    Demonstrates OWASP API1:2023 (BOLA) and API3:2023 (Excessive Data Exposure) defense.
    Blocks unauthorized users from accessing objects they do not own, and redacts PII/keys.
    """
    client_key = rate_limiter.get_client_identifier(request, user.user_id)
    rate_limiter.check_rate_limit(client_key)

    if resource_id not in RESOURCES_DATABASE:
        raise HTTPException(status_code=404, detail="Resource not found")

    res = RESOURCES_DATABASE[resource_id]

    # Validate BOLA (Object ownership and tenant boundary)
    bola_guard.validate_object_access(user, requested_object_owner_id=res["owner_id"], object_type="document")
    bola_guard.validate_tenant_isolation(user, resource_tenant_id=res["tenant_id"])

    # Sanitize and redact outgoing response (prevent excessive data exposure)
    return data_redactor.sanitize(res)

@app.post("/v1/resources", tags=["REST Security (Payload & Injection Defense)"])
async def create_resource(
    body: DocumentCreateRequest,
    request: Request,
    user: UserPrincipal = Depends(get_current_user)
):
    """
    Demonstrates deep payload inspection (SQLi, Command Injection, Path Traversal)
    and rate limiting on resource creation.
    """
    client_key = rate_limiter.get_client_identifier(request, user.user_id)
    rate_limiter.check_rate_limit(client_key, cost=2)

    # Inspect payload for injection threats
    payload_inspector.enforce_safe_payload(body.title.encode(), parsed_json=body.model_dump())

    new_id = f"doc-{len(RESOURCES_DATABASE) + 101}"
    doc = {
        "id": new_id,
        "title": body.title,
        "owner_id": user.user_id,
        "tenant_id": user.tenant_id,
        "content": body.content
    }
    RESOURCES_DATABASE[new_id] = doc
    return {"message": "Resource created securely", "resource_id": new_id}

# --- ADMIN ONLY ROUTE (BFLA PROTECTION) ---
@app.get("/v1/admin/security/audit-policy", tags=["REST Security (BFLA Defense)"])
async def get_security_audit_policy(
    user: UserPrincipal = Depends(require_roles(["admin", "secops"]))
):
    """Demonstrates Broken Function Level Authorization (BFLA - OWASP API5:2023)."""
    return {
        "status": "active",
        "mcp_scoping": settings.MCP_ENFORCE_TOOL_SCOPING,
        "prompt_injection_guard": settings.MCP_BLOCK_PROMPT_INJECTION,
        "active_rules": [
            "OWASP_API1_BOLA_ENFORCEMENT",
            "OWASP_API3_DATA_REDACTION",
            "OWASP_API4_TOKEN_BUCKET_RATE_LIMIT",
            "OWASP_API5_BFLA_ROLE_GATE",
            "OWASP_API8_INJECTION_FILTER",
            "MCP_TOOL_LEAST_PRIVILEGE_TIER",
            "MCP_SAMPLING_TOKEN_CEILING"
        ]
    }
