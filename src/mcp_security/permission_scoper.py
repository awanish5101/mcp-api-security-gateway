from enum import Enum
from typing import Dict, List, Set, Any, Optional
from pydantic import BaseModel
from fastapi import HTTPException, status
from src.core.auth import UserPrincipal
from src.core.config import settings

class ToolRiskTier(str, Enum):
    SAFE_READ = "SAFE_READ"
    STATE_CHANGE = "STATE_CHANGE"
    ELEVATED_EXECUTION = "ELEVATED_EXECUTION"

class ToolMetadata(BaseModel):
    name: str
    description: str
    risk_tier: ToolRiskTier
    required_scopes: List[str]
    allowed_roles: List[str]

# Enterprise Registry of MCP Tools with Scopes and Permissions
MCP_TOOL_REGISTRY: Dict[str, ToolMetadata] = {
    "search_knowledge_base": ToolMetadata(
        name="search_knowledge_base",
        description="Search enterprise internal knowledge docs",
        risk_tier=ToolRiskTier.SAFE_READ,
        required_scopes=["mcp:read"],
        allowed_roles=["agent", "developer", "analyst", "admin"]
    ),
    "query_infrastructure_metrics": ToolMetadata(
        name="query_infrastructure_metrics",
        description="Query real-time cloud and cluster observability metrics",
        risk_tier=ToolRiskTier.SAFE_READ,
        required_scopes=["mcp:read", "metrics:read"],
        allowed_roles=["agent", "developer", "secops", "admin"]
    ),
    "update_incident_status": ToolMetadata(
        name="update_incident_status",
        description="Update enterprise incident response status",
        risk_tier=ToolRiskTier.STATE_CHANGE,
        required_scopes=["mcp:call", "incident:write"],
        allowed_roles=["secops", "admin"]
    ),
    "execute_system_command": ToolMetadata(
        name="execute_system_command",
        description="Run operational CLI scripts in sandbox",
        risk_tier=ToolRiskTier.ELEVATED_EXECUTION,
        required_scopes=["mcp:admin", "system:execute"],
        allowed_roles=["admin"]
    ),
    "modify_security_firewall": ToolMetadata(
        name="modify_security_firewall",
        description="Change network security and WAF rule definitions",
        risk_tier=ToolRiskTier.ELEVATED_EXECUTION,
        required_scopes=["mcp:admin", "firewall:write"],
        allowed_roles=["secops", "admin"]
    )
}

class MCPPermissionScoper:
    """Enforces least-privilege scoping and authorization for Model Context Protocol tools."""

    def filter_visible_tools(self, user: UserPrincipal) -> List[Dict[str, Any]]:
        """Filter MCP tools list according to user's permissions."""
        visible = []
        for name, tool in MCP_TOOL_REGISTRY.items():
            if "admin" in user.roles or "*" in user.scopes:
                visible.append(tool.model_dump())
                continue
            
            # Check role alignment
            if any(r in user.roles for r in tool.allowed_roles):
                # Check scope alignment
                if any(s in user.scopes for s in tool.required_scopes):
                    visible.append(tool.model_dump())
        return visible

    def authorize_tool_call(self, tool_name: str, user: UserPrincipal, arguments: Dict[str, Any]) -> ToolMetadata:
        """Verify whether the agent/caller has sufficient privilege to execute the MCP tool."""
        if not settings.MCP_ENFORCE_TOOL_SCOPING:
            return MCP_TOOL_REGISTRY.get(tool_name, ToolMetadata(
                name=tool_name, description="", risk_tier=ToolRiskTier.SAFE_READ,
                required_scopes=[], allowed_roles=[]
            ))

        if tool_name not in MCP_TOOL_REGISTRY:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MCP Tool '{tool_name}' is not registered in enterprise catalog."
            )

        tool = MCP_TOOL_REGISTRY[tool_name]

        # Admin bypass
        if "admin" in user.roles or "*" in user.scopes:
            return tool

        # Check role entitlement
        if not any(r in user.roles for r in tool.allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "MCP Tool Permission Scoping Violation",
                    "tool": tool_name,
                    "risk_tier": tool.risk_tier,
                    "caller_id": user.user_id,
                    "caller_roles": user.roles,
                    "required_roles": tool.allowed_roles
                }
            )

        # Check required scopes
        has_scope = any(s in user.scopes for s in tool.required_scopes)
        if not has_scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Insufficient OAuth2 / MCP Tool Scope",
                    "tool": tool_name,
                    "required_scopes": tool.required_scopes,
                    "caller_scopes": user.scopes
                }
            )

        # If elevated execution tier, check approval flag
        if tool.risk_tier == ToolRiskTier.ELEVATED_EXECUTION and settings.MCP_REQUIRE_APPROVAL_FOR_ELEVATED:
            approval_token = arguments.get("__enterprise_approval_token")
            if not approval_token or not approval_token.startswith("appr_"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "Elevated Tool Execution Requires Prior Enterprise Approval Token",
                        "tool": tool_name,
                        "risk_tier": ToolRiskTier.ELEVATED_EXECUTION
                    }
                )

        return tool

mcp_permission_scoper = MCPPermissionScoper()
