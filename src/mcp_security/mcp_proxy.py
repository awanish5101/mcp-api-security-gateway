from typing import Dict, Any, Optional
from fastapi import HTTPException
from pydantic import BaseModel
from src.core.auth import UserPrincipal
from src.mcp_security.permission_scoper import mcp_permission_scoper, ToolRiskTier
from src.mcp_security.prompt_injection_detector import prompt_injection_detector
from src.mcp_security.sampling_guard import mcp_sampling_guard
from src.mcp_security.audit_logger import audit_logger
from src.gateway.data_redaction import data_redactor

class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None

class MCPProxyService:
    """Intersects and hardens Model Context Protocol JSON-RPC communications."""

    async def handle_jsonrpc(self, request: JSONRPCRequest, user: UserPrincipal) -> Dict[str, Any]:
        method = request.method
        params = request.params or {}

        # 1. tools/list: Filter tool visibility by caller's entitlements
        if method == "tools/list":
            tools = mcp_permission_scoper.filter_visible_tools(user)
            return {
                "jsonrpc": "2.0",
                "result": {"tools": tools},
                "id": request.id
            }

        # 2. tools/call: Authorize, scan parameters, enforce policy, execute
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # Check least privilege permission scoping
            try:
                tool_meta = mcp_permission_scoper.authorize_tool_call(tool_name, user, arguments)
            except HTTPException as e:
                audit_logger.log_event(
                    event_type="MCP_TOOL_PERMISSION_DENIED",
                    severity="HIGH",
                    user_id=user.user_id,
                    tenant_id=user.tenant_id,
                    details={"tool": tool_name, "error": e.detail}
                )
                raise e

            # Scan arguments for prompt injection
            try:
                prompt_injection_detector.enforce_clean_arguments(tool_name, arguments)
            except HTTPException as e:
                audit_logger.log_event(
                    event_type="MCP_PROMPT_INJECTION_DETECTED",
                    severity="CRITICAL",
                    user_id=user.user_id,
                    tenant_id=user.tenant_id,
                    details={"tool": tool_name, "error": e.detail}
                )
                raise e

            # Execute simulation or upstream forward
            simulated_execution = {
                "status": "success",
                "tool": tool_name,
                "executed_by": user.user_id,
                "risk_tier": tool_meta.risk_tier,
                "output": f"Executed '{tool_name}' safely inside Sentinel secure enclave. Access token was Bearer eyJhbGciOi...",
                "sensitive_metadata": {"internal_token": "sk_live_secret_leaked_key_999"}
            }

            # Apply response data redaction
            sanitized_output = data_redactor.sanitize(simulated_execution)

            audit_logger.log_event(
                event_type="MCP_TOOL_EXECUTION_SUCCESS",
                severity="INFO",
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                details={"tool": tool_name, "risk_tier": tool_meta.risk_tier},
                action_taken="ALLOWED"
            )

            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": str(sanitized_output)}]
                },
                "id": request.id
            }

        # 3. sampling/createMessage: Validate and enforce sampling/elicitation guardrails
        elif method == "sampling/createMessage":
            mcp_sampling_guard.validate_sampling_request(user, params)
            audit_logger.log_event(
                event_type="MCP_SAMPLING_ALLOWED",
                severity="INFO",
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                details={"maxTokens": params.get("maxTokens")},
                action_taken="ALLOWED"
            )
            return {
                "jsonrpc": "2.0",
                "result": {
                    "role": "assistant",
                    "content": {"type": "text", "text": "Sampled message generated safely under Sentinel enterprise controls."}
                },
                "id": request.id
            }

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported or unhandled MCP JSON-RPC method: '{method}'"
            )

mcp_proxy = MCPProxyService()
