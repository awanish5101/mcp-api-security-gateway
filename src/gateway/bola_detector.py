from typing import Optional, Dict, Any, List
from fastapi import HTTPException, status
from src.core.auth import UserPrincipal

class BOLAGuard:
    """
    Guards against Broken Object Level Authorization (OWASP API1:2023)
    and Broken Function Level Authorization (OWASP API5:2023).
    """

    def validate_object_access(
        self,
        user: UserPrincipal,
        requested_object_owner_id: str,
        object_type: str = "resource",
        allow_roles: Optional[List[str]] = None
    ) -> bool:
        """
        Validates whether the authenticated user has legitimate ownership or authorized
        role access to the requested object.
        """
        # Super-admin or secops can access across objects
        if "admin" in user.roles or "secops" in user.roles or "*" in user.scopes:
            return True

        # Custom allowed roles
        if allow_roles and any(r in user.roles for r in allow_roles):
            return True

        # Strict object ownership check
        if user.user_id == requested_object_owner_id:
            return True

        # If ownership does not match and no elevated role, block
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": f"BOLA / Broken Object Level Authorization violation detected",
                "message": f"User '{user.user_id}' is unauthorized to access {object_type} belonging to '{requested_object_owner_id}'",
                "owasp_category": "API1:2023 Broken Object Level Authorization"
            }
        )

    def validate_tenant_isolation(
        self,
        user: UserPrincipal,
        resource_tenant_id: str
    ) -> bool:
        """Enforce strict multi-tenant boundary isolation."""
        if "admin" in user.roles:
            return True
        
        if user.tenant_id != resource_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Cross-tenant data access violation",
                    "user_tenant": user.tenant_id,
                    "target_tenant": resource_tenant_id,
                    "owasp_category": "API1:2023 Broken Object Level Authorization"
                }
            )
        return True

bola_guard = BOLAGuard()
