import pytest
from fastapi import HTTPException
from src.gateway.bola_detector import bola_guard
from src.core.auth import UserPrincipal

def test_bola_access_allowed_for_owner():
    user = UserPrincipal(user_id="user-alice", roles=["developer"], scopes=[], tenant_id="cbre")
    # Accessing own object
    assert bola_guard.validate_object_access(user, requested_object_owner_id="user-alice") is True

def test_bola_access_denied_for_different_user():
    user = UserPrincipal(user_id="user-bob", roles=["developer"], scopes=[], tenant_id="cbre")
    # Trying to access Alice's object
    with pytest.raises(HTTPException) as exc:
        bola_guard.validate_object_access(user, requested_object_owner_id="user-alice")
    assert exc.value.status_code == 403
    assert "BOLA" in exc.value.detail["error"]

def test_bola_access_allowed_for_admin():
    admin = UserPrincipal(user_id="secops-lead", roles=["admin"], scopes=["*"], tenant_id="cbre")
    assert bola_guard.validate_object_access(admin, requested_object_owner_id="user-alice") is True

def test_tenant_boundary_isolation():
    user = UserPrincipal(user_id="user-cbre", roles=["developer"], scopes=[], tenant_id="cbre-apac")
    # Same tenant
    assert bola_guard.validate_tenant_isolation(user, resource_tenant_id="cbre-apac") is True
    # Different tenant
    with pytest.raises(HTTPException) as exc:
        bola_guard.validate_tenant_isolation(user, resource_tenant_id="cbre-emea")
    assert exc.value.status_code == 403
