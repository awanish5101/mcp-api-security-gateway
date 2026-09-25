import pytest
from fastapi import HTTPException
from src.core.auth import create_access_token, verify_token, UserPrincipal, require_roles
from datetime import timedelta

def test_valid_jwt_token():
    token = create_access_token({"sub": "sec-eng-01", "roles": ["secops"], "tenant_id": "cbre"})
    payload = verify_token(token)
    assert payload.sub == "sec-eng-01"
    assert "secops" in payload.roles
    assert payload.tenant_id == "cbre"

def test_expired_jwt_token():
    token = create_access_token({"sub": "sec-eng-01"}, expires_delta=timedelta(seconds=-10))
    with pytest.raises(HTTPException) as exc:
        verify_token(token)
    assert exc.value.status_code == 401

@pytest.mark.asyncio
async def test_role_authorization_check():
    checker = require_roles(["admin", "secops"])
    
    # Authorized user
    user_authorized = UserPrincipal(user_id="user-1", roles=["secops"], scopes=[], tenant_id="cbre")
    result = await checker(user_authorized)
    assert result.user_id == "user-1"

    # Unauthorized user
    user_unauthorized = UserPrincipal(user_id="user-2", roles=["guest"], scopes=[], tenant_id="cbre")
    with pytest.raises(HTTPException) as exc:
        await checker(user_unauthorized)
    assert exc.value.status_code == 403
