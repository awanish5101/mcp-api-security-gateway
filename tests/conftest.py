import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.core.auth import create_access_token

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def user_alice_token():
    return create_access_token(data={
        "sub": "user-alice",
        "roles": ["developer"],
        "tenant_id": "cbre-global",
        "scopes": ["api:read", "api:write", "mcp:read", "mcp:call"]
    })

@pytest.fixture
def user_bob_token():
    return create_access_token(data={
        "sub": "user-bob",
        "roles": ["developer"],
        "tenant_id": "cbre-global",
        "scopes": ["api:read", "api:write", "mcp:read", "mcp:call"]
    })

@pytest.fixture
def admin_token():
    return create_access_token(data={
        "sub": "secops-admin",
        "roles": ["admin", "secops"],
        "tenant_id": "cbre-global",
        "scopes": ["*"]
    })

@pytest.fixture
def agent_token():
    return create_access_token(data={
        "sub": "agent-worker-01",
        "roles": ["agent"],
        "tenant_id": "cbre-global",
        "scopes": ["mcp:read", "mcp:call"]
    })
