def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_auth_token_issuance(client):
    res = client.post("/v1/auth/token", json={
        "user_id": "test-secops-user",
        "password": "ValidPassword123!",
        "roles": ["secops"],
        "tenant_id": "cbre-global"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_bola_protection_e2e(client, user_alice_token, user_bob_token, admin_token):
    # Alice accesses Alice's doc-101 -> 200 OK
    res_alice = client.get(
        "/v1/resources/doc-101",
        headers={"Authorization": f"Bearer {user_alice_token}"}
    )
    assert res_alice.status_code == 200
    assert res_alice.json()["id"] == "doc-101"
    # Verify data redaction on SSN and Credit Card
    assert "****-****-****-XXXX" in res_alice.json()["content"]

    # Bob tries to access Alice's doc-101 -> 403 Forbidden (BOLA Blocked)
    res_bob = client.get(
        "/v1/resources/doc-101",
        headers={"Authorization": f"Bearer {user_bob_token}"}
    )
    assert res_bob.status_code == 403
    assert "BOLA" in res_bob.json()["detail"]["error"]

    # Admin accesses Alice's doc-101 -> 200 OK (Privileged bypass)
    res_admin = client.get(
        "/v1/resources/doc-101",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200

def test_bfla_function_protection_e2e(client, user_alice_token, admin_token):
    # Developer Alice tries to access Admin security audit policy -> 403 Forbidden
    res_alice = client.get(
        "/v1/admin/security/audit-policy",
        headers={"Authorization": f"Bearer {user_alice_token}"}
    )
    assert res_alice.status_code == 403

    # Admin accesses Admin security audit policy -> 200 OK
    res_admin = client.get(
        "/v1/admin/security/audit-policy",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["status"] == "active"

def test_injection_blocked_on_resource_create(client, user_alice_token):
    # SQLi in title
    res = client.post(
        "/v1/resources",
        json={
            "title": "Quarterly Report'; DROP TABLE users; --",
            "content": "Normal content"
        },
        headers={"Authorization": f"Bearer {user_alice_token}"}
    )
    assert res.status_code == 400
    assert "Security Threat Detected" in res.json()["detail"]["error"]
