from src.gateway.data_redaction import data_redactor

def test_credit_card_redaction():
    text = "User credit card is 4111-2222-3333-4444 on file"
    redacted = data_redactor.redact_string(text)
    assert "4111-2222-3333-4444" not in redacted
    assert "****-****-****-XXXX" in redacted

def test_bearer_token_redaction():
    text = "Authorization token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    redacted = data_redactor.redact_string(text)
    assert "[REDACTED_TOKEN]" in redacted

def test_sensitive_dictionary_field_redaction():
    data = {
        "username": "alice",
        "email": "alice@cbre.com",
        "password": "SuperSecretPassword123!",
        "api_key": "sk_live_enterprise_9876543210123456",
        "nested": {
            "credit_card": "4111-2222-3333-4444"
        }
    }
    sanitized = data_redactor.sanitize(data)
    assert sanitized["password"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["api_key"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["nested"]["credit_card"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["username"] == "alice"
