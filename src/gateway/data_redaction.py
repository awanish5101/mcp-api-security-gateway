import re
from typing import Any, Dict, List, Union
from src.core.config import settings

EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
BEARER_TOKEN_REGEX = re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE)
API_KEY_REGEX = re.compile(r'\b(?:sk_live_|ghp_|AKIA|AWS_SECRET)[A-Za-z0-9_]{16,}\b')

SENSITIVE_FIELD_NAMES = {
    "password", "secret", "token", "access_token", "refresh_token", 
    "private_key", "ssn", "cvv", "credit_card", "apiKey", "api_key"
}

class DataRedactor:
    """Sanitizes outgoing response payloads to eliminate excessive data exposure (OWASP API3:2023)."""

    def redact_string(self, text: str) -> str:
        if not settings.REDACT_SENSITIVE_DATA:
            return text
        text = CREDIT_CARD_REGEX.sub("****-****-****-XXXX", text)
        text = SSN_REGEX.sub("***-**-XXXX", text)
        text = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", text)
        text = API_KEY_REGEX.sub("[REDACTED_API_KEY]", text)
        return text

    def sanitize(self, data: Any) -> Any:
        if not settings.REDACT_SENSITIVE_DATA:
            return data

        if isinstance(data, str):
            return self.redact_string(data)
        elif isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                if str(k).lower() in SENSITIVE_FIELD_NAMES:
                    sanitized[k] = "[REDACTED_SENSITIVE_FIELD]"
                else:
                    sanitized[k] = self.sanitize(v)
            return sanitized
        elif isinstance(data, list):
            return [self.sanitize(item) for item in data]
        return data

data_redactor = DataRedactor()
