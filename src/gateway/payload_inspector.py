import re
import json
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status
from src.core.config import settings

SQLI_PATTERNS = [
    re.compile(r"(\b(UNION(\s+ALL)?)\b.*?\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
    re.compile(r"(\bDROP\s+TABLE\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b)", re.IGNORECASE),
    re.compile(r"(--|#|/\*.*?\*/)", re.DOTALL),
    re.compile(r"(\bEXEC(\s+XP_\w+)?\b|\bWAITFOR\s+DELAY\b)", re.IGNORECASE)
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(;\s*(rm|cat|ls|whoami|id|nc|bash|sh|curl|wget)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(rm|cat|ls|whoami|id|nc|bash|sh|curl|wget)\b)", re.IGNORECASE),
    re.compile(r"(`.*?`)"),
    re.compile(r"(\$\(.*?\))")
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)"),
    re.compile(r"(/etc/passwd|/windows/win\.ini|/proc/self)", re.IGNORECASE)
]

NOSQL_PATTERNS = [
    re.compile(r"(\$gt|\$ne|\$where|\$regex|\$or|\$and)\b")
]

class PayloadInspector:
    def __init__(self):
        self.max_size = settings.MAX_PAYLOAD_SIZE_BYTES

    def inspect_text(self, text: str, field_name: str = "payload") -> List[str]:
        threats = []
        if settings.BLOCK_SQLI:
            for pattern in SQLI_PATTERNS:
                if pattern.search(text):
                    threats.append(f"SQL Injection detected in {field_name}")
                    break

        if settings.BLOCK_COMMAND_INJECTION:
            for pattern in COMMAND_INJECTION_PATTERNS:
                if pattern.search(text):
                    threats.append(f"OS Command Injection detected in {field_name}")
                    break

        if settings.BLOCK_PATH_TRAVERSAL:
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(text):
                    threats.append(f"Path Traversal attempt detected in {field_name}")
                    break

        for pattern in NOSQL_PATTERNS:
            if pattern.search(text):
                threats.append(f"NoSQL Injection pattern detected in {field_name}")
                break

        return threats

    def inspect_data(self, data: Any, path: str = "root") -> List[str]:
        threats = []
        if isinstance(data, str):
            threats.extend(self.inspect_text(data, field_name=path))
        elif isinstance(data, dict):
            for k, v in data.items():
                threats.extend(self.inspect_text(str(k), field_name=f"{path}.key[{k}]"))
                threats.extend(self.inspect_data(v, path=f"{path}.{k}"))
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                threats.extend(self.inspect_data(item, path=f"{path}[{idx}]"))
        return threats

    def enforce_safe_payload(self, body_bytes: bytes, parsed_json: Optional[Any] = None):
        if len(body_bytes) > self.max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Payload size {len(body_bytes)} exceeds gateway limit of {self.max_size} bytes."
            )
        
        threats = []
        if parsed_json is not None:
            threats = self.inspect_data(parsed_json)
        else:
            try:
                text = body_bytes.decode('utf-8', errors='ignore')
                threats = self.inspect_text(text)
            except Exception:
                pass

        if threats:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Security Threat Detected: Request rejected by Sentinel Gateway",
                    "threats": threats,
                    "owasp_category": "API8:2023 Security Misconfiguration / Injection"
                }
            )

payload_inspector = PayloadInspector()
