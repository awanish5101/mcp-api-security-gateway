import re
from typing import Dict, Any, List, Tuple
from fastapi import HTTPException, status
from src.core.config import settings

DIRECT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|system|above)\s+(instructions|prompts|rules)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?developer\s+mode", re.IGNORECASE),
    re.compile(r"system\s+(override|instructions\s+override)", re.IGNORECASE),
    re.compile(r"(new\s+system\s+prompt\s*:|override\s+system\s+role\s*:)", re.IGNORECASE),
    re.compile(r"(\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<\|im_start\|>|<\|im_end\|>)", re.IGNORECASE),
    re.compile(r"bypass\s+(content\s+filter|safety\s+guidelines)", re.IGNORECASE),
]

EXFILTRATION_PATTERNS = [
    re.compile(r"(https?://[a-zA-Z0-9.\-_]+/(exfil|steal|leak|webhook|collect|pwn))", re.IGNORECASE),
    re.compile(r"(curl|wget|fetch)\s+https?://", re.IGNORECASE),
    re.compile(r"(print|echo|leak)\s+(API_KEY|AWS_SECRET|JWT|PRIVATE_KEY|DATABASE_URL)", re.IGNORECASE),
]

class PromptInjectionDetector:
    """Inspects MCP agent tool parameters and prompt payloads for injection attacks."""

    def scan_string(self, text: str, context: str = "") -> List[str]:
        findings = []
        if not settings.MCP_BLOCK_PROMPT_INJECTION:
            return findings

        for pattern in DIRECT_INJECTION_PATTERNS:
            if pattern.search(text):
                findings.append(f"Prompt Injection Signature: Direct instruction override attempt in {context}")
                break

        for pattern in EXFILTRATION_PATTERNS:
            if pattern.search(text):
                findings.append(f"Data Exfiltration Pattern: Unauthorized exfiltration attempt in {context}")
                break

        return findings

    def inspect_tool_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> List[str]:
        """Recursively scan arguments passed to an MCP tool."""
        violations = []

        def _traverse(val: Any, path: str):
            if isinstance(val, str):
                violations.extend(self.scan_string(val, context=f"tool '{tool_name}' argument '{path}'"))
            elif isinstance(val, dict):
                for k, v in val.items():
                    _traverse(v, f"{path}.{k}")
            elif isinstance(val, list):
                for idx, v in enumerate(val):
                    _traverse(v, f"{path}[{idx}]")

        _traverse(arguments, "params")
        return violations

    def enforce_clean_arguments(self, tool_name: str, arguments: Dict[str, Any]):
        violations = self.inspect_tool_arguments(tool_name, arguments)
        if violations:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Agent Tool Call Blocked: Malicious Prompt Injection Detected",
                    "tool": tool_name,
                    "violations": violations,
                    "mitigation": "Scrub user input or strip adversarial prompt injection delimiters before tool invocation."
                }
            )

prompt_injection_detector = PromptInjectionDetector()
