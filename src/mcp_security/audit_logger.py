import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.audit")

class SecurityAuditLogger:
    """Emits structured JSON security events for SIEM and security observability pipelines."""

    def log_event(
        self,
        event_type: str,
        severity: str,
        user_id: str,
        tenant_id: str,
        details: Dict[str, Any],
        action_taken: str = "BLOCKED"
    ):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "action_taken": action_taken,
            "details": details,
            "service": "sentinel-api-mcp-gateway"
        }
        logger.info(json.dumps(record))
        return record

audit_logger = SecurityAuditLogger()
