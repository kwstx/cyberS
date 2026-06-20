import structlog
from typing import Any, Dict

# Create a dedicated structured logger for audit events
audit_logger = structlog.get_logger("AuditLogger")

class AuditEvent:
    """Standardized audit event structure for compliance and security monitoring."""
    
    @staticmethod
    def log(action: str, actor: str, target: str, status: str, details: Dict[str, Any] = None) -> None:
        """
        Record an immutable audit event.
        In a production system, this could also write to a WORM (Write Once Read Many) storage
        or forward directly to an external SIEM via Kafka.
        """
        payload = {
            "event_type": "AUDIT",
            "action": action,
            "actor": actor,
            "target": target,
            "status": status,
        }
        if details:
            payload["details"] = details
            
        audit_logger.info("audit_event", **payload)
