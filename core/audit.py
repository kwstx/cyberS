import structlog
from typing import Any, Dict
from governance.audit_ledger import audit_ledger

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
            
        # Log to structlog for observability/SIEM
        audit_logger.info("audit_event", **payload)
        
        # Append to the cryptographic immutable ledger for compliance
        audit_ledger.append_event(payload)
