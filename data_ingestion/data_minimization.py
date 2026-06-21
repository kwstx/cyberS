import hashlib
import os

SALT = os.getenv("DARIP_HASH_SALT", "default_secure_salt_value").encode()

def hash_sensitive_value(value: str) -> str:
    """Hashes a sensitive string (e.g. IP address or email) with a salt."""
    if not value:
        return value
    return hashlib.sha256(value.encode() + SALT).hexdigest()

def apply_data_minimization(normalized_data: dict) -> dict:
    """
    Applies data minimization principles to the normalized payload before it leaves the ingestion boundary.
    - Strips developer emails and sensitive contact info from SBOMs.
    - Hashes IP addresses in network scans and telemetry.
    """
    payload = normalized_data.get("payload", {})
    
    # 1. Minimize SBOMs
    if "sbom" in payload:
        sbom_data = payload["sbom"]
        # Strip emails from components if they exist
        for component in sbom_data.get("components", []):
            if "author" in component and isinstance(component["author"], str) and "@" in component["author"]:
                # Remove the author or hash it to prevent PII leakage
                component["author"] = "REDACTED_PII"
                
    # 2. Minimize Telemetry
    if "telemetry" in payload:
        telemetry_data = payload["telemetry"]
        if "device_id" in telemetry_data:
            # Hash device ID if it is considered sensitive (like MAC address)
            telemetry_data["device_id"] = hash_sensitive_value(telemetry_data["device_id"])
            
    # 3. Minimize Network Scans
    if "network_scan" in payload:
        network_data = payload["network_scan"]
        if "ip_address" in network_data:
            # Hash IP address to prevent exact internal network mapping leakage
            network_data["ip_address"] = hash_sensitive_value(network_data["ip_address"])
            
    normalized_data["payload"] = payload
    return normalized_data
