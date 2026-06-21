from abc import ABC, abstractmethod
from typing import Optional, Dict
import os
import logging
import time
import json

logger = logging.getLogger("DARIP.Secrets")
AUDIT_LOG_PATH = os.environ.get("SECRETS_AUDIT_LOG", "secrets_audit.log")

def log_audit_event(action: str, secret_name: str, status: str, caller_info: str = "internal-system"):
    """Write an immutable audit log entry for secrets access."""
    event = {
        "timestamp": time.time(),
        "action": action,
        "secret_name": secret_name,
        "status": status,
        "caller": caller_info
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logger.error(f"Failed to write secret audit log: {e}")

class SecretManager(ABC):
    """Abstract base class for secure secret management with audit logging."""

    @abstractmethod
    def get_secret(self, secret_name: str, caller_info: str = "internal-system") -> Optional[str]:
        """Retrieve a secret by its name."""
        pass

class VaultSecretManager(SecretManager):
    """Implementation for HashiCorp Vault with strict rate limiting and auditing."""
    
    def __init__(self, url: str = None, token: str = None):
        self.url = url or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.client = None
        self.cache: Dict[str, tuple[str, float]] = {}
        self.cache_ttl = 60.0  # 60 seconds TTL for secret cache
        self.rate_limits: Dict[str, list[float]] = {}
        self.max_requests_per_minute = 30
        
        try:
            import hvac
            self.client = hvac.Client(url=self.url, token=self.token)
        except ImportError:
            logger.warning("hvac module not found. VaultSecretManager will not work.")

    def _check_rate_limit(self, caller: str) -> bool:
        """Enforce rate limits per caller to mitigate harvesting attacks."""
        now = time.time()
        requests = self.rate_limits.setdefault(caller, [])
        # Clean older requests
        requests = [r for r in requests if now - r < 60]
        self.rate_limits[caller] = requests
        
        if len(requests) >= self.max_requests_per_minute:
            return False
        requests.append(now)
        return True

    def get_secret(self, secret_name: str, caller_info: str = "internal-system") -> Optional[str]:
        # 1. Check Rate Limiting
        if not self._check_rate_limit(caller_info):
            log_audit_event("RATE_LIMIT_EXCEEDED", secret_name, "DENIED", caller_info)
            logger.warning(f"Rate limit exceeded for caller '{caller_info}' requesting secret '{secret_name}'")
            return None

        # 2. Check Cache
        now = time.time()
        if secret_name in self.cache:
            val, expiry = self.cache[secret_name]
            if now < expiry:
                log_audit_event("GET_CACHE", secret_name, "SUCCESS", caller_info)
                return val

        if not self.client:
            log_audit_event("GET_VAULT", secret_name, "FAILED_NO_CLIENT", caller_info)
            return None
            
        try:
            # Assuming KV v2 and the secret is under 'secret/data/darip'
            path = "darip"
            read_response = self.client.secrets.kv.v2.read_secret_version(path=path)
            secret_val = read_response['data']['data'].get(secret_name)
            if secret_val:
                self.cache[secret_name] = (secret_val, now + self.cache_ttl)
                log_audit_event("GET_VAULT", secret_name, "SUCCESS", caller_info)
                return secret_val
            else:
                log_audit_event("GET_VAULT", secret_name, "NOT_FOUND", caller_info)
                return None
        except Exception as e:
            logger.error(f"Failed to fetch secret {secret_name} from Vault: {e}")
            log_audit_event("GET_VAULT", secret_name, f"ERROR: {str(e)}", caller_info)
            return None

class AWSSecretManager(SecretManager):
    """Implementation for AWS Secrets Manager."""
    
    def __init__(self, region_name: str = None):
        self.client = None
        try:
            import boto3
            self.region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
            self.client = boto3.client('secretsmanager', region_name=self.region_name)
        except ImportError:
            logger.warning("boto3 module not found. AWSSecretManager will not work.")

    def get_secret(self, secret_name: str, caller_info: str = "internal-system") -> Optional[str]:
        if not self.client:
            log_audit_event("GET_AWS", secret_name, "FAILED_NO_CLIENT", caller_info)
            return None
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            secret_val = response.get('SecretString')
            if secret_val:
                log_audit_event("GET_AWS", secret_name, "SUCCESS", caller_info)
            else:
                log_audit_event("GET_AWS", secret_name, "NOT_FOUND", caller_info)
            return secret_val
        except Exception as e:
            logger.error(f"Failed to fetch secret {secret_name} from AWS Secrets Manager: {e}")
            log_audit_event("GET_AWS", secret_name, f"ERROR: {str(e)}", caller_info)
            return None

def get_secret_manager() -> SecretManager:
    """Factory to get the configured secret manager."""
    provider = os.environ.get("SECRET_PROVIDER", "vault").lower()
    if provider == "aws":
        return AWSSecretManager()
    return VaultSecretManager()

