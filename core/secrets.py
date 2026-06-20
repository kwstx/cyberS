from abc import ABC, abstractmethod
from typing import Optional
import os
import logging

logger = logging.getLogger("DARIP.Secrets")

class SecretManager(ABC):
    """Abstract base class for secure secret management."""

    @abstractmethod
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve a secret by its name."""
        pass

class VaultSecretManager(SecretManager):
    """Implementation for HashiCorp Vault."""
    
    def __init__(self, url: str = None, token: str = None):
        try:
            import hvac
            self.url = url or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
            self.token = token or os.environ.get("VAULT_TOKEN")
            self.client = hvac.Client(url=self.url, token=self.token)
        except ImportError:
            logger.warning("hvac module not found. VaultSecretManager will not work.")
            self.client = None

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not self.client:
            return None
        try:
            # Assuming KV v2 and the secret is under 'secret/data/darip'
            path = "darip"
            read_response = self.client.secrets.kv.v2.read_secret_version(path=path)
            return read_response['data']['data'].get(secret_name)
        except Exception as e:
            logger.error(f"Failed to fetch secret {secret_name} from Vault: {e}")
            return None

class AWSSecretManager(SecretManager):
    """Implementation for AWS Secrets Manager."""
    
    def __init__(self, region_name: str = None):
        try:
            import boto3
            self.region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
            self.client = boto3.client('secretsmanager', region_name=self.region_name)
        except ImportError:
            logger.warning("boto3 module not found. AWSSecretManager will not work.")
            self.client = None

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not self.client:
            return None
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            return response.get('SecretString')
        except Exception as e:
            logger.error(f"Failed to fetch secret {secret_name} from AWS Secrets Manager: {e}")
            return None

def get_secret_manager() -> SecretManager:
    """Factory to get the configured secret manager."""
    provider = os.environ.get("SECRET_PROVIDER", "vault").lower()
    if provider == "aws":
        return AWSSecretManager()
    return VaultSecretManager()
