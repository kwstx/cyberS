import logging
from typing import Dict, Any, List
from pydantic import BaseModel, SecretStr
from ldap3 import Server, Connection, ALL, SUBTREE

logger = logging.getLogger(__name__)

class ADConfig(BaseModel):
    server_uri: str
    bind_dn: str
    bind_password: SecretStr
    search_base: str

class ActiveDirectoryConnector:
    """
    Production-ready Active Directory connector using LDAP3.
    Used for identity context enrichment, tracking disabled accounts, and group memberships.
    """
    def __init__(self, config: ADConfig):
        self.config = config
        self.server = Server(config.server_uri, get_info=ALL)
        self._connection = None

    def connect(self) -> bool:
        try:
             self._connection = Connection(
                 self.server, 
                 user=self.config.bind_dn, 
                 password=self.config.bind_password.get_secret_value(),
                 auto_bind=True
             )
             logger.info("Successfully bound to Active Directory.")
             return True
        except Exception as e:
             logger.error(f"Failed to bind to Active Directory: {e}")
             return False

    def disconnect(self):
        if self._connection:
            self._connection.unbind()

    def fetch_users(self, filter_query: str = "(objectClass=user)") -> List[Dict[str, Any]]:
        """
        Fetches user objects matching the filter query.
        """
        if not self._connection:
            if not self.connect():
                return []
        
        try:
            self._connection.search(
                search_base=self.config.search_base,
                search_filter=filter_query,
                search_scope=SUBTREE,
                attributes=['cn', 'sAMAccountName', 'userPrincipalName', 'memberOf', 'userAccountControl']
            )
            
            users = []
            for entry in self._connection.entries:
                user_data = {
                    "dn": entry.entry_dn,
                    "cn": str(entry.cn),
                    "username": str(entry.sAMAccountName),
                    "upn": str(entry.userPrincipalName) if 'userPrincipalName' in entry else None,
                    "groups": [str(g) for g in entry.memberOf] if 'memberOf' in entry else [],
                    # userAccountControl contains flags like AccountDisabled (2)
                    "is_disabled": bool(int(entry.userAccountControl.value) & 2) if 'userAccountControl' in entry else False
                }
                users.append(user_data)
            return users
        except Exception as e:
            logger.exception(f"Error searching Active Directory: {e}")
            return []
