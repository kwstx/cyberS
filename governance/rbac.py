from typing import List, Optional
from pydantic import BaseModel
import re

class Policy(BaseModel):
    effect: str # "allow" or "deny"
    actions: List[str] # e.g. ["read:reports", "write:assets", "*"]
    resources: List[str] # e.g. ["asset:123", "report:*", "*"]

class RoleDefinition(BaseModel):
    name: str
    policies: List[Policy]

# Predefined roles for the system with fine-grained policies
ROLES = {
    "admin": RoleDefinition(
        name="admin",
        policies=[Policy(effect="allow", actions=["*"], resources=["*"])]
    ),
    "auditor": RoleDefinition(
        name="auditor",
        policies=[
            Policy(effect="allow", actions=["read:*", "generate:*"], resources=["*"]),
            Policy(effect="deny", actions=["write:*", "delete:*", "execute:*"], resources=["*"])
        ]
    ),
    "analyst": RoleDefinition(
        name="analyst",
        policies=[
            Policy(effect="allow", actions=["read:*", "write:exposures", "write:remediations"], resources=["*"]),
            Policy(effect="deny", actions=["delete:assets"], resources=["*"])
        ]
    ),
    "scanner": RoleDefinition(
        name="scanner",
        policies=[
            Policy(effect="allow", actions=["read:assets", "write:exposures", "write:scans"], resources=["*"])
        ]
    )
}

class FineGrainedRBAC:
    """
    Evaluates fine-grained permissions based on role policies.
    Supports wildcards in actions and resources.
    Explicit 'deny' policies take precedence over 'allow'.
    """
    @staticmethod
    def _match_pattern(pattern: str, target: str) -> bool:
        if pattern == "*":
            return True
        regex = "^" + pattern.replace("*", ".*") + "$"
        return bool(re.match(regex, target))

    @staticmethod
    def is_authorized(user_roles: List[str], action: str, resource: str) -> bool:
        """
        Evaluate if a user with given roles is authorized to perform an action on a resource.
        """
        allowed = False
        
        for role_name in user_roles:
            role_def = ROLES.get(role_name)
            if not role_def:
                continue
                
            for policy in role_def.policies:
                action_match = any(FineGrainedRBAC._match_pattern(act, action) for act in policy.actions)
                resource_match = any(FineGrainedRBAC._match_pattern(res, resource) for res in policy.resources)
                
                if action_match and resource_match:
                    if policy.effect == "deny":
                        return False # Explicit deny wins
                    if policy.effect == "allow":
                        allowed = True
                        
        return allowed
