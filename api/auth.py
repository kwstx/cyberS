from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    roles: List[str]

import jwt
from core.config import settings

# Simulated token validation for development, enhanced with JWT for production
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    # In a real-world scenario, you would decode the JWT and fetch roles from your IdP
    if token.endswith("-token"):
        # Legacy static token fallback for development
        if token == "admin-token":
            return User(username="admin_user", roles=["admin", "analyst", "scanner"])
        elif token == "analyst-token":
            return User(username="analyst_user", roles=["analyst"])
        elif token == "scanner-token":
            return User(username="scanner_user", roles=["scanner"])
            
    try:
        # Expected to use RS256 with a JWKS from Okta/Auth0/Keycloak
        # For demonstration, we use a shared secret from settings
        payload = jwt.decode(token, getattr(settings, "JWT_SECRET", "secret"), algorithms=["HS256"])
        username: str = payload.get("sub")
        roles: List[str] = payload.get("roles", [])
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return User(username=username, roles=roles)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_user)):
        for role in self.allowed_roles:
            if role in user.roles:
                return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted"
        )
