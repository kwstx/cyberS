from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    roles: List[str]

# Simulated token validation for development
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    # In a real-world scenario, you would decode the JWT and fetch roles from your IdP
    if token == "admin-token":
        return User(username="admin_user", roles=["admin", "analyst", "scanner"])
    elif token == "analyst-token":
        return User(username="analyst_user", roles=["analyst"])
    elif token == "scanner-token":
        return User(username="scanner_user", roles=["scanner"])
    else:
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
