"""
FastAPI dependency functions for authentication and RBAC.

Usage
-----
  from app.routes.deps import get_current_user, require_roles
  from app.models.user import UserRole

  @router.get("/admin-only")
  def admin_route(user = Depends(require_roles(UserRole.Admin))):
      ...
"""

from __future__ import annotations

from typing import Callable, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User, UserRole
from app.services import auth_service
from app.utils.security import decode_token
from app.utils.helpers import get_logger

logger = get_logger(__name__)

_bearer = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Extract and verify the JWT Bearer token; return the current User."""
    token = credentials.credentials
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if not username:
            raise ValueError("Token missing 'sub' claim.")
    except (JWTError, ValueError) as exc:
        logger.debug("Failed to decode token: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = auth_service.get_user_by_username(db, username)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(*roles: UserRole) -> Callable:
    """Return a dependency that enforces the user has one of the given roles."""
    allowed = set(roles)

    def _check(current_user: User = Depends(get_current_user)) -> User:
        if UserRole(current_user.role) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied. Required role(s): "
                    f"{[r.value for r in allowed]}. "
                    f"Your role: {current_user.role}."
                ),
            )
        return current_user

    return _check


# Convenience shorthand dependencies
require_admin    = require_roles(UserRole.Admin)
require_analyst  = require_roles(UserRole.Admin, UserRole.SOCAnalyst)
require_any_role = require_roles(UserRole.Admin, UserRole.SOCAnalyst, UserRole.Viewer)
