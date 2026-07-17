"""
Authentication router – JWT login, registration, and user management.

Endpoints
---------
POST   /auth/register        Register a new user (Admin only after first user).
POST   /auth/login           Obtain a JWT access token.
GET    /auth/me              Get the current authenticated user's profile.
GET    /auth/users           List all users (Admin only).
PATCH  /auth/users/{id}/role Change a user's role (Admin only).
DELETE /auth/users/{id}      Deactivate a user (Admin only).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User, UserRole
from app.models.schemas import (
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from app.routes.deps import get_current_user, require_admin, require_any_role
from app.services import auth_service
from app.utils.helpers import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ── POST /auth/register ───────────────────────────────────────────────────────
@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description=(
        "Creates a new user account. **The very first registration is always allowed** "
        "(bootstrapping the admin). Subsequent registrations require Admin role.\n\n"
        "**Roles:** `Admin` | `SOCAnalyst` | `Viewer`"
    ),
)
def register(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Register a new user. First user is always created; subsequent require auth."""
    # Allow first user (bootstrap) without auth
    total = db.query(User).count()
    if total > 0:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated.",
            )
        token = auth_header.split(" ")[1]
        try:
            from app.utils.security import decode_token
            payload_jwt = decode_token(token)
            username = payload_jwt.get("sub")
            if not username:
                raise ValueError()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
            )
        current_user = auth_service.get_user_by_username(db, username)
        if not current_user or current_user.role != UserRole.Admin or not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required for registration after bootstrapping.",
            )
    user = auth_service.create_user(db, payload)
    return user


# ── POST /auth/login ──────────────────────────────────────────────────────────
@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and obtain JWT",
    description=(
        "Authenticate with username + password. Returns a JWT bearer token "
        "valid for the configured expiry window (default 8 hours)."
    ),
)
def login(
    payload: UserLogin,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate and return a JWT access token."""
    user = auth_service.authenticate_user(db, payload.username, payload.password)
    token_data = auth_service.issue_token(user)
    return token_data


# ── GET /auth/me ──────────────────────────────────────────────────────────────
@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Returns the profile of the currently authenticated user.",
)
def get_me(current_user: User = Depends(require_any_role)) -> UserResponse:
    """Return the authenticated user's profile."""
    return current_user


# ── GET /auth/users ───────────────────────────────────────────────────────────
@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List all users",
    description="Returns all registered users. **Admin only.**",
)
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[UserResponse]:
    """List all users (Admin only)."""
    return auth_service.list_users(db)


# ── PATCH /auth/users/{id}/role ───────────────────────────────────────────────
@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Change a user's role",
    description="Update a user's RBAC role. **Admin only.**",
)
def update_role(
    user_id: int,
    role: UserRole,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserResponse:
    """Change a user's role (Admin only)."""
    user = auth_service.get_user_by_id(db, user_id)
    user.role = role
    db.commit()
    db.refresh(user)
    logger.info("User role updated | user_id=%s new_role=%s", user_id, role)
    return user


# ── DELETE /auth/users/{id} ───────────────────────────────────────────────────
@router.delete(
    "/users/{user_id}",
    summary="Deactivate a user",
    description="Soft-deactivate a user account. **Admin only.**",
)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
) -> dict:
    """Soft-delete (deactivate) a user (Admin only)."""
    if current.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account.",
        )
    user = auth_service.get_user_by_id(db, user_id)
    user.is_active = False
    db.commit()
    logger.info("User deactivated | user_id=%s by admin=%s", user_id, current.username)
    return {"message": f"User '{user.username}' deactivated successfully."}
